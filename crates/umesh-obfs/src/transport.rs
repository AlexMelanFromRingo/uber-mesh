//! Concrete obfuscated TCP transport (the first `ObfsTransport`-contract carrier), a concurrent
//! probe-resistant listener, and a connect-time rotation helper.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;

use crate::error::{ObfsError, Result};
use crate::handshake::{
    ClientConfig, ObfsPsk, ProbeResponse, ServerOutcome, client_handshake_with, handle_probe,
    server_handshake_core,
};
use crate::secure::SecureStream;
use crate::shaping::ShapingPolicy;

/// Default cap on concurrently running server handshakes per listener.
pub const DEFAULT_MAX_INFLIGHT_HANDSHAKES: usize = 256;
/// Default depth of the accepted-session queue of an [`ObfsListener`].
const DEFAULT_ACCEPT_QUEUE: usize = 64;

/// Obfuscated TCP carrier: Chrome-shaped TLS 1.3 handshake, probe-resistant, hybrid-PQ-keyed.
pub struct ObfsTcp;

type Pending = Pin<Box<dyn Future<Output = (TcpStream, SocketAddr, ServerOutcome)> + Send>>;

fn handshake_owned(mut sock: TcpStream, peer: SocketAddr, psk: ObfsPsk) -> Pending {
    Box::pin(async move {
        let _ = sock.set_nodelay(true);
        let outcome = server_handshake_core(&mut sock, &psk).await;
        (sock, peer, outcome)
    })
}

impl ObfsTcp {
    /// Dial `addr`, perform the obfs handshake, and return a secure message stream (default
    /// [`ClientConfig`]: per-connection cover SNI, 10 s connect + 10 s handshake timeouts).
    pub async fn connect<A: ToSocketAddrs>(
        addr: A,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
    ) -> Result<SecureStream<TcpStream>> {
        Self::connect_with(addr, psk, shaping, &ClientConfig::default()).await
    }

    /// Dial with explicit client options. Both the TCP connect and the handshake are bounded, so a
    /// silently-frozen endpoint yields a timeout error (and rotation) instead of a hang.
    pub async fn connect_with<A: ToSocketAddrs>(
        addr: A,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
        cfg: &ClientConfig,
    ) -> Result<SecureStream<TcpStream>> {
        let mut sock = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                ObfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tcp connect timed out",
                ))
            })??;
        let _ = sock.set_nodelay(true);
        let keys = client_handshake_with(&mut sock, psk, cfg).await?;
        Ok(SecureStream::new(sock, keys, shaping))
    }

    /// Accept the next inbound connection that completes the probe-resistant server handshake
    /// (silence on gate failure).
    ///
    /// Handshakes run **concurrently** inside this call, so a silent or slow prober never blocks a
    /// genuine client; probes are answered in detached tasks and never returned. Handshakes still
    /// in flight when one completes are abandoned — long-running servers should use
    /// [`ObfsListener`], which keeps them across calls.
    pub async fn accept(
        listener: &TcpListener,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
    ) -> Result<(SecureStream<TcpStream>, SocketAddr)> {
        Self::accept_with_probe(listener, psk, shaping, &ProbeResponse::Silence).await
    }

    /// [`ObfsTcp::accept`] with an explicit probe-response policy (e.g.
    /// [`ProbeResponse::Fallback`] to reverse-proxy probers to a real cover site).
    pub async fn accept_with_probe(
        listener: &TcpListener,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
        probe: &ProbeResponse,
    ) -> Result<(SecureStream<TcpStream>, SocketAddr)> {
        let mut pending: FuturesUnordered<Pending> = FuturesUnordered::new();
        loop {
            tokio::select! {
                Some((mut sock, peer, outcome)) = pending.next(), if !pending.is_empty() => {
                    match outcome {
                        ServerOutcome::Accepted(keys) => {
                            return Ok((SecureStream::new(sock, keys, shaping), peer));
                        }
                        ServerOutcome::Probe(prefix) => {
                            let probe = probe.clone();
                            tokio::spawn(async move {
                                handle_probe(&mut sock, &prefix, &probe).await;
                            });
                        }
                        ServerOutcome::Failed(e) => {
                            tracing::debug!(error = %e, "inbound obfs handshake failed");
                        }
                    }
                }
                acc = listener.accept(), if pending.len() < DEFAULT_MAX_INFLIGHT_HANDSHAKES => {
                    let (sock, peer) = acc?;
                    pending.push(handshake_owned(sock, peer, psk.clone()));
                }
            }
        }
    }
}

/// Options for an [`ObfsListener`].
#[derive(Clone, Debug)]
pub struct ListenerConfig {
    /// What unauthenticated / probing connections get.
    pub probe: ProbeResponse,
    /// Cap on concurrently running server handshakes (probe responses run outside the cap).
    pub max_inflight_handshakes: usize,
    /// Depth of the queue of completed sessions awaiting [`ObfsListener::accept`].
    pub accept_queue: usize,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        ListenerConfig {
            probe: ProbeResponse::Silence,
            max_inflight_handshakes: DEFAULT_MAX_INFLIGHT_HANDSHAKES,
            accept_queue: DEFAULT_ACCEPT_QUEUE,
        }
    }
}

/// A probe-resistant obfs-tcp listener. A background task accepts TCP connections and runs each
/// server handshake in its own task (bounded by `max_inflight_handshakes`); fully key-confirmed
/// sessions are delivered through [`ObfsListener::accept`]. A silent prober therefore never delays
/// other clients. Dropping the listener stops accepting.
pub struct ObfsListener {
    rx: mpsc::Receiver<(SecureStream<TcpStream>, SocketAddr)>,
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl ObfsListener {
    /// Bind `addr` and start accepting.
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        psk: ObfsPsk,
        shaping: ShapingPolicy,
        cfg: ListenerConfig,
    ) -> Result<Self> {
        let l = TcpListener::bind(addr).await?;
        Self::new(l, psk, shaping, cfg)
    }

    /// Start accepting on an already-bound listener (must be called inside a Tokio runtime).
    pub fn new(
        listener: TcpListener,
        psk: ObfsPsk,
        shaping: ShapingPolicy,
        cfg: ListenerConfig,
    ) -> Result<Self> {
        let local_addr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel(cfg.accept_queue.max(1));
        let sem = Arc::new(Semaphore::new(cfg.max_inflight_handshakes.max(1)));
        let probe = cfg.probe;
        let task = tokio::spawn(async move {
            loop {
                let Ok(permit) = sem.clone().acquire_owned().await else {
                    return;
                };
                let (mut sock, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        // e.g. EMFILE: back off briefly instead of spinning.
                        tracing::debug!(error = %e, "obfs listener accept error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if tx.is_closed() {
                    return;
                }
                let (psk, shaping, probe, tx) =
                    (psk.clone(), shaping.clone(), probe.clone(), tx.clone());
                tokio::spawn(async move {
                    let _ = sock.set_nodelay(true);
                    let outcome = server_handshake_core(&mut sock, &psk).await;
                    drop(permit);
                    match outcome {
                        ServerOutcome::Accepted(keys) => {
                            let _ = tx
                                .send((SecureStream::new(sock, keys, shaping), peer))
                                .await;
                        }
                        ServerOutcome::Probe(prefix) => {
                            handle_probe(&mut sock, &prefix, &probe).await;
                        }
                        ServerOutcome::Failed(e) => {
                            tracing::debug!(error = %e, from = %peer, "inbound obfs handshake failed");
                        }
                    }
                });
            }
        });
        Ok(ObfsListener {
            rx,
            local_addr,
            task,
        })
    }

    /// The next fully-authenticated inbound session.
    pub async fn accept(&mut self) -> Result<(SecureStream<TcpStream>, SocketAddr)> {
        self.rx.recv().await.ok_or_else(|| {
            ObfsError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "obfs listener stopped",
            ))
        })
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for ObfsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A dialable endpoint: an address plus the PSK gating its listener.
#[derive(Clone)]
pub struct Endpoint {
    /// `host:port` to dial.
    pub addr: String,
    /// PSK for this endpoint's obfs gate.
    pub psk: ObfsPsk,
}

impl Endpoint {
    /// Create an endpoint.
    pub fn new(addr: impl Into<String>, psk: ObfsPsk) -> Self {
        Endpoint {
            addr: addr.into(),
            psk,
        }
    }
}

/// Try each endpoint in order with the default [`ClientConfig`], returning the first that
/// establishes a session (connect-time half of transport rotation, SC-002).
pub async fn connect_first_working(
    endpoints: &[Endpoint],
    shaping: ShapingPolicy,
) -> Result<SecureStream<TcpStream>> {
    connect_first_working_with(endpoints, shaping, &ClientConfig::default()).await
}

/// [`connect_first_working`] with explicit client options. Every attempt is bounded by the
/// connect + handshake timeouts, so an endpoint that silently freezes is rotated past.
pub async fn connect_first_working_with(
    endpoints: &[Endpoint],
    shaping: ShapingPolicy,
    cfg: &ClientConfig,
) -> Result<SecureStream<TcpStream>> {
    for ep in endpoints {
        match ObfsTcp::connect_with(&ep.addr, &ep.psk, shaping.clone(), cfg).await {
            Ok(stream) => {
                tracing::debug!(addr = %ep.addr, "obfs-tcp session established");
                return Ok(stream);
            }
            Err(e) => {
                tracing::debug!(addr = %ep.addr, error = %e, "endpoint failed, rotating");
            }
        }
    }
    Err(ObfsError::NoTransport)
}
