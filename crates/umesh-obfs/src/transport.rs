//! Concrete obfuscated TCP transport (the first `ObfsTransport`-contract carrier) and a
//! connect-time rotation helper.

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::error::{ObfsError, Result};
use crate::handshake::{ObfsPsk, client_handshake, server_handshake};
use crate::secure::SecureStream;
use crate::shaping::ShapingPolicy;

/// Obfuscated TCP carrier: TLS-record-framed, probe-resistant, hybrid-PQ-keyed.
pub struct ObfsTcp;

impl ObfsTcp {
    /// Dial `addr`, perform the obfs handshake, and return a secure message stream.
    pub async fn connect<A: ToSocketAddrs>(
        addr: A,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
    ) -> Result<SecureStream<TcpStream>> {
        let mut sock = TcpStream::connect(addr).await?;
        let _ = sock.set_nodelay(true);
        let keys = client_handshake(&mut sock, psk).await?;
        Ok(SecureStream::new(sock, keys, shaping))
    }

    /// Accept one inbound connection and complete the **probe-resistant** server handshake.
    /// A connection that fails the gate returns [`ObfsError::AuthFailed`] after silent draining.
    pub async fn accept(
        listener: &TcpListener,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
    ) -> Result<(SecureStream<TcpStream>, SocketAddr)> {
        let (mut sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let keys = server_handshake(&mut sock, psk).await?;
        Ok((SecureStream::new(sock, keys, shaping), peer))
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

/// Try each endpoint in order, returning the first that establishes a session. This is the
/// connect-time half of transport rotation (SC-002); the runtime mid-session health loop lives in
/// `umesh-node`. Logs (without secrets) which endpoints were skipped.
pub async fn connect_first_working(
    endpoints: &[Endpoint],
    shaping: ShapingPolicy,
) -> Result<SecureStream<TcpStream>> {
    for ep in endpoints {
        match ObfsTcp::connect(&ep.addr, &ep.psk, shaping.clone()).await {
            Ok(stream) => {
                tracing::debug!(addr = %ep.addr, "obfs-tcp session established");
                return Ok(stream);
            }
            Err(e) => {
                tracing::debug!(addr = %ep.addr, error = %e, "endpoint unreachable, rotating");
            }
        }
    }
    Err(ObfsError::NoTransport)
}
