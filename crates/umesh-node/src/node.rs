//! Node runtime: bind an obfs listener, dial peers, and exchange signed hellos.
//!
//! This iteration carries an authenticated point-to-point hello over the obfs transport (proving the
//! crypto + obfs stack end-to-end). The full libp2p gossip/discovery/NAT mesh is layered on top in
//! the US2/US3 phases.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use umesh_crypto::identity::{self, NodeIdentity, PeerId};
use umesh_obfs::{ObfsPsk, ObfsTcp, SecureStream, ShapingPolicy};

use crate::config::Config;
use crate::error::{NodeError, Result};
use crate::status::{Event, NodeStatus, PeerCounts, TransportStatus};

const HELLO_LEN: usize = 32 + 32 + 64; // peer_id || verifying_key || signature

/// Live runtime state shared between the accept loop, dialers, and status queries.
#[derive(Default)]
struct RuntimeState {
    connected: HashSet<PeerId>,
    known: HashSet<PeerId>,
    events: Vec<Event>,
}

impl RuntimeState {
    fn record(&mut self, kind: &str, detail: String) {
        self.events.push(Event {
            kind: kind.into(),
            detail,
        });
        if self.events.len() > 64 {
            self.events.remove(0);
        }
    }
}

/// A running node.
pub struct Node {
    identity: Arc<NodeIdentity>,
    config: Config,
    state: Arc<Mutex<RuntimeState>>,
}

impl Node {
    /// Construct a node from an identity and config.
    pub fn new(identity: NodeIdentity, config: Config) -> Self {
        Node {
            identity: Arc::new(identity),
            config,
            state: Arc::new(Mutex::new(RuntimeState::default())),
        }
    }

    /// This node's PeerId.
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// Encode this node's signed hello (proof-of-possession over its own verifying key).
    fn hello(&self) -> Vec<u8> {
        let vk = self.identity.verifying_key().to_bytes();
        let sig = self.identity.sign_bytes(&vk);
        let mut msg = Vec::with_capacity(HELLO_LEN);
        msg.extend_from_slice(self.identity.peer_id().as_bytes());
        msg.extend_from_slice(&vk);
        msg.extend_from_slice(&sig);
        msg
    }

    /// Verify a received hello, returning the authenticated PeerId.
    fn verify_hello(msg: &[u8]) -> Result<PeerId> {
        if msg.len() != HELLO_LEN {
            return Err(NodeError::PeerRejected("bad hello length".into()));
        }
        let claimed: &[u8] = &msg[..32];
        let vk: [u8; 32] = msg[32..64].try_into().unwrap();
        let sig: [u8; 64] = msg[64..128].try_into().unwrap();
        let peer = identity::verify(&vk, &vk, &sig)
            .map_err(|_| NodeError::PeerRejected("invalid hello signature".into()))?;
        if peer.as_bytes() != claimed {
            return Err(NodeError::PeerRejected(
                "peer_id does not bind to key".into(),
            ));
        }
        Ok(peer)
    }

    async fn exchange_hello<S>(&self, stream: &mut SecureStream<S>, we_dial: bool) -> Result<PeerId>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // Dialer sends first; listener responds. Symmetric otherwise.
        if we_dial {
            stream.send(&self.hello()).await?;
            let peer = Self::verify_hello(&stream.recv().await?)?;
            Ok(peer)
        } else {
            let peer = Self::verify_hello(&stream.recv().await?)?;
            stream.send(&self.hello()).await?;
            Ok(peer)
        }
    }

    /// Bind an obfs-tcp listener and spawn the accept loop. Returns the bound address.
    pub async fn bind_listener(
        self: &Arc<Self>,
        psk: ObfsPsk,
        shaping: ShapingPolicy,
    ) -> Result<SocketAddr> {
        let addr = self
            .config
            .listen
            .clone()
            .ok_or_else(|| NodeError::Config("no listen address configured".into()))?;
        let listener = TcpListener::bind(&addr).await?;
        let bound = listener.local_addr()?;
        tracing::info!(addr = %bound, peer_id = %self.peer_id(), "listening (obfs-tcp)");
        self.state
            .lock()
            .await
            .record("listen", format!("obfs-tcp on {bound}"));

        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match ObfsTcp::accept(&listener, &psk, shaping.clone()).await {
                    Ok((mut stream, peer_addr)) => {
                        let node = this.clone();
                        tokio::spawn(async move {
                            match node.exchange_hello(&mut stream, false).await {
                                Ok(peer) => {
                                    tracing::info!(peer = %peer, from = %peer_addr, "inbound peer authenticated");
                                    let mut st = node.state.lock().await;
                                    st.connected.insert(peer);
                                    st.known.insert(peer);
                                    st.record("connect", format!("inbound {peer}"));
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, from = %peer_addr, "inbound peer rejected");
                                    node.state
                                        .lock()
                                        .await
                                        .record("reject", format!("inbound: {e}"));
                                }
                            }
                        });
                    }
                    Err(e) => {
                        // AuthFailed here is a probe being silently rejected — expected, debug-level.
                        tracing::debug!(error = %e, "inbound connection not authenticated");
                    }
                }
            }
        });
        Ok(bound)
    }

    /// Dial a peer endpoint, perform the obfs handshake, and exchange hellos.
    pub async fn dial_peer(
        self: &Arc<Self>,
        addr: &str,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
    ) -> Result<PeerId> {
        let mut stream = ObfsTcp::connect(addr, psk, shaping).await?;
        let peer = self.exchange_hello(&mut stream, true).await?;
        tracing::info!(peer = %peer, addr = %addr, "outbound peer authenticated");
        let mut st = self.state.lock().await;
        st.connected.insert(peer);
        st.known.insert(peer);
        st.record("connect", format!("outbound {peer} via {addr}"));
        Ok(peer)
    }

    /// A live status snapshot.
    pub async fn status(&self) -> NodeStatus {
        let st = self.state.lock().await;
        let mut transports = Vec::new();
        if self.config.listen.is_some() {
            transports.push(TransportStatus {
                kind: "obfs-tcp".into(),
                state: "listening".into(),
            });
        }
        NodeStatus {
            peer_id: self.peer_id().to_string(),
            profile: self.config.profile.clone(),
            listen: self.config.listen.clone(),
            bootstrap: self.config.bootstrap.clone(),
            psk_fingerprint: self.config.psk_fingerprint(),
            transports,
            peers: PeerCounts {
                connected: st.connected.len(),
                known: st.known.len(),
            },
            events: st.events.clone(),
        }
    }

    /// Full run: bind the listener, dial bootstraps, and block until Ctrl-C.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let psk = self.config.psk()?;
        let shaping = self.config.profile().shaping();

        if self.config.listen.is_some() {
            self.bind_listener(psk.clone(), shaping.clone()).await?;
        }
        for b in self.config.bootstrap.clone() {
            let this = self.clone();
            let psk2 = psk.clone();
            let sh = shaping.clone();
            tokio::spawn(async move {
                if let Err(e) = this.dial_peer(&b, &psk2, sh).await {
                    tracing::warn!(addr = %b, error = %e, "bootstrap dial failed");
                }
            });
        }

        tracing::info!("node running; press Ctrl-C to stop");
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn node(seed: u8, listen: Option<&str>) -> Arc<Node> {
        let id = NodeIdentity::from_seed(&[seed; 32]);
        let mut cfg = Config::default_with_psk("11".repeat(32));
        cfg.listen = listen.map(|s| s.to_string());
        cfg.profile = "aggressive".into();
        Arc::new(Node::new(id, cfg))
    }

    #[tokio::test]
    async fn two_nodes_authenticate_each_other() {
        let psk = ObfsPsk([0x11; 32]);
        let shaping = ShapingPolicy::aggressive();

        let server = node(1, Some("127.0.0.1:0"));
        let bound = server
            .bind_listener(psk.clone(), shaping.clone())
            .await
            .unwrap();

        let client = node(2, None);
        let learned = client
            .dial_peer(&bound.to_string(), &psk, shaping)
            .await
            .unwrap();
        assert_eq!(
            learned,
            server.peer_id(),
            "client must learn the server's PeerId"
        );

        // The server side authenticated the client too (give the spawned task a moment).
        for _ in 0..50 {
            let st = server.status().await;
            if st.peers.connected == 1 {
                assert!(st.peers.connected >= 1);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("server never recorded the inbound peer");
    }

    #[tokio::test]
    async fn wrong_psk_peer_cannot_join() {
        let server = node(1, Some("127.0.0.1:0"));
        let bound = server
            .bind_listener(ObfsPsk([0x11; 32]), ShapingPolicy::none())
            .await
            .unwrap();
        let client = node(2, None);
        // Different PSK ⇒ obfs gate fails ⇒ dial errors.
        let res = client
            .dial_peer(
                &bound.to_string(),
                &ObfsPsk([0x22; 32]),
                ShapingPolicy::none(),
            )
            .await;
        assert!(res.is_err());
    }
}
