//! Node runtime: bind an obfs listener, dial peers, and exchange authenticated hellos.
//!
//! This iteration carries an authenticated point-to-point hello over the obfs transport (proving the
//! crypto + obfs stack end-to-end). The full libp2p gossip/discovery/NAT mesh is layered on top in
//! the US2/US3 phases.
//!
//! ## Hello v2 (session-bound challenge-response)
//!
//! The v1 hello was a static `sign(own_vk)`, so any PSK-holding cohort peer that ever saw X's hello
//! could replay it and be recorded as X. v2 binds each proof to fresh per-session randomness:
//!
//! ```text
//! offer  = vk(32) ‖ challenge(32)                         # both sides, challenge = 32 fresh random bytes
//! proof  = Ed25519.sign(sk, HELLO_LABEL ‖ role(1) ‖ own_vk ‖ peer_vk ‖ own_challenge ‖ peer_challenge)
//! role   = 0x01 dialer | 0x02 listener
//! flow   : D→L offer_D;  L→D offer_L;  D→L proof_D;  L→D proof_L   (all inside the obfs SecureStream)
//! ```
//!
//! A proof is only valid for the verifier's own fresh challenge (no replay), names both endpoints'
//! keys (an identity cannot be re-targeted at a different verifier), and carries the signer's role
//! (no reflection). The listener verifies the dialer before revealing its own proof. The whole
//! exchange runs under [`HELLO_TIMEOUT`].
//!
//! Limitation: the obfs layer does not (yet) export a channel binding, so a PSK-holding peer that
//! actively relays a *live* session between two honest nodes is not detected here; binding the proof
//! to an exported handshake transcript hash would close that.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use umesh_crypto::identity::{self, NodeIdentity, PeerId};
use umesh_obfs::{ListenerConfig, ObfsListener, ObfsPsk, ObfsTcp, SecureStream, ShapingPolicy};

use crate::config::Config;
use crate::error::{NodeError, Result};
use crate::status::{Event, NodeStatus, PeerCounts, TransportStatus};

/// Domain-separation label for hello v2 proofs.
const HELLO_LABEL: &[u8] = b"uber-mesh node-hello v2";
const VK_LEN: usize = 32;
const CHALLENGE_LEN: usize = 32;
const OFFER_LEN: usize = VK_LEN + CHALLENGE_LEN;
const PROOF_LEN: usize = 64;
const ROLE_DIALER: u8 = 0x01;
const ROLE_LISTENER: u8 = 0x02;

/// Upper bound on the whole hello exchange (after the obfs handshake).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Overall upper bound on dialing + obfs handshake for an outbound connection (the obfs client
/// additionally bounds connect and handshake separately).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(25);
/// Upper bound on concurrent inbound sessions in the hello phase. (The obfs handshake phase is
/// bounded separately by [`ObfsListener`]'s in-flight cap.)
pub const MAX_PENDING_HELLOS: usize = 256;

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

/// One side's hello offer: its verifying key and a fresh challenge.
struct Offer {
    vk: [u8; VK_LEN],
    challenge: [u8; CHALLENGE_LEN],
}

impl Offer {
    fn encode(&self) -> [u8; OFFER_LEN] {
        let mut out = [0u8; OFFER_LEN];
        out[..VK_LEN].copy_from_slice(&self.vk);
        out[VK_LEN..].copy_from_slice(&self.challenge);
        out
    }

    fn decode(msg: &[u8]) -> Result<Self> {
        if msg.len() != OFFER_LEN {
            return Err(NodeError::PeerRejected("bad hello offer length".into()));
        }
        let mut vk = [0u8; VK_LEN];
        let mut challenge = [0u8; CHALLENGE_LEN];
        vk.copy_from_slice(&msg[..VK_LEN]);
        challenge.copy_from_slice(&msg[VK_LEN..]);
        Ok(Offer { vk, challenge })
    }
}

/// The byte string a hello proof signs, from the **signer's** perspective. `binding` is the obfs
/// session's channel binding, so a proof is valid only on the session it was made on: a cohort
/// peer relaying a live session between two honest nodes terminates two obfs sessions with
/// different bindings and cannot forward a valid proof from one to the other.
fn hello_transcript(
    signer_role: u8,
    signer: &Offer,
    verifier: &Offer,
    binding: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(HELLO_LABEL.len() + 1 + 2 * OFFER_LEN + 32);
    t.extend_from_slice(HELLO_LABEL);
    t.extend_from_slice(binding);
    t.push(signer_role);
    t.extend_from_slice(&signer.vk);
    t.extend_from_slice(&verifier.vk);
    t.extend_from_slice(&signer.challenge);
    t.extend_from_slice(&verifier.challenge);
    t
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

    /// A fresh offer for one session.
    fn new_offer(&self) -> Offer {
        let mut challenge = [0u8; CHALLENGE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        Offer {
            vk: self.identity.verifying_key().to_bytes(),
            challenge,
        }
    }

    /// Sign our proof for this session.
    fn prove(&self, role: u8, ours: &Offer, theirs: &Offer, binding: &[u8; 32]) -> [u8; PROOF_LEN] {
        self.identity
            .sign_bytes(&hello_transcript(role, ours, theirs, binding))
    }

    /// Verify the peer's proof for this session, returning its authenticated PeerId.
    fn verify_proof(
        peer_role: u8,
        theirs: &Offer,
        ours: &Offer,
        binding: &[u8; 32],
        proof: &[u8],
    ) -> Result<PeerId> {
        let sig: [u8; PROOF_LEN] = proof
            .try_into()
            .map_err(|_| NodeError::PeerRejected("bad hello proof length".into()))?;
        identity::verify(
            &theirs.vk,
            &hello_transcript(peer_role, theirs, ours, binding),
            &sig,
        )
        .map_err(|_| NodeError::PeerRejected("invalid hello signature".into()))
    }

    async fn exchange_hello<S>(&self, stream: &mut SecureStream<S>, we_dial: bool) -> Result<PeerId>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match tokio::time::timeout(HELLO_TIMEOUT, self.exchange_hello_inner(stream, we_dial)).await
        {
            Ok(r) => r,
            Err(_) => Err(NodeError::PeerRejected("hello timed out".into())),
        }
    }

    async fn exchange_hello_inner<S>(
        &self,
        stream: &mut SecureStream<S>,
        we_dial: bool,
    ) -> Result<PeerId>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let ours = self.new_offer();
        let (our_role, peer_role) = if we_dial {
            (ROLE_DIALER, ROLE_LISTENER)
        } else {
            (ROLE_LISTENER, ROLE_DIALER)
        };
        let check_offer = |theirs: &Offer| -> Result<()> {
            if theirs.vk == ours.vk {
                return Err(NodeError::PeerRejected("peer presented our own key".into()));
            }
            Ok(())
        };
        if we_dial {
            stream.send(&ours.encode()).await?;
            let theirs = Offer::decode(&stream.recv().await?)?;
            check_offer(&theirs)?;
            let binding = *stream.channel_binding();
            stream
                .send(&self.prove(our_role, &ours, &theirs, &binding))
                .await?;
            Self::verify_proof(peer_role, &theirs, &ours, &binding, &stream.recv().await?)
        } else {
            let theirs = Offer::decode(&stream.recv().await?)?;
            check_offer(&theirs)?;
            stream.send(&ours.encode()).await?;
            // Authenticate the dialer before revealing our own proof.
            let binding = *stream.channel_binding();
            let peer =
                Self::verify_proof(peer_role, &theirs, &ours, &binding, &stream.recv().await?)?;
            stream
                .send(&self.prove(our_role, &ours, &theirs, &binding))
                .await?;
            Ok(peer)
        }
    }

    /// Bind an obfs-tcp listener and spawn the accept loop. Returns the bound address.
    ///
    /// The obfs server handshake runs per connection inside [`ObfsListener`] (probes get silence),
    /// and each authenticated session's hello runs in its own task (bounded by
    /// [`MAX_PENDING_HELLOS`] and [`HELLO_TIMEOUT`]), so a slow or silent client cannot stall other
    /// inbound connections.
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
        let mut listener =
            ObfsListener::bind(&addr, psk, shaping, ListenerConfig::default()).await?;
        let bound = listener.local_addr();
        tracing::info!(addr = %bound, peer_id = %self.peer_id(), "listening (obfs-tcp)");
        self.state
            .lock()
            .await
            .record("listen", format!("obfs-tcp on {bound}"));

        let this = self.clone();
        let hellos = Arc::new(Semaphore::new(MAX_PENDING_HELLOS));
        tokio::spawn(async move {
            loop {
                let Ok(permit) = hellos.clone().acquire_owned().await else {
                    return;
                };
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(error = %e, "obfs listener stopped");
                        return;
                    }
                };
                let node = this.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    node.handle_inbound(stream, peer_addr).await;
                });
            }
        });
        Ok(bound)
    }

    /// Hello for one authenticated inbound obfs session.
    async fn handle_inbound(&self, mut stream: SecureStream<TcpStream>, peer_addr: SocketAddr) {
        match self.exchange_hello(&mut stream, false).await {
            Ok(peer) => {
                tracing::info!(peer = %peer, from = %peer_addr, "inbound peer authenticated");
                let mut st = self.state.lock().await;
                st.connected.insert(peer);
                st.known.insert(peer);
                st.record("connect", format!("inbound {peer}"));
            }
            Err(e) => {
                tracing::warn!(error = %e, from = %peer_addr, "inbound peer rejected");
                self.state
                    .lock()
                    .await
                    .record("reject", format!("inbound: {e}"));
            }
        }
    }

    /// Dial a peer endpoint, perform the obfs handshake, and exchange hellos.
    pub async fn dial_peer(
        self: &Arc<Self>,
        addr: &str,
        psk: &ObfsPsk,
        shaping: ShapingPolicy,
    ) -> Result<PeerId> {
        let mut stream = tokio::time::timeout(DIAL_TIMEOUT, ObfsTcp::connect(addr, psk, shaping))
            .await
            .map_err(|_| {
                NodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "dial/obfs handshake timed out",
                ))
            })??;
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
        let shaping = self.config.profile()?.shaping();

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
        let psk = ObfsPsk::new([0x11; 32]);
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

    /// A connected pair of `SecureStream`s over an in-memory duplex (no obfs handshake), so the
    /// hello can be driven message-by-message by a test "attacker" that holds the session keys —
    /// i.e. a PSK-holding cohort peer.
    fn secure_pair() -> (
        SecureStream<tokio::io::DuplexStream>,
        SecureStream<tokio::io::DuplexStream>,
    ) {
        secure_pair_bound([7; 32])
    }

    /// Like [`secure_pair`], with an explicit obfs channel binding for the session.
    fn secure_pair_bound(
        binding: [u8; 32],
    ) -> (
        SecureStream<tokio::io::DuplexStream>,
        SecureStream<tokio::io::DuplexStream>,
    ) {
        use umesh_crypto::aead::AeadKey;
        use umesh_obfs::SessionKeys;
        let (a, b) = tokio::io::duplex(1 << 16);
        let ka = SessionKeys {
            send: AeadKey::from_bytes([1; 32]),
            recv: AeadKey::from_bytes([2; 32]),
            send_dir: 0,
            recv_dir: 1,
            channel_binding: binding,
        };
        let kb = SessionKeys {
            send: AeadKey::from_bytes([2; 32]),
            recv: AeadKey::from_bytes([1; 32]),
            send_dir: 1,
            recv_dir: 0,
            channel_binding: binding,
        };
        (
            SecureStream::new(a, ka, ShapingPolicy::none()),
            SecureStream::new(b, kb, ShapingPolicy::none()),
        )
    }

    /// A PSK-holding cohort peer M splices a LIVE session: X dials M, M dials S, and M forwards
    /// every hello message verbatim between them. The two obfs sessions have different channel
    /// bindings, so neither proof verifies on the other leg — M cannot get recorded as X at S.
    #[tokio::test]
    async fn hello_relay_between_two_sessions_fails() {
        let (x, s) = (node(1, None), node(2, None));
        let (mut x_side, mut m_from_x) = secure_pair_bound([0xA1; 32]);
        let (mut m_to_s, mut s_side) = secure_pair_bound([0xB2; 32]);
        let relay = tokio::spawn(async move {
            // Dialer flow: X→offer, S→offer, X→proof, S→proof. Forward until either leg fails.
            for from_x in [true, false, true, false] {
                let msg = if from_x {
                    m_from_x.recv().await
                } else {
                    m_to_s.recv().await
                };
                let Ok(msg) = msg else { return };
                let sent = if from_x {
                    m_to_s.send(&msg).await
                } else {
                    m_from_x.send(&msg).await
                };
                if sent.is_err() {
                    return;
                }
            }
        });
        let s2 = s.clone();
        let srv = tokio::spawn(async move { s2.exchange_hello(&mut s_side, false).await });
        let dial = x.exchange_hello(&mut x_side, true).await;
        assert!(
            srv.await.unwrap().is_err(),
            "S must reject a proof made on another session"
        );
        assert!(
            dial.is_err(),
            "X must not authenticate S through the splice"
        );
        relay.abort();
    }

    #[tokio::test]
    async fn hello_authenticates_both_sides() {
        let (x, s) = (node(1, None), node(2, None));
        let (mut a, mut b) = secure_pair();
        let s2 = s.clone();
        let srv = tokio::spawn(async move { s2.exchange_hello(&mut b, false).await });
        assert_eq!(x.exchange_hello(&mut a, true).await.unwrap(), s.peer_id());
        assert_eq!(srv.await.unwrap().unwrap(), x.peer_id());
    }

    /// The v1 hello (`peer_id ‖ vk ‖ sign(vk)`) was a static credential: a cohort peer that saw it
    /// once could replay it to be recorded as X. A v2 proof recorded from a live X↔S session (here
    /// via a PSK-holding relay) must not authenticate a *new* session to S.
    #[tokio::test]
    async fn replayed_hello_is_rejected() {
        let (x, s) = (node(1, None), node(2, None));

        // Session 1: X ↔ relay(M) ↔ S, M records X's offer and proof in the clear.
        let (mut xa, mut ma) = secure_pair();
        let (mut mb, mut sb) = secure_pair();
        let (x2, s2) = (x.clone(), s.clone());
        let xt = tokio::spawn(async move { x2.exchange_hello(&mut xa, true).await });
        let st = tokio::spawn(async move { s2.exchange_hello(&mut sb, false).await });
        let offer_x = ma.recv().await.unwrap();
        mb.send(&offer_x).await.unwrap();
        ma.send(&mb.recv().await.unwrap()).await.unwrap();
        let proof_x = ma.recv().await.unwrap();
        mb.send(&proof_x).await.unwrap();
        ma.send(&mb.recv().await.unwrap()).await.unwrap();
        assert_eq!(st.await.unwrap().unwrap(), x.peer_id());
        assert_eq!(xt.await.unwrap().unwrap(), s.peer_id());

        // Session 2: M replays X's recorded offer + proof to S.
        let (mut m, mut sc) = secure_pair();
        let s3 = s.clone();
        let st = tokio::spawn(async move { s3.exchange_hello(&mut sc, false).await });
        m.send(&offer_x).await.unwrap();
        let _fresh_offer_s = m.recv().await.unwrap();
        m.send(&proof_x).await.unwrap();
        let res = st.await.unwrap();
        assert!(
            matches!(res, Err(NodeError::PeerRejected(_))),
            "replayed hello must be rejected, got {res:?}"
        );

        // The static v1 hello format is rejected outright.
        let (mut m, mut sc) = secure_pair();
        let s4 = s.clone();
        let st = tokio::spawn(async move { s4.exchange_hello(&mut sc, false).await });
        let ident = NodeIdentity::from_seed(&[1; 32]);
        let vk = ident.verifying_key().to_bytes();
        let mut v1 = Vec::new();
        v1.extend_from_slice(ident.peer_id().as_bytes());
        v1.extend_from_slice(&vk);
        v1.extend_from_slice(&ident.sign_bytes(&vk));
        m.send(&v1).await.unwrap();
        assert!(st.await.unwrap().is_err());
    }

    /// A proof X produced for verifier M (naming M's key) cannot be redirected to S, even if M
    /// echoes S's challenge to X — the transcript names the verifier's key.
    #[tokio::test]
    async fn hello_proof_is_bound_to_the_verifier() {
        let (x, s) = (node(1, None), node(2, None));
        let m_id = NodeIdentity::from_seed(&[9; 32]);

        // M opens a session to S first, claiming to be X, and learns S's challenge.
        let (mut ms, mut sc) = secure_pair();
        let s2 = s.clone();
        let st = tokio::spawn(async move { s2.exchange_hello(&mut sc, false).await });
        let (mut xa, mut ma) = secure_pair();
        let x2 = x.clone();
        let xt = tokio::spawn(async move { x2.exchange_hello(&mut xa, true).await });
        let offer_x = ma.recv().await.unwrap();
        ms.send(&offer_x).await.unwrap();
        let offer_s = Offer::decode(&ms.recv().await.unwrap()).unwrap();
        // M answers X with its own key but S's challenge, to get X to sign over S's challenge.
        let m_offer = Offer {
            vk: m_id.verifying_key().to_bytes(),
            challenge: offer_s.challenge,
        };
        ma.send(&m_offer.encode()).await.unwrap();
        let proof_x = ma.recv().await.unwrap();
        ms.send(&proof_x).await.unwrap();
        assert!(
            st.await.unwrap().is_err(),
            "proof for M must not verify at S"
        );
        drop(ma);
        assert!(xt.await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_hello_times_out() {
        let s = node(2, None);
        let (_held_open, mut sc) = secure_pair();
        let res = s.exchange_hello(&mut sc, false).await;
        assert!(
            matches!(&res, Err(NodeError::PeerRejected(m)) if m.contains("timed out")),
            "{res:?}"
        );
    }

    /// A connection that never sends a ClientHello must not stall other inbound peers.
    #[tokio::test]
    async fn stalled_inbound_does_not_block_accept_loop() {
        let psk = ObfsPsk::new([0x11; 32]);
        let server = node(1, Some("127.0.0.1:0"));
        let bound = server
            .bind_listener(psk.clone(), ShapingPolicy::none())
            .await
            .unwrap();
        let _stalled = tokio::net::TcpStream::connect(bound).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = node(2, None);
        let learned = tokio::time::timeout(
            Duration::from_secs(5),
            client.dial_peer(&bound.to_string(), &psk, ShapingPolicy::none()),
        )
        .await
        .expect("accept loop blocked by a stalled connection")
        .unwrap();
        assert_eq!(learned, server.peer_id());
    }

    #[tokio::test]
    async fn wrong_psk_peer_cannot_join() {
        let server = node(1, Some("127.0.0.1:0"));
        let bound = server
            .bind_listener(ObfsPsk::new([0x11; 32]), ShapingPolicy::none())
            .await
            .unwrap();
        let client = node(2, None);
        // Different PSK ⇒ obfs gate fails ⇒ dial errors.
        let res = client
            .dial_peer(
                &bound.to_string(),
                &ObfsPsk::new([0x22; 32]),
                ShapingPolicy::none(),
            )
            .await;
        assert!(res.is_err());
    }
}
