//! High-level mesh node: drives the swarm, publishes signed messages, validates inbound messages
//! before gossipsub re-propagates them.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use futures::StreamExt;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm, gossipsub, identify, relay};
use umesh_crypto::hash::Cid;
use umesh_crypto::identity::NodeIdentity;
use umesh_obfs::{ObfsPsk, ProbeResponse, ShapingPolicy};

use crate::behaviour::{KAD_PROTOCOL, MeshBehaviour, MeshBehaviourEvent};
use crate::blobs::{BlobRequest, BlobResponse, MAX_BLOB};
use crate::bounded::RateLimiter;
use crate::error::{P2pError, Result};
use crate::gossip::{self, ReplayGuard, SignedMessage};
use crate::metrics;
use crate::reconcile::{self, Reconciler};
use crate::sealed::{self, ContentKey, SealedBlobRef, SealedPayload, SealedTopic, TopicKey};
use crate::store::ContentStore;
use crate::sync::ReconcileMsg;

/// Per-peer blob serving budget: burst (bytes).
pub const BLOB_BURST_BYTES: f64 = 64.0 * 1024.0 * 1024.0;
/// Per-peer blob serving budget: sustained rate (bytes/s).
pub const BLOB_RATE_BYTES: f64 = 8.0 * 1024.0 * 1024.0;
/// Minimum cost charged per blob request (so "not found" spam isn't free).
const BLOB_MIN_COST: f64 = 4096.0;
/// Per-peer reconcile budget: burst (request units; a request costs `1 + segments/1024`).
pub const RECONCILE_BURST: f64 = 32.0;
/// Per-peer reconcile budget: sustained units/s.
pub const RECONCILE_RATE: f64 = 4.0;
/// Peers tracked by each rate limiter (bounded; connection limits bound it further in practice).
const RATE_LIMIT_PEERS: usize = 4096;
/// Max addresses taken from one peer's identify record into Kademlia.
const MAX_IDENTIFY_ADDRS: usize = 8;

/// In-flight set-reconciliation session with one peer.
struct SyncSession {
    rec: Reconciler,
    local: Vec<[u8; 32]>,
    /// The outstanding request of this session (stale responses from a replaced session are dropped).
    request: OutboundRequestId,
    rounds: usize,
}

/// Events surfaced to the application from [`MeshNode::next_event`].
#[derive(Debug)]
pub enum MeshEvent {
    /// A validated application message on a subscribed topic.
    ///
    /// On a topic this node holds a key for, only sealed messages that decrypt under it are
    /// delivered (`sealed: true`); on a topic without a key, only public messages are (sealed ones
    /// are forwarded unread).
    Message {
        /// Topic id.
        topic: String,
        /// Application-layer sender PeerId (`BLAKE3(pubkey)`), authenticated.
        sender: umesh_crypto::identity::PeerId,
        /// Application payload (decrypted, if `sealed`).
        payload: Vec<u8>,
        /// Whether the payload was end-to-end encrypted under the topic key (unreadable to
        /// forwarders). `false` = public topic: every forwarding peer could read it.
        sealed: bool,
    },
    /// A member of a sealed topic shared an encrypted blob. Fetch it with
    /// [`MeshNode::request_sealed_blob`] from `provider` (or any peer that mirrors the ciphertext);
    /// it arrives decrypted as [`MeshEvent::BlobReceived`].
    SealedBlob {
        /// Topic id.
        topic: String,
        /// Application-layer sender PeerId, authenticated.
        sender: umesh_crypto::identity::PeerId,
        /// libp2p PeerId of the original publisher (gossipsub `source`), a natural first provider.
        provider: Option<PeerId>,
        /// `Cid` of the ciphertext + the key that decrypts it.
        blob: SealedBlobRef,
    },
    /// A transport-level peer connection was established.
    PeerConnected(PeerId),
    /// A transport-level peer connection closed.
    PeerDisconnected(PeerId),
    /// The node started listening on a new address.
    Listening(Multiaddr),
    /// A requested blob arrived and was verified against its `Cid`.
    ///
    /// For a public blob (`request_blob`), `data` is the content and `BLAKE3(data) == cid`. For a
    /// sealed blob (`request_sealed_blob`), the `cid` was verified over the received ciphertext
    /// (which is what this node stores and re-serves) and `data` is the decrypted plaintext.
    BlobReceived {
        /// Content id (verified against the received bytes).
        cid: Cid,
        /// The verified (and, for a sealed blob, decrypted) content bytes.
        data: Vec<u8>,
    },
    /// A requested blob was unavailable (peer didn't have it, or it failed verification).
    BlobUnavailable {
        /// The requested content id.
        cid: Cid,
    },
    /// Set reconciliation with a peer converged.
    SyncComplete {
        /// The peer reconciled with.
        peer: PeerId,
        /// Content ids the peer has that we lack (fetch these via `request_blob`).
        need: Vec<Cid>,
        /// Content ids we have that the peer lacks (offer/announce these).
        have_extra: Vec<Cid>,
    },
    /// Set reconciliation with a peer failed (connection/transport error).
    SyncFailed {
        /// The peer.
        peer: PeerId,
    },
}

/// A running mesh node.
pub struct MeshNode {
    swarm: Swarm<MeshBehaviour>,
    identity: NodeIdentity,
    /// This identity's proof-of-work nonce, carried in every published message.
    pow_nonce: u64,
    /// Sender PoW required of inbound messages (the network-wide minimum outside tests).
    min_pow_bits: u32,
    guard: ReplayGuard,
    seqno: u64,
    store: ContentStore,
    /// Topics this node holds a key for (end-to-end sealed). Zeroized on drop.
    sealed_topics: HashMap<String, SealedTopic>,
    /// Outstanding blob requests: the cid and, for a sealed blob, the key that decrypts it.
    pending_blobs: HashMap<OutboundRequestId, (Cid, Option<ContentKey>)>,
    sync_sessions: HashMap<PeerId, SyncSession>,
    pending_reconcile: HashMap<OutboundRequestId, PeerId>,
    blob_limiter: RateLimiter<PeerId>,
    reconcile_limiter: RateLimiter<PeerId>,
    relay_reservations: HashSet<PeerId>,
}

impl MeshNode {
    /// Build a mesh node from a 32-byte Ed25519 seed (shared with the application identity), the
    /// identity's proof-of-work nonce (mined once, see [`umesh_crypto::pow::mine_identity`]) and the
    /// obfs PSK that gates the obfuscated carrier (shared out-of-band among the cohort), with no
    /// traffic shaping and silent probe rejection. Prefer [`MeshNode::with_transport`] with the
    /// active environment profile's settings.
    ///
    /// Fails with [`MsgError::InsufficientPow`](crate::MsgError::InsufficientPow) if `pow_nonce`
    /// does not prove [`gossip::MIN_SENDER_POW_BITS`] for this identity (every peer would reject
    /// its messages and penalize it).
    pub fn new(seed: &[u8; 32], pow_nonce: u64, psk: ObfsPsk) -> Result<Self> {
        Self::with_transport(
            seed,
            pow_nonce,
            psk,
            ShapingPolicy::none(),
            ProbeResponse::Silence,
        )
    }

    /// Build a mesh node whose obfs carrier uses the profile's `shaping` policy and answers
    /// failed-gate probes with `probe` (silence or cover-site fallback). See [`MeshNode::new`].
    pub fn with_transport(
        seed: &[u8; 32],
        pow_nonce: u64,
        psk: ObfsPsk,
        shaping: ShapingPolicy,
        probe: ProbeResponse,
    ) -> Result<Self> {
        Self::with_pow_policy(
            seed,
            pow_nonce,
            gossip::MIN_SENDER_POW_BITS,
            psk,
            shaping,
            probe,
        )
    }

    /// [`MeshNode::with_transport`] with a non-default sender-PoW difficulty, applied both to this
    /// node's own nonce and to inbound messages. **Tests / isolated devnets only**: every node of a
    /// mesh must use the same value — a node accepting less than its peers relays messages they
    /// `Reject` and is penalized (graylisted) for it.
    #[doc(hidden)]
    pub fn with_pow_policy(
        seed: &[u8; 32],
        pow_nonce: u64,
        min_pow_bits: u32,
        psk: ObfsPsk,
        shaping: ShapingPolicy,
        probe: ProbeResponse,
    ) -> Result<Self> {
        Self::build(
            seed,
            pow_nonce,
            min_pow_bits,
            psk,
            shaping,
            probe,
            umesh_obfs::ClientConfig::default(),
        )
    }

    /// [`MeshNode::with_transport`] with explicit dial-side obfs options — notably the cohort's
    /// cover domain (`ClientConfig::cover_domain`), which must equal the listeners' cover domain so
    /// the SNI matches the cover site whose server flight they mimic.
    pub fn with_transport_client(
        seed: &[u8; 32],
        pow_nonce: u64,
        psk: ObfsPsk,
        shaping: ShapingPolicy,
        probe: ProbeResponse,
        client: umesh_obfs::ClientConfig,
    ) -> Result<Self> {
        Self::build(
            seed,
            pow_nonce,
            gossip::MIN_SENDER_POW_BITS,
            psk,
            shaping,
            probe,
            client,
        )
    }

    fn build(
        seed: &[u8; 32],
        pow_nonce: u64,
        min_pow_bits: u32,
        psk: ObfsPsk,
        shaping: ShapingPolicy,
        probe: ProbeResponse,
        client: umesh_obfs::ClientConfig,
    ) -> Result<Self> {
        let identity = NodeIdentity::from_seed(seed);
        if !umesh_crypto::pow::verify_identity(
            &identity.verifying_key().to_bytes(),
            pow_nonce,
            min_pow_bits,
        ) {
            return Err(gossip::MsgError::InsufficientPow.into());
        }
        Ok(MeshNode {
            swarm: crate::behaviour::build_swarm(seed, psk, shaping, probe, client)?,
            identity,
            pow_nonce,
            min_pow_bits,
            guard: ReplayGuard::default(),
            seqno: 0,
            store: ContentStore::new(),
            sealed_topics: HashMap::new(),
            pending_blobs: HashMap::new(),
            sync_sessions: HashMap::new(),
            pending_reconcile: HashMap::new(),
            blob_limiter: RateLimiter::new(BLOB_BURST_BYTES, BLOB_RATE_BYTES, RATE_LIMIT_PEERS),
            reconcile_limiter: RateLimiter::new(RECONCILE_BURST, RECONCILE_RATE, RATE_LIMIT_PEERS),
            relay_reservations: HashSet::new(),
        })
    }

    /// Begin set reconciliation with `peer`: discover which content ids each side is missing. The
    /// result arrives as a [`MeshEvent::SyncComplete`] (or `SyncFailed`). Restarting a sync with
    /// the same peer replaces the previous session.
    pub fn start_sync(&mut self, peer: PeerId) {
        let local = self.store.ids_sorted();
        let first = reconcile::initiate(&local);
        let id = self
            .swarm
            .behaviour_mut()
            .reconcile
            .send_request(&peer, ReconcileMsg(first));
        self.pending_reconcile.insert(id, peer);
        self.sync_sessions.insert(
            peer,
            SyncSession {
                rec: Reconciler::default(),
                local,
                request: id,
                rounds: 0,
            },
        );
    }

    /// Advance a reconciliation session with the responder's message. Returns the event to
    /// surface, if the session ended.
    fn on_reconcile_response(
        &mut self,
        peer: PeerId,
        request_id: OutboundRequestId,
        response: ReconcileMsg,
    ) -> Option<MeshEvent> {
        let session = self.sync_sessions.get_mut(&peer)?;
        if session.request != request_id {
            return None; // stale response from a replaced session
        }
        session.rounds += 1;
        let next = match session.rec.refine(&session.local, &response.0) {
            Ok(next) if session.rounds < reconcile::MAX_ROUNDS => next,
            Ok(_) | Err(_) => {
                tracing::debug!(%peer, "reconciliation aborted (invalid response or round cap)");
                self.sync_sessions.remove(&peer);
                return Some(MeshEvent::SyncFailed { peer });
            }
        };
        if reconcile::is_converged(&next) {
            let diff = std::mem::take(&mut session.rec.diff);
            self.sync_sessions.remove(&peer);
            metrics::inc(&metrics::SYNC_COMPLETED);
            return Some(MeshEvent::SyncComplete {
                peer,
                need: diff.need.into_iter().map(Cid).collect(),
                have_extra: diff.have_extra.into_iter().map(Cid).collect(),
            });
        }
        let id = self
            .swarm
            .behaviour_mut()
            .reconcile
            .send_request(&peer, ReconcileMsg(next));
        session.request = id;
        self.pending_reconcile.insert(id, peer);
        None
    }

    /// Store **public** content locally and return its `Cid` (this node can now serve it to
    /// peers). Every peer that fetches or mirrors it can read it; for confidential content use
    /// [`MeshNode::seal_blob`].
    pub fn provide(&mut self, data: Vec<u8>) -> Cid {
        self.store.put(data)
    }

    /// Request a public blob by `Cid` from a specific peer. The result arrives as a [`MeshEvent`]
    /// (`BlobReceived` once verified, or `BlobUnavailable`). Also how a non-member mirrors a sealed
    /// blob: it stores and serves the ciphertext without being able to read it.
    pub fn request_blob(&mut self, peer: PeerId, cid: Cid) -> OutboundRequestId {
        self.send_blob_request(peer, cid, None)
    }

    /// Request a sealed blob (from a [`MeshEvent::SealedBlob`]) from a specific peer. The
    /// ciphertext is verified against the `Cid`, stored (so this node can serve it on — still
    /// encrypted) and decrypted; the plaintext arrives as `BlobReceived` (or `BlobUnavailable` if
    /// it is missing, fails the `Cid`, or does not decrypt).
    pub fn request_sealed_blob(&mut self, peer: PeerId, blob: &SealedBlobRef) -> OutboundRequestId {
        self.send_blob_request(peer, blob.cid, Some(blob.key.clone()))
    }

    fn send_blob_request(
        &mut self,
        peer: PeerId,
        cid: Cid,
        key: Option<ContentKey>,
    ) -> OutboundRequestId {
        let id = self.swarm.behaviour_mut().blobs.send_request(
            &peer,
            BlobRequest {
                cid: *cid.as_bytes(),
            },
        );
        self.pending_blobs.insert(id, (cid, key));
        id
    }

    /// Encrypt `data` under a fresh content key for the sealed `topic` and store the **ciphertext**
    /// (its `Cid` is over the ciphertext, so serving peers verify it without reading it). Share the
    /// returned reference with [`MeshNode::announce_blob`]. Fails if `topic` has no key.
    pub fn seal_blob(&mut self, topic: &str, data: &[u8]) -> Result<SealedBlobRef> {
        if !self.sealed_topics.contains_key(topic) {
            return Err(P2pError::Publish(format!(
                "topic {topic:?} is not sealed (no topic key); use provide() for public content"
            )));
        }
        let (ct, blob) = sealed::seal_blob(data)?;
        self.store.put(ct);
        Ok(blob)
    }

    /// Announce a sealed blob to the members of `topic`: `(cid, content_key)` travels inside a
    /// sealed message, so only key holders learn the key (or even the `Cid`).
    pub fn announce_blob(&mut self, topic: &str, blob: &SealedBlobRef) -> Result<()> {
        if !self.sealed_topics.contains_key(topic) {
            return Err(P2pError::Publish(format!(
                "topic {topic:?} is not sealed (no topic key)"
            )));
        }
        let msg = self.sign_next_payload(topic, SealedPayload::Blob(blob.clone()));
        self.publish_signed(topic, msg)
    }

    /// The raw bytes this node stores (and would serve) under `cid` — for a sealed blob, the
    /// ciphertext.
    pub fn stored(&self, cid: &Cid) -> Option<&[u8]> {
        self.store.get(cid)
    }

    /// Hold `key` for `topic`: from now on this node seals what it publishes on `topic` and
    /// delivers only sealed messages there that decrypt under the key (public ones are refused as a
    /// downgrade). Replaces (and wipes) any previous key for the topic. Key material is never
    /// logged.
    pub fn set_topic_key(&mut self, topic: &str, key: &TopicKey) {
        self.sealed_topics
            .insert(topic.to_string(), SealedTopic::new(topic, key));
    }

    /// Drop (and wipe) the key for `topic`, making it public again for this node. Returns whether a
    /// key was held.
    pub fn clear_topic_key(&mut self, topic: &str) -> bool {
        self.sealed_topics.remove(topic).is_some()
    }

    /// Whether this node holds a key for `topic` (its payloads are end-to-end encrypted).
    pub fn is_sealed(&self, topic: &str) -> bool {
        self.sealed_topics.contains_key(topic)
    }

    /// Whether a transport connection to `peer` is currently open.
    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.swarm.is_connected(peer)
    }

    /// libp2p transport PeerId (multihash of the public key).
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Application-layer PeerId (`BLAKE3(pubkey)`).
    pub fn app_peer_id(&self) -> umesh_crypto::identity::PeerId {
        self.identity.peer_id()
    }

    /// This identity's proof-of-work nonce (public; carried in every published message).
    pub fn pow_nonce(&self) -> u64 {
        self.pow_nonce
    }

    /// Start listening on a multiaddr (e.g. `/ip4/127.0.0.1/tcp/0`).
    pub fn listen(&mut self, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| P2pError::Address(e.to_string()))?;
        self.swarm
            .listen_on(ma)
            .map_err(|e| P2pError::Address(e.to_string()))?;
        Ok(())
    }

    /// Dial a peer multiaddr.
    pub fn dial(&mut self, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| P2pError::Address(e.to_string()))?;
        self.swarm
            .dial(ma)
            .map_err(|e| P2pError::Address(e.to_string()))?;
        Ok(())
    }

    /// Subscribe to a gossip topic (and install its peer-scoring parameters, so invalid messages
    /// on it cost the forwarder — P4).
    pub fn subscribe(&mut self, topic: &str) -> Result<()> {
        let t = gossipsub::IdentTopic::new(topic);
        let gs = &mut self.swarm.behaviour_mut().gossipsub;
        gs.set_topic_params(t.clone(), crate::behaviour::topic_score_params())
            .map_err(|e| P2pError::Subscribe(e.to_string()))?;
        gs.subscribe(&t)
            .map_err(|e| P2pError::Subscribe(e.to_string()))?;
        Ok(())
    }

    /// Sign the next outgoing application message: sealed (v3) if this node holds a key for
    /// `topic`, public (v2) otherwise. The seqno is time-based (`max(last + 1, now_µs)`) so it keeps
    /// increasing across restarts of the same identity.
    fn sign_next(&mut self, topic: &str, payload: Vec<u8>) -> SignedMessage {
        if self.sealed_topics.contains_key(topic) {
            return self.sign_next_payload(topic, SealedPayload::Data(payload));
        }
        self.seqno = gossip::next_seqno(self.seqno, gossip::now_micros());
        SignedMessage::create_with_pow(
            &self.identity,
            self.pow_nonce,
            topic,
            payload,
            self.seqno,
            gossip::now_millis(),
        )
    }

    /// Seal `payload` for a topic this node holds a key for, and sign it (v3).
    fn sign_next_payload(&mut self, topic: &str, payload: SealedPayload) -> SignedMessage {
        let st = &self.sealed_topics[topic];
        self.seqno = gossip::next_seqno(self.seqno, gossip::now_micros());
        sealed::seal_message(
            &self.identity,
            self.pow_nonce,
            st,
            &payload,
            self.seqno,
            gossip::now_millis(),
        )
    }

    /// Publish an application message to a topic: end-to-end sealed if this node holds the topic's
    /// key ([`MeshNode::set_topic_key`]), otherwise public (signed, but readable by every peer that
    /// forwards it).
    pub fn publish(&mut self, topic: &str, payload: Vec<u8>) -> Result<()> {
        let msg = self.sign_next(topic, payload);
        self.publish_signed(topic, msg)
    }

    fn publish_signed(&mut self, topic: &str, msg: SignedMessage) -> Result<()> {
        let t = gossipsub::IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(t, msg.encode())
            .map_err(|e| P2pError::Publish(e.to_string()))?;
        metrics::inc(&metrics::GOSSIP_PUBLISHED);
        Ok(())
    }

    /// Decide what a **validated** message delivers to the application. Runs after the gossipsub
    /// verdict was reported, so it never affects propagation: a node without the topic key forwards
    /// a valid sealed message exactly like a member does.
    ///
    /// | this node            | public (v2) message      | sealed (v3) message                      |
    /// |----------------------|--------------------------|------------------------------------------|
    /// | no key for the topic | delivered (`sealed=false`) | forwarded unread, not delivered        |
    /// | holds the topic key  | refused (downgrade)      | opened: delivered, or refused on failure |
    fn deliver(
        &self,
        topic: String,
        sender: umesh_crypto::identity::PeerId,
        m: SignedMessage,
        source: Option<PeerId>,
    ) -> Option<MeshEvent> {
        let Some(st) = self.sealed_topics.get(&topic) else {
            if m.sealed {
                metrics::inc(&metrics::GOSSIP_SEALED_UNREAD);
                return None;
            }
            return Some(MeshEvent::Message {
                topic,
                sender,
                payload: m.payload,
                sealed: false,
            });
        };
        match sealed::open_message(st, &m) {
            Ok(SealedPayload::Data(payload)) => Some(MeshEvent::Message {
                topic,
                sender,
                payload,
                sealed: true,
            }),
            Ok(SealedPayload::Blob(blob)) => Some(MeshEvent::SealedBlob {
                topic,
                sender,
                provider: source,
                blob,
            }),
            Err(e) => {
                metrics::inc(&metrics::GOSSIP_SEALED_REFUSED);
                tracing::debug!(error = %e, "sealed-topic message not delivered");
                None
            }
        }
    }

    /// Drive the swarm until the next application-relevant event.
    pub async fn next_event(&mut self) -> MeshEvent {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(MeshBehaviourEvent::Gossipsub(
                    gossipsub::Event::Message {
                        propagation_source,
                        message_id,
                        message,
                    },
                )) => {
                    let now = gossip::now_millis();
                    let topic = message.topic.to_string();
                    // Verdicts depend only on the message (topic binding, signature, replay state),
                    // never on which peer forwarded it: gossipsub caches the verdict by message-id,
                    // so a forwarder-based Ignore would also drop honest copies from other peers.
                    let verdict = SignedMessage::decode(&message.data).and_then(|m| {
                        gossip::validate_on_topic_with_pow(
                            &m,
                            message.topic.as_str(),
                            &mut self.guard,
                            now,
                            self.min_pow_bits,
                        )
                        .map(|p| (m, p))
                    });
                    let acceptance = match &verdict {
                        Ok(_) => gossipsub::MessageAcceptance::Accept,
                        // Provably invalid ⇒ Reject: not propagated, forwarder penalized (P4).
                        Err(e) if e.is_invalid() => {
                            metrics::inc(&metrics::GOSSIP_REJECTED);
                            tracing::debug!(error = %e, "rejected invalid gossip message");
                            gossipsub::MessageAcceptance::Reject
                        }
                        // Replay/duplicate/stale ⇒ Ignore: not propagated, not penalized.
                        Err(e) => {
                            metrics::inc(&metrics::GOSSIP_IGNORED);
                            tracing::trace!(error = %e, "ignored gossip message");
                            gossipsub::MessageAcceptance::Ignore
                        }
                    };
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            acceptance,
                        );
                    if let Ok((m, sender)) = verdict {
                        metrics::inc(&metrics::GOSSIP_RECEIVED);
                        if let Some(ev) = self.deliver(topic, sender, m, message.source) {
                            return ev;
                        }
                    }
                }
                SwarmEvent::Behaviour(MeshBehaviourEvent::Blobs(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        // Serve the blob from our store if we hold it, within the peer's budget.
                        let cid = Cid(request.cid);
                        let data = self
                            .store
                            .get(&cid)
                            .filter(|b| b.len() <= MAX_BLOB)
                            .map(|b| b.to_vec());
                        let cost = data.as_ref().map_or(0, Vec::len) as f64;
                        if !self
                            .blob_limiter
                            .check(peer, cost.max(BLOB_MIN_COST), Instant::now())
                        {
                            // Over budget: drop the channel (the peer sees a response omission).
                            metrics::inc(&metrics::REQUESTS_RATE_LIMITED);
                            continue;
                        }
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .blobs
                            .send_response(channel, BlobResponse { data });
                        metrics::inc(&metrics::BLOBS_SERVED);
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                        ..
                    } => {
                        if let Some((cid, key)) = self.pending_blobs.remove(&request_id) {
                            match response.data {
                                // Verify BLAKE3(bytes) == cid before trusting the content (FR-011).
                                Some(data) if cid.verifies(&data) => {
                                    let delivered = match key {
                                        None => {
                                            self.store.put(data.clone());
                                            data
                                        }
                                        // Sealed: decrypt; only the ciphertext goes in the store.
                                        Some(key) => {
                                            let blob = SealedBlobRef { cid, key };
                                            let Ok(pt) = sealed::open_blob(&blob, &data) else {
                                                return MeshEvent::BlobUnavailable { cid };
                                            };
                                            self.store.put(data);
                                            pt
                                        }
                                    };
                                    metrics::inc(&metrics::BLOBS_RECEIVED);
                                    return MeshEvent::BlobReceived {
                                        cid,
                                        data: delivered,
                                    };
                                }
                                _ => return MeshEvent::BlobUnavailable { cid },
                            }
                        }
                    }
                },
                SwarmEvent::Behaviour(MeshBehaviourEvent::Blobs(
                    request_response::Event::OutboundFailure { request_id, .. },
                )) => {
                    if let Some((cid, _)) = self.pending_blobs.remove(&request_id) {
                        return MeshEvent::BlobUnavailable { cid };
                    }
                }
                SwarmEvent::Behaviour(MeshBehaviourEvent::Reconcile(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        // Responder: answer this round from our current id set, within budget.
                        let cost = 1.0 + request.0.len() as f64 / 1024.0;
                        if !self.reconcile_limiter.check(peer, cost, Instant::now()) {
                            metrics::inc(&metrics::REQUESTS_RATE_LIMITED);
                            continue;
                        }
                        let local = self.store.ids_sorted();
                        match reconcile::respond(&local, &request.0) {
                            Ok(resp) => {
                                let _ = self
                                    .swarm
                                    .behaviour_mut()
                                    .reconcile
                                    .send_response(channel, ReconcileMsg(resp));
                            }
                            Err(e) => {
                                tracing::debug!(%peer, error = %e, "invalid reconcile request");
                            }
                        }
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        if let Some(peer) = self.pending_reconcile.remove(&request_id)
                            && let Some(ev) = self.on_reconcile_response(peer, request_id, response)
                        {
                            return ev;
                        }
                    }
                },
                SwarmEvent::Behaviour(MeshBehaviourEvent::Reconcile(
                    request_response::Event::OutboundFailure { request_id, .. },
                )) => {
                    if let Some(peer) = self.pending_reconcile.remove(&request_id)
                        && self
                            .sync_sessions
                            .get(&peer)
                            .is_some_and(|s| s.request == request_id)
                    {
                        self.sync_sessions.remove(&peer);
                        return MeshEvent::SyncFailed { peer };
                    }
                }
                SwarmEvent::Behaviour(MeshBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, info, .. },
                )) => {
                    // Feed the peer's self-reported listen addresses into our private DHT if it
                    // speaks `/uber-mesh/kad/1.0.0` (as a listener we otherwise never learn a
                    // dialable address for inbound peers).
                    if info.protocols.contains(&KAD_PROTOCOL) {
                        let kad = &mut self.swarm.behaviour_mut().kademlia;
                        for addr in info.listen_addrs.into_iter().take(MAX_IDENTIFY_ADDRS) {
                            kad.add_address(&peer_id, addr);
                        }
                    }
                }
                SwarmEvent::Behaviour(MeshBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
                )) => {
                    self.relay_reservations.insert(relay_peer_id);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    metrics::peers_delta(1);
                    return MeshEvent::PeerConnected(peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    metrics::peers_delta(-1);
                    return MeshEvent::PeerDisconnected(peer_id);
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return MeshEvent::Listening(address);
                }
                _ => continue,
            }
        }
    }

    /// Add a known peer address to the Kademlia routing table and (re)start a DHT bootstrap.
    pub fn add_address(&mut self, peer: PeerId, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| P2pError::Address(e.to_string()))?;
        let kad = &mut self.swarm.behaviour_mut().kademlia;
        kad.add_address(&peer, ma);
        let _ = kad.bootstrap(); // only fails with no known peers, which we just ruled out
        Ok(())
    }

    /// Declare an operator-known public address of this node (e.g. a port-forwarded/static
    /// address). It is treated as confirmed: Kademlia switches to server mode and the relay can
    /// hand out reservations. Addresses are otherwise confirmed automatically by AutoNAT v2.
    pub fn add_external_address(&mut self, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| P2pError::Address(e.to_string()))?;
        self.swarm.add_external_address(ma);
        Ok(())
    }

    /// Run a Kademlia bootstrap now (also runs periodically once peers are known).
    pub fn bootstrap(&mut self) -> Result<()> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map(|_| ())
            .map_err(|e| P2pError::Init(e.to_string()))
    }

    /// Whether Kademlia is in server mode (answers DHT queries; requires a confirmed address).
    pub fn kad_is_server(&self) -> bool {
        self.swarm.behaviour().kademlia.mode() == libp2p::kad::Mode::Server
    }

    /// Peers currently in our Kademlia routing table.
    pub fn kad_peers(&mut self) -> Vec<PeerId> {
        let mut out = Vec::new();
        for bucket in self.swarm.behaviour_mut().kademlia.kbuckets() {
            for e in bucket.iter() {
                out.push(*e.node.key.preimage());
            }
        }
        out
    }

    /// Whether `relay` accepted a Circuit Relay v2 reservation for us.
    pub fn has_relay_reservation(&self, relay: &PeerId) -> bool {
        self.relay_reservations.contains(relay)
    }

    /// Gossipsub score of a connected peer (scoring is always active).
    pub fn peer_score(&self, peer: &PeerId) -> Option<f64> {
        self.swarm.behaviour().gossipsub.peer_score(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Cheap identities for swarm tests (~256 hashes); the network minimum is exercised by
    /// `restarted_node_is_not_silenced` / `own_identity_pow_is_checked` with a pre-mined identity.
    const TEST_POW: u32 = 8;
    /// Identity pre-mined at `MIN_SENDER_POW_BITS` (= 24): seed `[0x24; 32]`.
    const MINED: ([u8; 32], u64) = ([0x24; 32], 18_566_826);

    fn test_node(seed: &[u8; 32], psk: ObfsPsk) -> Result<MeshNode> {
        let key = NodeIdentity::from_seed(seed).verifying_key().to_bytes();
        let nonce = (0u64..)
            .find(|&n| umesh_crypto::pow::verify_identity(&key, n, TEST_POW))
            .unwrap();
        MeshNode::with_pow_policy(
            seed,
            nonce,
            TEST_POW,
            psk,
            ShapingPolicy::none(),
            ProbeResponse::Silence,
        )
    }

    /// A node refuses to start with an identity whose nonce misses the network minimum (it would
    /// be rejected — and penalized — by every peer), and starts with a properly mined one.
    #[tokio::test]
    async fn own_identity_pow_is_checked() {
        let (seed, nonce) = MINED;
        let psk = || ObfsPsk::new([1; 32]);
        assert!(matches!(
            MeshNode::new(&seed, 0, psk()),
            Err(P2pError::Message(gossip::MsgError::InsufficientPow))
        ));
        assert!(matches!(
            MeshNode::new(&[0x25; 32], nonce, psk()), // another identity's nonce
            Err(P2pError::Message(gossip::MsgError::InsufficientPow))
        ));
        let mut n = MeshNode::new(&seed, nonce, psk()).unwrap();
        assert_eq!(n.pow_nonce(), nonce);
        let m = n.sign_next("t", b"x".to_vec());
        assert_eq!(m.pow_nonce, nonce);
        assert!(
            m.validate_stateless().is_ok(),
            "published messages carry the PoW"
        );
    }

    /// Regression: a message whose sender carries no proof-of-work is not delivered, and the
    /// forwarder is penalized (gossipsub Reject, P4) — it is provably invalid and free to check.
    #[tokio::test(flavor = "multi_thread")]
    async fn sender_without_pow_is_rejected_and_penalized() {
        let (mut v, mut m, mut p) = trio(40).await;
        let no_pow = SignedMessage::create(
            &m.identity,
            "news",
            b"free identity".to_vec(),
            gossip::next_seqno(0, gossip::now_micros()),
            gossip::now_millis(),
        );
        assert!(no_pow.validate_stateless_with_pow(TEST_POW).is_err());
        assert!(raw_publish(&mut m, "news", no_pow.encode()));
        let got = drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(3)).await;
        assert!(got.is_empty(), "PoW-less message delivered: {got:?}");
        let m_id = m.local_peer_id();
        assert!(v.peer_score(&m_id).unwrap() < 0.0, "forwarder penalized");
        // A properly mined sender on the same mesh is still delivered.
        let ok = p.sign_next("news", b"mined".to_vec());
        assert!(raw_publish(&mut p, "news", ok.encode()));
        let got = drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(3)).await;
        assert_eq!(got, vec![("news".to_string(), b"mined".to_vec())]);
    }

    async fn listen_addr(n: &mut MeshNode) -> Multiaddr {
        n.listen("/ip4/127.0.0.1/tcp/0").unwrap();
        loop {
            if let MeshEvent::Listening(a) = n.next_event().await {
                return a;
            }
        }
    }

    fn raw_publish(n: &mut MeshNode, topic: &str, data: Vec<u8>) -> bool {
        n.swarm
            .behaviour_mut()
            .gossipsub
            .publish(gossipsub::IdentTopic::new(topic), data)
            .is_ok()
    }

    /// Drive all nodes for `d`, collecting `Message` events delivered to the first one.
    async fn drive(nodes: &mut [&mut MeshNode], d: Duration) -> Vec<(String, Vec<u8>)> {
        let mut got = Vec::new();
        let _ = tokio::time::timeout(d, async {
            loop {
                let (first, rest) = nodes.split_first_mut().unwrap();
                let others =
                    futures::future::select_all(rest.iter_mut().map(|n| Box::pin(n.next_event())));
                tokio::select! {
                    ev = first.next_event() => {
                        if let MeshEvent::Message { topic, payload, .. } = ev {
                            got.push((topic, payload));
                        }
                    }
                    _ = others => {}
                }
            }
        })
        .await;
        got
    }

    /// Victim V, attacker M and honest publisher P (M and P both connected to V).
    async fn trio(base: u8) -> (MeshNode, MeshNode, MeshNode) {
        let psk = ObfsPsk::new([7u8; 32]);
        let mut v = test_node(&[base; 32], psk.clone()).unwrap();
        let mut m = test_node(&[base + 1; 32], psk.clone()).unwrap();
        let mut p = test_node(&[base + 2; 32], psk).unwrap();
        for n in [&mut v, &mut m, &mut p] {
            n.subscribe("news").unwrap();
        }
        let va = listen_addr(&mut v).await;
        m.dial(&va.to_string()).unwrap();
        p.dial(&va.to_string()).unwrap();
        drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(3)).await;
        (v, m, p)
    }

    /// Audit regression (HIGH insider censorship): M front-runs P's genuine message with a copy
    /// whose payload is swapped. The message-id used to exclude the payload, so gossipsub's
    /// duplicate cache dropped the genuine message at V.
    #[tokio::test(flavor = "multi_thread")]
    async fn forged_payload_copy_cannot_censor_genuine_message() {
        let (mut v, mut m, mut p) = trio(10).await;
        let genuine = SignedMessage::create_with_pow(
            &p.identity,
            p.pow_nonce,
            "news",
            b"genuine".to_vec(),
            gossip::next_seqno(0, gossip::now_micros()),
            gossip::now_millis(),
        );
        let mut evil = genuine.clone();
        evil.payload = b"garbage".to_vec();
        assert!(raw_publish(&mut m, "news", evil.encode()));
        drive(&mut [&mut v, &mut m, &mut p], Duration::from_millis(800)).await;
        assert!(raw_publish(&mut p, "news", genuine.encode()));
        let got = drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(3)).await;
        assert_eq!(got, vec![("news".to_string(), b"genuine".to_vec())]);
        // The forger was penalized for the invalid copy (P4).
        let m_id = m.local_peer_id();
        assert!(v.peer_score(&m_id).unwrap() < 0.0);
    }

    /// Audit regression (HIGH cross-topic replay): a message signed for topic "secret" replayed
    /// into "news" used to be delivered with topic "news".
    #[tokio::test(flavor = "multi_thread")]
    async fn cross_topic_replay_rejected() {
        let (mut v, mut m, mut p) = trio(20).await;
        let signed_for_secret = SignedMessage::create_with_pow(
            &p.identity,
            p.pow_nonce,
            "secret",
            b"genuine".to_vec(),
            gossip::next_seqno(0, gossip::now_micros()),
            gossip::now_millis(),
        );
        assert!(raw_publish(&mut m, "news", signed_for_secret.encode()));
        let got = drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(3)).await;
        assert!(got.is_empty(), "cross-topic replay delivered: {got:?}");
        let m_id = m.local_peer_id();
        assert!(v.peer_score(&m_id).unwrap() < 0.0, "replayer penalized");
    }

    /// Audit regression (MEDIUM): with no peer scoring, `Reject` cost nothing. Now invalid
    /// messages drive the forwarder's score down, while replays are only ignored.
    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_messages_penalize_replays_do_not() {
        let (mut v, mut m, mut p) = trio(30).await;
        let (m_id, p_id) = (m.local_peer_id(), p.local_peer_id());
        // P publishes a genuine message; then an honest relay (M) forwards a *different* message
        // reusing the same seqno (a replay from V's point of view).
        let seq = gossip::next_seqno(0, gossip::now_micros());
        let first = SignedMessage::create_with_pow(
            &p.identity,
            p.pow_nonce,
            "news",
            b"a".to_vec(),
            seq,
            gossip::now_millis(),
        );
        assert!(raw_publish(&mut p, "news", first.encode()));
        drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(1)).await;
        let replay = SignedMessage::create_with_pow(
            &p.identity,
            p.pow_nonce,
            "news",
            b"b".to_vec(),
            seq,
            gossip::now_millis(),
        );
        assert!(raw_publish(&mut m, "news", replay.encode()));
        drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(1)).await;
        assert!(
            v.peer_score(&m_id).unwrap() >= 0.0,
            "replay must be Ignore, not Reject"
        );

        // Now three forged messages from P's channel: P is the forwarder and gets penalized.
        for i in 0..3u8 {
            let mut bad = SignedMessage::create_with_pow(
                &p.identity,
                p.pow_nonce,
                "news",
                vec![i],
                seq + 1 + i as u64,
                gossip::now_millis(),
            );
            bad.sig[0] ^= 0xff;
            assert!(raw_publish(&mut p, "news", bad.encode()));
        }
        drive(&mut [&mut v, &mut m, &mut p], Duration::from_secs(1)).await;
        let s = v.peer_score(&p_id).unwrap();
        // 3 invalid ⇒ −90 instantly (graylist); after ~1s of ×0.9 decay still below publish.
        assert!(
            s < crate::behaviour::peer_score_thresholds().publish_threshold,
            "3 invalid messages should sink the forwarder's score, got {s}"
        );
    }

    /// Audit regression (HIGH restart silencing): seqno restarted at 1 while the identity (and the
    /// peers' last-seqno state) persisted, so a restarted node was rejected as a replay forever.
    #[tokio::test]
    async fn restarted_node_is_not_silenced() {
        // Real network-minimum identity: also checks publish ⇒ validate end to end at 24 bits.
        let (seed, nonce) = MINED;
        let mut guard = ReplayGuard::default();
        let mut n1 = MeshNode::new(&seed, nonce, ObfsPsk::new([1; 32])).unwrap();
        for _ in 0..3 {
            let m = n1.sign_next("t", b"before".to_vec());
            assert!(gossip::validate(&m, &mut guard, gossip::now_millis()).is_ok());
        }
        drop(n1);
        let mut n2 = MeshNode::new(&seed, nonce, ObfsPsk::new([1; 32])).unwrap();
        let m = n2.sign_next("t", b"after restart".to_vec());
        assert_eq!(
            gossip::validate(&m, &mut guard, gossip::now_millis()).map(|_| ()),
            Ok(())
        );
        let m2 = n2.sign_next("t", b"next".to_vec());
        assert!(m2.seqno > m.seqno);
    }

    /// Audit regression (MEDIUM): no connection limits — one peer could open unbounded connections.
    #[tokio::test(flavor = "multi_thread")]
    async fn per_peer_connection_cap_enforced() {
        let psk = ObfsPsk::new([3u8; 32]);
        let mut v = test_node(&[50; 32], psk.clone()).unwrap();
        let mut a = test_node(&[51; 32], psk).unwrap();
        let va = listen_addr(&mut v).await;
        for _ in 0..10 {
            a.dial(&va.to_string()).unwrap();
        }
        drive(&mut [&mut v, &mut a], Duration::from_secs(4)).await;
        let n = v
            .swarm
            .network_info()
            .connection_counters()
            .num_established_incoming();
        assert!(n >= 1, "at least one connection");
        assert!(
            n <= crate::behaviour::MAX_ESTABLISHED_PER_PEER,
            "{n} connections from one peer"
        );
    }

    /// Audit regression (HIGH): reconcile requests weren't rate-limited per peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn reconcile_requests_rate_limited_per_peer() {
        let psk = ObfsPsk::new([4u8; 32]);
        let mut v = test_node(&[60; 32], psk.clone()).unwrap();
        let mut a = test_node(&[61; 32], psk).unwrap();
        let v_peer = v.local_peer_id();
        let va = listen_addr(&mut v).await;
        a.dial(&va.to_string()).unwrap();
        drive(&mut [&mut v, &mut a], Duration::from_secs(1)).await;

        let total = 120usize;
        let started = Instant::now();
        for _ in 0..total {
            a.swarm
                .behaviour_mut()
                .reconcile
                .send_request(&v_peer, ReconcileMsg(reconcile::initiate(&[])));
        }
        let (mut ok, mut failed) = (0usize, 0usize);
        let _ = tokio::time::timeout(Duration::from_secs(15), async {
            while ok + failed < total {
                tokio::select! {
                    _ = v.next_event() => {}
                    ev = a.swarm.select_next_some() => match ev {
                        SwarmEvent::Behaviour(MeshBehaviourEvent::Reconcile(
                            request_response::Event::Message {
                                message: request_response::Message::Response { .. }, ..
                            },
                        )) => ok += 1,
                        SwarmEvent::Behaviour(MeshBehaviourEvent::Reconcile(
                            request_response::Event::OutboundFailure { .. },
                        )) => failed += 1,
                        _ => {}
                    }
                }
            }
        })
        .await;
        let secs = started.elapsed().as_secs_f64();
        let allowed = (RECONCILE_BURST + RECONCILE_RATE * secs).ceil() as usize + 1;
        assert!(ok >= 1, "some requests served");
        assert!(
            ok <= allowed,
            "served {ok} > budget {allowed} in {secs:.1}s"
        );
        assert!(failed >= 1, "excess requests dropped");
    }

    /// Audit regression (MEDIUM inert discovery): a listener never learned a dialable address for
    /// inbound peers, so Kademlia's routing table stayed empty. Identify-learned listen addresses
    /// are now fed into the private DHT.
    #[tokio::test(flavor = "multi_thread")]
    async fn identify_feeds_kademlia() {
        let psk = ObfsPsk::new([5u8; 32]);
        let mut a = test_node(&[70; 32], psk.clone()).unwrap();
        let mut b = test_node(&[71; 32], psk).unwrap();
        let a_peer = a.local_peer_id();
        let aa = listen_addr(&mut a).await;
        // A has a confirmed address ⇒ Kademlia server mode (advertises /uber-mesh/kad/1.0.0).
        a.add_external_address(&aa.to_string()).unwrap();
        assert!(a.kad_is_server());
        let ba = listen_addr(&mut b).await;
        a.dial(&ba.to_string()).unwrap(); // B is the *listener* for this connection
        let found = tokio::time::timeout(Duration::from_secs(10), async {
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = a.next_event() => {}
                    _ = b.next_event() => {}
                    _ = tick.tick() => if b.kad_peers().contains(&a_peer) { return true; }
                }
            }
        })
        .await;
        assert_eq!(
            found,
            Ok(true),
            "B's routing table should learn A via identify"
        );
    }
}
