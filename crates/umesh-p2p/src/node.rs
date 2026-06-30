//! High-level mesh node: drives the swarm, publishes signed messages, validates inbound messages
//! before gossipsub re-propagates them.

use std::collections::HashMap;

use futures::StreamExt;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm, gossipsub};
use umesh_crypto::hash::Cid;
use umesh_crypto::identity::NodeIdentity;
use umesh_obfs::ObfsPsk;

use crate::behaviour::{MeshBehaviour, MeshBehaviourEvent};
use crate::blobs::{BlobRequest, BlobResponse};
use crate::error::{P2pError, Result};
use crate::gossip::{self, ReplayGuard, SignedMessage};
use crate::reconcile::{self, Reconciler};
use crate::store::ContentStore;
use crate::sync::ReconcileMsg;

/// In-flight set-reconciliation session with one peer.
struct SyncSession {
    rec: Reconciler,
    local: Vec<[u8; 32]>,
}

/// Events surfaced to the application from [`MeshNode::next_event`].
#[derive(Debug)]
pub enum MeshEvent {
    /// A validated application message on a subscribed topic.
    Message {
        /// Topic id.
        topic: String,
        /// Application-layer sender PeerId (`BLAKE3(pubkey)`), authenticated.
        sender: umesh_crypto::identity::PeerId,
        /// Decrypted application payload.
        payload: Vec<u8>,
    },
    /// A transport-level peer connection was established.
    PeerConnected(PeerId),
    /// A transport-level peer connection closed.
    PeerDisconnected(PeerId),
    /// The node started listening on a new address.
    Listening(Multiaddr),
    /// A requested blob arrived and was verified against its `Cid`.
    BlobReceived {
        /// Content id (verified: `BLAKE3(data) == cid`).
        cid: Cid,
        /// The verified content bytes.
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
    guard: ReplayGuard,
    seqno: u64,
    store: ContentStore,
    pending_blobs: HashMap<OutboundRequestId, Cid>,
    sync_sessions: HashMap<PeerId, SyncSession>,
    pending_reconcile: HashMap<OutboundRequestId, PeerId>,
}

impl MeshNode {
    /// Build a mesh node from a 32-byte Ed25519 seed (shared with the application identity) and the
    /// obfs PSK that gates the obfuscated carrier (shared out-of-band among the cohort).
    pub fn new(seed: &[u8; 32], psk: ObfsPsk) -> Result<Self> {
        Ok(MeshNode {
            swarm: crate::behaviour::build_swarm(seed, psk)?,
            identity: NodeIdentity::from_seed(seed),
            guard: ReplayGuard::default(),
            seqno: 0,
            store: ContentStore::new(),
            pending_blobs: HashMap::new(),
            sync_sessions: HashMap::new(),
            pending_reconcile: HashMap::new(),
        })
    }

    /// Begin set reconciliation with `peer`: discover which content ids each side is missing. The
    /// result arrives as a [`MeshEvent::SyncComplete`] (or `SyncFailed`).
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
            },
        );
    }

    /// Store content locally and return its `Cid` (this node can now serve it to peers).
    pub fn provide(&mut self, data: Vec<u8>) -> Cid {
        self.store.put(data)
    }

    /// Request a blob by `Cid` from a specific peer. The result arrives as a [`MeshEvent`]
    /// (`BlobReceived` once verified, or `BlobUnavailable`).
    pub fn request_blob(&mut self, peer: PeerId, cid: Cid) -> OutboundRequestId {
        let id = self.swarm.behaviour_mut().blobs.send_request(
            &peer,
            BlobRequest {
                cid: *cid.as_bytes(),
            },
        );
        self.pending_blobs.insert(id, cid);
        id
    }

    /// libp2p transport PeerId (multihash of the public key).
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Application-layer PeerId (`BLAKE3(pubkey)`).
    pub fn app_peer_id(&self) -> umesh_crypto::identity::PeerId {
        self.identity.peer_id()
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

    /// Subscribe to a gossip topic.
    pub fn subscribe(&mut self, topic: &str) -> Result<()> {
        let t = gossipsub::IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&t)
            .map_err(|e| P2pError::Subscribe(e.to_string()))?;
        Ok(())
    }

    /// Publish a signed application message to a topic.
    pub fn publish(&mut self, topic: &str, payload: Vec<u8>) -> Result<()> {
        self.seqno += 1;
        let msg = SignedMessage::create(
            &self.identity,
            topic,
            payload,
            self.seqno,
            gossip::now_millis(),
        );
        let t = gossipsub::IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(t, msg.encode())
            .map_err(|e| P2pError::Publish(e.to_string()))?;
        Ok(())
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
                    match SignedMessage::decode(&message.data)
                        .and_then(|m| gossip::validate(&m, &mut self.guard, now).map(|p| (m, p)))
                    {
                        Ok((m, sender)) => {
                            // Accept ⇒ gossipsub re-propagates to the mesh.
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .report_message_validation_result(
                                    &message_id,
                                    &propagation_source,
                                    gossipsub::MessageAcceptance::Accept,
                                );
                            return MeshEvent::Message {
                                topic,
                                sender,
                                payload: m.payload,
                            };
                        }
                        Err(e) => {
                            // Reject ⇒ penalize the forwarding peer's score, do not propagate.
                            tracing::debug!(error = %e, "rejected invalid gossip message");
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .report_message_validation_result(
                                    &message_id,
                                    &propagation_source,
                                    gossipsub::MessageAcceptance::Reject,
                                );
                        }
                    }
                }
                SwarmEvent::Behaviour(MeshBehaviourEvent::Blobs(
                    request_response::Event::Message { message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        // Serve the blob from our store if we hold it.
                        let cid = Cid(request.cid);
                        let data = self.store.get(&cid).map(|b| b.to_vec());
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .blobs
                            .send_response(channel, BlobResponse { data });
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                        ..
                    } => {
                        if let Some(cid) = self.pending_blobs.remove(&request_id) {
                            match response.data {
                                // Verify BLAKE3(bytes) == cid before trusting the content (FR-011).
                                Some(data) if cid.verifies(&data) => {
                                    self.store.put(data.clone());
                                    return MeshEvent::BlobReceived { cid, data };
                                }
                                _ => return MeshEvent::BlobUnavailable { cid },
                            }
                        }
                    }
                },
                SwarmEvent::Behaviour(MeshBehaviourEvent::Blobs(
                    request_response::Event::OutboundFailure { request_id, .. },
                )) => {
                    if let Some(cid) = self.pending_blobs.remove(&request_id) {
                        return MeshEvent::BlobUnavailable { cid };
                    }
                }
                SwarmEvent::Behaviour(MeshBehaviourEvent::Reconcile(
                    request_response::Event::Message { message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        // Responder: answer this reconciliation round from our current id set.
                        let local = self.store.ids_sorted();
                        let resp = reconcile::respond(&local, &request.0);
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .reconcile
                            .send_response(channel, ReconcileMsg(resp));
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                        ..
                    } => {
                        if let Some(peer) = self.pending_reconcile.remove(&request_id) {
                            if let Some(session) = self.sync_sessions.get_mut(&peer) {
                                let next = session.rec.refine(&session.local, &response.0);
                                if reconcile::is_converged(&next) {
                                    let diff = std::mem::take(&mut session.rec.diff);
                                    self.sync_sessions.remove(&peer);
                                    return MeshEvent::SyncComplete {
                                        peer,
                                        need: diff.need.into_iter().map(Cid).collect(),
                                        have_extra: diff.have_extra.into_iter().map(Cid).collect(),
                                    };
                                }
                                let id = self
                                    .swarm
                                    .behaviour_mut()
                                    .reconcile
                                    .send_request(&peer, ReconcileMsg(next));
                                self.pending_reconcile.insert(id, peer);
                            }
                        }
                    }
                },
                SwarmEvent::Behaviour(MeshBehaviourEvent::Reconcile(
                    request_response::Event::OutboundFailure { request_id, .. },
                )) => {
                    if let Some(peer) = self.pending_reconcile.remove(&request_id) {
                        self.sync_sessions.remove(&peer);
                        return MeshEvent::SyncFailed { peer };
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return MeshEvent::PeerConnected(peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    return MeshEvent::PeerDisconnected(peer_id);
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return MeshEvent::Listening(address);
                }
                _ => continue,
            }
        }
    }

    /// Add a known peer address to the Kademlia routing table (for discovery bootstrap).
    pub fn add_address(&mut self, peer: PeerId, addr: &str) -> Result<()> {
        let ma: Multiaddr = addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| P2pError::Address(e.to_string()))?;
        self.swarm.behaviour_mut().kademlia.add_address(&peer, ma);
        Ok(())
    }
}
