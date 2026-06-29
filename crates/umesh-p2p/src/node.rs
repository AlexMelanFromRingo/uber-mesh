//! High-level mesh node: drives the swarm, publishes signed messages, validates inbound messages
//! before gossipsub re-propagates them.

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm, gossipsub};
use umesh_crypto::identity::NodeIdentity;
use umesh_obfs::ObfsPsk;

use crate::behaviour::{MeshBehaviour, MeshBehaviourEvent};
use crate::error::{P2pError, Result};
use crate::gossip::{self, ReplayGuard, SignedMessage};

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
}

/// A running mesh node.
pub struct MeshNode {
    swarm: Swarm<MeshBehaviour>,
    identity: NodeIdentity,
    guard: ReplayGuard,
    seqno: u64,
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
        })
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
