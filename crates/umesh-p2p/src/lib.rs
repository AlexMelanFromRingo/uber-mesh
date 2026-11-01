//! # umesh-p2p
//!
//! The mesh overlay for uber-mesh: signed, content-addressed gossip messages from proof-of-work
//! bound sender identities, with application-level replay protection ([`gossip`]), and a composed
//! libp2p [`behaviour::MeshBehaviour`] (gossipsub + private Kademlia discovery + identify + ping).
//! A high-level [`node::MeshNode`] drives the swarm — subscribe, publish signed messages, and
//! validate inbound messages before propagation. Topics may be **sealed** ([`sealed`]): with a
//! shared topic key, payloads and blobs are end-to-end encrypted, so forwarding and serving peers
//! carry them without being able to read them; topics without a key stay public.
//!
//! The swarm runs over the obfs carrier (under Noise + Yamux) with NAT traversal (AutoNAT v2
//! client+server, Circuit Relay v2, DCUtR), gossipsub peer scoring and connection limits — see
//! `specs/001-uber-mesh-core/contracts/libp2p-protocols.md`. All state keyed by remote input is
//! bounded ([`bounded`]).

pub mod behaviour;
pub mod blobs;
pub mod bounded;
pub mod error;
pub mod gossip;
pub mod metrics;
pub mod node;
pub mod reconcile;
pub mod sealed;
pub mod store;
pub mod sync;

pub use behaviour::{MeshBehaviour, build_swarm};
pub use blobs::{BlobRequest, BlobResponse};
pub use error::{P2pError, Result};
pub use gossip::{
    MIN_SENDER_POW_BITS, MsgError, ReplayGuard, SignedMessage, validate, validate_on_topic,
};
pub use node::{MeshEvent, MeshNode};
pub use sealed::{ContentKey, SealError, SealedBlobRef, SealedPayload, SealedTopic, TopicKey};
pub use store::ContentStore;
