//! # umesh-p2p
//!
//! The mesh overlay for uber-mesh: signed, content-addressed gossip messages with application-level
//! replay protection ([`gossip`]), and a composed libp2p [`behaviour::MeshBehaviour`] (gossipsub +
//! private Kademlia discovery + identify + ping). A high-level [`node::MeshNode`] drives the swarm —
//! subscribe, publish signed messages, and validate inbound messages before propagation.
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
pub mod store;
pub mod sync;

pub use behaviour::{MeshBehaviour, build_swarm};
pub use blobs::{BlobRequest, BlobResponse};
pub use error::{P2pError, Result};
pub use gossip::{MsgError, ReplayGuard, SignedMessage, validate, validate_on_topic};
pub use node::{MeshEvent, MeshNode};
pub use store::ContentStore;
