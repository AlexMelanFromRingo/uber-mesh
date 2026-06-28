//! # umesh-p2p
//!
//! The mesh overlay for uber-mesh: signed, content-addressed gossip messages with application-level
//! replay protection ([`gossip`]), and a composed libp2p [`behaviour::MeshBehaviour`] (gossipsub +
//! private Kademlia discovery + identify + ping). A high-level [`node::MeshNode`] drives the swarm —
//! subscribe, publish signed messages, and validate inbound messages before propagation.
//!
//! NAT traversal (AutoNAT/Relay/DCUtR) and the obfs-transport-under-Noise integration are the next
//! steps — see `specs/001-uber-mesh-core/contracts/libp2p-protocols.md`.

pub mod behaviour;
pub mod error;
pub mod gossip;
pub mod node;

pub use behaviour::{MeshBehaviour, build_swarm};
pub use error::{P2pError, Result};
pub use gossip::{MsgError, ReplayGuard, SignedMessage, validate};
pub use node::{MeshEvent, MeshNode};
