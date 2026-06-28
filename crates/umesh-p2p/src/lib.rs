//! # umesh-p2p
//!
//! The mesh overlay for uber-mesh. Currently provides signed, content-addressed gossip messages with
//! application-level replay protection ([`gossip`]). The libp2p `NetworkBehaviour` (gossipsub +
//! private Kademlia discovery + identify/ping) and NAT traversal (AutoNAT/Relay/DCUtR) are layered on
//! top next — see `specs/001-uber-mesh-core/contracts/libp2p-protocols.md`.

pub mod gossip;

pub use gossip::{MsgError, ReplayGuard, SignedMessage, validate};
