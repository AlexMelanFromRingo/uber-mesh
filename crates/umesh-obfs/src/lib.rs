//! # umesh-obfs
//!
//! Pluggable obfuscated transport layer for uber-mesh (constitution Principle II). The first
//! concrete carrier is **obfs-tcp**: a TLS-record-framed, probe-resistant, hybrid-PQ-keyed TCP
//! transport with traffic shaping, selected by an environment [`Profile`].
//!
//! Layered design (research D2):
//! - [`wire`]: TLS-record framing + a censor "fully-encrypted" classifier model (test oracle).
//! - [`handshake`]: MAC-gate probe resistance + hybrid X25519+ML-KEM-768 key agreement.
//! - [`secure`]: AEAD record stream with length-hiding padding.
//! - [`shaping`]: padding + timing policy, independent of the carrier.
//! - [`profile`]: environment profiles that select transport + shaping.
//! - [`transport`]: the concrete `ObfsTcp` carrier + connect-time rotation.

pub mod bytestream;
pub mod error;
pub mod handshake;
pub mod profile;
pub mod secure;
pub mod shaping;
pub mod transport;
pub mod wire;

pub use bytestream::ObfsByteStream;
pub use error::{ObfsError, Result};
pub use handshake::{
    ObfsPsk, ProbeResponse, SessionKeys, client_handshake, server_handshake, server_handshake_probe,
};
pub use profile::{Profile, TransportKind};
pub use secure::SecureStream;
pub use shaping::ShapingPolicy;
pub use transport::{Endpoint, ObfsTcp, connect_first_working};
