//! # umesh-obfs
//!
//! Pluggable obfuscated transport layer for uber-mesh (constitution Principle II). The first
//! concrete carrier is **obfs-tcp**: a TLS-record-framed, probe-resistant, hybrid-PQ-keyed TCP
//! transport with traffic shaping, selected by an environment [`Profile`].
//!
//! Layered design (research D2):
//! - [`wire`]: TLS-record framing + a censor "fully-encrypted" classifier model (test oracle).
//! - [`tls`]: Chrome-shaped TLS 1.3 ClientHello/ServerHello templates + strict parsers.
//! - [`handshake`]: whole-hello MAC gate + replay cache (probe resistance), hybrid X25519+ML-KEM-768
//!   key agreement with a PSK-bound key schedule and mutual key confirmation (obfs wire v2).
//! - [`secure`]: AEAD record stream with length-hiding padding.
//! - [`shaping`]: padding + timing policy, independent of the carrier.
//! - [`profile`]: environment profiles that select transport + shaping.
//! - [`transport`]: the concrete `ObfsTcp` carrier, the concurrent [`ObfsListener`], and
//!   connect-time rotation.

pub mod bytestream;
pub mod error;
pub mod handshake;
pub mod profile;
pub mod secure;
pub mod shaping;
pub mod tls;
pub mod transport;
pub mod wire;

pub use bytestream::ObfsByteStream;
pub use error::{ObfsError, Result};
pub use handshake::{
    ClientConfig, ObfsPsk, ProbeResponse, ReplayCache, SessionKeys, client_handshake,
    client_handshake_with, server_handshake, server_handshake_probe,
};
pub use profile::{Profile, TransportKind};
pub use secure::SecureStream;
pub use shaping::ShapingPolicy;
pub use transport::{
    Endpoint, ListenerConfig, ObfsListener, ObfsTcp, connect_first_working,
    connect_first_working_with,
};
