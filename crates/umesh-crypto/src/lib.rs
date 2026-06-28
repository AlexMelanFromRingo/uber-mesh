//! # umesh-crypto
//!
//! Pure-Rust cryptographic core for uber-mesh. Contains only standardized, modern primitives
//! composed via established constructions (constitution Principle I). No hand-rolled primitives.
//!
//! Modules:
//! - [`hash`]: BLAKE3 hashing, keyed MAC, domain-separated KDF, content IDs.
//! - [`identity`]: Ed25519 node identity, signing, `PeerId = BLAKE3(pubkey)`.
//! - [`aead`]: XChaCha20-Poly1305 authenticated encryption.
//! - [`kem`]: hybrid X25519 + ML-KEM-768 key agreement (X-Wing-style combiner).
//! - [`merkle`]: BLAKE3 Merkle tree membership proofs.
//! - [`pow`]: BLAKE3 proof-of-work identity-creation friction.
#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub mod hash;
pub mod identity;
pub mod kem;
pub mod merkle;
pub mod pow;

pub use error::{CryptoError, Result};
pub use hash::{Cid, Hash32};
