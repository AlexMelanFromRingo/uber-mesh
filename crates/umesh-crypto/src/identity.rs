//! Ed25519 node identity, signatures, and `PeerId = BLAKE3(verifying_key)`.
//!
//! Long-term identity keys authenticate the node and sign control/gossip messages. They are
//! never used for bulk encryption (forward secrecy lives in the per-link session keys).

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::hash;

/// Length of a [`PeerId`] in bytes.
pub const PEER_ID_LEN: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// A self-certifying peer identifier: `BLAKE3(ed25519 verifying-key bytes)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; PEER_ID_LEN]);

impl PeerId {
    /// Derive the PeerId from a verifying key.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        PeerId(hash::hash(vk.as_bytes()))
    }

    /// The raw 32 identifier bytes.
    pub fn as_bytes(&self) -> &[u8; PEER_ID_LEN] {
        &self.0
    }

    /// Verify that a verifying key actually derives this PeerId (identity binding).
    pub fn binds(&self, vk: &VerifyingKey) -> bool {
        PeerId::from_verifying_key(vk) == *self
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b3:")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({self})")
    }
}

/// A node's long-term Ed25519 identity. The secret key is zeroized on drop (dalek `zeroize`).
pub struct NodeIdentity {
    signing: SigningKey,
}

impl NodeIdentity {
    /// Generate a fresh random identity from OS entropy.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let id = Self::from_seed(&seed);
        seed.zeroize();
        id
    }

    /// Reconstruct an identity from a 32-byte seed (e.g. loaded from the keystore).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        NodeIdentity {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Export the 32-byte secret seed (for persistence to a 0600 keystore only).
    ///
    /// The caller MUST wipe the returned copy, e.g. `Zeroizing::new(id.to_seed_bytes())`.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// This identity's verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// This identity's PeerId.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_verifying_key(&self.verifying_key())
    }

    /// Sign a message with the long-term identity key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    /// Sign a message, returning the raw 64-byte signature (convenience for wire encoding).
    pub fn sign_bytes(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(msg).to_bytes()
    }
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose secret material in Debug output (constitution Principle I / FR-013).
        write!(f, "NodeIdentity({})", self.peer_id())
    }
}

/// Strictly verify `sig` over `msg` under `vk` (rejects non-canonical / malleable signatures).
pub fn verify_strict(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<()> {
    vk.verify_strict(msg, sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// Parse a verifying key from 32 bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::MalformedKey)
}

/// Verify a raw signature over `msg` under a raw verifying key, returning the bound [`PeerId`].
///
/// On success the caller knows both that the signature is valid AND that `vk_bytes` derives the
/// returned PeerId (identity binding). Uses `verify_strict` to reject malleable signatures.
pub fn verify(vk_bytes: &[u8; 32], msg: &[u8], sig_bytes: &[u8; SIGNATURE_LEN]) -> Result<PeerId> {
    let vk = verifying_key_from_bytes(vk_bytes)?;
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify_strict(msg, &sig)
        .map_err(|_| CryptoError::BadSignature)?;
    Ok(PeerId::from_verifying_key(&vk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let id = NodeIdentity::generate();
        let vk = id.verifying_key();
        let msg = b"uber-mesh control message";
        let sig = id.sign(msg);
        assert!(verify_strict(&vk, msg, &sig).is_ok());
        assert!(verify_strict(&vk, b"other", &sig).is_err());
    }

    #[test]
    fn peer_id_binds_to_key() {
        let id = NodeIdentity::generate();
        let pid = id.peer_id();
        assert!(pid.binds(&id.verifying_key()));

        let other = NodeIdentity::generate();
        assert!(!pid.binds(&other.verifying_key()));
    }

    #[test]
    fn seed_roundtrip_is_deterministic() {
        let seed = [7u8; 32];
        let a = NodeIdentity::from_seed(&seed);
        let b = NodeIdentity::from_seed(&seed);
        assert_eq!(a.peer_id(), b.peer_id());
        assert_eq!(a.to_seed_bytes(), seed);
    }

    #[test]
    fn debug_never_leaks_secret_seed() {
        let id = NodeIdentity::from_seed(&[0x5Au8; 32]);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("NodeIdentity(b3:"));
        assert!(!dbg.contains(&"5a".repeat(32)));
    }

    /// Principle I: the long-term signing key wipes itself on drop (ed25519-dalek `zeroize`).
    #[test]
    fn signing_key_is_zeroize_on_drop() {
        fn zod<T: zeroize::ZeroizeOnDrop>() {}
        zod::<SigningKey>();
    }

    #[test]
    fn peer_id_display_format() {
        let id = NodeIdentity::from_seed(&[1u8; 32]);
        let s = format!("{}", id.peer_id());
        assert!(s.starts_with("b3:"));
        assert_eq!(s.len(), 3 + 64);
    }
}
