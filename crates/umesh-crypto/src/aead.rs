//! XChaCha20-Poly1305 authenticated encryption (192-bit random nonces).
//!
//! Random 24-byte nonces remove cross-peer nonce-coordination footguns (research D5). The wire
//! format is `nonce(24) || ciphertext||tag`; AAD is authenticated but not transmitted.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::hash::{self, Hash32};

/// Nonce length (XChaCha20 = 24 bytes).
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// A 256-bit AEAD key. Zeroized on drop.
pub struct AeadKey(Hash32);

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AeadKey {
    /// Wrap raw 32 key bytes.
    pub fn from_bytes(key: Hash32) -> Self {
        AeadKey(key)
    }

    /// Derive a key from input keying material under a domain-separation `context`
    /// (use a label from [`hash::labels`]).
    pub fn derive(context: &str, ikm: &[u8]) -> Self {
        AeadKey(hash::derive_key(context, ikm))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&self.0).expect("32-byte key is always valid")
    }
}

/// Encrypt `plaintext` with associated data `aad`. Returns `nonce(24) || ciphertext||tag`.
pub fn seal(key: &AeadKey, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = key
        .cipher()
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("xchacha20poly1305 encryption is infallible for valid inputs");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a `nonce(24) || ciphertext||tag` buffer with associated data `aad`.
pub fn open(key: &AeadKey, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if wire.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidLength {
            expected: NONCE_LEN + TAG_LEN,
            got: wire.len(),
        });
    }
    let (nonce, ct) = wire.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::AeadAuth)?;
    key.cipher()
        .decrypt(&nonce, Payload { msg: ct, aad })
        .map_err(|_| CryptoError::AeadAuth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = AeadKey::from_bytes([42u8; 32]);
        let pt = b"hello, mesh";
        let aad = b"c2s|epoch=0";
        let wire = seal(&key, pt, aad);
        assert_eq!(open(&key, &wire, aad).unwrap(), pt);
    }

    #[test]
    fn tamper_is_detected() {
        let key = AeadKey::from_bytes([42u8; 32]);
        let mut wire = seal(&key, b"secret", b"aad");
        let last = wire.len() - 1;
        wire[last] ^= 0x01; // flip a tag bit
        assert!(matches!(
            open(&key, &wire, b"aad"),
            Err(CryptoError::AeadAuth)
        ));
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let key = AeadKey::from_bytes([7u8; 32]);
        let wire = seal(&key, b"x", b"aad-a");
        assert!(open(&key, &wire, b"aad-b").is_err());
    }

    #[test]
    fn nonce_is_random_per_call() {
        let key = AeadKey::from_bytes([1u8; 32]);
        let a = seal(&key, b"x", b"");
        let b = seal(&key, b"x", b"");
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "nonces must differ");
    }

    #[test]
    fn too_short_is_length_error() {
        let key = AeadKey::from_bytes([1u8; 32]);
        assert!(matches!(
            open(&key, &[0u8; 4], b""),
            Err(CryptoError::InvalidLength { .. })
        ));
    }
}
