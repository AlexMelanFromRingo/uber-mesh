//! XChaCha20-Poly1305 authenticated encryption (192-bit random nonces).
//!
//! Random 24-byte nonces remove cross-peer nonce-coordination footguns (research D5). The wire
//! format is `nonce(24) || ciphertext||tag`; AAD is authenticated but not transmitted.

use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};
use crate::hash::{self, Hash32};

/// Nonce length (XChaCha20 = 24 bytes).
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// A 256-bit AEAD key.
///
/// The key is held only inside one cached, keyed [`XChaCha20Poly1305`] instance (built once, not
/// per record), which zeroizes its key on drop (`chacha20poly1305/zeroize`). No other copy of the
/// key is retained. `Debug` is redacted.
pub struct AeadKey {
    cipher: XChaCha20Poly1305,
}

// Sound: the only field is `XChaCha20Poly1305`, which is itself `ZeroizeOnDrop`.
impl ZeroizeOnDrop for AeadKey {}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey(<redacted>)")
    }
}

impl AeadKey {
    /// Wrap raw 32 key bytes. The caller remains responsible for wiping its own copy of `key`.
    pub fn from_bytes(mut key: Hash32) -> Self {
        // `new_from_slice` keys the cipher straight from `key` (no temporary Array copy).
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key is always valid");
        key.zeroize();
        AeadKey { cipher }
    }

    /// Derive a key from input keying material under a domain-separation `context`
    /// (use a label from [`hash::labels`]). `ikm` may be any byte container, including a
    /// [`crate::kem::SharedSecret`].
    pub fn derive<K: AsRef<[u8]> + ?Sized>(context: &str, ikm: &K) -> Self {
        Self::from_bytes(hash::derive_key(context, ikm.as_ref()))
    }

    fn cipher(&self) -> &XChaCha20Poly1305 {
        &self.cipher
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

    /// Principle I: the cached cipher (and therefore `AeadKey`) wipes its key on drop. Fails to
    /// compile without the `chacha20poly1305/zeroize` feature.
    #[test]
    fn key_types_are_zeroize_on_drop() {
        fn zod<T: ZeroizeOnDrop>() {}
        zod::<XChaCha20Poly1305>();
        zod::<AeadKey>();
    }

    #[test]
    fn debug_is_redacted() {
        let key = AeadKey::from_bytes([0xA5; 32]);
        let s = format!("{key:?}");
        assert_eq!(s, "AeadKey(<redacted>)");
    }

    #[test]
    fn derive_accepts_shared_secret_and_slices() {
        let (i, m) = crate::kem::Initiator::start();
        let (ss, r) = crate::kem::respond(&m).unwrap();
        let ss_i = i.finish(&r).unwrap();
        let a = AeadKey::derive(hash::labels::TRAFFIC_C2S, &ss);
        let b = AeadKey::derive(hash::labels::TRAFFIC_C2S, ss_i.expose());
        let wire = seal(&a, b"x", b"");
        assert_eq!(open(&b, &wire, b"").unwrap(), b"x");
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
