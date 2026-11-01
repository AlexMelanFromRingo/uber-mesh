//! Hybrid X25519 + ML-KEM-768 key agreement with an X-Wing-style combiner.
//!
//! A break in the (unaudited) ML-KEM implementation alone cannot compromise a session: the X25519
//! shared secret is mixed into the combiner, keeping the result secret as long as either KEM holds
//! (constitution Principle I; research D4). The combiner is `BLAKE3.derive_key("…xwing",
//! ss_mlkem ‖ ss_x25519 ‖ mlkem_ct ‖ x25519_initiator_pub ‖ x25519_responder_pub)`.
//!
//! Every intermediate secret (X25519 DH output, ML-KEM shared key, combiner input buffer) is wiped
//! after use, and the combined output is returned as a [`SharedSecret`] that zeroizes on drop,
//! redacts itself in `Debug`, and compares in constant time.

use core::fmt;

use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, Key as MlKey, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext as MlCiphertext, DecapsulationKey, EncapsulationKey};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::hash;

/// X25519 public key length.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Length of the combined hybrid shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// The 32-byte combined hybrid shared secret.
///
/// Zeroized on drop, never printed (`Debug` is redacted), not `Clone`/`Copy` (no silent copies),
/// and `==` is constant-time. Feed it to a KDF via [`SharedSecret::expose`] or its
/// `AsRef<[u8]>` impl, e.g. `AeadKey::derive(labels::TRAFFIC_C2S, &ss)`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    /// Borrow the raw secret bytes. Do not copy them into un-zeroized storage.
    pub fn expose(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SharedSecret {}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// X-Wing-style combiner. All inputs are available to both parties after the exchange. Both
/// ephemeral X25519 public keys are bound (not just the initiator's) so a tampered responder key is
/// cryptographically detectable in the derived secret, matching standard hybrid-binding practice.
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8; 32],
    mlkem_ct: &[u8],
    initiator_x_pub: &[u8; 32],
    responder_x_pub: &[u8; 32],
) -> SharedSecret {
    // Exact capacity: no reallocation, so no stray un-wiped copy of the secrets on the heap.
    let mut buf = Zeroizing::new(Vec::with_capacity(
        ss_mlkem.len() + 32 + mlkem_ct.len() + 32 + 32,
    ));
    buf.extend_from_slice(ss_mlkem);
    buf.extend_from_slice(ss_x25519);
    buf.extend_from_slice(mlkem_ct);
    buf.extend_from_slice(initiator_x_pub);
    buf.extend_from_slice(responder_x_pub);
    SharedSecret(hash::derive_key(hash::labels::XWING, &buf))
}

/// X25519 DH that rejects non-contributory (low-order / all-zero) peer keys (RFC 7748 §6.1), so a
/// malicious peer cannot silently zero out the classical half of the hybrid secret.
fn x25519_dh(secret: &StaticSecret, peer: &[u8; X25519_LEN]) -> Result<x25519_dalek::SharedSecret> {
    let ss = secret.diffie_hellman(&PublicKey::from(*peer));
    if ss.was_contributory() {
        Ok(ss)
    } else {
        Err(CryptoError::MalformedKey)
    }
}

fn random_x25519_secret() -> StaticSecret {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let s = StaticSecret::from(seed);
    seed.zeroize();
    s
}

/// First handshake flight (initiator → responder): X25519 public key + ML-KEM encapsulation key.
#[derive(Clone)]
pub struct InitiatorMessage {
    /// X25519 ephemeral public key (32 bytes).
    pub x25519_pub: [u8; X25519_LEN],
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub mlkem_ek: Vec<u8>,
}

/// Second handshake flight (responder → initiator): X25519 public key + ML-KEM ciphertext.
#[derive(Clone)]
pub struct ResponderMessage {
    /// X25519 ephemeral public key (32 bytes).
    pub x25519_pub: [u8; X25519_LEN],
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub mlkem_ct: Vec<u8>,
}

/// Initiator handshake state held between the two flights.
pub struct Initiator {
    x_secret: StaticSecret,
    x_pub: [u8; X25519_LEN],
    ml_dk: DecapsulationKey,
}

impl Initiator {
    /// Begin a hybrid handshake, producing the first flight.
    pub fn start() -> (Self, InitiatorMessage) {
        let x_secret = random_x25519_secret();
        let x_pub = PublicKey::from(&x_secret).to_bytes();

        let (ml_dk, ml_ek) = MlKem768::generate_keypair();
        let mlkem_ek = ml_ek.to_bytes().as_slice().to_vec();

        let msg = InitiatorMessage {
            x25519_pub: x_pub,
            mlkem_ek,
        };
        (
            Initiator {
                x_secret,
                x_pub,
                ml_dk,
            },
            msg,
        )
    }

    /// Complete the handshake from the responder's flight, yielding the shared secret.
    pub fn finish(self, resp: &ResponderMessage) -> Result<SharedSecret> {
        // `x25519_dalek::SharedSecret` is ZeroizeOnDrop; never copied out.
        let ss_x = x25519_dh(&self.x_secret, &resp.x25519_pub)?;

        let ct = MlCiphertext::try_from(resp.mlkem_ct.as_slice())
            .map_err(|_| CryptoError::MalformedKey)?;
        let mut ss_pq = self.ml_dk.decapsulate(&ct); // infallible (implicit rejection)

        let ss = combine(
            ss_pq.as_slice(),
            ss_x.as_bytes(),
            &resp.mlkem_ct,
            &self.x_pub,
            &resp.x25519_pub,
        );
        ss_pq.as_mut_slice().zeroize();
        Ok(ss)
        // `self` (StaticSecret + ML-KEM DecapsulationKey, both ZeroizeOnDrop) is dropped here.
    }
}

/// Responder side: consume the initiator flight, produce the response, and derive the shared secret.
pub fn respond(init: &InitiatorMessage) -> Result<(SharedSecret, ResponderMessage)> {
    let x_secret = random_x25519_secret();
    let x_pub = PublicKey::from(&x_secret).to_bytes();
    let ss_x = x25519_dh(&x_secret, &init.x25519_pub)?;

    let ek_key = MlKey::<EncapsulationKey>::try_from(init.mlkem_ek.as_slice())
        .map_err(|_| CryptoError::MalformedKey)?;
    let ek = EncapsulationKey::new(&ek_key).map_err(|_| CryptoError::MalformedKey)?;
    let (ct, mut ss_pq) = ek.encapsulate();
    let mlkem_ct = ct.as_slice().to_vec();

    let ss = combine(
        ss_pq.as_slice(),
        ss_x.as_bytes(),
        &mlkem_ct,
        &init.x25519_pub,
        &x_pub,
    );
    ss_pq.as_mut_slice().zeroize();
    Ok((
        ss,
        ResponderMessage {
            x25519_pub: x_pub,
            mlkem_ct,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_handshake_agrees() {
        let (initiator, init_msg) = Initiator::start();
        assert_eq!(init_msg.x25519_pub.len(), X25519_LEN);
        assert_eq!(init_msg.mlkem_ek.len(), MLKEM768_EK_LEN);

        let (ss_responder, resp_msg) = respond(&init_msg).unwrap();
        assert_eq!(resp_msg.mlkem_ct.len(), MLKEM768_CT_LEN);

        let ss_initiator = initiator.finish(&resp_msg).unwrap();
        assert_eq!(
            ss_initiator, ss_responder,
            "both sides must derive the same secret"
        );
    }

    #[test]
    fn distinct_handshakes_differ() {
        let (i1, m1) = Initiator::start();
        let (ss1, r1) = respond(&m1).unwrap();
        let _ = i1.finish(&r1).unwrap();

        let (_i2, m2) = Initiator::start();
        let (ss2, _r2) = respond(&m2).unwrap();
        assert_ne!(
            ss1, ss2,
            "independent handshakes must yield independent secrets"
        );
    }

    #[test]
    fn tampered_ciphertext_breaks_agreement() {
        let (initiator, init_msg) = Initiator::start();
        let (ss_r, mut resp_msg) = respond(&init_msg).unwrap();
        resp_msg.mlkem_ct[0] ^= 0xff;
        // ML-KEM uses implicit rejection, so decapsulation still returns *a* key — but it must not
        // equal the responder's, i.e. agreement is broken (or the ciphertext fails to parse).
        if let Ok(ss_i) = initiator.finish(&resp_msg) {
            assert_ne!(ss_i, ss_r);
        }
    }

    #[test]
    fn shared_secret_debug_is_redacted() {
        let (initiator, init_msg) = Initiator::start();
        let (ss, resp) = respond(&init_msg).unwrap();
        let dbg = format!("{ss:?}");
        assert_eq!(dbg, "SharedSecret(<redacted>)");
        let hex_secret: String = ss.expose().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hex_secret));
        assert_eq!(initiator.finish(&resp).unwrap().as_ref(), ss.as_ref());
    }

    /// Principle I: every secret-bearing type in the KEM path must wipe itself on drop. These are
    /// compile-time checks — they fail to build if the `zeroize` features are dropped.
    #[test]
    fn secret_types_are_zeroize_on_drop() {
        fn zod<T: ZeroizeOnDrop>() {}
        zod::<SharedSecret>();
        // x25519-dalek uses `#[zeroize(drop)]` (a `Drop` impl, no marker trait): check `Zeroize`.
        fn z<T: Zeroize>() {}
        z::<StaticSecret>();
        z::<x25519_dalek::SharedSecret>();
        zod::<DecapsulationKey>(); // requires ml-kem `zeroize`
    }

    /// RFC 7748 §6.1: an all-zero / low-order X25519 key would zero the classical half of the
    /// hybrid secret, leaving the session protected by ML-KEM alone.
    #[test]
    fn low_order_x25519_key_is_rejected() {
        let (_i, mut init_msg) = Initiator::start();
        init_msg.x25519_pub = [0u8; 32];
        assert!(matches!(respond(&init_msg), Err(CryptoError::MalformedKey)));

        let (initiator, init_msg) = Initiator::start();
        let (_ss, mut resp) = respond(&init_msg).unwrap();
        resp.x25519_pub = [0u8; 32];
        assert!(matches!(
            initiator.finish(&resp),
            Err(CryptoError::MalformedKey)
        ));
    }

    #[test]
    fn malformed_ek_is_rejected() {
        let bad = InitiatorMessage {
            x25519_pub: [0u8; 32],
            mlkem_ek: vec![0u8; 10],
        };
        assert!(respond(&bad).is_err());
    }
}
