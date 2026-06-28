//! Hybrid X25519 + ML-KEM-768 key agreement with an X-Wing-style combiner.
//!
//! A break in the (unaudited) ML-KEM implementation alone cannot compromise a session: the X25519
//! shared secret is mixed into the combiner, keeping the result secret as long as either KEM holds
//! (constitution Principle I; research D4). The combiner is `BLAKE3.derive_key("…xwing",
//! ss_mlkem ‖ ss_x25519 ‖ mlkem_ct ‖ x25519_initiator_pub)`.

use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, Key as MlKey, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext as MlCiphertext, DecapsulationKey, EncapsulationKey};
use rand::RngCore;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::hash::{self, Hash32};

/// X25519 public key length.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;

/// X-Wing-style combiner. All inputs are available to both parties after the exchange. Both
/// ephemeral X25519 public keys are bound (not just the initiator's) so a tampered responder key is
/// cryptographically detectable in the derived secret, matching standard hybrid-binding practice.
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8; 32],
    mlkem_ct: &[u8],
    initiator_x_pub: &[u8; 32],
    responder_x_pub: &[u8; 32],
) -> Hash32 {
    let mut buf = Vec::with_capacity(ss_mlkem.len() + 32 + mlkem_ct.len() + 32 + 32);
    buf.extend_from_slice(ss_mlkem);
    buf.extend_from_slice(ss_x25519);
    buf.extend_from_slice(mlkem_ct);
    buf.extend_from_slice(initiator_x_pub);
    buf.extend_from_slice(responder_x_pub);
    let ss = hash::derive_key(hash::labels::XWING, &buf);
    buf.zeroize();
    ss
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
    pub fn finish(self, resp: &ResponderMessage) -> Result<Hash32> {
        let their_pub = PublicKey::from(resp.x25519_pub);
        let ss_x = self.x_secret.diffie_hellman(&their_pub).to_bytes();

        let ct = MlCiphertext::try_from(resp.mlkem_ct.as_slice())
            .map_err(|_| CryptoError::MalformedKey)?;
        let ss_pq = self.ml_dk.decapsulate(&ct); // infallible (implicit rejection)

        Ok(combine(
            ss_pq.as_slice(),
            &ss_x,
            &resp.mlkem_ct,
            &self.x_pub,
            &resp.x25519_pub,
        ))
    }
}

/// Responder side: consume the initiator flight, produce the response, and derive the shared secret.
pub fn respond(init: &InitiatorMessage) -> Result<(Hash32, ResponderMessage)> {
    let x_secret = random_x25519_secret();
    let x_pub = PublicKey::from(&x_secret).to_bytes();
    let their_pub = PublicKey::from(init.x25519_pub);
    let ss_x = x_secret.diffie_hellman(&their_pub).to_bytes();

    let ek_key = MlKey::<EncapsulationKey>::try_from(init.mlkem_ek.as_slice())
        .map_err(|_| CryptoError::MalformedKey)?;
    let ek = EncapsulationKey::new(&ek_key).map_err(|_| CryptoError::MalformedKey)?;
    let (ct, ss_pq) = ek.encapsulate();
    let mlkem_ct = ct.as_slice().to_vec();

    let ss = combine(ss_pq.as_slice(), &ss_x, &mlkem_ct, &init.x25519_pub, &x_pub);
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
    fn malformed_ek_is_rejected() {
        let bad = InitiatorMessage {
            x25519_pub: [0u8; 32],
            mlkem_ek: vec![0u8; 10],
        };
        assert!(respond(&bad).is_err());
    }
}
