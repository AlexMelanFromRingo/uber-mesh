//! Hybrid post-quantum key agreement: the **X-Wing** KEM (X25519 + ML-KEM-768), exactly as specified
//! in IETF `draft-connolly-cfrg-xwing-kem-11` and verified byte-for-byte against the draft's official
//! test vectors (`tests/xwing_kat.rs`, constitution Principle V).
//!
//! X-Wing in the two-flight shape used by the handshake:
//!
//! - **Initiator = key generation.** A fresh 32-byte decapsulation seed `sk` is expanded with
//!   `SHAKE256(sk, 96 bytes)`: bytes `0..64` are the ML-KEM-768 `KeyGen_internal(d, z)` seed and bytes
//!   `64..96` are the X25519 secret `sk_X`. The first flight is the X-Wing encapsulation key
//!   `pk = pk_M (1184) ‖ pk_X (32)`.
//! - **Responder = encapsulation.** With a fresh 64-byte `eseed`, ML-KEM encapsulates with
//!   `m = eseed[0..32]` and the ephemeral X25519 secret is `eseed[32..64]`. The second flight is the
//!   X-Wing ciphertext `ct = ct_M (1088) ‖ ct_X (32)`.
//! - **Combiner.** `ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` with
//!   `XWingLabel = "\./" ‖ "/^\"` (hex `5c2e2f2f5e5c`).
//!
//! Both flights are byte-identical to the IANA `X25519MLKEM768` (`0x11EC`) TLS key-share layout
//! (client: ek ‖ X25519 pub; server: ct ‖ X25519 pub), so the obfs TLS mimicry is unaffected.
//!
//! The session stays secret as long as *either* X25519 or ML-KEM-768 holds (constitution
//! Principle I). As a strictly-stricter local policy on top of the draft, non-contributory
//! (low-order / all-zero) X25519 inputs are rejected (RFC 7748 §6.1); honest X-Wing peers never
//! produce such keys, so this does not affect conformance.
//!
//! Every intermediate secret (seed, SHAKE output, X25519 DH output, ML-KEM shared key, hash state)
//! is wiped after use, and the combined output is returned as a [`SharedSecret`] that zeroizes on
//! drop, redacts itself in `Debug`, and compares in constant time.

use core::fmt;

use ml_kem::kem::{Decapsulate, Key as MlKey, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext as MlCiphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Seed as MlSeed};
use rand::RngCore;
use rand::rngs::OsRng;
use sha3::Sha3_256;
use sha3::digest::{FixedOutput, Update};
use shake::{ExtendableOutput, Shake256, XofReader};
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};

/// X25519 public key length.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation-key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Length of the combined hybrid shared secret.
pub const SHARED_SECRET_LEN: usize = 32;
/// X-Wing decapsulation-key (seed) length.
pub const XWING_SEED_LEN: usize = 32;
/// X-Wing encapsulation randomness (`eseed`) length.
pub const XWING_ESEED_LEN: usize = 64;
/// X-Wing encapsulation-key length: `pk_M ‖ pk_X`.
pub const XWING_PK_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;
/// X-Wing ciphertext length: `ct_M ‖ ct_X`.
pub const XWING_CT_LEN: usize = MLKEM768_CT_LEN + X25519_LEN;

/// The X-Wing combiner label `"\./" ‖ "/^\"` (draft §5.3), hex `5c2e2f2f5e5c`. Fixed by the
/// standard — deliberately not an uber-mesh `hash::labels` entry.
pub const XWING_LABEL: [u8; 6] = *b"\\.//^\\";

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

/// X-Wing `Combiner(ss_M, ss_X, ct_X, pk_X)` = `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`.
/// `ct_X` is the responder's ephemeral X25519 public key, `pk_X` the initiator's.
fn combine(
    ss_m: &[u8],
    ss_x: &[u8; 32],
    ct_x: &[u8; X25519_LEN],
    pk_x: &[u8; X25519_LEN],
) -> SharedSecret {
    // `sha3/zeroize`: the sponge state (which absorbed ss_M, ss_X) is wiped when `h` is consumed.
    let mut h = Sha3_256::default();
    h.update(ss_m);
    h.update(ss_x);
    h.update(ct_x);
    h.update(pk_x);
    h.update(&XWING_LABEL);
    let mut out = h.finalize_fixed();
    let ss = SharedSecret(out.into());
    out.as_mut_slice().zeroize();
    ss
}

/// X-Wing `expandDecapsulationKey(sk)`: `SHAKE256(sk, 96 bytes)` → (ML-KEM-768 key from
/// `expanded[0..64]` = `d ‖ z`, X25519 secret `expanded[64..96]`, its public key `pk_X`).
fn expand_decapsulation_key(
    sk: &[u8; XWING_SEED_LEN],
) -> (DecapsulationKey, StaticSecret, [u8; X25519_LEN]) {
    let mut xof = Shake256::default();
    xof.update(sk);
    let mut expanded = Zeroizing::new([0u8; 96]);
    xof.finalize_xof().read(&mut expanded[..]);

    let mut ml_seed = MlSeed::default();
    ml_seed.copy_from_slice(&expanded[..64]);
    let ml_dk = DecapsulationKey::from_seed(ml_seed);
    ml_seed.as_mut_slice().zeroize();

    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&expanded[64..]);
    let x_secret = StaticSecret::from(sk_x);
    sk_x.zeroize();
    let pk_x = PublicKey::from(&x_secret).to_bytes();
    (ml_dk, x_secret, pk_x)
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

/// First handshake flight (initiator → responder): the X-Wing encapsulation key, kept split into
/// its ML-KEM and X25519 halves. [`InitiatorMessage::to_bytes`] gives the 1216-byte X-Wing `pk`.
#[derive(Clone)]
pub struct InitiatorMessage {
    /// X25519 public key `pk_X` (32 bytes).
    pub x25519_pub: [u8; X25519_LEN],
    /// ML-KEM-768 encapsulation key `pk_M` (1184 bytes).
    pub mlkem_ek: Vec<u8>,
}

impl InitiatorMessage {
    /// Serialize as the X-Wing encapsulation key `pk_M ‖ pk_X` (also the `X25519MLKEM768` client
    /// key-share layout).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(XWING_PK_LEN);
        out.extend_from_slice(&self.mlkem_ek);
        out.extend_from_slice(&self.x25519_pub);
        out
    }

    /// Parse a 1216-byte X-Wing encapsulation key `pk_M ‖ pk_X`. Only the length is checked here;
    /// the ML-KEM key check (FIPS 203 §7.2) runs in [`respond`].
    pub fn from_bytes(pk: &[u8]) -> Result<Self> {
        if pk.len() != XWING_PK_LEN {
            return Err(CryptoError::MalformedKey);
        }
        let (pk_m, pk_x) = pk.split_at(MLKEM768_EK_LEN);
        let mut x25519_pub = [0u8; X25519_LEN];
        x25519_pub.copy_from_slice(pk_x);
        Ok(Self {
            x25519_pub,
            mlkem_ek: pk_m.to_vec(),
        })
    }
}

/// Second handshake flight (responder → initiator): the X-Wing ciphertext, kept split into its
/// ML-KEM and X25519 halves. [`ResponderMessage::to_bytes`] gives the 1120-byte X-Wing `ct`.
#[derive(Clone)]
pub struct ResponderMessage {
    /// X25519 ephemeral public key `ct_X` (32 bytes).
    pub x25519_pub: [u8; X25519_LEN],
    /// ML-KEM-768 ciphertext `ct_M` (1088 bytes).
    pub mlkem_ct: Vec<u8>,
}

impl ResponderMessage {
    /// Serialize as the X-Wing ciphertext `ct_M ‖ ct_X` (also the `X25519MLKEM768` server key-share
    /// layout).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(XWING_CT_LEN);
        out.extend_from_slice(&self.mlkem_ct);
        out.extend_from_slice(&self.x25519_pub);
        out
    }

    /// Parse a 1120-byte X-Wing ciphertext `ct_M ‖ ct_X`.
    pub fn from_bytes(ct: &[u8]) -> Result<Self> {
        if ct.len() != XWING_CT_LEN {
            return Err(CryptoError::MalformedKey);
        }
        let (ct_m, ct_x) = ct.split_at(MLKEM768_CT_LEN);
        let mut x25519_pub = [0u8; X25519_LEN];
        x25519_pub.copy_from_slice(ct_x);
        Ok(Self {
            x25519_pub,
            mlkem_ct: ct_m.to_vec(),
        })
    }
}

/// Initiator handshake state held between the two flights: the *expanded* X-Wing decapsulation key
/// (draft §5.5 explicitly allows caching it locally; it is never transmitted).
pub struct Initiator {
    x_secret: StaticSecret,
    x_pub: [u8; X25519_LEN],
    ml_dk: DecapsulationKey,
}

impl Initiator {
    /// Begin a hybrid handshake: X-Wing `GenerateKeyPair()` with a fresh 32-byte OsRng seed,
    /// producing the first flight.
    pub fn start() -> (Self, InitiatorMessage) {
        let mut sk = Zeroizing::new([0u8; XWING_SEED_LEN]);
        OsRng.fill_bytes(&mut sk[..]);
        Self::start_derand(&sk)
    }

    /// X-Wing `GenerateKeyPairDerand(sk)`. **Known-answer tests only**: production code MUST use
    /// [`Initiator::start`]; a non-uniform or reused `sk` is a catastrophic key compromise.
    #[doc(hidden)]
    pub fn start_derand(sk: &[u8; XWING_SEED_LEN]) -> (Self, InitiatorMessage) {
        let (ml_dk, x_secret, x_pub) = expand_decapsulation_key(sk);
        let mlkem_ek = ml_dk.encapsulation_key().to_bytes().as_slice().to_vec();
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

    /// X-Wing `Decapsulate`: complete the handshake from the responder's flight, yielding the
    /// shared secret.
    pub fn finish(self, resp: &ResponderMessage) -> Result<SharedSecret> {
        // `x25519_dalek::SharedSecret` is ZeroizeOnDrop; never copied out.
        let ss_x = x25519_dh(&self.x_secret, &resp.x25519_pub)?;

        let ct = MlCiphertext::try_from(resp.mlkem_ct.as_slice())
            .map_err(|_| CryptoError::MalformedKey)?;
        let mut ss_m = self.ml_dk.decapsulate(&ct); // infallible (implicit rejection)

        let ss = combine(
            ss_m.as_slice(),
            ss_x.as_bytes(),
            &resp.x25519_pub,
            &self.x_pub,
        );
        ss_m.as_mut_slice().zeroize();
        Ok(ss)
        // `self` (StaticSecret + ML-KEM DecapsulationKey, both wipe on drop) is dropped here.
    }
}

/// Responder side (X-Wing `Encapsulate` with 64 fresh OsRng bytes): consume the initiator flight,
/// produce the response, and derive the shared secret.
pub fn respond(init: &InitiatorMessage) -> Result<(SharedSecret, ResponderMessage)> {
    let mut eseed = Zeroizing::new([0u8; XWING_ESEED_LEN]);
    OsRng.fill_bytes(&mut eseed[..]);
    respond_derand(init, &eseed)
}

/// X-Wing `EncapsulateDerand(pk, eseed)`. **Known-answer tests only**: production code MUST use
/// [`respond`]; a non-uniform or reused `eseed` is a catastrophic key compromise.
#[doc(hidden)]
pub fn respond_derand(
    init: &InitiatorMessage,
    eseed: &[u8; XWING_ESEED_LEN],
) -> Result<(SharedSecret, ResponderMessage)> {
    // ML-KEM-768 encapsulation-key check (FIPS 203 §7.2), required by the draft.
    let ek_key = MlKey::<EncapsulationKey>::try_from(init.mlkem_ek.as_slice())
        .map_err(|_| CryptoError::MalformedKey)?;
    let ek = EncapsulationKey::new(&ek_key).map_err(|_| CryptoError::MalformedKey)?;

    let mut ek_x = [0u8; 32];
    ek_x.copy_from_slice(&eseed[32..]);
    let x_secret = StaticSecret::from(ek_x);
    ek_x.zeroize();
    let ct_x = PublicKey::from(&x_secret).to_bytes();
    let ss_x = x25519_dh(&x_secret, &init.x25519_pub)?;

    let mut m = B32::default();
    m.copy_from_slice(&eseed[..32]);
    let (ct_m, mut ss_m) = ek.encapsulate_deterministic(&m);
    m.as_mut_slice().zeroize();

    let ss = combine(ss_m.as_slice(), ss_x.as_bytes(), &ct_x, &init.x25519_pub);
    ss_m.as_mut_slice().zeroize();
    Ok((
        ss,
        ResponderMessage {
            x25519_pub: ct_x,
            mlkem_ct: ct_m.as_slice().to_vec(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xwing_label_matches_draft() {
        assert_eq!(XWING_LABEL, [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    }

    #[test]
    fn hybrid_handshake_agrees() {
        let (initiator, init_msg) = Initiator::start();
        assert_eq!(init_msg.x25519_pub.len(), X25519_LEN);
        assert_eq!(init_msg.mlkem_ek.len(), MLKEM768_EK_LEN);
        assert_eq!(init_msg.to_bytes().len(), XWING_PK_LEN);

        let (ss_responder, resp_msg) = respond(&init_msg).unwrap();
        assert_eq!(resp_msg.mlkem_ct.len(), MLKEM768_CT_LEN);
        assert_eq!(resp_msg.to_bytes().len(), XWING_CT_LEN);

        let ss_initiator = initiator.finish(&resp_msg).unwrap();
        assert_eq!(
            ss_initiator, ss_responder,
            "both sides must derive the same secret"
        );
    }

    #[test]
    fn message_bytes_round_trip() {
        let (_i, m) = Initiator::start();
        let m2 = InitiatorMessage::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(m2.to_bytes(), m.to_bytes());
        let (_ss, r) = respond(&m).unwrap();
        let r2 = ResponderMessage::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(r2.to_bytes(), r.to_bytes());
        assert!(InitiatorMessage::from_bytes(&[0u8; XWING_PK_LEN - 1]).is_err());
        assert!(ResponderMessage::from_bytes(&[0u8; XWING_CT_LEN + 1]).is_err());
    }

    #[test]
    fn keygen_is_deterministic_in_seed() {
        let (_a, ma) = Initiator::start_derand(&[7u8; 32]);
        let (_b, mb) = Initiator::start_derand(&[7u8; 32]);
        let (_c, mc) = Initiator::start_derand(&[8u8; 32]);
        assert_eq!(ma.to_bytes(), mb.to_bytes());
        assert_ne!(ma.to_bytes(), mc.to_bytes());
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
    fn tampered_x25519_ciphertext_breaks_agreement() {
        let (initiator, init_msg) = Initiator::start();
        let (ss_r, mut resp_msg) = respond(&init_msg).unwrap();
        resp_msg.x25519_pub[5] ^= 0x01;
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
        zod::<Sha3_256>(); // requires sha3 `zeroize`
        zod::<Shake256>(); // requires shake `zeroize`
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
