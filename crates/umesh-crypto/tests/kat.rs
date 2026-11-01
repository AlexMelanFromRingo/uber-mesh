//! Known-answer tests against published reference vectors (constitution Principle V).
//!
//! - BLAKE3 empty-input vector (also covered inline in `hash`).
//! - X25519 RFC 7748 §5.2 first scalar-multiplication vector.
//! - Hybrid X25519+ML-KEM-768 handshake agreement and sizes. The byte-exact X-Wing conformance
//!   vectors (draft-connolly-cfrg-xwing-kem-11) live in `tests/xwing_kat.rs`; full ML-KEM ACVP KATs
//!   are covered upstream in `ml-kem`.

use umesh_crypto::{hash, kem};

fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("valid hex");
    v.try_into().expect("32 bytes")
}

#[test]
fn blake3_empty_input_kat() {
    assert_eq!(
        hex::encode(hash::hash(b"")),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

/// RFC 7748, Section 5.2 — first X25519 test vector.
#[test]
fn x25519_rfc7748_vector() {
    let scalar = h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
    let out = x25519_dalek::x25519(scalar, u);
    assert_eq!(hex::encode(out), expected);
}

/// The hybrid handshake must produce identical secrets on both sides, and the encapsulation-key /
/// ciphertext sizes must match the ML-KEM-768 standard (FIPS 203).
#[test]
fn hybrid_kem_agreement_and_sizes() {
    let (initiator, init_msg) = kem::Initiator::start();
    assert_eq!(init_msg.mlkem_ek.len(), kem::MLKEM768_EK_LEN);

    let (ss_responder, resp_msg) = kem::respond(&init_msg).expect("responder");
    assert_eq!(resp_msg.mlkem_ct.len(), kem::MLKEM768_CT_LEN);

    let ss_initiator = initiator.finish(&resp_msg).expect("initiator finish");
    assert_eq!(ss_initiator, ss_responder);
}
