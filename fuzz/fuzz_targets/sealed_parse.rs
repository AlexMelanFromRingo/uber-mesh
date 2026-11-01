#![no_main]
//! Fuzz target for the sealed-payload parsers (end-to-end confidentiality; constitution
//! Principle V).
//!
//! Run with: `cargo +nightly fuzz run sealed_parse`.
//! Invariants on arbitrary attacker-controlled bytes:
//! - the inner sealed-payload parser (`SealedPayload::decode`, run on decrypted plaintext) never
//!   panics and is canonical (`encode(decode(b)) == b`);
//! - a sealed (v3) gossip message decodes canonically, its payload is at least nonce + tag long, and
//!   opening it with a topic key never panics (random bytes essentially never authenticate);
//! - opening a blob (cid check + AEAD) never panics.

use libfuzzer_sys::fuzz_target;
use umesh_crypto::hash::Cid;
use umesh_p2p::gossip::MIN_SEALED_PAYLOAD;
use umesh_p2p::sealed::{self, ContentKey, SealedBlobRef, SealedPayload, SealedTopic, TopicKey};
use umesh_p2p::SignedMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = SealedPayload::decode(data) {
        assert_eq!(&*p.encode(), data, "canonical inner payload");
    }
    if let Ok(msg) = SignedMessage::decode(data) {
        assert_eq!(msg.encode(), data, "canonical encoding");
        if msg.sealed {
            assert!(msg.payload.len() >= MIN_SEALED_PAYLOAD);
            let st = SealedTopic::new(&msg.topic, &TopicKey::from_bytes([7; 32]));
            let _ = sealed::open_message(&st, &msg);
        }
    }
    let blob = SealedBlobRef {
        cid: Cid::of(data),
        key: ContentKey::from_bytes([7; 32]),
    };
    let _ = sealed::open_blob(&blob, data);
});
