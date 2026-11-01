#![no_main]
//! Fuzz target for the signed-gossip-message decoder (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run message_parse`.
//! Invariants on arbitrary attacker-controlled bytes (message format v2, with the sender's
//! identity proof-of-work nonce):
//! - decoding never panics;
//! - the encoding is canonical: anything that decodes re-encodes to exactly the input bytes
//!   (`encode(decode(b)) == b`), and re-decodes to the same message;
//! - the message-id and the full stateless validation (identity binding, identity PoW, payload
//!   hash, signature) are computable without panicking. Validity is not asserted: random bytes
//!   essentially never carry both valid work and a valid signature.

use libfuzzer_sys::fuzz_target;
use umesh_p2p::{MsgError, SignedMessage};

fuzz_target!(|data: &[u8]| {
    match SignedMessage::decode(data) {
        Ok(msg) => {
            let re = msg.encode();
            assert_eq!(re, data, "canonical encoding");
            let back = SignedMessage::decode(&re).expect("re-decode of self-encoding");
            assert_eq!(back, msg);
            let _ = msg.message_id();
            let _ = msg.validate_stateless();
            let _ = msg.validate_stateless_with_pow(0);
        }
        // Only a wrong version byte may be classified as `Version` (Ignore, never penalized).
        // v2 (public) and v3 (sealed) are both known versions.
        Err(MsgError::Version) => assert!(!matches!(
            data.first(),
            Some(&umesh_p2p::gossip::MSG_VERSION | &umesh_p2p::gossip::SEALED_MSG_VERSION)
        )),
        Err(_) => {}
    }
});
