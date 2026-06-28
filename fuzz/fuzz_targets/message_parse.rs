#![no_main]
//! Fuzz target for the signed-gossip-message decoder (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run message_parse`.
//! Invariant: decoding arbitrary attacker-controlled bytes must never panic; and any message that
//! decodes must re-encode to a prefix-stable form (decode∘encode is consistent).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = umesh_p2p::SignedMessage::decode(data) {
        // A decoded message must round-trip through encode without panicking, and message_id must
        // be computable. (We do not assert signature validity — that is a separate check.)
        let re = msg.encode();
        let _ = umesh_p2p::SignedMessage::decode(&re).expect("re-decode of self-encoding");
        let _ = msg.message_id();
    }
});
