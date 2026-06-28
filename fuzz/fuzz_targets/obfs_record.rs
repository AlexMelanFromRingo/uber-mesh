#![no_main]
//! Fuzz target for the obfs TLS-record framing parser (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run obfs_record` (requires `cargo install cargo-fuzz`).
//! Invariant: parsing arbitrary attacker-controlled bytes must never panic, over-read, or
//! over-allocate; a declared length above the record ceiling must be rejected.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((payload, consumed)) = umesh_obfs::wire::parse_record(data) {
        // Returned slice must lie within the consumed prefix of the input.
        assert!(consumed <= data.len());
        assert!(payload.len() <= consumed);
    }
});
