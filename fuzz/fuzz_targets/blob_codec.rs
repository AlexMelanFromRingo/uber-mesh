#![no_main]
//! Fuzz target for the `/uber-mesh/blobs/1.0.0` bincode codec (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run blob_codec`.
//! Invariants: decoding attacker-controlled request/response frames never panics or aborts (the
//! bincode decode limit bounds every length claim before allocation — audit 2026-11 CRITICAL), and
//! anything that decodes respects the size caps.

use libfuzzer_sys::fuzz_target;
use umesh_p2p::blobs::{self, MAX_BLOB};

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = blobs::decode_request(data) {
        assert_eq!(req.cid.len(), 32);
    }
    if let Ok(resp) = blobs::decode_response(data) {
        assert!(resp.data.map_or(0, |d| d.len()) <= MAX_BLOB);
    }
});
