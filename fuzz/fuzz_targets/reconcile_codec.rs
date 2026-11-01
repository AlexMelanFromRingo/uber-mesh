#![no_main]
//! Fuzz target for the `/uber-mesh/reconcile/1.0.0` bincode codec (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run reconcile_codec`.
//! Invariants: decoding never panics or aborts on huge length claims (audit 2026-11 CRITICAL);
//! anything accepted is structurally valid and re-encodes into a frame that decodes again.

use libfuzzer_sys::fuzz_target;
use umesh_p2p::reconcile;
use umesh_p2p::sync::{self, MAX_RECONCILE};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = sync::decode_msg(data) {
        assert!(reconcile::validate(&msg.0).is_ok());
        assert!(msg.0.len() <= reconcile::MAX_SEGMENTS);
        let re = sync::encode_msg(&msg).expect("valid message fits a frame");
        assert!(re.len() <= MAX_RECONCILE);
        sync::decode_msg(&re).expect("re-decode of self-encoding");
    }
});
