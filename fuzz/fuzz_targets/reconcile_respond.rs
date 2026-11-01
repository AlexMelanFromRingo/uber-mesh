#![no_main]
//! Fuzz target for the stateless reconciliation responder `reconcile::respond` and the initiator's
//! `Reconciler::refine` (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run reconcile_respond`.
//! Invariants: for any decodable message, neither side panics, every output is structurally valid,
//! holds at most `MAX_SEGMENTS` segments and fits one frame (no amplification — audit 2026-11).

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use umesh_p2p::reconcile::{self, Id, Reconciler};
use umesh_p2p::sync::{self, ReconcileMsg};

fn local_set() -> &'static [Id] {
    static SET: OnceLock<Vec<Id>> = OnceLock::new();
    SET.get_or_init(|| {
        let mut v: Vec<Id> = (0..2000u64)
            .map(|i| {
                let mut id = [0u8; 32];
                // Spread across the id space deterministically (cheap, no hashing dependency).
                id[..8].copy_from_slice(&i.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
                id[8..16].copy_from_slice(&i.to_le_bytes());
                id
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    })
}

fn check(out: &reconcile::Message) {
    assert!(reconcile::validate(out).is_ok(), "output must be valid");
    assert!(out.len() <= reconcile::MAX_SEGMENTS);
    sync::encode_msg(&ReconcileMsg(out.clone())).expect("output fits one frame");
}

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = sync::decode_msg(data) else {
        return;
    };
    let local = local_set();
    if let Ok(resp) = reconcile::respond(local, &msg.0) {
        check(&resp);
    }
    let mut rec = Reconciler::default();
    if let Ok(next) = rec.refine(local, &msg.0) {
        check(&next);
    }
});
