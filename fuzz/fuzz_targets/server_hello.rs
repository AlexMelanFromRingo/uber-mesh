#![no_main]
//! Fuzz target for the strict TLS ServerHello parser and the cover-flight profile parser
//! (constitution Principle V) — both consume network bytes (an obfs server's flight; the cover
//! site's flight, which an on-path adversary can forge).
//!
//! Run with: `cargo +nightly fuzz run server_hello`.
//! Invariants: never panics; an accepted ServerHello carries a share of exactly its group's size,
//! has the record length its shape predicts, and re-serializes (same session_id / shape / share) to a
//! record the parser accepts again; an accepted cover flight yields a profile that validates (≤ 8
//! records, ≤ 32 KiB, room for the confirmation) and whose ServerHello length matches the input's.

use libfuzzer_sys::fuzz_target;
use umesh_obfs::{tls, CoverProfile};

fuzz_target!(|data: &[u8]| {
    if let Some(info) = tls::parse_server_hello(data) {
        assert_eq!(info.key_share.len(), info.shape.group.share_len());
        assert_eq!(data.len(), info.shape.record_len());
        let mut rng = rand::rngs::mock::StepRng::new(0, 1);
        let re = tls::build_server_hello_shaped(
            &mut rng,
            &info.session_id,
            &info.shape,
            &info.key_share,
        );
        let again = tls::parse_server_hello(&re).expect("self-built ServerHello must parse");
        assert_eq!(again.key_share, info.key_share);
        assert_eq!(again.session_id, info.session_id);
        assert_eq!(again.shape, info.shape);
    }
    if let Some(p) = CoverProfile::from_server_flight(data) {
        assert!(p.validate());
        assert!(p.records.len() <= 8 && p.flight_bytes() <= 32 * 1024);
        let sh_len = 5 + u16::from_be_bytes([data[3], data[4]]) as usize;
        assert_eq!(sh_len, p.server_hello_len());
        let ccs = if p.ccs { 6 } else { 0 };
        assert_eq!(
            data.len(),
            sh_len + ccs + 5 * p.records.len() + p.flight_bytes()
        );
    }
});
