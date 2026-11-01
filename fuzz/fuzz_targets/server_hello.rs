#![no_main]
//! Fuzz target for the strict TLS ServerHello parser (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run server_hello`.
//! Invariants: never panics; anything accepted carries an X25519MLKEM768 share of the IANA size and
//! re-serializes (with the same random/session_id/share) to a record the parser accepts again.

use libfuzzer_sys::fuzz_target;
use umesh_obfs::tls;

fuzz_target!(|data: &[u8]| {
    if let Some(info) = tls::parse_server_hello(data) {
        assert_eq!(info.hybrid_share.len(), tls::HYBRID_SERVER_SHARE_LEN);
        let mut rng = rand::rngs::mock::StepRng::new(0, 1);
        let re = tls::build_server_hello(&mut rng, &info.session_id, &info.hybrid_share);
        let again = tls::parse_server_hello(&re).expect("self-built ServerHello must parse");
        assert_eq!(again.hybrid_share, info.hybrid_share);
        assert_eq!(again.session_id, info.session_id);
    }
});
