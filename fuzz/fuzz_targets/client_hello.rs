#![no_main]
//! Fuzz target for the strict TLS ClientHello parser (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run client_hello`.
//! Invariants: never panics on attacker-controlled bytes; anything accepted carries exactly one
//! X25519MLKEM768 share of the IANA size and a valid SNI; the extension-order helper agrees.

use libfuzzer_sys::fuzz_target;
use umesh_obfs::tls;

fuzz_target!(|data: &[u8]| {
    if let Some(info) = tls::parse_client_hello(data) {
        assert_eq!(info.hybrid_share.len(), tls::HYBRID_CLIENT_SHARE_LEN);
        if let Some(sni) = &info.sni {
            assert!(tls::sni_is_valid(sni));
        }
        assert!(tls::client_hello_extension_order(data).is_some());
        assert_eq!(
            &data[tls::SESSION_ID_OFFSET..tls::SESSION_ID_OFFSET + tls::SESSION_ID_LEN],
            &info.session_id
        );
    }
    let _ = tls::client_hello_extension_order(data);
});
