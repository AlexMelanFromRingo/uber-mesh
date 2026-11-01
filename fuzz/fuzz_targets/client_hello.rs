#![no_main]
//! Fuzz target for the strict TLS ClientHello parser (constitution Principle V).
//!
//! Run with: `cargo +nightly fuzz run client_hello`.
//! Invariants: never panics on attacker-controlled bytes; anything accepted carries exactly one
//! X25519MLKEM768 share of the IANA size and a valid SNI; the extension-order helper agrees; and a
//! hello *built* from fuzz-chosen randomness/SNI always parses back (the Chrome template — JA4
//! `t13d1516h2_8daaf6152771_d8a2da3f94cd`, `tests/fingerprint.rs` — is closed under the parser).

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

    if data.len() >= 8 {
        let seed = u64::from_le_bytes(data[..8].try_into().unwrap());
        let sni = std::str::from_utf8(&data[8..]).unwrap_or("");
        let mut rng = rand::rngs::mock::StepRng::new(seed, 0x9e37_79b9_7f4a_7c15);
        let share = vec![data[0]; tls::HYBRID_CLIENT_SHARE_LEN];
        let ch = tls::build_client_hello(&mut rng, &share, sni);
        let info = tls::parse_client_hello(&ch).expect("built ClientHello must parse");
        assert_eq!(info.sni.as_deref(), tls::sni_is_valid(sni).then_some(sni));
        // GREASE first + last around the 15 (no SNI) or 16 template extensions.
        let order = tls::client_hello_extension_order(&ch).unwrap();
        assert!(tls::is_grease(order[0]) && tls::is_grease(*order.last().unwrap()));
        assert_eq!(order.len(), if info.sni.is_some() { 18 } else { 17 });
    }
});
