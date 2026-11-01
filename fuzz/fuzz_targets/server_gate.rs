#![no_main]
//! Fuzz target for the full server-side first-flight path (constitution Principle V): the
//! incremental ClientHello-prefix classifier the async reader uses, then strict parse + PSK gate
//! (epochs e−1..e+1) + replay cache, exactly as `server_handshake_probe` runs them.
//!
//! Run with: `cargo +nightly fuzz run server_gate`.
//! Invariants: never panics; the classifier never asks to read past a complete record and never
//! accepts a prefix it would reject byte-by-byte; random input never passes the MAC gate; a
//! genuinely gated hello built from fuzz-chosen fields passes exactly once (replay ⇒ rejected).

use std::sync::{LazyLock, Mutex};

use libfuzzer_sys::fuzz_target;
use umesh_obfs::handshake::{build_gated_client_hello, gate_client_hello};
use umesh_obfs::wire::{classify_client_hello_prefix, HelloPrefix};
use umesh_obfs::{tls, ObfsPsk, ReplayCache};

const NOW: u64 = 29_000_000;
static CACHE: LazyLock<Mutex<ReplayCache>> =
    LazyLock::new(|| Mutex::new(ReplayCache::new(1 << 12)));

fn psk() -> ObfsPsk {
    ObfsPsk::new([0x5a; 32])
}

fuzz_target!(|data: &[u8]| {
    // 1. Byte-at-a-time classification, mirroring `wire::read_client_hello_record`.
    let mut complete = None;
    for n in 0..=data.len() {
        match classify_client_hello_prefix(&data[..n]) {
            HelloPrefix::NeedMore(total) => assert!(total > n),
            HelloPrefix::Complete => {
                complete = Some(n);
                break;
            }
            HelloPrefix::Implausible => break,
        }
    }

    // 2. Gate on the complete record (the server only ever gates a Complete record).
    if let Some(n) = complete {
        let mut cache = CACHE.lock().unwrap();
        assert!(
            gate_client_hello(&psk(), &data[..n], NOW, &mut cache).is_none(),
            "arbitrary bytes must not pass the PSK gate"
        );
    }

    // 3. A real gated hello from fuzz-chosen randomness/SNI/epoch offset passes once, then replays fail.
    if data.len() >= 9 {
        let seed = u64::from_le_bytes(data[..8].try_into().unwrap());
        let epoch = NOW - 1 + (data[8] % 3) as u64;
        let sni = std::str::from_utf8(&data[9..]).unwrap_or("");
        let mut rng = rand::rngs::mock::StepRng::new(seed, 0x9e37_79b9_7f4a_7c15);
        let share = vec![data[8]; tls::HYBRID_CLIENT_SHARE_LEN];
        let ch = build_gated_client_hello(&mut rng, &psk(), epoch, &share, sni);
        assert_eq!(classify_client_hello_prefix(&ch), HelloPrefix::Complete);
        let mut cache = ReplayCache::new(4);
        assert!(gate_client_hello(&psk(), &ch, NOW, &mut cache).is_some());
        assert!(
            gate_client_hello(&psk(), &ch, NOW, &mut cache).is_none(),
            "replay"
        );
        let mut tampered = ch.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(gate_client_hello(&psk(), &tampered, NOW, &mut ReplayCache::new(4)).is_none());
    }
});
