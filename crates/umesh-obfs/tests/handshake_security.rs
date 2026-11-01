//! Security regression tests for the obfs wire-v2 handshake (2026-11 audit).
//!
//! Each `audit_*` test is a ported audit proof-of-concept with the assertion inverted: it failed on
//! the v1 handshake (0.8.x) and must pass now. The rest pin the v2 behaviour (KAT-style determinism,
//! wire shape, non-blocking accept, client timeouts, fingerprint variability).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use umesh_crypto::hash::hash;
use umesh_crypto::kem;
use umesh_obfs::handshake::{
    CONFIRM_LEN, build_gated_client_hello, current_epoch, key_schedule_fingerprint,
    verify_client_hello,
};
use umesh_obfs::wire::read_record_raw;
use umesh_obfs::{
    ClientConfig, Endpoint, ListenerConfig, ObfsError, ObfsListener, ObfsPsk, ObfsTcp,
    ProbeResponse, ShapingPolicy, client_handshake, client_handshake_with,
    connect_first_working_with, server_handshake, server_handshake_detached,
    server_handshake_probe, tls,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fast_cfg() -> ClientConfig {
    ClientConfig {
        handshake_timeout: Duration::from_secs(3),
        connect_timeout: Duration::from_secs(3),
        ..ClientConfig::default()
    }
}

/// Capture one genuine ClientHello produced by `client_handshake` (the client is then abandoned).
async fn capture_ch(psk: &ObfsPsk, cfg: &ClientConfig) -> Vec<u8> {
    let (mut c, mut s) = tokio::io::duplex(64 * 1024);
    let (psk, cfg) = (psk.clone(), cfg.clone());
    let h = tokio::spawn(async move {
        let _ = client_handshake_with(&mut c, &psk, &cfg).await;
    });
    let raw = read_record_raw(&mut s).await.unwrap();
    h.abort();
    raw
}

/// A cover upstream that records everything it receives and answers each read with `reply`.
async fn recording_upstream(reply: &'static [u8]) -> (String, Arc<Mutex<Vec<u8>>>) {
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = up.local_addr().unwrap().to_string();
    let rec = Arc::new(Mutex::new(Vec::new()));
    let r2 = rec.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = up.accept().await {
            let r3 = r2.clone();
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            r3.lock().await.extend_from_slice(&b[..n]);
                            let _ = s.write_all(reply).await;
                        }
                    }
                }
            });
        }
    });
    (addr, rec)
}

/// Read whatever the peer sends within `dur` (until EOF or quiet).
async fn read_for(s: &mut DuplexStream, dur: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + dur;
    while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, s.read(&mut b)).await {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&b[..n]);
    }
    out
}

// ── Audit F1: PSK-less MITM ──────────────────────────────────────────────────────────────────────

/// F1: an on-path attacker WITHOUT the PSK answers with a perfectly well-formed ServerHello (correct
/// session_id echo, a real KEM response) plus a plausible CCS + encrypted flight. v1 clients accepted
/// it and sent application data the attacker could decrypt. v2 clients must reject it and never
/// send anything after the ClientHello. (Since the client accepts any cover-shaped layout, it
/// rejects by never finding a confirmation: the attempt ends when the forger goes quiet/closes,
/// the record bounds are hit, or the handshake timeout fires.)
#[tokio::test]
async fn audit_mitm_without_psk_is_rejected_by_client() {
    let client_psk = ObfsPsk::new([0x42; 32]);
    let (mut c, mut m) = tokio::io::duplex(64 * 1024);

    let mitm = tokio::spawn(async move {
        let raw = read_record_raw(&mut m).await.unwrap();
        let info = tls::parse_client_hello(&raw).unwrap();
        let ks = &info.hybrid_share;
        let mut x = [0u8; 32];
        x.copy_from_slice(&ks[1184..]);
        let init = kem::InitiatorMessage {
            x25519_pub: x,
            mlkem_ek: ks[..1184].to_vec(),
        };
        let (_ss, resp) = kem::respond(&init).unwrap();
        let mut sks = resp.mlkem_ct.clone();
        sks.extend_from_slice(&resp.x25519_pub);
        let mut flight = tls::build_server_hello(&mut OsRng, &info.session_id, &sks);
        flight.extend_from_slice(&tls::CCS_RECORD);
        for len in [3000usize, CONFIRM_LEN] {
            flight.extend_from_slice(&[0x17, 0x03, 0x03]);
            flight.extend_from_slice(&(len as u16).to_be_bytes());
            flight.extend(std::iter::repeat_n(0x5a, len));
        }
        m.write_all(&flight).await.unwrap();
        // Everything the client sends after the ClientHello.
        read_for(&mut m, Duration::from_millis(500)).await
    });

    let r = client_handshake_with(&mut c, &client_psk, &fast_cfg()).await;
    assert!(r.is_err(), "client must reject a PSK-less server");
    drop(c);
    let leaked = mitm.await.unwrap();
    assert!(
        leaked.is_empty(),
        "client must not send anything (CCS/Finished/app data) to an unauthenticated server"
    );
}

/// The client checks the session_id echo (v1 ignored it).
#[tokio::test]
async fn audit_client_rejects_wrong_session_id_echo() {
    let (mut c, mut m) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let raw = read_record_raw(&mut m).await.unwrap();
        let info = tls::parse_client_hello(&raw).unwrap();
        let ks = &info.hybrid_share;
        let mut x = [0u8; 32];
        x.copy_from_slice(&ks[1184..]);
        let (_ss, resp) = kem::respond(&kem::InitiatorMessage {
            x25519_pub: x,
            mlkem_ek: ks[..1184].to_vec(),
        })
        .unwrap();
        let mut sks = resp.mlkem_ct.clone();
        sks.extend_from_slice(&resp.x25519_pub);
        m.write_all(&tls::build_server_hello(&mut OsRng, &[0xAA; 32], &sks))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let r = client_handshake_with(&mut c, &ObfsPsk::new([9; 32]), &fast_cfg()).await;
    assert!(matches!(r, Err(ObfsError::AuthFailed)));
}

/// On-path modification of the genuine server's flight (one bit of the ServerHello random) breaks
/// the transcript and therefore the server's key confirmation: the client never confirms, sends
/// nothing more, and the server never gets a session.
#[tokio::test]
async fn tampered_server_hello_is_rejected() {
    let psk = ObfsPsk::new([0x21; 32]);
    let (mut c, mut mc) = tokio::io::duplex(64 * 1024);
    let (mut ms, mut s) = tokio::io::duplex(64 * 1024);
    let psk_s = psk.clone();
    let server = tokio::spawn(async move { server_handshake(&mut s, &psk_s).await.is_ok() });
    let leaked = tokio::spawn(async move {
        let ch = read_record_raw(&mut mc).await.unwrap();
        ms.write_all(&ch).await.unwrap();
        let mut sh = read_record_raw(&mut ms).await.unwrap();
        sh[20] ^= 0x01; // inside server random
        mc.write_all(&sh).await.unwrap();
        let mut b = vec![0u8; 16 * 1024];
        let n = ms.read(&mut b).await.unwrap();
        mc.write_all(&b[..n]).await.unwrap();
        read_for(&mut mc, Duration::from_secs(4)).await
    });
    let r = client_handshake_with(&mut c, &psk, &fast_cfg()).await;
    assert!(r.is_err(), "tampered ServerHello accepted");
    drop(c);
    assert!(
        leaked.await.unwrap().is_empty(),
        "client sent nothing after the ClientHello"
    );
    assert!(!server.await.unwrap(), "server must not get a session");
}

// ── Audit F2: replay ─────────────────────────────────────────────────────────────────────────────

/// F2: a captured ClientHello replayed by an active prober must get the probe response (cover site),
/// exactly like an unauthenticated probe — not a ServerHello. v1 answered every replay with a
/// fixed-size ServerHello.
#[tokio::test]
async fn audit_replayed_client_hello_goes_to_fallback() {
    let psk = ObfsPsk::new([0x11; 32]);
    let ch = capture_ch(&psk, &fast_cfg()).await;
    let (up_addr, rec) = recording_upstream(b"COVER-SITE").await;

    // First presentation: genuinely fresh ⇒ ServerHello (the attacker cannot finish it anyway).
    let (mut prober, mut srv) = tokio::io::duplex(64 * 1024);
    let (pol, psk2) = (ProbeResponse::Fallback(up_addr.clone()), psk.clone());
    tokio::spawn(async move {
        let _ = server_handshake_probe(&mut srv, &psk2, &pol).await;
    });
    prober.write_all(&ch).await.unwrap();
    let reply = read_record_raw(&mut prober).await.unwrap();
    assert_eq!(
        (reply[0], reply[5]),
        (0x16, 0x02),
        "fresh hello ⇒ ServerHello"
    );
    drop(prober);

    // Replays: the cover site answers, and it receives the replayed hello verbatim.
    for _ in 0..2 {
        rec.lock().await.clear();
        let (mut prober, mut srv) = tokio::io::duplex(64 * 1024);
        let (pol, psk2) = (ProbeResponse::Fallback(up_addr.clone()), psk.clone());
        let h = tokio::spawn(async move { server_handshake_probe(&mut srv, &psk2, &pol).await });
        prober.write_all(&ch).await.unwrap();
        let mut b = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(3), prober.read_exact(&mut b))
            .await
            .expect("cover site should answer")
            .unwrap();
        assert_eq!(&b, b"COVER-SITE", "replay must reach the cover site");
        assert_eq!(
            *rec.lock().await,
            ch,
            "upstream must get the full replayed hello"
        );
        drop(prober);
        assert!(matches!(h.await.unwrap(), Err(ObfsError::AuthFailed)));
    }
}

// ── Audit F3: cleartext epoch / static shape ─────────────────────────────────────────────────────

/// F3: v1 session_ids were `epoch_le(8) ‖ tag[..24]` — bytes 4..8 always zero, 0..4 the minute. All
/// 32 bytes must now look uniformly random, even across many hellos in the same epoch.
#[tokio::test]
async fn audit_session_id_has_no_cleartext_epoch() {
    let psk = ObfsPsk::new([0x33; 32]);
    // Real client hellos (end to end), a handful…
    let epoch = current_epoch();
    for _ in 0..4 {
        let ch = capture_ch(&psk, &fast_cfg()).await;
        let sid = tls::parse_client_hello(&ch).unwrap().session_id;
        assert_ne!(&sid[4..8], &[0, 0, 0, 0]);
        assert_ne!(&sid[..8], &epoch.to_le_bytes());
    }
    // …and a statistical test over many hellos at one fixed epoch.
    const N: usize = 512;
    let share = vec![0x42u8; tls::HYBRID_CLIENT_SHARE_LEN];
    let sids: Vec<[u8; 32]> = (0..N)
        .map(|_| {
            let ch = build_gated_client_hello(&mut OsRng, &psk, epoch, &share, "a.example");
            tls::parse_client_hello(&ch).unwrap().session_id
        })
        .collect();
    for pos in 0..32 {
        let distinct: HashSet<u8> = sids.iter().map(|s| s[pos]).collect();
        // Expected ≈ 256·(1 − e^{−2}) ≈ 221 for uniform bytes; a constant/epoch byte gives ≤ 2.
        assert!(
            distinct.len() >= 180,
            "session_id byte {pos} is structured ({} distinct values)",
            distinct.len()
        );
    }
    let ones: u32 = sids.iter().flatten().map(|b| b.count_ones()).sum();
    let frac = ones as f64 / (N * 256) as f64;
    assert!((0.49..=0.51).contains(&frac), "bit balance {frac}");
}

/// ClientHello size and extension order vary per connection (v1: always 1370 B, fixed order), and
/// the cover SNI rotates over the configured list.
#[tokio::test]
async fn client_hello_size_order_and_sni_vary() {
    let psk = ObfsPsk::new([0x44; 32]);
    let cfg = ClientConfig {
        cover_snis: vec![
            "a.example.com".into(),
            "bb.example.net".into(),
            "ccc.example.org".into(),
        ],
        ..fast_cfg()
    };
    let mut sizes = HashSet::new();
    let mut orders = HashSet::new();
    let mut snis = HashSet::new();
    for _ in 0..24 {
        let ch = capture_ch(&psk, &cfg).await;
        sizes.insert(ch.len());
        orders.insert(tls::client_hello_extension_order(&ch).unwrap());
        snis.insert(tls::parse_client_hello(&ch).unwrap().sni.unwrap());
        assert!(
            ch.len() > 1700,
            "PQ Chrome hellos are ~1.8-2 KB, got {}",
            ch.len()
        );
    }
    assert!(sizes.len() >= 3, "ClientHello size must vary: {sizes:?}");
    assert!(
        orders.len() >= 20,
        "extension order must be permuted per connection"
    );
    assert!(snis.len() >= 2, "cover SNI must rotate: {snis:?}");
}

// ── Audit F4: fallback must forward every byte, immediately ─────────────────────────────────────

/// F4: v1 parsed `GET /` as a TLS header with a bogus length, blocked ~10 s, then forwarded an EMPTY
/// prefix. Now a non-TLS opening falls back immediately and the upstream receives every byte.
#[tokio::test]
async fn audit_http_probe_forwarded_immediately_and_completely() {
    let (up_addr, rec) = recording_upstream(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let pol = ProbeResponse::Fallback(up_addr);
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let _ = server_handshake_probe(&mut s, &ObfsPsk::new([1; 32]), &pol).await;
    });
    let mut p = TcpStream::connect(addr).await.unwrap();
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    p.write_all(req).await.unwrap();
    let t0 = Instant::now();
    let mut b = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(3), p.read_exact(&mut b))
        .await
        .expect("prober must get the cover reply promptly")
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert_eq!(&b, b"HTTP/1.1 400");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        &rec.lock().await[..],
        &req[..],
        "every probe byte reaches the upstream"
    );
}

/// Review fix: a fallback relay can last up to FALLBACK_MAX_DURATION; in the libp2p upgrade it used
/// to hold a pending-incoming slot that whole time (64 lingering probers = no new inbound peers).
/// `server_handshake_detached` must return at once while the relay keeps serving the prober.
#[tokio::test]
async fn detached_probe_returns_immediately_while_relay_continues() {
    let (up_addr, rec) = recording_upstream(b"HTTP/1.1 200 OK\r\n\r\n").await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let pol = ProbeResponse::Fallback(up_addr);
    let server = tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let t0 = Instant::now();
        let r = server_handshake_detached(s, &ObfsPsk::new([1; 32]), &pol).await;
        (r.is_err(), t0.elapsed())
    });
    let mut p = TcpStream::connect(addr).await.unwrap();
    p.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let (failed, took) = server.await.unwrap();
    assert!(failed, "a probe is never an accepted session");
    assert!(
        took < Duration::from_secs(2),
        "handshake returned only after {took:?}"
    );
    // The prober keeps talking to the cover site through the detached relay.
    let mut b = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(3), p.read_exact(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b, b"HTTP/1.1 200 OK");
    p.write_all(b"more").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        rec.lock().await.ends_with(b"more"),
        "relay still alive after the handshake returned"
    );
}

/// F4b: an oversized declared record length falls back immediately with the header forwarded.
#[tokio::test]
async fn audit_oversized_header_forwarded_on_fallback() {
    let (up_addr, rec) = recording_upstream(b"x").await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let pol = ProbeResponse::Fallback(up_addr);
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let _ = server_handshake_probe(&mut s, &ObfsPsk::new([1; 32]), &pol).await;
    });
    let mut p = TcpStream::connect(addr).await.unwrap();
    p.write_all(&[0x16, 0x03, 0x01, 0x48, 0x01]).await.unwrap(); // 18433 > 16384
    tokio::time::sleep(Duration::from_millis(200)).await;
    p.write_all(b"TAIL").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(&rec.lock().await[..], b"\x16\x03\x01\x48\x01TAIL");
}

/// A real (foreign) TLS ClientHello that fails the gate is forwarded byte-for-byte, so the cover site
/// completes the TLS handshake with the prober.
#[tokio::test]
async fn foreign_client_hello_forwarded_verbatim() {
    let (up_addr, rec) = recording_upstream(b"SH").await;
    let foreign = build_gated_client_hello(
        &mut OsRng,
        &ObfsPsk::new([0xEE; 32]), // a different PSK ≈ any non-uber-mesh client
        current_epoch(),
        &vec![1u8; tls::HYBRID_CLIENT_SHARE_LEN],
        "www.example.com",
    );
    let (mut prober, mut srv) = tokio::io::duplex(64 * 1024);
    let pol = ProbeResponse::Fallback(up_addr);
    tokio::spawn(async move {
        let _ = server_handshake_probe(&mut srv, &ObfsPsk::new([0x01; 32]), &pol).await;
    });
    prober.write_all(&foreign).await.unwrap();
    let mut b = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), prober.read_exact(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*rec.lock().await, foreign);
}

// ── Wire shape & round trip ──────────────────────────────────────────────────────────────────────

/// Full round trip through a tap: verifies the v2 wire shape without a cover profile (SH → CCS →
/// 0x17 flight of 2500–5000 B in the PSK default layout; client CCS → 53-byte Finished record) and
/// data exchange.
#[tokio::test]
async fn round_trip_with_tls13_wire_shape() {
    let psk = ObfsPsk::new([0x55; 32]);
    let mut listener = ObfsListener::bind(
        "127.0.0.1:0",
        psk.clone(),
        ShapingPolicy::none(),
        ListenerConfig::default(),
    )
    .await
    .unwrap();
    let srv_addr = listener.local_addr();

    // Tap proxy recording each direction.
    let tap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tap_addr = tap.local_addr().unwrap();
    let c2s = Arc::new(Mutex::new(Vec::new()));
    let s2c = Arc::new(Mutex::new(Vec::new()));
    let (c2s2, s2c2) = (c2s.clone(), s2c.clone());
    tokio::spawn(async move {
        let (inb, _) = tap.accept().await.unwrap();
        let up = TcpStream::connect(srv_addr).await.unwrap();
        let (mut ir, mut iw) = inb.into_split();
        let (mut ur, mut uw) = up.into_split();
        let a = tokio::spawn(async move {
            let mut b = [0u8; 8192];
            while let Ok(n) = ir.read(&mut b).await {
                if n == 0 || uw.write_all(&b[..n]).await.is_err() {
                    break;
                }
                c2s2.lock().await.extend_from_slice(&b[..n]);
            }
        });
        let mut b = [0u8; 8192];
        while let Ok(n) = ur.read(&mut b).await {
            if n == 0 || iw.write_all(&b[..n]).await.is_err() {
                break;
            }
            s2c2.lock().await.extend_from_slice(&b[..n]);
        }
        let _ = a.await;
    });

    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let m = s.recv().await.unwrap();
        s.send(&m).await.unwrap();
    });
    let mut c = ObfsTcp::connect_with(tap_addr, &psk, ShapingPolicy::none(), &fast_cfg())
        .await
        .unwrap();
    c.send(b"ping over v2").await.unwrap();
    assert_eq!(c.recv().await.unwrap(), b"ping over v2");
    server.await.unwrap();

    // Server flight: ServerHello, CCS, then 0x17 records totalling 2500–5000 bytes of payload.
    let s2c = s2c.lock().await.clone();
    let sh_len = 5 + u16::from_be_bytes([s2c[3], s2c[4]]) as usize;
    assert!(tls::parse_server_hello(&s2c[..sh_len]).is_some());
    assert_eq!(&s2c[sh_len..sh_len + 6], &tls::CCS_RECORD);
    let mut p = sh_len + 6;
    let mut flight = 0usize;
    while flight < 2500 {
        assert_eq!(&s2c[p..p + 3], &[0x17, 0x03, 0x03]);
        let l = u16::from_be_bytes([s2c[p + 3], s2c[p + 4]]) as usize;
        flight += l;
        p += 5 + l;
    }
    assert!((2500..=5000).contains(&flight), "flight payload {flight}");

    // Client second flight: CCS + one Finished-sized (53 B) record, then application data.
    let c2s = c2s.lock().await.clone();
    let ch_len = 5 + u16::from_be_bytes([c2s[3], c2s[4]]) as usize;
    assert_eq!(&c2s[ch_len..ch_len + 6], &tls::CCS_RECORD);
    assert_eq!(&c2s[ch_len + 6..ch_len + 11], &[0x17, 0x03, 0x03, 0x00, 53]);
}

/// A client that passes the gate but sends a bad confirmation is not given a session.
#[tokio::test]
async fn bad_client_confirmation_is_rejected() {
    let psk = ObfsPsk::new([0x66; 32]);
    let (mut c, mut s) = tokio::io::duplex(64 * 1024);
    let psk_s = psk.clone();
    let server = tokio::spawn(async move { server_handshake(&mut s, &psk_s).await.map(|_| ()) });
    let ch = build_gated_client_hello(
        &mut OsRng,
        &psk,
        current_epoch(),
        &{
            let (_i, m) = kem::Initiator::start();
            let mut v = m.mlkem_ek.clone();
            v.extend_from_slice(&m.x25519_pub);
            v
        },
        "a.example",
    );
    c.write_all(&ch).await.unwrap();
    let _ = read_for(&mut c, Duration::from_millis(300)).await;
    let mut fin = tls::CCS_RECORD.to_vec();
    fin.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 53]);
    fin.extend_from_slice(&[0u8; 53]);
    c.write_all(&fin).await.unwrap();
    assert!(matches!(server.await.unwrap(), Err(ObfsError::AuthFailed)));
}

// ── Timeouts & concurrency ───────────────────────────────────────────────────────────────────────

/// Audit M6: an endpoint that accepts TCP and then silently freezes must be rotated past within the
/// handshake timeout (v1 hung forever).
#[tokio::test]
async fn client_timeout_rotates_past_silent_endpoint() {
    let frozen = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let frozen_addr = frozen.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = frozen.accept().await {
            held.push(s); // never answer, never close
        }
    });
    let psk = ObfsPsk::new([0x77; 32]);
    let mut listener = ObfsListener::bind(
        "127.0.0.1:0",
        psk.clone(),
        ShapingPolicy::none(),
        ListenerConfig::default(),
    )
    .await
    .unwrap();
    let good_addr = listener.local_addr().to_string();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = s.recv().await;
    });

    let cfg = ClientConfig {
        handshake_timeout: Duration::from_millis(500),
        ..fast_cfg()
    };
    let eps = vec![
        Endpoint::new(frozen_addr, psk.clone()),
        Endpoint::new(good_addr, psk.clone()),
    ];
    let t0 = Instant::now();
    let mut s = tokio::time::timeout(
        Duration::from_secs(5),
        connect_first_working_with(&eps, ShapingPolicy::none(), &cfg),
    )
    .await
    .expect("rotation must not hang on a frozen endpoint")
    .expect("should rotate to the live endpoint");
    assert!(t0.elapsed() < Duration::from_secs(3));
    s.send(b"rotated").await.unwrap();
}

/// Audit M7: one silent probe must not block other clients behind it (v1 ran the handshake inline in
/// the accept loop: ~10 s stall per probe).
#[tokio::test]
async fn listener_not_blocked_by_silent_probe() {
    let psk = ObfsPsk::new([0x88; 32]);
    let mut listener = ObfsListener::bind(
        "127.0.0.1:0",
        psk.clone(),
        ShapingPolicy::none(),
        ListenerConfig::default(),
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    let _probes: Vec<TcpStream> = futures::future::join_all(
        (0..3).map(|_| async { TcpStream::connect(addr).await.unwrap() }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let server = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    let t0 = Instant::now();
    let _c = ObfsTcp::connect_with(addr, &psk, ShapingPolicy::none(), &fast_cfg())
        .await
        .expect("client must not wait behind silent probes");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("accept returned promptly")
        .unwrap()
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2));
}

/// Same guarantee for the legacy `ObfsTcp::accept` API.
#[tokio::test]
async fn legacy_accept_not_blocked_by_silent_probe() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let psk = ObfsPsk::new([0x99; 32]);
    let psk_s = psk.clone();
    let server = tokio::spawn(async move {
        ObfsTcp::accept(&l, &psk_s, ShapingPolicy::none())
            .await
            .map(|_| ())
    });
    let _probe = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t0 = Instant::now();
    let _c = ObfsTcp::connect_with(addr, &psk, ShapingPolicy::none(), &fast_cfg())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("accept returned promptly")
        .unwrap()
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2));
}

// ── Determinism (KAT-style regression vectors) ──────────────────────────────────────────────────

/// The Chrome template + gate are a pure function of (rng seed, psk, epoch, share, sni). Pinning the
/// hash catches unintended wire changes; update it only together with a wire-version bump.
#[test]
fn kat_gated_client_hello() {
    let psk = ObfsPsk::new([0x07; 32]);
    let share: Vec<u8> = (0..tls::HYBRID_CLIENT_SHARE_LEN).map(|i| i as u8).collect();
    let ch = build_gated_client_hello(
        &mut StdRng::seed_from_u64(0x5eed),
        &psk,
        29_000_000,
        &share,
        "www.example.com",
    );
    assert!(verify_client_hello(&psk, &ch, 29_000_000).is_some());
    assert_eq!(
        (ch.len(), hex(&hash(&ch))),
        (KAT_CH_LEN, KAT_CH_HASH.to_string()),
        "ClientHello template changed (wire-breaking): update KAT + bump wire version"
    );
}

/// The v2 key schedule is a pure function of (ss, psk, ClientHello, ServerHello).
#[test]
fn kat_key_schedule() {
    let fps = key_schedule_fingerprint(
        &[0x01; 32],
        &ObfsPsk::new([0x02; 32]),
        b"client hello bytes",
        b"server hello bytes",
    );
    let got: Vec<String> = fps.iter().map(|f| hex(&f[..8])).collect();
    assert_eq!(got, KAT_KS.to_vec());
    // All four derived keys are distinct; changing any input changes them all.
    assert_eq!(fps.iter().collect::<HashSet<_>>().len(), 4);
    for (ss, psk, ch, sh) in [
        (
            [0x09; 32],
            [0x02; 32],
            &b"client hello bytes"[..],
            &b"server hello bytes"[..],
        ),
        (
            [0x01; 32],
            [0x03; 32],
            b"client hello bytes",
            b"server hello bytes",
        ),
        (
            [0x01; 32],
            [0x02; 32],
            b"client hello byteZ",
            b"server hello bytes",
        ),
        (
            [0x01; 32],
            [0x02; 32],
            b"client hello bytes",
            b"server hello byteZ",
        ),
    ] {
        let other = key_schedule_fingerprint(&ss, &ObfsPsk::new(psk), ch, sh);
        for i in 0..4 {
            assert_ne!(other[i], fps[i]);
        }
    }
}

const KAT_CH_LEN: usize = 1821;
const KAT_CH_HASH: &str = "16d5c616ceb15ed0d093c1a19de09366680690f405f6d826b685e60eaabf70b5";
const KAT_KS: [&str; 4] = [
    "98d55cf4f1ad6c8e",
    "47b267757dd483e5",
    "c67834a19206a477",
    "ef98d88364790295",
];

#[allow(dead_code)]
async fn _api_still_exported() {
    let (mut a, _b) = tokio::io::duplex(1);
    let _ = client_handshake(&mut a, &ObfsPsk::new([0; 32])).await;
}
