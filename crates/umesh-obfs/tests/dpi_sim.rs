//! DPI-simulation integration test (spec US1, SC-001/SC-002).
//!
//! Exercises the obfs-tcp transport over real loopback TCP against a simulated censor:
//!   1. establishment + authenticated data exchange,
//!   2. active-probe resistance (a prober receives no distinguishing reply → silence + close),
//!   3. first-flight mimicry (the wire opens with a structurally-valid TLS 1.3 ClientHello),
//!   4. connect-time transport rotation past a dead endpoint.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use umesh_obfs::wire::{TLS_PREFIX, is_tls_record_header, looks_fully_encrypted};
use umesh_obfs::{
    Endpoint, ObfsError, ObfsPsk, ObfsTcp, ProbeResponse, ShapingPolicy, connect_first_working,
    server_handshake_probe,
};

/// A plausible TLS record size for a junk probe (not a valid ClientHello).
const PROBE_REC_LEN: usize = 1264;

/// 1. A client and server complete the obfs handshake and exchange an authenticated message.
#[tokio::test]
async fn establishes_and_exchanges_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let psk = ObfsPsk([7u8; 32]);
    let psk_s = psk.clone();

    let server = tokio::spawn(async move {
        let (mut s, _peer) = ObfsTcp::accept(&listener, &psk_s, ShapingPolicy::aggressive())
            .await
            .expect("server handshake");
        let m = s.recv().await.expect("recv");
        s.send(&m).await.expect("echo"); // echo back
    });

    let mut c = ObfsTcp::connect(addr, &psk, ShapingPolicy::aggressive())
        .await
        .expect("client handshake");
    c.send(b"hello over a censored link").await.unwrap();
    let echoed = c.recv().await.unwrap();
    assert_eq!(echoed, b"hello over a censored link");
    server.await.unwrap();
}

/// 2. An active prober (record-shaped junk, not a valid ClientHello) receives no bytes — only
///    silence then close.
#[tokio::test]
async fn active_probe_gets_silence() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let r = ObfsTcp::accept(&listener, &ObfsPsk([7u8; 32]), ShapingPolicy::none()).await;
        assert!(
            matches!(r, Err(ObfsError::AuthFailed)),
            "probe must fail the gate"
        );
    });

    // Probe: a correctly-framed record full of junk → does not parse as a gated ClientHello.
    let mut probe = TcpStream::connect(addr).await.unwrap();
    let mut rec = vec![TLS_PREFIX[0], TLS_PREFIX[1], TLS_PREFIX[2], 0, 0];
    rec[3..5].copy_from_slice(&(PROBE_REC_LEN as u16).to_be_bytes());
    rec.extend_from_slice(&vec![0u8; PROBE_REC_LEN]);
    probe.write_all(&rec).await.unwrap();

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(3), probe.read(&mut buf))
        .await
        .expect("probe should be closed quickly, not hang")
        .expect("read");
    assert_eq!(n, 0, "a prober must receive zero distinguishing bytes");
    server.await.unwrap();
}

/// 3. The first flight on the wire is a structurally-valid TLS 1.3 ClientHello (handshake record
///    `0x16` carrying a PQ-hybrid X25519MLKEM768 key_share) — it defeats both the no-header entropy
///    classifier AND the TLS-state-machine heuristic (a real TLS flow opens with a ClientHello, not
///    application data).
#[tokio::test]
async fn first_flight_is_a_client_hello() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let cap2 = captured.clone();

    let recorder = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut hdr = [0u8; 5];
        if s.read_exact(&mut hdr).await.is_ok() {
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut body = vec![0u8; len];
            let _ = s.read_exact(&mut body).await;
            let mut rec = hdr.to_vec();
            rec.extend_from_slice(&body);
            cap2.lock().await.extend_from_slice(&rec);
        }
        // drop the connection — the client's handshake will then error, which is fine here.
    });

    let _ = ObfsTcp::connect(addr, &ObfsPsk([1u8; 32]), ShapingPolicy::none()).await;
    recorder.await.unwrap();

    let first = captured.lock().await.clone();
    assert!(first.len() >= 5);
    // Opens with a TLS *handshake* record (0x16), not application-data.
    assert_eq!(first[0], 0x16, "first flight must be a TLS handshake record");
    assert!(is_tls_record_header(&first));
    assert!(
        !looks_fully_encrypted(&first),
        "censor classifier must not flag the opening"
    );
    // ...and it parses as a real ClientHello carrying the 1216-byte PQ-hybrid key_share.
    let (_sid, key_share) = umesh_obfs::tls::parse_client_hello(&first)
        .expect("first flight must parse as a TLS 1.3 ClientHello");
    assert_eq!(
        key_share.len(),
        1184 + 32,
        "X25519MLKEM768 key_share = ml-kem-768 ek ‖ x25519 pub"
    );
}

/// 4. Rotation: connect_first_working skips a dead endpoint and connects via a live one (SC-002).
#[tokio::test]
async fn rotates_past_dead_endpoint() {
    // Dead endpoint: accepts then immediately drops (handshake fails).
    let bad = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = bad.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((s, _)) = bad.accept().await {
            drop(s);
        }
    });

    // Live endpoint: a real obfs server.
    let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good_addr = good.local_addr().unwrap().to_string();
    let psk = ObfsPsk([5u8; 32]);
    let psk_s = psk.clone();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = ObfsTcp::accept(&good, &psk_s, ShapingPolicy::none()).await {
            let _ = s.recv().await;
        }
    });

    let eps = vec![
        Endpoint::new(bad_addr, psk.clone()),
        Endpoint::new(good_addr, psk.clone()),
    ];
    let mut s = connect_first_working(&eps, ShapingPolicy::none())
        .await
        .expect("should rotate to the live endpoint");
    s.send(b"via rotation").await.unwrap();
}

/// 5. REALITY/ShadowTLS-style fallback: a prober that fails the gate is transparently reverse-proxied
///    to a real cover upstream and receives the upstream's genuine content (active-probe resistance).
#[tokio::test]
async fn probe_is_proxied_to_cover_site() {
    // A "real site" upstream that greets any connection.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = upstream.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = upstream.accept().await {
            let mut buf = [0u8; 128];
            let _ = s.read(&mut buf).await; // consume the forwarded probe bytes
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nreal-site-content")
                .await;
            let _ = s.flush().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });

    // The obfs server, configured to fall back to the cover upstream on gate failure.
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = server.local_addr().unwrap().to_string();
    let probe_policy = ProbeResponse::Fallback(up_addr);
    tokio::spawn(async move {
        if let Ok((mut s, _)) = server.accept().await {
            let r = server_handshake_probe(&mut s, &ObfsPsk([1u8; 32]), &probe_policy).await;
            assert!(matches!(r, Err(ObfsError::AuthFailed)));
        }
    });

    // A prober sends a record-shaped junk flight (not a gated ClientHello) and should receive the
    // cover content rather than anything that distinguishes uber-mesh.
    let mut probe = TcpStream::connect(&srv_addr).await.unwrap();
    let body = vec![0u8; 1264];
    let mut rec = vec![TLS_PREFIX[0], TLS_PREFIX[1], TLS_PREFIX[2], 0, 0];
    rec[3..5].copy_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(&body);
    probe.write_all(&rec).await.unwrap();

    let mut buf = vec![0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(5), probe.read(&mut buf))
        .await
        .expect("should receive proxied content")
        .expect("read");
    let got = String::from_utf8_lossy(&buf[..n]);
    assert!(
        got.contains("real-site-content"),
        "prober must receive the cover site's content, got: {got:?}"
    );
}
