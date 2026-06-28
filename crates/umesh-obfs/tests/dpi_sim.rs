//! DPI-simulation integration test (spec US1, SC-001/SC-002).
//!
//! Exercises the obfs-tcp transport over real loopback TCP against a simulated censor:
//!   1. establishment + authenticated data exchange,
//!   2. active-probe resistance (a prober receives no distinguishing reply → silence + close),
//!   3. first-flight entropy mitigation (the wire opens with a TLS record header),
//!   4. connect-time transport rotation past a dead endpoint.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use umesh_obfs::wire::{TLS_PREFIX, looks_fully_encrypted};
use umesh_obfs::{Endpoint, ObfsError, ObfsPsk, ObfsTcp, ShapingPolicy, connect_first_working};

const FLIGHT1_LEN: usize = 16 + 32 + 1184 + 8 + 16;

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

/// 2. An active prober (record-shaped junk, wrong MAC) receives no bytes — only silence then close.
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

    // Probe: a correctly-framed flight-1-sized record full of junk → MAC mismatch.
    let mut probe = TcpStream::connect(addr).await.unwrap();
    let mut rec = vec![TLS_PREFIX[0], TLS_PREFIX[1], TLS_PREFIX[2], 0, 0];
    rec[3..5].copy_from_slice(&(FLIGHT1_LEN as u16).to_be_bytes());
    rec.extend_from_slice(&vec![0u8; FLIGHT1_LEN]);
    probe.write_all(&rec).await.unwrap();

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(3), probe.read(&mut buf))
        .await
        .expect("probe should be closed quickly, not hang")
        .expect("read");
    assert_eq!(n, 0, "a prober must receive zero distinguishing bytes");
    server.await.unwrap();
}

/// 3. The first flight on the wire opens with a TLS record header (defeats the no-header classifier).
#[tokio::test]
async fn first_flight_is_tls_prefixed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let cap2 = captured.clone();

    let recorder = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut hdr = [0u8; 5];
        let _ = s.read_exact(&mut hdr).await;
        cap2.lock().await.extend_from_slice(&hdr);
        // drop the connection — the client's handshake will then error, which is fine here.
    });

    let _ = ObfsTcp::connect(addr, &ObfsPsk([1u8; 32]), ShapingPolicy::none()).await;
    recorder.await.unwrap();

    let first = captured.lock().await.clone();
    assert!(first.len() >= 3);
    assert_eq!(
        &first[..3],
        &TLS_PREFIX,
        "carrier must open with a TLS record header"
    );
    assert!(
        !looks_fully_encrypted(&first),
        "censor classifier must not flag the opening"
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
