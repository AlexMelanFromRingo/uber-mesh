//! A real DPI middlebox in the connection path that BLOCKS "fully-encrypted" flows using the
//! USENIX'23 entropy/no-header heuristic (the primary modern censor technique — dossier §2). We
//! verify that:
//!   1. the obfs transport **passes** the DPI box (its TLS-record-framed first flight is exempt) and
//!      the handshake + data exchange complete *through* the censor, and
//!   2. a raw high-entropy flow (what a naive encrypted proxy looks like) is **blocked** — proving
//!      the box genuinely censors, so (1) is meaningful.
//!
//! (SNI filtering is orthogonal: the obfs flow presents no TLS ClientHello/SNI, so an SNI blocklist
//! has nothing to match; the REALITY-style fallback handles active probers separately.)

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use umesh_obfs::wire::{is_tls_record_header, looks_fully_encrypted};
use umesh_obfs::{ObfsPsk, ObfsTcp, ShapingPolicy};

/// A censor box: peek the first bytes; if they look fully-encrypted (no recognizable header + high
/// popcount) → DROP. Otherwise forward to `upstream_port`, replaying the peeked bytes.
async fn dpi_box(upstream_port: u16, allowed: Arc<AtomicUsize>, blocked: Arc<AtomicUsize>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = l.accept().await else {
                break;
            };
            let (allowed, blocked) = (allowed.clone(), blocked.clone());
            tokio::spawn(async move {
                let mut peek = vec![0u8; 64];
                let n = match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut peek))
                    .await
                {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                };
                if looks_fully_encrypted(&peek[..n]) {
                    blocked.fetch_add(1, Ordering::SeqCst); // CENSOR: drop the flow
                    return;
                }
                allowed.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut up) = TcpStream::connect(("127.0.0.1", upstream_port)).await {
                    let _ = up.write_all(&peek[..n]).await;
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut up).await;
                }
            });
        }
    });
    port
}

async fn spawn_obfs_echo(psk: ObfsPsk) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            match ObfsTcp::accept(&l, &psk, ShapingPolicy::aggressive()).await {
                Ok((mut s, _)) => {
                    tokio::spawn(async move {
                        while let Ok(m) = s.recv().await {
                            if s.send(&m).await.is_err() {
                                break;
                            }
                        }
                    });
                }
                Err(_) => continue,
            }
        }
    });
    port
}

#[tokio::test]
async fn obfs_passes_entropy_dpi_box() {
    let psk = ObfsPsk([3u8; 32]);
    let upstream = spawn_obfs_echo(psk.clone()).await;
    let allowed = Arc::new(AtomicUsize::new(0));
    let blocked = Arc::new(AtomicUsize::new(0));
    let box_port = dpi_box(upstream, allowed.clone(), blocked.clone()).await;

    // Connect via obfs THROUGH the censor box. The TLS-record-framed first flight is exempt.
    let mut c = ObfsTcp::connect(("127.0.0.1", box_port), &psk, ShapingPolicy::aggressive())
        .await
        .expect("obfs handshake should complete through the DPI box");
    c.send(b"hello through the censor").await.unwrap();
    assert_eq!(c.recv().await.unwrap(), b"hello through the censor");

    assert!(
        allowed.load(Ordering::SeqCst) >= 1,
        "obfs flow must be ALLOWED by the entropy DPI box"
    );
    assert_eq!(
        blocked.load(Ordering::SeqCst),
        0,
        "obfs flow must not be blocked"
    );
}

#[tokio::test]
async fn raw_encrypted_flow_is_blocked() {
    let psk = ObfsPsk([4u8; 32]);
    let upstream = spawn_obfs_echo(psk).await;
    let allowed = Arc::new(AtomicUsize::new(0));
    let blocked = Arc::new(AtomicUsize::new(0));
    let box_port = dpi_box(upstream, allowed.clone(), blocked.clone()).await;

    // A naive encrypted proxy: high-entropy, no recognizable header. The censor must drop it.
    let mut raw = TcpStream::connect(("127.0.0.1", box_port)).await.unwrap();
    let junk: Vec<u8> = (0..2048u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    raw.write_all(&junk).await.unwrap();

    // The box drops it ⇒ no forwarding, connection closes with no reply.
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), raw.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    assert_eq!(n, 0, "a censored raw flow receives nothing");
    assert_eq!(
        allowed.load(Ordering::SeqCst),
        0,
        "raw flow must not be allowed"
    );
    assert!(
        blocked.load(Ordering::SeqCst) >= 1,
        "raw high-entropy flow must be BLOCKED by the DPI box"
    );
}

// ── Active-probing censor ────────────────────────────────────────────────────────────────────────
// A stronger censor: for a flow that passes the entropy filter, it ALSO actively probes the
// destination (opens its own connection, sends junk) — if the server *responds* like a proxy, block.

async fn active_probe(upstream_port: u16) -> bool {
    let Ok(mut p) = TcpStream::connect(("127.0.0.1", upstream_port)).await else {
        return false;
    };
    let _ = p.write_all(b"GET / HTTP/1.0\r\n\r\n").await; // unauthenticated junk probe
    let mut b = [0u8; 16];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), p.read(&mut b)).await,
        Ok(Ok(n)) if n > 0 // a reply ⇒ looks like a proxy/server answering probes
    )
}

async fn probing_dpi(
    upstream_port: u16,
    allowed: Arc<AtomicUsize>,
    blocked: Arc<AtomicUsize>,
) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = l.accept().await else {
                break;
            };
            let (allowed, blocked) = (allowed.clone(), blocked.clone());
            tokio::spawn(async move {
                let mut peek = vec![0u8; 64];
                let n = match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut peek))
                    .await
                {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                };
                if looks_fully_encrypted(&peek[..n]) || active_probe(upstream_port).await {
                    blocked.fetch_add(1, Ordering::SeqCst); // entropy OR active-probe unmasked it
                    return;
                }
                allowed.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut up) = TcpStream::connect(("127.0.0.1", upstream_port)).await {
                    let _ = up.write_all(&peek[..n]).await;
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut up).await;
                }
            });
        }
    });
    port
}

async fn spawn_echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn obfs_survives_active_probing() {
    let psk = ObfsPsk([5u8; 32]);
    let upstream = spawn_obfs_echo(psk.clone()).await;
    let (allowed, blocked) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let box_port = probing_dpi(upstream, allowed.clone(), blocked.clone()).await;

    // The obfs server answers the censor's active probe with SILENCE ⇒ the probe cannot unmask it.
    let mut c = ObfsTcp::connect(("127.0.0.1", box_port), &psk, ShapingPolicy::aggressive())
        .await
        .expect("obfs handshake should survive the active-probing censor");
    c.send(b"under active probing").await.unwrap();
    assert_eq!(c.recv().await.unwrap(), b"under active probing");
    assert!(
        allowed.load(Ordering::SeqCst) >= 1,
        "obfs must survive active probing"
    );
}

#[tokio::test]
async fn naive_proxy_is_unmasked_by_active_probing() {
    // A naive server that answers everything (no probe resistance) is caught by the active probe.
    let echo = spawn_echo_server().await;
    let (allowed, blocked) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let box_port = probing_dpi(echo, allowed.clone(), blocked.clone()).await;

    // A low-entropy (TLS-prefixed) flow passes the entropy filter, but the active probe unmasks the
    // always-answering upstream ⇒ blocked.
    let mut client = TcpStream::connect(("127.0.0.1", box_port)).await.unwrap();
    let mut rec = vec![0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]; // TLS-record-shaped, low entropy
    rec.extend_from_slice(&[0x20; 16]); // printable padding to stay out of the entropy band
    client.write_all(&rec).await.unwrap();
    let mut b = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut b))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    assert_eq!(n, 0, "the naive proxy's flow is cut after active probing");
    assert!(
        blocked.load(Ordering::SeqCst) >= 1,
        "active probing must unmask a naive always-answering server"
    );
}

// ── TLS state-machine censor ─────────────────────────────────────────────────────────────────────
// A stricter censor that enforces the TLS handshake state machine: a genuine TLS flow MUST open with
// a *handshake* record (ClientHello, content_type 0x16). A flow that opens with application-data
// (0x17) before any handshake is anomalous → DROP. This is exactly the heuristic that flagged the old
// app-data-first obfs carrier; the ClientHello-mimicry first flight now passes it.

async fn state_machine_dpi(
    upstream_port: u16,
    allowed: Arc<AtomicUsize>,
    blocked: Arc<AtomicUsize>,
) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = l.accept().await else {
                break;
            };
            let (allowed, blocked) = (allowed.clone(), blocked.clone());
            tokio::spawn(async move {
                let mut peek = vec![0u8; 64];
                let n = match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut peek))
                    .await
                {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                };
                // The first record must be a TLS *handshake* (ClientHello), not application-data.
                if !is_tls_record_header(&peek[..n]) || peek[0] != 0x16 {
                    blocked.fetch_add(1, Ordering::SeqCst); // CENSOR: app-data before handshake
                    return;
                }
                allowed.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut up) = TcpStream::connect(("127.0.0.1", upstream_port)).await {
                    let _ = up.write_all(&peek[..n]).await;
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut up).await;
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn obfs_passes_tls_state_machine_dpi() {
    let psk = ObfsPsk([6u8; 32]);
    let upstream = spawn_obfs_echo(psk.clone()).await;
    let (allowed, blocked) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let box_port = state_machine_dpi(upstream, allowed.clone(), blocked.clone()).await;

    // The obfs first flight is a ClientHello (0x16) ⇒ accepted by the state-machine censor; the
    // handshake and data exchange complete *through* it.
    let mut c = ObfsTcp::connect(("127.0.0.1", box_port), &psk, ShapingPolicy::aggressive())
        .await
        .expect("obfs handshake must pass the TLS-state-machine DPI (opens with a ClientHello)");
    c.send(b"clienthello-first").await.unwrap();
    assert_eq!(c.recv().await.unwrap(), b"clienthello-first");
    assert!(
        allowed.load(Ordering::SeqCst) >= 1,
        "obfs flow must be ALLOWED by the TLS-state-machine box"
    );
    assert_eq!(blocked.load(Ordering::SeqCst), 0, "obfs flow must not be blocked");
}

#[tokio::test]
async fn appdata_first_flow_is_blocked_by_state_machine() {
    // A carrier that opens with a TLS *application-data* record (the old obfs behaviour, and what any
    // "looks-like-TLS" obfuscator without handshake mimicry emits) is anomalous to a state-machine
    // censor — proving the box genuinely enforces the state machine, so the pass above is meaningful.
    let upstream = spawn_echo_server().await;
    let (allowed, blocked) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let box_port = state_machine_dpi(upstream, allowed.clone(), blocked.clone()).await;

    let mut client = TcpStream::connect(("127.0.0.1", box_port)).await.unwrap();
    // 0x17 = application-data, low-entropy body: passes a naive entropy filter but NOT the state
    // machine (no preceding handshake).
    let mut rec = vec![0x17, 0x03, 0x03, 0x00, 0x08];
    rec.extend_from_slice(&[0x20; 8]);
    client.write_all(&rec).await.unwrap();

    let mut b = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut b))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    assert_eq!(n, 0, "an app-data-first flow is cut by the state-machine censor");
    assert_eq!(allowed.load(Ordering::SeqCst), 0, "app-data-first flow must not be allowed");
    assert!(
        blocked.load(Ordering::SeqCst) >= 1,
        "an app-data-first flow must be BLOCKED by the TLS-state-machine box"
    );
}
