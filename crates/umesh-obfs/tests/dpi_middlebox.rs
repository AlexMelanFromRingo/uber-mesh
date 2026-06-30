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

use umesh_obfs::wire::looks_fully_encrypted;
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
