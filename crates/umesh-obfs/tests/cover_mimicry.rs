//! Cover-site mimicry (REALITY-style "know your cover"): the listener learns its cover site's TLS 1.3
//! server-flight layout and its authenticated flight reproduces it, so a validating censor sees the
//! same record structure from the bridge as from the real site — including when it replays a
//! genuine ClientHello (which is proxied to the real site).
//!
//! No network: the "cover site" is a local TLS-1.3-shaped server that answers a ClientHello with a
//! canned flight (ServerHello of a given shape, optional CCS, encrypted records of given sizes),
//! modelled on common real layouts (BoringSSL-style coalesced flight with X25519MLKEM768; OpenSSL
//! style split EE/Certificate/CertificateVerify/Finished with x25519 + AES-256). Its bodies are
//! filler: only the record structure matters to the learner and to an observer.

use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use umesh_obfs::tls::{self, ServerGroup, ServerHelloShape};
use umesh_obfs::wire::{TLS_PREFIX, read_record_raw};
use umesh_obfs::{
    ClientConfig, CoverProfile, CoverRefresh, CoverSite, ListenerConfig, ObfsListener, ObfsPsk,
    ObfsTcp, ProbeResponse, ShapingPolicy,
};

const DOMAIN: &str = "cdn.cover.example";

/// What the fake cover site answers to a ClientHello.
#[derive(Clone)]
enum Answer {
    Flight(ServerHelloShape, bool, Vec<usize>),
    Alert,
}

struct FakeCover {
    addr: String,
    answers: Arc<Mutex<Vec<Answer>>>, // used front to back; the last one repeats
    hellos: Arc<Mutex<Vec<Vec<u8>>>>, // every first record received
    other: Arc<Mutex<Vec<u8>>>,       // bytes of non-ClientHello connections
}

fn boring() -> ServerHelloShape {
    ServerHelloShape {
        cipher_suite: 0x1301,
        group: ServerGroup::X25519MlKem768,
        key_share_first: true,
    }
}

fn openssl() -> ServerHelloShape {
    ServerHelloShape {
        cipher_suite: 0x1302,
        group: ServerGroup::X25519,
        key_share_first: false,
    }
}

fn canned_flight(sid: &[u8; 32], shape: &ServerHelloShape, ccs: bool, recs: &[usize]) -> Vec<u8> {
    let share = vec![0x3c; shape.group.share_len()];
    let mut out = tls::build_server_hello_shaped(&mut OsRng, sid, shape, &share);
    if ccs {
        out.extend_from_slice(&tls::CCS_RECORD);
    }
    for &l in recs {
        out.extend_from_slice(&TLS_PREFIX);
        out.extend_from_slice(&(l as u16).to_be_bytes());
        let mut body = vec![0u8; l];
        rand::RngCore::fill_bytes(&mut OsRng, &mut body);
        out.extend_from_slice(&body);
    }
    out
}

async fn fake_cover(answers: Vec<Answer>) -> FakeCover {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fc = FakeCover {
        addr: l.local_addr().unwrap().to_string(),
        answers: Arc::new(Mutex::new(answers)),
        hellos: Arc::default(),
        other: Arc::default(),
    };
    let (answers, hellos, other) = (fc.answers.clone(), fc.hellos.clone(), fc.other.clone());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (answers, hellos, other) = (answers.clone(), hellos.clone(), other.clone());
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if s.peek(&mut first).await.unwrap_or(0) == 0 {
                    return;
                }
                if first[0] != 0x16 {
                    // Not TLS: behave like a web server answering garbage.
                    let mut b = [0u8; 4096];
                    if let Ok(n) = s.read(&mut b).await {
                        other.lock().await.extend_from_slice(&b[..n]);
                    }
                    let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                }
                let Ok(ch) = read_record_raw(&mut s).await else {
                    return;
                };
                hellos.lock().await.push(ch.clone());
                let answer = {
                    let mut a = answers.lock().await;
                    if a.len() > 1 {
                        a.remove(0)
                    } else {
                        a[0].clone()
                    }
                };
                let reply = match (answer, tls::parse_client_hello(&ch)) {
                    (Answer::Flight(shape, ccs, recs), Some(info)) => {
                        canned_flight(&info.session_id, &shape, ccs, &recs)
                    }
                    // illegal_parameter alert
                    _ => vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f],
                };
                let _ = s.write_all(&reply).await;
                // Like a real server: wait for the client's Finished (it never comes), then close.
                let mut sink = [0u8; 1024];
                let _ = tokio::time::timeout(Duration::from_secs(5), s.read(&mut sink)).await;
            });
        }
    });
    fc
}

/// Record layout `(content type, payload length)` of a byte stream (complete records only).
fn layout(bytes: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 5 <= bytes.len() {
        let len = u16::from_be_bytes([bytes[p + 3], bytes[p + 4]]) as usize;
        if p + 5 + len > bytes.len() {
            break;
        }
        out.push((bytes[p], len));
        p += 5 + len;
    }
    out
}

/// Read what the peer sends for `dur` (until EOF / quiet).
async fn read_for(s: &mut TcpStream, dur: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + dur;
    while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, s.read(&mut b)).await {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&b[..n]);
    }
    out
}

/// A TCP tap in front of `target`: returns its address and the (c→s, s→c) byte logs of the first
/// connection.
type Log = Arc<Mutex<Vec<u8>>>;
async fn tap(target: std::net::SocketAddr) -> (std::net::SocketAddr, Log, Log) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (c2s, s2c): (Log, Log) = (Arc::default(), Arc::default());
    let (c2s2, s2c2) = (c2s.clone(), s2c.clone());
    tokio::spawn(async move {
        let (inb, _) = l.accept().await.unwrap();
        let up = TcpStream::connect(target).await.unwrap();
        let (mut ir, mut iw) = inb.into_split();
        let (mut ur, mut uw) = up.into_split();
        tokio::spawn(async move {
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
            if n == 0 {
                break;
            }
            s2c2.lock().await.extend_from_slice(&b[..n]);
            if iw.write_all(&b[..n]).await.is_err() {
                break;
            }
        }
    });
    (addr, c2s, s2c)
}

fn client_cfg() -> ClientConfig {
    ClientConfig {
        cover_domain: Some(DOMAIN.to_string()),
        handshake_timeout: Duration::from_secs(3),
        connect_timeout: Duration::from_secs(3),
        ..ClientConfig::default()
    }
}

/// The learner connects with our exact Chrome ClientHello (SNI = cover domain) and records the
/// cover's layout.
#[tokio::test]
async fn profile_is_learned_from_local_tls13_server() {
    for (shape, ccs, recs) in [
        (boring(), true, vec![4012]),
        (openssl(), false, vec![36, 2875, 281, 69]),
    ] {
        let cover = fake_cover(vec![Answer::Flight(shape, ccs, recs.clone())]).await;
        let site = CoverSite::new(cover.addr.clone(), Some(DOMAIN)).unwrap();
        let p = site.refresh(Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            *p,
            CoverProfile {
                server_hello: shape,
                ccs,
                records: recs
            }
        );
        assert_eq!(site.profile().as_deref(), Some(&*p));
        let hellos = cover.hellos.lock().await;
        let info = tls::parse_client_hello(&hellos[0]).expect("Chrome ClientHello");
        assert_eq!(info.sni.as_deref(), Some(DOMAIN));
        assert_eq!(hellos[0][1..3], [0x03, 0x01]);
    }
}

/// Core property: a genuine client's session and a censor's replay of that client's ClientHello
/// (proxied by the bridge to the real cover site) show the SAME server record layout — ServerHello
/// length, CCS, every encrypted record size — for both common cover layouts.
#[tokio::test]
async fn bridge_flight_is_indistinguishable_from_cover_flight() {
    for (shape, ccs, recs) in [
        (boring(), true, vec![4012]),
        (openssl(), true, vec![36, 2875, 281, 69]),
        (openssl(), false, vec![6120, 264, 69]),
    ] {
        let cover = fake_cover(vec![Answer::Flight(shape, ccs, recs.clone())]).await;
        let site = CoverSite::new(cover.addr.clone(), Some(DOMAIN)).unwrap();
        site.refresh(Duration::from_secs(5)).await.unwrap();

        let psk = ObfsPsk::new([0x5c; 32]);
        let mut listener = ObfsListener::bind(
            "127.0.0.1:0",
            psk.clone(),
            ShapingPolicy::none(),
            ListenerConfig {
                probe: ProbeResponse::Cover(site),
                ..ListenerConfig::default()
            },
        )
        .await
        .unwrap();
        let bridge_addr = listener.local_addr();
        let (tap_addr, c2s, s2c) = tap(bridge_addr).await;
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let m = s.recv().await.unwrap();
            s.send(&m).await.unwrap();
            (s, listener)
        });
        let mut c = ObfsTcp::connect_with(tap_addr, &psk, ShapingPolicy::none(), &client_cfg())
            .await
            .unwrap();
        c.send(b"through the cover").await.unwrap();
        assert_eq!(c.recv().await.unwrap(), b"through the cover");
        let _keep = server.await.unwrap();

        let c2s = c2s.lock().await.clone();
        let s2c = s2c.lock().await.clone();
        let ch_len = 5 + u16::from_be_bytes([c2s[3], c2s[4]]) as usize;
        let ch = c2s[..ch_len].to_vec();
        assert_eq!(
            tls::parse_client_hello(&ch).unwrap().sni.as_deref(),
            Some(DOMAIN),
            "client SNI = cover domain"
        );

        // The bridge's flight up to (excluding) the first record after the server's flight.
        let n_flight = 1 + usize::from(ccs) + recs.len();
        let bridge: Vec<(u8, usize)> = layout(&s2c).into_iter().take(n_flight).collect();

        // A censor replays the genuine ClientHello at the bridge: it is proxied to the cover site.
        let mut prober = TcpStream::connect(bridge_addr).await.unwrap();
        prober.write_all(&ch).await.unwrap();
        let probed = read_for(&mut prober, Duration::from_millis(800)).await;
        let real: Vec<(u8, usize)> = layout(&probed);

        let mut want = vec![(0x16u8, shape.record_len() - 5)];
        if ccs {
            want.push((0x14, 1));
        }
        want.extend(recs.iter().map(|&l| (0x17u8, l)));
        assert_eq!(real, want, "the replay reached the real cover site");
        assert_eq!(bridge, want, "bridge flight == cover flight");
        assert_eq!(
            tls::parse_server_hello(&s2c[..shape.record_len()])
                .unwrap()
                .shape,
            shape
        );
        // Client's second flight is Finished-sized for the cover's suite.
        let after_ch = layout(&c2s[ch_len..]);
        assert_eq!(after_ch[0], (0x14, 1));
        assert_eq!(
            after_ch[1],
            (0x17, tls::finished_record_len(shape.cipher_suite))
        );
        // The cover site received exactly the replayed bytes.
        assert_eq!(cover.hellos.lock().await.last().unwrap(), &ch);
    }
}

/// Unauthenticated, non-TLS probes are still proxied verbatim to the cover site in Cover mode.
#[tokio::test]
async fn http_probe_still_proxied_in_cover_mode() {
    let cover = fake_cover(vec![Answer::Flight(boring(), true, vec![3000])]).await;
    let site = CoverSite::new(cover.addr.clone(), Some(DOMAIN)).unwrap();
    let listener = ObfsListener::bind(
        "127.0.0.1:0",
        ObfsPsk::new([0x5d; 32]),
        ShapingPolicy::none(),
        ListenerConfig {
            probe: ProbeResponse::Cover(site),
            ..ListenerConfig::default()
        },
    )
    .await
    .unwrap();
    let mut p = TcpStream::connect(listener.local_addr()).await.unwrap();
    p.write_all(b"GET / HTTP/1.1\r\nHost: cdn.cover.example\r\n\r\n")
        .await
        .unwrap();
    let got = read_for(&mut p, Duration::from_millis(800)).await;
    assert_eq!(got, b"HTTP/1.1 400 Bad Request\r\n\r\n");
    assert!(cover.other.lock().await.starts_with(b"GET / HTTP/1.1\r\n"));
}

/// A failed refresh (alert, unreachable) keeps the last good profile; with none learned yet the
/// server uses the PSK default layout and still works.
#[tokio::test]
async fn refresh_failure_keeps_last_good_profile() {
    let good = vec![36, 2875, 281, 69];
    let cover = fake_cover(vec![
        Answer::Flight(openssl(), true, good.clone()),
        Answer::Alert,
    ])
    .await;
    let site = CoverSite::new(cover.addr.clone(), Some(DOMAIN)).unwrap();
    site.refresh(Duration::from_secs(5)).await.unwrap();
    assert!(site.refresh(Duration::from_secs(5)).await.is_err(), "alert");
    assert_eq!(site.profile().unwrap().records, good, "kept last good");

    // Never learned + unreachable upstream: no profile, sessions still establish (default layout).
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap().to_string();
    drop(dead);
    let site = CoverSite::new(dead_addr, Some(DOMAIN)).unwrap();
    assert!(site.refresh(Duration::from_secs(2)).await.is_err());
    assert!(site.profile().is_none());
    let psk = ObfsPsk::new([0x5e; 32]);
    let mut listener = ObfsListener::bind(
        "127.0.0.1:0",
        psk.clone(),
        ShapingPolicy::none(),
        ListenerConfig {
            probe: ProbeResponse::Cover(site),
            ..ListenerConfig::default()
        },
    )
    .await
    .unwrap();
    let addr = listener.local_addr();
    let server = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    ObfsTcp::connect_with(addr, &psk, ShapingPolicy::none(), &client_cfg())
        .await
        .unwrap();
    server.await.unwrap().unwrap();
}

/// The background refresher learns at start, retries after failures, and picks up layout changes.
#[tokio::test]
async fn background_refresher_retries_and_tracks_changes() {
    let first = vec![3000];
    let second = vec![23, 3900, 79, 53];
    let cover = fake_cover(vec![
        Answer::Alert, // initial attempt fails → retry soon
        Answer::Flight(boring(), true, first.clone()),
        Answer::Flight(boring(), false, second.clone()),
    ])
    .await;
    let site = CoverSite::new(cover.addr.clone(), Some(DOMAIN)).unwrap();
    site.start(CoverRefresh {
        interval: Duration::from_millis(150),
        jitter: Duration::ZERO,
        retry: Duration::from_millis(50),
        timeout: Duration::from_secs(3),
    });
    site.start(CoverRefresh::default()); // idempotent
    let wait_for = |want: Vec<usize>| {
        let site = site.clone();
        async move {
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    if site.profile().is_some_and(|p| p.records == want) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("refresher converged")
        }
    };
    wait_for(first).await;
    wait_for(second).await;
    assert!(!site.profile().unwrap().ccs);
    assert!(cover.hellos.lock().await.len() >= 3);
}
