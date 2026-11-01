//! The mesh transport honours the environment profile: the configured `ProbeResponse` is what an
//! unauthenticated prober gets (audit 2026-11 #9 — it used to be hard-wired to silence), and a
//! shaped node interoperates with an unshaped one.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use umesh_obfs::{ObfsPsk, ProbeResponse, ShapingPolicy};
use umesh_p2p::MeshEvent;

mod common;

fn tcp_port(addr: &libp2p::Multiaddr) -> u16 {
    addr.iter()
        .find_map(|p| match p {
            libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("tcp listen address")
}

#[tokio::test]
async fn prober_is_spliced_to_configured_cover_site() {
    // A stand-in "cover site": answers anything with a fixed banner.
    let cover = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cover_addr = cover.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = cover.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                if s.read(&mut buf).await.unwrap_or(0) > 0 {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\ncover").await;
                }
            });
        }
    });

    let mut node = common::node_with_transport(
        &[21u8; 32],
        ObfsPsk::new([1u8; 32]),
        ShapingPolicy::none(),
        ProbeResponse::Fallback(cover_addr),
    )
    .unwrap();
    node.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let addr = loop {
        if let MeshEvent::Listening(a) = node.next_event().await {
            break a;
        }
    };
    let port = tcp_port(&addr);
    tokio::spawn(async move {
        loop {
            let _ = node.next_event().await;
        }
    });

    // An active prober speaking plain HTTP must transparently reach the cover site.
    let reply = tokio::time::timeout(Duration::from_secs(15), async move {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        while !out.ends_with(b"cover") {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    })
    .await
    .expect("prober got no reply (probe response not wired?)");
    assert!(
        reply.ends_with(b"cover"),
        "unexpected reply: {:?}",
        String::from_utf8_lossy(&reply)
    );
}

#[tokio::test]
async fn shaped_and_unshaped_nodes_gossip() {
    let psk = ObfsPsk::new([2u8; 32]);
    let mut a = common::node_with_transport(
        &[22u8; 32],
        psk.clone(),
        ShapingPolicy::aggressive(),
        ProbeResponse::Silence,
    )
    .unwrap();
    let mut b = common::node(&[23u8; 32], psk).unwrap();
    let topic = "uber-mesh/shaped";
    a.subscribe(topic).unwrap();
    b.subscribe(topic).unwrap();
    a.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let a_addr = loop {
        if let MeshEvent::Listening(x) = a.next_event().await {
            break x;
        }
    };
    b.dial(&a_addr.to_string()).unwrap();

    let got = tokio::time::timeout(Duration::from_secs(30), async {
        let mut tick = tokio::time::interval(Duration::from_millis(300));
        let mut connected = false;
        loop {
            tokio::select! {
                ev = a.next_event() => if matches!(ev, MeshEvent::PeerConnected(_)) { connected = true; },
                ev = b.next_event() => if let MeshEvent::Message { payload, .. } = ev { return payload; },
                _ = tick.tick() => if connected { let _ = a.publish(topic, b"shaped hello".to_vec()); },
            }
        }
    })
    .await;
    assert_eq!(got.as_deref(), Ok(&b"shaped hello"[..]));
}
