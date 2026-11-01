//! End-to-end confidentiality integration tests (spec edge case "untrusted relay/serving peer",
//! contracts/message-wire.md "Sealed messages (v3)").
//!
//! Topology for every test: a hub `F`/`S` that holds **no** topic key, and members that connect only
//! to the hub — so every member-to-member message or blob necessarily passes through a peer that
//! must not be able to read it.

use std::time::Duration;

use libp2p::Multiaddr;
use umesh_crypto::hash::Cid;
use umesh_obfs::ObfsPsk;
use umesh_p2p::{MeshEvent, MeshNode, SealedBlobRef, TopicKey};

mod common;

const SECRET: &str = "uber-mesh/secret";
const NEWS: &str = "uber-mesh/news";

async fn listen_addr(n: &mut MeshNode) -> Multiaddr {
    n.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    loop {
        if let MeshEvent::Listening(a) = n.next_event().await {
            return a;
        }
    }
}

/// What one node delivered to its application: `(topic, payload, sealed)`.
type Got = Vec<(String, Vec<u8>, bool)>;

fn record(got: &mut Got, ev: MeshEvent) {
    if let MeshEvent::Message {
        topic,
        payload,
        sealed,
        ..
    } = ev
    {
        got.push((topic, payload, sealed));
    }
}

/// Regression (confidentiality gap): gossip payloads used to be only signed, so every forwarding
/// peer read them. Now a forwarder without the topic key validates and forwards a sealed message
/// but never delivers it; members holding the key receive it; a member with the wrong key gets
/// nothing; a public message injected into the sealed topic is refused by members (downgrade); and
/// a public topic behaves exactly as before for everyone.
#[tokio::test(flavor = "multi_thread")]
async fn non_member_forwards_sealed_message_it_cannot_read() {
    let psk = ObfsPsk::new([0x51; 32]);
    let key = TopicKey::from_bytes([0xA1; 32]);
    let wrong = TopicKey::from_bytes([0xA2; 32]);

    let mut f = common::node(&[0x60; 32], psk.clone()).unwrap(); // forwarder, no key
    let mut a = common::node(&[0x61; 32], psk.clone()).unwrap(); // member, publisher
    let mut b = common::node(&[0x62; 32], psk.clone()).unwrap(); // member
    let mut w = common::node(&[0x63; 32], psk).unwrap(); // holds the wrong key
    for n in [&mut f, &mut a, &mut b, &mut w] {
        n.subscribe(SECRET).unwrap();
        n.subscribe(NEWS).unwrap();
    }
    a.set_topic_key(SECRET, &key);
    b.set_topic_key(SECRET, &key);
    w.set_topic_key(SECRET, &wrong);
    assert!(a.is_sealed(SECRET) && !a.is_sealed(NEWS) && !f.is_sealed(SECRET));

    let fa = listen_addr(&mut f).await;
    for n in [&mut a, &mut b, &mut w] {
        n.dial(&fa.to_string()).unwrap();
    }
    let a_app = a.app_peer_id();
    let b_peer = b.local_peer_id();

    let (mut gf, mut ga, mut gb, mut gw) = (Got::new(), Got::new(), Got::new(), Got::new());
    let secret_to_b = |gb: &Got| {
        gb.iter()
            .any(|(t, p, s)| t == SECRET && p == b"attack at dawn" && *s)
    };
    let news_to_all = |g: &[&Got]| {
        g.iter().all(|g| {
            g.iter()
                .any(|(t, p, s)| t == NEWS && p == b"weather" && !*s)
        })
    };
    let done = tokio::time::timeout(Duration::from_secs(30), async {
        let mut tick = tokio::time::interval(Duration::from_millis(300));
        loop {
            tokio::select! {
                ev = f.next_event() => record(&mut gf, ev),
                ev = a.next_event() => record(&mut ga, ev),
                ev = b.next_event() => {
                    if let MeshEvent::Message { topic, sender, sealed: true, .. } = &ev {
                        assert_eq!((topic.as_str(), *sender), (SECRET, a_app), "authenticated");
                    }
                    record(&mut gb, ev)
                }
                ev = w.next_event() => record(&mut gw, ev),
                _ = tick.tick() => {
                    if secret_to_b(&gb) && news_to_all(&[&gf, &gb, &gw]) {
                        return;
                    }
                    let _ = a.publish(SECRET, b"attack at dawn".to_vec()); // sealed (A holds key)
                    let _ = a.publish(NEWS, b"weather".to_vec()); // public
                    let _ = f.publish(SECRET, b"downgrade".to_vec()); // public: F has no key
                }
            }
        }
    })
    .await;
    assert!(done.is_ok(), "B: {gb:?}\nF: {gf:?}\nW: {gw:?}");
    // Keep the mesh running a little longer so late copies would surface.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                ev = f.next_event() => record(&mut gf, ev),
                ev = a.next_event() => record(&mut ga, ev),
                ev = b.next_event() => record(&mut gb, ev),
                ev = w.next_event() => record(&mut gw, ev),
            }
        }
    })
    .await;

    // B received the sealed message although it is connected only to F: F forwarded it.
    assert!(
        !a.is_connected(&b_peer),
        "premise: A and B are not directly connected"
    );
    assert!(secret_to_b(&gb));
    // F (no key) and W (wrong key) never delivered anything on the sealed topic.
    for (name, g) in [("forwarder", &gf), ("wrong key", &gw)] {
        assert!(
            g.iter().all(|(t, _, _)| t != SECRET),
            "{name} delivered a sealed-topic message: {g:?}"
        );
    }
    // Members refuse the public message injected into the sealed topic.
    for g in [&ga, &gb] {
        assert!(g.iter().all(|(_, p, _)| p != b"downgrade"), "{g:?}");
    }
    // Public topics are unchanged: delivered to everyone, marked unsealed.
    assert!(news_to_all(&[&gf, &gb, &gw]));
}

/// Regression (confidentiality gap): blobs used to be stored and served in cleartext. A sealed
/// blob is stored as ciphertext (`Cid` over the ciphertext) by the publisher, mirrored by a
/// serving peer without the key — which verifies it against the `Cid` and serves it, but only ever
/// holds ciphertext — and fetched + decrypted by a member that is connected only to that serving
/// peer.
#[tokio::test(flavor = "multi_thread")]
async fn sealed_blob_is_served_by_a_peer_that_cannot_read_it() {
    let psk = ObfsPsk::new([0x52; 32]);
    let key = TopicKey::from_bytes([0xB1; 32]);
    let mut s = common::node(&[0x70; 32], psk.clone()).unwrap(); // serving peer, no key
    let mut a = common::node(&[0x71; 32], psk.clone()).unwrap(); // member, publisher
    let mut b = common::node(&[0x72; 32], psk).unwrap(); // member, fetcher
    for n in [&mut s, &mut a, &mut b] {
        n.subscribe(SECRET).unwrap();
    }
    a.set_topic_key(SECRET, &key);
    b.set_topic_key(SECRET, &key);

    let marker = b"TOP-SECRET-PLAINTEXT ";
    let plaintext = marker.repeat(200);
    let blob = a.seal_blob(SECRET, &plaintext).unwrap();
    assert!(
        s.seal_blob(SECRET, b"x").is_err(),
        "a node without the key cannot seal for the topic"
    );
    let holds_only_ciphertext = |n: &MeshNode, cid: &Cid| {
        let stored = n.stored(cid).expect("stored");
        cid.verifies(stored) && !stored.windows(marker.len()).any(|w| w == marker)
    };
    assert!(
        holds_only_ciphertext(&a, &blob.cid),
        "publisher stores ciphertext"
    );

    let sa = listen_addr(&mut s).await;
    a.dial(&sa.to_string()).unwrap();
    b.dial(&sa.to_string()).unwrap();
    let (a_peer, s_peer, a_app) = (a.local_peer_id(), s.local_peer_id(), a.app_peer_id());

    let mut announced: Option<SealedBlobRef> = None;
    let mut s_has = false;
    let mut b_requested = false;
    let mut s_synced = false;
    let got = tokio::time::timeout(Duration::from_secs(40), async {
        let mut tick = tokio::time::interval(Duration::from_millis(300));
        loop {
            tokio::select! {
                ev = s.next_event() => match ev {
                    // S mirrors what A holds: set reconciliation reveals only Cids.
                    MeshEvent::PeerConnected(p) if p == a_peer && !s_synced => {
                        s_synced = true;
                        s.start_sync(a_peer);
                    }
                    MeshEvent::SyncComplete { need, .. } => {
                        assert!(need.contains(&blob.cid));
                        s.request_blob(a_peer, blob.cid);
                    }
                    MeshEvent::BlobReceived { cid, data } => {
                        assert_eq!(cid, blob.cid);
                        assert_ne!(data, plaintext, "serving peer must only get ciphertext");
                        s_has = true;
                    }
                    MeshEvent::SealedBlob { .. } => panic!("non-member learned a sealed blob"),
                    MeshEvent::Message { topic, .. } if topic == SECRET => {
                        panic!("non-member delivered a sealed message")
                    }
                    _ => {}
                },
                _ = a.next_event() => {}
                ev = b.next_event() => match ev {
                    MeshEvent::SealedBlob { blob: r, provider, sender, .. } => {
                        assert_eq!(r, blob);
                        assert_eq!(provider, Some(a_peer), "publisher is the first provider");
                        assert_eq!(sender, a_app);
                        announced = Some(r);
                    }
                    MeshEvent::BlobReceived { cid, data } => {
                        assert_eq!(cid, blob.cid);
                        return data;
                    }
                    MeshEvent::BlobUnavailable { .. } => b_requested = false, // retry
                    _ => {}
                },
                _ = tick.tick() => {
                    if announced.is_none() {
                        let _ = a.announce_blob(SECRET, &blob);
                    }
                    // B is not connected to A: it fetches from the serving peer.
                    if let Some(r) = &announced
                        && s_has
                        && !b_requested
                    {
                        b_requested = true;
                        b.request_sealed_blob(s_peer, r);
                    }
                    if !s_synced && s.is_connected(&a_peer) {
                        s_synced = true;
                        s.start_sync(a_peer);
                    }
                }
            }
        }
    })
    .await;
    assert_eq!(
        got.as_deref(),
        Ok(&plaintext[..]),
        "member decrypts the blob"
    );
    assert!(!b.is_connected(&a_peer), "premise: B fetched from S, not A");
    // Nobody's store holds plaintext: S serves ciphertext, B re-serves ciphertext.
    assert!(
        holds_only_ciphertext(&s, &blob.cid),
        "serving peer stores ciphertext"
    );
    assert!(
        holds_only_ciphertext(&b, &blob.cid),
        "member stores ciphertext"
    );
    assert_ne!(s.stored(&blob.cid), Some(&plaintext[..]));
}

/// A member asking for a sealed blob with the wrong content key gets `BlobUnavailable` (the
/// ciphertext verifies against its `Cid` but does not decrypt) and stores nothing.
#[tokio::test(flavor = "multi_thread")]
async fn sealed_blob_with_wrong_key_is_unavailable() {
    let psk = ObfsPsk::new([0x53; 32]);
    let mut a = common::node(&[0x74; 32], psk.clone()).unwrap();
    let mut b = common::node(&[0x75; 32], psk).unwrap();
    a.set_topic_key(SECRET, &TopicKey::from_bytes([0xC1; 32]));
    let blob = a.seal_blob(SECRET, b"payload").unwrap();
    let forged = SealedBlobRef {
        cid: blob.cid,
        key: umesh_p2p::ContentKey::from_bytes([0; 32]),
    };
    let a_peer = a.local_peer_id();
    let aa = listen_addr(&mut a).await;
    b.dial(&aa.to_string()).unwrap();
    let r = tokio::time::timeout(Duration::from_secs(20), async {
        let mut requested = false;
        loop {
            tokio::select! {
                _ = a.next_event() => {}
                ev = b.next_event() => match ev {
                    MeshEvent::PeerConnected(_) if !requested => {
                        requested = true;
                        b.request_sealed_blob(a_peer, &forged);
                    }
                    MeshEvent::BlobUnavailable { cid } => return Ok(cid),
                    MeshEvent::BlobReceived { data, .. } => return Err(data),
                    _ => {}
                }
            }
        }
    })
    .await;
    assert_eq!(r, Ok(Ok(blob.cid)));
    assert!(b.stored(&blob.cid).is_none());
}
