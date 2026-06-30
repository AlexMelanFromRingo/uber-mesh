//! Content exchange integration test: a node requests a blob by `Cid` from a peer over the mesh
//! (request-response, bincode codec, over the obfuscated transport) and verifies it (FR-011).

use std::time::Duration;

use umesh_crypto::hash::Cid;
use umesh_obfs::ObfsPsk;
use umesh_p2p::{MeshEvent, MeshNode};

#[tokio::test]
async fn requests_and_verifies_a_blob() {
    let psk = ObfsPsk([8u8; 32]);
    let mut a = MeshNode::new(&[1u8; 32], psk.clone()).unwrap();
    let mut b = MeshNode::new(&[2u8; 32], psk).unwrap();
    let a_peer = a.local_peer_id();

    // A holds some content; B will ask for it by Cid.
    let content = b"the quick brown fox jumps over the lazy dog\n".repeat(64);
    let cid = a.provide(content.clone());

    a.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let a_addr = loop {
        if let MeshEvent::Listening(addr) = a.next_event().await {
            break addr;
        }
    };
    b.dial(&a_addr.to_string()).unwrap();

    let ok = tokio::time::timeout(Duration::from_secs(30), async {
        let mut requested = false;
        loop {
            tokio::select! {
                ev = a.next_event() => { let _ = ev; }
                ev = b.next_event() => match ev {
                    MeshEvent::PeerConnected(_) if !requested => {
                        b.request_blob(a_peer, cid);
                        requested = true;
                    }
                    MeshEvent::BlobReceived { cid: got, data } => {
                        assert_eq!(got, cid);
                        assert_eq!(data, content, "delivered bytes must match");
                        return true;
                    }
                    MeshEvent::BlobUnavailable { .. } => return false,
                    _ => {}
                }
            }
        }
    })
    .await;

    assert_eq!(ok, Ok(true), "B should receive and verify the blob");
}

#[tokio::test]
async fn unknown_blob_is_unavailable() {
    let psk = ObfsPsk([9u8; 32]);
    let mut a = MeshNode::new(&[3u8; 32], psk.clone()).unwrap();
    let mut b = MeshNode::new(&[4u8; 32], psk).unwrap();
    let a_peer = a.local_peer_id();
    let missing = Cid::of(b"content that nobody has");

    a.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let a_addr = loop {
        if let MeshEvent::Listening(addr) = a.next_event().await {
            break addr;
        }
    };
    b.dial(&a_addr.to_string()).unwrap();

    let unavailable = tokio::time::timeout(Duration::from_secs(30), async {
        let mut requested = false;
        loop {
            tokio::select! {
                ev = a.next_event() => { let _ = ev; }
                ev = b.next_event() => match ev {
                    MeshEvent::PeerConnected(_) if !requested => {
                        b.request_blob(a_peer, missing);
                        requested = true;
                    }
                    MeshEvent::BlobUnavailable { cid } => return cid == missing,
                    MeshEvent::BlobReceived { .. } => return false,
                    _ => {}
                }
            }
        }
    })
    .await;

    assert_eq!(
        unavailable,
        Ok(true),
        "requesting an absent blob must yield BlobUnavailable"
    );
}
