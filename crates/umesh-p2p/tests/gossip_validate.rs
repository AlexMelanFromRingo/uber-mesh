//! US2 integration test: two in-process mesh nodes form a gossipsub mesh over loopback TCP and
//! deliver an authenticated signed message; the receiver validates sender identity (SC-003/SC-004).
//! Rejection of forged/tampered/replayed messages is covered by the `gossip` unit tests.

use std::time::Duration;

use umesh_obfs::ObfsPsk;
use umesh_p2p::{MeshEvent, MeshNode};

#[tokio::test]
async fn two_nodes_gossip_a_validated_message() {
    // Both nodes share the same obfs PSK (the bridge secret gating the obfuscated carrier).
    let psk = ObfsPsk::new([7u8; 32]);
    let mut a = MeshNode::new(&[1u8; 32], psk.clone()).unwrap();
    let mut b = MeshNode::new(&[2u8; 32], psk).unwrap();
    let a_app_id = a.app_peer_id();

    let topic = "uber-mesh/test";
    a.subscribe(topic).unwrap();
    b.subscribe(topic).unwrap();

    a.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let a_addr = loop {
        if let MeshEvent::Listening(addr) = a.next_event().await {
            break addr;
        }
    };
    b.dial(&a_addr.to_string()).unwrap();

    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let mut interval = tokio::time::interval(Duration::from_millis(300));
        let mut connected = false;
        loop {
            tokio::select! {
                ev = a.next_event() => {
                    if matches!(ev, MeshEvent::PeerConnected(_)) { connected = true; }
                }
                ev = b.next_event() => {
                    if let MeshEvent::Message { topic: t, sender, payload } = ev {
                        assert_eq!(t, topic);
                        assert_eq!(payload, b"hello over the mesh");
                        assert_eq!(sender, a_app_id, "message must be authenticated to node A");
                        return;
                    }
                }
                _ = interval.tick() => {
                    // Republish until the gossipsub mesh has formed and B receives it.
                    if connected {
                        let _ = a.publish(topic, b"hello over the mesh".to_vec());
                    }
                }
            }
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "B did not receive A's gossip message within the timeout"
    );
}

/// A peer with the wrong obfs PSK must NOT form a connection — the obfuscated carrier's gate rejects
/// it before any libp2p Noise upgrade (T032: the mesh inherits probe resistance).
#[tokio::test]
async fn mismatched_psk_cannot_connect() {
    let mut a = MeshNode::new(&[3u8; 32], ObfsPsk::new([1u8; 32])).unwrap();
    let mut b = MeshNode::new(&[4u8; 32], ObfsPsk::new([2u8; 32])).unwrap(); // different PSK

    a.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let a_addr = loop {
        if let MeshEvent::Listening(addr) = a.next_event().await {
            break addr;
        }
    };
    b.dial(&a_addr.to_string()).unwrap();

    // Drive both for a window; neither side may reach PeerConnected. Timeout (Err) ⇒ success.
    let connected = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            tokio::select! {
                ev = a.next_event() => if matches!(ev, MeshEvent::PeerConnected(_)) { return true; },
                ev = b.next_event() => if matches!(ev, MeshEvent::PeerConnected(_)) { return true; },
            }
        }
    })
    .await;

    assert!(
        connected.is_err(),
        "peers with mismatched PSK must not connect"
    );
}
