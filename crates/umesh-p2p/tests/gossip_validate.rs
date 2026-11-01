//! US2 integration test: two in-process mesh nodes form a gossipsub mesh over loopback TCP and
//! deliver an authenticated signed message; the receiver validates sender identity (SC-003/SC-004).
//! Rejection of forged/tampered/replayed messages is covered by the `gossip` unit tests. Both nodes
//! here run the production sender-PoW policy (`MIN_SENDER_POW_BITS`) with pre-mined identities.

use std::time::Duration;

use umesh_obfs::ObfsPsk;
use umesh_p2p::{MeshEvent, MeshNode};

mod common;

#[tokio::test]
async fn two_nodes_gossip_a_validated_message() {
    // Both nodes share the same obfs PSK (the bridge secret gating the obfuscated carrier).
    let psk = ObfsPsk::new([7u8; 32]);
    let [(sa, na), (sb, nb)] = common::MINED;
    let mut a = MeshNode::new(&sa, na, psk.clone()).unwrap();
    let mut b = MeshNode::new(&sb, nb, psk).unwrap();
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
                    if let MeshEvent::Message { topic: t, sender, payload, sealed } = ev {
                        assert_eq!(t, topic);
                        assert!(!sealed, "a topic without a key stays public");
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
    let mut a = common::node(&[3u8; 32], ObfsPsk::new([1u8; 32])).unwrap();
    let mut b = common::node(&[4u8; 32], ObfsPsk::new([2u8; 32])).unwrap(); // different PSK

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

/// A sender whose identity carries less than the network-wide PoW (here: an 8-bit devnet identity)
/// cannot get messages through a production node, even with a working connection and mesh.
#[tokio::test]
async fn sender_below_network_pow_is_not_delivered() {
    let psk = ObfsPsk::new([9u8; 32]);
    let weak_seed = [5u8; 32];
    let key = umesh_crypto::identity::NodeIdentity::from_seed(&weak_seed)
        .verifying_key()
        .to_bytes();
    let weak_nonce = common::test_nonce(&weak_seed);
    assert!(
        umesh_crypto::pow::identity_pow_bits(&key, weak_nonce)
            < umesh_crypto::pow::MIN_SENDER_POW_BITS,
        "premise: the test identity is below the network minimum"
    );
    // The production constructor refuses the weak identity outright…
    assert!(MeshNode::new(&weak_seed, weak_nonce, psk.clone()).is_err());
    // …so build it with the devnet policy and point it at a production node.
    let mut a = common::node(&weak_seed, psk.clone()).unwrap();
    let (sb, nb) = common::MINED[0];
    let mut b = MeshNode::new(&sb, nb, psk).unwrap();
    let topic = "uber-mesh/pow";
    a.subscribe(topic).unwrap();
    b.subscribe(topic).unwrap();
    b.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let b_addr = loop {
        if let MeshEvent::Listening(addr) = b.next_event().await {
            break addr;
        }
    };
    a.dial(&b_addr.to_string()).unwrap();

    let delivered = tokio::time::timeout(Duration::from_secs(6), async {
        let mut interval = tokio::time::interval(Duration::from_millis(300));
        let mut connected = false;
        loop {
            tokio::select! {
                ev = a.next_event() => {
                    if matches!(ev, MeshEvent::PeerConnected(_)) { connected = true; }
                }
                ev = b.next_event() => {
                    if let MeshEvent::Message { .. } = ev { return true; }
                }
                _ = interval.tick() => {
                    if connected {
                        let _ = a.publish(topic, b"free identity".to_vec());
                    }
                }
            }
        }
    })
    .await;
    assert!(
        delivered.is_err(),
        "a message below the network PoW was delivered"
    );
    // Positive control: the messages did arrive and were Rejected (forwarder penalized, P4).
    let score = b.peer_score(&a.local_peer_id());
    assert!(
        score.is_some_and(|s| s < 0.0),
        "expected a penalized sender, got {score:?}"
    );
}
