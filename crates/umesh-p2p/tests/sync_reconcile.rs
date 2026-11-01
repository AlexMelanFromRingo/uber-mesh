//! Live set-reconciliation integration test: two nodes with overlapping content sets reconcile over
//! the `/uber-mesh/reconcile` protocol (multi-round request-response) and the initiator learns the
//! exact symmetric difference of content ids.

use std::collections::HashSet;
use std::time::Duration;

use umesh_crypto::hash::Cid;
use umesh_obfs::ObfsPsk;
use umesh_p2p::MeshEvent;

mod common;

#[tokio::test]
async fn two_nodes_reconcile_content_sets() {
    let psk = ObfsPsk::new([5u8; 32]);
    let mut a = common::node(&[1u8; 32], psk.clone()).unwrap();
    let mut b = common::node(&[2u8; 32], psk).unwrap();
    let b_peer = b.local_peer_id();

    // A holds content 0..10; B holds content 5..15. Overlap 5..10.
    for i in 0..10 {
        a.provide(format!("content-{i}").into_bytes());
    }
    for i in 5..15 {
        b.provide(format!("content-{i}").into_bytes());
    }
    let need_expected: HashSet<Cid> = (10..15)
        .map(|i| Cid::of(format!("content-{i}").as_bytes()))
        .collect();
    let offer_expected: HashSet<Cid> = (0..5)
        .map(|i| Cid::of(format!("content-{i}").as_bytes()))
        .collect();

    b.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let b_addr = loop {
        if let MeshEvent::Listening(addr) = b.next_event().await {
            break addr;
        }
    };
    a.dial(&b_addr.to_string()).unwrap();

    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let mut started = false;
        loop {
            tokio::select! {
                ev = a.next_event() => match ev {
                    MeshEvent::PeerConnected(_) if !started => {
                        a.start_sync(b_peer);
                        started = true;
                    }
                    MeshEvent::SyncComplete { need, have_extra, .. } => {
                        return (
                            need.into_iter().collect::<HashSet<_>>(),
                            have_extra.into_iter().collect::<HashSet<_>>(),
                        );
                    }
                    MeshEvent::SyncFailed { .. } => return (HashSet::new(), HashSet::new()),
                    _ => {}
                },
                ev = b.next_event() => { let _ = ev; }
            }
        }
    })
    .await
    .expect("sync should converge within the timeout");

    assert_eq!(result.0, need_expected, "A should need the ids only B has");
    assert_eq!(
        result.1, offer_expected,
        "A should offer the ids only A has"
    );
}
