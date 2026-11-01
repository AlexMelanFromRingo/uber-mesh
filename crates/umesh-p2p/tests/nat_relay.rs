//! NAT-traversal integration test (T038).
//!
//! The NAT stack (AutoNAT v2 + Circuit Relay v2 server/client + DCUtR) is wired into `MeshBehaviour`.
//! This test verifies the deterministic, in-process-reproducible part: a client connects to a
//! relay-capable node **over the obfuscated transport**, so the relay infrastructure is reachable
//! and the relay-client transport composes correctly with obfs+Noise+Yamux.
//!
//! The subsequent reservation/hole-punch upgrade depends on AutoNAT reachability detection and relay
//! voucher exchange, which libp2p documents as having rough edges and which do not reliably converge
//! in a single-process loopback test; they are validated in deployment. (A manual diagnostic confirms
//! the client connects to the relay and issues the reservation request over the obfs carrier.)

use std::time::Duration;

use umesh_obfs::ObfsPsk;
use umesh_p2p::MeshEvent;

mod common;

#[tokio::test]
async fn connects_to_relay_node_over_obfs() {
    let psk = ObfsPsk::new([6u8; 32]);
    let mut relay = common::node(&[1u8; 32], psk.clone()).unwrap();
    let mut client = common::node(&[2u8; 32], psk).unwrap();
    let relay_peer = relay.local_peer_id();

    relay.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let relay_addr = loop {
        if let MeshEvent::Listening(a) = relay.next_event().await {
            break a;
        }
    };

    client.dial(&relay_addr.to_string()).unwrap();
    // Issue the relay reservation request over the connection (exercises the relay-client path).
    let circuit = format!("{relay_addr}/p2p/{relay_peer}/p2p-circuit");
    client.listen(&circuit).unwrap();

    let connected = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                ev = relay.next_event() => { let _ = ev; }
                ev = client.next_event() => {
                    if let MeshEvent::PeerConnected(p) = ev
                        && p == relay_peer {
                            return true;
                        }
                }
            }
        }
    })
    .await;

    assert_eq!(
        connected,
        Ok(true),
        "client should reach the relay-capable node over the obfs transport"
    );
}

/// Audit regression (MEDIUM inert NAT): the relay had no confirmed external address, so every
/// reservation response carried no addresses and the client rejected it. With an operator-declared
/// (or AutoNAT-confirmed) address the reservation is accepted.
#[tokio::test]
async fn relay_reservation_accepted_with_confirmed_address() {
    let psk = ObfsPsk::new([16u8; 32]);
    let mut relay = common::node(&[11u8; 32], psk.clone()).unwrap();
    let mut client = common::node(&[12u8; 32], psk).unwrap();
    let relay_peer = relay.local_peer_id();

    relay.listen("/ip4/127.0.0.1/tcp/0").unwrap();
    let relay_addr = loop {
        if let MeshEvent::Listening(a) = relay.next_event().await {
            break a;
        }
    };
    relay.add_external_address(&relay_addr.to_string()).unwrap();

    client.dial(&relay_addr.to_string()).unwrap();
    let circuit = format!("{relay_addr}/p2p/{relay_peer}/p2p-circuit");
    client.listen(&circuit).unwrap();

    let reserved = tokio::time::timeout(Duration::from_secs(20), async {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = relay.next_event() => {}
                _ = client.next_event() => {}
                _ = tick.tick() => if client.has_relay_reservation(&relay_peer) { return true; }
            }
        }
    })
    .await;
    assert_eq!(
        reserved,
        Ok(true),
        "relay should accept the client's reservation"
    );
}
