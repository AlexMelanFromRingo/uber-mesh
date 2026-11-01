//! The composed libp2p `NetworkBehaviour` and swarm builder.
//!
//! Combines gossipsub (signed, strict validation, our content-derived message-id), a **private**
//! Kademlia DHT (`/uber-mesh/kad/1.0.0` — not enumerable on the public IPFS DHT), identify, ping,
//! and the NAT-traversal trio: AutoNAT v2 (reachability), Circuit Relay v2 (server + client), and
//! DCUtR (hole punching) — research D9 — plus connection limits. AutoNAT v2 runs as both client and
//! server so peers can confirm each other's external addresses; a confirmed address flips Kademlia
//! into server mode and lets the relay hand out reservations. The libp2p transport identity is derived from the same
//! Ed25519 seed as the node's [`umesh_crypto`] identity, but libp2p's PeerId (a multihash of the
//! public key) differs from uber-mesh's `BLAKE3(pubkey)` PeerId used at the application/gossip layer.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use libp2p::core::upgrade::Version;
use libp2p::core::{ConnectedPoint, Endpoint};
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::NetworkBehaviour;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::timeout::TransportTimeout;
use libp2p::{
    StreamProtocol, Swarm, Transport, autonat, connection_limits, dcutr, gossipsub, identify,
    identity, kad, noise, ping, relay, request_response, tcp, yamux,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use umesh_obfs::{
    ObfsByteStream, ObfsPsk, ProbeResponse, ShapingPolicy, client_handshake,
    server_handshake_detached,
};

use crate::blobs::{BLOB_PROTOCOL, BlobCodec};
use crate::error::P2pError;
use crate::sync::{RECONCILE_PROTOCOL, ReconcileCodec};

/// Private Kademlia protocol name.
pub const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/uber-mesh/kad/1.0.0");
/// Identify protocol version string.
pub const IDENTIFY_PROTOCOL: &str = "/uber-mesh/id/1.0.0";
/// Agent version advertised via identify.
pub const AGENT_VERSION: &str = concat!("uber-mesh/", env!("CARGO_PKG_VERSION"));

/// Max concurrent pending inbound connections (handshakes in flight).
pub const MAX_PENDING_INCOMING: u32 = 64;
/// Max concurrent pending outbound dials.
pub const MAX_PENDING_OUTGOING: u32 = 64;
/// Max established inbound connections.
pub const MAX_ESTABLISHED_INCOMING: u32 = 128;
/// Max established outbound connections.
pub const MAX_ESTABLISHED_OUTGOING: u32 = 128;
/// Max established connections overall.
pub const MAX_ESTABLISHED: u32 = 192;
/// Max established connections per peer (direct + relayed + a hole-punch upgrade in flight).
pub const MAX_ESTABLISHED_PER_PEER: u32 = 4;
/// Max concurrent blob streams per connection (inbound + outbound).
pub const BLOB_MAX_STREAMS: usize = 16;
/// Max concurrent reconcile streams per connection (inbound + outbound).
pub const RECONCILE_MAX_STREAMS: usize = 4;

/// The composed mesh behaviour.
#[derive(NetworkBehaviour)]
pub struct MeshBehaviour {
    /// Connection caps (pending/established/per-peer). Listed first so it can deny a connection
    /// before any other behaviour allocates per-connection state.
    pub connection_limits: connection_limits::Behaviour,
    /// Signed pub/sub broadcast with strict validation + peer scoring.
    pub gossipsub: gossipsub::Behaviour,
    /// Private Kademlia DHT for peer discovery.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Peer capability/address exchange.
    pub identify: identify::Behaviour,
    /// Liveness.
    pub ping: ping::Behaviour,
    /// NAT reachability detection (dial-back); confirms external addresses on success.
    pub autonat: autonat::v2::client::Behaviour,
    /// AutoNAT v2 server: dial back peers' candidate addresses so they can confirm them.
    pub autonat_server: autonat::v2::server::Behaviour,
    /// Circuit Relay v2 server (this node relays for others when reachable).
    pub relay: relay::Behaviour,
    /// Circuit Relay v2 client (reach unreachable peers via a relay).
    pub relay_client: relay::client::Behaviour,
    /// Direct Connection Upgrade through Relay (coordinated hole punching).
    pub dcutr: dcutr::Behaviour,
    /// Content-addressed blob request/response (`/uber-mesh/blobs/1.0.0`, bincode codec).
    pub blobs: request_response::Behaviour<BlobCodec>,
    /// Range-based set reconciliation (`/uber-mesh/reconcile/1.0.0`, bincode codec).
    pub reconcile: request_response::Behaviour<ReconcileCodec>,
}

/// gossipsub message-id = [`crate::gossip::message_id_of`] the raw data: BLAKE3 over the **full**
/// canonical encoding (payload included). Any two distinct byte strings get distinct ids, so a
/// forged variant of a genuine message can't occupy its slot in gossipsub's duplicate cache.
fn message_id(msg: &gossipsub::Message) -> gossipsub::MessageId {
    gossipsub::MessageId::from(crate::gossip::message_id_of(&msg.data).to_vec())
}

/// Global gossipsub peer-scoring parameters (P5–P7). Loopback is whitelisted from the
/// IP-colocation penalty (P6) so local multi-node clusters/tests aren't graylisted.
pub fn peer_score_params() -> gossipsub::PeerScoreParams {
    gossipsub::PeerScoreParams {
        ip_colocation_factor_whitelist: [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

/// Score thresholds (gossip −10 / publish −50 / graylist −80; libp2p defaults).
pub fn peer_score_thresholds() -> gossipsub::PeerScoreThresholds {
    gossipsub::PeerScoreThresholds::default()
}

/// Per-topic scoring, installed on every subscribed topic. P4 (invalid messages, i.e. our
/// `Reject`s) is heavily negative and squared: one invalid message costs −10, three in quick
/// succession (−90) graylist the peer; the counter decays ×0.9 per decay interval. P3/P3b
/// (mesh-delivery quotas) are off — in a low-traffic mesh they would penalize honest quiet peers.
pub fn topic_score_params() -> gossipsub::TopicScoreParams {
    gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_weight: 0.01,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 100.0,
        first_message_deliveries_weight: 1.0,
        first_message_deliveries_decay: 0.5,
        first_message_deliveries_cap: 10.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: -10.0,
        invalid_message_deliveries_decay: 0.9,
        ..Default::default()
    }
}

/// Whether this side runs the obfs **client** handshake on a raw connection. Respects the
/// hole-punch `role_override`: in a DCUtR simultaneous open both sides dial, and the side told to
/// act as listener (`role_override: Listener`) must run the server handshake, or both would send a
/// ClientHello and the upgrade could never succeed.
pub fn obfs_runs_client(point: &ConnectedPoint) -> bool {
    matches!(
        point,
        ConnectedPoint::Dialer {
            role_override: Endpoint::Dialer,
            ..
        }
    )
}

/// The connection caps applied to every swarm.
pub fn connection_limits() -> connection_limits::ConnectionLimits {
    connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
        .with_max_pending_outgoing(Some(MAX_PENDING_OUTGOING))
        .with_max_established_incoming(Some(MAX_ESTABLISHED_INCOMING))
        .with_max_established_outgoing(Some(MAX_ESTABLISHED_OUTGOING))
        .with_max_established(Some(MAX_ESTABLISHED))
        .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER))
}

fn build_behaviour(
    key: &identity::Keypair,
    relay_client: relay::client::Behaviour,
) -> Result<MeshBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = key.public().to_peer_id();

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        // Private protocol ids (`/uber-mesh/meshsub/1.{2,1,0}`), like the private Kademlia: a
        // stock libp2p gossipsub node never joins this mesh by accident.
        .protocol_id_prefix("/uber-mesh/meshsub")
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id)
        .validate_messages() // app validates each message and reports Accept/Reject (T034)
        .heartbeat_interval(Duration::from_secs(1))
        .build()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    // Activate peer scoring so `Reject` actually costs the forwarder (P4), per the contract.
    gossipsub
        .with_peer_score(peer_score_params(), peer_score_thresholds())
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    let kademlia = kad::Behaviour::with_config(
        local_peer_id,
        MemoryStore::new(local_peer_id),
        kad::Config::new(KAD_PROTOCOL),
    );

    let identify = identify::Behaviour::new(
        identify::Config::new(IDENTIFY_PROTOCOL.to_string(), key.public())
            .with_agent_version(AGENT_VERSION.to_string()),
    );

    let blobs = request_response::Behaviour::with_codec(
        BlobCodec,
        [(BLOB_PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(Duration::from_secs(30))
            .with_max_concurrent_streams(BLOB_MAX_STREAMS),
    );

    let reconcile = request_response::Behaviour::with_codec(
        ReconcileCodec,
        [(RECONCILE_PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(Duration::from_secs(20))
            .with_max_concurrent_streams(RECONCILE_MAX_STREAMS),
    );

    Ok(MeshBehaviour {
        connection_limits: connection_limits::Behaviour::new(connection_limits()),
        gossipsub,
        kademlia,
        identify,
        ping: ping::Behaviour::default(),
        autonat: autonat::v2::client::Behaviour::default(),
        autonat_server: autonat::v2::server::Behaviour::default(),
        relay: relay::Behaviour::new(local_peer_id, relay::Config::default()),
        relay_client,
        dcutr: dcutr::Behaviour::new(local_peer_id),
        blobs,
        reconcile,
    })
}

/// Build a Tokio-backed swarm whose base transport is the **obfuscated, probe-resistant obfs-tcp
/// carrier under libp2p Noise + Yamux** (T032): `TCP → obfs handshake → ObfsByteStream →
/// .upgrade().authenticate(noise).multiplex(yamux)`. The obfs layer (gated by `psk`) hides Noise's
/// fingerprint and gives the whole mesh DPI resistance; Noise still authenticates the libp2p PeerId.
/// A Circuit Relay v2 client transport is layered on for NAT traversal.
///
/// `shaping` and `probe` come from the active environment profile: `probe` is what an inbound
/// connection that fails the PSK gate gets (silence or a cover-site fallback proxy); `shaping` is
/// the record padding/jitter policy for the obfs byte stream.
pub fn build_swarm(
    seed: &[u8; 32],
    psk: ObfsPsk,
    shaping: ShapingPolicy,
    probe: ProbeResponse,
) -> Result<Swarm<MeshBehaviour>, P2pError> {
    let keypair =
        identity::Keypair::ed25519_from_bytes(*seed).map_err(|e| P2pError::Init(e.to_string()))?;

    // Assembled by hand rather than with `SwarmBuilder::with_tokio()`: that needs libp2p's umbrella
    // `tokio` feature, whose weak `libp2p-{mdns,dns,quic,upnp}?/tokio` entries pull those (unused)
    // crates — and hickory-proto with its advisories — into Cargo.lock. This is exactly what the
    // builder does: obfs-TCP or relay transport → TransportTimeout(10 s) → tokio-executor Swarm.
    let init = |e: Box<dyn std::error::Error + Send + Sync>| P2pError::Init(e.to_string());
    let local_peer_id = keypair.public().to_peer_id();
    let obfs_tcp = {
            let noise = noise::Config::new(&keypair).map_err(|e| init(e.into()))?;
            tcp::tokio::Transport::new(tcp::Config::default())
                .and_then(move |conn, point| {
                    let psk = psk.clone();
                    let probe = probe.clone();
                    let shaping = shaping.clone();
                    async move {
                        // Bridge libp2p's futures-io stream to our tokio-based obfs handshake.
                        let mut tk = conn.compat();
                        let started = std::time::Instant::now();
                        // Inbound: the probe response (possibly a long cover-site relay) runs in a
                        // detached, capped task so it never holds a libp2p pending-incoming slot.
                        let result = if obfs_runs_client(&point) {
                            client_handshake(&mut tk, &psk).await.map(|k| (tk, k))
                        } else {
                            server_handshake_detached(tk, &psk, &probe).await
                        };
                        let (tk, keys) = match result {
                            Ok(v) => {
                                crate::metrics::record_handshake(
                                    started.elapsed().as_millis() as u64
                                );
                                v
                            }
                            Err(e) => {
                                crate::metrics::inc(&crate::metrics::HANDSHAKE_FAILS);
                                return Err(io::Error::other(e.to_string()));
                            }
                        };
                        // Expose the obfs byte stream back as futures-io for the Noise/Yamux upgrade.
                        Ok::<_, io::Error>(shaped_stream(tk, keys, shaping).compat())
                    }
                })
                .upgrade(Version::V1)
                .authenticate(noise)
                .multiplex(yamux::Config::default())
                .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
    };
    let (relay_transport, relay_behaviour) = relay::client::new(local_peer_id);
    let relay_transport = relay_transport
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(&keypair).map_err(|e| init(e.into()))?)
        .multiplex(yamux::Config::default())
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)));
    let transport = relay_transport
        .or_transport(obfs_tcp)
        .map(|either, _| either.into_inner());
    let transport = TransportTimeout::new(transport, CONNECTION_TIMEOUT).boxed();
    let behaviour = build_behaviour(&keypair, relay_behaviour).map_err(init)?;
    Ok(Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(60)),
    ))
}

/// Upper bound on one connection upgrade (obfs handshake + Noise + Yamux), as libp2p's builder.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Wrap a handshaked carrier in the obfs byte stream with the profile's shaping policy (record
/// padding + write coalescing). Interoperates with unshaped peers: the receiver strips padding.
fn shaped_stream<S>(
    inner: S,
    keys: umesh_obfs::SessionKeys,
    shaping: ShapingPolicy,
) -> ObfsByteStream<S> {
    ObfsByteStream::with_shaping(inner, keys, shaping)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::transport::PortUse;

    fn dialer(role_override: Endpoint) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            role_override,
            port_use: PortUse::New,
        }
    }

    /// Audit regression: `point.is_dialer()` ignored `role_override`, so in a DCUtR simultaneous
    /// open both sides ran the client handshake and hole punching over obfs never worked.
    #[test]
    fn obfs_role_respects_role_override() {
        assert!(obfs_runs_client(&dialer(Endpoint::Dialer)));
        assert!(!obfs_runs_client(&dialer(Endpoint::Listener)));
        let listener = ConnectedPoint::Listener {
            local_addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            send_back_addr: "/ip4/127.0.0.1/tcp/2".parse().unwrap(),
        };
        assert!(!obfs_runs_client(&listener));
    }

    #[test]
    fn scoring_params_validate() {
        peer_score_params().validate().unwrap();
        peer_score_thresholds().validate().unwrap();
        topic_score_params().validate().unwrap();
        let t = topic_score_params();
        assert!(t.invalid_message_deliveries_weight < 0.0);
        // Three invalid messages graylist the forwarder.
        let p4 = t.topic_weight * t.invalid_message_deliveries_weight * 9.0;
        assert!(p4 < peer_score_thresholds().graylist_threshold);
    }

    #[test]
    fn message_id_is_full_content_hash() {
        let id = umesh_crypto::identity::NodeIdentity::from_seed(&[3; 32]);
        let m = crate::gossip::SignedMessage::create(&id, "t", b"p".to_vec(), 1, 1);
        let mut gm = gossipsub::Message {
            source: None,
            data: m.encode(),
            sequence_number: None,
            topic: gossipsub::TopicHash::from_raw("t"),
        };
        let a = message_id(&gm);
        assert_eq!(a.0, m.message_id().to_vec());
        let last = gm.data.len() - 65; // last payload byte
        gm.data[last] ^= 1;
        assert_ne!(message_id(&gm), a);
    }
}
