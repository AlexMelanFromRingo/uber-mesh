//! The composed libp2p `NetworkBehaviour` and swarm builder.
//!
//! Combines gossipsub (signed, strict validation, our content-derived message-id), a **private**
//! Kademlia DHT (`/uber-mesh/kad/1.0.0` — not enumerable on the public IPFS DHT), identify, ping,
//! and the NAT-traversal trio: AutoNAT v2 (reachability), Circuit Relay v2 (server + client), and
//! DCUtR (hole punching) — research D9. The libp2p transport identity is derived from the same
//! Ed25519 seed as the node's [`umesh_crypto`] identity, but libp2p's PeerId (a multihash of the
//! public key) differs from uber-mesh's `BLAKE3(pubkey)` PeerId used at the application/gossip layer.

use std::time::Duration;

use libp2p::kad::store::MemoryStore;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    StreamProtocol, Swarm, SwarmBuilder, autonat, dcutr, gossipsub, identify, identity, kad, noise,
    ping, relay, tcp, yamux,
};

use umesh_crypto::hash;

use crate::error::P2pError;

/// Private Kademlia protocol name.
pub const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/uber-mesh/kad/1.0.0");
/// Identify protocol version string.
pub const IDENTIFY_PROTOCOL: &str = "/uber-mesh/id/1.0.0";
/// Agent version advertised via identify.
pub const AGENT_VERSION: &str = concat!("uber-mesh/", env!("CARGO_PKG_VERSION"));

/// The composed mesh behaviour.
#[derive(NetworkBehaviour)]
pub struct MeshBehaviour {
    /// Signed pub/sub broadcast with strict validation + peer scoring.
    pub gossipsub: gossipsub::Behaviour,
    /// Private Kademlia DHT for peer discovery.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Peer capability/address exchange.
    pub identify: identify::Behaviour,
    /// Liveness.
    pub ping: ping::Behaviour,
    /// NAT reachability detection (dial-back).
    pub autonat: autonat::v2::client::Behaviour,
    /// Circuit Relay v2 server (this node relays for others when reachable).
    pub relay: relay::Behaviour,
    /// Circuit Relay v2 client (reach unreachable peers via a relay).
    pub relay_client: relay::client::Behaviour,
    /// Direct Connection Upgrade through Relay (coordinated hole punching).
    pub dcutr: dcutr::Behaviour,
}

/// gossipsub message-id = our content-derived [`crate::gossip::SignedMessage::message_id`] when the
/// payload is a valid uber-mesh message, else `BLAKE3(data)`. This makes dedup content-addressed.
fn message_id(msg: &gossipsub::Message) -> gossipsub::MessageId {
    match crate::gossip::SignedMessage::decode(&msg.data) {
        Ok(m) => gossipsub::MessageId::from(m.message_id().to_vec()),
        Err(_) => gossipsub::MessageId::from(hash::hash(&msg.data).to_vec()),
    }
}

fn build_behaviour(
    key: &identity::Keypair,
    relay_client: relay::client::Behaviour,
) -> Result<MeshBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = key.public().to_peer_id();

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id)
        .validate_messages() // app validates each message and reports Accept/Reject (T034)
        .heartbeat_interval(Duration::from_secs(1))
        .build()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let kademlia = kad::Behaviour::with_config(
        local_peer_id,
        MemoryStore::new(local_peer_id),
        kad::Config::new(KAD_PROTOCOL),
    );

    let identify = identify::Behaviour::new(
        identify::Config::new(IDENTIFY_PROTOCOL.to_string(), key.public())
            .with_agent_version(AGENT_VERSION.to_string()),
    );

    Ok(MeshBehaviour {
        gossipsub,
        kademlia,
        identify,
        ping: ping::Behaviour::default(),
        autonat: autonat::v2::client::Behaviour::default(),
        relay: relay::Behaviour::new(local_peer_id, relay::Config::default()),
        relay_client,
        dcutr: dcutr::Behaviour::new(local_peer_id),
    })
}

/// Build a Tokio-backed swarm with the mesh behaviour over TCP + Noise + Yamux, with a Circuit
/// Relay v2 client transport for NAT traversal.
///
/// The obfuscated transport is layered under Noise in a later step (T032); this builds the overlay
/// on the stock secure transport so the gossip/discovery/NAT layer is testable now.
pub fn build_swarm(seed: &[u8; 32]) -> Result<Swarm<MeshBehaviour>, P2pError> {
    let keypair =
        identity::Keypair::ed25519_from_bytes(*seed).map_err(|e| P2pError::Init(e.to_string()))?;

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| P2pError::Init(e.to_string()))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| P2pError::Init(e.to_string()))?
        .with_behaviour(build_behaviour)
        .map_err(|e| P2pError::Init(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Ok(swarm)
}
