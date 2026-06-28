# Contract: libp2p protocol IDs & behaviour composition

## Protocol identifiers (private namespace)

| Concern | Protocol ID | Notes |
|---|---|---|
| Kademlia DHT | `/uber-mesh/kad/1.0.0` | private name ⇒ not enumerable on the public IPFS DHT |
| Identify | `/uber-mesh/id/1.0.0` | agent string `uber-mesh/<semver>` |
| Gossipsub | `/uber-mesh/gossipsub/1.2.0` | v1.2 (IDONTWANT); `ValidationMode::Strict` |
| Rendezvous | `/uber-mesh/rendezvous/1.0.0` | namespace bootstrap |
| Ping | `/ipfs/ping/1.0.0` | standard |
| Relay v2 / DCUtR / AutoNAT v2 | libp2p defaults | standard hop/stop/dcutr/autonat |

## NetworkBehaviour composition (umesh-p2p)

```rust
#[derive(NetworkBehaviour)]
pub struct MeshBehaviour {
    pub gossipsub: gossipsub::Behaviour,      // signed, strict validation, P1–P7 scoring
    pub kademlia: kad::Behaviour<MemoryStore>,// private protocol name, bootstrap
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::v2::client::Behaviour,
    pub relay: relay::Behaviour,              // limited-resource server
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub rendezvous: rendezvous::client::Behaviour,
    pub connection_limits: connection_limits::Behaviour,
}
```

## Transport stack (per dialed/listened address)

```
base carrier (TCP or QUIC)
   → [ObfsTransport wrapper: obfs-tcp handshake + AEAD framing]   (TCP path; below Noise)
      → .upgrade(Version::V1)
         → .authenticate(noise::Config)      // stock noise this iteration (PQ upgrade deferred)
            → .multiplex(yamux::Config)
```

QUIC (`quic-v1`) is offered only when the active profile allows UDP and runtime UDP-probing succeeds; otherwise
the obfs-tcp path is used. The obfs wrapper is applied via `Transport::and_then` (handshake-bearing).

## Gossipsub scoring parameters (conservative)

`ValidationMode::Strict`; `PeerScoreParams` with: P4 (invalid-message) heavily negative and squared; P6
(IP-colocation) negative; `D_out` outbound-mesh quota enforced; flood-publish on; opportunistic graft on; PRUNE
backoff + peer-exchange on. Thresholds gate graylist/publish/gossip per libp2p guidance.
