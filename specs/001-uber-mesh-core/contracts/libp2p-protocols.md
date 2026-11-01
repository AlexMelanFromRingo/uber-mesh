# Contract: libp2p protocol IDs & behaviour composition

## Protocol identifiers (private namespace)

| Concern | Protocol ID | Notes |
|---|---|---|
| Kademlia DHT | `/uber-mesh/kad/1.0.0` | private name ⇒ not enumerable on the public IPFS DHT |
| Identify | `/uber-mesh/id/1.0.0` | agent string `uber-mesh/<semver>` |
| Gossipsub | `/uber-mesh/meshsub/1.2.0` (falls back to `/uber-mesh/meshsub/1.1.0`, `1.0.0`) | v1.2 (IDONTWANT); `ValidationMode::Strict` |
| Rendezvous | `/uber-mesh/rendezvous/1.0.0` | namespace bootstrap |
| Ping | `/ipfs/ping/1.0.0` | standard |
| Relay v2 / DCUtR / AutoNAT v2 | libp2p defaults | standard hop/stop/dcutr/autonat (client **and** server) |
| Blob exchange | `/uber-mesh/blobs/1.0.0` | request-response, bincode (see below); sealed-topic blobs are ciphertext |
| Set reconciliation | `/uber-mesh/reconcile/1.0.0` | request-response, bincode (see below) |

## NetworkBehaviour composition (umesh-p2p)

```rust
#[derive(NetworkBehaviour)]
pub struct MeshBehaviour {
    pub connection_limits: connection_limits::Behaviour, // first: denies before others allocate
    pub gossipsub: gossipsub::Behaviour,      // signed, strict validation, peer scoring (below)
    pub kademlia: kad::Behaviour<MemoryStore>,// private protocol name; auto mode, bootstrap
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::v2::client::Behaviour,        // confirms our external addresses
    pub autonat_server: autonat::v2::server::Behaviour, // dial-back service for peers
    pub relay: relay::Behaviour,              // limited-resource server
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub blobs: request_response::Behaviour<BlobCodec>,
    pub reconcile: request_response::Behaviour<ReconcileCodec>,
    // rendezvous: not yet implemented
}
```

### Connection limits

pending in/out ≤ 64/64; established in/out ≤ 128/128, total ≤ 192, **per peer ≤ 4** (direct + relayed + a
hole-punch upgrade). Request-response: blobs ≤ 16 concurrent streams per connection (30 s timeout),
reconcile ≤ 4 (20 s timeout).

### Discovery / NAT

- AutoNAT v2 client+server: peers test each other's candidate addresses (identify-observed); a successful
  dial-back emits `ExternalAddrConfirmed`. Operators may also declare a static public address
  (`MeshNode::add_external_address`), which counts as confirmed.
- A confirmed external address switches Kademlia (auto mode) to **server** mode and lets the relay server
  include addresses in reservations (with none, every reservation was rejected by the client as
  `NoAddressesInReservation`).
- Identify-learned `listen_addrs` (≤ 8 per peer) of peers that advertise `/uber-mesh/kad/1.0.0` are added
  to the routing table; `add_address` triggers a bootstrap; periodic bootstrap every 5 min.
- DCUtR over obfs: the obfs **client** handshake runs iff `ConnectedPoint::Dialer { role_override:
  Endpoint::Dialer, .. }`; a hole-punch dial with `role_override: Listener` runs the server handshake (so a
  simultaneous open has exactly one client).

### Request-response codecs (`/uber-mesh/blobs/1.0.0`, `/uber-mesh/reconcile/1.0.0`)

Frame = `u32_le length ‖ bincode(standard, varint) body`. Decoding uses a bincode **byte limit** (every
container length claim is checked before allocation) and rejects trailing bytes.

- Blobs: request = 32-byte cid (frame ≤ 64 B); response = `Option<Vec<u8>>`, data ≤ 8 MiB (frame ≤ 8 MiB+16).
  The receiver verifies `BLAKE3(data) == cid`. The protocol is content-agnostic: a blob shared in a
  **sealed topic** is stored, reconciled and served as **ciphertext** (`nonce ‖ XChaCha20-Poly1305 ‖ tag`
  under a per-blob content key), and its `cid` is over the ciphertext — so a serving or mirroring peer
  verifies and serves it without being able to read it; only members, who receive `(cid, content_key)`
  inside a sealed gossip message, decrypt it (message-wire.md "Encrypted blobs"). Public blobs carry
  plaintext, as before. Serving is rate-limited per peer (token bucket: 64 MiB burst,
  8 MiB/s, ≥ 4 KiB charged per request); over-budget requests get no response.
- Reconcile: frame ≤ 2 MiB. A message is a list of `Segment { upper: Option<[u8;32]>, mode }` that MUST
  satisfy: 1 ≤ segments ≤ 8192; `upper`s strictly increasing with the first `> [0;32]` (non-empty ranges
  `[prev, upper)`); only the last segment has `upper = None`; `IdList` length ≤ 4. Invalid messages are
  dropped. Both sides answer under an 8192-segment output budget (ranges that don't fit are answered with a
  single fingerprint and refined in a later round), and the responder answers an `IdList` with its own ids
  only when it holds ≤ 4 in that range (else bucketed fingerprints). Initiator: ≤ 256 rounds, diff ≤ 2^18
  ids, else `SyncFailed`. Responder: per-peer token bucket (32 burst, 4/s; a request costs
  `1 + segments/1024`).

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

`ValidationMode::Strict`; peer scoring always active. Global `PeerScoreParams` = libp2p defaults (P5 app
weight 10, P6 IP-colocation −5 above 10 peers/IP with loopback whitelisted, P7 behaviour penalty −10).
Per-topic `TopicScoreParams` installed on subscribe: topic weight 1; P1 time-in-mesh 0.01/s (cap 100);
P2 first deliveries 1 (decay 0.5, cap 10); **P3/P3b off** (delivery quotas would penalize quiet honest
peers in a low-traffic mesh); **P4 invalid messages −10 × count², decay 0.9** — fed by our `Reject`s only
(replays/duplicates/stale/unknown-version are `Ignore`d and never scored). Thresholds = libp2p defaults:
gossip −10, publish −50, graylist −80 (three invalid messages in quick succession graylist a peer),
accept-PX 10, opportunistic-graft 20. Message-id: see message-wire.md.

Gossipsub uses the private prefix `/uber-mesh/meshsub` (set via `protocol_id_prefix`), so it never
interoperates with stock libp2p gossipsub meshes.

## Confidentiality per hop vs. end to end

Every link is encrypted (obfs hybrid-PQ AEAD around Noise), but each hop terminates it: a gossip forwarder
and a blob-serving peer see what they relay. Payload confidentiality against them comes only from
**sealed topics** (message-wire.md "Sealed messages (v3)"). A Circuit Relay v2 relay is different: it splices
two streams and the relayed connection runs its own Noise handshake end to end, so the relay sees only Noise
ciphertext (plus both endpoints' PeerIds, timing and volume).
