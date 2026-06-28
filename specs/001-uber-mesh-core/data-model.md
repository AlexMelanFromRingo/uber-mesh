# Phase 1 Data Model: uber-mesh core

Entities, their fields, relationships, validation rules, and key/identity model. Wire-level byte layouts live
in `contracts/handshake-wire.md` and `contracts/message-wire.md`.

## Keys & identity model

```
Ed25519 identity keypair (long-term, auth only)
   └─ PeerId = BLAKE3-256(ed25519_public_key)            # 32 bytes, self-certifying
Per-link ephemeral:
   X25519 keypair  +  ML-KEM-768 (decaps key / encaps key)   # ephemeral, per handshake
   └─ shared_secret = X-Wing(ss_mlkem, ss_x25519, ct_x25519, pk_x25519)
        └─ BLAKE3.derive_key("uber-mesh v1 traffic c2s", ss) → key_c2s
           BLAKE3.derive_key("uber-mesh v1 traffic s2c", ss) → key_s2c
Obfs handshake (below Noise):
   obfs_psk (per-listener)  → MAC gate key, frame keys     # popcount/entropy-mitigated
```

Domain-separation labels (BLAKE3 `derive_key` context strings) are constants in `umesh-crypto`; each distinct
use (traffic c2s, traffic s2c, content-id, message-id, pow-challenge, obfs-frame) MUST use a distinct label.

## Entities

### NodeIdentity
- `ed25519_signing_key` (secret; `zeroize` on drop; never serialized in cleartext)
- `ed25519_verifying_key` (public)
- `peer_id`: `[u8; 32]` = BLAKE3(verifying_key) — derived, cached
- **Validation**: secret key persisted only to a 0600 keystore; `verify_strict` used for first-seen verification.
- **State**: created on first run → persisted → loaded on subsequent runs.

### Peer
- `peer_id`: `[u8; 32]`
- `verifying_key`: Ed25519 public (learned via identify, bound to peer_id by re-deriving BLAKE3)
- `addrs`: set of multiaddrs + transport tags
- `capabilities`: relay?, reachable?, protocols
- `score`: local reputation (f64, gossipsub P1–P7 derived) — never shared
- `last_seen`, `nat_class` (Unknown/Public/Cone/Symmetric/Relayed)
- **Validation**: `BLAKE3(verifying_key) == peer_id` MUST hold or the peer is rejected.

### Session (Link)
- `peer_id`, `transport` (which `ObfsTransport`), `profile`
- `key_send`, `key_recv`: XChaCha20-Poly1305 keys (ephemeral; `zeroize`)
- `epoch`: re-key counter; `send_nonce_seq`/dedup state
- `established_at`, `health` (Healthy/Degraded/Dead), `last_activity`
- **State**: Dialing → Handshaking → Established → (Rekeying) → Closing/Dead. On Dead via health-check, trigger
  rotation (FR-004).

### TransportProfile
- `name`: `Open | Moderate | Aggressive | Shutdown`
- `transports`: ordered preference list (e.g. `[Quic, ObfsTcp]` for Open; `[ObfsTcp]` for Aggressive)
- `shaping`: `ShapingPolicy { pad_to, min_pad, max_pad, iat_jitter_ms, decoy }`
- `udp_allowed`: bool (false ⇒ skip QUIC dialing)
- `fingerprint`: opaque handle (reserved for future uTLS profiles)

### Message (gossip)
- `topic`: string id
- `payload`: bytes (application data; carried inside AEAD on the wire)
- `sender`: `peer_id` + `verifying_key`
- `seqno`: u64 monotonic per sender
- `timestamp`: u64 unix-millis
- `signature`: Ed25519 over canonical `(topic ‖ sender ‖ seqno ‖ timestamp ‖ BLAKE3(payload))`
- `message_id`: BLAKE3 of the canonical signed bytes
- **Validation rules (reject if any fail)**: signature valid under sender key; `BLAKE3(sender_key)==sender`;
  `seqno > last_seqno[sender]`; `|now - timestamp| ≤ skew_window`; `message_id` not in dedup LRU.

### ContentObject
- `cid`: `[u8; 32]` = BLAKE3(bytes)
- `bytes`: data
- **Validation**: receiver recomputes `BLAKE3(bytes) == cid` before accepting (FR-011). (Verified streaming via
  bao-tree is a deferred enhancement.)

### MerkleProof (membership / set state)
- `root`: `[u8; 32]`, `leaf`: `[u8; 32]`, `path`: ordered sibling hashes + directions
- **Validation**: recomputed root from leaf+path equals `root`.

### ProofOfWork (NodeID creation friction)
- `challenge` (derived from pubkey + epoch), `nonce`, `difficulty` (leading-zero bits)
- **Validation**: `BLAKE3(domain ‖ challenge ‖ nonce)` has ≥ `difficulty` leading zero bits.

## Relationships

- `NodeIdentity` 1—1 local node; produces signatures on every `Message` and authenticates every `Session`.
- `Peer` *—* `Session` (a peer may have one active session at a time in this iteration).
- `TransportProfile` 1—* `Session` (the active profile drives transport/shaping selection).
- `Message` references `Peer` (sender) and is content-addressed by `message_id`; replay state is keyed per sender.

## Persistence

| Artifact | Location | Notes |
|---|---|---|
| Identity secret | `<data_dir>/identity.key` (0600) | raw 32-byte seed; `zeroize` in memory |
| Config | `<config>/config.toml` | profile, bootstrap peers, listen addrs, data_dir |
| Peer cache (optional) | `<data_dir>/peers.json` | last-known addrs; non-authoritative |

No secret material is ever written to logs, status output, or the peer cache.
