# Phase 0 Research: uber-mesh core

Decisions distilled from `docs/research/dossier.md` (14-agent verified web research, 2026-06-28) into the
Decision / Rationale / Alternatives format. Every NEEDS CLARIFICATION from Technical Context is resolved here.

## D1. Mesh framework → rust-libp2p 0.56 (umbrella, Tokio)

- **Decision**: Build the overlay on the `libp2p` umbrella crate 0.56.x, Tokio runtime, composing one
  `#[derive(NetworkBehaviour)]` from gossipsub + kad + identify + ping + autonat + relay + dcutr + rendezvous +
  connection-limits.
- **Rationale**: Only mature Rust P2P stack with gossipsub v1.2 scoring, Kademlia, and a proven NAT-traversal
  trio (~70% in-the-wild hole-punch). Umbrella crate keeps member versions coherent.
- **Alternatives**: iroh (QUIC + iroh-gossip Plumtree) — cleaner sync but lacks gossipsub's P1–P7 scoring and
  would require re-implementing replay/scoring; rejected for the open adversarial mesh. Hand-rolled overlay —
  rejected (reinvents discovery/relay).

## D2. Censorship transport → pluggable `ObfsTransport`, obfs below Noise, profile-selected

- **Decision**: A single async `ObfsTransport` trait; concrete transports selected by an environment
  **profile** (`Open`/`Moderate`/`Aggressive`/`Shutdown`). The obfuscation layer sits **below** libp2p's Noise
  so Noise's fixed-shape XX handshake is hidden. First concrete transport: a pure-Rust **fully-encrypted
  obfuscated TCP transport** with popcount/entropy mitigation + probe-resistant auth + AEAD framing + shaping.
- **Rationale**: 2025–26 reality is that resilience = agility, not one unbreakable protocol; no production
  rust-libp2p obfuscated transport exists, so this is net-new but well-scoped and fully testable in Rust.
- **Alternatives**: REALITY-first — strongest design but needs a TLS stack with ClientHello control
  (`craftls`/`boring`) and faithful post-handshake `NewSessionTicket` relay (Aparecium, Jun 2025); deferred to a
  later iteration behind a feature flag. Plain Shadowsocks/obfs4 — rejected as primary (entropy-classified).

## D3. Probe resistance → MAC-gated silence (obfs4 model) for the TCP transport

- **Decision**: An unauthenticated connection that fails the keyed-MAC handshake gate receives **cryptographic
  silence** plus a randomized read-drain/delay; no distinguishing response, no RST timing tell.
- **Rationale**: Active probing (not passive analysis) burns most servers. The MAC-gate model is pure-Rust and
  needs no cover site. (The fallback-to-real-site model is reserved for the future REALITY/:443 transport, where
  silence is itself anomalous.)
- **Alternatives**: transparent reverse-proxy-to-dest — superior on :443 but requires running/【selecting a real
  cover site and is part of the deferred REALITY work.

## D4. Handshake / key agreement → hybrid X25519 + ML-KEM-768 (X-Wing combiner)

- **Decision**: Session keys come from a **hybrid** KEM: X25519 ECDH combined with ML-KEM-768 via the X-Wing
  construction (concatenate `ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519` under a domain-separated hash). The
  classical share is authoritative. Transcript-bound; ephemeral per link; supports epoch re-keying.
- **Rationale**: Mirrors PQNoise/Rosenpass; a flaw in the unaudited `ml-kem` alone cannot break a session
  (Principle I). X-Wing gives IND-CCA binding vs an ad-hoc KDF.
- **Alternatives**: PQ-only (trusts unaudited ML-KEM); classical-only (ignores harvest-now-decrypt-later);
  ad-hoc BLAKE3 concatenation combiner (weaker binding) — all rejected.

## D5. AEAD → XChaCha20-Poly1305 (192-bit random nonce)

- **Decision**: Data channel and handshake records use XChaCha20-Poly1305 from the NCC-audited
  `chacha20poly1305` 0.11; 192-bit random nonces avoid cross-peer nonce coordination footguns. Keys derived per
  direction via BLAKE3 `derive_key` with distinct labels.
- **Rationale**: Audited, constant-time, pure-Rust; random nonce space removes a whole class of reuse bugs.
- **Alternatives**: AES-GCM (fine but nonce-fragile; AES needs care w/o AES-NI); ChaCha20-Poly1305 96-bit nonce
  (needs counter coordination) — rejected for the misuse-resistance win.

## D6. Identity & content addressing → Ed25519 + BLAKE3

- **Decision**: Long-term identity = Ed25519 keypair; `PeerID = BLAKE3-256(pubkey)`. Content/message IDs =
  BLAKE3 of canonical bytes. BLAKE3 also serves as KDF (`derive_key`) and keyed-MAC, always domain-separated.
- **Rationale**: Standard, fast, SIMD; `ed25519-dalek` 2.2 is mature (avoid v1.x / RUSTSEC-2022-0093); BLAKE3
  unifies hash/KDF/MAC and enables verified streaming later (bao-tree).
- **Alternatives**: SHA-256 (slower, no built-in KDF/verified-streaming story); secp256k1 (no advantage here).

## D7. Serialization → bincode 3, inside the encrypted channel only

- **Decision**: `bincode` 3 for internal message structs, used **only** within the AEAD-protected channel, with
  explicit decode/byte limits on any untrusted input. Handshake/obfs framing uses hand-written, fuzzed parsers.
- **Rationale**: Deterministic cleartext framing is itself a fingerprint; keep bincode behind encryption and
  bound decode to prevent decode-bomb DoS.
- **Alternatives**: protobuf/CBOR (heavier, still must stay under encryption); exposing bincode framing in
  cleartext — rejected (fingerprint + DoS).

## D8. Discovery → private Kademlia + rendezvous + identify

- **Decision**: Kademlia with a **private protocol name** `/uber-mesh/kad/1.0.0` (not enumerable on the public
  IPFS DHT) plus `rendezvous` for fast bootstrap and `identify` for address/capability exchange.
- **Rationale**: Decentralized discovery without leaking the mesh into unrelated public networks.
- **Alternatives**: public IPFS DHT (enumerable, eclipse surface); mDNS only (LAN-bound); central tracker
  (violates Principle III).

## D9. NAT traversal → AutoNAT v2 + Relay v2 + DCUtR, relay-first, TCP+QUIC

- **Decision**: Relay-first connectivity with opportunistic DCUtR hole-punch on both TCP and QUIC; AutoNAT v2 for
  reachability; ordinary reachable nodes offer limited-resource relay. Skip symmetric-NAT port prediction.
- **Rationale**: Only decentralized stack with proven success; TCP hole-punch survives UDP-blocking regimes;
  relay guarantees baseline reachability for CGNAT/symmetric peers.
- **Alternatives**: STUN/TURN/ICE (centralized infra); `ant-quic` draft-seemann (experimental, PQ-only, large
  distinctive QUIC Initials — counterproductive in QUIC-hostile regions) — rejected as foundation.

## D10. Integrity & anti-abuse → signed gossip + replay protection + scoring + PoW-gated NodeIDs

- **Decision**: gossipsub `ValidationMode::Strict` signed messages; app-level monotonic per-sender seqno +
  timestamp window + bounded LRU dedup for replay; P1–P7 peer scoring with invalid-message and IP-colocation
  penalties; NodeIDs derived from pubkeys with a static BLAKE3 PoW creation gate (friction, not a hard barrier).
- **Rationale**: gossipsub dedup alone doesn't survive cache eviction; layered structural defenses are required
  because PoW alone won't stop a state adversary (2025 IPFS Sybil research).
- **Alternatives**: unsigned gossip (spoofable); PoW-only Sybil defense (insufficient) — rejected.

## D11. uTLS fidelity → deferred, feature-gated

- **Decision**: Defer browser-accurate TLS fingerprinting. When built, gate behind a feature flag, start with
  `craftls` (pure-Rust rustls fork), allow a `boring`/Go-REALITY sidecar escape hatch. Not in the default build.
- **Rationale**: `rustls` cannot reorder ClientHello extensions; pure-Rust uTLS parity is immature (dossier §7).
  Keep the default pure-Rust; opt into C/FFI only when REALITY/VLESS-mimic transports are added.
- **Alternatives**: ship `boring` by default (violates Principle IV default-pure-Rust) — rejected.

## Resolved unknowns

All Technical Context items are resolved above. Remaining items are **empirical** (real-world DPI survivability)
and tracked as measurement work, not design blockers — the spec evaluates against a DPI **simulation** harness.
