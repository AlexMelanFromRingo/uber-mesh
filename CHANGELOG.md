# Changelog

All notable changes to **uber-mesh** are documented here. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may break).

> Each release is a git tag (`v0.x.0`). The project is built spec-first (GitHub Spec Kit) and committed
> step by step; see [`specs/001-uber-mesh-core/tasks.md`](specs/001-uber-mesh-core/tasks.md) for the
> task-level history and [`docs/`](docs/) for design rationale.

## [Unreleased]

- Documentation, repository presentation, and CI/community files.

## [0.8.0] — 2026-06-30

### Added
- **TLS 1.3 ClientHello mimicry** for the obfs handshake (`umesh-obfs/src/tls.rs`). The first flight is
  now a structurally-valid TLS 1.3 **ClientHello** (record type `0x16`) carrying a PQ-hybrid
  `X25519MLKEM768` `key_share` (IANA group `0x11EC`); the reply is a **ServerHello**. The flow opens
  *ClientHello → ServerHello → application-data*, defeating the TLS-state-machine DPI heuristic
  ("handshake must precede application data") that flagged the old app-data-first carrier.
- TLS-state-machine censor test (`tests/dpi_middlebox.rs`): obfs passes; an app-data-first flow is blocked.
- `UMESH_SNI` env var to override the cover-domain SNI.

### Changed
- The PSK probe-resistance gate moved into the 32-byte TLS `session_id` (a keyed BLAKE3 MAC over the
  key_share + epoch) — REALITY's short-id-in-SessionID idea. KEM material is now public (as in any TLS
  key_share); session confidentiality still comes from the KEM secret and the AEAD record layer.
- Small default Tokio worker pool via `UMESH_WORKERS` (default `2` → ~4 threads/node, was ~14; `1` =
  current-thread runtime) — lighter footprint, friendlier to mobile/embedded.

### Notes
- Residual gap (deferred to native REALITY): structurally valid TLS, **not** a byte-exact uTLS JA3/JA4
  fingerprint nor a full TLS-1.3 transcript. See [`docs/security-and-deferred.md`](docs/security-and-deferred.md).

## [0.7.0] — 2026-06-30

### Added
- **Grafana** provisioning (datasource + cluster dashboard) and **Docker** clusters that scale to **100
  nodes** scraped by Prometheus (DNS-SD) under real `tc netem` impairment.
- **DPI middlebox** integration tests (`tests/dpi_middlebox.rs`): an in-path censor using the USENIX'23
  entropy/no-header heuristic **and** active probing — obfs passes, raw/naive flows are blocked.
- Per-node resource metrics (`umesh_process_*` from `/proc/self`), geo-emulation
  (`docker/compose.geo.yml`), chaos/partition runs, and a multi-minute soak (no RSS leak).

## [0.6.0] — 2026-06-30

### Added
- **Prometheus `/metrics`** on every node (`umesh-p2p::metrics`, hand-rolled exposition format; served by
  the CLI `mesh` command on `METRICS_PORT`, default `9100`).
- In-process N-node gossip benchmark (`examples/cluster.rs`): 100 nodes, 100% delivery, p95 ≈ 3 ms.

## [0.5.0] — 2026-06-30

### Added
- **Set reconciliation** (negentropy-style range-based, `umesh-p2p::reconcile`,
  `/uber-mesh/reconcile/1.0.0`).
- **REALITY-style fallback proxy** (`ProbeResponse::Fallback`): a prober that fails the gate is
  transparently reverse-proxied to a real cover site.
- NAT traversal wiring validated (Circuit Relay v2 / AutoNAT v2 / DCUtR; client↔relay over obfs tested).

## [0.4.0] — 2026-06-30

### Added
- **Content exchange**: content-addressed `ContentStore` + libp2p request-response
  (`/uber-mesh/blobs/1.0.0`, bincode codec). Receivers verify `BLAKE3(bytes) == Cid`.

## [0.3.0] — 2026-06-29

### Added
- **Obfuscated transport under libp2p Noise**: `build_swarm` wraps libp2p TCP with the PSK-gated obfs
  handshake (`SwarmBuilder::with_other_transport`), so the whole gossip mesh inherits DPI resistance. A
  wrong-PSK peer cannot connect.

## [0.2.0] — 2026-06-28

### Added
- **libp2p gossip mesh**: `MeshBehaviour` (Gossipsub Strict + scoring, private Kademlia, identify, ping)
  and the `MeshNode` driver; signed messages with replay protection. Two-node gossip integration test.

## [0.1.0] — 2026-06-28

### Added
- **Crypto core** (`umesh-crypto`, pure-Rust, `#![forbid(unsafe_code)]`): hybrid **X25519 + ML-KEM-768**
  KEM with an X-Wing-style BLAKE3 combiner, **Ed25519** identity (`PeerId = BLAKE3(pubkey)`), **BLAKE3**
  hash/KDF/keyed-MAC/Cid with domain separation, **XChaCha20-Poly1305** AEAD, Merkle trees, and PoW —
  with known-answer and property tests.

[Unreleased]: https://github.com/AlexMelanFromRingo/uber-mesh/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.8.0
[0.7.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.7.0
[0.6.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.6.0
[0.5.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.5.0
[0.4.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.4.0
[0.3.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.3.0
[0.2.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.2.0
[0.1.0]: https://github.com/AlexMelanFromRingo/uber-mesh/releases/tag/v0.1.0
