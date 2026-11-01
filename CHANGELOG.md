# Changelog

All notable changes to **uber-mesh** are documented here. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions may break).

> Each release is a git tag (`v0.x.0`). The project is built spec-first (GitHub Spec Kit) and committed
> step by step; see [`specs/001-uber-mesh-core/tasks.md`](specs/001-uber-mesh-core/tasks.md) for the
> task-level history and [`docs/`](docs/) for design rationale.

## [Unreleased]

## [0.9.0] — 2026-11-01 — security audit (**wire-breaking**)

Full security audit with proof-of-concept tests; every finding below has a regression test.

### Security — obfs carrier (wire v2, flag day: no v1 compatibility)
- **Server authentication (critical).** v1 derived session keys from the KEM secret only and accepted any
  ServerHello, so an on-path party *without the PSK* could impersonate a bridge and decrypt the client
  (identifying it as uber-mesh). Keys are now `KDF(hybrid ss ‖ PSK ‖ transcript)` with mutual key
  confirmation hidden in a TLS-1.3-shaped server flight and a Finished-sized client record.
- **No passive one-packet fingerprint.** v1 put a cleartext epoch in `session_id` (bytes 4..8 always
  zero). The whole 32 bytes are now a MAC over the entire ClientHello; replays are rejected by a bounded
  per-epoch cache and sent to the probe response.
- **Honest fallback.** Probe bytes already read are all forwarded to the cover site; non-TLS probes fall
  back immediately instead of hanging; cover connect has a timeout.
- **Chrome-shaped ClientHello** (GREASE, Chrome's suites/extensions, ALPN, GREASE ECH, per-connection
  extension order and cover SNI, decoy X25519 next to X25519MLKEM768).
- Client connect/handshake timeouts (endpoint rotation on silent freezes); accept loop no longer blocked by
  a slow probe (`ObfsListener`, per-connection tasks, capped).
- Exported **channel binding**; the node hello signs it, so a PSK-holding relay can't splice two sessions.

### Security — crypto hygiene
- Secrets zeroized (`SharedSecret`, cached AEAD cipher, ML-KEM/ChaCha `zeroize`, `ObfsPsk`), redacted
  `Debug`, `subtle` comparisons; low-order X25519 keys rejected.
- Merkle: RFC 9162 tree with distinct leaf/node/root labels; the root commits to the size (no
  internal-node-as-leaf or resized proofs). `rs_merkle` dropped.
- Shaping adds random padding on top of buckets (no constant length mod bucket); the libp2p path is now
  shaped per environment profile (`ObfsByteStream::with_shaping`).

### Security — mesh overlay
- **Remote abort (critical):** bincode decoding without a size limit let a 13-byte reconcile request (or a
  blob response) abort a node via a huge allocation. Bounded decoding + fuzz targets.
- Reconcile amplification (4 MiB request → 172 MiB response) closed: strictly increasing segments, caps,
  round/diff limits, per-peer rate limit.
- Gossip message-id covers the full message (an insider could censor a message by poisoning the duplicate
  cache); the signed topic must match the delivery topic.
- Restarted nodes are no longer silenced (time-based seqno, sliding replay window, bounded state;
  replays → Ignore, not Reject). `lru` dropped (RUSTSEC-2026-0253).
- Gossipsub peer scoring and connection limits enabled; private gossipsub protocol id
  (`/uber-mesh/meshsub/1.x`); DCUtR honours `role_override`; AutoNAT v2 server, Kademlia bootstrap and
  identify→Kademlia so NAT traversal and discovery actually work.

### Security — node, CLI, ops
- Metrics endpoint **off by default** (it identified the host to scanners); loopback when enabled; header
  timeout and connection cap.
- Node hello v2: session-bound challenge-response (v1's static signed hello could be replayed).
- Key file created atomically 0600, symlinks refused; config 0600, data dir 0700; PSK via `--psk-file` /
  `UMESH_PSK` (`--psk` deprecated); a mistyped profile is an error. New `mesh --profile` / `--fallback`.
- Docker: non-root, PSK never in argv, Grafana without anonymous admin, ports on loopback, pinned images.
- CI: cargo-audit job, fuzz smoke over every target, actions pinned by SHA, `permissions: read`, and a
  guard proving lockfile-only advisories (hickory) never enter the build. Dependencies updated (quinn,
  rustls, h2, tokio, crossbeam, ctutils, time…); MSRV 1.88.

### Notes
- Tests: 99 → 213. Fuzz targets: 2 → 8.
- Gossip replay state (post-audit review rounds): per-sender floors for evicted windows that are never
  dropped (folded into 4 096 buckets keyed by a per-node secret), timestamps ≤ 30 s in the future, verdicts
  that depend only on the message. Residual risk + deferred identity-PoW fix in
  `docs/security-and-deferred.md`.
- Residual gaps (documented): not a byte-exact JA3/JA4 of one Chrome build; the fake certificate flight
  does not survive a TLS-terminating censor; no NewSessionTicket.

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
