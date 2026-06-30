---
description: "Task list for uber-mesh core (001-uber-mesh-core)"
---

# Tasks: uber-mesh — Decentralized Censorship-Resistant Mesh

**Input**: Design documents from `specs/001-uber-mesh-core/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: REQUIRED for cryptographic, handshake/key-agreement, transport-obfuscation, and wire-parser code per
constitution Principle V (NON-NEGOTIABLE). Other tasks include tests where they add value.

**Organization**: Grouped by user story (US1=P1 MVP, US2=P2, US3=P3, US4=P3) for independent delivery.

## Implementation status (2026-06-28)

- ✅ **Phase 1 Setup** (T001–T004) — workspace, lints, `deny.toml`, CI. `462dd19`/`e4ecb47`
- ✅ **Phase 2 Foundational `umesh-crypto`** (T005–T013) — all modules + KATs + property tests (33 tests). `e4ecb47`
- ✅ **Phase 3 US1 (MVP)** (T014, T016–T024, T026) — obfs-tcp transport, probe resistance, hybrid-PQ handshake,
  shaping, profiles, rotation; DPI-simulation test passes over real TCP. `e4eb924`, hardened in `e3f16d8`.
- ✅ **Phase 6 US4** (T039–T045) — config, keystore, status, node runtime, CLI; two-node demo verified. `c6070df`
- ✅ **Adversarial security review** applied (4-lens) — handshake PSK-sealing, combiner binding, AAD counter,
  DoS bounds, checked conversions. `e3f16d8`
- ✅ **Phase 4 US2** (T027, T029–T034) — signed gossip + replay protection, libp2p `MeshBehaviour`
  (gossipsub Strict + private Kademlia + identify + ping), `MeshNode`; two-node gossip integration test. `c96220f`, `73d1915`
- ✅ **Phase 5 US3** (T035–T037) — AutoNAT v2 + Circuit Relay v2 + DCUtR wired into the behaviour. `e913e1c`
- ✅ **CLI mesh** — `uber-mesh mesh` runs the gossip overlay; verified two-process signed-heartbeat exchange. `b5ad1ab`
- ✅ **T032 — obfs transport under libp2p Noise** — `ObfsByteStream` (poll-based AsyncRead/Write over the obfs
  AEAD framing) + `with_other_transport` wraps TCP with the PSK-gated obfs handshake under Noise+Yamux. The
  mesh now inherits probe resistance; a wrong-PSK peer cannot connect (integration + cross-process tests). `68e4038`
- ✅ **Content exchange (FR-011)** — `ContentStore` + libp2p request-response `/uber-mesh/blobs/1.0.0` with a
  **bincode** codec; `MeshNode::provide`/`request_blob`; receiver verifies `BLAKE3(bytes)==cid`. Integration
  tests (fetch+verify over the obfuscated transport; absent→unavailable). `d35eb69`
- ✅ **Set reconciliation** — negentropy-style range-based sync (`reconcile` + `/uber-mesh/reconcile/1.0.0`);
  `MeshNode::start_sync` → `SyncComplete{need, have_extra}`. Pure algorithm + live integration tests. `e0e925a`
- ✅ **REALITY-style probe resistance** — `ProbeResponse::Fallback` reverse-proxies probers to a real cover
  site; prober receives genuine content (test). `cb80fa3`
- ✅ **NAT (T038)** — AutoNAT v2 + Relay v2 + DCUtR wired; client↔relay over obfs tested; reservation/hole-punch
  deployment-validated. `95a53fc`
- ✅ **Polish** — fuzz harnesses (`fuzz/`: obfs_record + message_parse), README, supply-chain policy.
- 📐 **Resolved by design / dependency-gated** (see [`docs/security-and-deferred.md`](../../docs/security-and-deferred.md)):
  hybrid-PQ confidentiality is **already** end-to-end via the obfs layer (a PQ Noise upgrade adds no
  harvest-now-decrypt-later protection); full native REALITY (needs a uTLS stack), QUIC+Salamander (needs
  `quinn` UDP access), AmneziaWG (needs a WireGuard core), and the local-RF blackout tier (needs radio
  hardware) are designed with rationale and are additive behind the `ObfsTransport` seam — not stubbed/faked.
- ⏳ **Remaining (designed)** — native REALITY/AmneziaWG transports, QUIC+Salamander datapath, hybrid-PQ libp2p
  security upgrade (replace stock Noise), range-based set-reconciliation sync, local-RF blackout tier, T038 NAT test.

## Validation & operations (added 2026-06-30, after review feedback)

Beyond unit/integration tests — real multi-node runs + metrics + impairment (see
[`docs/benchmarks.md`](../../docs/benchmarks.md)):

- ✅ **In-process N-node benchmark** (`examples/cluster.rs`) — gossip propagation p50/p95/max +
  delivery ratio under injected link latency. **100 nodes: 396 links, 100% delivery, p50=2ms/p95=3ms.** `b1529ef`,…
- ✅ **Docker cluster under real `tc netem`** (`docker/`) — isolated containers, real packet loss +
  latency; mesh forms and signed heartbeats propagate. `005173a`
- ✅ **Prometheus metrics** — `/metrics` on every node (peers, gossip, blobs, sync, handshake
  histogram); scalable compose + Prometheus DNS-SD scrape; runner queries aggregate metrics. `34fecf0`,(this change)
- ✅ **Docker scale to 100 nodes + Prometheus** — 100 nodes scraped, 25,540 gossip msgs under netem
  (loss 2% + 50ms±10); **obfs handshake p95=147ms (< 150ms SC target)**. `2833949`
- ✅ **DPI middlebox** — entropy-classifier censor in the path: obfs PASSES, raw high-entropy flow
  BLOCKED (`tests/dpi_middlebox.rs`). `05b292c`
- ✅ **Heavy netem + chaos** — loss/reorder/duplicate/corrupt + killing 12/50 nodes mid-run; survivors
  keep gossiping (3,741 msgs).
- ✅ **DPI active-probing** — censor probes suspects; obfs silence survives, naive proxy unmasked. `tests/dpi_middlebox.rs`
- ✅ **TLS ClientHello mimicry (state-machine DPI)** — obfs first flight is now a structurally-valid TLS 1.3
  ClientHello (`umesh-obfs::tls`, record `0x16`, PQ-hybrid X25519MLKEM768 key_share, PSK gate in `session_id`);
  flow opens ClientHello→ServerHello→app-data. New `dpi_middlebox::obfs_passes_tls_state_machine_dpi` passes
  while `appdata_first_flow_is_blocked_by_state_machine` confirms the censor enforces it; `dpi_sim::first_flight_is_a_client_hello`
  parses the on-wire CH. Closes the old "app-data-first → flagged" gap; byte-exact JA3/JA4 + full transcript
  remain deferred (native REALITY). 99 workspace tests green. (this change)
- ✅ **Per-node resources** — `umesh_process_*` metrics: RSS ~4MB leaf/~33MB boot, near-idle CPU. Tokio worker
  pool now small by default (`UMESH_WORKERS`, default 2 → 4 threads/node, was ~14; 1 = current-thread). (this change)
- ✅ **Throughput** — 267 MB/s (no shaping); aggressive IAT jitter caps bulk to 1.4 MB/s (by design).
- ✅ **Grafana pipeline** — provisioned datasource + dashboard, verified via API (`docker/grafana/`).
- ✅ **Geo-emulation** — 3 regions × per-container netem on eth0 (`docker/compose.geo.yml`); handshake p95 reflects far region.
- ✅ **Soak (3 min)** — RSS stable, no leak.
- 🚫 **Cannot close here (won't fake):** real nation-state/in-country DPI (incl. full TLS-transcript /
  byte-exact JA3/JA4 fingerprinting), true geo across real datacenters, hours/days soak, Grafana visual.
  See `docs/benchmarks.md` caveats.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable (different files, no incomplete-task dependency)
- Crate paths: `crates/umesh-crypto`, `crates/umesh-obfs`, `crates/umesh-p2p`, `crates/umesh-node`, `crates/uber-mesh`

---

## Phase 1: Setup (Shared Infrastructure)

- [ ] T001 Convert root `Cargo.toml` to a `[workspace]` virtual manifest (members `crates/*`), shared
  `[workspace.dependencies]` (pinned per plan.md) and `[workspace.lints]` (`unsafe_code`, clippy); remove root `src/`.
- [ ] T002 [P] Scaffold the five member crates with `Cargo.toml` + `src/lib.rs`/`main.rs`:
  `crates/umesh-crypto`, `crates/umesh-obfs`, `crates/umesh-p2p`, `crates/umesh-node`, `crates/uber-mesh`.
- [ ] T003 [P] Add `deny.toml` (advisories, licenses, bans, sources) and a `.github/workflows/ci.yml`
  (build, test, clippy -D warnings, fmt, cargo-deny) at repo root.
- [ ] T004 [P] Add `#![forbid(unsafe_code)]` to `umesh-crypto` and `#![deny(warnings)]` policy via workspace lints.

**Checkpoint**: `cargo build --workspace` succeeds on empty crates.

---

## Phase 2: Foundational — `umesh-crypto` (Blocking Prerequisites)

**⚠️ CRITICAL**: every other crate depends on this. Each task ships with tests (Principle V).

- [ ] T005 [P] Implement error types in `crates/umesh-crypto/src/error.rs` (`thiserror`).
- [ ] T006 [P] Implement BLAKE3 helpers in `crates/umesh-crypto/src/hash.rs`: `hash`, `keyed_mac`,
  `derive_key(label, ikm)` with the domain-separation label constants; `Cid` newtype. + unit tests.
- [ ] T007 [P] Implement Ed25519 identity in `crates/umesh-crypto/src/identity.rs`: keygen, sign,
  `verify_strict`, `PeerId = BLAKE3(pubkey)`, `zeroize` secret; serde for public parts only. + tests.
- [ ] T008 [P] Implement AEAD in `crates/umesh-crypto/src/aead.rs`: XChaCha20-Poly1305 seal/open with random
  24-byte nonce, per-direction keys via `derive_key`. + round-trip + tamper-detection tests.
- [ ] T009 Implement hybrid KEM in `crates/umesh-crypto/src/kem.rs`: X25519 + ML-KEM-768, X-Wing combiner per
  `contracts/handshake-wire.md` §B; ephemeral keygen, encapsulate, decapsulate → shared secret. (depends on T006)
- [ ] T010 [US-crypto] **KAT tests** in `crates/umesh-crypto/tests/kat_mlkem.rs` and `kat_xwing.rs`: ML-KEM-768
  NIST ACVP vectors + X-Wing test vectors; assert zero mismatches. (depends on T009)
- [ ] T011 [P] Implement Merkle tree in `crates/umesh-crypto/src/merkle.rs` (BLAKE3 leaves via `rs-merkle` or
  in-crate): root, membership proof, verify. + proof round-trip + tamper tests.
- [ ] T012 [P] Implement PoW in `crates/umesh-crypto/src/pow.rs`: challenge from pubkey+epoch, solve, verify
  leading-zero-bit difficulty. + solve/verify tests.
- [ ] T013 [P] Property tests in `crates/umesh-crypto/tests/props.rs` (`proptest`): AEAD seal∘open identity,
  KEM encapsulate/decapsulate agreement, Merkle proof soundness.

**Checkpoint**: `cargo test -p umesh-crypto` green; KATs pass.

---

## Phase 3: User Story 1 — Stay connected under active censorship (Priority: P1) 🎯 MVP

**Goal**: two nodes complete an obfuscated, probe-resistant, hybrid-PQ handshake, exchange data, and rotate
transports when one is blocked — all without manual config.

**Independent Test**: `cargo test -p umesh-obfs --test dpi_sim` — entropy classifier, active prober, and a
mid-session block forcing rotation, per `quickstart.md`.

### Tests for User Story 1 (write first; must fail before impl)

- [ ] T014 [P] [US1] Wire-parser fuzz target in `fuzz/fuzz_targets/obfs_handshake.rs` for the Layer-A/B parsers.
- [ ] T015 [P] [US1] DPI-simulation integration test scaffold in `crates/umesh-obfs/tests/dpi_sim.rs`:
  in-process middlebox (entropy band check, active probe, mid-session block) asserting SC-001/SC-002.

### Implementation for User Story 1

- [ ] T016 [P] [US1] Define `ObfsTransport` trait + `ObfsStream`/`ObfsParams`/`ObfsError` in
  `crates/umesh-obfs/src/lib.rs` + `transport.rs` per `contracts/obfs-transport.md`.
- [ ] T017 [US1] Implement Layer-A MAC-gate handshake in `crates/umesh-obfs/src/handshake.rs`: Elligator2-style
  uniform X25519 repr, BLAKE3-keyed MAC, sliding epoch window, **probe-resistant silence** path. (depends on T016, umesh-crypto)
- [ ] T018 [US1] Implement Layer-B hybrid-KEM exchange over the gated channel in `handshake.rs` (uses
  `umesh-crypto::kem`); derive `key_c2s`/`key_s2c`. (depends on T017, T009)
- [ ] T019 [US1] Implement Layer-C AEAD record framing + re-key/epoch in `crates/umesh-obfs/src/frame.rs`
  (length-prefixed XChaCha20-Poly1305 records, ≤16384). + parser unit tests. (depends on T018)
- [ ] T020 [P] [US1] Implement popcount/entropy mitigation + padding in `crates/umesh-obfs/src/handshake.rs`
  first-flight (assert exempt-band avoidance) + `entropy_band` test. (depends on T017)
- [ ] T021 [P] [US1] Implement `Shaper` (padding + IAT jitter + decoy) in `crates/umesh-obfs/src/shaping.rs`
  per `ShapingPolicy`. + shaping unit tests.
- [ ] T022 [P] [US1] Implement environment profiles + `ProfileSelector` in `crates/umesh-obfs/src/profile.rs`
  (Open/Moderate/Aggressive/Shutdown → transport order + shaping + udp_allowed).
- [ ] T023 [US1] Implement the concrete **obfs-tcp** `ObfsTransport` (tokio TCP listener/dialer wiring
  handshake+frame+shaper) in `crates/umesh-obfs/src/transport.rs`. + connect/accept integration test. (depends on T017–T021)
- [ ] T024 [US1] Implement active-probe resistance test path in `crates/umesh-obfs/src/probe.rs` and satisfy
  T015's probe assertion (unauth connect ⇒ silence+delay+close, indistinguishable). (depends on T017, T023)
- [ ] T025 [US1] Implement transport health-check + rotation logic in `crates/umesh-node/src/health.rs`
  (detect silent failure → select next transport from profile) and satisfy T015's rotation assertion (SC-002).
- [ ] T026 [US1] Make T014/T015 pass; verify SC-001 (≥95% establish) + SC-002 (≤10s rotate) in the sim.

**Checkpoint**: US1 MVP — obfuscated, probe-resistant, rotating connectivity demonstrable in the DPI sim.

---

## Phase 4: User Story 2 — Decentralized authenticated messaging (Priority: P2)

**Goal**: peers discover each other without a central server and exchange signed pub/sub messages; forged /
tampered / replayed messages are rejected.

**Independent Test**: bootstrap-only cluster; new node discovers peers, publishes a signed message all accept;
injected forged/tampered/replayed messages are rejected by every node (SC-004).

### Tests for User Story 2

- [ ] T027 [P] [US2] Fuzz target `fuzz/fuzz_targets/message_parse.rs` for the signed-message decoder.
- [ ] T028 [P] [US2] Integration test `crates/umesh-p2p/tests/gossip_validate.rs`: accept-valid + reject
  forged/tampered/replayed (SC-004, zero false accepts).

### Implementation for User Story 2

- [ ] T029 [P] [US2] Implement `SignedMessage` encode/validate in `crates/umesh-p2p/src/gossip.rs` per
  `contracts/message-wire.md` (transcript, Ed25519 sign/verify, `payload_hash`, `message_id`). + unit tests.
- [ ] T030 [US2] Implement replay protection in `crates/umesh-p2p/src/gossip.rs`: per-sender monotonic seqno,
  timestamp window, bounded LRU dedup. + replay-rejection test. (depends on T029)
- [ ] T031 [US2] Build the `MeshBehaviour` `#[derive(NetworkBehaviour)]` in `crates/umesh-p2p/src/behaviour.rs`
  with gossipsub (Strict validation, P1–P7 scoring), identify, ping per `contracts/libp2p-protocols.md`.
- [ ] T032 [US2] Integrate the obfs-tcp transport under libp2p Noise+yamux in
  `crates/umesh-p2p/src/transport.rs` (`Transport::and_then`). (depends on T023, T031)
- [ ] T032b [P] [US2] Wire stock `libp2p-quic` (`quic-v1`) as an opportunistic carrier for Open/Moderate
  profiles with a runtime UDP-availability probe in `crates/umesh-p2p/src/transport.rs` (FR-005). Note: this is
  *plain* QUIC for open networks; *obfuscated* QUIC (Salamander) remains deferred per plan.md.
- [ ] T033 [US2] Implement private Kademlia (`/uber-mesh/kad/1.0.0`) + rendezvous discovery in
  `crates/umesh-p2p/src/discovery.rs` (bootstrap, peer-exchange). (depends on T031)
- [ ] T034 [US2] Wire gossipsub validation callback to T029/T030 and emit peer-score penalties on invalid msgs;
  satisfy T028. (depends on T029, T030, T031)

**Checkpoint**: discovery + authenticated pub/sub with replay/forgery rejection.

---

## Phase 5: User Story 3 — Reach peers behind NAT/CGNAT (Priority: P3)

**Goal**: NATed peers participate via relay and upgrade to direct connections via hole punching where possible.

> **Deferred (FR-018 partial)**: S/Kademlia *disjoint-path* eclipse hardening is intentionally deferred this
> iteration (dossier §7 — non-trivial on rust-libp2p kad). FR-018 is covered here by creation-friction (PoW,
> T012), invalid-message + IP-colocation peer-score penalties (T031/T034), and pubkey-derived NodeIDs. Disjoint
> paths tracked as a follow-up feature.

**Independent Test**: node behind simulated symmetric NAT joins via relay and stays reachable; compatible NATs
upgrade to direct (SC-005).

### Implementation for User Story 3

- [ ] T035 [P] [US3] Add AutoNAT v2 client + reachability classification in `crates/umesh-p2p/src/nat.rs`.
- [ ] T036 [US3] Add Circuit Relay v2 (limited-resource server + client) and relay-first dialing in `nat.rs`. (depends on T035)
- [ ] T037 [US3] Add DCUtR hole-punch (TCP + QUIC where available) with relay fallback in `nat.rs`. (depends on T036)
- [ ] T038 [P] [US3] NAT integration test `crates/umesh-p2p/tests/nat_traversal.rs` (relay reachability +
  direct upgrade; symmetric stays relayed). (depends on T036)

**Checkpoint**: NATed peers reachable; opportunistic direct upgrade.

---

## Phase 6: User Story 4 — Operate and observe a node simply (Priority: P3)

**Goal**: single binary, persistent identity, config, health/rotation visibility, secret-free human+JSON status.

### Implementation for User Story 4

- [ ] T039 [P] [US4] Implement config in `crates/umesh-node/src/config.rs` (`serde`/`toml`: profile, listen,
  bootstrap, data_dir) + defaults + load/validate tests.
- [ ] T040 [P] [US4] Implement keystore in `crates/umesh-node/src/keystore.rs` (generate/load identity, 0600
  perms, `zeroize`, refuse overwrite without force) + tests.
- [ ] T041 [US4] Implement node runtime in `crates/umesh-node/src/node.rs` (build Swarm from `umesh-p2p`,
  identity, profile; run loop; integrate health/rotation T025). (depends on T031, T039, T040)
- [ ] T042 [US4] Implement status model in `crates/umesh-node/src/status.rs` (peers, transports, reachability,
  events) with `--json` schema per `contracts/cli.md`; assert no secrets present. + test.
- [ ] T043 [US4] Implement `tracing` setup (secret-free, leveled) in `crates/umesh-node/src/lib.rs`.
- [ ] T044 [US4] Implement CLI in `crates/uber-mesh/src/{main,cli}.rs` (`clap`): `init`, `run`, `status`,
  `peer`, `keys`; exit codes per `contracts/cli.md`. (depends on T039–T042)
- [ ] T045 [US4] End-to-end test `crates/uber-mesh/tests/two_node.rs`: init→run two nodes→status shows peer
  (SC-003, SC-006). (depends on T044)

**Checkpoint**: runnable, observable node from a single binary.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T046 [P] Ensure every wire parser has a fuzz target under `fuzz/` (obfs handshake, frame, message) and a
  short CI fuzz smoke run.
- [ ] T047 [P] `cargo deny check` + `cargo audit` clean; pin/justify any exception in `deny.toml`.
- [ ] T048 [P] Docs: per-crate `README.md` + crate-level `//!` docs; refresh root `README.md` and `quickstart.md`.
- [ ] T049 Security-hardening pass: confirm no secrets in logs/status/errors (grep + test), `zeroize` on all key
  types, decode limits on untrusted `bincode`, timestamp-skew + dedup bounds reviewed.
- [ ] T050 Performance check: handshake ≤150ms, rotation ≤10s, discovery+first-msg ≤5s against SC targets.
- [ ] T051 Run `/speckit-analyze` consistency pass and resolve any findings.

---

## Dependencies & Execution Order

- **Setup (P1)** → **Foundational `umesh-crypto` (P2)** blocks all stories.
- **US1 (P3 phase)** is the MVP and depends only on Foundational + Setup.
- **US2** depends on Foundational + US1's obfs-tcp transport (T023) for the under-Noise integration.
- **US3** depends on US2's `MeshBehaviour` (T031).
- **US4** depends on US2 (T031) + US1 rotation (T025).
- **Polish** last.

## Parallel Opportunities

- T002/T003/T004 in parallel. Most `umesh-crypto` modules (T006–T008, T011–T013) in parallel (different files).
- Within US1: T020/T021/T022 parallel after T017; T014/T015 (tests) parallel up front.
- Different stories can proceed in parallel once their dependency (Foundational, then T031) is met.

## Implementation Strategy

**MVP = Setup + Foundational + US1.** Deliver obfuscated, probe-resistant, rotating connectivity first
(STOP & VALIDATE via `dpi_sim`), then layer US2 messaging, US3 NAT, US4 operability incrementally. Commit after
each task or logical group (constitution: commit discipline).
