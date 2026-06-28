# Implementation Plan: uber-mesh — Decentralized Censorship-Resistant Mesh

**Branch**: `001-uber-mesh-core` | **Date**: 2026-06-28 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-uber-mesh-core/spec.md`

## Summary

uber-mesh is a decentralized, censorship-resistant P2P mesh. The primary requirement is **authenticated,
forward-secret connectivity that survives hostile DPI** (Russia TSPU, Iran IRGFW) and degrades gracefully.
The technical approach: a **layered, pluggable obfuscated transport** (`ObfsTransport` trait, selected by
environment profile) sitting *below* a **hybrid post-quantum** secure handshake (X25519 + ML-KEM-768),
carried over a **rust-libp2p** mesh (gossipsub pub/sub with signed messages + peer scoring, a private
Kademlia DHT + rendezvous for discovery, AutoNAT v2 + Circuit Relay v2 + DCUtR for NAT traversal). Integrity
is BLAKE3 content-addressing + Ed25519 signatures + replay protection. Rationale and verified crate
selection are in `docs/research/dossier.md` and Phase 0 `research.md`.

## Technical Context

**Language/Version**: Rust 1.95 (edition 2024). The core crypto crate targets `no_std`-compatible deps where feasible.

**Primary Dependencies** (verified mid-2026; pin via `Cargo.toml`):
- Mesh: `libp2p` 0.56.x (umbrella, Tokio): `gossipsub`, `kad`, `identify`, `ping`, `autonat`, `relay`,
  `dcutr`, `rendezvous`, `noise`, `yamux`, `tcp`, `quic`, `connection-limits`.
- Crypto: `ml-kem` 0.3, `x25519-dalek` 2 (`curve25519-dalek ≥ 4.1.3`), `ed25519-dalek` 2.2, `blake3` 1.8,
  `chacha20poly1305` 0.11 (XChaCha20), `hkdf`/`hmac`/`sha2`, `rs-merkle`, `zeroize`, `subtle`, `rand`/`getrandom`.
- Hybrid KEM combiner: X-Wing construction (via `x-wing` crate if sound, else an in-crate combiner per spec).
- Serialization: `bincode` 3 (used inside the encrypted channel only).
- Async/runtime/CLI/obs: `tokio` 1.x, `futures`, `tracing`/`tracing-subscriber`, `clap` 4, `serde`/`toml`, `thiserror`.
- Optional (feature-gated, NOT in default core): `boring` / Go-REALITY sidecar (uTLS fidelity), `quinn` extras.

**Storage**: Local filesystem only — identity keystore (`identity.key`, mode 0600), config (`config.toml`),
optional peer cache. No database.

**Testing**: `cargo test` (unit + integration), known-answer tests (NIST ACVP / RFC vectors), property tests
(`proptest`), parser fuzzing (`cargo-fuzz`/libFuzzer), a DPI-simulation harness (in-process middlebox),
`cargo-deny` + `cargo-audit` in CI.

**Target Platform**: Linux/macOS/Windows native (x86_64/aarch64); architecture must not preclude a future
mobile/local-RF tier.

**Project Type**: Multi-crate Cargo workspace — library crates + a CLI binary.

**Performance Goals**: hybrid-PQ handshake ≤ 150 ms on a normal link; transport rotation on detected block
≤ 10 s (SC-002); discovery + first authenticated message ≤ 5 s (SC-003); shaping overhead tunable per profile.

**Constraints**: no hand-rolled primitives; AEAD-only on the wire; no plaintext protocol fingerprint;
probe-resistant listeners; no mandatory central server; secrets never logged; warning-clean + clippy-clean.

**Scale/Scope**: tens-to-thousands of peers per node's view; single-binary deployment; this feature builds
the core (see "Scope for this iteration"); REALITY/AmneziaWG/QUIC-Salamander/local-RF are deferred.

## Constitution Check

*GATE: evaluated against `.specify/memory/constitution.md` v1.0.0. PASS / FAIL / N/A + note.*

- **I. Security & Cryptography First** — **PASS**. Only standardized primitives (ML-KEM-768, X25519, Ed25519,
  BLAKE3, XChaCha20-Poly1305) from maintained crates; hybrid PQ with classical authoritative; constant-time
  (`subtle`) + `zeroize` + BLAKE3 domain-separated KDF; AEAD-only wire. *(NON-NEGOTIABLE — satisfied.)*
- **II. Censorship-Resilience by Design** — **PASS**. All wire transports behind `ObfsTransport`; obfs sits
  below Noise; popcount/entropy mitigation + probe-resistant auth + environment profiles + health-checked rotation.
- **III. Decentralization & Self-Sovereign Identity** — **PASS**. No mandatory central server; `PeerID =
  BLAKE3(Ed25519 pubkey)`; private Kademlia + peer-provided relay/bootstrap.
- **IV. Memory Safety & Pure-Rust Preference** — **PASS**. Safe Rust; default build is pure-Rust; `boring`/sidecar
  behind feature flags only (see Complexity Tracking); `#![forbid(unsafe_code)]` in the crypto crate.
- **V. Test-First & Cryptographic Verification** — **PASS** (plan-level). KAT + property + fuzz harness tasks are
  mandatory and precede/accompany the crypto & parser code. *(NON-NEGOTIABLE — enforced in tasks.md.)*
- **VI. Observability & Operability** — **PASS**. `tracing` structured logs (secret-free), health-checks with
  rotation, `status` command in human + JSON.
- **VII. Simplicity, Versioning & Supply-Chain Integrity** — **PASS**. Minimal pinned deps; `cargo-deny`/`audit`
  gates; versioned wire formats (documented in `contracts/`); SemVer.

**Result: all gates PASS. No unjustified violations.** Feature-gated C/FFI dependencies are tracked below.

## Project Structure

### Documentation (this feature)

```text
specs/001-uber-mesh-core/
├── plan.md              # This file
├── research.md          # Phase 0 — decisions/rationale/alternatives (distilled from docs/research/dossier.md)
├── data-model.md        # Phase 1 — entities, key/identity model, wire-format fields
├── quickstart.md        # Phase 1 — build/run/try-it
├── contracts/           # Phase 1 — CLI schema, ObfsTransport trait, handshake & message wire formats, protocol IDs
│   ├── cli.md
│   ├── obfs-transport.md
│   ├── handshake-wire.md
│   ├── message-wire.md
│   └── libp2p-protocols.md
└── checklists/
    └── requirements.md  # spec quality checklist (passing)
```

### Source Code (repository root) — Cargo workspace

```text
Cargo.toml                       # [workspace] virtual manifest (members + shared deps/lints)
deny.toml                        # cargo-deny supply-chain policy
crates/
├── umesh-crypto/                # PURE-RUST crypto core — #![forbid(unsafe_code)], no C deps
│   └── src/{lib,kem,identity,hash,aead,merkle,pow,error}.rs   + tests/kat_*.rs
├── umesh-obfs/                  # ObfsTransport trait + obfuscated TCP transport + shaping + profiles
│   └── src/{lib,transport,handshake,frame,shaping,profile,probe,error}.rs + tests/
├── umesh-p2p/                   # libp2p behaviour wiring: gossip, discovery, NAT, transport integration
│   └── src/{lib,behaviour,gossip,discovery,nat,transport,event}.rs
├── umesh-node/                  # node orchestration library: config, identity store, runtime, health/rotation, status
│   └── src/{lib,config,keystore,node,health,status}.rs
└── uber-mesh/                   # CLI binary (clap): init, run, status, peer, keys
    └── src/{main,cli}.rs
fuzz/                            # cargo-fuzz targets for every wire parser
docs/research/dossier.md         # technical rationale (already committed)
```

**Structure Decision**: A **Cargo workspace** is chosen over a single crate to honor Principle IV (the
crypto core is an independently-testable, pure-Rust, `unsafe`-free library isolated from the heavier
networking stack) and the dossier's "split architecture" (crypto/handshake evolves independently of
obfuscation and of the libp2p layer). The binary `uber-mesh` is a thin CLI over `umesh-node`.

### Scope for this iteration (build now)

Crates `umesh-crypto` (complete + KAT/property tests), `umesh-obfs` (trait + working obfuscated TCP transport
with popcount/entropy mitigation, probe-resistant handshake, AEAD framing, shaping, profiles + tests),
`umesh-p2p` (compiling NetworkBehaviour: gossipsub signed + scoring, private Kademlia + identify + ping +
autonat + relay + dcutr; custom transport plugged under noise), `umesh-node` + `uber-mesh` CLI (init/run/status,
persistent identity, health-checked rotation, JSON+human status).

### Deferred (documented, not built this iteration)

Native REALITY client/server, AmneziaWG transport, QUIC+Salamander datapath, custom hybrid-PQ libp2p security
upgrade (stock noise used first), range-based set reconciliation sync, local-RF blackout tier, browser
(WebTransport) reach, uTLS-grade fingerprinting via `boring`/sidecar.

## Complexity Tracking

> Deviations from "simplest possible" that are justified per the constitution.

| Decision | Why Needed | Simpler Alternative Rejected Because |
|----------|-----------|--------------------------------------|
| Multi-crate workspace (5 crates) vs single crate | Isolates a pure-Rust, `unsafe`-free, independently-testable crypto core (Principle IV) and lets crypto/obfs/p2p evolve independently (dossier split-architecture) | A single crate couples the audited crypto core to the heavy libp2p/Tokio graph, weakening auditability and `no_std` portability of the primitives |
| Custom `ObfsTransport` layer below libp2p's Noise | DPI resilience requires hiding Noise's fixed-shape handshake; no production rust-libp2p obfuscated transport exists (Principle II) | Stock libp2p transports alone leave a static, classifiable fingerprint that fails in RU/IR |
| Hybrid PQ (two KEMs) instead of one | A break in the unaudited ML-KEM impl must not break sessions (Principle I) | PQ-only trusts an unaudited primitive; classical-only ignores harvest-now-decrypt-later |
| Feature-gated C/FFI (`boring`, optional Go-REALITY sidecar) — NOT default | uTLS-grade fidelity / native-REALITY parity are not yet achievable in pure Rust (dossier §7) | Forcing pure-Rust-only ships a weaker fingerprint or blocks the feature; gating keeps the default build pure-Rust and the dependency opt-in (Principle IV) |
| Stock libp2p-noise first; custom hybrid-PQ upgrade deferred | Ships a working, interoperable mesh now; the PQ security-upgrade is net-new and must be built + tested carefully (Principle V) | Building the custom PQ libp2p upgrade up front risks an untested security layer gating all connectivity |
