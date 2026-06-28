<!--
SYNC IMPACT REPORT
==================
Version change: (template) → 1.0.0
Bump rationale: Initial ratification of the uber-mesh constitution (MAJOR baseline).

Principles defined:
  I.   Security & Cryptography First (NON-NEGOTIABLE)
  II.  Censorship-Resilience by Design
  III. Decentralization & Self-Sovereign Identity
  IV.  Memory Safety & Pure-Rust Preference
  V.   Test-First & Cryptographic Verification (NON-NEGOTIABLE)
  VI.  Observability & Operability
  VII. Simplicity, Versioning & Supply-Chain Integrity

Added sections:
  - Security & Privacy Requirements (Section 2)
  - Development Workflow & Quality Gates (Section 3)
  - Governance

Templates requiring updates:
  ✅ .specify/templates/plan-template.md      (Constitution Check gates populated)
  ✅ .specify/templates/spec-template.md       (reviewed — security/censorship requirements already expressible)
  ✅ .specify/templates/tasks-template.md      (reviewed — principle-driven task categories noted)

Follow-up TODOs: none. All placeholders resolved.
-->

# uber-mesh Constitution

uber-mesh is a decentralized, censorship-resistant peer-to-peer mesh network written in Rust. It
exists to provide private, authenticated, resilient connectivity that survives hostile Deep Packet
Inspection (DPI) environments — including Russia's TSPU and Iran's IRGFW — and degrades gracefully
toward total-blackout conditions. This constitution defines the non-negotiable rules that govern its
design, implementation, and evolution. It supersedes all other practices.

## Core Principles

### I. Security & Cryptography First (NON-NEGOTIABLE)

Security is the product; everything else serves it.

- Use ONLY standardized, modern, peer-reviewed cryptographic primitives from audited-where-possible,
  actively-maintained crates. Inventing or hand-rolling primitives (ciphers, KEMs, hashes, signature
  schemes, KDFs) is PROHIBITED. Composing standard primitives into protocols is allowed but MUST follow
  established constructions (e.g. X-Wing for hybrid KEM, Noise patterns for handshakes).
- All key agreement MUST be **hybrid post-quantum**: a classical primitive (X25519) combined with a
  post-quantum KEM (ML-KEM-768). The classical half remains authoritative — a break in an unaudited PQ
  implementation MUST NOT by itself compromise a session.
- Secret material MUST use constant-time operations (`subtle`), be zeroized on drop (`zeroize`), and never
  appear in logs, errors, serialized cleartext, or telemetry.
- Apply strict **domain separation**: every distinct use of a hash/KDF (content IDs, message IDs, PoW
  challenges, handshake transcript, AEAD key derivation) MUST use a distinct, labeled derivation.
- Authenticated encryption (AEAD) is mandatory for all data channels; nonces MUST be misuse-resistant
  (random 192-bit XChaCha20-Poly1305 by default). No unauthenticated or cleartext payloads on the wire.

### II. Censorship-Resilience by Design

Reachability under active censorship is a first-class requirement, not an add-on.

- Every wire-exposed transport MUST be obfuscation-capable and pluggable behind a single `ObfsTransport`
  abstraction. Shipping a transport with a static, fingerprintable protocol signature (plaintext header,
  fixed handshake shape, or high-entropy "random" bytes without popcount/entropy mitigation) is PROHIBITED.
- All listeners MUST implement **probe-resistant authentication**: an unauthenticated/probing connection
  receives either cryptographic silence or a transparent fallback to genuine cover traffic — never a
  distinguishing response.
- Resilience derives from **agility**, not a single unbreakable protocol. Transport, fingerprint, and
  traffic-shaping aggressiveness MUST be selectable per **environment profile** (`Open`, `ModerateDPI`,
  `AggressiveDPI`, `Shutdown`) and rotatable at runtime via active transport health-checks.
- Defaults MUST be safe for hostile networks: TCP/443-survivable transports are the baseline; UDP/QUIC is
  an opportunistic fast-path that MUST fail over automatically when blocked.

### III. Decentralization & Self-Sovereign Identity

No single point of failure, no privileged operator.

- There MUST be no mandatory central server. Discovery, relay, bootstrap, and rendezvous MUST be
  peer-providable and substitutable; any centralized aid is an optional accelerant, never a dependency.
- Node identity is self-sovereign: derived from a locally-generated Ed25519 keypair, with `PeerID =
  BLAKE3(pubkey)`. No registration authority.
- The protocol MUST remain functional when any subset of peers is unavailable, censored, or adversarial,
  consistent with the integrity guarantees in Section 2.

### IV. Memory Safety & Pure-Rust Preference

- Code MUST be safe Rust by default. Each `unsafe` block requires an inline justification comment, a
  reviewer sign-off, and a test exercising it. Undocumented `unsafe` is PROHIBITED.
- Prefer pure-Rust, `no_std`-friendly dependencies to preserve auditability and portability. C/FFI
  dependencies (e.g. `boring`, `oqs`) are allowed ONLY behind an explicit feature flag with a recorded
  rationale, and MUST NOT be in the default build of the core libraries.
- The build MUST be warning-clean (`#![deny(warnings)]` in CI) and pass `clippy` with the project lint set.

### V. Test-First & Cryptographic Verification (NON-NEGOTIABLE)

- Cryptographic and protocol code MUST ship with: unit tests, **known-answer tests (KATs)** against the
  reference vectors of the standard, round-trip/property tests, and **fuzz harnesses for every wire parser**
  before merge. Handshake or parser code without tests MUST NOT be merged.
- Where interop with an external ecosystem is claimed (e.g. REALITY, Noise), a conformance test against the
  canonical implementation's vectors is REQUIRED before the interop claim may appear in docs.
- CI MUST be green (build, test, clippy, `cargo-audit`, `cargo-deny`) before any merge. A red pipeline blocks.

### VI. Observability & Operability

- Use structured logging (`tracing`) with leveled, machine-parseable output. Secrets and key material MUST
  never be logged, even at trace level.
- Transports MUST be actively health-checked; silent failures (timeout without RST, freezes) MUST be
  detected and trigger transport/endpoint/IP rotation.
- The CLI MUST support both human-readable and JSON output and follow a text-in/text-out contract.

### VII. Simplicity, Versioning & Supply-Chain Integrity

- Apply YAGNI. Prefer the simplest design that meets the requirement; justify every added dependency and
  every layer of indirection in the plan's Complexity Tracking.
- Dependencies MUST be pinned, minimal, and continuously audited (`cargo-deny`, `cargo-audit`,
  `cargo-vet` where feasible). Re-pin and re-audit before any release.
- Public APIs and wire formats follow Semantic Versioning. Wire formats MUST be documented and versioned;
  breaking a wire format is a MAJOR change requiring a migration path.

## Security & Privacy Requirements

- **Threat model alignment.** Design and reviews MUST be evaluated against the documented adversary
  (`docs/research/dossier.md`): passive entropy/fingerprint classification, active probing, SNI/QUIC-Initial
  inspection, TLS-in-TLS detection, volumetric TCP freezes, and UDP/protocol blackouts.
- **Forward secrecy.** Long-term Ed25519 identity keys are for authentication only. Every link MUST derive
  ephemeral session keys via a fresh handshake and support epoch re-keying so that key compromise never
  exposes past traffic.
- **Integrity & anti-abuse.** All gossip messages MUST be signed and carry a monotonic per-sender sequence
  number and timestamp; replays MUST be rejected (signature binding + bounded dedup cache + time window).
  Content MUST be self-certifying via BLAKE3 content addressing.
- **Privacy.** No deanonymizing telemetry. The system MUST NOT phone home. Metadata minimization is a goal;
  any optional analytics MUST be opt-in, local-first, and incapable of correlating peers.
- **Sybil/eclipse resistance.** DHT NodeIDs derive from public keys; identity creation is gated by
  proof-of-work friction; lookups use disjoint paths and outbound-quota/IP-colocation defenses. PoW is
  treated as friction, not a hard barrier, and combined with structural defenses.

## Development Workflow & Quality Gates

- **Spec-driven.** Work follows the SpecKit flow: constitution → specify → (clarify) → plan → tasks →
  analyze → implement. Design artifacts precede implementation; the plan's Constitution Check gate MUST pass
  before and after design.
- **Commit discipline.** Every meaningful step is committed with a descriptive message. History MUST remain
  bisectable; the build at each commit SHOULD compile.
- **Review gates.** Changes to crypto, handshake, or transport code REQUIRE adversarial review (a reviewer
  whose explicit job is to refute the change's safety) in addition to normal review.
- **No silent scope/complexity creep.** Any deviation from the constitution MUST be recorded in the plan's
  Complexity Tracking with justification and the rejected simpler alternative.

## Governance

- This constitution supersedes all other practices. Where guidance conflicts, the constitution wins.
- **Amendments** require: a written proposal describing the change and rationale, a version bump per the
  policy below, propagation to dependent templates (`plan-template.md`, `spec-template.md`,
  `tasks-template.md`), and a migration note when behavior or wire formats change.
- **Versioning policy** (of this document): MAJOR = backward-incompatible governance/principle removal or
  redefinition; MINOR = a new principle/section or materially expanded guidance; PATCH = clarifications and
  non-semantic refinements.
- **Compliance.** Every plan and review MUST verify compliance with these principles. Non-negotiable
  principles (I and V) cannot be waived; other principles may be deviated from only via recorded Complexity
  Tracking justification. Use `docs/research/dossier.md` and the feature plan for runtime development guidance.

**Version**: 1.0.0 | **Ratified**: 2026-06-28 | **Last Amended**: 2026-06-28
