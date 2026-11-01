<!-- SPECKIT START -->
# uber-mesh — agent context

Active feature: **001-uber-mesh-core** (branch `001-uber-mesh-core`).

Read these for technologies, structure, commands, and rules before working:
- Iron rules: `.specify/memory/constitution.md` (v1.0.0 — security-first, hybrid PQ, pluggable obfuscation,
  test-first crypto verification)
- Current plan: `specs/001-uber-mesh-core/plan.md` (architecture, crate layout, dependency manifest)
- Design: `specs/001-uber-mesh-core/{research,data-model}.md` and `contracts/` (wire formats, traits, CLI)
- Technical rationale: `docs/research/dossier.md`
- Tasks: `specs/001-uber-mesh-core/tasks.md`

Stack: Rust 1.95 (edition 2024) Cargo workspace; rust-libp2p 0.56 (Tokio); crypto = ml-kem + x25519-dalek +
ed25519-dalek + blake3 + chacha20poly1305 (XChaCha20); Merkle = own RFC 9162 tree (`umesh-crypto::merkle`). Default build is pure-Rust; C/FFI is
feature-gated only. Commit each step. Tests for crypto/protocol/parser code are mandatory (Principle V).
<!-- SPECKIT END -->
