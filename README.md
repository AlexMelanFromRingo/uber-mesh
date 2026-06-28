# uber-mesh

A decentralized, **censorship-resistant** peer-to-peer mesh network in Rust, built on modern,
standardized, hybrid post-quantum cryptography. Designed to establish stable, private connectivity even
under aggressive DPI — Russia's TSPU and Iran's IRGFW — and to degrade gracefully toward blackout.

> **Status: working core foundation.** The cryptography, the obfuscated DPI-resilient transport, and a
> runnable two-node CLI are implemented and tested (60 tests, green CI lints). The libp2p gossip/discovery/
> NAT mesh (US2/US3) is specified and staged as the next iteration — see *Roadmap*.

Spec-driven via [GitHub Spec Kit](https://github.com/github/spec-kit): the project's iron rules live in
[`.specify/memory/constitution.md`](.specify/memory/constitution.md); the full design is under
[`specs/001-uber-mesh-core/`](specs/001-uber-mesh-core/); the verified technical rationale is in
[`docs/research/dossier.md`](docs/research/dossier.md).

## Why

Resilience under censorship comes from **agility, not a single unbreakable protocol** (2025–26 field
reality). uber-mesh layers a pluggable, environment-selected obfuscation transport *below* a hybrid
post-quantum secure channel, over a decentralized overlay — so a node can survive passive
fully-encrypted classification, active probing, SNI/QUIC inspection, and volumetric throttling.

## Architecture

```
                    ┌──────────────────────────── uber-mesh (CLI) ────────────────────────────┐
                    │  init · run · status · keys           (umesh-node: config, keystore,     │
                    │                                        identity, runtime, status)         │
                    └───────────────────────────────────────┬─────────────────────────────────┘
   overlay (staged) │  libp2p: gossipsub (signed+scored) · Kademlia (private) · AutoNAT/Relay/DCUtR
                    ├─────────────────────────────────────────────────────────────────────────┤
   secure channel   │  hybrid handshake  X25519 + ML-KEM-768  (X-Wing-style combiner)          │  umesh-crypto
                    │  XChaCha20-Poly1305 · Ed25519 identity · BLAKE3 CID/KDF · Merkle · PoW    │  (#![forbid(unsafe)])
                    ├─────────────────────────────────────────────────────────────────────────┤
   obfuscation      │  ObfsTransport: TLS-record framing · PSK-sealed probe-resistant handshake │  umesh-obfs
   (below Noise)    │  · length-hiding padding + IAT shaping · environment profiles · rotation  │
                    ├─────────────────────────────────────────────────────────────────────────┤
   carrier          │  obfs-tcp (TCP/443-survivable)        [ QUIC opportunistic — staged ]     │
                    └─────────────────────────────────────────────────────────────────────────┘
```

### Workspace crates

| Crate | Role |
|-------|------|
| [`umesh-crypto`](crates/umesh-crypto) | Pure-Rust crypto core (no C, `#![forbid(unsafe_code)]`): hybrid X25519+ML-KEM-768 KEM, Ed25519 identity, BLAKE3, XChaCha20-Poly1305, Merkle, PoW. KATs + property tests. |
| [`umesh-obfs`](crates/umesh-obfs) | Pluggable obfuscated transport: PSK-sealed probe-resistant handshake, AEAD record stream, traffic shaping, environment profiles, `ObfsTcp` + connect-time rotation. DPI-simulation test. |
| [`umesh-p2p`](crates/umesh-p2p) | libp2p mesh behaviour (gossip/discovery/NAT) — *staged* (design in `contracts/libp2p-protocols.md`). |
| [`umesh-node`](crates/umesh-node) | Node orchestration: config, identity keystore, runtime, secret-free status. |
| [`uber-mesh`](crates/uber-mesh) | CLI binary. |

## Quickstart

```bash
cargo build --workspace
cargo test  --workspace          # 60 tests: KATs, property tests, DPI sim, two-node auth
cargo clippy --workspace --all-targets -- -D warnings
```

### Two-node demo (obfuscated, hybrid-PQ, probe-resistant)

```bash
# Node A — generates an identity + a shared obfs PSK (printed once, share out-of-band)
cargo run -p uber-mesh -- --data-dir /tmp/a init        # note the printed PSK

# Node B
cargo run -p uber-mesh -- --data-dir /tmp/b init

# Run A as a listener, B dials A using A's PSK
cargo run -p uber-mesh -- --data-dir /tmp/a run --listen 127.0.0.1:4001 --psk <A_PSK>
cargo run -p uber-mesh -- --data-dir /tmp/b run --listen 127.0.0.1:4002 \
    --bootstrap 127.0.0.1:4001 --psk <A_PSK>
# A logs "inbound peer authenticated", B logs "outbound peer authenticated".

cargo run -p uber-mesh -- --data-dir /tmp/a status --json   # never reveals secrets
```

Fuzz the wire parser (nightly): `cargo +nightly fuzz run obfs_record` (in `fuzz/`).

## Security model (summary)

- **Hybrid PQ, classical-authoritative.** Session keys combine X25519 and ML-KEM-768; a break in the
  (unaudited) PQ part alone cannot compromise a session. No hand-rolled primitives.
- **Probe resistance.** Both handshake flights are AEAD-sealed under a per-cohort PSK; the wire looks like
  uniform-random TLS application data, and a peer without the PSK gets **silence** (no distinguishing reply).
- **Self-sovereign identity.** `PeerId = BLAKE3(Ed25519 pubkey)`; signatures use `verify_strict`.
- **No secrets leak.** Identity seeds + PSKs never appear in logs, status, or errors; secrets are zeroized.
- See the constitution (Principles I–VII) and `docs/research/dossier.md` for the full threat model. The PQ
  crates are pre-audit; pin and re-audit before any production use.

## Roadmap

Implemented: crypto core · obfs-tcp transport · profiles/shaping/rotation · node + CLI · adversarial security
review applied. **Staged (designed, not yet built):** libp2p gossipsub + private Kademlia discovery (US2),
AutoNAT/Relay/DCUtR NAT traversal (US3), native REALITY & AmneziaWG transports, QUIC+Salamander datapath,
hybrid-PQ libp2p security upgrade, range-based set-reconciliation sync, local-RF blackout tier. Tracked in
[`specs/001-uber-mesh-core/tasks.md`](specs/001-uber-mesh-core/tasks.md).

## License

MPL-2.0.
