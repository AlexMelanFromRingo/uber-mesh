# Quickstart: uber-mesh

> Status: core iteration (crypto + obfs transport + libp2p mesh + CLI). Some transports are deferred (see plan).

## Prerequisites

- Rust 1.95+ (edition 2024), `cargo`.
- Optional dev tools: `cargo-deny`, `cargo-audit`, `cargo-fuzz`.

## Build & test

```bash
cargo build --workspace
cargo test  --workspace            # unit + KAT + property tests
cargo test  -p umesh-crypto        # crypto known-answer tests only
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check                   # supply-chain policy (advisories, licenses, bans)
```

## Run a two-node local mesh

```bash
# Node A (bootstrap/relay-capable)
cargo run -p uber-mesh -- init --data-dir /tmp/a
cargo run -p uber-mesh -- run  --data-dir /tmp/a --profile open \
    --listen /ip4/127.0.0.1/tcp/4001

# Node B — dial A as bootstrap
cargo run -p uber-mesh -- init --data-dir /tmp/b
cargo run -p uber-mesh -- run  --data-dir /tmp/b --profile moderate \
    --listen /ip4/127.0.0.1/tcp/4002 \
    --bootstrap /ip4/127.0.0.1/tcp/4001

# Inspect
cargo run -p uber-mesh -- status --data-dir /tmp/b --json
```

## Try censorship resilience (simulation)

```bash
# Runs the in-process DPI-simulation integration test: entropy classifier,
# active prober, and a mid-session block that forces transport rotation.
cargo test -p umesh-obfs --test dpi_sim -- --nocapture
```

## Profiles

| Profile | Use when | Transport preference | Shaping |
|---|---|---|---|
| `open` | uncensored | QUIC, then obfs-tcp | minimal |
| `moderate` | light DPI | obfs-tcp, then QUIC | light padding |
| `aggressive` | RU TSPU / IR DPI | obfs-tcp only (TCP/443-style) | padding + IAT jitter |
| `shutdown` | near-blackout | obfs-tcp local; (future local-RF) | max, decoy |

## Where things live

- Crypto primitives & KATs: `crates/umesh-crypto`
- Obfuscated transport + DPI simulation: `crates/umesh-obfs`
- libp2p mesh behaviour: `crates/umesh-p2p`
- Node runtime + config + keystore: `crates/umesh-node`
- CLI: `crates/uber-mesh`
- Rationale: `docs/research/dossier.md`; design: `specs/001-uber-mesh-core/`
