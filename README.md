<div align="center">

# uber-mesh

**A decentralized, censorship-resistant peer-to-peer mesh network in Rust — built on modern, standardized, hybrid post-quantum cryptography.**

*Designed to keep nodes connected under aggressive DPI (Russia's TSPU, Iran's IRGFW) and to degrade gracefully toward blackout.*

[![CI](https://github.com/AlexMelanFromRingo/uber-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexMelanFromRingo/uber-mesh/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen.svg?style=flat-square)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![edition 2024](https://img.shields.io/badge/edition-2024-blue.svg?style=flat-square)](https://doc.rust-lang.org/edition-guide/)
[![tests](https://img.shields.io/badge/tests-99%20passing-success.svg?style=flat-square)](#validation--benchmarks)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden%20(core)-success.svg?style=flat-square)](#security-model)
[![crypto](https://img.shields.io/badge/crypto-X25519%20%2B%20ML--KEM--768-8A2BE2.svg?style=flat-square)](#security-model)
[![built with libp2p](https://img.shields.io/badge/built%20with-libp2p-269?style=flat-square)](https://libp2p.io)

</div>

> [!WARNING]
> **Research-grade and unaudited.** The post-quantum component (`ml-kem`) is **pre-audit**, and so is the
> wider stack. The classical X25519 half is kept *authoritative* so a flaw in the PQ half alone cannot
> break a session — but that is a mitigation, not an assurance. **Do not rely on uber-mesh for life-safety
> or anti-coercion** until an independent audit says otherwise. See [`SECURITY.md`](SECURITY.md).

---

## Contents

- [Why](#why) · [Highlights](#highlights) · [Architecture](#architecture) · [Workspace](#workspace-crates)
- [Quickstart](#quickstart) · [Censorship resistance](#censorship-resistance) · [Validation & benchmarks](#validation--benchmarks)
- [Security model](#security-model) · [Project layout](#project-layout) · [Spec-driven development](#spec-driven-development)
- [Roadmap](#roadmap) · [Contributing](#contributing) · [License](#license)

## Why

Resilience under censorship in 2025–26 comes from **agility, not a single unbreakable protocol**. Censors
combine passive fully-encrypted classification (entropy/no-header heuristics), active probing, TLS-state-machine
and SNI inspection, and volumetric throttling. uber-mesh layers a **pluggable, environment-selected
obfuscation transport** *below* a **hybrid post-quantum secure channel**, over a **decentralized libp2p
overlay** — so a node can blend with ordinary TLS traffic, refuse to reveal itself to probes, route around
blocks, and verify every message end-to-end without any central authority.

## Highlights

| Capability | What it does |
|---|---|
| 🔐 **Hybrid post-quantum** | Every link is keyed by **X25519 + ML-KEM-768** via **X-Wing** (draft-connolly-cfrg-xwing-kem-11, KAT-verified against the official vectors). Classical half stays authoritative; all mesh data rides a PQ-keyed tunnel (no harvest-now-decrypt-later). |
| 🥷 **TLS-1.3-ClientHello mimicry** | The obfs handshake is a *structurally-valid* TLS 1.3 ClientHello → ServerHello with a PQ-hybrid `X25519MLKEM768` key_share. Defeats entropy/no-header **and** TLS-state-machine DPI; blends with real PQ-TLS. |
| 🪞 **REALITY-style probe resistance** | A peer without the shared PSK fails the gate and gets **silence** or is **reverse-proxied to a real cover site** — an active prober can't distinguish a node from a genuine TLS server. |
| 🕸️ **Decentralized overlay** | libp2p **Gossipsub** (Strict signing + scoring), **private Kademlia**, identify/ping, and the NAT trio (**AutoNAT v2 / Circuit Relay v2 / DCUtR**) — all running *over* the obfs carrier. |
| 🔒 **End-to-end sealed topics** | With a shared 32-byte topic key, gossip payloads are **XChaCha20-Poly1305-encrypted end to end** (AAD-bound to topic/sender/seqno/timestamp) and blobs are stored and served as ciphertext (`Cid` over the ciphertext): forwarders and serving peers validate, relay and serve them **without being able to read them**. Topics without a key stay public — readable by every forwarding peer. |
| ✍️ **Signed gossip + replay protection** | Ed25519-signed, content-addressed messages with monotonic seqno, timestamp window, and an LRU dedup guard. Forgeries and replays are rejected. |
| 📦 **Content exchange & sync** | Content-addressed store + request/response blobs (`BLAKE3(bytes) == Cid`) and **negentropy-style set reconciliation**. |
| 📈 **Observable & light** | Opt-in, loopback-only Prometheus `/metrics` + provisioned Grafana; **~4 MB RSS** per leaf node, tunable Tokio worker pool (`UMESH_WORKERS`). |
| 🦀 **Pure-Rust, no `unsafe`** | `unsafe_code = "deny"` workspace-wide; `#![forbid(unsafe_code)]` in the crypto core. Default build has no C/FFI. |

## Architecture

uber-mesh stacks obfuscation **below** libp2p's Noise channel, so the entire gossip mesh inherits the
transport's DPI resistance and the data path is hybrid-PQ end to end.

```mermaid
flowchart TB
    subgraph app["uber-mesh CLI · umesh-node"]
        A["init · run · mesh · status · keys<br/>config · keystore · runtime · Prometheus /metrics"]
    end
    subgraph overlay["umesh-p2p — libp2p overlay"]
        B["Gossipsub (signed + scored) · private Kademlia<br/>AutoNAT v2 / Relay v2 / DCUtR · blobs · set reconciliation"]
    end
    subgraph noise["libp2p Noise + Yamux"]
        C["authenticated, multiplexed secure channel"]
    end
    subgraph obfs["umesh-obfs — obfuscation carrier"]
        D["TLS-1.3 ClientHello/ServerHello handshake (PQ key_share + session_id MAC gate)<br/>AEAD record stream · length-hiding padding · IAT shaping · profiles · rotation"]
    end
    subgraph crypto["umesh-crypto (#![forbid(unsafe_code)])"]
        E["hybrid X25519 + ML-KEM-768 KEM · Ed25519 identity<br/>BLAKE3 hash/KDF/MAC/CID · XChaCha20-Poly1305 · Merkle · PoW"]
    end
    A --> B --> C --> D --> F["TCP / :443-survivable  (QUIC — staged)"]
    E -. keys & primitives .-> C
    E -. keys & primitives .-> D
```

The obfs handshake itself looks like an ordinary post-quantum TLS 1.3 opening on the wire:

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server (PSK holder)
    Note over C: ephemeral X25519 + ML-KEM-768 keygen
    C->>S: TLS ClientHello (0x16), Chrome-shaped (GREASE, shuffled extensions)<br/>key_share = X25519MLKEM768 + decoy X25519<br/>session_id = MAC_psk(whole ClientHello) — looks random
    Note over S: verify MAC (epochs e−1..e+1) + replay cache<br/>fail ⇒ silence OR forward every byte to the cover site
    S->>C: ServerHello + CCS + "encrypted handshake" records<br/>(hidden inside: server key confirmation)
    Note over C: verify server confirmation ⇒ server knows PSK + KEM secret
    C->>S: CCS + Finished-sized record (client key confirmation)
    Note over C,S: keys = KDF(hybrid secret ‖ PSK ‖ transcript), directional
    C->>S: Application-Data records (0x17) — Noise → Gossipsub …
    S->>C: Application-Data records (0x17)
```

### Workspace crates

| Crate | Role |
|-------|------|
| [`umesh-crypto`](crates/umesh-crypto) | Pure-Rust crypto core (`#![forbid(unsafe_code)]`): hybrid X25519+ML-KEM-768 **X-Wing** KEM (draft-11, KAT-verified), Ed25519 identity (`PeerId = BLAKE3(pubkey)`), BLAKE3 hash/KDF/keyed-MAC/CID with domain separation, XChaCha20-Poly1305, Merkle, PoW. KATs + property tests. |
| [`umesh-obfs`](crates/umesh-obfs) | Pluggable obfuscation carrier: TLS-1.3 ClientHello/ServerHello mimicry handshake with a `session_id` MAC gate, AEAD record stream, length-hiding padding + traffic shaping, environment profiles, `ObfsTcp` + connect-time rotation, REALITY-style fallback. DPI-simulation tests. |
| [`umesh-p2p`](crates/umesh-p2p) | libp2p mesh: signed gossip + replay protection, `MeshBehaviour` (Gossipsub Strict, private Kademlia, identify, ping) + NAT trio (AutoNAT v2 / Relay v2 / DCUtR) + blob request/response (bincode codec) + negentropy-style reconciliation, content-addressed `ContentStore`, `MeshNode` driver, Prometheus metrics. |
| [`umesh-node`](crates/umesh-node) | Node orchestration: config, identity keystore (`0600`), runtime, secret-free status. |
| [`uber-mesh`](crates/uber-mesh) | The CLI binary. |

## Quickstart

```bash
git clone https://github.com/AlexMelanFromRingo/uber-mesh
cd uber-mesh

cargo build --workspace
cargo test  --workspace        # 275 tests: KATs (incl. X-Wing), JA4, DPI sim, handshake attacks, sealed topics, gossip/NAT
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Two-node gossip mesh (obfuscated, hybrid-PQ, probe-resistant)

The mesh runs over the obfs carrier, so peers share an obfs **PSK** (a bridge secret printed by `init`,
distributed out-of-band).

```bash
# Initialize two nodes — each prints a PSK once. Note node A's PSK.
cargo run -p uber-mesh -- --data-dir /tmp/a init      # ← copy A's PSK
cargo run -p uber-mesh -- --data-dir /tmp/b init

# Put A's PSK in an owner-only file (never on the command line: argv is visible in `ps`).
(umask 077; printf '%s\n' '<A_PSK>' > /tmp/a.psk)

# Node A (bootstrap) — prints "libp2p peer: <PEER_ID>"; --metrics-addr opts in to a loopback /metrics
cargo run -p uber-mesh -- --data-dir /tmp/a mesh --listen /ip4/127.0.0.1/tcp/41999 \
    --psk-file /tmp/a.psk --metrics-addr 9100

# Node B — dials A over the obfuscated transport using A's PSK (here via the environment)
UMESH_PSK="$(cat /tmp/a.psk)" cargo run -p uber-mesh -- --data-dir /tmp/b mesh --listen /ip4/127.0.0.1/tcp/0 \
    --bootstrap /ip4/127.0.0.1/tcp/41999/p2p/<A_PEER_ID>
```

Each node prints `[uber-mesh/global] b3:<sender>: heartbeat …` (sender authenticated via Ed25519). A peer
started with the **wrong PSK is rejected by the obfs gate and never connects**. Inspect a node without
ever revealing secrets:

```bash
cargo run -p uber-mesh -- --data-dir /tmp/a status --json
curl -s 127.0.0.1:9100/metrics | grep umesh_      # peers, gossip, handshake histogram, resources
```

The `uber-mesh/global` topic above is **public**: the heartbeats are signed, but every peer that forwards
them can read them. To make a topic confidential end to end, give its members a shared **topic key**:

```bash
cargo run -p uber-mesh -- keys new-topic-key --out /tmp/ops.key     # 0600 file; key never printed
cargo run -p uber-mesh -- --data-dir /tmp/a mesh --topic ops --topic-key-file /tmp/ops.key --psk-file /tmp/a.psk …
```

Forwarders without the key still validate and relay `ops` messages but cannot read them (they see the
topic name, sender, sizes and timing); see `contracts/message-wire.md` "Sealed messages (v3)".

<details>
<summary>Environment variables</summary>

| Var | Default | Meaning |
|---|---|---|
| `UMESH_WORKERS` | `2` | Tokio worker threads (`1` = current-thread runtime; lower = lighter footprint). |
| `UMESH_PSK` | — | Obfs PSK (hex) override for `run`/`mesh`. Precedence: `--psk-file` > `--psk` (deprecated) > `UMESH_PSK` > `config.toml`. |
| `UMESH_TOPIC_KEY` | — | Sealed-topic key (hex) for `mesh --topic`. Precedence: `--topic-key-file` > `UMESH_TOPIC_KEY` > `config.toml` `[topic_keys]`. No key ⇒ the topic is public. |
| `UMESH_METRICS_ADDR` | *off* | Enables `/metrics` for `mesh` (same as `--metrics-addr`): `PORT` ⇒ `127.0.0.1:PORT`, or `IP:PORT`. |
| `METRICS_PORT` | — | **Deprecated.** If set, binds `/metrics` on `127.0.0.1:PORT` only (previously on by default on `0.0.0.0`). |
| `UMESH_SNI` | `www.cloudflare.com` | Cover-domain SNI presented in the obfs ClientHello. |
| `RUST_LOG` | `info` | Tracing filter (never logs secrets). |

</details>

Fuzz the wire parsers (nightly): `cd fuzz && cargo +nightly fuzz run obfs_record` (or `message_parse`,
`sealed_parse`, …).
Run a 100-node Docker cluster with Prometheus + Grafana under `tc-netem`: `NODES=100 bash docker/run-cluster.sh`
(generates a per-run PSK and Grafana admin password; Prometheus/Grafana are published on `127.0.0.1` only).

<details>
<summary>Operational security (read before deploying)</summary>

- **`/metrics` is off by default.** It is unauthenticated plaintext HTTP and its metric names identify the
  host as an uber-mesh node, which would defeat probe resistance if a censor can reach it. Enable it only on
  loopback (`--metrics-addr 9100`) or a private monitoring network; never on a public interface. It enforces a
  5 s header-read timeout, an 8 KiB header cap and at most 8 concurrent connections.
- **Pass the PSK via `--psk-file` or `UMESH_PSK`.** `--psk <HEX>` still works but logs a deprecation warning:
  command-line arguments are readable by other local users (`ps`, `/proc/<pid>/cmdline`).
- **Public vs sealed topics.** Link encryption ends at every hop. A topic without a topic key is public to
  every peer that forwards it; seal topics that carry anything confidential (`--topic-key-file`,
  `UMESH_TOPIC_KEY` or `config.toml` `[topic_keys]`). Anyone holding a topic key reads the whole topic, past
  and future — rotate it out of band to remove a member.
- **On-disk secrets.** `identity.key` and `config.toml` (which holds the PSK and any topic keys) are created `0600`, the data
  directory `0700`; the keystore refuses to read or write through symlinks. `identity.pow` (the public
  identity proof-of-work nonce) sits next to the key; if it is missing it is re-mined on start. A mistyped `profile` in
  `config.toml` / `--profile` is now an error instead of silently running as `moderate`.
- **Docker.** The image runs as uid 10001; bench containers start as root only to apply `tc-netem`
  (`NET_ADMIN`) and then drop privileges. Base images are pinned by tag + digest.

</details>

## Censorship resistance

uber-mesh borrows the load-bearing idea from each major circumvention design and composes them behind one
pluggable transport seam. The table is about *ideas and posture*, not a benchmark shoot-out.

| | uber-mesh | REALITY / XTLS | Hysteria2 | AmneziaWG | obfs4 |
|---|---|---|---|---|---|
| **Carrier** | TCP (`:443`-survivable) | TCP / TLS | QUIC / UDP | WireGuard / UDP | TCP |
| **Anti-DPI** | TLS-1.3 ClientHello mimicry + entropy/probe/state-machine resistance + cover-site fallback | steals a real TLS handshake (byte-exact) | Salamander obfs + congestion control | junk packets + magic headers | uniform-random + ntor + IAT |
| **Post-quantum** | ✅ X25519 + ML-KEM-768 | ❌ classical | ❌ | ❌ | ❌ |
| **Decentralized** | ✅ libp2p mesh | ❌ client/server proxy | ❌ proxy | ❌ VPN | ❌ pluggable transport |
| **What uber-mesh takes** | — | cover-site fallback + short-id-in-`session_id` gate | QUIC+Salamander *(designed, deferred)* | AmneziaWG obfs *(designed, deferred)* | silence / active-probe resistance |

> [!NOTE]
> uber-mesh's TLS mimicry is *structurally* valid (it defeats record-type and TLS-state-machine analysis and
> blends with real X25519MLKEM768 traffic). It is **not yet** a byte-exact uTLS JA3/JA4 fingerprint of a
> specific browser, nor a full TLS-1.3 transcript — closing that is the deferred native-REALITY work. See
> [`docs/security-and-deferred.md`](docs/security-and-deferred.md); who sees what, evidence levels and
> requirement → test traceability: [`docs/threat-model.md`](docs/threat-model.md).

## Validation & benchmarks

Harnesses exercising the **real code** beyond unit tests (single host, mid-2026; full method + caveats in
[`docs/benchmarks.md`](docs/benchmarks.md)):

| Scenario | Result |
|---|---|
| In-process gossip, **100 nodes** | **100% delivery**, propagation p95 ≈ **3 ms** |
| Docker **100 nodes** + Prometheus under `tc-netem` (loss 2%, 50 ms±10) | obfs handshake p95 = **147 ms** (< 150 ms target), 25 540 gossip msgs, **0 forgeries** |
| **DPI middlebox** in-path ([`tests/dpi_middlebox.rs`](crates/umesh-obfs/tests/dpi_middlebox.rs)) | obfs **passes** entropy/no-header **+** active-probing **+** TLS-state-machine censors; raw / always-answering / app-data-first flows are **blocked** |
| Throughput (loopback, AEAD records) | **267 MB/s** (aggressive IAT shaping caps bulk to 1.4 MB/s *by design*) |
| Per-node resources | RSS **~4 MB** leaf / ~33 MB bootstrap, near-idle CPU, ~4 threads (default pool) |
| Soak (3 min) · heavy chaos (kill 12/50) | RSS stable, no leak · 38 survivors keep gossiping, 0 forgeries |

> [!IMPORTANT]
> **Not faked, not closable here:** real nation-state / in-country DPI at scale, byte-exact JA3/JA4 + full
> TLS-transcript validation, true geographic distribution across real datacenters, and multi-day soak are
> out of reach of a software-only environment. The DPI middlebox is a faithful *model* of the primary
> heuristics, not a real censor. We document gaps rather than overclaim.

## Security model

- **Hybrid PQ, classical-authoritative.** Session keys combine X25519 and ML-KEM-768; a break in the
  (unaudited) PQ part alone cannot compromise a session. No hand-rolled primitives.
- **Probe resistance.** The PSK gate is a keyed BLAKE3 MAC in the TLS `session_id` (constant-time check,
  ±1-minute epoch window). Non-PSK peers get silence (obfs4 model) or a transparent cover-site proxy (REALITY model).
- **Self-sovereign identity.** `PeerId = BLAKE3(Ed25519 pubkey)`; signatures use `verify_strict`. No CA, no registry.
  Gossip senders carry a one-time **identity proof-of-work** (24 bits, ≈1 s at `init`) so fresh-identity
  floods against replay state cost real compute — friction, not a barrier.
- **No secret leakage.** PSKs, identity seeds, and session keys are zeroized on drop and never appear in logs,
  status, errors, or metrics (only fingerprints). On-disk secrets are `0600`.
- **Memory safety.** `unsafe_code = "deny"` workspace-wide; `#![forbid(unsafe_code)]` in `umesh-crypto`.

Full policy, threat model, and reporting: [`SECURITY.md`](SECURITY.md). Deferred-work disposition:
[`docs/security-and-deferred.md`](docs/security-and-deferred.md). The PQ crates are pre-audit — pin and
re-audit before any production use.

## Project layout

```text
crates/
  umesh-crypto   pure-Rust crypto core (#![forbid(unsafe_code)])
  umesh-obfs     obfuscation carrier (TLS-mimicry handshake, AEAD record stream, shaping, profiles)
  umesh-p2p      libp2p mesh overlay (gossip, Kademlia, NAT, blobs, reconciliation) over the obfs carrier
  umesh-node     config, keystore, node orchestration, status
  uber-mesh      the CLI (init / run / mesh / status / keys show|new-topic-key)
fuzz/            standalone nightly libFuzzer harnesses (excluded from the workspace)
docker/          scalable Docker cluster + Prometheus + Grafana + tc-netem runner
docs/            benchmarks, security-and-deferred, research dossier
specs/           Spec Kit design artifacts for 001-uber-mesh-core
.specify/        the constitution (iron rules) + Spec Kit templates
```

## Spec-driven development

uber-mesh is built with [**GitHub Spec Kit**](https://github.com/github/spec-kit): design precedes code and
the artifacts are checked in. The project's **iron rules** are seven constitutional principles
([`.specify/memory/constitution.md`](.specify/memory/constitution.md), v1.0.0):

> **I.** Security & Cryptography First *(non-negotiable)* · **II.** Censorship-Resilience by Design ·
> **III.** Decentralization & Self-Sovereign Identity · **IV.** Memory Safety & Pure-Rust Preference ·
> **V.** Test-First & Cryptographic Verification *(non-negotiable)* · **VI.** Observability & Operability ·
> **VII.** Simplicity, Versioning & Supply-Chain Integrity

The full design lives under [`specs/001-uber-mesh-core/`](specs/001-uber-mesh-core/) (`spec.md`, `plan.md`,
`tasks.md`, `data-model.md`, `research.md`, `contracts/`); the verified technical rationale is in
[`docs/research/dossier.md`](docs/research/dossier.md).

## Roadmap

**Implemented & tested** — crypto core (X-Wing, KAT-verified) · obfs carrier with an exact Chrome-133
ClientHello (JA4-verified), cover-site server-flight mimicry, probe resistance & REALITY-style fallback ·
sealed (end-to-end encrypted) topics + encrypted blobs · identity PoW · profiles / shaping / rotation · obfs **under libp2p Noise** (mesh inherits DPI
resistance) · Gossipsub + private Kademlia + AutoNAT/Relay/DCUtR · signed gossip + replay protection ·
content exchange + set reconciliation · Prometheus metrics + Grafana · node + CLI · Docker validation.

**Deferred by design** (additive behind the `ObfsTransport` seam; rationale in
[`docs/security-and-deferred.md`](docs/security-and-deferred.md)): QUIC + Salamander (needs `quinn` UDP access),
AmneziaWG (needs a WireGuard core), and a local-RF blackout tier (needs radio hardware). Tracked in
[`specs/001-uber-mesh-core/tasks.md`](specs/001-uber-mesh-core/tasks.md); release history in
[`CHANGELOG.md`](CHANGELOG.md).

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev loop, the **test-first rule**
for crypto/protocol/parser code, the default-deny-`unsafe` policy, and the spec-driven workflow. Please also
read the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Report vulnerabilities privately per [`SECURITY.md`](SECURITY.md).

## License

Licensed under the **Mozilla Public License 2.0** ([`LICENSE`](LICENSE)). By contributing you agree your
contributions are licensed under MPL-2.0.

## Acknowledgements

Built on the work of [rust-libp2p](https://github.com/libp2p/rust-libp2p), the
[dalek](https://github.com/dalek-cryptography) and [RustCrypto](https://github.com/RustCrypto) ecosystems
(`ml-kem`, `chacha20poly1305`), [BLAKE3](https://github.com/BLAKE3-team/BLAKE3), and the techniques behind
REALITY/XTLS, Hysteria, AmneziaWG, and obfs4. Developed with [GitHub Spec Kit](https://github.com/github/spec-kit).
