# Security Policy

[![CI](https://github.com/AlexMelanFromRingo/uber-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexMelanFromRingo/uber-mesh/actions/workflows/ci.yml)
![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)
![Status: research-grade](https://img.shields.io/badge/status-research--grade-orange.svg)
![PQ crates: pre-audit](https://img.shields.io/badge/PQ%20crates-pre--audit-red.svg)

uber-mesh is a censorship-resistant mesh networking stack. Security is its reason to exist, so we
take reports seriously and try to be honest about exactly what is and is not protected.

> [!WARNING]
> **uber-mesh is research-grade software and is not audited.** The post-quantum component (the
> `ml-kem` crate, used for the ML-KEM-768 half of the hybrid key agreement) is **pre-audit**, and so
> is the wider stack. **Do not rely on uber-mesh for life-safety, anti-coercion, or any setting where
> a compromise endangers a person.** The design keeps the *classical* X25519 half authoritative
> precisely so that a flaw in the unaudited PQ implementation cannot, by itself, break a session — but
> that is a mitigation, not an assurance. Treat everything here as experimental until an independent
> audit says otherwise.

## Reporting a Vulnerability

Please report security vulnerabilities **privately**, through GitHub Security Advisories:

1. Go to the repository's **Security** tab:
   <https://github.com/AlexMelanFromRingo/uber-mesh/security/advisories>
2. Click **Report a vulnerability** to open a private advisory draft visible only to you and the
   maintainers.
3. Include enough detail to reproduce: affected crate/version (tag or commit), the threat-model
   assumption you believe is violated, and a proof-of-concept if you have one.

> [!IMPORTANT]
> **Do not open a public GitHub issue or pull request for a vulnerability.** Public disclosure before
> a fix is available puts users at risk. There is **no dedicated security email address** — GitHub
> Security Advisories is the single private channel.

What to expect:

- We aim to acknowledge a report within a few days. As an unfunded research project there is **no
  contractual SLA**, but we will keep you updated on triage and remediation.
- We ask for **reasonable / coordinated disclosure**: give us a fair window to investigate and ship a
  fix before any public write-up. We are happy to credit reporters in the advisory (or keep you
  anonymous — your call).
- If a report turns out to describe an *already-documented* residual gap (see
  [Known limitations](#known-limitations--residual-gaps) below), we will say so and point you at the
  relevant section rather than treat it as a new finding.

## Supported Versions

uber-mesh is **pre-1.0** and moves fast; the API and wire formats are not yet stable.

| Version | Supported |
|---|---|
| Latest tagged release (currently **v0.8.0**) | ✅ Security fixes land here |
| Any older tag | ❌ Not supported — upgrade to the latest tag |
| `main` between tags | ⚠️ Best-effort only |

There are no long-term-support branches. If you are running uber-mesh, track the latest tag.

## Threat Model (summary)

uber-mesh is built against a network adversary with deep-packet-inspection capability. The full
rationale lives in [`docs/research/dossier.md`](docs/research/dossier.md) and the iron rules in the
project constitution ([`.specify/memory/constitution.md`](.specify/memory/constitution.md),
Principles I and II). In brief, we design against:

- **Passive classification** — entropy/fingerprint analysis of the byte stream (e.g. USENIX'23-style
  "no plaintext header / high-entropy" classifiers).
- **Active probing** — a censor that connects to a suspected endpoint and watches how it responds.
- **TLS-in-TLS and TLS-state-machine inspection** — heuristics such as "a real flow must open with a
  ClientHello before any application data."
- **SNI / QUIC-Initial inspection** and protocol/port blocking, volumetric TCP freezes, and UDP
  blackouts.
- **Harvest-now-decrypt-later (HNDL)** — an adversary recording ciphertext today to decrypt with a
  future quantum computer.

Out of scope: a compromised endpoint/host, malicious peers you explicitly trust, traffic-confirmation
attacks by a global passive adversary with full netflow, and real nation-state DPI with ML
classifiers at scale (we model these in tests but cannot claim to defeat the real thing — see
[`docs/benchmarks.md`](docs/benchmarks.md)).

## Security Properties

What the implementation provides today, with the crate that owns each property:

- **Hybrid post-quantum confidentiality, classical-authoritative.** Every link derives ephemeral
  session keys from a hybrid **X25519 + ML-KEM-768** KEM combined with an X-Wing-style BLAKE3 combiner
  (`umesh-crypto::kem`). All mesh traffic rides inside the obfs AEAD record stream, so libp2p's own
  Noise layer sits *inside* a PQ-keyed tunnel — defeating HNDL for mesh data. A break of ML-KEM-768
  alone cannot compromise a session because the classical X25519 half remains authoritative.
  (Constitution Principle I.)
- **Probe resistance / authenticated handshake.** The v0.8.0 obfs carrier rides a structurally-valid
  TLS 1.3 ClientHello → ServerHello → application-data exchange (`umesh-obfs::tls`). Authentication
  and probe-resistance are gated by a **keyed BLAKE3 MAC smuggled in the 32-byte TLS `session_id`**
  (`epoch || MAC(key_share, epoch)`, verified in constant time, ±1-minute epoch window). A peer
  without the shared PSK fails the gate and gets either **silence** (obfs4 model: randomized drain
  delay, no distinguishing reply) or a **transparent reverse-proxy to a real cover site**
  (`ProbeResponse::Fallback`, REALITY model). The cover SNI defaults to `www.cloudflare.com` and is
  overridable via `UMESH_SNI`.
- **Signed, content-addressed gossip with replay protection.** Gossip messages are Ed25519-signed and
  bound to `(topic, sender PeerId, sender_key, seqno, timestamp, payload_hash)`. Validation is
  stateless signature + payload-hash checks plus a stateful **replay guard**: monotonic per-sender
  seqno, a ±5-minute timestamp window, and a 65 536-entry LRU dedup cache (`umesh-p2p::gossip`).
  gossipsub runs with Strict signing, peer scoring, and content-derived message-ids. Blob transfers
  are CID-verified (`BLAKE3(bytes) == cid`).
- **Self-sovereign identity.** Node identity is an Ed25519 keypair; `PeerId = BLAKE3(verifying_key)`,
  and signatures are checked with `verify_strict` (`umesh-crypto::identity`). No certificate
  authority, no registry.
- **No secret leakage + zeroization.** Secret material (PSK, identity seed, session keys) is
  zeroized on drop and never written to logs or status output — `NodeStatus`, errors, and metrics
  expose only fingerprints (e.g. `psk_fingerprint = BLAKE3(psk)[..6]`). On-disk secrets are `0600`
  files (`umesh-node::keystore`).
- **Memory safety, default-deny unsafe.** The whole workspace is `unsafe_code = "deny"`, and the
  cryptographic core (`umesh-crypto`) is `#![forbid(unsafe_code)]` — zero unsafe. Pure-Rust by
  default; any C/FFI is feature-gated. (Constitution Principle IV.)
- **Test-first crypto/protocol/parser verification.** Crypto and wire parsers ship with unit tests,
  known-answer tests (BLAKE3 empty-input, RFC 7748 §5.2 X25519, hybrid-KEM agreement), property tests
  (AEAD round-trip + bit-flip detection, CID determinism, Merkle membership), and DPI/censor
  simulation tests. CI enforces `cargo fmt`, `clippy -D warnings`, build, the full test suite, and
  `cargo-deny` (advisories/bans/licenses/sources). (Constitution Principle V.)

## Known Limitations & Residual Gaps

We document gaps rather than paper over them. Full disposition and rationale:
[`docs/security-and-deferred.md`](docs/security-and-deferred.md).

- **Obfs carrier is structurally valid, not byte-exact.** The TLS 1.3 ClientHello/ServerHello mimicry
  defeats entropy, active-probing, and TLS-state-machine DPI heuristics, but it is **not** a
  byte-for-byte uTLS fingerprint of a specific browser (fixed extension set, single default SNI, so
  **JA3/JA4 fingerprinting is not yet matched**) and it is **not** a full TLS 1.3 transcript (no real
  EncryptedExtensions/Certificate/Finished). A DPI engine performing full-transcript validation could
  still distinguish it. Closing this requires a real ClientHello-controlling TLS stack and Go-Xray
  interop testing, and is **deferred behind a future `reality` feature flag.**
- **Pre-audit cryptography.** As stated in the warning above, the PQ crate and the stack are
  unaudited.
- **Deferred carriers.** QUIC + Salamander, AmneziaWG, and a local-RF blackout tier are *designed but
  not implemented* (they need heavy external dependencies or radio hardware). They are isolated behind
  the `ObfsTransport` seam as additive carriers — see `docs/security-and-deferred.md` §2.
- **Benchmarks are emulated.** Resilience numbers in [`docs/benchmarks.md`](docs/benchmarks.md) come
  from in-process clusters and Docker + `tc-netem` impairment on a single host. They are a faithful
  model, **not** evidence against real in-country DPI, true geographic distribution, or multi-day
  soak.

## References

- Security rationale & deferred-work disposition: [`docs/security-and-deferred.md`](docs/security-and-deferred.md)
- Project constitution (iron rules, threat model): [`.specify/memory/constitution.md`](.specify/memory/constitution.md)
- Technical dossier: [`docs/research/dossier.md`](docs/research/dossier.md)
- Validation & benchmarks: [`docs/benchmarks.md`](docs/benchmarks.md)
