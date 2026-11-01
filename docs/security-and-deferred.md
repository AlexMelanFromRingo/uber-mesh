# uber-mesh — Security analysis & disposition of dependency-gated work

This document gives the security rationale for the post-quantum posture and an honest disposition of
the remaining designed-but-not-built items. It is deliberately precise about what is implemented and
tested versus what is deferred and why.

## 1. Post-quantum posture — the requirement is met *by design*

**Claim: the mesh's data confidentiality is already hybrid post-quantum, end to end.**

Every byte the mesh carries travels inside the **obfs layer's AEAD record stream**, whose keys come from
the hybrid **X25519 + ML-KEM-768** handshake (`umesh-crypto::kem`, X-Wing-style combiner; tested in
`crates/umesh-crypto/tests/kat.rs` and `kem.rs`). Concretely, for the gossip mesh the layering is:

```
TCP → obfs handshake (hybrid X25519+ML-KEM-768) → ObfsByteStream (AEAD) → libp2p Noise → Yamux → app
```

The libp2p **Noise** layer sits *inside* the obfs AEAD tunnel. Therefore:

- **Harvest-now-decrypt-later is defeated for all mesh traffic.** A future quantum adversary that records
  the wire sees only the obfs hybrid-PQ ciphertext; recovering the plaintext requires breaking *both*
  X25519 and ML-KEM-768. The classical-only Noise handshake it would also see is already encrypted by the
  PQ-keyed obfs layer.
- **Noise's role here is peer *authentication*** (binding the connection to a libp2p PeerId), not
  long-term confidentiality. Authentication is a *real-time* property: a recorded classical handshake
  cannot be retroactively forged by a later quantum computer. So classical X25519 authentication carries
  **no** harvest-now-decrypt-later risk.

**Conclusion.** The "hybrid PQ everywhere" goal (constitution Principle I) is satisfied for confidentiality
by the obfs layer. A PQ-signature identity (ML-DSA) or a custom PQ Noise upgrade would be *defense in
depth* for authentication only, and is deliberately **not** adopted yet because: (a) it adds no
harvest-now-decrypt-later protection, and (b) pure-Rust ML-DSA / PQ-Noise are pre-audit and have had real
correctness bugs (dossier §3). Keeping Ed25519 for identity + hybrid-PQ for confidentiality is the
defensible, lower-risk choice. *(Future option: register a custom hybrid-PQ libp2p `ConnectionUpgrade`
using `umesh-crypto::kem` once an audited ML-KEM/ML-DSA lands; the architecture already isolates this.)*

## 2. Deferred transports — concrete designs, honest rationale

These are **not implemented** because each requires a specific heavy external dependency (a uTLS-grade TLS
stack, a WireGuard implementation, a QUIC stack with UDP-level packet access) or hardware that cannot be
exercised or tested in a software-only session. They are *not* stubbed or faked. The `ObfsTransport`
pluggability is in place (obfs-tcp is the first carrier; the fallback-proxy variant is the second probe
policy), so each is an additive carrier behind the same seam.

### 2.1 Native REALITY (full Xray interop) — *largely delivered; byte-exact fingerprint deferred*

- **Delivered — active-probe resistance:** REALITY's load-bearing idea — **transparent reverse-proxy to a
  real cover site** for any connection that fails the gate — is implemented and tested
  (`ProbeResponse::Fallback`, `dpi_sim::probe_is_proxied_to_cover_site`). A prober with the wrong PSK
  receives a genuine site's content.
- **Delivered — TLS-state-machine mimicry (`umesh-obfs::tls`):** the obfs handshake now rides a
  **structurally-valid TLS 1.3 ClientHello** (record type `0x16`) with a PQ-hybrid `X25519MLKEM768`
  key_share carrying the X25519 + ML-KEM-768 material, answered by a ServerHello; the PSK auth gate is a
  keyed MAC smuggled in the 32-byte `session_id` (REALITY's short-id-in-SessionID idea). **Wire v2
  (0.9.0)** adds a Chrome-shaped template (GREASE, shuffled extensions, decoy X25519 share), a full-looking
  server flight carrying mutual key confirmation, PSK + transcript-bound keys, a MAC over the whole
  ClientHello with no cleartext epoch, and a replay cache — see `contracts/handshake-wire.md`. The flow therefore
  opens *ClientHello → ServerHello → application-data* — a valid TLS state-machine opening that defeats the
  "handshake-must-precede-app-data" heuristic that flagged the old app-data-first carrier
  (`dpi_middlebox::obfs_passes_tls_state_machine_dpi`; `dpi_middlebox::appdata_first_flow_is_blocked_by_state_machine`
  shows the censor genuinely enforces it). The 1216-byte PQ key_share blends with real X25519MLKEM768 TLS
  (Chrome/Cloudflare default since 2024).
- **Deferred — byte-exact fingerprint + full transcript:** this is *structurally* valid, not a
  byte-for-byte **uTLS fingerprint** of a specific browser (JA3/JA4 — extension order/GREASE/ALPN are a
  fixed, recognizable set; the cover SNI is a single `UMESH_SNI` default), and the transcript is not a full
  TLS 1.3 handshake (no real EncryptedExtensions/Certificate/Finished — a DPI doing full-transcript
  validation, or stealing a third-party ServerHello to evade the Aparecium distinguisher (dossier §1), would
  still distinguish it). Closing that needs a real TLS stack with ClientHello control (`craftls`/`boring`)
  and Go-Xray interop testing. Gated behind a future `reality` feature flag.

### 2.2 QUIC + Salamander datapath — *deferred*

- **Design:** add a `quinn`-based UDP carrier; apply Salamander obfuscation (BLAKE2b(salt‖PSK) keystream
  XORed over each QUIC packet) to defeat QUIC-Initial SNI classification; expose it as a `TransportKind::Quic`
  selected only when the profile allows UDP and a runtime UDP probe succeeds.
- **Rationale for deferral:** Salamander needs UDP-packet-level access that libp2p-quic does not expose;
  it is a separate `quinn` integration. Per the dossier QUIC/UDP is blocked in Iran and throttled in Russia,
  so it is an *opportunistic fast-path*, never the survivable path — lowest censorship value for the cost.
  The `Profile` model already encodes `udp_allowed` and TCP-fallback.

### 2.3 AmneziaWG transport — *deferred*

- **Design:** fork a pure-Rust WireGuard core (`boringtun`/`GotaTun`) and add AmneziaWG 2.0 obfuscation
  (randomized junk packets `Jc`/`Jmin`/`Jmax`, per-packet magic-header ranges `H1`–`H4`, init padding `S1`/`S2`).
- **Rationale for deferral:** requires vendoring + maintaining a WireGuard implementation; AmneziaWG only buys
  ~30–40% against TSPU and dies under UDP blocking (dossier §2), so it is a secondary carrier. Additive behind
  the transport seam.

### 2.4 Local-RF blackout tier — *deferred (hardware)*

- **Design:** a `TransportKind::LocalRf` over BLE / Wi-Fi-Aware / LoRa (`btleplug` et al.) for store-and-forward
  when egress reaches zero (Iran-style total shutdown).
- **Rationale for deferral:** intrinsically needs radio hardware and platform peripheral/advertise roles; it
  cannot be implemented or tested in a software-only environment. The transport abstraction does not preclude it
  (constitution / spec assumption).

## 3. Summary table

| Item | Status | Where |
|---|---|---|
| Hybrid-PQ confidentiality (data path) | ✅ implemented + tested | `umesh-crypto::kem`, obfs handshake |
| Hybrid-PQ libp2p Noise upgrade | 📐 resolved by design (not needed for HNDL; optional DiD) | §1 |
| REALITY active-probe resistance (fallback proxy) | ✅ implemented + tested | `ProbeResponse::Fallback` |
| TLS 1.3 ClientHello mimicry (state-machine DPI) | ✅ implemented + tested | `umesh-obfs::tls`, §2.1 |
| REALITY byte-exact uTLS fingerprint + full transcript | 📐 designed; needs TLS-fingerprint stack | §2.1 |
| QUIC + Salamander | 📐 designed; needs `quinn` UDP access | §2.2 |
| AmneziaWG | 📐 designed; needs WireGuard core | §2.3 |
| Local-RF blackout tier | 📐 designed; needs radio hardware | §2.4 |
| NAT relay/hole-punch | ✅ behaviours wired; connection tested; reservation deployment-validated | `tests/nat_relay.rs` |

- **Deferred — identity proof-of-work for gossip senders.** Replay protection keeps bounded state per
  sender, and identities are free, so a sustained flood of fresh identities can overflow the exact floor
  table; floors then fold into 4 096 hashed buckets (never dropped, so replays stay closed) and senders
  sharing a poisoned bucket may wait up to `MAX_FUTURE_MS` (30 s). Requiring a PoW-bound sender key
  (`umesh-crypto::pow`, already implemented and domain-separated) would price identities and close this
  residual DoS; it is a wire/identity change and is left for a later release.

