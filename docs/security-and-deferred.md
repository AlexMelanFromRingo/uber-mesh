# uber-mesh — Security analysis & disposition of dependency-gated work

This document gives the security rationale for the post-quantum posture and an honest disposition of
the remaining designed-but-not-built items. It is deliberately precise about what is implemented and
tested versus what is deferred and why.

## 1. Post-quantum posture — the requirement is met *by design*

**Claim: the mesh's data confidentiality is already hybrid post-quantum on every link.** *(Hop by hop: each
link is protected, but a peer that forwards gossip or serves content is an endpoint of its links and sees
what it relays — payload confidentiality against such peers is §4, sealed topics.)*

Every byte the mesh carries travels inside the **obfs layer's AEAD record stream**, whose keys come from
the hybrid **X25519 + ML-KEM-768** handshake (`umesh-crypto::kem`, X-Wing (draft-connolly-cfrg-xwing-kem-11, KAT-verified); tested in
`crates/umesh-crypto/tests/xwing_kat.rs` and `kem.rs`). Concretely, for the gossip mesh the layering is:

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

### 2.1 Native REALITY (full Xray interop) — *delivered except Xray wire interop*

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
- **Delivered — exact Chrome fingerprint (wire v2.1):** the ClientHello is pinned to desktop Chrome stable 133+
  (BoringSSL defaults: GREASE placement, `X25519MLKEM768` first, ALPS `0x44cd`, GREASE-ECH payload sizes, no
  `padding`, per-connection extension permutation). Its JA4 is exactly Chrome's
  `t13d1516h2_8daaf6152771_d8a2da3f94cd` for every generated hello and every field is checked byte-for-byte
  (`umesh-obfs/tests/fingerprint.rs`, with an independent JA4/JA3 calculator). JA3 varies per connection, as
  Chrome's does. Clients send the listener's cover domain as SNI (`ClientConfig::cover_domain`).
- **Delivered — cover-shaped server flight (REALITY-style "know your cover"):** a listener in cover mode
  (`ProbeResponse::Cover` / `ListenerConfig::with_cover`) learns its cover site's real TLS 1.3 flight layout by
  connecting with our own Chrome ClientHello at startup and every 30 min ± 5 min (last good profile kept on
  failure) and reproduces it — ServerHello suite/group/extension order (hence length), CCS presence, every
  encrypted-record size — with the key confirmation hidden in the tail of the final record. A censor that
  validates the flight against the cover site, or replays a captured hello (which the bridge proxies to the real
  site), sees the same layout (`umesh-obfs/tests/cover_mimicry.rs`). Probes still reach the genuine site and
  its genuine certificate.
- **Not a goal — surviving a TLS-terminating MITM:** a middlebox with a CA the client trusts must send its own
  ClientHello, which fails the gate and is proxied to the real cover; our client finds no server confirmation and
  fails closed without sending anything after its hello. No tunnel survives a full MITM; the guarantee is
  **non-identification of the bridge**, not reachability (`contracts/handshake-wire.md`, "What a censor can and
  cannot do now").
- **Remaining (honest):** one Chrome generation/platform only (template must track Chrome stable); the cover
  domain does not resolve to the bridge IP (inherent to REALITY-style designs); one layout sample per refresh, so
  real per-connection variance (ECDSA signature length, multiple backends) is not reproduced; profile learning is
  unauthenticated (an adversary on the bridge's uplink can poison it); no NewSessionTicket records. Full Xray
  REALITY interop would still need a real TLS stack and Go-Xray conformance tests (constitution Principle V); it
  remains out of scope.

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
| Hybrid-PQ confidentiality (data path, per link) | ✅ implemented + tested | `umesh-crypto::kem`, obfs handshake |
| End-to-end payload confidentiality (sealed topics + encrypted blobs) | ✅ implemented + tested (0.10) | `umesh-p2p::sealed`, `tests/sealed_topics.rs`, §4 |
| Forward secrecy for sealed topics (ratchet / MLS) | 📐 deferred — static topic key, epoch keys are separation only | §4 |
| Topic-name / size / timing hiding from forwarders | 📐 deferred (metadata visible by design) | §4 |
| Hybrid-PQ libp2p Noise upgrade | 📐 resolved by design (not needed for HNDL; optional DiD) | §1 |
| REALITY active-probe resistance (fallback proxy) | ✅ implemented + tested | `ProbeResponse::Fallback` |
| TLS 1.3 ClientHello mimicry (state-machine DPI) | ✅ implemented + tested | `umesh-obfs::tls`, §2.1 |
| Exact Chrome 133+ ClientHello (JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`) | ✅ implemented + tested | `umesh-obfs::tls`, `tests/fingerprint.rs` |
| Cover-shaped server flight (learned cover profile, REALITY-style) | ✅ implemented + tested | `umesh-obfs::cover`, `tests/cover_mimicry.rs` |
| Real TLS transcript / survive a TLS-terminating MITM | ⛔ not a goal (fails closed; bridge not identified) | §2.1 |
| Xray REALITY wire interop | 📐 out of scope; needs a real TLS stack + Go-Xray vectors | §2.1 |
| QUIC + Salamander | 📐 designed; needs `quinn` UDP access | §2.2 |
| AmneziaWG | 📐 designed; needs WireGuard core | §2.3 |
| Local-RF blackout tier | 📐 designed; needs radio hardware | §2.4 |
| NAT relay/hole-punch | ✅ behaviours wired; connection tested; reservation deployment-validated | `tests/nat_relay.rs` |
| Identity PoW for gossip senders (24 bits) | ✅ implemented + tested (0.10.0); friction, not a barrier | `umesh-crypto::pow`, `umesh-p2p::gossip`, below |

- **Delivered (0.10.0) — identity proof-of-work for gossip senders.** *(Was deferred in 0.9.0.)* Replay
  protection keeps bounded state per sender, and identities used to be free, so a sustained flood of fresh
  identities (≈135 new identities/s for 10 min ≈ 81 000 identities) could overflow the exact floor table;
  floors then fold into 4 096 hashed buckets (never dropped, so replays stay closed) and senders sharing a
  poisoned bucket may wait up to `MAX_FUTURE_MS` (30 s).
  - **Construction.** Every gossip message (format **v2**) carries `pow_nonce`;
    `BLAKE3-derive_key("uber-mesh v1 identity pow", sender_key ‖ u64_le(nonce))` must have
    ≥ `MIN_SENDER_POW_BITS` = **24** leading zero bits (`umesh-crypto::pow::{identity_digest,
    mine_identity, verify_identity}`). Hash-based nonce PoW bound to the public key — not key grinding — so
    honest mining is a plain parallel nonce search and verification is one BLAKE3 call. The nonce is in
    the signing transcript (no swapping/malleability) and the key is inside the hashed input (a nonce is
    worthless for any other key). Insufficient work is provably invalid ⇒ gossipsub `Reject` (checked
    before the signature and before any replay state); v1 messages are `Ignore`d.
  - **Honest cost (measured, release build, AMD Ryzen 5 5500, 6C/12T).** ≈10 M hashes/s per core while
    mining ⇒ 2^24 ≈ 16.8 M hashes expected ≈ **1.7 s on one core, ≈0.25 s on all 12 threads** (observed
    `uber-mesh init`: 0.6–1.1 s wall including unlucky nonces of 2–3× the expectation). A ~1 M hash/s
    embedded core needs ≈17 s. Paid once, at `uber-mesh init`; keystores from before 0.10 get their nonce
    mined automatically on the first `mesh` start (sidecar `identity.pow`, `0600`, atomically written,
    re-verified against the key on every load). Reproduce with
    `cargo test --release -p umesh-crypto --lib identity_mining_benchmark -- --ignored --nocapture`.
  - **Attacker cost of the flood above.** Mined live: 135 × 2^24 ≈ **2.3·10⁹ hashes/s** sustained for
    10 min, i.e. ≈ **225 CPU cores** at the measured rate (vs. zero before). **Caveat — precomputation and
    reuse:** nonces do not expire, so the ≈81 000 identities can be mined in advance
    (81 000 × 2^24 ≈ 1.4·10¹² hashes ≈ **38 CPU core-hours**, or minutes to hours on GPUs running BLAKE3
    at GH/s rates) and *reused* for later floods once their replay state has expired (`2 × skew` = 10 min
    after last use). So identity PoW is **friction, not a barrier** (constitution §Sybil): it turns a free
    attack into one that needs a deliberate, sizeable compute investment and caps the flood rate of an
    attacker who did not stockpile, while the structural defenses (floors never dropped ⇒ no replay;
    keyed buckets ⇒ no targeting; ≤ 30 s delay bound; Reject + peer scoring for PoW-less traffic) bound
    the impact of one who did.
  - **Still open (designed, not built).** (a) *Epoch-bound PoW* — mine over `(sender_key, epoch)` (the
    existing `pow::challenge(pubkey, epoch)` helper) so stockpiles expire; it multiplies the attacker's
    cost by the number of epochs flooded but makes honest nodes re-mine every epoch and needs an
    epoch-transition grace window, so it was not adopted in this release. (b) Raising
    `MIN_SENDER_POW_BITS` (each +1 doubles both costs) — a network-wide flag day with a format-version
    bump. (c) A memory-hard PoW (e.g. Argon2id) would blunt GPU/ASIC advantage but is a new dependency
    and makes verification costly; rejected for now.

## 4. End-to-end payload confidentiality — sealed topics (0.10)

**Gap closed.** The spec's edge case *"a relay or content-serving peer MUST be unable to read or tamper with
payloads it forwards"* was met for tampering (Ed25519 signatures, self-certifying `Cid`s) but not for
reading: gossip payloads were only signed, so every forwarding mesh peer read them, and blobs were stored and
served in cleartext. Link encryption (§1) does not help — those peers are link endpoints.

**Construction** (`umesh-p2p::sealed`, contract: `message-wire.md` "Sealed messages (v3)"). A topic may have a
32-byte topic key, distributed out of band like the bridge PSK (`keys new-topic-key`, `--topic-key-file`,
`UMESH_TOPIC_KEY`, `config.toml [topic_keys]` — `0600` enforced). Its messages are format v3: payload =
`nonce(24) ‖ XChaCha20-Poly1305` under `K_epoch = derive_key("uber-mesh v1 topic epoch key",
derive_key("uber-mesh v1 topic key", topic_key ‖ topic) ‖ epoch)`, random 192-bit nonce, AAD =
`(version, topic, sender, seqno, timestamp)`. The signature and `payload_hash` cover the ciphertext, so every
peer still validates identity, PoW, signature and replay state and forwards without the key; only key holders
deliver. Blobs shared in a sealed topic are encrypted under a fresh random content key, `Cid` = BLAKE3 over the
ciphertext, and `(cid, content_key)` rides inside a sealed message. Only standard primitives (XChaCha20-Poly1305,
BLAKE3 `derive_key`) composed in the standard encrypt-then-sign way (constitution Principle I).

**What each party sees.**

| party | sees | cannot see |
|---|---|---|
| Circuit Relay v2 relay | both endpoints' libp2p PeerIds, timing, volume; **only Noise ciphertext** (the relayed connection is Noise-secured end to end) | anything inside the connection |
| gossip forwarder without the topic key | topic name, sender id / key / PoW nonce, publisher libp2p PeerId, seqno, timestamp, ciphertext size (plaintext + 41 B; a blob announcement is a fixed 105 B), timing, previous hop | content; blob `Cid`s and keys announced in the topic |
| serving / mirroring peer | blob ciphertext + `Cid` + size (plaintext + 40 B); who fetches it, when | content |
| topic member | everything in the topic | — |

**Tests.** `crates/umesh-p2p/tests/sealed_topics.rs`: a 4-node mesh where the members are connected only to a
key-less forwarder — the member receives the sealed message, the forwarder and a wrong-key node deliver
nothing, a public message injected into the sealed topic is refused (downgrade), and a public topic is
delivered to all unchanged; a sealed blob is mirrored and served by a key-less peer whose store provably holds
only ciphertext and is decrypted by a member connected only to that peer; a wrong content key yields
`BlobUnavailable`. Unit tests (`sealed.rs`): ciphertext moved to another topic, seqno, timestamp or sender fails
AEAD; wrong key fails; public↔sealed version flip breaks the signature; epoch boundary; strict inner parser.
Fuzz target `fuzz/fuzz_targets/sealed_parse.rs`.

**Limits (honest).**
- **No forward secrecy, no post-compromise security.** The topic key is static; `K_epoch` gives per-day key
  *separation* (and needs only the current + previous epoch at a receiver, since the epoch comes from the
  signed timestamp), but anyone who obtains the topic key — or a member's disk — derives every past and
  future epoch key. A one-way hash-chain ratchet (`K_{e+1} = H(K_e)`, deleting `K_e`, persisting the ratcheted
  key in place of the root) would give FS against later compromise but needs on-disk key rewriting and a
  join procedure for late members; a real group key agreement (MLS, RFC 9420) would add post-compromise
  security and member removal. Both are **deferred**; the wire format does not change for the former (the
  epoch is still derived from the timestamp).
- **Membership = key possession.** No revocation: removing a member means distributing a new key out of band
  (and, for the CLI, restarting with it). A member can read and re-share everything in the topic; per-sender
  authenticity still holds (members cannot forge each other's signatures).
- **Metadata is visible to forwarders:** topic names, sender identities, sizes and timing (no padding,
  no hashed topic names). Hiding them is deferred; the obfs layer only hides them from the network.
- **Public topics are still public.** A topic without a key behaves exactly as before; its payloads are
  readable by every forwarder. Members holding a key refuse public messages on that topic (no silent
  downgrade).
- **Mixed versions.** 0.10 is a flag day anyway (obfs wire, message v2 with identity PoW), so every
  node of a cohort runs a version that forwards v3.
