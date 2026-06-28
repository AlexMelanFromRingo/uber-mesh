# uber-mesh — Technical Research Dossier

> Compiled 2026-06-28 from a 14-agent web-research workflow (7 topic finders + 7 adversarial
> fact-checkers, 192 web fetches). Every version/claim below was independently verified mid-2026.
> This dossier is the technical rationale behind the constitution, spec, and plan.

## 1. Mission & threat model

uber-mesh is a **decentralized, censorship-resistant P2P mesh** built on modern, standardized,
audited-where-possible cryptography. The defining requirement is **reachability under hostile
DPI** — specifically Russia's TSPU/Roskomnadzor and Iran's IRGFW — degrading gracefully toward
total-blackout conditions.

### Adversary capabilities (verified, 2024–2026)

- **Fully-encrypted / high-entropy classification.** China's GFW pioneered passive popcount/entropy
  heuristics (USENIX'23 "Ex1–Ex5"); Russia's TSPU and Iran ramped equivalent protocol-type blocking
  through 2023–2025. *Plain* Shadowsocks/VMess/obfs4/WireGuard are reliably flagged. **⇒ never ship a
  raw random-looking transport without popcount/entropy mitigation.**
- **Active probing.** Unauthenticated connections to a suspected proxy are probed; servers that answer
  abnormally (or with silence on :443) get burned. **⇒ probe-resistant auth is mandatory** — either
  cryptographic silence (obfs4 model) or transparent fallback-proxy to a real site (REALITY model).
- **SNI / QUIC-Initial inspection.** SNI is extracted from TLS *and* from the QUIC Initial packet;
  unobfuscated Hysteria2/TUIC are identified within ~30 s on some China routes. Russia TSPU drops
  QUIC v1 on :443 (payload ≥1001 B; rule live since Mar 2022). Russia (early 2026) drops ClientHellos
  carrying **both ECH and SNI** ⇒ naive ECH camouflage is itself a fingerprint.
- **TLS-in-TLS detection.** Record-size/timing signature of nested TLS. Mitigated by XTLS-Vision-style
  inner-stream splicing.
- **Russia 15–20 KB / ~25-packet TCP freeze** to foreign-DC IPs: a flow to a non-whitelisted foreign IP
  is throttled/frozen after ~25 packets *either direction* (net4people #490). Multiplexing **increases**
  per-connection volume ⇒ can trigger the freeze *sooner*. Real fix = clean/CDN/residential IP placement
  + connection rotation, not blind mux.
- **Iran UDP/QUIC blackouts & protocol whitelisting.** Jun 2025 blackout preserved TCP/443 + TLS/WS but
  killed UDP; Jan 2026 whitelist-only drills. **⇒ QUIC is opportunistic-only; TCP/443-over-TLS-camouflage
  is the survivable fallback; plan a local-RF tier for total blackout.**

### Distinguisher watch (raises the bar for our own impl)

- **Aparecium (ban6cat6, Jun 2025)** published a passive/semi-active distinguisher for **both ShadowTLS v3
  and REALITY**: they mishandle TLS 1.3 **post-handshake `NewSessionTicket`** when mimicking OpenSSL servers
  (Xray-core #4778). The "no passive distinguisher exists for REALITY" framing is now **false**. A from-scratch
  REALITY/ShadowTLS must relay the dest's post-handshake records verbatim, or pick a dest whose TLS stack
  doesn't emit tell-tale tickets. → concrete, testable acceptance criterion.
- ShadowTLS v3 has published ServerFinished-length + NewSessionTicket tells (Mar 2026) ⇒ situational fallback only.

## 2. Anti-censorship protocol landscape & decision

Three design camps:
1. **"Look like nothing"** (random/fully-encrypted): Shadowsocks-2022, obfs4, Hysteria-Salamander, AmneziaWG.
   Now actively entropy-classified → needs popcount mitigation.
2. **"Look like real TLS"** (mimicry): VLESS+TLS+uTLS, NaiveProxy, Cloak. Generic rustls ClientHello is
   itself a fingerprint → needs uTLS-grade parroting.
3. **"Borrow a real handshake"**: **REALITY** (steals a genuine third-party TLS handshake; auth smuggled in
   the ClientHello SessionID — first **16 bytes of the 32-byte** SessionID are AES-GCM-encrypted under an
   X25519-ECDH-derived key, HKDF info `"REALITY"`, ClientHello.Random as salt/AAD; temp ed25519 cert whose
   signature field is overwritten with HMAC-SHA512(AuthKey, pubkey); unauthenticated probes are transparently
   reverse-proxied to a real `dest` site). **Strongest mainstream design** (~98–99.5% survival) but with the
   Aparecium caveat above. Modern REALITY (2025–26) also negotiates **hybrid X25519+ML-KEM-768 + ML-DSA-65**.

### Decision for uber-mesh

- **Resilience comes from agility, not one unbreakable protocol.** Ship transports behind a single pluggable
  `ObfsTransport` trait and select per **environment profile** (`Open` / `ModerateDPI` / `AggressiveDPI-RU-TSPU` /
  `Shutdown-IR`). This is the load-bearing design decision.
- **Layered stack (composable, each layer independently toggleable):**
  - L0 carrier: TCP/443 (survivable) or UDP/QUIC (opportunistic fast-path).
  - L1 handshake/auth + camouflage: obfs4-style MAC-gate (silence) **or** REALITY/ShadowTLS TLS-mimic (fallback-to-site).
  - L2 record/framing crypto (AEAD, no cleartext header).
  - L3 traffic shaping: padding policy + inter-arrival-time jitter + optional decoy/cover, as a `Conn` wrapper.
- **Ship order by maturity:** (1) pure-Rust fully-encrypted obfs transport **with popcount/entropy mitigation +
  shaping** (all primitives exist, conformance-testable); (2) REALITY-compatible **client** (craftls/boring);
  (3) TLS-mimic **server** (ShadowTLS or Go REALITY sidecar until native Rust server is viable); (4) optional
  QUIC/Hysteria-Salamander UDP path.
- **uTLS gap (key risk):** pure-Rust `rustls` cannot reorder ClientHello extensions (issues #1421/#1932/#2498).
  Options: `craftls` (rustls fork, ClientHello fingerprints, **experimental/unaudited**) or `boring` (BoringSSL,
  vendored C, Chrome-accurate JA3/JA4; conflicts with `openssl-sys`). `wreq` is a higher-adoption reference for
  boring-based fingerprints. **Decision: keep a pure-Rust default; gate uTLS-grade mimicry behind a feature flag,
  start with `craftls`, allow a `boring`/Go-sidecar escape hatch.**
- **Avoid as primaries:** plain fully-encrypted protocols, ShadowTLS v3, classic CDN domain-fronting (broadly disabled).

## 3. Cryptography stack (verified crate manifest, mid-2026)

**Principle: hybrid, never PQ-only.** A flaw in an unaudited PQ impl must not by itself break a session.

| Concern | Crate | Version | Status |
|---|---|---|---|
| PQ KEM (FIPS 203) | `ml-kem` (RustCrypto) | 0.3.2 (May 2026) | ACVP/KAT-tested, **unaudited** (explicit warning) |
| Hybrid KEM combiner | `x-wing` (X25519+ML-KEM-768) | RFC-track | preferred over ad-hoc KDF (IND-CCA binding) |
| Classical ECDH | `x25519-dalek` | 2.0.1 | mature; require transitive `curve25519-dalek ≥ 4.1.3` (RUSTSEC-2024-0344) |
| Signatures / identity | `ed25519-dalek` | 2.2.0 | mature; avoid v1.x (RUSTSEC-2022-0093); 3.0-pre exists |
| Hash / CID / KDF / MAC | `blake3` | 1.8.5 | official, SIMD, broadly deployed |
| AEAD data channel | `chacha20poly1305` | 0.11.0 (Jun 28 2026) | NCC-audited; use **XChaCha20** (192-bit nonce) to avoid nonce coordination |
| PQ Noise framework | `clatter` | 2.2.0 (Jan 2026) | hybrid X25519+ML-KEM Noise, no_std, **unaudited** |
| Classical Noise (fallback) | `snow` | 0.9.x / 0.10 | mature; 0.10 has limited Kyber1024 PQ via pqcrypto (C FFI) |
| Verified ML-KEM (optional) | `libcrux-ml-kem` | pre-1.0 | formally verified (hax/F*); pre-1.0 churn; pin a commit |
| Serialization | `bincode` | 3.0.0 (Dec 2025) | use **only inside the encrypted channel**, with explicit decode limits |
| Merkle proofs | `rs-merkle` | current | most complete; no_std-capable; unaudited |
| Verified streaming | `bao-tree` / `iroh-blobs` | 0.9x | BLAKE3 verified streaming (outboard); production in iroh |
| Set reconciliation | `negentropy` (rust-nostr) | current | range-based, O(log n) RTT, battle-tested at scale |
| Secret hygiene | `zeroize`, `subtle` | current | constant-time compare, zeroization |

**Design rules:**
- Session key = X-Wing-style combiner; KDF via `blake3::derive_key` with **per-use domain separation**
  (distinct labels for CIDs, message-ids, PoW, handshake, AEAD keys).
- Split architecture (Rosenpass pattern): PQ key agreement is a distinct handshake outputting a symmetric key
  for the fast data transport, so obfuscation can evolve independently of crypto.
- Treat all PQ crates as pre-audit: pin exact versions, run `cargo-audit`/`cargo-deny` in CI, keep the classical
  half authoritative until an audited ML-KEM ships.

## 4. libp2p mesh core (verified)

- **`libp2p` 0.56.0 umbrella crate, Tokio** (async-std removed, MSRV 1.83). Pin through the umbrella to keep
  member-crate versions coherent (gossipsub 0.49.4, relay 0.21.1, dcutr 0.14.1 have post-0.56 patches).
- **Behaviours:** `gossipsub` (v1.2 IDONTWANT, `ValidationMode::Strict` signed messages, full P1–P7 peer scoring,
  flood-publish, opportunistic graft, PX), `kad` with a **private protocol name** `/uber-mesh/kad/1.0.0`
  (not enumerable via public IPFS DHT) + `rendezvous` for fast bootstrap, `identify`, `ping`, `autonat` v2,
  `relay` (client+server, limited-resource), `dcutr`, `connection_limits`.
- **Custom obfs transport** plugs in as a `Transport` wrapper: `TCP → Obfs → .upgrade().authenticate(noise).multiplex(yamux)`.
  **Obfs must sit BELOW Noise** to hide Noise's fixed-size XX handshake fingerprint from DPI. Use `Transport::and_then`
  for handshake-bearing obfs, `Transport::map` for stateless mangling.
- **PQ gap:** `libp2p-noise` is X25519/ChaChaPoly/SHA256 only — no PQ. A hybrid PQ security upgrade must be a
  **custom `ConnectionUpgrade`** (reuse `ml-kem` + `clatter`), registered via `.authenticate()`; keep stock noise as
  interop fallback. (`rustls` supports `X25519MLKEM768` since 0.23.22 as a reference.)

## 5. NAT traversal (verified)

- **Core trio:** AutoNAT v2 (reachability) + Circuit Relay v2 (always-available relay + DCUtR signaling) + DCUtR
  (coordinated hole punch). Only decentralized stack with proven **~70% in-the-wild** success (arXiv 2510.27500;
  TCP == QUIC, 97.6% first-attempt).
- **Relay-first, direct-upgrade-second.** Every session must start and stay on a relay; direct connection is an
  opportunistic upgrade, never a precondition (CGNAT/symmetric NAT + UDP blackouts force relaying).
- **Hole-punch on BOTH TCP and QUIC**; TCP is the only one surviving UDP-blocking regimes. Detect UDP availability at
  runtime and fail over fast. Add CONNECTION_REVERSAL + UPnP/PCP (cheap wins); **skip symmetric-NAT port prediction**
  initially (libp2p deliberately doesn't; relay instead). `ant-quic` (draft-seemann) is experimental, PQ-only, and its
  "near-100% without infra" claims are vendor-self-reported — not a foundation.

## 6. Mesh integrity & anti-abuse (verified)

- **Self-certifying content:** every object/message id = `BLAKE3(content)`; `PeerID = BLAKE3(pubkey)`. Use bao-tree
  outboard encoding so even untrusted peers can serve incrementally-verified chunks.
- **Signed gossip:** Ed25519 over `(topic, payload, sender_pubkey, seqno, timestamp)`; require valid signature to
  accept *or* re-propagate (StrictSign); `verify_strict` for first-seen keys.
- **Replay protection:** monotonic per-sender seqno bound into the signature + out-of-window timestamp rejection +
  bounded LRU dedup on message-ids (gossipsub dedup alone does NOT survive cache eviction — enforce monotonicity at app level).
- **Sync:** range-based set reconciliation (negentropy / iroh-docs model), sorted by BLAKE3 id — O(log n) RTT, O(diff)
  bytes, stateless responder. Merkle-DAG only if DAG-shaped versioned content is needed.
- **Eclipse/Sybil hardening:** S/Kademlia (NodeID from pubkey) + static BLAKE3/Argon2 PoW NodeID gate (friction, **not**
  a hard barrier vs state adversaries) + disjoint lookup paths + D_out outbound quotas + IP-colocation penalties.
  2025 IPFS research: disjoint paths alone are necessary but **not sufficient** against active Sybil.
- **Forward secrecy:** long-term Ed25519 for auth only; per-link Noise XX/IK ephemeral X25519 session keys; epoch
  re-handshake / DH ratchet. Plan hybrid PQ ratchet migration (Signal SPQR, 2025).

## 7. Key risks / open questions carried into the plan

1. **uTLS fidelity in Rust** — is `craftls` enough for JA4 + active-probe checks, or is `boring` (C) / Go sidecar mandatory? → feature-gate; measure.
2. **No mature pure-Rust REALITY** (server especially) — port Xray-core semantics onto rustls/boring, or sidecar. Interop now needs PQ key-share handling.
3. **PQ crates unaudited** — hybrid keeps classical authoritative; re-pin before any release (ed25519/x25519 3.0 in RC Jun 2026).
4. **Russia 25-packet freeze** — clean-IP placement + connection rotation; do NOT blindly mux.
5. **Total blackout tier** — local RF (BLE/Wi-Fi-Aware/LoRa) is best-effort; platform-uneven. Justifies mesh-over-VPN.
6. **DPI survivability is empirical** — needs gfw.report-style measurement, not just design. Build active transport health-checks + auto-rotation.

## 8. What this session builds vs. defers

**Build now (pure-Rust, compiling, tested):** crypto core (hybrid X25519+ML-KEM-768 KEM, Ed25519 identity, BLAKE3
CID/KDF, XChaCha20-Poly1305 AEAD, Merkle tree, PoW), the `ObfsTransport` trait + a working fully-encrypted obfuscated
TCP transport with popcount/entropy mitigation + traffic-shaping middleware + environment profiles, libp2p
NetworkBehaviour wiring (gossipsub+kad+identify+autonat+relay+dcutr+ping) with signed gossip & scoring, config + CLI node.

**Defer (documented as tasks):** native REALITY client/server, AmneziaWG transport, QUIC+Salamander datapath, custom
hybrid-PQ libp2p security upgrade, set-reconciliation sync, local-RF blackout tier, browser (WebTransport) reach.
