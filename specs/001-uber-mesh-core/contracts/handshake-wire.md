# Contract: obfs-tcp handshake & hybrid KEM wire format (obfs wire v2.1)

Wire format of the pure-Rust **obfs-tcp** transport (`umesh-obfs::{tls, handshake, cover, wire}`). Versioned;
breaking it is a MAJOR change. Parsers MUST be fuzzed (constitution Principle V): `fuzz/fuzz_targets/{client_hello,
server_hello, server_gate, obfs_record}.rs` (`server_hello` also covers the cover-flight parser).

> **Version history**
>
> | wire | release | summary |
> |---|---|---|
> | v1 | ≤ 0.8.x | ClientHello/ServerHello with `session_id = epoch_le(8) ‖ MAC(key_share, epoch)[..24]`; keys from the KEM secret only; no key confirmation; app data straight after ServerHello. |
> | v2 | 0.9.0 | **Wire-breaking** — v1 and v2 peers cannot interoperate (a v2 server treats a v1 hello as a probe). Fixes from the 2026-11 audit: the server is now authenticated (PSK in the key schedule + mutual key confirmation), the session_id has no cleartext epoch and MACs the whole ClientHello, replays are rejected, the fallback forwards every byte, and the hello follows a Chrome template instead of a static shape. |
> | **v2.1** | **next release** | This document. ClientHello unchanged byte-for-byte (now pinned and tested as Chrome 133+, JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`). **Cover mimicry:** a server in cover mode learns its cover site's real TLS 1.3 flight layout and reproduces it (ServerHello suite/group/extension order, CCS presence, every encrypted record size); the client accepts any layout within bounds and finds the confirmation by trial-opening record tails; a plain-`x25519` ServerHello carries the ML-KEM ciphertext masked in the encrypted flight; the client Finished is sized for the selected suite. |
>
> **Migration (v1 → v2):** all nodes of a PSK cohort must upgrade together (flag day). There is no v1 compatibility
> mode: a downgrade path would re-introduce the unauthenticated-server defect.
>
> **Compatibility (v2 → v2.1):** a v2.1 client talks to a v2 (0.9.0) server (it accepts the v2 layout). A v2
> client talks to a v2.1 server **only while that server uses the default layout** (no cover mode, or no profile
> learned yet): the v2 client checks the PSK-derived shape exactly and rejects a cover-shaped flight. Upgrade all
> clients of a cohort before enabling cover mode on its listeners.

All multi-byte TLS fields are big-endian (as in TLS); `epoch_le` is little-endian. `‖` is concatenation.
`KDF(label, x)` = `BLAKE3.derive_key(label, x)`; `MAC(k, x)` = `BLAKE3.keyed_hash(k, x)`;
`AEAD` = XChaCha20-Poly1305 with a random 24-byte nonce, output `nonce ‖ ct ‖ tag`.

## Flow

```
C → S   ClientHello                       record 0x16 0x0301 (Chrome 133+ exact; SNI = cover domain)
S → C   ServerHello                       record 0x16 0x0303, shaped like the cover site's (suite, group,
                                          extension order ⇒ identical length)
        [ChangeCipherSpec]                14 03 03 00 01 01 — iff the cover site sends one
        "encrypted handshake"             17 03 03 … records with exactly the cover site's sizes
                                          (≤ 8 records, ≤ 32 KiB); last 53 B of the last record =
                                          server confirmation; for an x25519 ServerHello the first
                                          1088 B of the flight = masked ML-KEM ciphertext
C → S   ChangeCipherSpec                  14 03 03 00 01 01
        "Finished"                        17 03 03 ‖ len (53, or 69 for suite 1302) ‖ random pad ‖
                                          client confirmation (53 B)
C ⇄ S   application data                  17 03 03 … (SecureStream / ObfsByteStream records)
```

Without cover mode (or before the first profile is learned) the server uses the **default layout**: ServerHello
`1301`/`X25519MLKEM768`/OpenSSL order, CCS, and the PSK-derived records of v2 (below).

The client sends **nothing** after its ClientHello until the server confirmation verifies; the server returns a
session only after the client confirmation verifies.

## Labels (domain separation)

| use | label |
|---|---|
| PSK → gate MAC key | `uber-mesh v2 obfs psk gate-key` |
| PSK → key-schedule input | `uber-mesh v2 obfs psk key-schedule` |
| PSK → default flight layout (public sizes) | `uber-mesh v2 obfs psk flight-shape` |
| (PSK key-schedule key ‖ H(CH ‖ SH)) → mask for an in-flight ML-KEM ciphertext | `uber-mesh v2 obfs flight kem-ct mask` |
| transcript hash | `uber-mesh v2 obfs transcript` |
| master secret | `uber-mesh v2 obfs master` |
| server confirmation key | `uber-mesh v2 obfs server confirm` |
| client confirmation key | `uber-mesh v2 obfs client confirm` |
| traffic key c→s | `uber-mesh v2 obfs traffic c2s` |
| traffic key s→c | `uber-mesh v2 obfs traffic s2c` |
| gate MAC context (in the MAC input) | `uber-mesh v2 obfs gate` |
| server confirmation AAD prefix | `uber-mesh v2 obfs server finished` |
| client confirmation AAD prefix | `uber-mesh v2 obfs client finished` |

The hybrid combiner keeps its v1 label (`uber-mesh v1 xwing`, `umesh-crypto::kem`). The v1 labels
`uber-mesh v1 obfs-mac` and `uber-mesh v1 traffic c2s/s2c` are no longer used by the obfs handshake.

## ClientHello (desktop Chrome stable 133+, exact)

The default first-connection ClientHello of desktop Chrome 133 and later (BoringSSL, AES-NI; no resumption ⇒
no `pre_shared_key`/`early_data`; > 512 B ⇒ no `padding`). **JA4 = `t13d1516h2_8daaf6152771_d8a2da3f94cd`**
(Chrome 133+'s; `t13i1515h2_…` when the SNI is omitted for an IP, as Chrome does), asserted for every generated
hello by `umesh-obfs/tests/fingerprint.rs`, which recomputes JA4 independently and checks every extension body
byte-for-byte. JA3 changes per connection exactly as Chrome's does (extension permutation); its order-normalised
form is `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0`.
The pinned template with its source note lives in `umesh-obfs/src/tls.rs`; when Chrome stable changes its hello,
update template, `CHROME_JA4`, the KAT and this section together.

A TLS 1.3 ClientHello in one handshake record, record version `0x0301`, `legacy_version = 0x0303`, 32-byte
random, **32-byte `legacy_session_id` = gate tag** (below), compression `[null]`.

- **cipher_suites** (16): `GREASE, 1301, 1302, 1303, c02b, c02f, c02c, c030, cca9, cca8, c013, c014, 009c, 009d,
  002f, 0035`.
- **extensions**: a GREASE extension (empty) first, a different GREASE extension (body `00`) last, and between
  them the following, **shuffled uniformly per connection** (Chrome's permutation):

| ext | body |
|---|---|
| `server_name` (0000) | the listener's **cover domain** (`ClientConfig::cover_domain`, env `UMESH_COVER_DOMAIN`) — the same name the server learns its profile with; if unset, a name chosen per connection from `ClientConfig::cover_snis` / `UMESH_SNI=a,b,c` / a built-in list (**weaker mimicry**: the SNI then need not be the site whose flight the server imitates, and a replayed hello reaches the cover with a different name); omitted if invalid / an IP |
| `extended_master_secret` (0017) | empty |
| `renegotiation_info` (ff01) | `00` |
| `supported_groups` (000a) | `GREASE, 11ec (X25519MLKEM768), 001d, 0017, 0018` |
| `ec_point_formats` (000b) | `01 00` |
| `session_ticket` (0023) | empty |
| `application_layer_protocol_negotiation` (0010) | `h2`, `http/1.1` |
| `status_request` (0005) | `01 0000 0000` |
| `signature_algorithms` (000d) | `0403 0804 0401 0503 0805 0501 0806 0601` |
| `signed_certificate_timestamp` (0012) | empty |
| `key_share` (0033) | `GREASE` (1 byte `00`), **`11ec`: ML-KEM-768 ek (1184) ‖ X25519 pub (32) = 1216 B**, `001d`: 32 B X25519-shaped decoy (random, top bit clear) |
| `psk_key_exchange_modes` (002d) | `01 01` |
| `supported_versions` (002b) | `GREASE, 0304, 0303` |
| `compress_certificate` (001b) | `02 0002` (brotli) |
| `application_settings` (44cd) | `h2` |
| `encrypted_client_hello` (fe0d) | GREASE ECH: outer, HKDF-SHA256/AES-128-GCM, random config_id, 32 B random enc, random payload of 144/176/208/240 B |

GREASE values (RFC 8701) for cipher, group (also used for the GREASE key share), version and the two extensions
are drawn independently per connection; the two GREASE extensions always differ (BoringSSL rule). The `X25519MLKEM768` layouts are the IANA ones and carry
`umesh_crypto::kem`'s initiator/responder messages verbatim. Typical size: ~1.8–2.0 KB, varying per connection.

### Gate tag (`legacy_session_id`)

```
gate_key  = KDF("uber-mesh v2 obfs psk gate-key", psk)
epoch     = floor(unix_seconds / 60)
CH⁰       = the complete ClientHello record (header included) with the 32 session_id bytes set to 0
session_id = MAC(gate_key, "uber-mesh v2 obfs gate" ‖ epoch_le(8) ‖ CH⁰)        # all 32 bytes
```

The tag is a PRF output: no cleartext epoch, uniformly random-looking. It authenticates **every byte** of the
hello (random, SNI, GREASE, key shares, extension order), so nothing is malleable.

### Server gate (in order; any failure ⇒ probe response, nothing has been sent yet)

1. **Plausibility while reading** (`wire::classify_client_hello_prefix`): first bytes must be `16 03 01|03`, record
   length in `[40, 16384]`, handshake type `01`, handshake length = record length − 4. The server never reads past
   the first record. The first byte that breaks this ends the read **immediately**. Overall read deadline 10 s.
2. **Strict parse** (`tls::parse_client_hello`): exact length agreement at record / handshake / vector level,
   `legacy_version 0303`, 32-byte session_id, null-only compression, no duplicate extensions or key-share groups,
   exactly one `11ec` share of 1216 B, valid SNI if present.
3. **MAC** recomputed for epochs `e−1, e, e+1` (server clock), compared in constant time (`subtle`).
4. **Replay cache**: the tag's first 16 bytes are inserted into a process-wide cache bucketed by the authenticated
   epoch; buckets older than `now − 1` are pruned; at most 65 536 tags per bucket (only PSK holders can insert;
   a full bucket fails closed). A tag already present ⇒ replay ⇒ probe response.

### Probe response

- `Silence`: drain ≤ 64 KiB for a random 50–400 ms, close; no reply.
- `Cover(CoverSite)`: identical to `Fallback(site.upstream)` for probes; additionally drives the server flight
  layout (below).
- `Fallback(host:port)`: connect to the cover upstream (5 s timeout; unreachable ⇒ silence), write **every byte read
  so far** verbatim, then `copy_bidirectional` until either side closes. A replayed or foreign ClientHello thus
  reaches the cover site intact and the prober completes a genuine TLS handshake with it.

## ServerHello + server flight

```
ServerHello: record 16 0303, legacy_version 0303, random(32), session_id = client's (echo),
             cipher_suite = profile suite ∈ {1301, 1302, 1303}, compression 00,
             extensions = exactly supported_versions(0304) and key_share, in the profile's order:
               group 11ec: ML-KEM-768 ct (1088) ‖ X25519 pub (32)        (record 1215 B)
               group 001d: X25519 pub (32)                                (record 127 B)
CCS:         14 03 03 00 01 01, iff profile.ccs
Flight:      one 17 03 03 record per profile.records[i], bodies random, except
               - group 001d: payload bytes [0, 1088) of the concatenated flight =
                 ct XOR mask, mask = PRF-counter(KDF("uber-mesh v2 obfs flight kem-ct mask",
                 psk_ks ‖ H(CH ‖ SH)))   (BLAKE3-keyed blocks over u32_le counters, truncated to 1088)
               - the last 53 bytes of the last record = server confirmation
```

The **profile** (`umesh-obfs::cover::CoverProfile`) is either

- **learned** (cover mode, `ProbeResponse::Cover`): the layout of the real cover site's answer to our own
  Chrome ClientHello — see *Cover profile* below; or
- the **default** (no cover mode / nothing learned yet): suite `1301`, group `11ec`, `supported_versions` first,
  CCS, and records from `KDF("uber-mesh v2 obfs psk flight-shape", psk)`: style A (BoringSSL-like) one record of
  `C` bytes, or style B (OpenSSL-like) `[EE 40–55, C − EE − CV − 53, CV (281 | 96–111), 53]`, `C ∈ [2500, 5000]`
  — exactly the v2 layout.

A profile is usable only if it **validates**: 1–8 records, each ≤ 16 640 B (2^14 + 256), total ≤ 32 KiB, last
record ≥ 53 B, suite ∈ {1301, 1302, 1303}, and for group `001d` total ≥ 1088 + 53. Learned profiles that do not
validate are discarded (the last good one stays).

### Client acceptance

The client knows nothing of the profile. After the ClientHello it requires, in order:

1. a ServerHello that parses strictly (above), echoes the session_id exactly, selects a suite Chrome offered and
   group `11ec` (1120 B share) or `001d` (32 B share);
2. optionally one CCS, byte-exact, directly after it;
3. `0x17` records, each ≤ 16 640 B, at most **8** and at most **32 KiB** in total. For group `11ec` the KEM
   finishes at once; for `001d` it finishes once the first 1088 flight bytes have arrived (unmask, decapsulate,
   transcript includes the ciphertext). After each record whose tail lies beyond the ciphertext, it **trial-opens
   the last 53 bytes** under the server-confirmation key (≤ 8 AEAD opens per handshake). The first record that
   opens to `0^13` ends the server flight.

Anything else — a malformed record, an oversized record, a 9th record, more than 32 KiB, EOF, or the handshake
timeout — fails the handshake **without the client having sent anything after its ClientHello**.

The client then sends CCS and a `0x17` record of `finished_record_len(suite)` bytes (53, or 69 for the SHA-384
suite `1302`): random padding ‖ client confirmation (53 B). The server requires CCS byte-exact, a `17 03 03`
record of exactly that length, and that its last 53 bytes open to `0^13`.

## Cover profile (learning, refresh, trust)

`CoverSite { upstream (host:port), domain }`, with `domain` defaulting to the upstream's host name. The learner
connects to `upstream`, sends **the same Chrome ClientHello an obfs client sends** with SNI = `domain`, a real
`X25519MLKEM768` share (fresh ML-KEM-768 key, so the site can encapsulate) and a random 32-byte session_id, then
reads: one handshake record (the ServerHello, ≤ 16 KiB), an optional CCS, and `0x17` records until the site goes
quiet for 1.5 s (it is waiting for our Finished), closes, or exceeds 8 records / 32 KiB; anything else (alert,
TLS 1.2 handshake records, HelloRetryRequest, another group) fails. The capture is parsed by the pure, fuzzed
`CoverProfile::from_server_flight`. The learner never completes the handshake (the site sees a client that went
away after its flight, like an aborted page load).

Refresh (`CoverSite::start`, `CoverRefresh`): at startup, then every 30 min ± 5 min; on failure retry after
2 min ± 75 s and **keep the last good profile**; with none ever learned, the default layout is used. The refresher
stops when the last `CoverSite` clone is dropped. A profile can also be pinned (`CoverSite::set_profile`).

**Trust.** Learning is unauthenticated (no certificate validation — that needs a real TLS stack). An adversary
that can MITM *the bridge's own uplink* can feed a crafted layout; it is bounded by validation, and the worst
outcome is a distinctive layout on that bridge's flights (a confirmation attack against an already-suspected
bridge).

## What a censor can and cannot do now

- **Passive fingerprinting.** ClientHello = Chrome 133+ (JA4 exact, fields exact, per-connection permutation and
  GREASE). ServerHello length, CCS presence and every encrypted-record size equal what the cover site itself sends
  to that ClientHello.
- **Validating the server flight against the cover site.** A censor that re-fetches the SNI's site, or replays a
  captured genuine ClientHello at the bridge (the replay cache sends it to the real cover site, which answers with
  its genuine certificate), sees the same record layout as the genuine session got — as long as the client used
  the cover domain as SNI and the profile is current.
- **Active probing.** Anything that is not a fresh, gate-authenticated ClientHello is proxied byte-for-byte to the
  cover site: a prober or a certificate validator talks to the genuine site and sees its genuine certificate.
- **TLS-terminating middlebox (full MITM with a CA the client device trusts).** The middlebox must originate its
  *own* ClientHello toward the bridge; that hello lacks the gate MAC, so the bridge proxies it to the real cover
  site — the middlebox's upstream leg is a genuine TLS session with the cover site, and the bridge never reveals
  itself (it behaved exactly like the cover). Toward the client, the middlebox answers with its own ServerHello and
  flight; our client never finds a server confirmation (the middlebox lacks the PSK), so it **fails closed**: it
  sends nothing after its ClientHello (no CCS, no Finished, no application byte) and gives up at the 8-record /
  32 KiB bound, on EOF, or at the handshake timeout, then rotates. **No tunnel survives a full MITM** — the
  property guaranteed is **non-identification of the bridge**, not reachability. The middlebox can still observe
  that this *client* did not finish a handshake it should have (a real Chrome would have sent Finished, or an
  alert on an untrusted certificate) — a client-side anomaly that does not point at the bridge.

## Key schedule

```
ss          = hybrid X25519+ML-KEM-768 secret (umesh_crypto::kem, X-Wing draft-11)
transcript  = KDF("uber-mesh v2 obfs transcript", ClientHello_record ‖ ServerHello_record ‖ ct_in_flight)
              # ct_in_flight = the unmasked ML-KEM ct for an x25519 ServerHello, else empty (= v2)
psk_ks      = KDF("uber-mesh v2 obfs psk key-schedule", psk)
master      = KDF("uber-mesh v2 obfs master", ss ‖ psk_ks ‖ transcript)
k_sconf     = KDF("uber-mesh v2 obfs server confirm", master)
k_cconf     = KDF("uber-mesh v2 obfs client confirm", master)
key_c2s     = KDF("uber-mesh v2 obfs traffic c2s", master)
key_s2c     = KDF("uber-mesh v2 obfs traffic s2c", master)

server_confirmation = AEAD(k_sconf, 0^13, aad = "uber-mesh v2 obfs server finished" ‖ transcript)   # 53 B
client_confirmation = AEAD(k_cconf, 0^13, aad = "uber-mesh v2 obfs client finished" ‖ transcript)   # 53 B
```

53 B = the payload size of a real TLS 1.3 Finished record under `TLS_AES_128_GCM_SHA256` (32 + 4 + 1 + 16).

Client and server checks: see *Client acceptance* above. The confirmations are unchanged from v2; only their
position (tail of the last record of a cover-shaped flight; tail of a suite-sized Finished) is new.

**Properties.** A party without the PSK cannot produce the server confirmation (MITM rejected by the client) and
cannot compute any session key (the PSK is in `master`). A replayer of a captured ClientHello lacks `ss` and cannot
produce the client confirmation. Any on-path change to either hello changes `transcript` and breaks both
confirmations. The X25519 half stays authoritative for confidentiality against an ML-KEM break (combiner), and
`ss` is ephemeral (forward secrecy; the PSK is for authentication / probe resistance).

Secrets (`psk`, gate key, `psk_ks`, `ss`, `master`, AEAD keys) are zeroized on drop; `ObfsPsk` has no public
field and a redacted `Debug`.

## Timeouts

| phase | bound |
|---|---|
| client TCP connect | `ClientConfig::connect_timeout` (10 s) |
| client whole handshake | `ClientConfig::handshake_timeout` (10 s) — silent freeze ⇒ error ⇒ endpoint rotation |
| server ClientHello read | 10 s, then probe response with the bytes read so far |
| server: send flight + read client confirmation | 10 s |
| fallback upstream connect | 5 s |
| cover-profile learning (connect + flight) | `CoverRefresh::timeout` (10 s); 1.5 s idle ends the flight |

## Record framing (post-handshake, unchanged from v1)

```
inner   = u32 real_len ‖ data ‖ padding                          # padding per ShapingPolicy (length-hiding)
aad     = direction(1) ‖ record_counter(8, little-endian)        # per-direction monotonic counter
wire    = 17 03 03 ‖ len ‖ XChaCha20Poly1305_seal(key_dir, nonce(24), inner, aad)   # len ≤ 16384
```

`direction` is `0x00` (c2s) or `0x01` (s2c); `key_dir` is the matching v2 traffic key.

## Known residual gaps

- **One Chrome generation.** The ClientHello is Chrome 133+ desktop with AES-NI on a first connection. Resumed
  connections (`pre_shared_key`), other platforms (e.g. the ChaCha-first suite order and ChaCha GREASE-ECH suite
  without AES hardware) and future Chrome changes are not imitated; the template must be updated when Chrome
  stable changes.
- **Cover-domain plausibility.** The bridge's IP is not one of the cover domain's IPs; a censor that checks DNS
  for SNI ↔ IP consistency sees the mismatch (inherent to REALITY-style designs; choose a cover hosted near the
  bridge, e.g. on the same provider).
- **Profile freshness and variance.** One layout sample is replicated per refresh period. Per-connection variance
  of the real site (ECDSA signature length ±1–2 B, several backends or certificates behind one name) and certificate
  changes between refreshes are not reproduced; a statistical comparison over many fetches can see a bridge whose
  flight never varies. Learning is unauthenticated (see *Trust*).
- **Client SNI is not enforced.** A client without `cover_domain` (or with a different one) still gets a session;
  its SNI then disagrees with the imitated flight.
- **Encrypted content is not real TLS.** Records are random bytes of the right sizes; anything that can decrypt
  them (only a party that completed the real key exchange — i.e. not a passive censor) would notice. A full MITM
  gets no tunnel (above).
- No post-handshake NewSessionTicket records are emitted (the real site sends them after the client Finished).
- With `Fallback`, a prober that stalls mid-ClientHello sees the 10 s gate read plus the upstream's own timeout.
- Gate epochs require client/server clocks within roughly ±1 minute.
