# Contract: obfs-tcp handshake & hybrid KEM wire format (obfs wire v2)

Wire format of the pure-Rust **obfs-tcp** transport (`umesh-obfs::{tls, handshake, wire}`). Versioned; breaking
it is a MAJOR change. Parsers MUST be fuzzed (constitution Principle V): `fuzz/fuzz_targets/{client_hello,
server_hello, server_gate, obfs_record}.rs`.

> **Version history**
>
> | wire | release | summary |
> |---|---|---|
> | v1 | ≤ 0.8.x | ClientHello/ServerHello with `session_id = epoch_le(8) ‖ MAC(key_share, epoch)[..24]`; keys from the KEM secret only; no key confirmation; app data straight after ServerHello. |
> | **v2** | **0.9.0** | This document. **Wire-breaking** — v1 and v2 peers cannot interoperate (a v2 server treats a v1 hello as a probe). Fixes from the 2026-11 audit: the server is now authenticated (PSK in the key schedule + mutual key confirmation), the session_id has no cleartext epoch and MACs the whole ClientHello, replays are rejected, the fallback forwards every byte, and the hello follows a Chrome template instead of a static shape. |
>
> **Migration:** all nodes of a PSK cohort must upgrade together (flag day). There is no v1 compatibility mode:
> a downgrade path would re-introduce the unauthenticated-server defect.

All multi-byte TLS fields are big-endian (as in TLS); `epoch_le` is little-endian. `‖` is concatenation.
`KDF(label, x)` = `BLAKE3.derive_key(label, x)`; `MAC(k, x)` = `BLAKE3.keyed_hash(k, x)`;
`AEAD` = XChaCha20-Poly1305 with a random 24-byte nonce, output `nonce ‖ ct ‖ tag`.

## Flow

```
C → S   ClientHello                       record 0x16 0x0301
S → C   ServerHello                       record 0x16 0x0303
        ChangeCipherSpec                  14 03 03 00 01 01
        "encrypted handshake"             1 or 4 records 17 03 03 …, 2500–5000 B payload in total;
                                          last 53 B of the last record = server confirmation
C → S   ChangeCipherSpec                  14 03 03 00 01 01
        "Finished"                        17 03 03 00 35 ‖ client confirmation (53 B)
C ⇄ S   application data                  17 03 03 … (SecureStream / ObfsByteStream records)
```

The client sends **nothing** after its ClientHello until the server confirmation verifies; the server returns a
session only after the client confirmation verifies.

## Labels (domain separation)

| use | label |
|---|---|
| PSK → gate MAC key | `uber-mesh v2 obfs psk gate-key` |
| PSK → key-schedule input | `uber-mesh v2 obfs psk key-schedule` |
| PSK → server flight shape (public sizes) | `uber-mesh v2 obfs psk flight-shape` |
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

## ClientHello (Chrome stable 2025-26 template)

A TLS 1.3 ClientHello in one handshake record, record version `0x0301`, `legacy_version = 0x0303`, 32-byte
random, **32-byte `legacy_session_id` = gate tag** (below), compression `[null]`.

- **cipher_suites** (16): `GREASE, 1301, 1302, 1303, c02b, c02f, c02c, c030, cca9, cca8, c013, c014, 009c, 009d,
  002f, 0035`.
- **extensions**: a GREASE extension (empty) first, a different GREASE extension (body `00`) last, and between
  them the following, **shuffled uniformly per connection** (Chrome's permutation):

| ext | body |
|---|---|
| `server_name` (0000) | cover SNI chosen per connection from the client's list (`ClientConfig::cover_snis`, `UMESH_SNI=a,b,c`, else a built-in list); omitted if invalid / an IP |
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
are drawn independently per connection. The `X25519MLKEM768` layouts are the IANA ones and carry
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
- `Fallback(host:port)`: connect to the cover upstream (5 s timeout; unreachable ⇒ silence), write **every byte read
  so far** verbatim, then `copy_bidirectional` until either side closes. A replayed or foreign ClientHello thus
  reaches the cover site intact and the prober completes a genuine TLS handshake with it.

## ServerHello + server flight

```
ServerHello: record 16 0303, legacy_version 0303, random(32), session_id = client's (echo),
             cipher_suite 1301, compression 00,
             extensions: supported_versions(0304), key_share(11ec: ML-KEM-768 ct (1088) ‖ X25519 pub (32))
CCS:         14 03 03 00 01 01
Flight:      shape = public function of psk via KDF("uber-mesh v2 obfs psk flight-shape", psk):
               style A (BoringSSL-like): one record of C bytes
               style B (OpenSSL-like):   records [EE 40–55, C − EE − CV − 53, CV (281 | 96–111), 53]
             with C ∈ [2500, 5000]. Record bodies are random; the last 53 bytes of the last record are the
             server confirmation.
```

The shape is constant per PSK (a real server's certificate flight is constant-size too) and lets the client check
the record count and sizes exactly.

## Key schedule

```
ss          = hybrid X25519+ML-KEM-768 secret (umesh_crypto::kem, X-Wing-style combiner)
transcript  = KDF("uber-mesh v2 obfs transcript", ClientHello_record ‖ ServerHello_record)
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

Client checks, in order: strict ServerHello parse; exact session_id echo; cipher `1301`; CCS bytes exact; flight
record count and sizes equal to the PSK shape; server confirmation opens and decrypts to `0^13`. Only then does it
send CCS + client confirmation. The server checks CCS bytes exact, a `17 03 03` record of exactly 53 B, and that the
client confirmation opens to `0^13`.

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

## Record framing (post-handshake, unchanged from v1)

```
inner   = u32 real_len ‖ data ‖ padding                          # padding per ShapingPolicy (length-hiding)
aad     = direction(1) ‖ record_counter(8, little-endian)        # per-direction monotonic counter
wire    = 17 03 03 ‖ len ‖ XChaCha20Poly1305_seal(key_dir, nonce(24), inner, aad)   # len ≤ 16384
```

`direction` is `0x00` (c2s) or `0x01` (s2c); `key_dir` is the matching v2 traffic key.

## Known residual gaps

- Not a byte-exact JA3/JA4 clone of one Chrome build (e.g. no `padding`/`pre_shared_key` behaviour, ALPS codepoint
  and ECH sizes track one Chrome generation). A DPI that terminates TLS or validates the certificate flight (it is
  random) still distinguishes it; a full uTLS/REALITY stack remains deferred (`docs/security-and-deferred.md`).
- No post-handshake NewSessionTicket records are emitted.
- With `Fallback`, a prober that stalls mid-ClientHello sees the 10 s gate read plus the upstream's own timeout.
- Gate epochs require client/server clocks within roughly ±1 minute.
