# Contract: obfuscated handshake & hybrid KEM wire format (v1)

Wire format for the pure-Rust **obfs-tcp** transport. Versioned; breaking it is a MAJOR change. All multi-byte
integers are little-endian. Parsers MUST be fuzzed (constitution Principle V).

> **v1 design note (reconciled after the 2026-06-28 security review):** rather than sending a plaintext
> MAC-gate flight followed by a separately-encrypted KEM flight, **both flights are AEAD-sealed under a key
> derived from the per-listener PSK**. This is strictly stronger for the anti-DPI goal: the ML-KEM-768 key /
> ciphertext and the X25519 keys carry **no plaintext structure** on the wire (so DPI cannot fingerprint
> hybrid-PQ usage or recover EC-point structure — this also subsumes the need for Elligator2 encoding), and the
> AEAD tag itself **is** the probe-resistance gate (a peer without the PSK cannot produce a flight that opens).

## Frame key

```
frame_key = BLAKE3_derive_key("uber-mesh v1 obfs-frame", obfs_psk)     # XChaCha20-Poly1305 key
```

`obfs_psk` is a 32-byte per-listener "bridge secret" shared out-of-band among a cohort of peers.

## Flight 1 — client → server (AEAD-sealed, TLS-record-framed)

```
plaintext_1 = x25519_pub(32) ‖ mlkem_ek(1184) ‖ epoch(8)          # 1224 bytes
wire_1      = TLSrecord( XChaCha20Poly1305_seal(frame_key, nonce, plaintext_1, aad="uber-mesh-hs1-v1") )
              # = TLSrecord( nonce(24) ‖ ciphertext ‖ tag(16) )
```

- `epoch = unix_seconds / 60` (little-endian); authenticated inside the AEAD.
- The server reads the record (under a 10 s timeout) and `open`s it with `frame_key`.
  **Open failure OR a stale epoch (`|client_epoch − server_epoch| > 1`) ⇒ silence**: the server drains input
  (bounded by ≤ 64 KiB and a randomized 50–400 ms delay) then closes, sending no distinguishing reply.
  The ±1-epoch window (~3 min) is the accepted, stateless clock-skew/replay tolerance.

## Flight 2 — server → client (AEAD-sealed, TLS-record-framed)

```
plaintext_2 = x25519_pub(32) ‖ mlkem_ct(1088)                     # 1120 bytes
wire_2      = TLSrecord( XChaCha20Poly1305_seal(frame_key, nonce, plaintext_2, aad="uber-mesh-hs2-v1") )
```

Because Flight 2 is also sealed under the PSK frame key, the responder's flight is authenticated to anyone
holding the PSK (an off-path or PSK-less attacker cannot forge it). *Peer identity* — which specific node is on
the far end — is established by the signed-hello / future Noise layer **above** this transport; the obfs layer
authenticates the **carrier**, not the peer.

## Hybrid PQ key agreement (X-Wing-style combiner)

After both flights, each side holds: its X25519 secret + the peer's X25519 public, an ML-KEM-768 shared secret
(server via `encapsulate`, client via `decapsulate`), the ML-KEM ciphertext, and both X25519 public keys.

```
ss = BLAKE3_derive_key("uber-mesh v1 xwing",
        ss_mlkem ‖ ss_x25519 ‖ mlkem_ct ‖ x25519_initiator_pub ‖ x25519_responder_pub)
key_c2s = BLAKE3_derive_key("uber-mesh v1 traffic c2s", ss)
key_s2c = BLAKE3_derive_key("uber-mesh v1 traffic s2c", ss)
```

**Both** ephemeral X25519 public keys are bound into the combiner (not just the initiator's), so a tampered
responder key is cryptographically detectable. The X25519 share is authoritative: even if ML-KEM is broken,
`ss_x25519` keeps `ss` secret (hybrid guarantee, constitution Principle I).

## Record framing (post-handshake)

```
inner   = u32 real_len ‖ data ‖ padding                          # padding per ShapingPolicy (length-hiding)
aad     = direction(1) ‖ record_counter(8, little-endian)        # per-direction monotonic counter
wire    = TLSrecord( XChaCha20Poly1305_seal(key_dir, nonce(24), inner, aad) )   # len ≤ 16384
```

- `direction` is `0x00` (c2s) or `0x01` (s2c); `key_dir` is the matching directional traffic key.
- Binding `direction ‖ counter` into the AAD means record reordering, replay, injection, or truncation within a
  session is detected (TCP delivers in order; any mismatch ⇒ decrypt failure).
- Re-key (epoch bump after N records / T seconds, re-running the KEM and rotating keys with old keys zeroized) is
  a planned v1.x addition; the counter/AAD scheme is forward-compatible with it.

## Carrier framing

Every record (handshake flights included) is wrapped in a TLS 1.2 Application-Data record header
(`0x17 0x03 0x03 <len:u16-be>`) so the flow opens like ordinary TLS rather than uniform-random noise, defeating
the "fully-encrypted / no-header" classifier (USENIX'23). See `contracts/obfs-transport.md` and `umesh-obfs::wire`.
