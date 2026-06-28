# Contract: obfuscated handshake & hybrid KEM wire format (v1)

Wire format for the pure-Rust **obfs-tcp** transport. Versioned; breaking it is a MAJOR change. All multi-byte
integers are little-endian. Parsers MUST be fuzzed (constitution Principle V).

## Layer A — obfs MAC gate (probe resistance, popcount-mitigated)

Client → Server, first flight:

```
[ repr: 32 bytes ]   X25519 ephemeral client pubkey, Elligator2-style uniform encoding (looks random)
[ epoch: 8 bytes ]   unix-seconds / 60, little-endian (replay window)
[ mac: 16 bytes ]    BLAKE3_keyed(mac_key, repr ‖ epoch),  mac_key = derive_key("uber-mesh v1 obfs-mac", obfs_psk)
[ pad: P bytes ]     random padding, P chosen so the flight length ∉ a fixed value and total popcount/byte
                     stays outside the fully-encrypted exempt band
```

- Server recomputes the MAC over a sliding epoch window (`epoch-1..=epoch+1`). **Mismatch ⇒ silence**: the
  server keeps reading, drains a random number of bytes, waits a randomized delay, then closes (no RST tell).
- On match, server replies with its own `repr ‖ mac ‖ pad` flight.

## Layer B — hybrid PQ key agreement (X-Wing over the gated channel)

After the MAC gate establishes an ephemeral X25519 shared secret used to encrypt Layer B:

```
Client → Server:
  [ mlkem_ek: 1184 bytes ]   ML-KEM-768 encapsulation (public) key, ephemeral
Server → Client:
  [ mlkem_ct: 1088 bytes ]   ML-KEM-768 ciphertext (encapsulated to client ek)
```

Shared secret (X-Wing construction, domain-separated):

```
ss = BLAKE3_derive_key("uber-mesh v1 xwing",
        ss_mlkem ‖ ss_x25519 ‖ mlkem_ct ‖ x25519_client_pub)
key_c2s = BLAKE3_derive_key("uber-mesh v1 traffic c2s", ss)
key_s2c = BLAKE3_derive_key("uber-mesh v1 traffic s2c", ss)
```

The X25519 share is authoritative: even if ML-KEM is broken, `ss_x25519` keeps `ss` secret.

## Layer C — record framing (post-handshake)

```
[ len: 2 bytes ]     ciphertext length (≤ 16384)
[ ciphertext ]       XChaCha20-Poly1305(key_dir, nonce, plaintext, aad = direction ‖ epoch)
                     nonce = 24 random bytes prepended to the ciphertext block
```

Re-key: after `N` records or `T` seconds, either side initiates an epoch bump that re-runs Layer B and
increments `epoch`; old keys are zeroized (forward secrecy, FR-010).

## Identity binding

The libp2p Noise upgrade (running *above* this transport) binds the connection to the Ed25519 `PeerId`. The
obfs handshake authenticates the *carrier* (anti-DPI), Noise/identify authenticates the *peer*.
