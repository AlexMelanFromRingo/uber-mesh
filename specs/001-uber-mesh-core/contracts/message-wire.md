# Contract: signed gossip message format (v2 public, v3 sealed)

Application messages disseminated via gossipsub. Carried inside the AEAD-secured libp2p stream; the signed
canonical bytes below are what gossipsub validates and dedups.

Two envelopes share one layout and one validation pipeline:

- **v2 — public.** `payload` is the application bytes. Signed and authenticated, but **every peer that
  forwards the message can read it** (the link encryption ends at each hop). Used on every topic this node
  holds no topic key for — the same as 0.10's public messages, unchanged byte for byte.
- **v3 — sealed (0.10).** `payload` is an XChaCha20-Poly1305 ciphertext under the topic's key; see
  [Sealed messages (v3)](#sealed-messages-v3--end-to-end-confidentiality). Forwarders without the key
  validate and forward it but cannot read it.

## Canonical signed structure

```rust
struct SignedMessage {
    v: u8,              // 2 = public, 3 = sealed (v1 had no pow_nonce)
    topic: String,      // topic id
    sender: [u8; 32],   // PeerId = BLAKE3(verifying_key)
    sender_key: [u8; 32], // Ed25519 verifying key bytes
    pow_nonce: u64,     // sender identity proof-of-work (see below)
    seqno: u64,         // per sender, time-based: max(last + 1, now_µs)
    timestamp: u64,     // unix millis
    payload_hash: [u8; 32], // BLAKE3(payload)  — of the ciphertext when sealed
    payload: Vec<u8>,   // v2: application bytes; v3: nonce(24) ‖ ciphertext ‖ tag(16), ≥ 40 bytes
    sig: [u8; 64],      // Ed25519 over the signing transcript below
}
```

## Signing transcript (what `sig` covers)

```
transcript = label ‖ topic_len ‖ topic ‖ sender ‖ sender_key ‖ pow_nonce_le
             ‖ seqno_le ‖ timestamp_le ‖ payload_hash
label      = "uber-mesh-msg-v2" (public) | "uber-mesh-msg-v3" (sealed)
sig = Ed25519_sign(identity_secret, transcript)
message_id = BLAKE3-derive_key("uber-mesh v1 gossip message-id", encode(SignedMessage))
```

Wire encoding (canonical, little-endian, fixed width):
`v(1) ‖ topic_len(u16) ‖ topic ‖ sender(32) ‖ sender_key(32) ‖ pow_nonce(u64) ‖ seqno(u64) ‖
timestamp(u64) ‖ payload_hash(32) ‖ payload_len(u32) ‖ payload ‖ sig(64)`.

`payload_hash` is signed (not the raw payload) so the transcript is fixed-size; the receiver recomputes
`BLAKE3(payload)` and compares before trusting `payload`. The version selects the signing label, so a
forwarder flipping the version byte (public ↔ sealed) invalidates the signature (`Reject`).

**message_id covers the full canonical encoding** (every field, payload and sig included) — it is also
the gossipsub `message_id_fn`, applied to the raw gossipsub data whether or not it decodes. *(Changed in
audit 2026-11: the v1 id `BLAKE3("uber-mesh-msgid-v1" ‖ transcript ‖ sig)` excluded the payload, so an
insider could re-publish a genuine message with a swapped payload under the same id, poison gossipsub's
duplicate cache, and have the genuine message dropped. Ids are not persisted or signed, so this is a
local/dedup change; mixed-version meshes simply dedup the two id forms separately.)*

`encode` is canonical (fixed-width fields, exact lengths, no trailing bytes), so `encode(decode(b)) == b`
for every accepted `b`.

### Sender identity proof-of-work (v2, 0.10.0)

Identities are free (a fresh Ed25519 key per message), but replay state is kept per sender, so a
fresh-identity flood is the cheapest way to pressure it. v2 prices identities:

```
pow_digest = BLAKE3-derive_key("uber-mesh v1 identity pow", sender_key ‖ u64_le(pow_nonce))
valid iff leading_zero_bits(pow_digest) ≥ MIN_SENDER_POW_BITS        (= 24)
```

- **Hash-based nonce PoW bound to the public key** (not key grinding): the key is generated first, the
  nonce is mined once (`uber-mesh init`; ≈ 2^24 hashes ≈ 1.7 s on one core, ≈ 0.25 s on 12 threads,
  measured on a Ryzen 5 5500) and reused for the identity's lifetime. Verification is one BLAKE3 call.
- **Binding:** `sender_key` is inside the hashed input, so a nonce mined for one key is worthless for any
  other; `pow_nonce` is also in the signing transcript, so a forwarder cannot swap it (no malleability of
  the message id).
- **`MIN_SENDER_POW_BITS` is a network-wide constant** (`umesh_crypto::pow::MIN_SENDER_POW_BITS`,
  re-exported as `umesh_p2p::MIN_SENDER_POW_BITS`). All nodes must agree: a message below it is
  provably invalid (`Reject`). Changing it is wire-breaking and requires a format-version bump.
- Mining is a one-time cost, so PoW is *friction*, not a barrier (constitution §Sybil): see the
  residual-risk note below and `docs/security-and-deferred.md`.

### seqno

`seqno = max(last_seqno_sent + 1, now_unix_µs)`. Being time-based, it keeps increasing across restarts of
a persistent identity without persisting a counter (a restarted node used to restart at 1 and be rejected
as a replay by every peer forever).

## Validation pipeline

Verdicts map to gossipsub acceptance: **Reject** = provably invalid (not propagated, forwarder penalized via
P4); **Ignore** = not propagated, *not* penalized (an honest peer can relay it, or it's our own state).

1. `v ∈ {2, 3}` — else **Ignore** (a peer that upgraded first must not be penalized by older ones; v1
   messages from pre-0.10 nodes are ignored, never penalized; v3 was introduced in the same release, so all 0.10 nodes understand it).
2. Decodes canonically (for v3 also `len(payload) ≥ 40`, the minimum AEAD output) — else **Reject**.
3. `topic == gossipsub delivery topic` (topic binding: the signed topic must equal the topic the message
   arrived on; prevents cross-topic replay) — else **Reject**.
4. `BLAKE3(sender_key) == sender` (identity binding) — else **Reject**.
5. Identity PoW: `leading_zero_bits(pow_digest) ≥ MIN_SENDER_POW_BITS` — else **Reject**
   (`InsufficientPow`; free to check, costs an honest sender nothing; checked before the signature and
   before any replay state is touched).
6. `BLAKE3(payload) == payload_hash` — else **Reject**.
7. `Ed25519_verify_strict(sender_key, transcript, sig)` passes — else **Reject**.
8. `|now - timestamp| ≤ skew_window` (default 5 min) — else **Ignore**.
9. `message_id ∉ dedup set` — else **Ignore** (Duplicate).
10. Per-sender sliding replay window — else **Ignore** (Replay): accept iff `seqno > floor[sender]` and
   `seqno ∉ recent[sender]`. On accept: insert into `recent`; `floor = max(floor, max_seqno − skew_window_µs)`;
   while `|recent| > 256`, raise `floor` to the evicted minimum. Legitimately reordered messages within the
   window are accepted exactly once.

State bounds: the dedup set (default 65 536 ids) and per-sender windows (default 16 384 senders, ≤ 256
seqnos each) are capacity-bounded, and entries expire `2 × skew_window` after last use (after that,
replays of the messages they protected fail step 7 anyway). When the sender table is full, the
least-recently-used window is evicted and its highest accepted timestamp is kept as a **per-sender floor**
(exact table, 65 536 entries, `2 × skew_window` expiry). If that table must drop a still-live floor, the
floor is **folded** (max) into one of 4 096 buckets instead (bucket index = keyed BLAKE3 of the sender id under a
random per-node secret, so no one can aim identities at a chosen sender's bucket) — a floor is never lost, so a replay of an
evicted sender's message is always refused (`Replay`, gossipsub `Ignore`, no penalty), also after the
sender is tracked again. Message timestamps may be at most **30 s in the future** (5 min in the past), so no
floor exceeds the receiver's clock by more than 30 s: a future-dated flood constrains only its own identities,
plus — only once the exact table overflows — senders sharing a bucket, for at most 30 s.

Verdicts depend only on the message, never on the forwarding peer: gossipsub caches a verdict by
message-id, so a per-forwarder Ignore would also drop honest copies relayed by others. Residual risk: a
sustained fresh-identity flood (≈135 new identities/s for 10 min ≈ 81 000 identities) can make
bucket-sharing newcomers wait up to 30 s. Since v2 every identity costs 2^24 hashes: mined live that is
≈135 × 2^24 ≈ 2.3·10⁹ hashes/s (≈ 225 CPU cores at the measured ≈10 M hashes/s/core); but nonces do not
expire, so the identities can be pre-mined (≈1.4·10¹² hashes ≈ 38 CPU core-hours, far less on GPUs)
and reused once their replay state has expired. Identity PoW is therefore friction, not a hard
barrier — see `docs/security-and-deferred.md`. The dedup set is a plain LRU cache — the per-sender windows are authoritative.

Envelope fields use fixed-width little-endian encoding for a stable transcript (no bincode in this format).

## Sealed messages (v3) — end-to-end confidentiality

*(0.10.)* Closes the spec edge case "untrusted relay/serving peer: … MUST be unable to read or tamper with
payloads it forwards". Integrity was already end to end (signatures, CIDs); v3 adds confidentiality.

### Keys

A **topic key** is 32 random bytes shared out of band among the topic's members (like the bridge PSK;
`uber-mesh keys new-topic-key`). A topic without a key is **public** (v2). The topic key never encrypts
anything directly:

```
topic_root = BLAKE3-derive_key("uber-mesh v1 topic key",       topic_key ‖ topic)
epoch      = timestamp_ms / 86 400 000                                   (daily; the *signed* timestamp)
K_epoch    = BLAKE3-derive_key("uber-mesh v1 topic epoch key", topic_root ‖ u64_le(epoch))
```

Binding the topic name into the root makes one key reused for two topics yield unrelated AEAD keys. The
epoch is computed from the message's signed timestamp, and accepted timestamps lie within
`now − 5 min … now + 30 s`, so a receiver only ever uses the current or the previous epoch's key; no
epoch field is carried. **This is key separation, not forward secrecy** — anyone holding the topic key
derives every epoch key (see `docs/security-and-deferred.md` §4).

### Sealing

```
aad      = "uber-mesh v1 sealed message" ‖ u8(3) ‖ u16_le(topic_len) ‖ topic ‖ sender(32)
           ‖ u64_le(seqno) ‖ u64_le(timestamp)
nonce    = 24 random bytes (OsRng)
payload  = nonce ‖ XChaCha20-Poly1305(K_epoch, nonce, inner, aad)        (= ciphertext ‖ tag)
```

then sign as above with `v = 3` (`payload_hash = BLAKE3(payload)` covers the **ciphertext**). The AAD binds
version, topic, sender, seqno and timestamp, so a ciphertext copied into another topic, another sender's
message or another message of the same sender fails authentication (and the signature already prevents a
non-sender from re-wrapping it).

`inner` (the plaintext, parsed strictly; unknown kind or wrong length ⇒ not delivered):

| kind | layout | meaning |
|---|---|---|
| `0x00` | `0x00 ‖ application bytes` | application data → `MeshEvent::Message { sealed: true }` |
| `0x01` | `0x01 ‖ cid(32) ‖ content_key(32)` (exactly 65 bytes) | encrypted blob shared in the topic → `MeshEvent::SealedBlob` |

### Receiving

Steps 1–10 of the validation pipeline are unchanged and **do not need the key**: every subscribed peer
validates identity binding, PoW, payload hash, signature, timestamp and replay state on the ciphertext and
reports the gossipsub verdict, so a non-member forwards a valid sealed message exactly like a member. The
verdict never depends on key possession. Only after the verdict, delivery:

| this node | public (v2) message | sealed (v3) message |
|---|---|---|
| holds no key for the topic | delivered (`sealed: false`) | **forwarded, never delivered** (`umesh_gossip_sealed_unread_total`) |
| holds the topic key | **refused** — downgrade (`umesh_gossip_sealed_refused_total`) | decrypted with `K_epoch(timestamp)`; AEAD failure (wrong key, moved ciphertext) or malformed `inner` ⇒ refused, not delivered |

A refused message has still been forwarded (it was valid); refusal is local and never penalizes anyone.

### Encrypted blobs

Content shared in a sealed topic is encrypted under a fresh random 32-byte `content_key`:
`blob = nonce(24) ‖ XChaCha20-Poly1305(content_key, nonce, plaintext, aad = "uber-mesh v1 sealed blob")`,
plaintext ≤ 8 MiB − 40. Its `Cid = BLAKE3-derive_key("uber-mesh v1 cid", blob)` is over the **ciphertext**:
storing, mirroring (set reconciliation) and serving peers verify integrity against the `Cid` and serve the
blob without being able to read it. `(cid, content_key)` travels only inside a sealed message (kind `0x01`),
so non-members learn neither the key nor which `Cid` belongs to the topic. A member fetches by `Cid`
(`MeshNode::request_sealed_blob`), verifies the `Cid`, decrypts, and stores only the ciphertext. Public
blobs (`provide` / `request_blob`) are unchanged: plaintext, `Cid` over the plaintext.

### What each party sees

| party | sees | does not see |
|---|---|---|
| network observer on a link | obfs records shaped like TLS 1.3 (sizes, timing, endpoints) | anything inside the obfs AEAD (incl. Noise) |
| Circuit Relay v2 relay | the two endpoints' libp2p PeerIds, timing and volume of the relayed connection, **only Noise ciphertext** (the relayed connection is Noise-secured end to end between the two peers) | gossip messages, topics, blobs |
| gossip forwarder **without** the topic key | topic name; sender PeerId, `sender_key`, `pow_nonce`; gossipsub publisher PeerId; `seqno`, timestamp; ciphertext size (= plaintext + 41 bytes; a blob announcement is a fixed 105-byte payload); timing and which neighbour sent it | the content; blob `Cid`s and content keys announced in the topic |
| serving / mirroring peer (no key) | blob ciphertext, its `Cid` and size (= plaintext + 40 bytes), who requests it and when | the content |
| topic member (holds the key) | everything in the topic, including past and future epochs | — (a member is trusted with the topic) |

Residual leaks, by design: topic names, sizes and timing are visible to forwarders; any key holder can read
the topic and keep reading until the key is rotated out of band (no revocation, no forward secrecy). Topics
that need confidentiality from forwarders MUST be sealed; a public topic's payload is readable by every peer
that forwards it.

### Compatibility

v2 (public) and v3 (sealed) both ship in 0.10, which is already a flag day (obfs wire, identity PoW), so
every 0.10 node validates and forwards both. Older nodes `Ignore` v2/v3 (never penalize) and cannot be part
of a 0.10 cohort anyway.
