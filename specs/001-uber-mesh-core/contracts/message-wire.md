# Contract: signed gossip message format (v1)

Application messages disseminated via gossipsub. Carried inside the AEAD-secured libp2p stream; the signed
canonical bytes below are what gossipsub validates and dedups.

## Canonical signed structure

```rust
struct SignedMessage {
    v: u8,              // format version = 1
    topic: String,      // topic id
    sender: [u8; 32],   // PeerId = BLAKE3(verifying_key)
    sender_key: [u8; 32], // Ed25519 verifying key bytes
    seqno: u64,         // per sender, time-based: max(last + 1, now_µs)
    timestamp: u64,     // unix millis
    payload_hash: [u8; 32], // BLAKE3(payload)
    payload: Vec<u8>,   // application bytes
    sig: [u8; 64],      // Ed25519 over the signing transcript below
}
```

## Signing transcript (what `sig` covers)

```
transcript = "uber-mesh-msg-v1" ‖ topic_len ‖ topic ‖ sender ‖ sender_key
             ‖ seqno_le ‖ timestamp_le ‖ payload_hash
sig = Ed25519_sign(identity_secret, transcript)
message_id = BLAKE3-derive_key("uber-mesh v1 gossip message-id", encode(SignedMessage))
```

`payload_hash` is signed (not the raw payload) so the transcript is fixed-size; the receiver recomputes
`BLAKE3(payload)` and compares before trusting `payload`.

**message_id covers the full canonical encoding** (every field, payload and sig included) — it is also
the gossipsub `message_id_fn`, applied to the raw gossipsub data whether or not it decodes. *(Changed in
audit 2026-11: the v1 id `BLAKE3("uber-mesh-msgid-v1" ‖ transcript ‖ sig)` excluded the payload, so an
insider could re-publish a genuine message with a swapped payload under the same id, poison gossipsub's
duplicate cache, and have the genuine message dropped. Ids are not persisted or signed, so this is a
local/dedup change; mixed-version meshes simply dedup the two id forms separately.)*

`encode` is canonical (fixed-width fields, exact lengths, no trailing bytes), so `encode(decode(b)) == b`
for every accepted `b`.

### seqno

`seqno = max(last_seqno_sent + 1, now_unix_µs)`. Being time-based, it keeps increasing across restarts of
a persistent identity without persisting a counter (a restarted node used to restart at 1 and be rejected
as a replay by every peer forever).

## Validation pipeline

Verdicts map to gossipsub acceptance: **Reject** = provably invalid (not propagated, forwarder penalized via
P4); **Ignore** = not propagated, *not* penalized (an honest peer can relay it, or it's our own state).

1. `v == 1` — else **Ignore** (a peer that upgraded first must not be penalized by older ones).
2. Decodes canonically — else **Reject**.
3. `topic == gossipsub delivery topic` (topic binding: the signed topic must equal the topic the message
   arrived on; prevents cross-topic replay) — else **Reject**.
4. `BLAKE3(sender_key) == sender` (identity binding) — else **Reject**.
5. `BLAKE3(payload) == payload_hash` — else **Reject**.
6. `Ed25519_verify_strict(sender_key, transcript, sig)` passes — else **Reject**.
7. `|now - timestamp| ≤ skew_window` (default 5 min) — else **Ignore**.
8. `message_id ∉ dedup set` — else **Ignore** (Duplicate).
9. Per-sender sliding replay window — else **Ignore** (Replay): accept iff `seqno > floor[sender]` and
   `seqno ∉ recent[sender]`. On accept: insert into `recent`; `floor = max(floor, max_seqno − skew_window_µs)`;
   while `|recent| > 256`, raise `floor` to the evicted minimum. Legitimately reordered messages within the
   window are accepted exactly once.

State bounds: the dedup set (default 65 536 ids) and per-sender windows (default 16 384 senders, ≤ 256
seqnos each) are capacity-bounded with least-recently-used eviction, and entries expire `2 × skew_window`
after last use (after that, replays of the messages they protected fail step 7 anyway). Eviction under a
flood can only re-open a replay inside the timestamp window; it never blocks legitimate traffic.

Envelope fields use fixed-width little-endian encoding for a stable transcript (no bincode in this format).
