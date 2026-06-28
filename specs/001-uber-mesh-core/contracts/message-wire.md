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
    seqno: u64,         // monotonic per sender
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
message_id = BLAKE3("uber-mesh-msgid-v1" ‖ transcript ‖ sig)
```

`payload_hash` is signed (not the raw payload) so the transcript is fixed-size; the receiver recomputes
`BLAKE3(payload)` and compares before trusting `payload`.

## Validation pipeline (reject ⇒ do not accept AND do not re-propagate)

1. `v == 1`.
2. `BLAKE3(sender_key) == sender` (identity binding).
3. `Ed25519_verify_strict(sender_key, transcript, sig)` passes.
4. `BLAKE3(payload) == payload_hash`.
5. `seqno > last_seqno[sender]` (monotonic; update on accept).
6. `|now - timestamp| ≤ skew_window` (default 5 min).
7. `message_id ∉ dedup_lru` (bounded; insert on accept).

A failure at steps 2–4 additionally reports a gossipsub validation failure (peer-score penalty P4). Serialization
of `payload` uses bincode 3 with a decode byte-limit; the envelope fields use fixed-width encoding for a stable
transcript.
