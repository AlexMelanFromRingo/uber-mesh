//! Signed gossip messages + replay protection (contracts/message-wire.md).
//!
//! Every message is authenticated to its sender and content-addressed. Validation has a stateless
//! part (identity binding, identity proof-of-work, signature, payload hash, topic binding) and a
//! stateful part (per-sender sliding replay window, timestamp window, bounded dedup) — gossipsub's
//! own dedup does NOT survive cache eviction, so replay protection is enforced here at the
//! application layer (research D10 / mesh-integrity). All stateful structures are bounded and expire, since remote peers pick the keys.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use umesh_crypto::hash::{self, Hash32};
use umesh_crypto::identity::{self, NodeIdentity, PeerId};
use umesh_crypto::pow;

use crate::bounded::BoundedMap;

/// Message format version of a **public** message. v2 (0.10.0) added the sender's identity
/// proof-of-work nonce; v1 messages are `Ignore`d (never penalized), like any other unknown version.
pub const MSG_VERSION: u8 = 2;
/// Message format version of a **sealed** (end-to-end encrypted) message: the v2 layout, but the
/// payload is `nonce(24) ‖ XChaCha20-Poly1305(ciphertext ‖ tag)` under the topic's key (see
/// [`crate::sealed`]). Signed under a distinct label, so a forwarder cannot flip the version byte.
pub const SEALED_MSG_VERSION: u8 = 3;
const SIG_LABEL: &[u8] = b"uber-mesh-msg-v2";
const SEALED_SIG_LABEL: &[u8] = b"uber-mesh-msg-v3";
/// Smallest valid sealed payload: a 24-byte nonce and a 16-byte tag (empty plaintext).
pub const MIN_SEALED_PAYLOAD: usize = umesh_crypto::aead::NONCE_LEN + umesh_crypto::aead::TAG_LEN;
/// Network-wide minimum identity proof-of-work (leading zero bits of
/// [`umesh_crypto::pow::identity_digest`]) a sender must carry. Defined once, in
/// [`umesh_crypto::pow::MIN_SENDER_POW_BITS`]; **all nodes must agree** on it — a message below it
/// is provably invalid (`Reject`), so changing it requires a [`MSG_VERSION`] bump.
pub const MIN_SENDER_POW_BITS: u32 = pow::MIN_SENDER_POW_BITS;
/// BLAKE3 `derive_key` context for message-ids. The id covers the **full canonical encoding**
/// (including the payload), so two different byte strings can never share an id — a forged copy
/// with a swapped payload cannot poison the gossipsub duplicate cache for the genuine message.
pub const MSGID_CONTEXT: &str = "uber-mesh v1 gossip message-id";

/// Default acceptable clock skew for message timestamps (±5 minutes).
pub const DEFAULT_SKEW_MS: u64 = 5 * 60 * 1000;
/// Default dedup cache capacity (message-ids retained).
pub const DEFAULT_DEDUP_CAP: usize = 65536;
/// Default cap on tracked senders (per-sender replay windows).
pub const DEFAULT_SENDER_CAP: usize = 16384;
/// Capacity of the exact per-sender floor table kept for evicted sender windows (entries expire
/// after `2·skew`, when every message they protect fails the timestamp check anyway).
pub const DEFAULT_EVICTED_CAP: usize = 65536;
/// Hashed fallback for floors that overflow the exact table: a live floor is never dropped, it is
/// folded (max) into one of these buckets. Fixed memory (`8 × N` bytes).
pub const FLOOR_BUCKETS: usize = 4096;
/// How far in the future a message timestamp may be (the past tolerance is the full skew window).
/// Kept small because it bounds how far above the receiver's clock any replay floor can sit, i.e.
/// how long a future-dated flood can affect other senders sharing a fallback bucket.
pub const MAX_FUTURE_MS: u64 = 30_000;
/// Seqnos remembered per sender inside its replay window (out-of-order tolerance).
pub const REPLAY_WINDOW_SEQNOS: usize = 256;

/// Wall-clock now in unix microseconds.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Next publisher seqno: `max(last + 1, now_µs)`. Time-based, so a restarted node (same identity,
/// fresh process state) continues above anything it sent before instead of restarting at 1 and
/// being silenced as a replay by every peer.
pub fn next_seqno(last: u64, now_us: u64) -> u64 {
    last.saturating_add(1).max(now_us)
}

/// The message-id of a canonical encoding: `BLAKE3-derive_key(MSGID_CONTEXT, encoded)`.
/// Also used as the gossipsub message-id function for arbitrary (possibly invalid) data.
pub fn message_id_of(encoded: &[u8]) -> Hash32 {
    hash::derive_key(MSGID_CONTEXT, encoded)
}

/// Wall-clock now in unix milliseconds.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why a message was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MsgError {
    /// Unsupported message version.
    #[error("unsupported message version")]
    Version,
    /// Truncated or malformed encoding.
    #[error("malformed message")]
    Malformed,
    /// `BLAKE3(sender_key) != sender`.
    #[error("sender id does not bind to key")]
    IdentityBinding,
    /// Signature verification failed.
    #[error("invalid signature")]
    Signature,
    /// `BLAKE3(payload) != payload_hash`.
    #[error("payload hash mismatch")]
    PayloadHash,
    /// Seqno already seen for this sender, or older than its replay window.
    #[error("replayed or stale seqno")]
    Replay,
    /// Timestamp outside the accepted skew window.
    #[error("timestamp outside window")]
    Timestamp,
    /// Already-seen message-id.
    #[error("duplicate message")]
    Duplicate,
    /// The signed topic differs from the gossipsub topic the message arrived on.
    #[error("signed topic does not match delivery topic")]
    TopicMismatch,
    /// The sender identity's proof-of-work nonce is below the required difficulty.
    #[error("insufficient sender identity proof-of-work")]
    InsufficientPow,
}

impl MsgError {
    /// Whether the message is provably invalid (forged/tampered/malformed/cross-topic), so the
    /// forwarding peer should be penalized (gossipsub `Reject`, P4). Replays, duplicates and
    /// out-of-window timestamps can be relayed by honest peers (or caused by our own state/clock)
    /// and are only `Ignore`d — never scored. An unknown version is also ignored, so peers that
    /// upgraded first aren't penalized by older ones.
    pub fn is_invalid(&self) -> bool {
        !matches!(
            self,
            MsgError::Replay | MsgError::Duplicate | MsgError::Timestamp | MsgError::Version
        )
    }
}

/// A signed, content-addressed gossip message.
///
/// Public (v2) messages carry the application bytes in `payload`. Sealed (v3) messages carry the
/// AEAD ciphertext there instead: `payload_hash` and `sig` cover the **ciphertext**, so every
/// forwarder can still check identity binding, PoW, signature and replay state — and forward the
/// message — without being able to read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedMessage {
    /// `true` for a sealed (v3, end-to-end encrypted) message, `false` for a public (v2) one.
    pub sealed: bool,
    /// Topic id.
    pub topic: String,
    /// Sender PeerId (`BLAKE3(sender_key)`).
    pub sender: [u8; 32],
    /// Sender Ed25519 verifying key.
    pub sender_key: [u8; 32],
    /// Identity proof-of-work nonce: `pow::identity_digest(sender_key, pow_nonce)` must have at
    /// least [`MIN_SENDER_POW_BITS`] leading zero bits. Mined once per identity; signed.
    pub pow_nonce: u64,
    /// Per-sender sequence number (time-based: `max(last + 1, now_µs)`).
    pub seqno: u64,
    /// Unix-millis timestamp.
    pub timestamp: u64,
    /// `BLAKE3(payload)`.
    pub payload_hash: Hash32,
    /// Application payload (public) or `nonce ‖ ciphertext ‖ tag` (sealed).
    pub payload: Vec<u8>,
    /// Ed25519 signature over the transcript.
    pub sig: [u8; 64],
}

#[allow(clippy::too_many_arguments)]
fn transcript(
    sealed: bool,
    topic: &str,
    sender: &[u8; 32],
    sender_key: &[u8; 32],
    pow_nonce: u64,
    seqno: u64,
    timestamp: u64,
    payload_hash: &Hash32,
) -> Vec<u8> {
    let label = if sealed { SEALED_SIG_LABEL } else { SIG_LABEL };
    let mut t = Vec::with_capacity(label.len() + 2 + topic.len() + 32 + 32 + 8 + 8 + 8 + 32);
    t.extend_from_slice(label);
    t.extend_from_slice(&(topic.len() as u16).to_le_bytes());
    t.extend_from_slice(topic.as_bytes());
    t.extend_from_slice(sender);
    t.extend_from_slice(sender_key);
    t.extend_from_slice(&pow_nonce.to_le_bytes());
    t.extend_from_slice(&seqno.to_le_bytes());
    t.extend_from_slice(&timestamp.to_le_bytes());
    t.extend_from_slice(payload_hash);
    t
}

impl SignedMessage {
    /// Build and sign a message from an identity **without** a proof-of-work (`pow_nonce = 0`).
    ///
    /// Such a message fails validation at [`MIN_SENDER_POW_BITS`] (except with probability
    /// `2^-MIN_SENDER_POW_BITS`); it exists for low-level tests of the other checks. Real senders
    /// use [`SignedMessage::create_with_pow`] (as [`crate::MeshNode::publish`] does).
    pub fn create(
        id: &NodeIdentity,
        topic: &str,
        payload: Vec<u8>,
        seqno: u64,
        timestamp: u64,
    ) -> Self {
        Self::create_with_pow(id, 0, topic, payload, seqno, timestamp)
    }

    /// Build and sign a message from an identity and its mined proof-of-work nonce (see
    /// [`umesh_crypto::pow::mine_identity`]). The nonce is covered by the signature.
    pub fn create_with_pow(
        id: &NodeIdentity,
        pow_nonce: u64,
        topic: &str,
        payload: Vec<u8>,
        seqno: u64,
        timestamp: u64,
    ) -> Self {
        Self::sign(id, pow_nonce, false, topic, payload, seqno, timestamp)
    }

    /// Build and sign a **sealed** (v3) message whose `ciphertext` is already sealed for exactly
    /// this `(topic, sender, seqno, timestamp)` — use [`crate::sealed::seal_message`], which picks
    /// the seqno/timestamp, binds them into the AEAD associated data and calls this.
    pub fn create_sealed_with_pow(
        id: &NodeIdentity,
        pow_nonce: u64,
        topic: &str,
        ciphertext: Vec<u8>,
        seqno: u64,
        timestamp: u64,
    ) -> Self {
        Self::sign(id, pow_nonce, true, topic, ciphertext, seqno, timestamp)
    }

    fn sign(
        id: &NodeIdentity,
        pow_nonce: u64,
        sealed: bool,
        topic: &str,
        payload: Vec<u8>,
        seqno: u64,
        timestamp: u64,
    ) -> Self {
        let sender = *id.peer_id().as_bytes();
        let sender_key = id.verifying_key().to_bytes();
        let payload_hash = hash::hash(&payload);
        let t = transcript(
            sealed,
            topic,
            &sender,
            &sender_key,
            pow_nonce,
            seqno,
            timestamp,
            &payload_hash,
        );
        let sig = id.sign_bytes(&t);
        SignedMessage {
            sealed,
            topic: topic.to_string(),
            sender,
            sender_key,
            pow_nonce,
            seqno,
            timestamp,
            payload_hash,
            payload,
            sig,
        }
    }

    fn transcript(&self) -> Vec<u8> {
        transcript(
            self.sealed,
            &self.topic,
            &self.sender,
            &self.sender_key,
            self.pow_nonce,
            self.seqno,
            self.timestamp,
            &self.payload_hash,
        )
    }

    /// Deterministic content id of this message: [`message_id_of`] its canonical encoding
    /// (covers every field, payload included).
    pub fn message_id(&self) -> Hash32 {
        message_id_of(&self.encode())
    }

    /// Stateless validation at the network-wide [`MIN_SENDER_POW_BITS`]: identity binding,
    /// identity proof-of-work, payload hash, signature. Returns the bound PeerId.
    pub fn validate_stateless(&self) -> Result<PeerId, MsgError> {
        self.validate_stateless_with_pow(MIN_SENDER_POW_BITS)
    }

    /// [`SignedMessage::validate_stateless`] with an explicit PoW difficulty. Anything other than
    /// [`MIN_SENDER_POW_BITS`] is for tests/isolated devnets only (see [`validate_with_pow`]).
    pub fn validate_stateless_with_pow(&self, min_pow_bits: u32) -> Result<PeerId, MsgError> {
        if hash::hash(&self.sender_key) != self.sender {
            return Err(MsgError::IdentityBinding);
        }
        // One BLAKE3 call, checked before the (expensive) signature: work bound to this key.
        if !pow::verify_identity(&self.sender_key, self.pow_nonce, min_pow_bits) {
            return Err(MsgError::InsufficientPow);
        }
        if hash::hash(&self.payload) != self.payload_hash {
            return Err(MsgError::PayloadHash);
        }
        identity::verify(&self.sender_key, &self.transcript(), &self.sig)
            .map_err(|_| MsgError::Signature)
    }

    /// Canonical wire encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 2 + self.topic.len() + 32 + 32 + 8 + 8 + 8 + 32 + 4 + self.payload.len() + 64,
        );
        out.push(self.version());
        out.extend_from_slice(&(self.topic.len() as u16).to_le_bytes());
        out.extend_from_slice(self.topic.as_bytes());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.sender_key);
        out.extend_from_slice(&self.pow_nonce.to_le_bytes());
        out.extend_from_slice(&self.seqno.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.sig);
        out
    }

    /// Wire version byte: [`MSG_VERSION`] (public) or [`SEALED_MSG_VERSION`] (sealed).
    pub fn version(&self) -> u8 {
        if self.sealed {
            SEALED_MSG_VERSION
        } else {
            MSG_VERSION
        }
    }

    /// Parse a message from its canonical encoding. Never panics on arbitrary input.
    ///
    /// A sealed (v3) message whose payload is shorter than [`MIN_SEALED_PAYLOAD`] cannot be a
    /// valid AEAD output and is `Malformed` (checkable by every forwarder, key or not).
    pub fn decode(buf: &[u8]) -> Result<Self, MsgError> {
        let mut c = Cursor { buf, pos: 0 };
        let sealed = match c.u8()? {
            MSG_VERSION => false,
            SEALED_MSG_VERSION => true,
            _ => return Err(MsgError::Version),
        };
        let topic_len = c.u16()? as usize;
        let topic =
            String::from_utf8(c.take(topic_len)?.to_vec()).map_err(|_| MsgError::Malformed)?;
        let sender = c.arr32()?;
        let sender_key = c.arr32()?;
        let pow_nonce = c.u64()?;
        let seqno = c.u64()?;
        let timestamp = c.u64()?;
        let payload_hash = c.arr32()?;
        let payload_len = c.u32()? as usize;
        let payload = c.take(payload_len)?.to_vec();
        let sig = c.arr64()?;
        if c.pos != buf.len() {
            return Err(MsgError::Malformed); // trailing bytes
        }
        if sealed && payload.len() < MIN_SEALED_PAYLOAD {
            return Err(MsgError::Malformed);
        }
        Ok(SignedMessage {
            sealed,
            topic,
            sender,
            sender_key,
            pow_nonce,
            seqno,
            timestamp,
            payload_hash,
            payload,
            sig,
        })
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MsgError> {
        let end = self.pos.checked_add(n).ok_or(MsgError::Malformed)?;
        if end > self.buf.len() {
            return Err(MsgError::Malformed);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, MsgError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, MsgError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, MsgError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, MsgError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn arr32(&mut self) -> Result<[u8; 32], MsgError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn arr64(&mut self) -> Result<[u8; 64], MsgError> {
        Ok(self.take(64)?.try_into().unwrap())
    }
}

/// Per-sender replay window: every seqno `<= floor` is rejected; seqnos above `floor` are accepted
/// once each (`recent` remembers them). `floor` trails the highest seqno by the skew window and is
/// raised whenever `recent` overflows, so state per sender is `O(REPLAY_WINDOW_SEQNOS)`.
struct SenderWindow {
    floor: u64,
    high: u64,
    recent: BTreeSet<u64>,
    last_ms: u64,
    /// Highest message timestamp accepted from this sender (feeds the eviction floor).
    max_ts: u64,
    /// This sender's floor from an earlier evicted window (0 if none): its messages at or below
    /// this timestamp may be replays of what the evicted window protected — refuse them.
    ts_floor: u64,
}

/// Stateful anti-replay: per-sender sliding seqno window, timestamp window, bounded message-id
/// dedup. Both maps are capacity-bounded and entries expire `2·skew` after their last use (after
/// which any replay of the messages they protected fails the timestamp check anyway).
pub struct ReplayGuard {
    senders: BoundedMap<[u8; 32], SenderWindow>,
    seen: BoundedMap<Hash32, u64>,
    skew_ms: u64,
    /// Floors of sender windows evicted for space: sender → (highest accepted timestamp, when it was
    /// evicted). Per sender, so a sender's (possibly future-dated) timestamps only ever constrain
    /// that same sender — no global value an attacker can push above everyone's clock.
    evicted: BoundedMap<[u8; 32], (u64, u64)>,
    /// Fallback floors for exact floors evicted while still live (see [`FLOOR_BUCKETS`]).
    buckets: Box<[u64]>,
    /// Secret, per-node key for the bucket index: without it nobody can grind identities that land
    /// in a chosen (victim's) bucket.
    bucket_key: Hash32,
}

impl ReplayGuard {
    /// Create a guard with the given skew window and dedup capacity.
    pub fn new(skew_ms: u64, dedup_cap: usize) -> Self {
        ReplayGuard::with_limits(skew_ms, dedup_cap, DEFAULT_SENDER_CAP)
    }

    /// Create a guard with explicit dedup and tracked-sender capacities.
    pub fn with_limits(skew_ms: u64, dedup_cap: usize, sender_cap: usize) -> Self {
        ReplayGuard {
            senders: BoundedMap::new(sender_cap),
            seen: BoundedMap::new(dedup_cap),
            skew_ms,
            evicted: BoundedMap::new(DEFAULT_EVICTED_CAP),
            buckets: vec![0u64; FLOOR_BUCKETS].into_boxed_slice(),
            bucket_key: {
                use rand::RngCore;
                let mut k = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut k);
                k
            },
        }
    }

    /// Number of senders currently tracked (bounded by the sender cap).
    pub fn tracked_senders(&self) -> usize {
        self.senders.len()
    }

    /// Number of message-ids currently remembered (bounded by the dedup cap).
    pub fn tracked_ids(&self) -> usize {
        self.seen.len()
    }

    /// Whether `sender` currently has a replay window (a message from an untracked sender creates one).
    pub fn tracks(&self, sender: &[u8; 32]) -> bool {
        self.senders.contains_key(sender)
    }

    /// Bucket index under the node's secret key (keyed BLAKE3): an attacker can't predict which
    /// bucket an identity maps to here, so it can't target a particular sender's bucket.
    fn bucket(&self, sender: &[u8; 32]) -> usize {
        let h = hash::keyed_mac(&self.bucket_key, sender);
        u32::from_le_bytes(h[..4].try_into().expect("4 bytes")) as usize % FLOOR_BUCKETS
    }

    /// Replay floor for an untracked sender: its exact floor, else its bucket's folded floor.
    fn floor_of(&self, sender: &[u8; 32]) -> u64 {
        let exact = self.evicted.get(sender).map(|&(f, _)| f).unwrap_or(0);
        exact.max(self.buckets[self.bucket(sender)])
    }

    /// Remember an evicted window's floor; if the exact table must drop a still-live floor to make
    /// room, fold that one into its bucket instead of losing it.
    fn record_floor(&mut self, sender: [u8; 32], floor: u64, now_ms: u64) {
        if !self.evicted.contains_key(&sender)
            && self.evicted.is_full()
            && let Some((old, (old_floor, _))) = self.evicted.pop_oldest()
        {
            let idx = self.bucket(&old);
            let b = &mut self.buckets[idx];
            *b = (*b).max(old_floor);
        }
        self.evicted.insert(sender, (floor, now_ms));
    }

    /// Check freshness/ordering/uniqueness and, on success, record the message. Does NOT verify
    /// the signature — call [`SignedMessage::validate_stateless`] first.
    pub fn accept(&mut self, msg: &SignedMessage, now_ms: u64) -> Result<(), MsgError> {
        if msg.timestamp > now_ms.saturating_add(MAX_FUTURE_MS)
            || now_ms.saturating_sub(msg.timestamp) > self.skew_ms
        {
            return Err(MsgError::Timestamp);
        }
        // Expire state that can no longer matter: a message accepted at `t` carries a timestamp
        // within `t ± skew`, so after `t + 2·skew` every replay of it fails the timestamp check.
        let retain = self.skew_ms.saturating_mul(2);
        self.seen
            .expire_oldest_while(|&t| now_ms.saturating_sub(t) > retain);
        self.senders
            .expire_oldest_while(|w| now_ms.saturating_sub(w.last_ms) > retain);
        self.evicted
            .expire_oldest_while(|&(_, at)| now_ms.saturating_sub(at) > retain);

        let id = msg.message_id();
        if self.seen.contains_key(&id) {
            return Err(MsgError::Duplicate);
        }
        if let Some(w) = self.senders.get(&msg.sender)
            && (msg.seqno <= w.floor
                || w.recent.contains(&msg.seqno)
                || msg.timestamp <= w.ts_floor)
        {
            return Err(MsgError::Replay);
        }
        // Fail closed: everything left after expiry is still inside its replay-relevant lifetime.
        // Evicting it to make room would let a flood of fresh identities push out a victim's
        // window (or a message id) and then replay the victim's message. Drop the newcomer instead;
        // state frees itself `2·skew` later.
        // A sender we don't track may be one whose window was evicted for space: its messages up
        // to that window's highest timestamp might be replays, so refuse them (Ignore). Floors are
        // exact per sender; only if that table overflows with LIVE floors is the evicted floor
        // folded into a hashed bucket (shared with ~1/FLOOR_BUCKETS of senders) — so no floor is ever
        // dropped (replays stay closed) and, because timestamps are capped at now + MAX_FUTURE_MS, a
        // folded floor can delay a colliding newcomer by at most MAX_FUTURE_MS.
        if !self.senders.contains_key(&msg.sender) {
            let floor = self.floor_of(&msg.sender);
            if msg.timestamp <= floor {
                return Err(MsgError::Replay);
            }
            if self.senders.is_full()
                && let Some((k, evicted)) = self.senders.pop_oldest()
            {
                self.record_floor(k, evicted.max_ts, now_ms);
            }
        }
        let inherited_floor = self.floor_of(&msg.sender);
        self.evicted.remove(&msg.sender);
        // Accept: record the seqno in the sender's window and slide it.
        let window_us = self.skew_ms.saturating_mul(1000);
        let w = self
            .senders
            .touch_or_insert_with(msg.sender, || SenderWindow {
                floor: 0,
                high: 0,
                recent: BTreeSet::new(),
                last_ms: now_ms,
                max_ts: 0,
                ts_floor: inherited_floor,
            });
        w.last_ms = now_ms;
        w.max_ts = w.max_ts.max(msg.timestamp);
        w.recent.insert(msg.seqno);
        w.high = w.high.max(msg.seqno);
        let slide_to = w.high.saturating_sub(window_us);
        if slide_to > w.floor {
            w.floor = slide_to;
            w.recent = w.recent.split_off(&(slide_to + 1));
        }
        while w.recent.len() > REPLAY_WINDOW_SEQNOS {
            if let Some(oldest) = w.recent.pop_first() {
                w.floor = w.floor.max(oldest);
            }
        }
        self.seen.insert(id, now_ms);
        Ok(())
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        ReplayGuard::new(DEFAULT_SKEW_MS, DEFAULT_DEDUP_CAP)
    }
}

/// Full validation pipeline at the network-wide [`MIN_SENDER_POW_BITS`]: stateless checks then
/// stateful anti-replay. Returns the sender PeerId.
pub fn validate(
    msg: &SignedMessage,
    guard: &mut ReplayGuard,
    now_ms: u64,
) -> Result<PeerId, MsgError> {
    validate_with_pow(msg, guard, now_ms, MIN_SENDER_POW_BITS)
}

/// [`validate`] with an explicit sender-PoW difficulty. **Tests / isolated devnets only**: a node
/// accepting less than its peers relays messages they `Reject`, and gets penalized for it.
pub fn validate_with_pow(
    msg: &SignedMessage,
    guard: &mut ReplayGuard,
    now_ms: u64,
    min_pow_bits: u32,
) -> Result<PeerId, MsgError> {
    let peer = msg.validate_stateless_with_pow(min_pow_bits)?;
    guard.accept(msg, now_ms)?;
    Ok(peer)
}

/// [`validate`] plus topic binding: the signed `msg.topic` must equal the (unauthenticated)
/// gossipsub topic it was delivered on, so a valid message can't be replayed into another topic.
pub fn validate_on_topic(
    msg: &SignedMessage,
    delivered_topic: &str,
    guard: &mut ReplayGuard,
    now_ms: u64,
) -> Result<PeerId, MsgError> {
    validate_on_topic_with_pow(msg, delivered_topic, guard, now_ms, MIN_SENDER_POW_BITS)
}

/// [`validate_on_topic`] with an explicit sender-PoW difficulty (tests / devnets only, see
/// [`validate_with_pow`]).
pub fn validate_on_topic_with_pow(
    msg: &SignedMessage,
    delivered_topic: &str,
    guard: &mut ReplayGuard,
    now_ms: u64,
    min_pow_bits: u32,
) -> Result<PeerId, MsgError> {
    if msg.topic != delivered_topic {
        return Err(MsgError::TopicMismatch);
    }
    validate_with_pow(msg, guard, now_ms, min_pow_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests exercise the replay/format logic with cheap identities: 8-bit PoW (~256 hashes).
    /// The network minimum itself is covered by `network_minimum_pow_*` with pre-mined identities.
    const TEST_POW: u32 = 8;

    /// Least nonce meeting [`TEST_POW`] for `id` (deterministic).
    fn test_nonce(id: &NodeIdentity) -> u64 {
        let key = id.verifying_key().to_bytes();
        (0u64..)
            .find(|&n| pow::verify_identity(&key, n, TEST_POW))
            .unwrap()
    }

    /// Sign with a valid (test-difficulty) identity PoW.
    fn signed(
        id: &NodeIdentity,
        topic: &str,
        payload: Vec<u8>,
        seqno: u64,
        ts: u64,
    ) -> SignedMessage {
        SignedMessage::create_with_pow(id, test_nonce(id), topic, payload, seqno, ts)
    }

    fn tv(msg: &SignedMessage, g: &mut ReplayGuard, now_ms: u64) -> Result<PeerId, MsgError> {
        validate_with_pow(msg, g, now_ms, TEST_POW)
    }

    fn tvt(
        msg: &SignedMessage,
        topic: &str,
        g: &mut ReplayGuard,
        now_ms: u64,
    ) -> Result<PeerId, MsgError> {
        validate_on_topic_with_pow(msg, topic, g, now_ms, TEST_POW)
    }

    fn msg(seed: u8, seqno: u64, ts: u64, payload: &[u8]) -> (SignedMessage, NodeIdentity) {
        let id = NodeIdentity::from_seed(&[seed; 32]);
        (
            signed(&id, "uber-mesh/news", payload.to_vec(), seqno, ts),
            id,
        )
    }

    /// Identities pre-mined at the network minimum (least nonce, one worker), so tests can check
    /// the real [`MIN_SENDER_POW_BITS`] without mining 2^24 hashes in a debug build.
    const MINED: [(u8, u64); 2] = [(0x24, 18_566_826), (0x25, 76_581_304)];

    fn mined(i: usize) -> (NodeIdentity, u64) {
        let (seed, nonce) = MINED[i];
        (NodeIdentity::from_seed(&[seed; 32]), nonce)
    }

    #[test]
    fn network_minimum_pow_is_accepted() {
        assert_eq!(
            MIN_SENDER_POW_BITS, 24,
            "update MINED when the network minimum changes"
        );
        for i in 0..MINED.len() {
            let (id, nonce) = mined(i);
            let m = SignedMessage::create_with_pow(&id, nonce, "t", b"x".to_vec(), 1, 1000);
            assert_eq!(m.validate_stateless(), Ok(id.peer_id()));
            let mut g = ReplayGuard::default();
            assert_eq!(validate(&m, &mut g, 1000), Ok(id.peer_id()));
            let back = SignedMessage::decode(&m.encode()).unwrap();
            assert_eq!(back.pow_nonce, nonce);
            assert_eq!(
                validate_on_topic(&back, "t", &mut g, 1000),
                Err(MsgError::Duplicate)
            );
        }
    }

    /// Regression: a message without proof-of-work (nonce 0 / `create`) is provably invalid.
    #[test]
    fn message_without_pow_is_rejected() {
        let (id, _) = mined(0);
        let m = SignedMessage::create(&id, "t", b"x".to_vec(), 1, 1000);
        assert_eq!(m.pow_nonce, 0);
        assert!(pow::identity_pow_bits(&m.sender_key, 0) < MIN_SENDER_POW_BITS);
        assert_eq!(m.validate_stateless(), Err(MsgError::InsufficientPow));
        let mut g = ReplayGuard::default();
        assert_eq!(validate(&m, &mut g, 1000), Err(MsgError::InsufficientPow));
        assert!(
            MsgError::InsufficientPow.is_invalid(),
            "Reject (forwarder penalized)"
        );
        assert_eq!(
            g.tracked_senders(),
            0,
            "rejected before touching replay state"
        );
    }

    /// Regression: work below the network minimum is rejected even though it is valid PoW at a
    /// lower difficulty; it passes only where that lower difficulty is explicitly configured.
    #[test]
    fn insufficient_pow_is_rejected() {
        let id = NodeIdentity::from_seed(&[0x31; 32]);
        let key = id.verifying_key().to_bytes();
        let weak = (0u64..)
            .find(|&n| {
                let b = pow::identity_pow_bits(&key, n);
                (TEST_POW..MIN_SENDER_POW_BITS).contains(&b)
            })
            .unwrap();
        let m = SignedMessage::create_with_pow(&id, weak, "t", b"x".to_vec(), 1, 1000);
        assert_eq!(m.validate_stateless(), Err(MsgError::InsufficientPow));
        assert_eq!(m.validate_stateless_with_pow(TEST_POW), Ok(id.peer_id()));
        let mut g = ReplayGuard::default();
        assert_eq!(
            validate_on_topic(&m, "t", &mut g, 1000),
            Err(MsgError::InsufficientPow)
        );
    }

    /// Regression: a nonce is bound to the key it was mined for — B re-signing a message with A's
    /// valid nonce is rejected, and swapping the nonce of a signed message breaks the signature.
    #[test]
    fn swapped_nonce_is_rejected() {
        let ((a, a_nonce), (b, b_nonce)) = (mined(0), mined(1));
        assert!(!pow::verify_identity(
            &b.verifying_key().to_bytes(),
            a_nonce,
            MIN_SENDER_POW_BITS
        ));
        // B claims A's work (correctly signed by B): the work does not bind to B's key.
        let stolen = SignedMessage::create_with_pow(&b, a_nonce, "t", b"x".to_vec(), 1, 1000);
        assert_eq!(stolen.validate_stateless(), Err(MsgError::InsufficientPow));
        // A forwarder swaps the nonce field of B's genuine message for A's: not B's work.
        let mut swapped = SignedMessage::create_with_pow(&b, b_nonce, "t", b"x".to_vec(), 1, 1000);
        assert!(swapped.validate_stateless().is_ok());
        swapped.pow_nonce = a_nonce;
        assert_eq!(swapped.validate_stateless(), Err(MsgError::InsufficientPow));
        // Swapping in a *different valid* nonce for the same key is caught by the signature.
        let key = a.verifying_key().to_bytes();
        let n1 = test_nonce(&a);
        let n2 = (n1 + 1..)
            .find(|&n| pow::verify_identity(&key, n, TEST_POW))
            .unwrap();
        let mut m = SignedMessage::create_with_pow(&a, n1, "t", b"x".to_vec(), 1, 1000);
        m.pow_nonce = n2;
        assert_eq!(
            m.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::Signature)
        );
        // Same through the wire encoding: flip a nonce byte in the canonical bytes.
        let mut bytes = SignedMessage::create_with_pow(&a, a_nonce, "t", vec![1], 1, 1000).encode();
        let nonce_at = 1 + 2 + 1 + 32 + 32; // version, topic_len, "t", sender, sender_key
        assert_eq!(bytes[nonce_at..nonce_at + 8], a_nonce.to_le_bytes());
        bytes[nonce_at] ^= 1;
        let m = SignedMessage::decode(&bytes).unwrap();
        assert!(matches!(
            m.validate_stateless(),
            Err(MsgError::InsufficientPow | MsgError::Signature)
        ));
    }

    /// The v2 format bump: a v1 (pre-PoW) message — or any other version — is ignored, never
    /// rejected, so peers on different releases do not penalize each other.
    #[test]
    fn old_version_is_ignored_not_rejected() {
        assert_eq!(MSG_VERSION, 2);
        let (m, _) = msg(1, 1, 1000, b"x");
        let mut v1 = m.encode();
        v1[0] = 1;
        assert_eq!(SignedMessage::decode(&v1), Err(MsgError::Version));
        assert!(!MsgError::Version.is_invalid());
        // A genuine v1 layout (no nonce field) is ignored the same way.
        let mut legacy = vec![1u8];
        legacy.extend_from_slice(&m.encode()[1..]);
        legacy.drain(1 + 2 + m.topic.len() + 64..1 + 2 + m.topic.len() + 72);
        assert_eq!(SignedMessage::decode(&legacy), Err(MsgError::Version));
        // v3 is the sealed envelope (0.10): not an unknown version. v4+ is.
        let mut v4 = m.encode();
        v4[0] = SEALED_MSG_VERSION + 1;
        assert_eq!(SignedMessage::decode(&v4), Err(MsgError::Version));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (m, _) = msg(1, 7, 1000, b"hello");
        let bytes = m.encode();
        let back = SignedMessage::decode(&bytes).unwrap();
        assert_eq!(m, back);
        assert_eq!(back.message_id(), m.message_id());
    }

    #[test]
    fn valid_message_accepts_once() {
        let (m, id) = msg(2, 1, 1000, b"x");
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 16);
        let peer = tv(&m, &mut g, 1000).unwrap();
        assert_eq!(peer, id.peer_id());
        // Replaying the exact message is a duplicate.
        assert_eq!(tv(&m, &mut g, 1000), Err(MsgError::Duplicate));
    }

    #[test]
    fn tampered_payload_rejected() {
        let (mut m, _) = msg(3, 1, 1000, b"x");
        m.payload = b"y".to_vec();
        assert_eq!(
            m.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::PayloadHash)
        );
    }

    #[test]
    fn forged_sender_rejected() {
        let (mut m, _) = msg(4, 1, 1000, b"x");
        m.sender[0] ^= 0xff; // claim a different PeerId
        assert_eq!(
            m.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::IdentityBinding)
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let (mut m, _) = msg(5, 1, 1000, b"x");
        m.sig[0] ^= 0xff;
        assert_eq!(
            m.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::Signature)
        );
    }

    #[test]
    fn non_monotonic_seqno_rejected() {
        let id = NodeIdentity::from_seed(&[6; 32]);
        let m1 = signed(&id, "t", b"a".to_vec(), 5, 1000);
        let m2 = signed(&id, "t", b"b".to_vec(), 5, 1001); // same seqno
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 16);
        assert!(tv(&m1, &mut g, 1000).is_ok());
        assert_eq!(tv(&m2, &mut g, 1001), Err(MsgError::Replay));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (m, _) = msg(7, 1, 1000, b"x");
        let mut g = ReplayGuard::new(1000, 16); // 1s window
        assert_eq!(tv(&m, &mut g, 1_000_000), Err(MsgError::Timestamp));
    }

    /// Audit regression (msgid collision): a re-signed copy with a swapped payload used to share
    /// the genuine message's id (the id excluded the payload), poisoning gossipsub's dedup cache.
    #[test]
    fn message_id_covers_payload() {
        let (genuine, _) = msg(8, 1, 1000, b"genuine");
        let mut evil = genuine.clone();
        evil.payload = b"garbage".to_vec(); // payload_hash + sig untouched
        assert_ne!(evil.message_id(), genuine.message_id());
        assert_eq!(
            evil.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::PayloadHash)
        );
        // The gossipsub id fn and the typed id agree on canonical bytes.
        assert_eq!(message_id_of(&genuine.encode()), genuine.message_id());
    }

    #[test]
    fn topic_must_match_delivery_topic() {
        let (m, _) = msg(9, 1, 1000, b"x"); // signed for "uber-mesh/news"
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 16);
        assert_eq!(
            tvt(&m, "uber-mesh/other", &mut g, 1000),
            Err(MsgError::TopicMismatch)
        );
        assert!(MsgError::TopicMismatch.is_invalid());
        // A mismatch must not consume replay state: the genuine delivery still validates.
        assert!(tvt(&m, "uber-mesh/news", &mut g, 1000).is_ok());
    }

    #[test]
    fn replays_and_duplicates_are_ignored_not_penalized() {
        assert!(!MsgError::Replay.is_invalid());
        assert!(!MsgError::Duplicate.is_invalid());
        assert!(!MsgError::Timestamp.is_invalid());
        assert!(!MsgError::Version.is_invalid());
        assert!(MsgError::Signature.is_invalid());
        assert!(MsgError::PayloadHash.is_invalid());
        assert!(MsgError::IdentityBinding.is_invalid());
        assert!(MsgError::Malformed.is_invalid());
        assert!(MsgError::InsufficientPow.is_invalid());
    }

    /// Audit regression: a strict high-water mark dropped legitimately reordered messages.
    #[test]
    fn reordered_messages_accepted_once() {
        let id = NodeIdentity::from_seed(&[10; 32]);
        let late = signed(&id, "t", b"a".to_vec(), 9_000, 1000);
        let early = signed(&id, "t", b"b".to_vec(), 10_000, 1000);
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 16);
        assert!(tv(&early, &mut g, 1000).is_ok());
        assert!(tv(&late, &mut g, 1000).is_ok(), "reordered delivery");
        // Re-signed copy of an accepted seqno (different payload ⇒ different id) is a replay.
        let again = signed(&id, "t", b"c".to_vec(), 9_000, 1001);
        assert_eq!(tv(&again, &mut g, 1001), Err(MsgError::Replay));
    }

    #[test]
    fn window_floor_rejects_evicted_seqnos() {
        let id = NodeIdentity::from_seed(&[11; 32]);
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 4096);
        for s in 1..=(REPLAY_WINDOW_SEQNOS as u64 + 10) {
            let m = signed(&id, "t", s.to_le_bytes().to_vec(), s, 1000);
            assert!(tv(&m, &mut g, 1000).is_ok());
        }
        // Seqno 1 fell out of the remembered set; the floor must still reject a re-signed copy.
        let old = signed(&id, "t", b"replay".to_vec(), 1, 1000);
        assert_eq!(tv(&old, &mut g, 1000), Err(MsgError::Replay));
        // Seqnos far behind the highest one (beyond the skew window, in µs) are stale.
        let hi = signed(&id, "t", b"hi".to_vec(), 10_000_000_000, 1000);
        assert!(tv(&hi, &mut g, 1000).is_ok());
        let stale = signed(&id, "t", b"st".to_vec(), 5_000_000, 1000);
        assert_eq!(tv(&stale, &mut g, 1000), Err(MsgError::Replay));
    }

    #[test]
    fn restarted_sender_with_time_based_seqno_is_accepted() {
        let id = NodeIdentity::from_seed(&[12; 32]);
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 64);
        let now_us = 1_700_000_000_000_000u64;
        let now_ms = now_us / 1000;
        // Previous process run published a few messages.
        let mut last = 0;
        for i in 0..3u8 {
            last = next_seqno(last, now_us);
            let m = signed(&id, "t", vec![i], last, now_ms);
            assert!(tv(&m, &mut g, now_ms).is_ok());
        }
        // Restart: in-memory seqno state is gone (last = 0) but the clock moved on.
        let s = next_seqno(0, now_us + 2_000_000);
        let m = signed(&id, "t", b"after restart".to_vec(), s, now_ms + 2000);
        assert!(tv(&m, &mut g, now_ms + 2000).is_ok());
        assert!(next_seqno(5, 3) == 6 && next_seqno(5, 100) == 100);
    }

    #[test]
    fn per_sender_state_is_bounded_and_expires() {
        let mut g = ReplayGuard::with_limits(1000, 32, 8);
        for i in 0..100u8 {
            let id = NodeIdentity::from_seed(&[i; 32]);
            let m = signed(&id, "t", vec![i], 1, 5000 + i as u64);
            assert!(tv(&m, &mut g, 5000).is_ok());
            assert!(g.tracked_senders() <= 8 && g.tracked_ids() <= 32);
        }
        // After 2·skew everything expires on the next accept.
        let id = NodeIdentity::from_seed(&[200; 32]);
        let m = signed(&id, "t", vec![1], 1, 9000);
        assert!(tv(&m, &mut g, 9000).is_ok());
        assert_eq!((g.tracked_senders(), g.tracked_ids()), (1, 1));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(SignedMessage::decode(&[]).is_err());
        assert!(SignedMessage::decode(&[0xff; 4]).is_err());
        assert_eq!(
            SignedMessage::decode(&[MSG_VERSION, 0, 0]),
            Err(MsgError::Malformed)
        ); // version ok, truncated
    }
    /// Regression (two review rounds): (1) a fresh-identity flood used to LRU-evict a victim's replay
    /// window and replay its message; (2) a global eviction floor let future-dated attacker messages
    /// lock out every newcomer. Floors are now per evicted sender: the victim stays unreplayable,
    /// while a future-dated flood constrains only the flooding identities themselves.
    #[test]
    fn per_sender_eviction_floor_blocks_replays_without_global_lockout() {
        // Tiny dedup set too, so the victim's message-id is gone and only the floor protects.
        let mut g = ReplayGuard::with_limits(60_000, 4, 4);
        let at = |seed: u8, seqno: u64, ts: u64| msg(seed, seqno, ts, b"x").0;
        let victim = at(1, 1, 1000);
        assert!(tv(&victim, &mut g, 1000).is_ok());
        // Sybil flood, FUTURE-dated by almost the whole skew window, evicts the victim's window.
        for k in 10..20u8 {
            assert!(tv(&at(k, 1, 1000 + 29_000), &mut g, 1001 + k as u64).is_ok());
        }
        assert!(!g.tracks(&victim.sender), "premise: victim window evicted");
        // The victim's message still can't be replayed…
        assert_eq!(tv(&victim, &mut g, 1100).map(|_| ()), Err(MsgError::Replay));
        // …its old message stays refused even after it is tracked again with a fresh message…
        assert!(tv(&at(1, 2, 1200), &mut g, 1200).is_ok());
        assert_eq!(tv(&victim, &mut g, 1201).map(|_| ()), Err(MsgError::Replay));
        // …and an honest newcomer at the current time is NOT locked out by the future-dated flood.
        assert!(tv(&at(50, 1, 1300), &mut g, 1300).is_ok());
        assert!(!MsgError::Replay.is_invalid(), "never penalized");
    }

    /// Review round 4: even when the exact floor table overflows with live floors, no floor is
    /// dropped (folded into a hashed bucket), so a massive fresh-identity flood still cannot replay
    /// a victim's message.
    #[test]
    fn overflowing_floor_table_folds_instead_of_dropping() {
        let mut g = ReplayGuard::with_limits(600_000, 4, 2);
        g.evicted = BoundedMap::new(2); // tiny exact floor table to force folding
        let at = |seed: u8, seqno: u64, ts: u64| msg(seed, seqno, ts, b"x").0;
        let victim = at(1, 1, 1000);
        assert!(tv(&victim, &mut g, 1000).is_ok());
        for k in 10..60u8 {
            let ts = 1000 + k as u64;
            assert!(tv(&at(k, 1, ts), &mut g, ts).is_ok());
        }
        assert!(!g.tracks(&victim.sender) && !g.evicted.contains_key(&victim.sender));
        assert_eq!(tv(&victim, &mut g, 2000).map(|_| ()), Err(MsgError::Replay));
    }

    #[test]
    fn far_future_timestamps_are_refused() {
        let mut g = ReplayGuard::default();
        let (m, _) = msg(3, 1, 1000 + MAX_FUTURE_MS + 1, b"x");
        assert_eq!(tv(&m, &mut g, 1000).map(|_| ()), Err(MsgError::Timestamp));
        let (ok, _) = msg(4, 1, 1000 + MAX_FUTURE_MS, b"x");
        assert!(tv(&ok, &mut g, 1000).is_ok());
    }
    /// Review round 5: the fallback bucket of a sender must not be predictable from its public id
    /// (or an attacker could grind identities into a chosen victim's bucket). Two guards (= two
    /// nodes) map the same senders to unrelated buckets.
    #[test]
    fn bucket_index_is_keyed_per_node() {
        let (a, b) = (ReplayGuard::default(), ReplayGuard::default());
        let same = (0u8..64)
            .filter(|i| {
                let s = hash::hash(&[*i]);
                a.bucket(&s) == b.bucket(&s)
            })
            .count();
        assert!(same < 8, "bucket index looks unkeyed: {same}/64 identical");
        let s = hash::hash(b"sender");
        let prefix = u32::from_le_bytes(s[..4].try_into().unwrap()) as usize % FLOOR_BUCKETS;
        assert!(
            (0..8).any(|_| ReplayGuard::default().bucket(&s) != prefix),
            "bucket must not be the public-id prefix"
        );
    }
}
