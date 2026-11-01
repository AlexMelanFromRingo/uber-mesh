//! Signed gossip messages + replay protection (contracts/message-wire.md).
//!
//! Every message is authenticated to its sender and content-addressed. Validation has a stateless
//! part (identity binding, signature, payload hash, topic binding) and a stateful part (per-sender
//! sliding replay window, timestamp window, bounded dedup) — gossipsub's own dedup does NOT survive
//! cache eviction, so replay protection is enforced here at the application layer (research D10 /
//! mesh-integrity). All stateful structures are bounded and expire, since remote peers pick the keys.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use umesh_crypto::hash::{self, Hash32};
use umesh_crypto::identity::{self, NodeIdentity, PeerId};

use crate::bounded::BoundedMap;

/// Message format version.
pub const MSG_VERSION: u8 = 1;
const SIG_LABEL: &[u8] = b"uber-mesh-msg-v1";
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedMessage {
    /// Topic id.
    pub topic: String,
    /// Sender PeerId (`BLAKE3(sender_key)`).
    pub sender: [u8; 32],
    /// Sender Ed25519 verifying key.
    pub sender_key: [u8; 32],
    /// Per-sender sequence number (time-based: `max(last + 1, now_µs)`).
    pub seqno: u64,
    /// Unix-millis timestamp.
    pub timestamp: u64,
    /// `BLAKE3(payload)`.
    pub payload_hash: Hash32,
    /// Application payload.
    pub payload: Vec<u8>,
    /// Ed25519 signature over the transcript.
    pub sig: [u8; 64],
}

fn transcript(
    topic: &str,
    sender: &[u8; 32],
    sender_key: &[u8; 32],
    seqno: u64,
    timestamp: u64,
    payload_hash: &Hash32,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(SIG_LABEL.len() + 2 + topic.len() + 32 + 32 + 8 + 8 + 32);
    t.extend_from_slice(SIG_LABEL);
    t.extend_from_slice(&(topic.len() as u16).to_le_bytes());
    t.extend_from_slice(topic.as_bytes());
    t.extend_from_slice(sender);
    t.extend_from_slice(sender_key);
    t.extend_from_slice(&seqno.to_le_bytes());
    t.extend_from_slice(&timestamp.to_le_bytes());
    t.extend_from_slice(payload_hash);
    t
}

impl SignedMessage {
    /// Build and sign a message from this node's identity.
    pub fn create(
        id: &NodeIdentity,
        topic: &str,
        payload: Vec<u8>,
        seqno: u64,
        timestamp: u64,
    ) -> Self {
        let sender = *id.peer_id().as_bytes();
        let sender_key = id.verifying_key().to_bytes();
        let payload_hash = hash::hash(&payload);
        let t = transcript(topic, &sender, &sender_key, seqno, timestamp, &payload_hash);
        let sig = id.sign_bytes(&t);
        SignedMessage {
            topic: topic.to_string(),
            sender,
            sender_key,
            seqno,
            timestamp,
            payload_hash,
            payload,
            sig,
        }
    }

    fn transcript(&self) -> Vec<u8> {
        transcript(
            &self.topic,
            &self.sender,
            &self.sender_key,
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

    /// Stateless validation: identity binding, signature, payload hash. Returns the bound PeerId.
    pub fn validate_stateless(&self) -> Result<PeerId, MsgError> {
        if hash::hash(&self.sender_key) != self.sender {
            return Err(MsgError::IdentityBinding);
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
            1 + 2 + self.topic.len() + 32 + 32 + 8 + 8 + 32 + 4 + self.payload.len() + 64,
        );
        out.push(MSG_VERSION);
        out.extend_from_slice(&(self.topic.len() as u16).to_le_bytes());
        out.extend_from_slice(self.topic.as_bytes());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.sender_key);
        out.extend_from_slice(&self.seqno.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.sig);
        out
    }

    /// Parse a message from its canonical encoding. Never panics on arbitrary input.
    pub fn decode(buf: &[u8]) -> Result<Self, MsgError> {
        let mut c = Cursor { buf, pos: 0 };
        let v = c.u8()?;
        if v != MSG_VERSION {
            return Err(MsgError::Version);
        }
        let topic_len = c.u16()? as usize;
        let topic =
            String::from_utf8(c.take(topic_len)?.to_vec()).map_err(|_| MsgError::Malformed)?;
        let sender = c.arr32()?;
        let sender_key = c.arr32()?;
        let seqno = c.u64()?;
        let timestamp = c.u64()?;
        let payload_hash = c.arr32()?;
        let payload_len = c.u32()? as usize;
        let payload = c.take(payload_len)?.to_vec();
        let sig = c.arr64()?;
        if c.pos != buf.len() {
            return Err(MsgError::Malformed); // trailing bytes
        }
        Ok(SignedMessage {
            topic,
            sender,
            sender_key,
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

    fn bucket(sender: &[u8; 32]) -> usize {
        // `sender` is a BLAKE3 hash, so its bytes are already uniform.
        u32::from_le_bytes(sender[..4].try_into().expect("4 bytes")) as usize % FLOOR_BUCKETS
    }

    /// Replay floor for an untracked sender: its exact floor, else its bucket's folded floor.
    fn floor_of(&self, sender: &[u8; 32]) -> u64 {
        let exact = self.evicted.get(sender).map(|&(f, _)| f).unwrap_or(0);
        exact.max(self.buckets[Self::bucket(sender)])
    }

    /// Remember an evicted window's floor; if the exact table must drop a still-live floor to make
    /// room, fold that one into its bucket instead of losing it.
    fn record_floor(&mut self, sender: [u8; 32], floor: u64, now_ms: u64) {
        if !self.evicted.contains_key(&sender)
            && self.evicted.is_full()
            && let Some((old, (old_floor, _))) = self.evicted.pop_oldest()
        {
            let b = &mut self.buckets[Self::bucket(&old)];
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

/// Full validation pipeline: stateless checks then stateful anti-replay. Returns the sender PeerId.
pub fn validate(
    msg: &SignedMessage,
    guard: &mut ReplayGuard,
    now_ms: u64,
) -> Result<PeerId, MsgError> {
    let peer = msg.validate_stateless()?;
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
    if msg.topic != delivered_topic {
        return Err(MsgError::TopicMismatch);
    }
    validate(msg, guard, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(seed: u8, seqno: u64, ts: u64, payload: &[u8]) -> (SignedMessage, NodeIdentity) {
        let id = NodeIdentity::from_seed(&[seed; 32]);
        (
            SignedMessage::create(&id, "uber-mesh/news", payload.to_vec(), seqno, ts),
            id,
        )
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
        let peer = validate(&m, &mut g, 1000).unwrap();
        assert_eq!(peer, id.peer_id());
        // Replaying the exact message is a duplicate.
        assert_eq!(validate(&m, &mut g, 1000), Err(MsgError::Duplicate));
    }

    #[test]
    fn tampered_payload_rejected() {
        let (mut m, _) = msg(3, 1, 1000, b"x");
        m.payload = b"y".to_vec();
        assert_eq!(m.validate_stateless(), Err(MsgError::PayloadHash));
    }

    #[test]
    fn forged_sender_rejected() {
        let (mut m, _) = msg(4, 1, 1000, b"x");
        m.sender[0] ^= 0xff; // claim a different PeerId
        assert_eq!(m.validate_stateless(), Err(MsgError::IdentityBinding));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (mut m, _) = msg(5, 1, 1000, b"x");
        m.sig[0] ^= 0xff;
        assert_eq!(m.validate_stateless(), Err(MsgError::Signature));
    }

    #[test]
    fn non_monotonic_seqno_rejected() {
        let id = NodeIdentity::from_seed(&[6; 32]);
        let m1 = SignedMessage::create(&id, "t", b"a".to_vec(), 5, 1000);
        let m2 = SignedMessage::create(&id, "t", b"b".to_vec(), 5, 1001); // same seqno
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 16);
        assert!(validate(&m1, &mut g, 1000).is_ok());
        assert_eq!(validate(&m2, &mut g, 1001), Err(MsgError::Replay));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (m, _) = msg(7, 1, 1000, b"x");
        let mut g = ReplayGuard::new(1000, 16); // 1s window
        assert_eq!(validate(&m, &mut g, 1_000_000), Err(MsgError::Timestamp));
    }

    /// Audit regression (msgid collision): a re-signed copy with a swapped payload used to share
    /// the genuine message's id (the id excluded the payload), poisoning gossipsub's dedup cache.
    #[test]
    fn message_id_covers_payload() {
        let (genuine, _) = msg(8, 1, 1000, b"genuine");
        let mut evil = genuine.clone();
        evil.payload = b"garbage".to_vec(); // payload_hash + sig untouched
        assert_ne!(evil.message_id(), genuine.message_id());
        assert_eq!(evil.validate_stateless(), Err(MsgError::PayloadHash));
        // The gossipsub id fn and the typed id agree on canonical bytes.
        assert_eq!(message_id_of(&genuine.encode()), genuine.message_id());
    }

    #[test]
    fn topic_must_match_delivery_topic() {
        let (m, _) = msg(9, 1, 1000, b"x"); // signed for "uber-mesh/news"
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 16);
        assert_eq!(
            validate_on_topic(&m, "uber-mesh/other", &mut g, 1000),
            Err(MsgError::TopicMismatch)
        );
        assert!(MsgError::TopicMismatch.is_invalid());
        // A mismatch must not consume replay state: the genuine delivery still validates.
        assert!(validate_on_topic(&m, "uber-mesh/news", &mut g, 1000).is_ok());
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
    }

    /// Audit regression: a strict high-water mark dropped legitimately reordered messages.
    #[test]
    fn reordered_messages_accepted_once() {
        let id = NodeIdentity::from_seed(&[10; 32]);
        let late = SignedMessage::create(&id, "t", b"a".to_vec(), 9_000, 1000);
        let early = SignedMessage::create(&id, "t", b"b".to_vec(), 10_000, 1000);
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 16);
        assert!(validate(&early, &mut g, 1000).is_ok());
        assert!(validate(&late, &mut g, 1000).is_ok(), "reordered delivery");
        // Re-signed copy of an accepted seqno (different payload ⇒ different id) is a replay.
        let again = SignedMessage::create(&id, "t", b"c".to_vec(), 9_000, 1001);
        assert_eq!(validate(&again, &mut g, 1001), Err(MsgError::Replay));
    }

    #[test]
    fn window_floor_rejects_evicted_seqnos() {
        let id = NodeIdentity::from_seed(&[11; 32]);
        let mut g = ReplayGuard::new(DEFAULT_SKEW_MS, 4096);
        for s in 1..=(REPLAY_WINDOW_SEQNOS as u64 + 10) {
            let m = SignedMessage::create(&id, "t", s.to_le_bytes().to_vec(), s, 1000);
            assert!(validate(&m, &mut g, 1000).is_ok());
        }
        // Seqno 1 fell out of the remembered set; the floor must still reject a re-signed copy.
        let old = SignedMessage::create(&id, "t", b"replay".to_vec(), 1, 1000);
        assert_eq!(validate(&old, &mut g, 1000), Err(MsgError::Replay));
        // Seqnos far behind the highest one (beyond the skew window, in µs) are stale.
        let hi = SignedMessage::create(&id, "t", b"hi".to_vec(), 10_000_000_000, 1000);
        assert!(validate(&hi, &mut g, 1000).is_ok());
        let stale = SignedMessage::create(&id, "t", b"st".to_vec(), 5_000_000, 1000);
        assert_eq!(validate(&stale, &mut g, 1000), Err(MsgError::Replay));
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
            let m = SignedMessage::create(&id, "t", vec![i], last, now_ms);
            assert!(validate(&m, &mut g, now_ms).is_ok());
        }
        // Restart: in-memory seqno state is gone (last = 0) but the clock moved on.
        let s = next_seqno(0, now_us + 2_000_000);
        let m = SignedMessage::create(&id, "t", b"after restart".to_vec(), s, now_ms + 2000);
        assert!(validate(&m, &mut g, now_ms + 2000).is_ok());
        assert!(next_seqno(5, 3) == 6 && next_seqno(5, 100) == 100);
    }

    #[test]
    fn per_sender_state_is_bounded_and_expires() {
        let mut g = ReplayGuard::with_limits(1000, 32, 8);
        for i in 0..100u8 {
            let id = NodeIdentity::from_seed(&[i; 32]);
            let m = SignedMessage::create(&id, "t", vec![i], 1, 5000 + i as u64);
            assert!(validate(&m, &mut g, 5000).is_ok());
            assert!(g.tracked_senders() <= 8 && g.tracked_ids() <= 32);
        }
        // After 2·skew everything expires on the next accept.
        let id = NodeIdentity::from_seed(&[200; 32]);
        let m = SignedMessage::create(&id, "t", vec![1], 1, 9000);
        assert!(validate(&m, &mut g, 9000).is_ok());
        assert_eq!((g.tracked_senders(), g.tracked_ids()), (1, 1));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(SignedMessage::decode(&[]).is_err());
        assert!(SignedMessage::decode(&[0xff; 4]).is_err());
        assert!(SignedMessage::decode(&[1, 0, 0]).is_err()); // version ok, truncated
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
        assert!(validate(&victim, &mut g, 1000).is_ok());
        // Sybil flood, FUTURE-dated by almost the whole skew window, evicts the victim's window.
        for k in 10..20u8 {
            assert!(validate(&at(k, 1, 1000 + 29_000), &mut g, 1001 + k as u64).is_ok());
        }
        assert!(!g.tracks(&victim.sender), "premise: victim window evicted");
        // The victim's message still can't be replayed…
        assert_eq!(
            validate(&victim, &mut g, 1100).map(|_| ()),
            Err(MsgError::Replay)
        );
        // …its old message stays refused even after it is tracked again with a fresh message…
        assert!(validate(&at(1, 2, 1200), &mut g, 1200).is_ok());
        assert_eq!(
            validate(&victim, &mut g, 1201).map(|_| ()),
            Err(MsgError::Replay)
        );
        // …and an honest newcomer at the current time is NOT locked out by the future-dated flood.
        assert!(validate(&at(50, 1, 1300), &mut g, 1300).is_ok());
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
        assert!(validate(&victim, &mut g, 1000).is_ok());
        for k in 10..60u8 {
            let ts = 1000 + k as u64;
            assert!(validate(&at(k, 1, ts), &mut g, ts).is_ok());
        }
        assert!(!g.tracks(&victim.sender) && !g.evicted.contains_key(&victim.sender));
        assert_eq!(
            validate(&victim, &mut g, 2000).map(|_| ()),
            Err(MsgError::Replay)
        );
    }

    #[test]
    fn far_future_timestamps_are_refused() {
        let mut g = ReplayGuard::default();
        let (m, _) = msg(3, 1, 1000 + MAX_FUTURE_MS + 1, b"x");
        assert_eq!(
            validate(&m, &mut g, 1000).map(|_| ()),
            Err(MsgError::Timestamp)
        );
        let (ok, _) = msg(4, 1, 1000 + MAX_FUTURE_MS, b"x");
        assert!(validate(&ok, &mut g, 1000).is_ok());
    }
}
