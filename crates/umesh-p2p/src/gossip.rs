//! Signed gossip messages + replay protection (contracts/message-wire.md).
//!
//! Every message is authenticated to its sender and content-addressed. Validation has a stateless
//! part (identity binding, signature, payload hash) and a stateful part (monotonic per-sender seqno,
//! timestamp window, bounded dedup) — gossipsub's own dedup does NOT survive cache eviction, so the
//! monotonic seqno is enforced here at the application layer (research D10 / mesh-integrity).

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{SystemTime, UNIX_EPOCH};

use lru::LruCache;
use thiserror::Error;
use umesh_crypto::hash::{self, Hash32};
use umesh_crypto::identity::{self, NodeIdentity, PeerId};

/// Message format version.
pub const MSG_VERSION: u8 = 1;
const SIG_LABEL: &[u8] = b"uber-mesh-msg-v1";
const MSGID_LABEL: &[u8] = b"uber-mesh-msgid-v1";

/// Default acceptable clock skew for message timestamps (±5 minutes).
pub const DEFAULT_SKEW_MS: u64 = 5 * 60 * 1000;
/// Default dedup cache capacity (message-ids retained).
pub const DEFAULT_DEDUP_CAP: usize = 65536;

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
    /// `seqno <= last seen for this sender`.
    #[error("non-monotonic seqno (replay)")]
    Replay,
    /// Timestamp outside the accepted skew window.
    #[error("timestamp outside window")]
    Timestamp,
    /// Already-seen message-id.
    #[error("duplicate message")]
    Duplicate,
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
    /// Per-sender monotonic sequence number.
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

    /// Deterministic content id of this message.
    pub fn message_id(&self) -> Hash32 {
        let t = self.transcript();
        let mut buf = Vec::with_capacity(MSGID_LABEL.len() + t.len() + 64);
        buf.extend_from_slice(MSGID_LABEL);
        buf.extend_from_slice(&t);
        buf.extend_from_slice(&self.sig);
        hash::hash(&buf)
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

/// Stateful anti-replay: per-sender monotonic seqno, timestamp window, bounded message-id dedup.
pub struct ReplayGuard {
    last_seqno: HashMap<[u8; 32], u64>,
    seen: LruCache<Hash32, ()>,
    skew_ms: u64,
}

impl ReplayGuard {
    /// Create a guard with the given skew window and dedup capacity.
    pub fn new(skew_ms: u64, dedup_cap: usize) -> Self {
        ReplayGuard {
            last_seqno: HashMap::new(),
            seen: LruCache::new(NonZeroUsize::new(dedup_cap.max(1)).unwrap()),
            skew_ms,
        }
    }

    /// Check freshness/ordering/uniqueness and, on success, record the message. Does NOT verify
    /// the signature — call [`SignedMessage::validate_stateless`] first.
    pub fn accept(&mut self, msg: &SignedMessage, now_ms: u64) -> Result<(), MsgError> {
        if now_ms.abs_diff(msg.timestamp) > self.skew_ms {
            return Err(MsgError::Timestamp);
        }
        let id = msg.message_id();
        if self.seen.contains(&id) {
            return Err(MsgError::Duplicate);
        }
        if let Some(&last) = self.last_seqno.get(&msg.sender) {
            if msg.seqno <= last {
                return Err(MsgError::Replay);
            }
        }
        self.last_seqno.insert(msg.sender, msg.seqno);
        self.seen.put(id, ());
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

    #[test]
    fn decode_rejects_garbage() {
        assert!(SignedMessage::decode(&[]).is_err());
        assert!(SignedMessage::decode(&[0xff; 4]).is_err());
        assert!(SignedMessage::decode(&[1, 0, 0]).is_err()); // version ok, truncated
    }
}
