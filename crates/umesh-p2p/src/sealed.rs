//! End-to-end payload confidentiality: **sealed topics** and **encrypted blobs**
//! (contracts/message-wire.md "Sealed messages (v3)").
//!
//! The links themselves are already encrypted hop by hop (obfs + Noise), but every gossip forwarder
//! and every content-serving peer is an endpoint of those links. Sealing makes the *payload*
//! unreadable to them:
//!
//! - **Sealed topic.** A topic may carry a 32-byte [`TopicKey`], distributed out of band like the
//!   bridge PSK. Its messages are format v3: the payload is
//!   `nonce(24) ‖ XChaCha20-Poly1305(plaintext) ‖ tag(16)` under a per-epoch key derived from the
//!   topic key and the topic name, with associated data binding `(version, topic, sender, seqno,
//!   timestamp)` — a ciphertext cannot be moved to another topic, sender or message. The signature
//!   covers the ciphertext, so a forwarder **without** the key still validates identity, PoW,
//!   signature and replay state and forwards the message; it never delivers it. Topics without a key
//!   stay **public** (format v2, readable by every forwarding peer) exactly as before.
//! - **Encrypted blob.** Content shared in a sealed topic is encrypted under a fresh random
//!   [`ContentKey`]; its `Cid` is computed over the **ciphertext**, so storing/serving peers verify
//!   integrity and serve it without being able to read it. `(cid, content_key)` travels inside a
//!   sealed message ([`SealedPayload::Blob`]).
//!
//! Key epochs: the AEAD key for a message is `K_epoch = derive_key(TOPIC_EPOCH_KEY, root ‖ epoch)`
//! with `epoch = timestamp_ms / EPOCH_MS` (daily) of the *signed* timestamp. Because accepted
//! timestamps are within `now − 5 min … now + 30 s`, a receiver only ever needs the current and the
//! previous epoch key. This is key separation, **not forward secrecy**: whoever holds the topic key
//! can derive every epoch key, past and future (see `docs/security-and-deferred.md`).
//!
//! Secrets ([`TopicKey`], [`SealedTopic`], [`ContentKey`], derived AEAD keys, decrypted plaintext
//! buffers) are zeroized on drop and never `Debug`-printed.

use core::fmt;

use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use thiserror::Error;
use umesh_crypto::aead::{self, AeadKey, NONCE_LEN, TAG_LEN};
use umesh_crypto::hash::{self, Cid, labels};
use umesh_crypto::identity::NodeIdentity;
use zeroize::Zeroizing;

use crate::blobs::MAX_BLOB;
use crate::gossip::{SEALED_MSG_VERSION, SignedMessage};

/// Topic-key epoch length: one day, in milliseconds of the message's signed timestamp.
pub const EPOCH_MS: u64 = 86_400_000;
/// Domain label prefixed to the associated data of a sealed gossip message.
const MSG_AAD_LABEL: &[u8] = b"uber-mesh v1 sealed message";
/// Associated data of a sealed blob (the content key is single-use; the label separates domains).
pub const BLOB_AAD: &[u8] = b"uber-mesh v1 sealed blob";
/// Largest plaintext that seals into a servable blob (`MAX_BLOB` minus nonce and tag).
pub const MAX_SEALED_BLOB_PLAINTEXT: usize = MAX_BLOB - NONCE_LEN - TAG_LEN;

/// Inner-payload kind byte: application data.
const KIND_DATA: u8 = 0x00;
/// Inner-payload kind byte: reference to an encrypted blob.
const KIND_BLOB: u8 = 0x01;
/// Encoded length of a [`SealedPayload::Blob`]: kind + cid + content key.
const BLOB_REF_LEN: usize = 1 + 32 + 32;

/// Why sealing or opening failed. Carries no secret material.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealError {
    /// The message is public (v2), not sealed.
    #[error("message is not sealed")]
    NotSealed,
    /// The message belongs to a different topic than the key.
    #[error("sealed message is for another topic")]
    TopicMismatch,
    /// AEAD authentication failed: wrong key, or ciphertext moved/tampered.
    #[error("sealed payload failed authentication")]
    Auth,
    /// The decrypted inner payload is not a well-formed [`SealedPayload`].
    #[error("malformed sealed payload")]
    Malformed,
    /// The fetched blob does not hash to its `Cid`.
    #[error("blob does not match its cid")]
    CidMismatch,
    /// Blob plaintext larger than [`MAX_SEALED_BLOB_PLAINTEXT`].
    #[error("blob too large to seal")]
    TooLarge,
    /// A key string is not 32 bytes of hex.
    #[error("topic key must be 32 bytes of hex")]
    BadKey,
}

/// A 32-byte topic key, shared out of band among a topic's members. Zeroized on drop; `Debug` is
/// redacted. It never encrypts anything directly — see [`SealedTopic`].
#[derive(Clone)]
pub struct TopicKey(Zeroizing<[u8; 32]>);

impl TopicKey {
    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TopicKey(Zeroizing::new(bytes))
    }

    /// A fresh random key (OS RNG).
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *k);
        TopicKey(k)
    }

    /// Parse 64 hex characters (surrounding whitespace ignored). The error never echoes the input.
    pub fn from_hex(s: &str) -> Result<Self, SealError> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(SealError::BadKey);
        }
        let mut k = Zeroizing::new([0u8; 32]);
        for (i, out) in k.iter_mut().enumerate() {
            let hi = hex_val(s.as_bytes()[2 * i]).ok_or(SealError::BadKey)?;
            let lo = hex_val(s.as_bytes()[2 * i + 1]).ok_or(SealError::BadKey)?;
            *out = (hi << 4) | lo;
        }
        Ok(TopicKey(k))
    }

    /// Lower-case hex (for writing a freshly generated key to a `0600` file). Zeroized on drop.
    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(64));
        for b in self.0.iter() {
            s.push(char::from(HEX[(b >> 4) as usize]));
            s.push(char::from(HEX[(b & 0x0f) as usize]));
        }
        s
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for TopicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TopicKey(<redacted>)")
    }
}

/// Sealing state of one topic: `root = derive_key("uber-mesh v1 topic key", topic_key ‖ topic)`.
/// Binding the topic name into the root means one key shared by two topics still yields unrelated
/// AEAD keys. Zeroized on drop; `Debug` shows only the topic name.
pub struct SealedTopic {
    topic: String,
    root: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for SealedTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedTopic")
            .field("topic", &self.topic)
            .field("root", &"<redacted>")
            .finish()
    }
}

impl SealedTopic {
    /// Bind `key` to `topic`.
    pub fn new(topic: &str, key: &TopicKey) -> Self {
        let mut ikm = Zeroizing::new(Vec::with_capacity(32 + topic.len()));
        ikm.extend_from_slice(&*key.0);
        ikm.extend_from_slice(topic.as_bytes());
        SealedTopic {
            topic: topic.to_string(),
            root: Zeroizing::new(hash::derive_key(labels::TOPIC_KEY, &ikm)),
        }
    }

    /// The topic this state seals.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// AEAD key of `epoch`: `derive_key("uber-mesh v1 topic epoch key", root ‖ u64_le(epoch))`.
    fn epoch_key(&self, epoch: u64) -> AeadKey {
        let mut ikm = Zeroizing::new([0u8; 40]);
        ikm[..32].copy_from_slice(&*self.root);
        ikm[32..].copy_from_slice(&epoch.to_le_bytes());
        AeadKey::derive(labels::TOPIC_EPOCH_KEY, &*ikm)
    }
}

/// Key epoch of a message timestamp (unix millis): daily.
pub fn epoch_of(timestamp_ms: u64) -> u64 {
    timestamp_ms / EPOCH_MS
}

/// Associated data of a sealed message:
/// `label ‖ version ‖ u16_le(topic_len) ‖ topic ‖ sender ‖ u64_le(seqno) ‖ u64_le(timestamp)`.
fn message_aad(topic: &str, sender: &[u8; 32], seqno: u64, timestamp: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(MSG_AAD_LABEL.len() + 1 + 2 + topic.len() + 32 + 16);
    a.extend_from_slice(MSG_AAD_LABEL);
    a.push(SEALED_MSG_VERSION);
    a.extend_from_slice(&(topic.len() as u16).to_le_bytes());
    a.extend_from_slice(topic.as_bytes());
    a.extend_from_slice(sender);
    a.extend_from_slice(&seqno.to_le_bytes());
    a.extend_from_slice(&timestamp.to_le_bytes());
    a
}

/// A per-blob content key (fresh, random, single-use). Zeroized on drop; `Debug` is redacted;
/// equality is constant-time.
#[derive(Clone)]
pub struct ContentKey(Zeroizing<[u8; 32]>);

impl ContentKey {
    /// A fresh random content key.
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *k);
        ContentKey(k)
    }

    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ContentKey(Zeroizing::new(bytes))
    }

    /// The raw key bytes (secret — only for re-encoding into a sealed payload).
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    fn aead(&self) -> AeadKey {
        AeadKey::from_bytes(*self.0)
    }
}

impl PartialEq for ContentKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}
impl Eq for ContentKey {}

impl fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContentKey(<redacted>)")
    }
}

/// Reference to an encrypted blob: its `Cid` (over the ciphertext — what peers store and serve) and
/// the key that decrypts it. Only ever transmitted inside a sealed message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlobRef {
    /// `Cid` of the blob **ciphertext**.
    pub cid: Cid,
    /// Key that decrypts the blob.
    pub key: ContentKey,
}

/// The plaintext inside a sealed message:
/// `0x00 ‖ application bytes` or `0x01 ‖ cid(32) ‖ content_key(32)` (exact length).
/// Unknown kinds and wrong lengths are [`SealError::Malformed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedPayload {
    /// Application data.
    Data(Vec<u8>),
    /// An encrypted blob shared in the topic.
    Blob(SealedBlobRef),
}

impl SealedPayload {
    /// Canonical encoding (zeroized on drop: it may hold a content key or private data).
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        match self {
            SealedPayload::Data(d) => {
                let mut v = Zeroizing::new(Vec::with_capacity(1 + d.len()));
                v.push(KIND_DATA);
                v.extend_from_slice(d);
                v
            }
            SealedPayload::Blob(r) => {
                let mut v = Zeroizing::new(Vec::with_capacity(BLOB_REF_LEN));
                v.push(KIND_BLOB);
                v.extend_from_slice(r.cid.as_bytes());
                v.extend_from_slice(r.key.expose());
                v
            }
        }
    }

    /// Strict parser for decrypted plaintext. Never panics; `encode(decode(b)) == b` for every
    /// accepted `b`.
    pub fn decode(buf: &[u8]) -> Result<Self, SealError> {
        match buf.split_first() {
            Some((&KIND_DATA, rest)) => Ok(SealedPayload::Data(rest.to_vec())),
            Some((&KIND_BLOB, rest)) if buf.len() == BLOB_REF_LEN => {
                let (cid, key) = rest.split_at(32);
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(key);
                Ok(SealedPayload::Blob(SealedBlobRef {
                    cid: Cid(cid.try_into().expect("32 bytes")),
                    key: ContentKey(k),
                }))
            }
            _ => Err(SealError::Malformed),
        }
    }
}

/// Seal `payload` for `topic` and sign the resulting v3 message. `seqno`/`timestamp` are chosen by
/// the caller (as for public messages) and bound into the AEAD associated data.
pub fn seal_message(
    id: &NodeIdentity,
    pow_nonce: u64,
    topic: &SealedTopic,
    payload: &SealedPayload,
    seqno: u64,
    timestamp: u64,
) -> SignedMessage {
    let sender = *id.peer_id().as_bytes();
    let aad = message_aad(&topic.topic, &sender, seqno, timestamp);
    let pt = payload.encode();
    let ct = aead::seal(&topic.epoch_key(epoch_of(timestamp)), &pt, &aad);
    SignedMessage::create_sealed_with_pow(id, pow_nonce, &topic.topic, ct, seqno, timestamp)
}

/// Open a sealed message with the topic's key. Call only **after** the message has been validated
/// (signature, PoW, replay) — this checks confidentiality, not authenticity of the sender.
pub fn open_message(topic: &SealedTopic, msg: &SignedMessage) -> Result<SealedPayload, SealError> {
    if !msg.sealed {
        return Err(SealError::NotSealed);
    }
    if msg.topic != topic.topic {
        return Err(SealError::TopicMismatch);
    }
    let aad = message_aad(&msg.topic, &msg.sender, msg.seqno, msg.timestamp);
    let pt = Zeroizing::new(
        aead::open(
            &topic.epoch_key(epoch_of(msg.timestamp)),
            &msg.payload,
            &aad,
        )
        .map_err(|_| SealError::Auth)?,
    );
    SealedPayload::decode(&pt)
}

/// Encrypt blob `plaintext` under a fresh content key. Returns the ciphertext (what is stored and
/// served) and its reference (`Cid` over the ciphertext + key).
pub fn seal_blob(plaintext: &[u8]) -> Result<(Vec<u8>, SealedBlobRef), SealError> {
    if plaintext.len() > MAX_SEALED_BLOB_PLAINTEXT {
        return Err(SealError::TooLarge);
    }
    let key = ContentKey::generate();
    let ct = aead::seal(&key.aead(), plaintext, BLOB_AAD);
    let cid = Cid::of(&ct);
    Ok((ct, SealedBlobRef { cid, key }))
}

/// Verify a fetched blob ciphertext against its `Cid`, then decrypt it.
pub fn open_blob(blob: &SealedBlobRef, ciphertext: &[u8]) -> Result<Vec<u8>, SealError> {
    if !blob.cid.verifies(ciphertext) {
        return Err(SealError::CidMismatch);
    }
    aead::open(&blob.key.aead(), ciphertext, BLOB_AAD).map_err(|_| SealError::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::{MIN_SEALED_PAYLOAD, MsgError, ReplayGuard};

    const TEST_POW: u32 = 8;
    const TS: u64 = 1_700_000_000_000;

    fn ident(seed: u8) -> (NodeIdentity, u64) {
        let id = NodeIdentity::from_seed(&[seed; 32]);
        let key = id.verifying_key().to_bytes();
        let n = (0u64..)
            .find(|&n| umesh_crypto::pow::verify_identity(&key, n, TEST_POW))
            .unwrap();
        (id, n)
    }

    fn topic(name: &str, k: u8) -> SealedTopic {
        SealedTopic::new(name, &TopicKey::from_bytes([k; 32]))
    }

    fn sealed(st: &SealedTopic, pt: &[u8], seqno: u64, ts: u64) -> SignedMessage {
        let (id, n) = ident(1);
        seal_message(&id, n, st, &SealedPayload::Data(pt.to_vec()), seqno, ts)
    }

    #[test]
    fn seal_open_roundtrip_and_forwarder_can_validate() {
        let st = topic("secret", 9);
        let m = sealed(&st, b"attack at dawn", 1, TS);
        assert!(m.sealed);
        // The wire carries ciphertext only.
        let wire = m.encode();
        assert!(!wire.windows(14).any(|w| w == b"attack at dawn"));
        assert_eq!(wire[0], SEALED_MSG_VERSION);
        // A non-member (no key) validates signature, PoW and replay state on the ciphertext.
        let back = SignedMessage::decode(&wire).unwrap();
        let mut g = ReplayGuard::default();
        assert!(
            crate::gossip::validate_on_topic_with_pow(&back, "secret", &mut g, TS, TEST_POW)
                .is_ok()
        );
        // A member opens it.
        assert_eq!(
            open_message(&st, &back),
            Ok(SealedPayload::Data(b"attack at dawn".to_vec()))
        );
    }

    /// Regression: a member holding the wrong key cannot read the message.
    #[test]
    fn wrong_key_fails() {
        let m = sealed(&topic("secret", 9), b"x", 1, TS);
        assert_eq!(open_message(&topic("secret", 8), &m), Err(SealError::Auth));
    }

    /// Regression: the same key bound to a different topic name yields an unrelated AEAD key, and
    /// ciphertext moved into another topic's (validly re-signed) message fails authentication.
    #[test]
    fn ciphertext_moved_to_another_topic_fails() {
        let a = topic("topic-a", 9);
        let b = topic("topic-b", 9); // same key, other topic
        let m = sealed(&a, b"for topic a", 1, TS);
        // Sender re-wraps the identical ciphertext into a message for topic-b.
        let (id, n) = ident(1);
        let moved =
            SignedMessage::create_sealed_with_pow(&id, n, "topic-b", m.payload.clone(), 1, TS);
        assert!(
            moved.validate_stateless_with_pow(TEST_POW).is_ok(),
            "validly signed"
        );
        assert_eq!(open_message(&b, &moved), Err(SealError::Auth));
        // And a topic-a state refuses a topic-b message outright.
        assert_eq!(open_message(&a, &moved), Err(SealError::TopicMismatch));
    }

    /// Regression: ciphertext moved into another message (other seqno / timestamp / sender) fails.
    #[test]
    fn ciphertext_moved_to_another_message_fails() {
        let st = topic("secret", 9);
        let m = sealed(&st, b"original", 7, TS);
        let (id1, n1) = ident(1);
        let (id2, n2) = ident(2);
        for (id, n, seq, ts) in [
            (&id1, n1, 8, TS),     // other seqno
            (&id1, n1, 7, TS + 1), // other timestamp (same epoch)
            (&id2, n2, 7, TS),     // other sender
        ] {
            let moved =
                SignedMessage::create_sealed_with_pow(id, n, "secret", m.payload.clone(), seq, ts);
            assert!(moved.validate_stateless_with_pow(TEST_POW).is_ok());
            assert_eq!(open_message(&st, &moved), Err(SealError::Auth));
        }
        // Tampering with the ciphertext itself breaks the signature first (payload_hash).
        let mut t = m.clone();
        t.payload[30] ^= 1;
        assert_eq!(
            t.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::PayloadHash)
        );
    }

    /// A forwarder cannot flip a message between public and sealed: the version is signed.
    #[test]
    fn version_flip_breaks_signature() {
        let st = topic("t", 1);
        let m = sealed(&st, b"x", 1, TS);
        let mut wire = m.encode();
        wire[0] = crate::gossip::MSG_VERSION;
        let flipped = SignedMessage::decode(&wire).unwrap();
        assert!(!flipped.sealed);
        assert_eq!(
            flipped.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::Signature)
        );
        let (id, n) = ident(1);
        let public = SignedMessage::create_with_pow(&id, n, "t", vec![0; 64], 1, TS);
        let mut wire = public.encode();
        wire[0] = SEALED_MSG_VERSION;
        let flipped = SignedMessage::decode(&wire).unwrap();
        assert_eq!(
            flipped.validate_stateless_with_pow(TEST_POW),
            Err(MsgError::Signature)
        );
        assert_eq!(open_message(&st, &public), Err(SealError::NotSealed));
    }

    #[test]
    fn short_sealed_payload_is_malformed() {
        let (id, n) = ident(1);
        let m = SignedMessage::create_sealed_with_pow(
            &id,
            n,
            "t",
            vec![0; MIN_SEALED_PAYLOAD - 1],
            1,
            TS,
        );
        assert_eq!(SignedMessage::decode(&m.encode()), Err(MsgError::Malformed));
        let ok =
            SignedMessage::create_sealed_with_pow(&id, n, "t", vec![0; MIN_SEALED_PAYLOAD], 1, TS);
        assert!(SignedMessage::decode(&ok.encode()).is_ok());
    }

    /// Epoch keys: messages from the previous day still open (the receiver derives the key from
    /// the signed timestamp), and different epochs use different keys.
    #[test]
    fn epochs_use_distinct_keys() {
        let st = topic("t", 3);
        let boundary = 20_000 * EPOCH_MS;
        let before = sealed(&st, b"late", 1, boundary - 1);
        let after = sealed(&st, b"early", 2, boundary);
        assert_eq!(epoch_of(before.timestamp) + 1, epoch_of(after.timestamp));
        assert!(open_message(&st, &before).is_ok());
        assert!(open_message(&st, &after).is_ok());
        // Same plaintext/key under another epoch key does not authenticate.
        let aad = message_aad("t", &before.sender, 1, boundary - 1);
        assert!(aead::open(&st.epoch_key(epoch_of(boundary)), &before.payload, &aad).is_err());
    }

    #[test]
    fn payload_codec_is_strict_and_canonical() {
        let r = SealedBlobRef {
            cid: Cid::of(b"ct"),
            key: ContentKey::from_bytes([5; 32]),
        };
        for p in [
            SealedPayload::Data(vec![]),
            SealedPayload::Data(b"hello".to_vec()),
            SealedPayload::Blob(r),
        ] {
            let e = p.encode();
            assert_eq!(SealedPayload::decode(&e).as_ref(), Ok(&p));
        }
        assert_eq!(SealedPayload::decode(&[]), Err(SealError::Malformed));
        assert_eq!(SealedPayload::decode(&[2]), Err(SealError::Malformed));
        assert_eq!(
            SealedPayload::decode(&[KIND_BLOB; 64]),
            Err(SealError::Malformed)
        );
        assert_eq!(
            SealedPayload::decode(&[KIND_BLOB; 66]),
            Err(SealError::Malformed)
        );
    }

    #[test]
    fn blob_roundtrip_cid_over_ciphertext() {
        let pt = b"confidential document ".repeat(100);
        let (ct, r) = seal_blob(&pt).unwrap();
        assert!(r.cid.verifies(&ct), "cid certifies the ciphertext");
        assert!(!ct.windows(22).any(|w| w == b"confidential document "));
        assert_eq!(open_blob(&r, &ct).unwrap(), pt);
        // Fresh key and nonce per blob: same plaintext ⇒ different cid.
        let (_, r2) = seal_blob(&pt).unwrap();
        assert_ne!(r.cid, r2.cid);
        // Tampered bytes fail the cid; wrong key fails AEAD.
        let mut bad = ct.clone();
        bad[40] ^= 1;
        assert_eq!(open_blob(&r, &bad), Err(SealError::CidMismatch));
        let wrong = SealedBlobRef {
            cid: r.cid,
            key: ContentKey::from_bytes([0; 32]),
        };
        assert_eq!(open_blob(&wrong, &ct), Err(SealError::Auth));
        assert_eq!(
            seal_blob(&vec![0; MAX_SEALED_BLOB_PLAINTEXT + 1]).unwrap_err(),
            SealError::TooLarge
        );
        let (max_ct, _) = seal_blob(&vec![0; MAX_SEALED_BLOB_PLAINTEXT]).unwrap();
        assert_eq!(max_ct.len(), MAX_BLOB);
    }

    #[test]
    fn keys_are_redacted_and_parse_strictly() {
        let hex = "ab".repeat(32);
        let k = TopicKey::from_hex(&format!("  {hex}\n")).unwrap();
        assert_eq!(k.to_hex().as_str(), hex);
        assert_eq!(format!("{k:?}"), "TopicKey(<redacted>)");
        let st = SealedTopic::new("t", &k);
        assert!(!format!("{st:?}").contains(&hex));
        let ck = ContentKey::from_bytes([0xab; 32]);
        assert_eq!(format!("{ck:?}"), "ContentKey(<redacted>)");
        let p = SealedPayload::Blob(SealedBlobRef {
            cid: Cid::of(b"x"),
            key: ck,
        });
        assert!(!format!("{p:?}").contains("abab"));
        for bad in [
            "",
            "zz".repeat(32).as_str(),
            "ab".repeat(31).as_str(),
            "ab".repeat(33).as_str(),
        ] {
            assert_eq!(TopicKey::from_hex(bad).unwrap_err(), SealError::BadKey);
        }
        assert_ne!(TopicKey::generate().to_hex(), TopicKey::generate().to_hex());
    }

    /// Fuzz-harness body (see `fuzz/fuzz_targets/sealed_parse.rs`) over a deterministic corpus.
    #[test]
    fn sealed_parser_never_panics_on_edge_inputs() {
        let st = topic("t", 1);
        let genuine = sealed(&st, b"hello", 1, TS).encode();
        let mut inputs: Vec<Vec<u8>> = vec![vec![], vec![0], vec![1], vec![3], vec![1; 65]];
        for cut in 0..genuine.len() {
            inputs.push(genuine[..cut].to_vec());
            let mut flipped = genuine.clone();
            flipped[cut] ^= 0x80;
            inputs.push(flipped);
        }
        for i in &inputs {
            fuzz_body(&st, i);
        }
    }

    pub(crate) fn fuzz_body(st: &SealedTopic, data: &[u8]) {
        if let Ok(p) = SealedPayload::decode(data) {
            assert_eq!(&*p.encode(), data);
        }
        if let Ok(m) = SignedMessage::decode(data)
            && m.sealed
        {
            let _ = open_message(st, &m);
        }
        let r = SealedBlobRef {
            cid: Cid::of(data),
            key: ContentKey::from_bytes([1; 32]),
        };
        let _ = open_blob(&r, data);
    }
}
