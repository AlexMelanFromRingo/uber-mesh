//! BLAKE3-based hashing, keyed MAC, and key derivation with strict domain separation.
//!
//! Every distinct use of the hash/KDF MUST use a distinct context label (constitution
//! Principle I). The canonical labels live in [`labels`]. A new use ⇒ a new label.

use core::fmt;

/// 32-byte digest / key output.
pub type Hash32 = [u8; 32];

/// Domain-separation context strings for `derive_key`. Each distinct use gets its own label.
pub mod labels {
    /// Traffic key, initiator → responder (client-to-server).
    pub const TRAFFIC_C2S: &str = "uber-mesh v1 traffic c2s";
    /// Traffic key, responder → initiator (server-to-client).
    pub const TRAFFIC_S2C: &str = "uber-mesh v1 traffic s2c";
    /// obfs-tcp MAC-gate key (derived from the per-listener PSK).
    pub const OBFS_MAC: &str = "uber-mesh v1 obfs-mac";
    /// obfs-tcp frame key (derived from the per-listener PSK).
    pub const OBFS_FRAME: &str = "uber-mesh v1 obfs-frame";
    /// Content identifier (CID) hashing.
    pub const CID: &str = "uber-mesh v1 cid";
    /// Proof-of-work challenge domain.
    pub const POW: &str = "uber-mesh v1 pow";
    /// Proof-of-work solution digest: `H(challenge ‖ nonce)` (distinct from challenge derivation).
    pub const POW_SOLVE: &str = "uber-mesh v1 pow solve";
    /// Gossip-sender identity proof-of-work: `H(sender_key ‖ nonce)` (see [`crate::pow`]).
    pub const IDENTITY_POW: &str = "uber-mesh v1 identity pow";
    /// Sealed-topic root key: `derive_key(TOPIC_KEY, topic_key ‖ topic)` (end-to-end gossip
    /// confidentiality; the out-of-band topic key never encrypts anything directly).
    pub const TOPIC_KEY: &str = "uber-mesh v1 topic key";
    /// Per-epoch sealed-topic AEAD key: `derive_key(TOPIC_EPOCH_KEY, topic_root ‖ u64_le(epoch))`.
    pub const TOPIC_EPOCH_KEY: &str = "uber-mesh v1 topic epoch key";
    /// Merkle leaf hashing (RFC 9162 `0x00` prefix equivalent).
    pub const MERKLE_LEAF: &str = "uber-mesh v1 merkle leaf";
    /// Merkle internal-node hashing (RFC 9162 `0x01` prefix equivalent).
    pub const MERKLE_NODE: &str = "uber-mesh v1 merkle node";
    /// Merkle root commitment binding the tree size.
    pub const MERKLE_ROOT: &str = "uber-mesh v1 merkle root";
}

/// Plain BLAKE3 hash of `bytes`.
#[inline]
pub fn hash(bytes: &[u8]) -> Hash32 {
    *blake3::hash(bytes).as_bytes()
}

/// Keyed BLAKE3 MAC over `data` under a 32-byte `key` (constant-time finalization).
#[inline]
pub fn keyed_mac(key: &Hash32, data: &[u8]) -> Hash32 {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// BLAKE3 key-derivation: derive a 32-byte subkey from `key_material` under a
/// domain-separation `context` label (use a constant from [`labels`]).
#[inline]
pub fn derive_key(context: &str, key_material: &[u8]) -> Hash32 {
    blake3::derive_key(context, key_material)
}

/// A content identifier: `BLAKE3(domain="cid", content)`. Self-certifying — a receiver
/// recomputes it from the bytes and compares before trusting content (FR-011).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cid(pub Hash32);

impl Cid {
    /// Compute the CID of `content`.
    pub fn of(content: &[u8]) -> Self {
        // derive_key gives domain separation from plain `hash` / message-ids.
        Cid(derive_key(labels::CID, content))
    }

    /// Verify that `content` matches this CID.
    pub fn verifies(&self, content: &[u8]) -> bool {
        // Constant-time compare not required (public values), but cheap and tidy.
        Cid::of(content) == *self
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &Hash32 {
        &self.0
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({self})")
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b3:")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official BLAKE3 known-answer test: hash of the empty input.
    /// (BLAKE3 reference test vector, input length 0.)
    #[test]
    fn blake3_empty_kat() {
        let got = hash(b"");
        let want = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        assert_eq!(hex::encode(got), want);
    }

    #[test]
    fn derive_key_is_domain_separated() {
        let ikm = b"same input key material";
        let a = derive_key(labels::TRAFFIC_C2S, ikm);
        let b = derive_key(labels::TRAFFIC_S2C, ikm);
        assert_ne!(a, b, "different contexts must yield different keys");
    }

    #[test]
    fn all_labels_are_distinct() {
        let all = [
            labels::TRAFFIC_C2S,
            labels::TRAFFIC_S2C,
            labels::OBFS_MAC,
            labels::OBFS_FRAME,
            labels::CID,
            labels::POW,
            labels::POW_SOLVE,
            labels::IDENTITY_POW,
            labels::TOPIC_KEY,
            labels::TOPIC_EPOCH_KEY,
            labels::MERKLE_LEAF,
            labels::MERKLE_NODE,
            labels::MERKLE_ROOT,
        ];
        let set: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn keyed_mac_changes_with_key_and_data() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert_ne!(keyed_mac(&k1, b"msg"), keyed_mac(&k2, b"msg"));
        assert_ne!(keyed_mac(&k1, b"a"), keyed_mac(&k1, b"b"));
    }

    #[test]
    fn cid_roundtrip_and_display() {
        let cid = Cid::of(b"hello uber-mesh");
        assert!(cid.verifies(b"hello uber-mesh"));
        assert!(!cid.verifies(b"tampered"));
        assert!(format!("{cid}").starts_with("b3:"));
        assert_eq!(format!("{cid}").len(), 3 + 64);
    }
}
