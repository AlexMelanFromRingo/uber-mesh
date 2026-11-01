//! BLAKE3 Merkle tree with single-leaf membership (inclusion) proofs.
//!
//! Construction: the RFC 9162 (Certificate Transparency v2) Merkle Tree Hash and inclusion-proof
//! algorithms (§2.1.1, §2.1.3), instantiated with BLAKE3 and **strict domain separation**
//! (constitution Principle I):
//!
//! - leaf hash  = `BLAKE3.derive_key(labels::MERKLE_LEAF, value)`
//! - node hash  = `BLAKE3.derive_key(labels::MERKLE_NODE, left ‖ right)`
//! - root       = `BLAKE3.derive_key(labels::MERKLE_ROOT, u64_le(total) ‖ MTH(leaves))`
//!
//! Distinct leaf/node labels make second-preimage forgeries impossible: an internal node value can
//! never verify as a leaf (the RFC 9162 `0x00`/`0x01` prefix rule, expressed as BLAKE3 contexts).
//! The tree size is **committed in the root**, so the `total` carried inside a
//! [`MembershipProof`] is authenticated by the root itself: a prover cannot re-interpret a proof
//! under a different tree size (which in a bare MTH could move a leaf to a different index).
//! Callers therefore only need the root from an authenticated source (signed manifest, gossip
//! message signature, …); nothing else in the proof has to be trusted.
//!
//! Leaves are arbitrary 32-byte values (e.g. content IDs / message IDs).

use crate::error::{CryptoError, Result};
use crate::hash::{Hash32, derive_key, labels};

/// Hard upper bound on the tree size accepted by [`verify`] (2^48 leaves). Keeps hostile `total`
/// values from producing absurd paths and bounds the proof length to 48 hashes.
pub const MAX_LEAVES: u64 = 1 << 48;

fn leaf_hash(value: &Hash32) -> Hash32 {
    derive_key(labels::MERKLE_LEAF, value)
}

fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    derive_key(labels::MERKLE_NODE, &buf)
}

fn commit_root(total: u64, mth: &Hash32) -> Hash32 {
    let mut buf = [0u8; 40];
    buf[..8].copy_from_slice(&total.to_le_bytes());
    buf[8..].copy_from_slice(mth);
    derive_key(labels::MERKLE_ROOT, &buf)
}

/// Largest power of two strictly smaller than `n` (`n >= 2`).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// RFC 9162 MTH over already-leaf-hashed entries (non-empty).
fn mth(hashed: &[Hash32]) -> Hash32 {
    match hashed.len() {
        1 => hashed[0],
        n => {
            let k = split_point(n);
            node_hash(&mth(&hashed[..k]), &mth(&hashed[k..]))
        }
    }
}

/// RFC 9162 PATH(m, D[n]), leaf-to-root order.
fn path(m: usize, hashed: &[Hash32], out: &mut Vec<Hash32>) {
    let n = hashed.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if m < k {
        path(m, &hashed[..k], out);
        out.push(mth(&hashed[k..]));
    } else {
        path(m - k, &hashed[k..], out);
        out.push(mth(&hashed[..k]));
    }
}

/// Compute the (size-committing) Merkle root of `leaves`. Returns `None` for an empty leaf set.
pub fn root(leaves: &[Hash32]) -> Option<Hash32> {
    if leaves.is_empty() {
        return None;
    }
    let hashed: Vec<Hash32> = leaves.iter().map(leaf_hash).collect();
    Some(commit_root(leaves.len() as u64, &mth(&hashed)))
}

/// A membership proof for a single leaf at `index` within a tree of `total` leaves.
///
/// `index` and `total` are untrusted on their own; they are authenticated by [`verify`] against
/// the root (which commits to `total`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    /// RFC 9162 inclusion path (sibling hashes, leaf-to-root order).
    pub path: Vec<Hash32>,
    /// Leaf index within the tree.
    pub index: u64,
    /// Total number of leaves in the tree (committed in the root).
    pub total: u64,
    /// The leaf value being proven.
    pub leaf: Hash32,
}

/// Build a membership proof for `index` over `leaves`. Returns the proof and the tree root.
pub fn prove(leaves: &[Hash32], index: usize) -> Result<(MembershipProof, Hash32)> {
    if index >= leaves.len() {
        return Err(CryptoError::InvalidLength {
            expected: leaves.len(),
            got: index,
        });
    }
    let hashed: Vec<Hash32> = leaves.iter().map(leaf_hash).collect();
    let total = leaves.len() as u64;
    let root = commit_root(total, &mth(&hashed));
    let mut p = Vec::new();
    path(index, &hashed, &mut p);
    Ok((
        MembershipProof {
            path: p,
            index: index as u64,
            total,
            leaf: leaves[index],
        },
        root,
    ))
}

/// Verify a [`MembershipProof`] against an expected `root`, which MUST come from an authenticated
/// source. The proof's `total` is bound by the root; `index`/`total`/`path` may be hostile and are
/// never trusted beyond what the root commits to. Never panics.
pub fn verify(root: &Hash32, proof: &MembershipProof) -> Result<()> {
    let MembershipProof {
        path,
        index,
        total,
        leaf,
    } = proof;
    if *total == 0 || *total > MAX_LEAVES || index >= total || path.len() > 64 {
        return Err(CryptoError::BadMerkleProof);
    }
    // RFC 9162 §2.1.3.2.
    let mut fnode = *index;
    let mut snode = *total - 1;
    let mut r = leaf_hash(leaf);
    for p in path {
        if snode == 0 {
            return Err(CryptoError::BadMerkleProof);
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode == 0 && commit_root(*total, &r) == *root {
        Ok(())
    } else {
        Err(CryptoError::BadMerkleProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> Hash32 {
        *blake3::hash(&[i]).as_bytes()
    }

    #[test]
    fn membership_proof_roundtrip() {
        let leaves: Vec<Hash32> = (0..8u8).map(leaf).collect();
        let (proof, root) = prove(&leaves, 3).unwrap();
        assert!(verify(&root, &proof).is_ok());
    }

    #[test]
    fn every_leaf_of_every_small_tree_proves() {
        for n in 1..=33u8 {
            let leaves: Vec<Hash32> = (0..n).map(leaf).collect();
            let r = root(&leaves).unwrap();
            for i in 0..n as usize {
                let (p, r2) = prove(&leaves, i).unwrap();
                assert_eq!(r, r2);
                assert!(verify(&r, &p).is_ok(), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn tampered_leaf_fails() {
        let leaves: Vec<Hash32> = (0..8u8).map(leaf).collect();
        let (mut proof, root) = prove(&leaves, 3).unwrap();
        proof.leaf[0] ^= 0xff;
        assert!(matches!(
            verify(&root, &proof),
            Err(CryptoError::BadMerkleProof)
        ));
    }

    #[test]
    fn wrong_root_fails() {
        let leaves: Vec<Hash32> = (0..8u8).map(leaf).collect();
        let (proof, _root) = prove(&leaves, 0).unwrap();
        let bad_root = [0u8; 32];
        assert!(verify(&bad_root, &proof).is_err());
    }

    #[test]
    fn out_of_range_index_errors() {
        let leaves: Vec<Hash32> = (0..4u8).map(leaf).collect();
        assert!(prove(&leaves, 9).is_err());
    }

    #[test]
    fn empty_root_is_none() {
        assert!(root(&[]).is_none());
    }

    /// Second-preimage regression: an internal node presented as a leaf (with the level-1 tree's
    /// proof) must not verify against the real root.
    #[test]
    fn internal_node_is_not_a_leaf() {
        let leaves: Vec<Hash32> = (0..8u8).map(leaf).collect();
        let real_root = root(&leaves).unwrap();
        let hashed: Vec<Hash32> = leaves.iter().map(leaf_hash).collect();
        let lvl1: Vec<Hash32> = hashed.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
        // The level-1 nodes' own subtree path (exactly what the forger would present).
        let mut p = Vec::new();
        path(0, &lvl1, &mut p);
        for total in [4u64, 8] {
            let forged = MembershipProof {
                path: p.clone(),
                index: 0,
                total,
                leaf: lvl1[0],
            };
            assert!(verify(&real_root, &forged).is_err());
        }
    }

    /// Size-ambiguity regression: in a bare MTH the last leaf of a 5-leaf tree also "verifies" as
    /// index 1 of a 2-leaf tree (path = [MTH(first 4)]). The size-committing root rejects it.
    #[test]
    fn proof_cannot_be_reinterpreted_under_another_size() {
        let leaves: Vec<Hash32> = (0..5u8).map(leaf).collect();
        let (p, r) = prove(&leaves, 4).unwrap();
        assert_eq!(p.path.len(), 1);
        let reinterpreted = MembershipProof {
            index: 1,
            total: 2,
            ..p.clone()
        };
        assert!(verify(&r, &reinterpreted).is_err());
        assert!(verify(&r, &p).is_ok());
    }

    #[test]
    fn hostile_index_total_never_panic_or_verify() {
        let leaves: Vec<Hash32> = (0..8u8).map(leaf).collect();
        let (p, r) = prove(&leaves, 3).unwrap();
        for (index, total) in [
            (3u64, 0u64),
            (100, 8),
            (3, 1),
            (u64::MAX, u64::MAX),
            (3, u64::MAX),
            (3, MAX_LEAVES),
            (8, 8),
        ] {
            let q = MembershipProof {
                index,
                total,
                ..p.clone()
            };
            assert!(verify(&r, &q).is_err(), "index={index} total={total}");
        }
        let long = MembershipProof {
            path: vec![[0u8; 32]; 10_000],
            ..p
        };
        assert!(verify(&r, &long).is_err());
    }

    #[test]
    fn leaf_node_root_labels_are_distinct() {
        let v = leaf(1);
        assert_ne!(leaf_hash(&v), *blake3::hash(&v).as_bytes());
        assert_ne!(node_hash(&v, &v), {
            let mut c = [0u8; 64];
            c[..32].copy_from_slice(&v);
            c[32..].copy_from_slice(&v);
            *blake3::hash(&c).as_bytes()
        });
        assert_ne!(root(&[v]).unwrap(), leaf_hash(&v));
    }
}
