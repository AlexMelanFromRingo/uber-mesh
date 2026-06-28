//! BLAKE3 Merkle tree with single-leaf membership proofs (via `rs_merkle`).
//!
//! Leaves are already-hashed 32-byte values (e.g. content IDs / message IDs). Used for
//! verifiable set membership and (later) range-based sync.

use rs_merkle::{Hasher, MerkleProof, MerkleTree};

use crate::error::{CryptoError, Result};
use crate::hash::Hash32;

/// BLAKE3 hasher adapter for `rs_merkle`.
#[derive(Clone)]
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}

/// Compute the Merkle root of `leaves`. Returns `None` for an empty leaf set.
pub fn root(leaves: &[Hash32]) -> Option<Hash32> {
    MerkleTree::<Blake3Hasher>::from_leaves(leaves).root()
}

/// A membership proof for a single leaf at `index` within a tree of `total` leaves.
#[derive(Clone, Debug)]
pub struct MembershipProof {
    /// Serialized `rs_merkle` proof (sibling path).
    pub proof_bytes: Vec<u8>,
    /// Leaf index within the tree.
    pub index: usize,
    /// Total number of leaves in the tree.
    pub total: usize,
    /// The leaf hash being proven.
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
    let tree = MerkleTree::<Blake3Hasher>::from_leaves(leaves);
    let root = tree.root().ok_or(CryptoError::BadMerkleProof)?;
    let proof = tree.proof(&[index]);
    Ok((
        MembershipProof {
            proof_bytes: proof.to_bytes(),
            index,
            total: leaves.len(),
            leaf: leaves[index],
        },
        root,
    ))
}

/// Verify a [`MembershipProof`] against an expected `root`.
pub fn verify(root: &Hash32, proof: &MembershipProof) -> Result<()> {
    let parsed = MerkleProof::<Blake3Hasher>::from_bytes(&proof.proof_bytes)
        .map_err(|_| CryptoError::BadMerkleProof)?;
    let ok = parsed.verify(*root, &[proof.index], &[proof.leaf], proof.total);
    if ok {
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
}
