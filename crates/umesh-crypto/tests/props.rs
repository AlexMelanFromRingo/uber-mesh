//! Property tests for the crypto core (constitution Principle V).

use proptest::prelude::*;
use umesh_crypto::aead::{AeadKey, open, seal};
use umesh_crypto::{hash, merkle};

proptest! {
    /// AEAD: open(seal(x)) == x for arbitrary plaintext, AAD, and key.
    #[test]
    fn aead_seal_open_roundtrip(key in any::<[u8; 32]>(), pt in proptest::collection::vec(any::<u8>(), 0..512), aad in proptest::collection::vec(any::<u8>(), 0..64)) {
        let k = AeadKey::from_bytes(key);
        let wire = seal(&k, &pt, &aad);
        prop_assert_eq!(open(&k, &wire, &aad).unwrap(), pt);
    }

    /// AEAD: any single-bit flip in the ciphertext is detected.
    #[test]
    fn aead_bitflip_detected(key in any::<[u8; 32]>(), pt in proptest::collection::vec(any::<u8>(), 1..256), idx in 0usize..128) {
        let k = AeadKey::from_bytes(key);
        let mut wire = seal(&k, &pt, b"");
        let i = idx % wire.len();
        wire[i] ^= 1;
        prop_assert!(open(&k, &wire, b"").is_err());
    }

    /// CID is deterministic and collision-distinguishing for distinct inputs.
    #[test]
    fn cid_is_function_of_content(a in proptest::collection::vec(any::<u8>(), 0..256), b in proptest::collection::vec(any::<u8>(), 0..256)) {
        let ca = hash::Cid::of(&a);
        prop_assert!(ca.verifies(&a));
        if a != b {
            prop_assert_ne!(ca, hash::Cid::of(&b));
        }
    }

    /// Merkle membership proofs verify for every leaf of a non-trivial tree.
    #[test]
    fn merkle_all_leaves_prove(n in 1usize..32, seed in any::<u64>()) {
        let leaves: Vec<[u8; 32]> = (0..n).map(|i| hash::hash(&(seed ^ i as u64).to_le_bytes())).collect();
        let root = merkle::root(&leaves).unwrap();
        for i in 0..n {
            let (proof, r) = merkle::prove(&leaves, i).unwrap();
            prop_assert_eq!(r, root);
            prop_assert!(merkle::verify(&root, &proof).is_ok());
        }
    }
}
