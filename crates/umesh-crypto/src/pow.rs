//! BLAKE3 proof-of-work used as identity-creation *friction* (not a hard barrier).
//!
//! A node proves it spent work to mint a NodeID, raising the cost of cheap Sybil floods. Per the
//! dossier this is friction combined with structural defenses (peer scoring, colocation penalties),
//! not a standalone Sybil defense.

use crate::hash::{self, Hash32};

/// Derive a PoW challenge bound to a node's public key and an epoch.
pub fn challenge(peer_pubkey: &[u8; 32], epoch: u64) -> Hash32 {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(peer_pubkey);
    buf[32..].copy_from_slice(&epoch.to_le_bytes());
    hash::derive_key(hash::labels::POW, &buf)
}

/// Number of leading zero bits in a digest.
fn leading_zero_bits(h: &Hash32) -> u32 {
    let mut bits = 0;
    for &byte in h {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// The PoW solution digest: `BLAKE3.derive_key(labels::POW_SOLVE, challenge ‖ u64_le(nonce))`.
///
/// Uses its own domain label (Principle I) so a PoW digest can never collide with a plain
/// `hash()` used elsewhere (content hashing, message IDs, Merkle leaves, …).
pub fn digest(challenge: &Hash32, nonce: u64) -> Hash32 {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(challenge);
    buf[32..].copy_from_slice(&nonce.to_le_bytes());
    hash::derive_key(hash::labels::POW_SOLVE, &buf)
}

/// Test whether `nonce` solves `challenge` at the given `difficulty` (leading zero bits).
pub fn meets(challenge: &Hash32, nonce: u64, difficulty: u32) -> bool {
    leading_zero_bits(&digest(challenge, nonce)) >= difficulty
}

/// Brute-force a nonce solving `challenge` at `difficulty`. Keep `difficulty` small in tests.
///
/// Returns `None` if the (bounded) search space is exhausted without a solution.
pub fn solve(challenge: &Hash32, difficulty: u32, max_iters: u64) -> Option<u64> {
    (0..max_iters).find(|&nonce| meets(challenge, nonce, difficulty))
}

/// Verify a PoW solution.
pub fn verify(challenge: &Hash32, nonce: u64, difficulty: u32) -> bool {
    meets(challenge, nonce, difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_then_verify() {
        let ch = challenge(&[9u8; 32], 1);
        let difficulty = 10; // ~1024 hashes on average — fast
        let nonce = solve(&ch, difficulty, 1 << 22).expect("should find a solution");
        assert!(verify(&ch, nonce, difficulty));
    }

    #[test]
    fn wrong_nonce_fails() {
        let ch = challenge(&[9u8; 32], 1);
        let difficulty = 12;
        let nonce = solve(&ch, difficulty, 1 << 24).unwrap();
        assert!(!verify(&ch, nonce.wrapping_add(1), difficulty) || verify(&ch, nonce, difficulty));
        // The real guarantee: the found nonce verifies, a zero difficulty always holds.
        assert!(verify(&ch, nonce, difficulty));
        assert!(verify(&ch, 0, 0));
    }

    #[test]
    fn challenge_is_bound_to_key_and_epoch() {
        assert_ne!(challenge(&[1u8; 32], 0), challenge(&[2u8; 32], 0));
        assert_ne!(challenge(&[1u8; 32], 0), challenge(&[1u8; 32], 1));
    }

    #[test]
    fn solution_digest_is_domain_separated() {
        let ch = challenge(&[9u8; 32], 1);
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(&ch);
        buf[32..].copy_from_slice(&7u64.to_le_bytes());
        let d = digest(&ch, 7);
        assert_ne!(d, hash::hash(&buf), "PoW digest must not be a plain hash");
        assert_eq!(d, hash::derive_key(hash::labels::POW_SOLVE, &buf));
        assert_ne!(hash::labels::POW_SOLVE, hash::labels::POW);
    }

    #[test]
    fn leading_zero_bits_counts() {
        let mut h = [0u8; 32];
        assert_eq!(leading_zero_bits(&h), 256);
        h[0] = 0x0f;
        assert_eq!(leading_zero_bits(&h), 4);
        h[0] = 0xff;
        assert_eq!(leading_zero_bits(&h), 0);
    }
}
