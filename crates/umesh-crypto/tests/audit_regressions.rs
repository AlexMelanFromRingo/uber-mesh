//! Regression tests for the 2026-11 hardening audit (crypto core). Each test reproduces an audit
//! PoC and asserts the fixed behaviour; all of them fail against the pre-fix code.

use umesh_crypto::hash::{self, Hash32};
use umesh_crypto::merkle::{self, MembershipProof};
use umesh_crypto::{SharedSecret, kem, pow};

fn leaf(i: u8) -> Hash32 {
    hash::hash(&[i])
}

fn concat_hash(a: &Hash32, b: &Hash32) -> Hash32 {
    let mut c = [0u8; 64];
    c[..32].copy_from_slice(a);
    c[32..].copy_from_slice(b);
    hash::hash(&c)
}

/// Audit PoC `internal_node_accepted_as_leaf`: with identical leaf/node hashing, the parent of
/// leaves 0 and 1 verified as a member leaf. Port of the PoC with every plausible proof shape.
#[test]
fn merkle_internal_node_is_not_accepted_as_leaf() {
    let leaves: Vec<Hash32> = (0..8u8).map(leaf).collect();
    let root = merkle::root(&leaves).unwrap();

    // The forger's best guesses at an internal node value: the undomain-separated concat-hash, and
    // the level-1 tree built by treating level-1 nodes as leaves (its own proof + root).
    let lvl1: Vec<Hash32> = (0..4)
        .map(|i| concat_hash(&leaves[2 * i], &leaves[2 * i + 1]))
        .collect();
    let (p, r2) = merkle::prove(&lvl1, 0).unwrap();
    assert_ne!(
        r2, root,
        "a tree of internal nodes must not share the real root"
    );
    for total in [4u64, 8] {
        let forged = MembershipProof {
            path: p.path.clone(),
            index: 0,
            total,
            leaf: lvl1[0],
        };
        assert!(merkle::verify(&root, &forged).is_err());
    }
}

/// Audit PoC `verify_with_hostile_index_total`: hostile index/total never panic and never verify.
#[test]
fn merkle_hostile_index_total_rejected_without_panic() {
    let leaves: Vec<Hash32> = (0..8u8).map(leaf).collect();
    let (p, root) = merkle::prove(&leaves, 3).unwrap();
    for (index, total) in [
        (3u64, 0u64),
        (100, 8),
        (3, 1),
        (u64::MAX, u64::MAX),
        (3, u64::MAX),
        (3, 4),
        (3, 16),
    ] {
        let q = MembershipProof {
            index,
            total,
            ..p.clone()
        };
        let r = std::panic::catch_unwind(|| merkle::verify(&root, &q).is_ok());
        assert_eq!(r.ok(), Some(false), "index={index} total={total}");
    }
}

/// Principle I: the combined hybrid secret is a zeroizing, redacted newtype — not a bare array.
#[test]
fn kem_returns_zeroizing_shared_secret() {
    fn zod<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let (i, m) = kem::Initiator::start();
    let (ss_r, r): (SharedSecret, _) = kem::respond(&m).unwrap();
    let ss_i: SharedSecret = i.finish(&r).unwrap();
    zod(&ss_r);
    assert_eq!(ss_i, ss_r);
    assert_eq!(format!("{ss_i:?}"), "SharedSecret(<redacted>)");
}

/// The PoW solution digest carries its own domain label (not a plain `hash(challenge ‖ nonce)`).
#[test]
fn pow_digest_has_own_label() {
    let ch = pow::challenge(&[3u8; 32], 9);
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(&ch);
    buf[32..].copy_from_slice(&0u64.to_le_bytes());
    assert_ne!(pow::digest(&ch, 0), hash::hash(&buf));
    let n = pow::solve(&ch, 8, 1 << 20).unwrap();
    assert!(pow::verify(&ch, n, 8));
}
