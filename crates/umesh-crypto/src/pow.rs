//! BLAKE3 proof-of-work used as identity-creation *friction* (not a hard barrier).
//!
//! A node proves it spent work to mint a NodeID, raising the cost of cheap Sybil floods. Per the
//! dossier this is friction combined with structural defenses (peer scoring, colocation penalties),
//! not a standalone Sybil defense.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::hash::{self, Hash32};

/// Network-wide minimum identity proof-of-work for gossip senders, in leading zero bits of
/// [`identity_digest`]. **Every node of a mesh must use the same value**: a message whose sender
/// identity carries less work is *provably invalid* (gossipsub `Reject`, forwarder penalized), so
/// nodes that disagree would penalize each other. Changing it is a wire-breaking change that must
/// come with a gossip message-format version bump (`umesh_p2p::gossip::MSG_VERSION`).
///
/// 24 bits = 2^24 ≈ 16.8 M hashes expected per identity, paid once at `uber-mesh init`. Measured
/// (release, AMD Ryzen 5 5500): ≈10 M hash/s per core while mining ⇒ ~1.7 s expected on one core,
/// ~0.25 s on all 12 threads (a 1 M hash/s embedded core: ~17 s). Verification is one BLAKE3 call.
/// See `docs/security-and-deferred.md` for what this buys against fresh-identity floods.
pub const MIN_SENDER_POW_BITS: u32 = 24;

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

// ---------------------------------------------------------------------------------------------
// Identity proof-of-work (gossip senders)
// ---------------------------------------------------------------------------------------------

/// Identity PoW digest: `BLAKE3.derive_key(labels::IDENTITY_POW, sender_key ‖ u64_le(nonce))`.
///
/// Hash-based nonce PoW bound to the *public* key (not key grinding): the key is chosen first, so
/// honest mining is a plain nonce search and verification is a single BLAKE3 call. A nonce found
/// for one key is worthless for any other key (the key is inside the hashed input), and its own
/// domain label keeps it distinct from every other hash use (Principle I).
pub fn identity_digest(sender_key: &[u8; 32], nonce: u64) -> Hash32 {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(sender_key);
    buf[32..].copy_from_slice(&nonce.to_le_bytes());
    hash::derive_key(hash::labels::IDENTITY_POW, &buf)
}

/// Work proven by `nonce` for `sender_key`: the leading zero bits of [`identity_digest`].
pub fn identity_pow_bits(sender_key: &[u8; 32], nonce: u64) -> u32 {
    leading_zero_bits(&identity_digest(sender_key, nonce))
}

/// Whether `nonce` proves at least `difficulty` bits of work for `sender_key` (one BLAKE3 call).
pub fn verify_identity(sender_key: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
    identity_pow_bits(sender_key, nonce) >= difficulty
}

/// How often (hashes per worker) the mining progress callback fires.
const PROGRESS_EVERY: u64 = 1 << 20;

/// Mine an identity nonce for `sender_key` at `difficulty` on all available cores.
///
/// Expected work is `2^difficulty` hashes. Returns `None` only if `difficulty > 64` (not
/// achievable: the search would never end) — any `difficulty ≤ 64` terminates.
pub fn mine_identity(sender_key: &[u8; 32], difficulty: u32) -> Option<u64> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    mine_identity_with(sender_key, difficulty, threads, &|_| {})
}

/// [`mine_identity`] with an explicit worker count (≥ 1) and a progress callback receiving the
/// total number of hashes tried so far (called from a worker thread roughly every 2^20 hashes per
/// worker; keep it cheap).
pub fn mine_identity_with(
    sender_key: &[u8; 32],
    difficulty: u32,
    threads: usize,
    progress: &(dyn Fn(u64) + Sync),
) -> Option<u64> {
    if difficulty > 64 {
        return None;
    }
    let threads = threads.max(1) as u64;
    let found = AtomicBool::new(false);
    let result = AtomicU64::new(0);
    let tried = AtomicU64::new(0);
    // The key-prefixed hasher state is shared; each nonce costs one clone + one compression.
    let mut base = blake3::Hasher::new_derive_key(hash::labels::IDENTITY_POW);
    base.update(sender_key);
    std::thread::scope(|s| {
        for t in 0..threads {
            let (base, found, result, tried) = (&base, &found, &result, &tried);
            s.spawn(move || {
                // Worker `t` tries t, t + threads, t + 2·threads, … (disjoint, covers all of u64).
                let mut nonce = t;
                let mut since = 0u64;
                loop {
                    let mut h = base.clone();
                    h.update(&nonce.to_le_bytes());
                    if leading_zero_bits(h.finalize().as_bytes()) >= difficulty {
                        if !found.swap(true, Ordering::AcqRel) {
                            result.store(nonce, Ordering::Release);
                        }
                        return;
                    }
                    since += 1;
                    if since == PROGRESS_EVERY {
                        let total = tried.fetch_add(since, Ordering::Relaxed) + since;
                        since = 0;
                        if found.load(Ordering::Acquire) {
                            return;
                        }
                        if t == 0 {
                            progress(total);
                        }
                    }
                    match nonce.checked_add(threads) {
                        Some(n) => nonce = n,
                        None => return, // this worker's share of the space is exhausted
                    }
                }
            });
        }
    });
    found
        .load(Ordering::Acquire)
        .then(|| result.load(Ordering::Acquire))
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
    fn mining_finds_a_valid_identity_nonce() {
        let key = [7u8; 32];
        for threads in [1, 4] {
            let n = mine_identity_with(&key, 12, threads, &|_| {}).expect("difficulty ≤ 64");
            assert!(verify_identity(&key, n, 12));
            assert!(identity_pow_bits(&key, n) >= 12);
        }
        assert_eq!(
            mine_identity(&key, 65),
            None,
            "unachievable difficulty refused"
        );
        assert!(verify_identity(&key, 0, 0), "difficulty 0 always holds");
    }

    #[test]
    fn identity_nonce_is_bound_to_the_key() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let n = mine_identity_with(&a, 16, 1, &|_| {}).unwrap(); // 1 worker: deterministic
        assert!(verify_identity(&a, n, 16));
        // The same nonce is (overwhelmingly likely) worthless for another key.
        assert!(!verify_identity(&b, n, 16));
        assert_ne!(identity_digest(&a, n), identity_digest(&b, n));
    }

    #[test]
    fn identity_digest_is_domain_separated() {
        let key = [3u8; 32];
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(&key);
        buf[32..].copy_from_slice(&9u64.to_le_bytes());
        let d = identity_digest(&key, 9);
        assert_eq!(d, hash::derive_key(hash::labels::IDENTITY_POW, &buf));
        assert_ne!(d, hash::derive_key(hash::labels::POW_SOLVE, &buf));
        assert_ne!(d, hash::hash(&buf));
        // The incremental mining hasher computes exactly the verifier's digest.
        let mut h = blake3::Hasher::new_derive_key(hash::labels::IDENTITY_POW);
        h.update(&key);
        h.update(&9u64.to_le_bytes());
        assert_eq!(*h.finalize().as_bytes(), d);
    }

    /// Known-answer test pinning the construction (any change to the label, input order or
    /// encoding is a network-wide break and must show up here).
    #[test]
    fn identity_pow_kat() {
        let key = [0u8; 32];
        let d0: Hash32 = [
            0xaa, 0xca, 0x40, 0x3a, 0x54, 0xb3, 0xe4, 0xb5, 0xce, 0x31, 0x11, 0x19, 0xaf, 0xe2,
            0xc6, 0x8a, 0xc2, 0xdd, 0xe2, 0x11, 0xf3, 0x8e, 0x77, 0x41, 0x24, 0xeb, 0xa3, 0x83,
            0x7c, 0x30, 0x2c, 0xbf,
        ];
        assert_eq!(identity_digest(&key, 0), d0);
        // Least nonce with ≥ 8 leading zero bits for the all-zero key; one worker finds exactly it.
        assert!(verify_identity(&key, 30, 8));
        assert!((0..30).all(|n| !verify_identity(&key, n, 8)));
        assert_eq!(mine_identity_with(&key, 8, 1, &|_| {}), Some(30));
    }

    /// Measures the identity mining cost on this machine (documented in
    /// `docs/security-and-deferred.md`). Run: `cargo test --release -p umesh-crypto --lib
    /// identity_mining_benchmark -- --ignored --nocapture`.
    #[test]
    #[ignore = "benchmark; run in release with --ignored --nocapture"]
    fn identity_mining_benchmark() {
        use std::time::Instant;
        // Raw single-core hash rate.
        let n = 1u64 << 24;
        let t = Instant::now();
        let mut acc = 0u32;
        for i in 0..n {
            acc = acc.wrapping_add(identity_pow_bits(&[5u8; 32], i));
        }
        let rate = n as f64 / t.elapsed().as_secs_f64();
        let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
        eprintln!("single core: {:.1} M hash/s (acc {acc})", rate / 1e6);
        eprintln!(
            "expected at {MIN_SENDER_POW_BITS} bits: {:.2} s on 1 core, {:.2} s on {cores} cores",
            (1u64 << MIN_SENDER_POW_BITS) as f64 / rate,
            (1u64 << MIN_SENDER_POW_BITS) as f64 / rate / cores as f64
        );
        for (k, threads) in [(1u8, 1usize), (2, 1), (3, cores), (4, cores), (5, cores)] {
            let t = Instant::now();
            let nonce =
                mine_identity_with(&[k; 32], MIN_SENDER_POW_BITS, threads, &|_| {}).unwrap();
            eprintln!(
                "key {k}: {threads} worker(s) mined nonce {nonce} in {:.2} s",
                t.elapsed().as_secs_f64()
            );
        }
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
