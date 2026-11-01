//! Shared integration-test helpers: cheap sender identities.
//!
//! Mining the network-wide `MIN_SENDER_POW_BITS` (2^24 hashes) per node would dominate a debug
//! test run, so swarm tests use an 8-bit PoW policy on every node of the test mesh (all nodes of a
//! mesh must agree on the difficulty). `MINED` holds identities pre-mined at the real minimum for
//! tests that exercise it end to end.
#![allow(dead_code)]

use umesh_crypto::identity::NodeIdentity;
use umesh_crypto::pow;
use umesh_obfs::{ObfsPsk, ProbeResponse, ShapingPolicy};
use umesh_p2p::{MeshNode, Result};

/// Sender-PoW difficulty used by test meshes.
pub const TEST_POW: u32 = 8;

/// Identities pre-mined at `MIN_SENDER_POW_BITS` (= 24): `(seed, nonce)`.
pub const MINED: [([u8; 32], u64); 2] = [([0x24; 32], 18_566_826), ([0x25; 32], 76_581_304)];

/// Least nonce meeting [`TEST_POW`] for the identity of `seed`.
pub fn test_nonce(seed: &[u8; 32]) -> u64 {
    let key = NodeIdentity::from_seed(seed).verifying_key().to_bytes();
    (0u64..)
        .find(|&n| pow::verify_identity(&key, n, TEST_POW))
        .unwrap()
}

/// A test-mesh node (8-bit PoW policy, no shaping, silent probe rejection).
pub fn node(seed: &[u8; 32], psk: ObfsPsk) -> Result<MeshNode> {
    node_with_transport(seed, psk, ShapingPolicy::none(), ProbeResponse::Silence)
}

/// A test-mesh node with explicit transport settings.
pub fn node_with_transport(
    seed: &[u8; 32],
    psk: ObfsPsk,
    shaping: ShapingPolicy,
    probe: ProbeResponse,
) -> Result<MeshNode> {
    MeshNode::with_pow_policy(seed, test_nonce(seed), TEST_POW, psk, shaping, probe)
}
