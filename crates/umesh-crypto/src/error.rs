//! Error types for the uber-mesh crypto core.

use thiserror::Error;

/// Result alias for crypto operations.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Errors produced by the uber-mesh crypto core.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD decryption failed (bad tag / tampered ciphertext / wrong key).
    #[error("aead: authentication failed")]
    AeadAuth,

    /// A ciphertext or key was the wrong length for the algorithm.
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },

    /// A signature failed to verify.
    #[error("signature verification failed")]
    BadSignature,

    /// A public key / encapsulation key / point was malformed.
    #[error("malformed key material")]
    MalformedKey,

    /// ML-KEM encapsulation/decapsulation failed.
    #[error("kem failure")]
    KemFailure,

    /// A Merkle proof did not verify against the supplied root.
    #[error("merkle proof verification failed")]
    BadMerkleProof,

    /// A proof-of-work solution did not meet the required difficulty.
    #[error("proof-of-work verification failed")]
    BadProofOfWork,
}
