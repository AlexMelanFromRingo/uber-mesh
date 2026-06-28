//! Node error types.

use thiserror::Error;

/// Node result alias.
pub type Result<T> = std::result::Result<T, NodeError>;

/// Errors produced by the node runtime.
#[derive(Debug, Error)]
pub enum NodeError {
    /// Filesystem / I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error (invalid value, parse failure).
    #[error("config: {0}")]
    Config(String),

    /// Identity keystore error.
    #[error("keystore: {0}")]
    Keystore(String),

    /// Transport/obfs error.
    #[error("transport: {0}")]
    Obfs(#[from] umesh_obfs::ObfsError),

    /// Crypto error.
    #[error("crypto: {0}")]
    Crypto(#[from] umesh_crypto::CryptoError),

    /// A peer's hello failed verification.
    #[error("peer handshake rejected: {0}")]
    PeerRejected(String),
}
