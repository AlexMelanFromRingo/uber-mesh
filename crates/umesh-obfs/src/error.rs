//! Error types for the obfuscated transport layer.

use thiserror::Error;

/// Result alias for obfs operations.
pub type Result<T> = std::result::Result<T, ObfsError>;

/// Errors produced by the obfuscated transport layer.
#[derive(Debug, Error)]
pub enum ObfsError {
    /// Underlying I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The peer failed the probe-resistant authentication gate (no distinguishing reply is sent).
    #[error("handshake authentication failed")]
    AuthFailed,

    /// A wire record/flight was malformed (bad length, short read, bad structure).
    #[error("malformed wire data")]
    Malformed,

    /// A record exceeded the maximum allowed size.
    #[error("record too large")]
    RecordTooLarge,

    /// A crypto-core error (AEAD/KEM/etc.).
    #[error("crypto: {0}")]
    Crypto(#[from] umesh_crypto::CryptoError),

    /// No transport/endpoint in the rotation list could be reached.
    #[error("no working transport could be established")]
    NoTransport,
}
