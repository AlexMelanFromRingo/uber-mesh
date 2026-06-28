//! Error types for the mesh overlay.

use thiserror::Error;

/// Result alias for p2p operations.
pub type Result<T> = std::result::Result<T, P2pError>;

/// Errors produced by the mesh overlay.
#[derive(Debug, Error)]
pub enum P2pError {
    /// Swarm/transport initialization failure.
    #[error("p2p init: {0}")]
    Init(String),

    /// Topic subscription failure.
    #[error("subscribe: {0}")]
    Subscribe(String),

    /// Publish failure.
    #[error("publish: {0}")]
    Publish(String),

    /// Listen/dial address error.
    #[error("address: {0}")]
    Address(String),

    /// Message validation error.
    #[error("message: {0}")]
    Message(#[from] crate::gossip::MsgError),

    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
