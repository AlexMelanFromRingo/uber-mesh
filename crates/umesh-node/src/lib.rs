//! # umesh-node
//!
//! Node orchestration for uber-mesh: configuration, identity keystore, the runtime that binds an
//! obfuscated listener / dials peers and exchanges authenticated hellos, and a secret-free status
//! model. The CLI (`uber-mesh`) is a thin wrapper over this crate.

pub mod config;
pub mod error;
pub mod keystore;
pub mod node;
pub mod status;

pub use config::{Config, DataDir};
pub use error::{NodeError, Result};
pub use node::Node;
pub use status::NodeStatus;
