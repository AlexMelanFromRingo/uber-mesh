//! Identity keystore: generate / load a node's long-term Ed25519 seed with restrictive permissions.

use std::path::Path;

use umesh_crypto::identity::NodeIdentity;
use zeroize::Zeroize;

use crate::error::{NodeError, Result};

/// Load the identity from `path`, or generate + persist a new one if absent.
pub fn load_or_generate(path: &Path) -> Result<NodeIdentity> {
    if path.exists() {
        load(path)
    } else {
        let id = NodeIdentity::generate();
        save(path, &id)?;
        Ok(id)
    }
}

/// Load an identity from a hex-encoded 32-byte seed file.
pub fn load(path: &Path) -> Result<NodeIdentity> {
    let text = std::fs::read_to_string(path)?;
    let mut seed = hex::decode(text.trim())
        .map_err(|_| NodeError::Keystore("identity file is not valid hex".into()))?;
    if seed.len() != 32 {
        seed.zeroize();
        return Err(NodeError::Keystore("identity seed must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed);
    seed.zeroize();
    let id = NodeIdentity::from_seed(&arr);
    arr.zeroize();
    Ok(id)
}

/// Persist an identity's secret seed to `path` with `0600` permissions (best-effort on non-Unix),
/// refusing to overwrite an existing file.
pub fn save(path: &Path, id: &NodeIdentity) -> Result<()> {
    if path.exists() {
        return Err(NodeError::Keystore(format!(
            "identity already exists at {} (refusing to overwrite)",
            path.display()
        )));
    }
    let mut seed = id.to_seed_bytes();
    let mut text = hex::encode(seed);
    std::fs::write(path, &text)?;
    text.zeroize();
    seed.zeroize();
    set_owner_only(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_persist_reload_is_stable() {
        let dir = std::env::temp_dir().join(format!("umesh-ks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");

        let id1 = load_or_generate(&path).unwrap();
        let id2 = load_or_generate(&path).unwrap();
        assert_eq!(
            id1.peer_id(),
            id2.peer_id(),
            "identity must be stable across reloads"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_overwrite() {
        let dir = std::env::temp_dir().join(format!("umesh-ks2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");
        let id = NodeIdentity::generate();
        save(&path, &id).unwrap();
        assert!(save(&path, &id).is_err(), "must refuse to overwrite");
        std::fs::remove_dir_all(&dir).ok();
    }
}
