//! Identity keystore: generate / load a node's long-term Ed25519 seed with restrictive permissions.
//!
//! Hardening (audit 2026-11):
//! - the key file is created atomically with `O_CREAT|O_EXCL` and mode `0600` — it is never briefly
//!   world-readable, and `O_EXCL` refuses to follow (or overwrite) any pre-planted file or symlink;
//! - loading refuses a symlink and detects a swap between the check and the open;
//! - the seed and its hex text are zeroized after use.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use umesh_crypto::identity::NodeIdentity;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{NodeError, Result};

/// Load the identity from `path`, or generate + persist a new one if absent.
///
/// Race-free: there is no separate existence check — a concurrent creator makes our `create_new`
/// fail with `AlreadyExists`, in which case the winner's identity is loaded.
pub fn load_or_generate(path: &Path) -> Result<NodeIdentity> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => load(path),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let id = NodeIdentity::generate();
            match save(path, &id) {
                Ok(()) => Ok(id),
                Err(NodeError::Keystore(_)) if std::fs::symlink_metadata(path).is_ok() => {
                    load(path)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Load an identity from a hex-encoded 32-byte seed file. Refuses symlinks.
pub fn load(path: &Path) -> Result<NodeIdentity> {
    let mut file = open_no_symlink(path)?;
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)?;
    let mut seed = Zeroizing::new(
        hex::decode(text.trim())
            .map_err(|_| NodeError::Keystore("identity file is not valid hex".into()))?,
    );
    if seed.len() != 32 {
        seed.zeroize();
        return Err(NodeError::Keystore("identity seed must be 32 bytes".into()));
    }
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&seed);
    Ok(NodeIdentity::from_seed(&arr))
}

/// Persist an identity's secret seed to `path` with `0600` permissions (best-effort on non-Unix),
/// refusing to overwrite an existing file or follow a symlink.
pub fn save(path: &Path, id: &NodeIdentity) -> Result<()> {
    let seed = Zeroizing::new(id.to_seed_bytes());
    let text = Zeroizing::new(hex::encode(seed.as_slice()));
    let mut f = create_owner_only(path).map_err(|e| match e {
        NodeError::Io(io) if io.kind() == ErrorKind::AlreadyExists => NodeError::Keystore(format!(
            "identity already exists at {} (refusing to overwrite)",
            path.display()
        )),
        other => other,
    })?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Atomically create a **new** file readable/writable only by the owner (`0600` on Unix).
///
/// Fails with `AlreadyExists` if anything — including a dangling symlink — is at `path`
/// (`O_CREAT|O_EXCL` never follows symlinks).
pub(crate) fn create_owner_only(path: &Path) -> Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}

/// Open `path` for reading, refusing a symlink (and detecting a swap between check and open).
fn open_no_symlink(path: &Path) -> Result<File> {
    let before = std::fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() {
        return Err(NodeError::Keystore(format!(
            "refusing to read identity through a symlink: {}",
            path.display()
        )));
    }
    if !before.file_type().is_file() {
        return Err(NodeError::Keystore(format!(
            "identity path is not a regular file: {}",
            path.display()
        )));
    }
    let file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let opened = file.metadata()?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(NodeError::Keystore(
                "identity file changed while opening (possible symlink race)".into(),
            ));
        }
        let mode = opened.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode & 0o777),
                "identity key is accessible by group/others; run `chmod 600` on it"
            );
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("umesh-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generate_persist_reload_is_stable() {
        let dir = tmpdir("ks");
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
        let dir = tmpdir("ks2");
        let path = dir.join("identity.key");
        let id = NodeIdentity::generate();
        save(&path, &id).unwrap();
        assert!(save(&path, &id).is_err(), "must refuse to overwrite");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("ks-perm");
        let path = dir.join("identity.key");
        save(&path, &NodeIdentity::generate()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity key must be owner-only");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_follow_symlink() {
        let dir = tmpdir("ks-symlink-save");
        let victim = dir.join("victim");
        let path = dir.join("identity.key");
        // Dangling symlink: the old `exists()` check returned false and `fs::write` followed it.
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(save(&path, &NodeIdentity::generate()).is_err());
        assert!(!victim.exists(), "must not create the symlink target");
        // Same via load_or_generate.
        assert!(load_or_generate(&path).is_err());
        assert!(!victim.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_symlink() {
        let dir = tmpdir("ks-symlink-load");
        let real = dir.join("real.key");
        save(&real, &NodeIdentity::generate()).unwrap();
        let link = dir.join("identity.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = load(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(load(&real).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
