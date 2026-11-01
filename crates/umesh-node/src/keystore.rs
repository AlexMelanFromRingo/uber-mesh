//! Identity keystore: generate / load a node's long-term Ed25519 seed with restrictive permissions.
//!
//! Hardening (audit 2026-11):
//! - the key file is created atomically with `O_CREAT|O_EXCL` and mode `0600` — it is never briefly
//!   world-readable, and `O_EXCL` refuses to follow (or overwrite) any pre-planted file or symlink;
//! - loading refuses a symlink and detects a swap between the check and the open;
//! - the seed and its hex text are zeroized after use.
//!
//! Identity proof-of-work (0.10.0): a gossip sender must carry a nonce proving
//! `pow::MIN_SENDER_POW_BITS` of work bound to its public key. It is mined once and persisted in a
//! **sidecar** next to the key (`identity.key` → `identity.pow`), so the secret key file keeps its
//! format and is never rewritten: pre-0.10 keystores load unchanged and get their nonce mined
//! lazily on first use ([`load_with_pow`]), and older binaries still read a new keystore. The
//! sidecar holds only public data, is re-verified against the key on every load (a stale or edited
//! one is re-mined, never trusted), and is written atomically with mode `0600`.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use umesh_crypto::identity::NodeIdentity;
use umesh_crypto::pow;
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

/// Header line of the identity-PoW sidecar file (format version 1).
const POW_FILE_HEADER: &str = "uber-mesh identity pow v1";

/// Path of the identity-PoW sidecar for the key at `key_path` (`identity.key` → `identity.pow`).
pub fn pow_path(key_path: &Path) -> PathBuf {
    key_path.with_extension("pow")
}

/// An identity's proof-of-work as loaded (or mined) for use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityPow {
    /// The nonce (public; carried in every gossip message).
    pub nonce: u64,
    /// Work it proves for this identity (leading zero bits, ≥ the required minimum).
    pub bits: u32,
    /// `Some(elapsed)` if it was mined by this call (missing/stale sidecar), `None` if loaded.
    pub mined_in: Option<Duration>,
}

/// Read the persisted nonce for `id`. `Ok(None)` if the sidecar is missing, malformed, belongs to
/// another key or proves less than `min_bits` (the caller re-mines; it is never trusted unchecked).
/// Refuses a symlink like the key itself.
pub fn load_pow(key_path: &Path, id: &NodeIdentity, min_bits: u32) -> Result<Option<IdentityPow>> {
    let path = pow_path(key_path);
    let mut file = match open_no_symlink(&path) {
        Ok(f) => f,
        Err(NodeError::Io(e)) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut text = String::new();
    // Tiny file; cap the read so a planted huge file can't exhaust memory.
    (&mut file).take(256).read_to_string(&mut text)?;
    let Some(nonce) = parse_pow_file(&text) else {
        tracing::warn!(path = %path.display(), "malformed identity PoW file; re-mining");
        return Ok(None);
    };
    let bits = pow::identity_pow_bits(&id.verifying_key().to_bytes(), nonce);
    if bits < min_bits {
        tracing::warn!(
            path = %path.display(),
            bits,
            min_bits,
            "identity PoW does not match this key or is below the network minimum; re-mining"
        );
        return Ok(None);
    }
    Ok(Some(IdentityPow {
        nonce,
        bits,
        mined_in: None,
    }))
}

fn parse_pow_file(text: &str) -> Option<u64> {
    let mut lines = text.lines();
    if lines.next()?.trim() != POW_FILE_HEADER {
        return None;
    }
    let nonce = lines.next()?.trim().strip_prefix("nonce=")?.parse().ok()?;
    lines.all(|l| l.trim().is_empty()).then_some(nonce)
}

/// Persist `nonce` to the sidecar of `key_path` (atomic replace, `0600`, never through a symlink).
pub fn save_pow(key_path: &Path, nonce: u64) -> Result<()> {
    write_owner_only_atomic(
        &pow_path(key_path),
        format!("{POW_FILE_HEADER}\nnonce={nonce}\n").as_bytes(),
    )
}

/// Mine an identity PoW nonce for `id` at `min_bits` on all cores. `progress` receives the number
/// of hashes tried so far (expected total: `2^min_bits`).
pub fn mine_pow(
    id: &NodeIdentity,
    min_bits: u32,
    progress: &(dyn Fn(u64) + Sync),
) -> Result<IdentityPow> {
    let key = id.verifying_key().to_bytes();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let start = Instant::now();
    let nonce = pow::mine_identity_with(&key, min_bits, threads, progress)
        .ok_or_else(|| NodeError::Keystore(format!("unachievable PoW difficulty {min_bits}")))?;
    Ok(IdentityPow {
        nonce,
        bits: pow::identity_pow_bits(&key, nonce),
        mined_in: Some(start.elapsed()),
    })
}

/// Load the identity at `key_path` together with its proof-of-work, mining and persisting the
/// nonce if the sidecar is missing or stale — the migration path for pre-0.10 keystores. If the
/// sidecar cannot be written (e.g. a read-only data dir) the freshly mined nonce is still returned
/// (with a warning): the node works, it just re-mines on the next start.
pub fn load_with_pow(
    key_path: &Path,
    min_bits: u32,
    progress: &(dyn Fn(u64) + Sync),
) -> Result<(NodeIdentity, IdentityPow)> {
    let id = load(key_path)?;
    if let Some(p) = load_pow(key_path, &id, min_bits)? {
        return Ok((id, p));
    }
    let mined = mine_pow(&id, min_bits, progress)?;
    if let Err(e) = save_pow(key_path, mined.nonce) {
        tracing::warn!(error = %e, "could not persist the identity PoW; it will be re-mined");
    }
    Ok((id, mined))
}

/// Write `data` to `path` atomically with owner-only permissions: a fresh temp file
/// (`create_new`, mode `0600`) in the same directory, fsynced, then renamed into place — never
/// briefly world-readable, and a pre-planted symlink at `path` is replaced rather than followed.
pub(crate) fn write_owner_only_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| NodeError::Keystore(format!("invalid path {}", path.display())))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let res = (|| -> Result<()> {
        let mut f = create_owner_only(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
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

    /// Cheap difficulty for keystore tests (the network minimum is exercised in umesh-p2p).
    const BITS: u32 = 10;

    #[test]
    fn pow_roundtrip_and_reload_without_mining() {
        let dir = tmpdir("ks-pow");
        let path = dir.join("identity.key");
        let id = NodeIdentity::generate();
        save(&path, &id).unwrap();
        let mined = mine_pow(&id, BITS, &|_| {}).unwrap();
        assert!(mined.bits >= BITS && mined.mined_in.is_some());
        save_pow(&path, mined.nonce).unwrap();
        assert_eq!(pow_path(&path), dir.join("identity.pow"));
        let (back, p) = load_with_pow(&path, BITS, &|_| panic!("must not re-mine")).unwrap();
        assert_eq!(back.peer_id(), id.peer_id());
        assert_eq!(
            (p.nonce, p.bits, p.mined_in),
            (mined.nonce, mined.bits, None)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Migration: a pre-0.10 keystore (bare hex seed, no sidecar) still loads; the nonce is mined
    /// once, persisted, and reused afterwards. The key file itself is never rewritten.
    #[test]
    fn legacy_keystore_without_pow_is_migrated() {
        let dir = tmpdir("ks-legacy");
        let path = dir.join("identity.key");
        let id = NodeIdentity::from_seed(&[0x5a; 32]);
        std::fs::write(&path, format!("{}\n", hex::encode([0x5a; 32]))).unwrap(); // legacy format
        let key_before = std::fs::read(&path).unwrap();
        assert!(load_pow(&path, &id, BITS).unwrap().is_none());

        let (loaded, first) = load_with_pow(&path, BITS, &|_| {}).unwrap();
        assert_eq!(loaded.peer_id(), id.peer_id());
        assert!(first.mined_in.is_some(), "mined on first load");
        assert!(pow::verify_identity(
            &id.verifying_key().to_bytes(),
            first.nonce,
            BITS
        ));
        let (_, second) = load_with_pow(&path, BITS, &|_| panic!("must not re-mine")).unwrap();
        assert_eq!(second.nonce, first.nonce);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            key_before,
            "key file untouched"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(pow_path(&path))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A sidecar that is malformed, belongs to another key, or proves too little is never trusted:
    /// it is re-mined and replaced.
    #[test]
    fn stale_or_foreign_pow_is_remined() {
        let dir = tmpdir("ks-pow-stale");
        let path = dir.join("identity.key");
        let id = NodeIdentity::from_seed(&[0x61; 32]);
        save(&path, &id).unwrap();
        let key = id.verifying_key().to_bytes();
        let other = NodeIdentity::from_seed(&[0x62; 32])
            .verifying_key()
            .to_bytes();
        // Valid work for another key that is not valid for ours.
        let foreign = (0u64..)
            .find(|&n| {
                pow::verify_identity(&other, n, BITS) && !pow::verify_identity(&key, n, BITS)
            })
            .unwrap();
        let weak = (0u64..)
            .find(|&n| pow::identity_pow_bits(&key, n) < BITS)
            .unwrap();
        for bad in [
            format!("{POW_FILE_HEADER}\nnonce={foreign}\n"),
            format!("{POW_FILE_HEADER}\nnonce={weak}\n"),
            "garbage".to_string(),
            format!("{POW_FILE_HEADER}\nnonce=-1\n"),
            format!("{POW_FILE_HEADER}\nnonce=1\nextra\n"),
        ] {
            std::fs::write(pow_path(&path), &bad).unwrap();
            assert!(load_pow(&path, &id, BITS).unwrap().is_none(), "{bad:?}");
            let (_, p) = load_with_pow(&path, BITS, &|_| {}).unwrap();
            assert!(p.mined_in.is_some() && pow::verify_identity(&key, p.nonce, BITS));
            assert_eq!(
                load_pow(&path, &id, BITS).unwrap().map(|q| q.nonce),
                Some(p.nonce),
                "replaced by the re-mined nonce"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn pow_file_symlink_is_refused_and_not_followed_on_write() {
        let dir = tmpdir("ks-pow-symlink");
        let path = dir.join("identity.key");
        let id = NodeIdentity::generate();
        save(&path, &id).unwrap();
        let victim = dir.join("victim");
        std::os::unix::fs::symlink(&victim, pow_path(&path)).unwrap();
        assert!(
            load_pow(&path, &id, BITS).is_err(),
            "symlinked sidecar refused"
        );
        save_pow(&path, 7).unwrap(); // replaces the link, never writes through it
        assert!(!victim.exists());
        assert!(
            !std::fs::symlink_metadata(pow_path(&path))
                .unwrap()
                .file_type()
                .is_symlink()
        );
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
