//! Node configuration (`config.toml`) and data-directory layout.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use umesh_obfs::{ObfsPsk, Profile};
use zeroize::Zeroize;

use crate::error::{NodeError, Result};

/// On-disk node configuration.
///
/// `config.toml` carries the cohort PSK, so it is written owner-only (`0600`) and the PSK is wiped
/// from memory when the config is dropped. `Debug` redacts the PSK.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// Environment profile name: `open` | `moderate` | `aggressive` | `shutdown`.
    pub profile: String,
    /// Address to listen on (`host:port`), if this node accepts connections.
    #[serde(default)]
    pub listen: Option<String>,
    /// Bootstrap/peer endpoints to dial on startup (`host:port`).
    #[serde(default)]
    pub bootstrap: Vec<String>,
    /// Hex-encoded 32-byte obfs pre-shared "bridge" secret shared by a cohort of nodes.
    ///
    /// This gates the obfs handshake (probe resistance). It is NOT a node secret — it is shared
    /// out-of-band among peers that should be able to reach each other, like a bridge line.
    pub psk_hex: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("profile", &self.profile)
            .field("listen", &self.listen)
            .field("bootstrap", &self.bootstrap)
            .field("psk_hex", &"<redacted>")
            .finish()
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        self.psk_hex.zeroize();
    }
}

impl Config {
    /// A sensible default config carrying the given PSK.
    pub fn default_with_psk(psk_hex: String) -> Self {
        Config {
            profile: "moderate".to_string(),
            listen: Some("127.0.0.1:4001".to_string()),
            bootstrap: Vec::new(),
            psk_hex,
        }
    }

    /// Load config from a TOML file and validate it (an unknown profile name is an error, not a
    /// silent fallback — a typo must never quietly downgrade the obfuscation posture).
    pub fn load(path: &Path) -> Result<Self> {
        let s = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
        let cfg: Config = toml::from_str(&s).map_err(|e| NodeError::Config(e.to_string()))?;
        cfg.profile()?;
        Ok(cfg)
    }

    /// Persist config to a TOML file with owner-only (`0600`) permissions.
    ///
    /// Written to a fresh temp file (`create_new`, mode `0600`) in the same directory and renamed
    /// into place, so the PSK is never briefly world-readable and a pre-planted symlink at `path`
    /// is replaced rather than followed.
    pub fn save(&self, path: &Path) -> Result<()> {
        let s = zeroize::Zeroizing::new(
            toml::to_string_pretty(self).map_err(|e| NodeError::Config(e.to_string()))?,
        );
        let file_name = path
            .file_name()
            .ok_or_else(|| NodeError::Config(format!("invalid config path {}", path.display())))?;
        let mut tmp_name = file_name.to_os_string();
        tmp_name.push(format!(".tmp.{}", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        let res = (|| -> Result<()> {
            let mut f = crate::keystore::create_owner_only(&tmp)?;
            f.write_all(s.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)?;
            Ok(())
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        res
    }

    /// Resolve the environment profile. An unknown name is a configuration error.
    pub fn profile(&self) -> Result<Profile> {
        Profile::parse(&self.profile).ok_or_else(|| {
            NodeError::Config(format!(
                "unknown profile {:?} (expected open|moderate|aggressive|shutdown)",
                self.profile
            ))
        })
    }

    /// Decode the obfs PSK bytes from their hex representation (wiped on drop).
    fn psk_bytes(&self) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let v = zeroize::Zeroizing::new(
            hex::decode(self.psk_hex.trim())
                .map_err(|_| NodeError::Config("psk_hex is not valid hex".into()))?,
        );
        if v.len() != 32 {
            return Err(NodeError::Config("psk must be exactly 32 bytes".into()));
        }
        let mut arr = zeroize::Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&v);
        Ok(arr)
    }

    /// Decode the obfs PSK from its hex representation.
    pub fn psk(&self) -> Result<ObfsPsk> {
        Ok(ObfsPsk::new(*self.psk_bytes()?))
    }

    /// A non-secret fingerprint of the PSK for display (`BLAKE3(psk)[..6]`), never the PSK itself.
    pub fn psk_fingerprint(&self) -> String {
        match self.psk_bytes() {
            Ok(psk) => {
                let fp = umesh_crypto::hash::hash(&*psk);
                hex::encode(&fp[..6])
            }
            Err(_) => "invalid".to_string(),
        }
    }
}

/// Standard paths inside a data directory.
pub struct DataDir {
    /// Root data directory.
    pub root: PathBuf,
}

impl DataDir {
    /// Wrap a data-directory path.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DataDir { root: root.into() }
    }

    /// Path to the identity keystore file.
    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.key")
    }

    /// Path to the config file.
    pub fn config(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// Create the data directory if missing (owner-only `0700` on Unix). An existing directory is
    /// left as-is (it may be a user-chosen path), but a group/world-accessible one is warned about.
    pub fn ensure(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.root)?;
            let mode = std::fs::metadata(&self.root)?.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    dir = %self.root.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "data directory is accessible by group/others; consider `chmod 700`"
                );
            }
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&self.root)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip() {
        let cfg = Config::default_with_psk("aa".repeat(32));
        let dir = std::env::temp_dir().join(format!("umesh-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.profile, "moderate");
        assert!(loaded.psk().is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bad_psk_is_rejected() {
        let cfg = Config::default_with_psk("zz".into());
        assert!(cfg.psk().is_err());
        let cfg2 = Config::default_with_psk("aa".repeat(31));
        assert!(cfg2.psk().is_err(), "must be exactly 32 bytes");
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("umesh-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn mistyped_profile_is_an_error() {
        let dir = tmpdir("cfg-typo");
        let path = dir.join("config.toml");
        let mut cfg = Config::default_with_psk("aa".repeat(32));
        cfg.profile = "agressive".into(); // typo
        assert!(
            cfg.profile().is_err(),
            "typo must not fall back to Moderate"
        );
        cfg.save(&path).unwrap();
        let err = Config::load(&path).unwrap_err();
        assert!(err.to_string().contains("unknown profile"), "{err}");
        cfg.profile = "Aggressive".into();
        assert_eq!(cfg.profile().unwrap(), Profile::Aggressive);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn debug_redacts_psk() {
        let psk_hex = "cd".repeat(32);
        let cfg = Config::default_with_psk(psk_hex.clone());
        assert!(!format!("{cfg:?}").contains(&psk_hex));
    }

    #[cfg(unix)]
    #[test]
    fn config_and_data_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = tmpdir("cfg-perm");
        let dd = DataDir::new(base.join("data"));
        dd.ensure().unwrap();
        let dmode = std::fs::metadata(&dd.root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "data dir must be 0700");

        let cfg = Config::default_with_psk("aa".repeat(32));
        cfg.save(&dd.config()).unwrap();
        let fmode = std::fs::metadata(dd.config()).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600, "config.toml (holds the PSK) must be 0600");

        // A planted symlink at the config path is replaced, not followed.
        let victim = base.join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        std::fs::remove_file(dd.config()).unwrap();
        std::os::unix::fs::symlink(&victim, dd.config()).unwrap();
        cfg.save(&dd.config()).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(
            !std::fs::symlink_metadata(dd.config())
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn fingerprint_is_not_the_psk() {
        let psk_hex = "bb".repeat(32);
        let cfg = Config::default_with_psk(psk_hex.clone());
        let fp = cfg.psk_fingerprint();
        assert!(
            !psk_hex.contains(&fp),
            "fingerprint must not reveal the psk"
        );
    }
}
