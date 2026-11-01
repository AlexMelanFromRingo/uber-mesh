//! Node configuration (`config.toml`) and data-directory layout.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use umesh_obfs::{ObfsPsk, Profile};
use zeroize::Zeroize;

use crate::error::{NodeError, Result};

/// On-disk node configuration.
///
/// `config.toml` carries the cohort PSK and any sealed-topic keys, so it is written owner-only
/// (`0600`) and those secrets are wiped from memory when the config is dropped. `Debug` redacts
/// them (topic names are shown, keys never).
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
    /// Sealed-topic keys: topic name → hex-encoded 32-byte topic key, shared out of band among the
    /// topic's members (end-to-end payload confidentiality; see `umesh_p2p::sealed`). A topic not
    /// listed here is **public**: every peer that forwards its messages can read them. A config
    /// holding topic keys must not be group/world-accessible (refused on load).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub topic_keys: BTreeMap<String, String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("profile", &self.profile)
            .field("listen", &self.listen)
            .field("bootstrap", &self.bootstrap)
            .field("psk_hex", &"<redacted>")
            .field(
                "topic_keys",
                &self
                    .topic_keys
                    .keys()
                    .map(|t| (t.as_str(), "<redacted>"))
                    .collect::<BTreeMap<_, _>>(),
            )
            .finish()
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        self.psk_hex.zeroize();
        for v in self.topic_keys.values_mut() {
            v.zeroize();
        }
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
            topic_keys: BTreeMap::new(),
        }
    }

    /// Load config from a TOML file and validate it (an unknown profile name is an error, not a
    /// silent fallback — a typo must never quietly downgrade the obfuscation posture).
    pub fn load(path: &Path) -> Result<Self> {
        let s = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
        let cfg: Config = toml::from_str(&s).map_err(|e| NodeError::Config(e.to_string()))?;
        cfg.profile()?;
        if !cfg.topic_keys.is_empty() {
            refuse_shared_permissions(path)?;
            for topic in cfg.topic_keys.keys() {
                cfg.topic_key(topic)?;
            }
        }
        Ok(cfg)
    }

    /// Decode the sealed-topic key configured for `topic`, if any (wiped on drop). The error names
    /// the topic, never the value.
    pub fn topic_key(&self, topic: &str) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
        let Some(h) = self.topic_keys.get(topic) else {
            return Ok(None);
        };
        decode_key32(h).map(Some).ok_or_else(|| {
            NodeError::Config(format!("topic_keys[{topic:?}] must be 32 bytes of hex"))
        })
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
        crate::keystore::write_owner_only_atomic(path, s.as_bytes())
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

    /// Names of the topics this config holds keys for (never the keys).
    pub fn sealed_topics(&self) -> Vec<String> {
        self.topic_keys.keys().cloned().collect()
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

/// Decode exactly 32 bytes of hex (surrounding whitespace ignored) into a wiped buffer.
pub fn decode_key32(h: &str) -> Option<zeroize::Zeroizing<[u8; 32]>> {
    let v = zeroize::Zeroizing::new(hex::decode(h.trim()).ok()?);
    if v.len() != 32 {
        return None;
    }
    let mut arr = zeroize::Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&v);
    Some(arr)
}

/// Refuse a secrets-bearing file that group/others can access (Unix). `save` always writes `0600`;
/// this catches a config edited or copied in by hand.
fn refuse_shared_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(NodeError::Config(format!(
                "{} holds topic keys but is accessible by group/others (mode {:o}); run `chmod 600`",
                path.display(),
                mode & 0o777
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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

    /// Path to the identity proof-of-work sidecar (public nonce; see [`crate::keystore`]).
    pub fn identity_pow(&self) -> PathBuf {
        crate::keystore::pow_path(&self.identity())
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
    fn topic_keys_roundtrip_are_redacted_and_validated() {
        let dir = tmpdir("cfg-topic");
        let path = dir.join("config.toml");
        let key_hex = "5e".repeat(32);
        let mut cfg = Config::default_with_psk("aa".repeat(32));
        assert!(
            !toml::to_string(&cfg).unwrap().contains("topic_keys"),
            "omitted when empty"
        );
        cfg.topic_keys
            .insert("uber-mesh/secret".into(), key_hex.clone());
        assert!(
            !format!("{cfg:?}").contains(&key_hex),
            "Debug redacts topic keys"
        );
        assert!(format!("{cfg:?}").contains("uber-mesh/secret"));
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(
            *loaded.topic_key("uber-mesh/secret").unwrap().unwrap(),
            [0x5e; 32]
        );
        assert!(loaded.topic_key("uber-mesh/global").unwrap().is_none());
        assert_eq!(loaded.sealed_topics(), vec!["uber-mesh/secret".to_string()]);

        // A malformed key is a config error that never echoes the value.
        cfg.topic_keys.insert("t".into(), "ab".repeat(31));
        cfg.save(&path).unwrap();
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("topic_keys") && !err.contains(&"ab".repeat(31)),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_config_with_topic_keys_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("cfg-topic-perm");
        let path = dir.join("config.toml");
        let mut cfg = Config::default_with_psk("aa".repeat(32));
        cfg.topic_keys.insert("t".into(), "11".repeat(32));
        cfg.save(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("chmod 600") && !err.contains(&"11".repeat(32)),
            "{err}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Config::load(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
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
