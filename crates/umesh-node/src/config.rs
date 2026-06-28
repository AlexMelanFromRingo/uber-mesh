//! Node configuration (`config.toml`) and data-directory layout.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use umesh_obfs::{ObfsPsk, Profile};

use crate::error::{NodeError, Result};

/// On-disk node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s).map_err(|e| NodeError::Config(e.to_string()))
    }

    /// Persist config to a TOML file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let s = toml::to_string_pretty(self).map_err(|e| NodeError::Config(e.to_string()))?;
        std::fs::write(path, s)?;
        Ok(())
    }

    /// Resolve the environment profile (defaults to Moderate on an unknown name).
    pub fn profile(&self) -> Profile {
        Profile::parse(&self.profile).unwrap_or(Profile::Moderate)
    }

    /// Decode the obfs PSK from its hex representation.
    pub fn psk(&self) -> Result<ObfsPsk> {
        let v = hex::decode(self.psk_hex.trim())
            .map_err(|_| NodeError::Config("psk_hex is not valid hex".into()))?;
        let arr: [u8; 32] = v
            .try_into()
            .map_err(|_| NodeError::Config("psk must be exactly 32 bytes".into()))?;
        Ok(ObfsPsk(arr))
    }

    /// A non-secret fingerprint of the PSK for display (`BLAKE3(psk)[..8]`), never the PSK itself.
    pub fn psk_fingerprint(&self) -> String {
        match self.psk() {
            Ok(psk) => {
                let fp = umesh_crypto::hash::hash(&psk.0);
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

    /// Create the data directory if missing.
    pub fn ensure(&self) -> Result<()> {
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
