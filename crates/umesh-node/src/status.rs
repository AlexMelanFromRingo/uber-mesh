//! Node status model — human + JSON, never containing secret material (FR-020 / Principle VI).

use serde::Serialize;

use crate::config::Config;
use umesh_crypto::identity::NodeIdentity;

/// A point-in-time snapshot of node status.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    /// This node's PeerId (`b3:…`).
    pub peer_id: String,
    /// Active environment profile.
    pub profile: String,
    /// Listen address, if any.
    pub listen: Option<String>,
    /// Configured bootstrap endpoints.
    pub bootstrap: Vec<String>,
    /// Non-secret fingerprint of the obfs PSK (never the PSK).
    pub psk_fingerprint: String,
    /// Topics configured as sealed (end-to-end encrypted) — names only, never the keys.
    pub sealed_topics: Vec<String>,
    /// Transport states.
    pub transports: Vec<TransportStatus>,
    /// Peer counts.
    pub peers: PeerCounts,
    /// Recent events (rotation, connect, reject).
    pub events: Vec<Event>,
}

/// Per-transport status line.
#[derive(Debug, Clone, Serialize)]
pub struct TransportStatus {
    /// Carrier kind, e.g. `obfs-tcp`.
    pub kind: String,
    /// State, e.g. `listening`, `healthy`, `idle`.
    pub state: String,
}

/// Connected / known peer counts.
#[derive(Debug, Clone, Serialize)]
pub struct PeerCounts {
    /// Currently connected peers.
    pub connected: usize,
    /// Total known peers.
    pub known: usize,
}

/// A node event for the status feed.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Event kind: `connect` | `reject` | `rotation` | `listen`.
    pub kind: String,
    /// Human-readable detail (must not contain secrets).
    pub detail: String,
}

impl NodeStatus {
    /// Build a status snapshot from persisted identity + config (no live runtime state).
    pub fn from_static(identity: &NodeIdentity, config: &Config) -> Self {
        let mut transports = Vec::new();
        if config.listen.is_some() {
            transports.push(TransportStatus {
                kind: "obfs-tcp".into(),
                state: "configured".into(),
            });
        }
        NodeStatus {
            peer_id: identity.peer_id().to_string(),
            profile: config.profile.clone(),
            listen: config.listen.clone(),
            bootstrap: config.bootstrap.clone(),
            psk_fingerprint: config.psk_fingerprint(),
            sealed_topics: config.sealed_topics(),
            transports,
            peers: PeerCounts {
                connected: 0,
                known: 0,
            },
            events: Vec::new(),
        }
    }

    /// Pretty JSON form.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("NodeStatus is always serializable")
    }

    /// Human-readable form.
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("peer_id:    {}\n", self.peer_id));
        out.push_str(&format!("profile:    {}\n", self.profile));
        out.push_str(&format!(
            "listen:     {}\n",
            self.listen.as_deref().unwrap_or("-")
        ));
        out.push_str(&format!(
            "bootstrap:  {}\n",
            if self.bootstrap.is_empty() {
                "-".into()
            } else {
                self.bootstrap.join(", ")
            }
        ));
        out.push_str(&format!("psk_fp:     {}\n", self.psk_fingerprint));
        out.push_str(&format!(
            "sealed:     {}\n",
            if self.sealed_topics.is_empty() {
                "- (all topics public)".into()
            } else {
                self.sealed_topics.join(", ")
            }
        ));
        out.push_str(&format!(
            "peers:      {} connected / {} known\n",
            self.peers.connected, self.peers.known
        ));
        out.push_str("transports:\n");
        for t in &self.transports {
            out.push_str(&format!("  - {} [{}]\n", t.kind, t.state));
        }
        if !self.events.is_empty() {
            out.push_str("events:\n");
            for e in &self.events {
                out.push_str(&format!("  - {}: {}\n", e.kind, e.detail));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_never_contains_secrets() {
        let id = NodeIdentity::from_seed(&[3u8; 32]);
        let psk_hex = "cd".repeat(32);
        let mut cfg = Config::default_with_psk(psk_hex.clone());
        let topic_hex = "7a".repeat(32);
        cfg.topic_keys
            .insert("uber-mesh/secret".into(), topic_hex.clone());
        let st = NodeStatus::from_static(&id, &cfg);
        let json = st.to_json();
        // The PSK, topic keys and the identity seed must never appear in status output.
        assert!(!json.contains(&psk_hex));
        assert!(!json.contains(&topic_hex) && !st.to_human().contains(&topic_hex));
        assert!(
            json.contains("uber-mesh/secret"),
            "sealed topic names are listed"
        );
        assert!(!json.contains(&hex::encode(id.to_seed_bytes())));
        assert!(st.to_human().contains("peer_id"));
    }
}
