//! Environment profiles: the toggle that selects transport order, shaping, and UDP policy by how
//! hostile the network is (research D2/obfuscation-design). Resilience comes from agility, so the
//! node picks a profile and the profile drives everything else.

use crate::shaping::ShapingPolicy;

/// How hostile the surrounding network is assumed to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Uncensored: prefer the fast path, minimal shaping.
    Open,
    /// Light DPI: obfuscated TCP preferred, light shaping.
    Moderate,
    /// Aggressive DPI (RU TSPU / IR IRGFW): obfuscated TCP only, heavy shaping.
    Aggressive,
    /// Near-blackout: obfuscated TCP locally, max shaping (future local-RF tier).
    Shutdown,
}

/// A carrier kind. Only `ObfsTcp` is implemented this iteration; `Quic` is reserved (plan deferral).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    /// Obfuscated TCP carrier (TLS-record-framed, probe-resistant).
    ObfsTcp,
    /// Plain QUIC (opportunistic; open networks only) — wired in the US2 phase.
    Quic,
}

impl Profile {
    /// Parse a profile name leniently (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "open" => Some(Profile::Open),
            "moderate" => Some(Profile::Moderate),
            "aggressive" => Some(Profile::Aggressive),
            "shutdown" => Some(Profile::Shutdown),
            _ => None,
        }
    }

    /// Ordered transport preference for this profile, given runtime UDP availability.
    /// QUIC (UDP) is opportunistic and is dropped whenever UDP is unavailable (research D9/nat).
    pub fn transports(&self, udp_available: bool) -> Vec<TransportKind> {
        match self {
            Profile::Open if udp_available => vec![TransportKind::Quic, TransportKind::ObfsTcp],
            Profile::Moderate if udp_available => vec![TransportKind::ObfsTcp, TransportKind::Quic],
            // Aggressive/Shutdown never rely on UDP; Open/Moderate fall back to TCP without UDP.
            _ => vec![TransportKind::ObfsTcp],
        }
    }

    /// Whether QUIC/UDP is permitted at all for this profile.
    pub fn udp_allowed(&self) -> bool {
        matches!(self, Profile::Open | Profile::Moderate)
    }

    /// The default shaping policy for this profile.
    pub fn shaping(&self) -> ShapingPolicy {
        match self {
            Profile::Open => ShapingPolicy::none(),
            Profile::Moderate => ShapingPolicy::light(),
            Profile::Aggressive | Profile::Shutdown => ShapingPolicy::aggressive(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        assert_eq!(Profile::parse("Aggressive"), Some(Profile::Aggressive));
        assert_eq!(Profile::parse("OPEN"), Some(Profile::Open));
        assert_eq!(Profile::parse("nope"), None);
    }

    #[test]
    fn aggressive_never_uses_udp() {
        assert_eq!(
            Profile::Aggressive.transports(true),
            vec![TransportKind::ObfsTcp]
        );
        assert!(!Profile::Aggressive.udp_allowed());
    }

    #[test]
    fn open_drops_quic_without_udp() {
        assert_eq!(
            Profile::Open.transports(false),
            vec![TransportKind::ObfsTcp],
            "must fall back to TCP when UDP is blocked"
        );
        assert_eq!(Profile::Open.transports(true)[0], TransportKind::Quic);
    }
}
