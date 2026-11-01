//! Traffic-shaping policy: record padding + inter-arrival timing jitter.
//!
//! Shaping is applied as a wrapper around the secure record stream (research D2: shaping must be
//! independent of the transport, toggleable per environment profile). It blunts length/timing
//! signatures (TLS-in-TLS record-size tells, website fingerprinting).

use rand::Rng;

/// How aggressively to pad and jitter records.
///
/// Padding = (round-up to the next `pad_to` bucket, if set) **plus** a uniformly random
/// `min_pad..=max_pad` bytes. The random component is always applied — bucketing alone would make
/// every record length ≡ constant (mod bucket), a static length signature (Principle II).
///
/// Cover/decoy traffic is **not** implemented; there is deliberately no flag for it, so no profile
/// can claim a protection it does not provide.
#[derive(Clone, Debug)]
pub struct ShapingPolicy {
    /// If set, first pad each record's framed length up to a multiple of this bucket size.
    pub pad_to: Option<usize>,
    /// Minimum random padding bytes added to every record (on top of bucket rounding).
    pub min_pad: usize,
    /// Maximum random padding bytes added to every record (on top of bucket rounding).
    pub max_pad: usize,
    /// Maximum inter-arrival timing jitter in milliseconds (0 = off). Honored by
    /// [`crate::secure::SecureStream`]; the poll-based [`crate::bytestream::ObfsByteStream`]
    /// does not sleep (it coalesces writes instead).
    pub iat_jitter_ms: u32,
}

impl ShapingPolicy {
    /// No shaping (lowest overhead) — for uncensored networks.
    pub fn none() -> Self {
        Self {
            pad_to: None,
            min_pad: 0,
            max_pad: 0,
            iat_jitter_ms: 0,
        }
    }

    /// Light shaping — bucket lengths plus a small random tail, no timing cost.
    pub fn light() -> Self {
        Self {
            pad_to: Some(256),
            min_pad: 0,
            max_pad: 64,
            iat_jitter_ms: 0,
        }
    }

    /// Aggressive shaping — bigger buckets, larger random padding, timing jitter.
    pub fn aggressive() -> Self {
        Self {
            pad_to: Some(512),
            min_pad: 16,
            max_pad: 256,
            iat_jitter_ms: 8,
        }
    }

    /// Whether this policy adds any padding at all.
    pub fn pads(&self) -> bool {
        self.pad_to.is_some_and(|b| b > 1) || self.max_pad > 0 || self.min_pad > 0
    }

    /// Compute the number of padding bytes to append given the already-framed plaintext length:
    /// bucket round-up (if `pad_to`) + uniform random in `min_pad..=max(min_pad, max_pad)`.
    ///
    /// Callers must clamp the result to their record ceiling.
    pub fn pad_len(&self, framed_len: usize) -> usize {
        let to_bucket = match self.pad_to {
            Some(bucket) if bucket > 0 => {
                let rem = framed_len % bucket;
                if rem == 0 { 0 } else { bucket - rem }
            }
            _ => 0,
        };
        let random = if self.max_pad > self.min_pad {
            rand::thread_rng().gen_range(self.min_pad..=self.max_pad)
        } else {
            self.min_pad
        };
        to_bucket.saturating_add(random)
    }

    /// Sleep for a random sub-`iat_jitter_ms` interval (no-op when jitter is 0).
    pub async fn jitter(&self) {
        if self.iat_jitter_ms > 0 {
            let ms = rand::thread_rng().gen_range(0..=u64::from(self.iat_jitter_ms));
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_padding_rounds_up() {
        let p = ShapingPolicy {
            pad_to: Some(256),
            min_pad: 0,
            max_pad: 0,
            iat_jitter_ms: 0,
        };
        assert_eq!(p.pad_len(256), 0);
        assert_eq!(p.pad_len(200), 56);
        assert_eq!(p.pad_len(257), 255);
    }

    #[test]
    fn random_padding_within_bounds() {
        let p = ShapingPolicy {
            pad_to: None,
            min_pad: 8,
            max_pad: 32,
            iat_jitter_ms: 0,
        };
        for _ in 0..100 {
            let n = p.pad_len(123);
            assert!((8..=32).contains(&n));
        }
    }

    #[test]
    fn none_adds_nothing() {
        assert_eq!(ShapingPolicy::none().pad_len(7), 0);
        assert!(!ShapingPolicy::none().pads());
        assert!(ShapingPolicy::light().pads());
    }

    /// Audit F6 regression: with `pad_to` set the random component was dropped, so every padded
    /// length was ≡ 0 (mod bucket). It must now vary within `min_pad..=max_pad` on top of the bucket.
    #[test]
    fn bucket_plus_random_padding_is_not_constant_mod_bucket() {
        for p in [ShapingPolicy::light(), ShapingPolicy::aggressive()] {
            let bucket = p.pad_to.unwrap();
            let mut residues = std::collections::HashSet::new();
            for framed in [1usize, 77, 300, 1000, 4096] {
                for _ in 0..64 {
                    let total = framed + p.pad_len(framed);
                    let over = total - framed.div_ceil(bucket) * bucket;
                    assert!((p.min_pad..=p.max_pad).contains(&over), "{p:?}");
                    residues.insert(total % bucket);
                }
            }
            assert!(residues.len() > 8, "{p:?}: residues {residues:?}");
        }
    }
}
