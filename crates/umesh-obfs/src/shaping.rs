//! Traffic-shaping policy: record padding + inter-arrival timing jitter.
//!
//! Shaping is applied as a wrapper around the secure record stream (research D2: shaping must be
//! independent of the transport, toggleable per environment profile). It blunts length/timing
//! signatures (TLS-in-TLS record-size tells, website fingerprinting).

use rand::Rng;

/// How aggressively to pad and jitter records.
#[derive(Clone, Debug)]
pub struct ShapingPolicy {
    /// If set, pad each record's framed length up to a multiple of this bucket size.
    pub pad_to: Option<usize>,
    /// Minimum random padding bytes added to every record.
    pub min_pad: usize,
    /// Maximum random padding bytes (when `pad_to` is `None`).
    pub max_pad: usize,
    /// Maximum inter-arrival timing jitter in milliseconds (0 = off).
    pub iat_jitter_ms: u32,
    /// Whether to emit decoy/cover traffic when idle (reserved; honored by the stream when enabled).
    pub decoy: bool,
}

impl ShapingPolicy {
    /// No shaping (lowest overhead) — for uncensored networks.
    pub fn none() -> Self {
        Self {
            pad_to: None,
            min_pad: 0,
            max_pad: 0,
            iat_jitter_ms: 0,
            decoy: false,
        }
    }

    /// Light shaping — bucket lengths, no timing cost.
    pub fn light() -> Self {
        Self {
            pad_to: Some(256),
            min_pad: 0,
            max_pad: 64,
            iat_jitter_ms: 0,
            decoy: false,
        }
    }

    /// Aggressive shaping — bigger buckets, random padding, timing jitter, decoys.
    pub fn aggressive() -> Self {
        Self {
            pad_to: Some(512),
            min_pad: 16,
            max_pad: 256,
            iat_jitter_ms: 8,
            decoy: true,
        }
    }

    /// Compute the number of padding bytes to append given the already-framed plaintext length.
    pub fn pad_len(&self, framed_len: usize) -> usize {
        if let Some(bucket) = self.pad_to {
            if bucket > 0 {
                let rem = framed_len % bucket;
                let to_bucket = if rem == 0 { 0 } else { bucket - rem };
                return to_bucket + self.min_pad;
            }
        }
        if self.max_pad > self.min_pad {
            rand::thread_rng().gen_range(self.min_pad..=self.max_pad)
        } else {
            self.min_pad
        }
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
            decoy: false,
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
            decoy: false,
        };
        for _ in 0..100 {
            let n = p.pad_len(123);
            assert!((8..=32).contains(&n));
        }
    }

    #[test]
    fn none_adds_nothing() {
        assert_eq!(ShapingPolicy::none().pad_len(7), 0);
    }
}
