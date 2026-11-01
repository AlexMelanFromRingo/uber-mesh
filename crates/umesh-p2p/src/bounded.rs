//! Small, dependency-free bounded containers used for all per-peer / per-sender state.
//!
//! Remote peers choose the keys of these maps (sender ids, message ids, libp2p PeerIds), so every
//! map is capped: inserting past capacity evicts the least-recently-touched entry, and callers can
//! additionally expire old entries from the front. This replaces the `lru` crate (RUSTSEC-2026-0253,
//! unsound in 0.12.x) with ~100 lines of safe code.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Instant;

/// A capacity-bounded map with least-recently-touched eviction.
///
/// Recency is tracked with a lazily-deleted touch log: each touch appends `(key, generation)`;
/// entries whose generation no longer matches the map are stale and skipped on eviction. The log
/// is compacted when it grows past `2·cap`, so memory stays `O(cap)`.
pub struct BoundedMap<K, V> {
    map: HashMap<K, (V, u64)>,
    order: VecDeque<(K, u64)>,
    cap: usize,
    generation: u64,
}

impl<K: Hash + Eq + Clone, V> BoundedMap<K, V> {
    /// An empty map holding at most `cap` (≥ 1) entries.
    pub fn new(cap: usize) -> Self {
        BoundedMap {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
            generation: 0,
        }
    }

    /// Number of live entries (always `<= cap`).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Whether the map holds `cap` entries (the next new key would evict one).
    pub fn is_full(&self) -> bool {
        self.map.len() >= self.cap
    }

    /// Whether `k` is present (does not count as a touch).
    pub fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    /// Look up `k` without touching it.
    pub fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k).map(|(v, _)| v)
    }

    /// Insert (or replace) `k`, marking it most-recently-used; evicts the oldest entry if full.
    pub fn insert(&mut self, k: K, v: V) {
        self.generation += 1;
        let g = self.generation;
        self.map.insert(k.clone(), (v, g));
        self.order.push_back((k, g));
        self.evict_over_cap();
        self.maybe_compact();
    }

    /// Get `k` mutably (inserting `default()` if absent), marking it most-recently-used.
    pub fn touch_or_insert_with(&mut self, k: K, default: impl FnOnce() -> V) -> &mut V {
        self.generation += 1;
        let g = self.generation;
        match self.map.get_mut(&k) {
            Some(e) => e.1 = g,
            None => {
                self.map.insert(k.clone(), (default(), g));
            }
        }
        self.order.push_back((k.clone(), g));
        // `k` is now the newest entry and cap >= 1, so it survives eviction.
        self.evict_over_cap();
        self.maybe_compact();
        &mut self.map.get_mut(&k).expect("just inserted").0
    }

    /// Remove `k`.
    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.map.remove(k).map(|(v, _)| v)
    }

    /// Remove least-recently-touched entries while `expired(value)` holds for the oldest one.
    pub fn expire_oldest_while(&mut self, mut expired: impl FnMut(&V) -> bool) {
        while let Some((k, g)) = self.order.front() {
            match self.map.get(k) {
                Some((v, cur)) if cur == g => {
                    if !expired(v) {
                        break;
                    }
                    let (k, _) = self.order.pop_front().expect("front exists");
                    self.map.remove(&k);
                }
                _ => {
                    self.order.pop_front(); // stale touch record
                }
            }
        }
    }

    fn evict_over_cap(&mut self) {
        while self.map.len() > self.cap {
            let Some((k, g)) = self.order.pop_front() else {
                break;
            };
            if self.map.get(&k).is_some_and(|(_, cur)| *cur == g) {
                self.map.remove(&k);
            }
        }
    }

    fn maybe_compact(&mut self) {
        if self.order.len() <= 2 * self.cap + 16 {
            return;
        }
        let mut live: Vec<(K, u64)> = self.map.iter().map(|(k, (_, g))| (k.clone(), *g)).collect();
        live.sort_unstable_by_key(|(_, g)| *g);
        self.order = live.into();
    }

    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.order.len()
    }
}

/// Per-key token-bucket rate limiter with a bounded key set.
///
/// Each key gets `capacity` tokens refilled at `refill_per_sec`. An evicted key restarts with a full
/// bucket, which is no worse than a fresh peer; the number of distinct keys is bounded by `max_keys`
/// (and, in practice, by the swarm's connection limits).
pub struct RateLimiter<K> {
    buckets: BoundedMap<K, Bucket>,
    capacity: f64,
    refill_per_sec: f64,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    /// A limiter allowing bursts of `capacity` and a sustained `refill_per_sec` per key.
    pub fn new(capacity: f64, refill_per_sec: f64, max_keys: usize) -> Self {
        RateLimiter {
            buckets: BoundedMap::new(max_keys),
            capacity,
            refill_per_sec,
        }
    }

    /// Try to spend `cost` tokens for `key` at time `now`. Returns `false` (spending nothing) if
    /// the bucket does not hold enough tokens.
    pub fn check(&mut self, key: K, cost: f64, now: Instant) -> bool {
        let (cap, rate) = (self.capacity, self.refill_per_sec);
        let b = self.buckets.touch_or_insert_with(key, || Bucket {
            tokens: cap,
            last: now,
        });
        let dt = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * rate).min(cap);
        b.last = now;
        if b.tokens >= cost {
            b.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn map_never_exceeds_cap_and_evicts_lru() {
        let mut m = BoundedMap::new(3);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(3, "c");
        *m.touch_or_insert_with(1, || "x") = "a2"; // 1 is now most recent
        m.insert(4, "d"); // evicts 2 (least recently touched)
        assert_eq!(m.len(), 3);
        assert!(!m.contains_key(&2));
        assert_eq!(m.get(&1), Some(&"a2"));
        assert!(m.contains_key(&3) && m.contains_key(&4));
    }

    #[test]
    fn touch_log_stays_bounded() {
        let mut m = BoundedMap::new(8);
        for i in 0..10_000u32 {
            *m.touch_or_insert_with(i % 4, || 0) += 1;
            assert!(m.order_len() <= 2 * 8 + 17);
        }
        assert_eq!(m.len(), 4);
    }

    #[test]
    fn many_keys_bounded() {
        let mut m = BoundedMap::new(100);
        for i in 0..100_000u32 {
            m.insert(i, ());
        }
        assert_eq!(m.len(), 100);
        assert!(m.contains_key(&99_999) && !m.contains_key(&0));
    }

    #[test]
    fn expire_from_front() {
        let mut m = BoundedMap::new(10);
        for i in 0..5u64 {
            m.insert(i, i * 10); // value = "timestamp"
        }
        m.expire_oldest_while(|ts| *ts < 25);
        assert_eq!(m.len(), 2);
        assert!(m.contains_key(&3) && m.contains_key(&4));
    }

    #[test]
    fn rate_limiter_bursts_then_refills() {
        let mut rl = RateLimiter::new(3.0, 1.0, 16);
        let t0 = Instant::now();
        assert!(rl.check("p", 1.0, t0));
        assert!(rl.check("p", 1.0, t0));
        assert!(rl.check("p", 1.0, t0));
        assert!(!rl.check("p", 1.0, t0), "burst exhausted");
        assert!(rl.check("q", 1.0, t0), "independent per key");
        assert!(rl.check("p", 1.0, t0 + Duration::from_millis(1100)));
        assert!(
            !rl.check("p", 5.0, t0 + Duration::from_secs(100)),
            "cost above capacity"
        );
    }
}
