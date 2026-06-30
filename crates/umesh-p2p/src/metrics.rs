//! Process-global Prometheus metrics for a mesh node, exposed in the Prometheus text exposition
//! format (no external metrics dependency — the format is trivial and we keep the dep tree lean).
//!
//! Counters/gauges are plain atomics updated from the node event loop and the transport handshake;
//! [`render`] produces a `/metrics` body. The CLI `mesh` command serves it over HTTP.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

/// Currently connected peers (gauge).
pub static PEERS_CONNECTED: AtomicI64 = AtomicI64::new(0);
/// Total peer connections established (counter).
pub static PEERS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Gossip messages accepted after validation (counter).
pub static GOSSIP_RECEIVED: AtomicU64 = AtomicU64::new(0);
/// Gossip messages published locally (counter).
pub static GOSSIP_PUBLISHED: AtomicU64 = AtomicU64::new(0);
/// Gossip messages rejected by validation (counter).
pub static GOSSIP_REJECTED: AtomicU64 = AtomicU64::new(0);
/// Blobs served to peers (counter).
pub static BLOBS_SERVED: AtomicU64 = AtomicU64::new(0);
/// Blobs received + verified (counter).
pub static BLOBS_RECEIVED: AtomicU64 = AtomicU64::new(0);
/// Set-reconciliation sessions completed (counter).
pub static SYNC_COMPLETED: AtomicU64 = AtomicU64::new(0);
/// Obfs handshakes that failed the gate (probes) (counter).
pub static HANDSHAKE_FAILS: AtomicU64 = AtomicU64::new(0);

/// Histogram upper bounds for obfs-handshake duration, in milliseconds.
pub const HS_BOUNDS_MS: [u64; 9] = [5, 10, 25, 50, 100, 150, 250, 500, 1000];
static HS_BUCKETS: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
static HS_COUNT: AtomicU64 = AtomicU64::new(0);
static HS_SUM_MS: AtomicU64 = AtomicU64::new(0);

/// Increment a counter.
#[inline]
pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Relaxed);
}

/// Adjust the connected-peers gauge.
#[inline]
pub fn peers_delta(d: i64) {
    PEERS_CONNECTED.fetch_add(d, Relaxed);
    if d > 0 {
        PEERS_TOTAL.fetch_add(d as u64, Relaxed);
    }
}

/// Record a successful obfs handshake of `ms` milliseconds into the histogram.
pub fn record_handshake(ms: u64) {
    HS_COUNT.fetch_add(1, Relaxed);
    HS_SUM_MS.fetch_add(ms, Relaxed);
    for (i, &bound) in HS_BOUNDS_MS.iter().enumerate() {
        if ms <= bound {
            HS_BUCKETS[i].fetch_add(1, Relaxed);
        }
    }
}

/// Render all metrics in the Prometheus text exposition format.
pub fn render() -> String {
    let mut s = String::with_capacity(2048);
    let g = |s: &mut String, name: &str, help: &str, kind: &str, val: i64| {
        s.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {val}\n"
        ));
    };
    g(
        &mut s,
        "umesh_peers_connected",
        "Currently connected peers",
        "gauge",
        PEERS_CONNECTED.load(Relaxed),
    );
    g(
        &mut s,
        "umesh_peers_total",
        "Total peer connections established",
        "counter",
        PEERS_TOTAL.load(Relaxed) as i64,
    );
    g(
        &mut s,
        "umesh_gossip_received_total",
        "Validated gossip messages received",
        "counter",
        GOSSIP_RECEIVED.load(Relaxed) as i64,
    );
    g(
        &mut s,
        "umesh_gossip_published_total",
        "Gossip messages published",
        "counter",
        GOSSIP_PUBLISHED.load(Relaxed) as i64,
    );
    g(
        &mut s,
        "umesh_gossip_rejected_total",
        "Gossip messages rejected by validation",
        "counter",
        GOSSIP_REJECTED.load(Relaxed) as i64,
    );
    g(
        &mut s,
        "umesh_blobs_served_total",
        "Blobs served to peers",
        "counter",
        BLOBS_SERVED.load(Relaxed) as i64,
    );
    g(
        &mut s,
        "umesh_blobs_received_total",
        "Blobs received and verified",
        "counter",
        BLOBS_RECEIVED.load(Relaxed) as i64,
    );
    g(
        &mut s,
        "umesh_sync_completed_total",
        "Set-reconciliation sessions completed",
        "counter",
        SYNC_COMPLETED.load(Relaxed) as i64,
    );
    g(
        &mut s,
        "umesh_handshake_failures_total",
        "Obfs handshakes that failed the gate (probes)",
        "counter",
        HANDSHAKE_FAILS.load(Relaxed) as i64,
    );

    // Handshake duration histogram (seconds).
    s.push_str("# HELP umesh_handshake_seconds Obfs handshake duration\n# TYPE umesh_handshake_seconds histogram\n");
    for (i, &bound) in HS_BOUNDS_MS.iter().enumerate() {
        let le = bound as f64 / 1000.0;
        s.push_str(&format!(
            "umesh_handshake_seconds_bucket{{le=\"{le}\"}} {}\n",
            HS_BUCKETS[i].load(Relaxed)
        ));
    }
    let count = HS_COUNT.load(Relaxed);
    s.push_str(&format!(
        "umesh_handshake_seconds_bucket{{le=\"+Inf\"}} {count}\n"
    ));
    s.push_str(&format!(
        "umesh_handshake_seconds_sum {}\n",
        HS_SUM_MS.load(Relaxed) as f64 / 1000.0
    ));
    s.push_str(&format!("umesh_handshake_seconds_count {count}\n"));

    process_metrics(&mut s);
    s
}

/// Per-node resource usage from `/proc/self` (Linux; best-effort, 0 if unavailable).
fn process_metrics(s: &mut String) {
    let rss_bytes = std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|c| c.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4096)
        .unwrap_or(0);
    let open_fds = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count() as u64)
        .unwrap_or(0);
    let threads = std::fs::read_dir("/proc/self/task")
        .map(|d| d.count() as u64)
        .unwrap_or(0);
    let cpu_secs = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|c| {
            // utime (14) + stime (15), in clock ticks (USER_HZ=100); fields after the (comm) paren.
            let rest = c.rsplit_once(')')?.1;
            let f: Vec<&str> = rest.split_whitespace().collect();
            let utime = f.get(11)?.parse::<u64>().ok()?;
            let stime = f.get(12)?.parse::<u64>().ok()?;
            Some((utime + stime) as f64 / 100.0)
        })
        .unwrap_or(0.0);

    s.push_str("# HELP umesh_process_resident_bytes Resident set size of the node process\n");
    s.push_str(&format!(
        "# TYPE umesh_process_resident_bytes gauge\numesh_process_resident_bytes {rss_bytes}\n"
    ));
    s.push_str("# TYPE umesh_process_open_fds gauge\n");
    s.push_str(&format!("umesh_process_open_fds {open_fds}\n"));
    s.push_str("# TYPE umesh_process_threads gauge\n");
    s.push_str(&format!("umesh_process_threads {threads}\n"));
    s.push_str("# TYPE umesh_process_cpu_seconds_total counter\n");
    s.push_str(&format!("umesh_process_cpu_seconds_total {cpu_secs}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_prometheus_shaped() {
        peers_delta(1);
        inc(&GOSSIP_RECEIVED);
        record_handshake(42);
        let out = render();
        assert!(out.contains("# TYPE umesh_peers_connected gauge"));
        assert!(out.contains("umesh_handshake_seconds_bucket{le=\"+Inf\"}"));
        assert!(out.contains("umesh_handshake_seconds_count"));
    }
}
