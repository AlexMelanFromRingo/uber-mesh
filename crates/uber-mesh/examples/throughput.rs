//! Saturating throughput benchmark for the obfuscated transport: one node streams a large payload
//! to another over the real obfs-tcp carrier (loopback), measuring goodput (MB/s) with no shaping
//! and with aggressive shaping (to show the padding/jitter cost).
//!
//!   TOTAL_MB=200 cargo run --release --example throughput

use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use umesh_obfs::{ObfsPsk, ObfsTcp, ShapingPolicy};

async fn run(total_mb: usize, shaping: ShapingPolicy, label: &str) {
    let psk = ObfsPsk::new([7u8; 32]);
    let chunk = vec![0xABu8; 8192];
    let n_msgs = total_mb * 1024 * 1024 / chunk.len();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let psk_s = psk.clone();
    let sh_s = shaping.clone();

    // Sink server: receive and discard until the client closes.
    let server = tokio::spawn(async move {
        let (mut s, _) = ObfsTcp::accept(&listener, &psk_s, sh_s).await.unwrap();
        let mut got = 0usize;
        while let Ok(m) = s.recv().await {
            got += m.len();
        }
        got
    });

    let mut c = ObfsTcp::connect(addr, &psk, shaping).await.unwrap();
    let start = Instant::now();
    for _ in 0..n_msgs {
        c.send(&chunk).await.unwrap();
    }
    let sent = n_msgs * chunk.len();
    let elapsed = start.elapsed();
    drop(c); // close → server's recv loop ends
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;

    let mb = sent as f64 / (1024.0 * 1024.0);
    let mbps = mb / elapsed.as_secs_f64();
    let msgs_per_s = n_msgs as f64 / elapsed.as_secs_f64();
    println!(
        "  {label:<22} {mb:>6.0} MB in {:>5.2}s  =>  {mbps:>7.1} MB/s  ({:.0} msgs/s, 8 KiB each)",
        elapsed.as_secs_f64(),
        msgs_per_s
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let total_mb: usize = std::env::var("TOTAL_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    println!(
        "=== obfs transport throughput (hybrid-PQ keyed, XChaCha20-Poly1305 records, loopback) ==="
    );
    run(total_mb, ShapingPolicy::none(), "no shaping").await;
    run(total_mb, ShapingPolicy::light(), "light shaping").await;
    // Aggressive shaping adds per-record IAT jitter (up to 8 ms) — by design it throttles bulk to a
    // low covert rate, so benchmark a small payload to show the cost without waiting minutes.
    run(
        total_mb.min(4),
        ShapingPolicy::aggressive(),
        "aggressive (IAT jitter)",
    )
    .await;
    println!("=== done ===");
    println!("note: aggressive shaping's per-record timing jitter caps bulk throughput by design");
    println!(
        "      (anti-traffic-analysis); for bulk transfer jitter should be per-burst, not per-record."
    );
}
