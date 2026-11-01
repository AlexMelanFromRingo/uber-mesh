//! Multi-node mesh benchmark on the real code (in-process, real libp2p + obfuscated transport over
//! loopback TCP). Measures mesh formation, gossip propagation latency across N nodes, and delivery
//! ratio — baseline and under an injected per-link latency "impairment" middlebox.
//!
//!   NODES=20 LATENCY_MS=0   cargo run --release --example cluster
//!   NODES=20 LATENCY_MS=60  cargo run --release --example cluster
//!
//! NOTE: this is loopback + a TCP middlebox (latency/throttle/drops are realistic; per-packet LOSS
//! and geographic RTT are not — that is the Docker + `tc netem` harness). It is not real-world DPI.

use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use umesh_obfs::ObfsPsk;
use umesh_p2p::{MeshEvent, MeshNode};

const TOPIC: &str = "uber-mesh/bench";

enum Cmd {
    Dial(String),
    Subscribe,
    Publish(Vec<u8>),
}

enum Metric {
    Listening(usize, String),
    Connected,
    Got(Instant),
}

async fn run_node(
    idx: usize,
    mut node: MeshNode,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    evt_tx: mpsc::Sender<Metric>,
) {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Dial(a)) => { let _ = node.dial(&a); }
                Some(Cmd::Subscribe) => { let _ = node.subscribe(TOPIC); }
                Some(Cmd::Publish(p)) => { let _ = node.publish(TOPIC, p); }
                None => break,
            },
            ev = node.next_event() => match ev {
                MeshEvent::Listening(a) => { let _ = evt_tx.send(Metric::Listening(idx, a.to_string())).await; }
                MeshEvent::PeerConnected(_) => { let _ = evt_tx.send(Metric::Connected).await; }
                MeshEvent::Message { .. } => { let _ = evt_tx.send(Metric::Got(Instant::now())).await; }
                _ => {}
            }
        }
    }
}

/// A TCP middlebox that forwards to `real`, delaying every chunk by `latency` in each direction.
async fn latency_proxy(real_multiaddr: String, latency: Duration) -> String {
    // The node's listen address is a multiaddr `/ip4/127.0.0.1/tcp/PORT`; connect to host:port.
    let port: u16 = real_multiaddr.rsplit('/').next().unwrap().parse().unwrap();
    let real = format!("127.0.0.1:{port}");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Return a multiaddr (what MeshNode::dial expects), not a SocketAddr.
    let addr = format!("/ip4/127.0.0.1/tcp/{}", l.local_addr().unwrap().port());
    tokio::spawn(async move {
        loop {
            let Ok((inbound, _)) = l.accept().await else {
                break;
            };
            let real = real.clone();
            tokio::spawn(async move {
                if let Ok(outbound) = TcpStream::connect(&real).await {
                    let (mut ri, mut wi) = inbound.into_split();
                    let (mut ro, mut wo) = outbound.into_split();
                    let f = pipe(&mut ri, &mut wo, latency);
                    let g = pipe(&mut ro, &mut wi, latency);
                    let _ = tokio::join!(f, g);
                }
            });
        }
    });
    addr
}

async fn pipe<R, W>(r: &mut R, w: &mut W, latency: Duration) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
        w.write_all(&buf[..n]).await?;
    }
    Ok(())
}

fn pct(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i]
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let n: usize = std::env::var("NODES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let latency_ms: u64 = std::env::var("LATENCY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let latency = Duration::from_millis(latency_ms);
    let psk = ObfsPsk::new([42u8; 32]);

    println!(
        "=== uber-mesh cluster benchmark: {n} nodes, link latency {latency_ms}ms (each direction) ==="
    );

    let (evt_tx, mut evt_rx) = mpsc::channel::<Metric>(4096);
    let mut cmd_txs = Vec::new();
    for i in 0..n {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        let mut node = MeshNode::new(&seed, psk.clone()).unwrap();
        node.listen("/ip4/127.0.0.1/tcp/0").unwrap();
        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(64);
        cmd_txs.push(cmd_tx);
        tokio::spawn(run_node(i, node, cmd_rx, evt_tx.clone()));
    }

    // Collect each node's real listen address.
    let mut real_addrs: Vec<Option<String>> = vec![None; n];
    while real_addrs.iter().filter(|a| a.is_some()).count() < n {
        if let Some(Metric::Listening(i, a)) = evt_rx.recv().await
            && real_addrs[i].is_none()
        {
            real_addrs[i] = Some(a);
        }
    }
    let real_addrs: Vec<String> = real_addrs.into_iter().map(|a| a.unwrap()).collect();

    // Optionally put a latency middlebox in front of every node's listener. (NOTE: this delays only
    // INBOUND traffic per node, so it models a uniform link latency, not per-node geographic RTT —
    // faithful geo dispersion needs per-container netem on eth0; see docker/compose.geo.yml.)
    let dial_addrs: Vec<String> = if latency.is_zero() {
        real_addrs.clone()
    } else {
        let mut v = Vec::new();
        for a in &real_addrs {
            v.push(latency_proxy(a.clone(), latency).await);
        }
        v
    };

    // Topology: everyone subscribes; node i dials node 0 (bootstrap) and node (i+1)%n (ring) for a
    // connected graph so gossipsub can form a healthy mesh.
    for tx in &cmd_txs {
        let _ = tx.send(Cmd::Subscribe).await;
    }
    let t_form = Instant::now();
    for i in 1..n {
        let _ = cmd_txs[i].send(Cmd::Dial(dial_addrs[0].clone())).await;
        let _ = cmd_txs[i]
            .send(Cmd::Dial(dial_addrs[(i + 1) % n].clone()))
            .await;
    }

    // Count connections as they form; wait for the gossipsub mesh to warm up.
    let mut connections = 0usize;
    let warmup = Duration::from_secs(6);
    let warm_deadline = Instant::now() + warmup;
    while Instant::now() < warm_deadline {
        if let Ok(Some(Metric::Connected)) =
            tokio::time::timeout(Duration::from_millis(200), evt_rx.recv()).await
        {
            connections += 1;
        }
    }
    println!(
        "mesh formation: {connections} peer connections established in ~{:?}",
        t_form.elapsed()
    );

    // Publish one message from node 0 and measure propagation to the other N-1 nodes.
    let t0 = Instant::now();
    let _ = cmd_txs[0]
        .send(Cmd::Publish(b"benchmark-broadcast".to_vec()))
        .await;
    let mut latencies: Vec<u128> = Vec::new();
    let recv_deadline = Instant::now() + Duration::from_secs(20);
    while latencies.len() < n - 1 && Instant::now() < recv_deadline {
        if let Ok(Some(Metric::Got(when))) =
            tokio::time::timeout(Duration::from_millis(250), evt_rx.recv()).await
        {
            latencies.push(when.duration_since(t0).as_millis());
        }
    }
    latencies.sort_unstable();

    let delivered = latencies.len();
    println!(
        "\n--- gossip propagation (node 0 → {} subscribers) ---",
        n - 1
    );
    println!(
        "delivery ratio: {delivered}/{} = {:.0}%",
        n - 1,
        100.0 * delivered as f64 / (n - 1) as f64
    );
    if delivered > 0 {
        println!(
            "propagation latency ms:  min={}  p50={}  p95={}  max={}",
            latencies[0],
            pct(&latencies, 0.50),
            pct(&latencies, 0.95),
            latencies[delivered - 1]
        );
    }
    println!("=== done ===");
}
