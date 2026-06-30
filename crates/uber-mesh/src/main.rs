//! uber-mesh CLI entry point.

mod cli;

use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Parser;
use cli::{Cli, Command, KeysCmd};
use rand::RngCore;
use tracing_subscriber::EnvFilter;
use umesh_crypto::identity::NodeIdentity;
use umesh_node::config::Config;
use umesh_node::status::NodeStatus;
use umesh_node::{DataDir, Node, keystore};

fn main() -> ExitCode {
    // Structured logs; never logs secrets. Level via RUST_LOG (default info).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let dd = DataDir::new(cli.data_dir.clone());
    match cli.command {
        Command::Init { force } => cmd_init(&dd, force),
        Command::Status => cmd_status(&dd, cli.json),
        Command::Keys { sub } => match sub {
            KeysCmd::Show => cmd_keys_show(&dd, cli.json),
        },
        Command::Run {
            profile,
            listen,
            bootstrap,
            psk,
        } => build_runtime()?.block_on(cmd_run(&dd, profile, listen, bootstrap, psk)),
        Command::Mesh {
            listen,
            bootstrap,
            topic,
            psk,
        } => build_runtime()?.block_on(cmd_mesh(&dd, listen, bootstrap, topic, psk)),
    }
}

/// Build the node's Tokio runtime. A mesh node is I/O-bound and mostly idle, so it defaults to a
/// small worker pool (lighter footprint → more nodes/host, friendlier to mobile/embedded). Override
/// with `UMESH_WORKERS` (1 = current-thread runtime).
fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let workers: usize = std::env::var("UMESH_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
        .max(1);
    if workers == 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
    }
}

/// Minimal Prometheus `/metrics` HTTP server (no framework — the exposition format is plain text).
async fn serve_metrics(addr: String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(listener) = tokio::net::TcpListener::bind(&addr).await else {
        tracing::warn!(%addr, "could not bind metrics endpoint");
        return;
    };
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // ignore the request line/headers
            let body = umesh_p2p::metrics::render();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

async fn cmd_mesh(
    dd: &DataDir,
    listen: Option<String>,
    bootstrap: Vec<String>,
    topic: Option<String>,
    psk: Option<String>,
) -> anyhow::Result<()> {
    use std::time::Duration;
    use umesh_p2p::{MeshEvent, MeshNode};

    let id = keystore::load(&dd.identity())
        .with_context(|| format!("loading identity from {}", dd.identity().display()))?;
    // PSK: --psk override, else from config (the shared bridge secret gating the obfs carrier).
    let mut cfg = Config::load(&dd.config())
        .with_context(|| format!("loading config from {}", dd.config().display()))?;
    if let Some(p) = psk {
        cfg.psk_hex = p;
    }
    let psk = cfg.psk().context("invalid obfs PSK")?;
    let seed = id.to_seed_bytes();
    let mut node = MeshNode::new(&seed, psk).context("building mesh node")?;

    let topic = topic.unwrap_or_else(|| "uber-mesh/global".to_string());
    node.subscribe(&topic).context("subscribe")?;
    let listen = listen.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".to_string());
    node.listen(&listen).context("listen")?;
    for b in &bootstrap {
        if let Err(e) = node.dial(b) {
            tracing::warn!(addr = %b, error = %e, "bootstrap dial failed");
        }
    }

    // Prometheus /metrics endpoint (METRICS_PORT, default 9100; set to "off" to disable).
    let metrics_port = std::env::var("METRICS_PORT").unwrap_or_else(|_| "9100".to_string());
    if metrics_port != "off" {
        tokio::spawn(serve_metrics(format!("0.0.0.0:{metrics_port}")));
    }

    println!(
        "uber-mesh gossip node started\n  libp2p peer: {}\n  app peer:    {}\n  topic:       {}\n  metrics:     :{}/metrics",
        node.local_peer_id(),
        node.app_peer_id(),
        topic,
        metrics_port,
    );

    let local = node.local_peer_id();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let ctrlc = tokio::signal::ctrl_c();
    tokio::pin!(ctrlc);
    loop {
        tokio::select! {
            ev = node.next_event() => match ev {
                MeshEvent::Listening(addr) => println!("listening on {addr}/p2p/{local}"),
                MeshEvent::PeerConnected(p) => tracing::info!(peer = %p, "peer connected"),
                MeshEvent::PeerDisconnected(p) => tracing::info!(peer = %p, "peer disconnected"),
                MeshEvent::Message { topic, sender, payload } => {
                    println!("[{topic}] {sender}: {}", String::from_utf8_lossy(&payload));
                }
                MeshEvent::BlobReceived { cid, data } => {
                    println!("blob {cid} received ({} bytes, verified)", data.len());
                }
                MeshEvent::BlobUnavailable { cid } => {
                    println!("blob {cid} unavailable");
                }
                MeshEvent::SyncComplete { peer, need, have_extra } => {
                    println!("sync with {peer}: need {} / can offer {}", need.len(), have_extra.len());
                }
                MeshEvent::SyncFailed { peer } => {
                    println!("sync with {peer} failed");
                }
            },
            _ = heartbeat.tick() => {
                let msg = format!("heartbeat from {}", node.app_peer_id());
                let _ = node.publish(&topic, msg.into_bytes());
            }
            _ = &mut ctrlc => {
                tracing::info!("shutting down");
                break;
            }
        }
    }
    Ok(())
}

fn cmd_init(dd: &DataDir, force: bool) -> anyhow::Result<()> {
    dd.ensure()?;
    let id_path = dd.identity();
    let cfg_path = dd.config();

    if id_path.exists() && !force {
        bail!(
            "already initialized at {} (use --force to overwrite)",
            dd.identity().display()
        );
    }
    if force {
        let _ = std::fs::remove_file(&id_path);
        let _ = std::fs::remove_file(&cfg_path);
    }

    let id = NodeIdentity::generate();
    keystore::save(&id_path, &id).context("writing identity")?;

    // Fresh 32-byte obfs PSK (a shared bridge secret to distribute out-of-band).
    let mut psk = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut psk);
    let psk_hex = hex::encode(psk);
    let cfg = Config::default_with_psk(psk_hex.clone());
    cfg.save(&cfg_path).context("writing config")?;

    println!("initialized uber-mesh node");
    println!("  data_dir: {}", dd.config().parent().unwrap().display());
    println!("  peer_id:  {}", id.peer_id());
    println!("  config:   {}", cfg_path.display());
    println!();
    println!("share this obfs PSK out-of-band with peers that should reach you:");
    println!("  PSK: {psk_hex}");
    Ok(())
}

fn load(dd: &DataDir) -> anyhow::Result<(NodeIdentity, Config)> {
    let id = keystore::load(&dd.identity())
        .with_context(|| format!("loading identity from {}", dd.identity().display()))?;
    let cfg = Config::load(&dd.config())
        .with_context(|| format!("loading config from {}", dd.config().display()))?;
    Ok((id, cfg))
}

fn cmd_status(dd: &DataDir, json: bool) -> anyhow::Result<()> {
    let (id, cfg) = load(dd)?;
    let status = NodeStatus::from_static(&id, &cfg);
    if json {
        println!("{}", status.to_json());
    } else {
        print!("{}", status.to_human());
    }
    Ok(())
}

fn cmd_keys_show(dd: &DataDir, json: bool) -> anyhow::Result<()> {
    let id = keystore::load(&dd.identity())?;
    let vk = hex::encode(id.verifying_key().to_bytes());
    if json {
        println!(
            "{{\"peer_id\":\"{}\",\"public_key\":\"{}\"}}",
            id.peer_id(),
            vk
        );
    } else {
        println!("peer_id:    {}", id.peer_id());
        println!("public_key: {vk}");
    }
    Ok(())
}

async fn cmd_run(
    dd: &DataDir,
    profile: Option<String>,
    listen: Option<String>,
    bootstrap: Vec<String>,
    psk: Option<String>,
) -> anyhow::Result<()> {
    let (id, mut cfg) = load(dd)?;
    if let Some(p) = profile {
        cfg.profile = p;
    }
    if let Some(l) = listen {
        cfg.listen = Some(l);
    }
    if !bootstrap.is_empty() {
        cfg.bootstrap = bootstrap;
    }
    if let Some(p) = psk {
        cfg.psk_hex = p;
    }
    // Validate the PSK before starting.
    cfg.psk().context("invalid obfs PSK")?;

    let node = std::sync::Arc::new(Node::new(id, cfg));
    node.run().await.context("node runtime")?;
    Ok(())
}
