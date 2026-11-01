//! uber-mesh CLI entry point.

mod cli;
mod metrics_http;

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Parser;
use cli::{Cli, Command, KeysCmd, PskArgs};
use rand::RngCore;
use tracing_subscriber::EnvFilter;
use umesh_crypto::identity::NodeIdentity;
use umesh_node::config::Config;
use umesh_node::status::NodeStatus;
use umesh_node::{DataDir, Node, keystore};
use zeroize::{Zeroize, Zeroizing};

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
        } => {
            let psk = resolve_psk(&psk)?;
            build_runtime()?.block_on(cmd_run(&dd, profile, listen, bootstrap, psk))
        }
        Command::Mesh {
            listen,
            bootstrap,
            topic,
            psk,
            metrics_addr,
            profile,
            fallback,
        } => {
            let psk = resolve_psk(&psk)?;
            let fallback = fallback.or_else(|| std::env::var("UMESH_FALLBACK").ok());
            let metrics = metrics_http::resolve_addr(
                metrics_addr.as_deref(),
                std::env::var(metrics_http::ENV_ADDR).ok().as_deref(),
                std::env::var(metrics_http::ENV_LEGACY_PORT).ok().as_deref(),
            )?;
            build_runtime()?.block_on(cmd_mesh(
                &dd,
                listen,
                bootstrap,
                topic,
                psk,
                metrics,
                MeshTransport { profile, fallback },
            ))
        }
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

/// Env var carrying the obfs PSK (hex) — preferred over `--psk`, which is visible in `ps`.
const ENV_PSK: &str = "UMESH_PSK";

/// Resolve a PSK override: `--psk-file` > `--psk` (deprecated) > `UMESH_PSK` > none (use config).
fn resolve_psk(args: &PskArgs) -> anyhow::Result<Option<Zeroizing<String>>> {
    resolve_psk_from(args, std::env::var(ENV_PSK).ok().map(Zeroizing::new))
}

fn resolve_psk_from(
    args: &PskArgs,
    env: Option<Zeroizing<String>>,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    if let Some(path) = &args.psk_file {
        return read_psk_file(path).map(Some);
    }
    if let Some(p) = &args.psk {
        tracing::warn!(
            "--psk is deprecated: the PSK is visible to other local users in the process list; \
             use --psk-file <PATH> or the {ENV_PSK} environment variable"
        );
        return Ok(Some(Zeroizing::new(p.clone())));
    }
    Ok(env.filter(|v| !v.trim().is_empty()))
}

/// Replace the config's PSK, wiping the previous value.
fn set_psk(cfg: &mut Config, psk_hex: &str) {
    let mut old = std::mem::replace(&mut cfg.psk_hex, psk_hex.to_string());
    old.zeroize();
}

fn read_psk_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("reading PSK file {}", path.display()))?,
    );
    Ok(Zeroizing::new(text.trim().to_string()))
}

/// Obfs-transport knobs for `mesh`: environment profile (record shaping) and probe fallback.
struct MeshTransport {
    profile: Option<String>,
    fallback: Option<String>,
}

async fn cmd_mesh(
    dd: &DataDir,
    listen: Option<String>,
    bootstrap: Vec<String>,
    topic: Option<String>,
    psk: Option<Zeroizing<String>>,
    metrics: Option<std::net::SocketAddr>,
    transport: MeshTransport,
) -> anyhow::Result<()> {
    let MeshTransport { profile, fallback } = transport;
    use std::time::Duration;
    use umesh_obfs::handshake::ProbeResponse;
    use umesh_p2p::{MeshEvent, MeshNode};

    let id = keystore::load(&dd.identity())
        .with_context(|| format!("loading identity from {}", dd.identity().display()))?;
    // PSK: --psk-file / UMESH_PSK override, else from config (the shared bridge secret gating the
    // obfs carrier).
    let mut cfg = Config::load(&dd.config())
        .with_context(|| format!("loading config from {}", dd.config().display()))?;
    if let Some(p) = psk {
        set_psk(&mut cfg, &p);
    }
    let psk = cfg.psk().context("invalid obfs PSK")?;
    if let Some(p) = profile {
        cfg.profile = p;
    }
    // The environment profile drives record shaping on every obfs link (the libp2p path used to
    // ignore it, leaking inner Noise/multistream record sizes); probes go to the cover site if set.
    let shaping = cfg.profile().context("invalid --profile")?.shaping();
    let probe = match fallback {
        Some(f) => ProbeResponse::Fallback(f),
        None => ProbeResponse::Silence,
    };
    let seed = Zeroizing::new(id.to_seed_bytes());
    drop(id);
    let mut node =
        MeshNode::with_transport(&seed, psk, shaping, probe).context("building mesh node")?;
    drop(seed);

    let topic = topic.unwrap_or_else(|| "uber-mesh/global".to_string());
    node.subscribe(&topic).context("subscribe")?;
    let listen = listen.unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".to_string());
    node.listen(&listen).context("listen")?;
    for b in &bootstrap {
        if let Err(e) = node.dial(b) {
            tracing::warn!(addr = %b, error = %e, "bootstrap dial failed");
        }
    }

    // Opt-in Prometheus /metrics endpoint (off by default; loopback unless an IP is given).
    let metrics_desc = match metrics {
        Some(addr) => {
            let listener = metrics_http::bind(addr).await?;
            let bound = listener.local_addr()?;
            tokio::spawn(metrics_http::serve(
                listener,
                metrics_http::Limits::default(),
                umesh_p2p::metrics::render,
            ));
            format!("http://{bound}/metrics")
        }
        None => "off".to_string(),
    };

    println!(
        "uber-mesh gossip node started\n  libp2p peer: {}\n  app peer:    {}\n  topic:       {}\n  metrics:     {}",
        node.local_peer_id(),
        node.app_peer_id(),
        topic,
        metrics_desc,
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
    let mut psk = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *psk);
    let psk_hex = Zeroizing::new(hex::encode(psk.as_slice()));
    let cfg = Config::default_with_psk(psk_hex.to_string());
    cfg.save(&cfg_path).context("writing config")?;

    println!("initialized uber-mesh node");
    println!("  data_dir: {}", dd.config().parent().unwrap().display());
    println!("  peer_id:  {}", id.peer_id());
    println!("  config:   {}", cfg_path.display());
    println!();
    println!("share this obfs PSK out-of-band with peers that should reach you:");
    println!("  PSK: {}", psk_hex.as_str());
    println!(
        "  (pass it to peers' nodes via --psk-file <PATH> or the {ENV_PSK} env var, not --psk)"
    );
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
    psk: Option<Zeroizing<String>>,
) -> anyhow::Result<()> {
    let (id, mut cfg) = load(dd)?;
    if let Some(p) = profile {
        cfg.profile = p;
        cfg.profile().context("invalid --profile")?;
    }
    if let Some(l) = listen {
        cfg.listen = Some(l);
    }
    if !bootstrap.is_empty() {
        cfg.bootstrap = bootstrap;
    }
    if let Some(p) = psk {
        set_psk(&mut cfg, &p);
    }
    // Validate the PSK before starting.
    cfg.psk().context("invalid obfs PSK")?;

    let node = std::sync::Arc::new(Node::new(id, cfg));
    node.run().await.context("node runtime")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfile(tag: &str, contents: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("umesh-cli-{tag}-{}", std::process::id()));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn psk_sources_and_precedence() {
        let env = || Some(Zeroizing::new("ee".repeat(32)));
        // Nothing given ⇒ env, else config (None).
        let none = PskArgs::default();
        assert_eq!(
            resolve_psk_from(&none, env()).unwrap().unwrap().as_str(),
            "ee".repeat(32)
        );
        assert!(resolve_psk_from(&none, None).unwrap().is_none());
        assert!(
            resolve_psk_from(&none, Some(Zeroizing::new(" ".into())))
                .unwrap()
                .is_none()
        );

        // --psk-file wins over env (whitespace/newline trimmed).
        let f = tmpfile("psk", &format!("{}\n", "ff".repeat(32)));
        let args = PskArgs {
            psk_file: Some(f.clone()),
            psk: None,
        };
        assert_eq!(
            resolve_psk_from(&args, env()).unwrap().unwrap().as_str(),
            "ff".repeat(32)
        );
        std::fs::remove_file(&f).ok();
        assert!(
            resolve_psk_from(&args, env()).is_err(),
            "missing file is an error"
        );

        // Deprecated --psk still works and wins over env.
        let args = PskArgs {
            psk_file: None,
            psk: Some("aa".repeat(32)),
        };
        assert_eq!(
            resolve_psk_from(&args, env()).unwrap().unwrap().as_str(),
            "aa".repeat(32)
        );
    }

    #[test]
    fn psk_and_psk_file_conflict() {
        let r = Cli::try_parse_from(["uber-mesh", "run", "--psk", "aa", "--psk-file", "/x"]);
        assert!(r.is_err());
    }

    #[test]
    fn mesh_metrics_flag_parses_and_defaults_off() {
        let cli = Cli::try_parse_from(["uber-mesh", "mesh"]).unwrap();
        let Command::Mesh { metrics_addr, .. } = cli.command else {
            panic!("expected mesh")
        };
        assert!(metrics_addr.is_none());
        assert_eq!(metrics_http::resolve_addr(None, None, None).unwrap(), None);
    }
}
