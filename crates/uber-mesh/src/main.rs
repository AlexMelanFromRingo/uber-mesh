//! uber-mesh CLI entry point.

mod cli;
mod metrics_http;

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::Parser;
use cli::{Cli, Command, KeysCmd, PskArgs, TopicKeyArgs};
use rand::RngCore;
use tracing_subscriber::EnvFilter;
use umesh_crypto::identity::NodeIdentity;
use umesh_crypto::pow::MIN_SENDER_POW_BITS;
use umesh_node::config::Config;
use umesh_node::keystore::IdentityPow;
use umesh_node::status::NodeStatus;
use umesh_node::{DataDir, Node, keystore};
use umesh_p2p::TopicKey;
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
            KeysCmd::NewTopicKey { out } => cmd_new_topic_key(&out),
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
            topic_key,
            psk,
            metrics_addr,
            profile,
            fallback,
            cover_domain,
        } => {
            let psk = resolve_psk(&psk)?;
            let topic = MeshTopic {
                name: topic.unwrap_or_else(|| DEFAULT_TOPIC.to_string()),
                key_override: resolve_topic_key(&topic_key)?,
            };
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
                MeshTransport {
                    profile,
                    fallback,
                    cover_domain: cover_domain.or_else(|| std::env::var("UMESH_COVER_DOMAIN").ok()),
                },
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
/// Env var carrying the `mesh --topic` sealed-topic key (hex).
const ENV_TOPIC_KEY: &str = "UMESH_TOPIC_KEY";
/// Topic joined by `mesh` when `--topic` is not given.
const DEFAULT_TOPIC: &str = "uber-mesh/global";

/// The `mesh` topic and an optional key override (`--topic-key-file` / `UMESH_TOPIC_KEY`); the
/// config's `topic_keys[name]` is the fallback.
struct MeshTopic {
    name: String,
    key_override: Option<TopicKey>,
}

/// Resolve a topic-key override: `--topic-key-file` > `UMESH_TOPIC_KEY` > none (use config).
fn resolve_topic_key(args: &TopicKeyArgs) -> anyhow::Result<Option<TopicKey>> {
    resolve_topic_key_from(args, std::env::var(ENV_TOPIC_KEY).ok().map(Zeroizing::new))
}

fn resolve_topic_key_from(
    args: &TopicKeyArgs,
    env: Option<Zeroizing<String>>,
) -> anyhow::Result<Option<TopicKey>> {
    if let Some(path) = &args.topic_key_file {
        warn_if_shared(path);
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading topic key file {}", path.display()))?,
        );
        return TopicKey::from_hex(&text)
            .map(Some)
            .with_context(|| format!("invalid topic key in {}", path.display()));
    }
    match env.filter(|v| !v.trim().is_empty()) {
        Some(v) => TopicKey::from_hex(&v)
            .map(Some)
            .with_context(|| format!("invalid {ENV_TOPIC_KEY}")),
        None => Ok(None),
    }
}

/// Warn when a secret file is accessible by group/others (Unix).
fn warn_if_shared(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(path)
            && m.permissions().mode() & 0o077 != 0
        {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", m.permissions().mode() & 0o777),
                "topic key file is accessible by group/others; consider `chmod 600`"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// `keys new-topic-key --out PATH`: a fresh random topic key, written (hex) to a new `0600` file.
/// Never printed.
fn cmd_new_topic_key(out: &Path) -> anyhow::Result<()> {
    use std::io::Write;
    let key = TopicKey::generate();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(out)
        .with_context(|| format!("creating {} (it must not exist)", out.display()))?;
    let mut line = Zeroizing::new(key.to_hex().to_string());
    line.push('\n');
    f.write_all(line.as_bytes())?;
    f.sync_all()?;
    println!("wrote a new sealed-topic key to {} (0600)", out.display());
    println!(
        "share it out of band with the topic's members only; use it with \
         `mesh --topic <name> --topic-key-file {}`, the {ENV_TOPIC_KEY} env var, or \
         config.toml [topic_keys]",
        out.display()
    );
    Ok(())
}

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
    /// Cohort cover domain: SNI on dials and the domain whose server flight listeners mimic.
    cover_domain: Option<String>,
    profile: Option<String>,
    fallback: Option<String>,
}

async fn cmd_mesh(
    dd: &DataDir,
    listen: Option<String>,
    bootstrap: Vec<String>,
    topic: MeshTopic,
    psk: Option<Zeroizing<String>>,
    metrics: Option<std::net::SocketAddr>,
    transport: MeshTransport,
) -> anyhow::Result<()> {
    let MeshTransport {
        profile,
        fallback,
        cover_domain,
    } = transport;
    use std::time::Duration;
    use umesh_obfs::handshake::ProbeResponse;
    use umesh_p2p::{MeshEvent, MeshNode};

    // Identity + its proof-of-work; a pre-0.10 keystore gets its nonce mined once here (migration).
    let (id, pow) = load_identity_with_pow(dd)?;
    // PSK: --psk-file / UMESH_PSK override, else from config (the shared bridge secret gating the
    // obfs carrier).
    let mut cfg = Config::load(&dd.config())
        .with_context(|| format!("loading config from {}", dd.config().display()))?;
    if let Some(p) = psk {
        set_psk(&mut cfg, &p);
    }
    let psk = cfg.psk().context("invalid obfs PSK")?;
    let MeshTopic {
        name: topic,
        key_override,
    } = topic;
    let topic_key = match key_override {
        Some(k) => Some(k),
        None => cfg
            .topic_key(&topic)
            .context("invalid topic key in config")?
            .map(|k| TopicKey::from_bytes(*k)),
    };
    if let Some(p) = profile {
        cfg.profile = p;
    }
    // The environment profile drives record shaping on every obfs link (the libp2p path used to
    // ignore it, leaking inner Noise/multistream record sizes); probes go to the cover site if set.
    let shaping = cfg.profile().context("invalid --profile")?.shaping();
    // The config holds the PSK and topic-key hex: wipe it (Drop zeroizes) instead of keeping it
    // alive for the node's whole runtime.
    drop(cfg);
    // With a fallback upstream, the listener learns that cover site's real TLS server-flight layout
    // and reproduces it for authenticated clients (REALITY-style); probes are proxied to it.
    let probe = match fallback {
        Some(f) => ProbeResponse::cover(f, cover_domain.as_deref())
            .context("invalid --fallback / --cover-domain")?,
        None => ProbeResponse::Silence,
    };
    let seed = Zeroizing::new(id.to_seed_bytes());
    drop(id);
    let client = umesh_obfs::ClientConfig {
        cover_domain: cover_domain.clone(),
        ..umesh_obfs::ClientConfig::default()
    };
    let mut node = MeshNode::with_transport_client(&seed, pow.nonce, psk, shaping, probe, client)
        .context("building mesh node")?;
    drop(seed);

    node.subscribe(&topic).context("subscribe")?;
    let sealing = match &topic_key {
        Some(k) => {
            node.set_topic_key(&topic, k);
            "sealed (end-to-end encrypted; forwarders cannot read it)"
        }
        None => "PUBLIC (no topic key: every forwarding peer can read it)",
    };
    drop(topic_key);
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
        "uber-mesh gossip node started\n  libp2p peer: {}\n  app peer:    {}\n  topic:       {} — {}\n  metrics:     {}",
        node.local_peer_id(),
        node.app_peer_id(),
        topic,
        sealing,
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
                MeshEvent::Message { topic, sender, payload, sealed } => {
                    let tag = if sealed { " sealed" } else { "" };
                    println!("[{topic}{tag}] {sender}: {}", String::from_utf8_lossy(&payload));
                }
                MeshEvent::SealedBlob { topic, sender, provider, blob } => {
                    println!("[{topic} sealed] {sender} shared blob {}", blob.cid);
                    if let Some(p) = provider {
                        node.request_sealed_blob(p, &blob);
                    }
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
        let _ = std::fs::remove_file(dd.identity_pow());
        let _ = std::fs::remove_file(&cfg_path);
    }

    let id = NodeIdentity::generate();
    keystore::save(&id_path, &id).context("writing identity")?;
    // One-time identity proof-of-work (required of every gossip sender). If this is interrupted the
    // key is kept and the nonce is mined on the next `mesh` start.
    let pow = mine_identity_pow(&id)?;
    keystore::save_pow(&id_path, pow.nonce).context("writing identity proof-of-work")?;

    // Fresh 32-byte obfs PSK (a shared bridge secret to distribute out-of-band).
    let mut psk = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *psk);
    let psk_hex = Zeroizing::new(hex::encode(psk.as_slice()));
    let cfg = Config::default_with_psk(psk_hex.to_string());
    cfg.save(&cfg_path).context("writing config")?;

    println!("initialized uber-mesh node");
    println!("  data_dir: {}", dd.config().parent().unwrap().display());
    println!("  peer_id:  {}", id.peer_id());
    println!("  pow:      {}", describe_pow(&pow));
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
    // Read-only: a missing/stale PoW is reported, not mined (that happens at `mesh` start).
    let pow = keystore::load_pow(&dd.identity(), &id, MIN_SENDER_POW_BITS)?;
    if json {
        let (nonce, bits) = match pow {
            Some(p) => (p.nonce.to_string(), p.bits.to_string()),
            None => ("null".into(), "null".into()),
        };
        println!(
            "{{\"peer_id\":\"{}\",\"public_key\":\"{}\",\"pow_nonce\":{nonce},\"pow_bits\":{bits},\"pow_min_bits\":{MIN_SENDER_POW_BITS}}}",
            id.peer_id(),
            vk
        );
    } else {
        println!("peer_id:    {}", id.peer_id());
        println!("public_key: {vk}");
        match pow {
            Some(p) => println!(
                "pow:        {} bits (network minimum {MIN_SENDER_POW_BITS}; nonce {})",
                p.bits, p.nonce
            ),
            None => println!(
                "pow:        missing or below the network minimum ({MIN_SENDER_POW_BITS} bits) \
                 — mined automatically on the next `mesh` start"
            ),
        }
    }
    Ok(())
}

/// Load the identity and its proof-of-work; a keystore that predates identity PoW (< 0.10) gets
/// its nonce mined once and persisted (migration).
fn load_identity_with_pow(dd: &DataDir) -> anyhow::Result<(NodeIdentity, IdentityPow)> {
    let path = dd.identity();
    let (id, pow) = keystore::load_with_pow(&path, MIN_SENDER_POW_BITS, &pow_progress())
        .with_context(|| format!("loading identity from {}", path.display()))?;
    if pow.mined_in.is_some() {
        end_progress();
        eprintln!(
            "mined the identity proof-of-work (one-time, keystore predates it): {}",
            describe_pow(&pow)
        );
    }
    Ok((id, pow))
}

/// Mine the one-time identity proof-of-work, showing progress on an interactive stderr.
fn mine_identity_pow(id: &NodeIdentity) -> anyhow::Result<IdentityPow> {
    eprintln!(
        "mining identity proof-of-work ({MIN_SENDER_POW_BITS} bits, ~{:.0} M hashes expected, one-time)…",
        (1u64 << MIN_SENDER_POW_BITS) as f64 / 1e6
    );
    let pow = keystore::mine_pow(id, MIN_SENDER_POW_BITS, &pow_progress())
        .context("mining identity proof-of-work")?;
    end_progress();
    Ok(pow)
}

/// Mining progress callback: a `\r`-updated hash count, only when stderr is a terminal.
fn pow_progress() -> impl Fn(u64) + Sync {
    use std::io::{IsTerminal, Write};
    let tty = std::io::stderr().is_terminal();
    move |tried: u64| {
        if tty {
            let mut e = std::io::stderr().lock();
            let _ = write!(
                e,
                "\r  mining identity PoW: {:.0} M hashes tried",
                tried as f64 / 1e6
            );
            let _ = e.flush();
        }
    }
}

/// Clear a progress line left by [`pow_progress`].
fn end_progress() {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        eprint!("\r\x1b[K");
    }
}

fn describe_pow(p: &IdentityPow) -> String {
    match p.mined_in {
        Some(t) => format!(
            "{} bits (nonce {}, mined in {:.2} s)",
            p.bits,
            p.nonce,
            t.as_secs_f64()
        ),
        None => format!("{} bits (nonce {})", p.bits, p.nonce),
    }
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
    fn topic_key_sources_and_precedence() {
        let hex_env = Zeroizing::new("ee".repeat(32));
        let none = TopicKeyArgs::default();
        // Nothing given ⇒ env, else none (config fallback / public topic).
        let k = resolve_topic_key_from(&none, Some(hex_env.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(k.to_hex().as_str(), "ee".repeat(32));
        assert!(resolve_topic_key_from(&none, None).unwrap().is_none());
        assert!(
            resolve_topic_key_from(&none, Some(Zeroizing::new(" ".into())))
                .unwrap()
                .is_none()
        );
        // A bad env value is an error that does not echo the value.
        let err = resolve_topic_key_from(&none, Some(Zeroizing::new("ab".repeat(31))))
            .err()
            .unwrap();
        assert!(!format!("{err:#}").contains(&"ab".repeat(31)), "{err:#}");

        // --topic-key-file wins over env; `keys new-topic-key` output is accepted as-is.
        let f = std::env::temp_dir().join(format!("umesh-cli-topickey-{}", std::process::id()));
        let _ = std::fs::remove_file(&f);
        cmd_new_topic_key(&f).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "topic key file must be owner-only");
        }
        assert!(cmd_new_topic_key(&f).is_err(), "never overwrites");
        let args = TopicKeyArgs {
            topic_key_file: Some(f.clone()),
        };
        let from_file = resolve_topic_key_from(&args, Some(hex_env))
            .unwrap()
            .unwrap();
        let on_disk = std::fs::read_to_string(&f).unwrap();
        assert_eq!(from_file.to_hex().as_str(), on_disk.trim());
        assert_ne!(on_disk.trim(), "ee".repeat(32));
        std::fs::remove_file(&f).ok();
        assert!(resolve_topic_key_from(&args, None).is_err(), "missing file");
    }

    #[test]
    fn mesh_accepts_topic_key_file_but_no_argv_key() {
        let cli = Cli::try_parse_from(["uber-mesh", "mesh", "--topic-key-file", "/k"]).unwrap();
        let Command::Mesh { topic_key, .. } = cli.command else {
            panic!("expected mesh")
        };
        assert_eq!(topic_key.topic_key_file.as_deref(), Some(Path::new("/k")));
        assert!(Cli::try_parse_from(["uber-mesh", "mesh", "--topic-key", "aa"]).is_err());
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
