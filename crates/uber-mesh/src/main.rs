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
        } => {
            // Async runtime only for the long-running command.
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_run(&dd, profile, listen, bootstrap, psk))
        }
    }
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
