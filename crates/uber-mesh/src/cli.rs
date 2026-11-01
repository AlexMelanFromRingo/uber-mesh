//! CLI argument definitions (clap).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// uber-mesh — a decentralized, censorship-resistant P2P mesh node.
#[derive(Parser, Debug)]
#[command(name = "uber-mesh", version, about)]
pub struct Cli {
    /// Data directory holding the identity keystore and config.
    #[arg(long, global = true, default_value = "./uber-mesh-data")]
    pub data_dir: PathBuf,

    /// Emit machine-readable JSON where applicable.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a node identity + default config (and a fresh obfs PSK).
    Init {
        /// Overwrite an existing identity/config.
        #[arg(long)]
        force: bool,
    },
    /// Start the node: bind the obfs listener, dial bootstraps, run until Ctrl-C.
    Run {
        /// Override the environment profile (open|moderate|aggressive|shutdown).
        #[arg(long)]
        profile: Option<String>,
        /// Override the listen address (host:port).
        #[arg(long)]
        listen: Option<String>,
        /// Bootstrap/peer endpoints to dial (repeatable).
        #[arg(long = "bootstrap")]
        bootstrap: Vec<String>,
        #[command(flatten)]
        psk: PskArgs,
    },
    /// Run the libp2p gossip mesh overlay (gossipsub + private Kademlia + NAT traversal).
    Mesh {
        /// Listen multiaddr (default /ip4/0.0.0.0/tcp/0).
        #[arg(long)]
        listen: Option<String>,
        /// Bootstrap peer multiaddrs to dial, e.g. /ip4/1.2.3.4/tcp/4001/p2p/<peerid> (repeatable).
        #[arg(long = "bootstrap")]
        bootstrap: Vec<String>,
        /// Gossip topic to join (default uber-mesh/global).
        #[arg(long)]
        topic: Option<String>,
        #[command(flatten)]
        psk: PskArgs,
        /// Enable the Prometheus /metrics endpoint (OFF by default). A bare PORT binds 127.0.0.1;
        /// give IP:PORT to bind elsewhere. Unauthenticated: it identifies the host as an uber-mesh
        /// node, so never expose it on a censor-reachable interface. Env: UMESH_METRICS_ADDR.
        #[arg(long, value_name = "PORT|IP:PORT")]
        metrics_addr: Option<String>,
        /// Override the environment profile (open|moderate|aggressive|shutdown); selects the
        /// record padding / shaping applied to every obfs link.
        #[arg(long)]
        profile: Option<String>,
        /// Cover site (`host:port`) that unauthenticated probes are transparently proxied to, so a
        /// prober of this listener talks to a genuine HTTPS server. Default: silent close.
        /// Env: UMESH_FALLBACK.
        #[arg(long, value_name = "HOST:PORT")]
        fallback: Option<String>,
    },
    /// Show node status (peers, transports, reachability) — never reveals secrets.
    Status,
    /// Key management.
    Keys {
        #[command(subcommand)]
        sub: KeysCmd,
    },
}

/// Sources for the obfs PSK (shared "bridge" secret, 32 bytes hex) overriding `config.toml`.
///
/// Precedence: `--psk-file` > `--psk` (deprecated) > `UMESH_PSK` env > config.
#[derive(Args, Debug, Default)]
pub struct PskArgs {
    /// Read the obfs PSK (hex, 32 bytes) from a file (e.g. a Docker/K8s secret).
    #[arg(long, value_name = "PATH", conflicts_with = "psk")]
    pub psk_file: Option<PathBuf>,
    /// DEPRECATED: the PSK on the command line is visible to other local users via `ps` /
    /// /proc/<pid>/cmdline. Use --psk-file or the UMESH_PSK environment variable instead.
    #[arg(long, value_name = "HEX")]
    pub psk: Option<String>,
}

/// `keys` subcommands.
#[derive(Subcommand, Debug)]
pub enum KeysCmd {
    /// Show the PeerId and public key (no secret material).
    Show,
}
