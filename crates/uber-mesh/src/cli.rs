//! CLI argument definitions (clap).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
        /// Override the obfs PSK (hex, 32 bytes) — shared "bridge" secret.
        #[arg(long)]
        psk: Option<String>,
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
    },
    /// Show node status (peers, transports, reachability) — never reveals secrets.
    Status,
    /// Key management.
    Keys {
        #[command(subcommand)]
        sub: KeysCmd,
    },
}

/// `keys` subcommands.
#[derive(Subcommand, Debug)]
pub enum KeysCmd {
    /// Show the PeerId and public key (no secret material).
    Show,
}
