use clap::{Parser, Subcommand};
use keyquorum::{client, daemon};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keyquorum",
    about = "Shamir secret sharing daemon for distributed key quorum",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the collection daemon
    Daemon {
        /// Path to config file
        #[arg(short, long, default_value = "/etc/keyquorum/config.toml")]
        config: PathBuf,
        /// Lockdown mode: maximum security posture. Rejects stdout action,
        /// forces on_failure=wipe. May gain new restrictions between versions.
        #[arg(long)]
        lockdown: bool,
        /// Disable strict hardening: allow the daemon to continue if memory
        /// protections (mlock, madvise) fail. Not recommended for production.
        #[arg(long)]
        no_strict_hardening: bool,
    },
    /// Submit a share to the running daemon.
    /// Share data is always read from stdin (pipe a file or type interactively).
    /// Shares are never accepted as command-line arguments to avoid exposure
    /// via process table (/proc, ps) and shell history.
    Submit {
        /// Your identifier (optional, for participation logging)
        #[arg(short = 'u', long)]
        user: Option<String>,
        /// Socket path or tcp://host:port (overrides config)
        #[arg(long)]
        socket: Option<String>,
        /// Path to config file (reads socket_path from it)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Query the current session status
    Status {
        /// Socket path or tcp://host:port (overrides config)
        #[arg(long)]
        socket: Option<String>,
        /// Path to config file (reads socket_path from it)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

/// Resolve the socket address: --socket wins, then --config, then default.
fn resolve_socket(socket: Option<String>, config: Option<PathBuf>) -> anyhow::Result<String> {
    if let Some(s) = socket {
        return Ok(s);
    }
    if let Some(path) = config {
        let cfg = keyquorum_core::config::Config::from_file(&path)
            .map_err(|e| anyhow::anyhow!("failed to load config from {}: {}", path.display(), e))?;
        return Ok(cfg.daemon.socket_path.to_string_lossy().into_owned());
    }
    Ok("/run/keyquorum/keyquorum.sock".to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    keyquorum_core::memory::warn_if_not_linux();
    let cli = Cli::parse();
    match cli.command {
        Commands::Daemon {
            config,
            lockdown,
            no_strict_hardening,
        } => daemon::run(config, lockdown, no_strict_hardening).await,
        Commands::Submit {
            user,
            socket,
            config,
        } => {
            let socket = resolve_socket(socket, config)?;
            client::submit::run(user, socket).await
        }
        Commands::Status { socket, config } => {
            let socket = resolve_socket(socket, config)?;
            client::status::run(socket).await
        }
    }
}
