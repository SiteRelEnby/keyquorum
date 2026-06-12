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
        /// Validate the config (applying lockdown/CLI overrides), print the
        /// effective settings, and exit without starting the daemon.
        #[arg(long)]
        check_config: bool,
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
    /// Offline recovery drill: verify that a set of shares still reconstructs
    /// a checksum-valid secret, WITHOUT revealing it or running any action.
    /// Give one decrypted share per file. Requires shares with the embedded
    /// blake3 checksum (the keyquorum-split default).
    Verify {
        /// Share files to verify (one share per file)
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Threshold K (defaults to the value in share metadata, if present)
        #[arg(short = 'k', long)]
        threshold: Option<u8>,
        /// Maximum share combinations to try
        #[arg(long, default_value_t = 100)]
        max_combinations: usize,
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
            check_config,
        } => daemon::run(config, lockdown, no_strict_hardening, check_config).await,
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
        Commands::Verify {
            files,
            threshold,
            max_combinations,
        } => keyquorum::verify::run(files, threshold, max_combinations),
    }
}
