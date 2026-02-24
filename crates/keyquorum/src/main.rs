mod client;
mod daemon;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keyquorum",
    about = "Shamir secret sharing daemon for distributed key quorum"
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
    },
    /// Submit a share to the running daemon
    Submit {
        /// Share data (base64). If omitted, reads from stdin.
        #[arg(short, long)]
        share: Option<String>,
        /// Your identifier (optional, for participation logging)
        #[arg(short = 'u', long)]
        user: Option<String>,
        /// Socket path or tcp://host:port
        #[arg(long, default_value = "/run/keyquorum/keyquorum.sock")]
        socket: String,
    },
    /// Query the current session status
    Status {
        /// Socket path or tcp://host:port
        #[arg(long, default_value = "/run/keyquorum/keyquorum.sock")]
        socket: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Daemon { config } => daemon::run(config).await,
        Commands::Submit {
            share,
            user,
            socket,
        } => client::submit::run(share, user, socket).await,
        Commands::Status { socket } => client::status::run(socket).await,
    }
}
