pub mod action;
pub mod handler;
pub mod listener;
pub mod session;

use std::path::PathBuf;

use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use keyquorum_core::config::{Config, Verification};

pub async fn run(
    config_path: PathBuf,
    lockdown: bool,
    no_strict_hardening: bool,
) -> anyhow::Result<()> {
    // Harden process before loading any secrets
    keyquorum_core::memory::harden_process()?;

    // Load config
    let mut config = Config::from_file(&config_path).map_err(|e| {
        anyhow::anyhow!("failed to load config from {}: {}", config_path.display(), e)
    })?;

    // Apply CLI overrides
    if no_strict_hardening {
        config.daemon.strict_hardening = false;
    }

    // Apply and validate lockdown mode (from CLI flag or config file)
    // Note: lockdown re-enables strict_hardening even if --no-strict-hardening was passed
    config.apply_lockdown(lockdown);
    config.validate_lockdown().map_err(|e| {
        anyhow::anyhow!("{}", e)
    })?;

    // Initialize logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if config.daemon.lockdown {
        info!("lockdown mode enabled");
    }

    if !config.daemon.strict_hardening {
        warn!(
            "strict_hardening disabled: the daemon will continue even if memory protections \
             (mlock, madvise) fail on secret buffers. Secret material may be swappable, \
             dumpable, or leaked to child processes. Not recommended for production."
        );
    }

    if config.session.verification == Verification::None {
        warn!(
            "verification = \"none\": reconstructed secrets will not be verified before \
             executing the action. If shares were generated with the default embedded checksum \
             (keyquorum-split without --no-checksum), the checksum bytes will be passed to the \
             action as part of the secret, causing consistent failures. Use \
             verification = \"embedded-blake3\" or regenerate shares with --no-checksum."
        );
    }

    info!(
        threshold = config.session.threshold,
        total_shares = config.session.total_shares,
        timeout_secs = config.session.timeout_secs,
        "keyquorum daemon starting"
    );

    // Create session channel
    let (session_tx, session_rx) = mpsc::channel::<session::SessionCommand>(32);

    // Spawn session task (single owner of all secret material)
    let session_config = config.session.clone();
    let action_config = config.action.clone();
    let log_participation = config.logging.log_participation;
    let session_lockdown = config.daemon.lockdown;
    let session_strict_hardening = config.daemon.strict_hardening;
    tokio::spawn(async move {
        session::run_session(
            session_rx,
            session_config,
            action_config,
            log_participation,
            session_lockdown,
            session_strict_hardening,
        )
        .await;
    });

    // Set up signal handler for graceful shutdown
    let socket_path = config.daemon.socket_path.clone();
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        result = listener::run_listeners(&config.daemon, session_tx) => {
            result?;
        }
        _ = ctrl_c => {
            info!("received shutdown signal");
        }
    }

    // Cleanup
    listener::cleanup_socket(&socket_path);
    info!("keyquorum daemon stopped");

    Ok(())
}
