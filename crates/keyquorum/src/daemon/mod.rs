pub mod action;
pub mod handler;
pub mod listener;
pub mod session;

use std::path::PathBuf;

use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use keyquorum_core::config::Config;

pub async fn run(config_path: PathBuf, lockdown: bool) -> anyhow::Result<()> {
    // Harden process before loading any secrets
    keyquorum_core::memory::harden_process()?;

    // Load config
    let mut config = Config::from_file(&config_path).map_err(|e| {
        anyhow::anyhow!("failed to load config from {}: {}", config_path.display(), e)
    })?;

    // Apply and validate lockdown mode (from CLI flag or config file)
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
    tokio::spawn(async move {
        session::run_session(
            session_rx,
            session_config,
            action_config,
            log_participation,
            session_lockdown,
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
