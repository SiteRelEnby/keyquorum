use std::path::Path;

use tokio::net::{TcpListener, UnixListener};
use tokio::sync::mpsc;
use tracing::{error, info};

use keyquorum_core::config::DaemonConfig;

use super::handler;
use super::session::SessionCommand;

/// Start listeners and accept connections, dispatching each to a handler task.
pub async fn run_listeners(
    config: &DaemonConfig,
    session_tx: mpsc::Sender<SessionCommand>,
) -> anyhow::Result<()> {
    // Clean up stale socket file if it exists
    let socket_path = &config.socket_path;
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let unix_listener = UnixListener::bind(socket_path)?;

    // Set socket permissions to 0o660
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    }

    info!(path = %socket_path.display(), "listening on Unix socket");

    if let Some(port) = config.tcp_port {
        let bind_addr = format!("127.0.0.1:{}", port);
        let tcp_listener = TcpListener::bind(&bind_addr).await?;
        info!(addr = %bind_addr, "listening on TCP");

        // Run both listeners concurrently
        tokio::select! {
            result = accept_unix_loop(unix_listener, session_tx.clone()) => result,
            result = accept_tcp_loop(tcp_listener, session_tx) => result,
        }
    } else {
        accept_unix_loop(unix_listener, session_tx).await
    }
}

async fn accept_unix_loop(
    listener: UnixListener,
    session_tx: mpsc::Sender<SessionCommand>,
) -> anyhow::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let tx = session_tx.clone();
                tokio::spawn(async move {
                    let (reader, writer) = tokio::io::split(stream);
                    handler::handle_connection(reader, writer, tx).await;
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept Unix connection");
            }
        }
    }
}

async fn accept_tcp_loop(
    listener: TcpListener,
    session_tx: mpsc::Sender<SessionCommand>,
) -> anyhow::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!(addr = %addr, "accepted TCP connection");
                let tx = session_tx.clone();
                tokio::spawn(async move {
                    let (reader, writer) = tokio::io::split(stream);
                    handler::handle_connection(reader, writer, tx).await;
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept TCP connection");
            }
        }
    }
}

/// Clean up the Unix socket file on shutdown.
pub fn cleanup_socket(path: &Path) {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}
