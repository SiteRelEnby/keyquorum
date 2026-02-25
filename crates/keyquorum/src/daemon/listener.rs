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
    // Clean up stale socket file if it exists — but only if it's actually a socket
    let socket_path = &config.socket_path;
    if socket_path.exists() {
        use std::os::unix::fs::FileTypeExt;
        let metadata = std::fs::symlink_metadata(socket_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to stat existing path {}: {}",
                socket_path.display(),
                e
            )
        })?;
        if metadata.file_type().is_socket() {
            std::fs::remove_file(socket_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to remove stale socket {}: {}",
                    socket_path.display(),
                    e
                )
            })?;
        } else {
            return Err(anyhow::anyhow!(
                "socket path {} already exists and is not a socket (refusing to delete)",
                socket_path.display()
            ));
        }
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!("failed to create socket directory {}: {}", parent.display(), e)
        })?;
    }

    let unix_listener = UnixListener::bind(socket_path).map_err(|e| {
        anyhow::anyhow!("failed to bind Unix socket {}: {}", socket_path.display(), e)
    })?;

    // Set socket permissions to 0o660
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660)).map_err(
            |e| {
                anyhow::anyhow!(
                    "failed to set permissions on {}: {}",
                    socket_path.display(),
                    e
                )
            },
        )?;
    }

    info!(path = %socket_path.display(), "listening on Unix socket");

    if let Some(port) = config.tcp_port {
        let bind_addr = format!("127.0.0.1:{}", port);
        let tcp_listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
            anyhow::anyhow!("failed to bind TCP listener on {}: {}", bind_addr, e)
        })?;
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
