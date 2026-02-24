use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use super::session::SessionCommand;
use keyquorum_core::protocol::{ClientMessage, DaemonMessage};

/// Handle a single client connection. Reads newline-delimited JSON,
/// dispatches to the session task, and writes responses.
pub async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    session_tx: mpsc::Sender<SessionCommand>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }

        let msg: ClientMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                let err = DaemonMessage::Error {
                    message: format!("Invalid JSON: {}", e),
                };
                let _ = write_message(&mut writer, &err).await;
                continue;
            }
        };

        let (tx, rx) = oneshot::channel();
        let cmd = match msg {
            ClientMessage::SubmitShare { share } => {
                debug!(index = share.index, "received share submission");
                SessionCommand::SubmitShare {
                    share,
                    respond_to: tx,
                }
            }
            ClientMessage::Status => {
                debug!("received status query");
                SessionCommand::GetStatus { respond_to: tx }
            }
        };

        if session_tx.send(cmd).await.is_err() {
            warn!("session task has shut down");
            let _ = write_message(
                &mut writer,
                &DaemonMessage::Error {
                    message: "Internal error: session task unavailable".to_string(),
                },
            )
            .await;
            break;
        }

        match rx.await {
            Ok(response) => {
                let _ = write_message(&mut writer, &response).await;
            }
            Err(_) => {
                warn!("session task dropped response channel");
                break;
            }
        }
    }
}

async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &DaemonMessage,
) -> std::io::Result<()> {
    let mut json = serde_json::to_string(msg).map_err(std::io::Error::other)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}
