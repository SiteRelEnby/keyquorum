use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use super::session::SessionCommand;
use keyquorum_core::protocol::{ClientMessage, DaemonMessage};

/// Maximum size of a single JSON message line (64 KB).
/// A base64-encoded share is ~350 bytes; this leaves ample room
/// while preventing memory exhaustion from oversized payloads.
const MAX_LINE_LENGTH: usize = 64 * 1024;

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
    let mut buf_reader = BufReader::new(reader);

    loop {
        let line = match read_limited_line(&mut buf_reader).await {
            Ok(Some(line)) => line,
            Ok(None) => break, // EOF
            Err(e) => {
                let _ = write_message(
                    &mut writer,
                    &DaemonMessage::Error {
                        message: format!("{}", e),
                    },
                )
                .await;
                break;
            }
        };

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

/// Read a single newline-terminated line, rejecting lines that exceed MAX_LINE_LENGTH.
/// Returns Ok(None) on EOF, Ok(Some(line)) on success, Err on oversized or invalid data.
async fn read_limited_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let found_newline = if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..pos]);
            reader.consume(pos + 1);
            true
        } else {
            line.extend_from_slice(buf);
            let len = buf.len();
            reader.consume(len);
            false
        };
        if line.len() > MAX_LINE_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Message exceeds maximum size of {} bytes", MAX_LINE_LENGTH),
            ));
        }
        if found_newline {
            break;
        }
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8"))
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
