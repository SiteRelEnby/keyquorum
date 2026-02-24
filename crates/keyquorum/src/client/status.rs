use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use keyquorum_core::protocol::{ClientMessage, DaemonMessage};
use keyquorum_core::types::SessionState;

pub async fn run(socket: String) -> Result<()> {
    let conn = super::connect(&socket).await?;
    let (reader, mut writer) = conn.split();

    // Send status query
    let msg = ClientMessage::Status;
    let mut json = serde_json::to_string(&msg)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;

    // Read response
    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        let response: DaemonMessage = serde_json::from_str(&line)?;
        match response {
            DaemonMessage::Status { status } => {
                let state_str = match status.state {
                    SessionState::Idle => "Idle (waiting for first share)",
                    SessionState::Collecting => "Collecting shares",
                    SessionState::Reconstructing => "Reconstructing secret",
                    SessionState::Completed => "Completed",
                    SessionState::TimedOut => "Timed out",
                    SessionState::Failed => "Failed",
                };
                eprintln!("Session state: {}", state_str);
                eprintln!("Shares: {}/{}", status.shares_received, status.threshold);
                if status.shares_needed > 0 {
                    eprintln!("Need {} more share(s)", status.shares_needed);
                }
                if status.state == SessionState::Collecting {
                    let remaining = status.timeout_secs.saturating_sub(status.elapsed_secs);
                    eprintln!("Time remaining: {}m {}s", remaining / 60, remaining % 60);
                }
            }
            DaemonMessage::Error { message } => {
                eprintln!("Error: {}", message);
                std::process::exit(1);
            }
            _ => {
                eprintln!("Unexpected response from daemon");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
