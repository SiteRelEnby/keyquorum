use anyhow::{bail, Result};
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use keyquorum_core::protocol::{ActionResult, ClientMessage, DaemonMessage};
use keyquorum_core::types::ShareSubmission;

pub async fn run(share_arg: Option<String>, user: Option<String>, socket: String) -> Result<()> {
    // Get share data from arg or stdin
    let share_b64 = match share_arg {
        Some(s) => s.trim().to_string(),
        None => {
            eprintln!("Enter share (base64):");
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            buf.trim().to_string()
        }
    };

    if share_b64.is_empty() {
        bail!("no share data provided");
    }

    // Decode to validate
    let engine = base64::engine::general_purpose::STANDARD;
    let share_bytes = engine.decode(&share_b64)?;

    if share_bytes.is_empty() {
        bail!("share data is empty");
    }

    // First byte is the share index
    let index = share_bytes[0];

    // Validate it's a valid sharks share
    if sharks::Share::try_from(share_bytes.as_slice()).is_err() {
        bail!("invalid share data");
    }

    // Build the message
    let msg = ClientMessage::SubmitShare {
        share: ShareSubmission {
            index,
            data: share_b64,
            submitted_by: user,
        },
    };

    // Connect to daemon
    let conn = super::connect(&socket).await?;
    let (reader, mut writer) = conn.split();

    // Send the message
    let mut json = serde_json::to_string(&msg)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;

    // Read response
    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        let response: DaemonMessage = serde_json::from_str(&line)?;
        print_response(&response);
    } else {
        bail!("daemon closed connection without responding");
    }

    Ok(())
}

fn print_response(msg: &DaemonMessage) {
    match msg {
        DaemonMessage::ShareAccepted { status } => {
            eprintln!("Share accepted.");
            eprintln!("  Shares: {}/{}", status.shares_received, status.threshold);
            if status.shares_needed > 0 {
                eprintln!("  Still need {} more share(s)", status.shares_needed);
            } else {
                eprintln!("  Quorum reached!");
            }
            let remaining = status.timeout_secs.saturating_sub(status.elapsed_secs);
            eprintln!("  Time remaining: {}m {}s", remaining / 60, remaining % 60);
        }
        DaemonMessage::ShareRejected { reason } => {
            eprintln!("Share rejected: {}", reason);
            std::process::exit(1);
        }
        DaemonMessage::QuorumReached { action_result } => match action_result {
            ActionResult::Success { message } => {
                eprintln!("Quorum reached! Action succeeded: {}", message);
            }
            ActionResult::Failure { message } => {
                eprintln!("Quorum reached but action failed: {}", message);
                std::process::exit(1);
            }
        },
        DaemonMessage::Error { message } => {
            eprintln!("Error: {}", message);
            std::process::exit(1);
        }
        DaemonMessage::Status { status } => {
            eprintln!("Status: {:?}", status.state);
        }
    }
}
