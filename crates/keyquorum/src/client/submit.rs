use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use keyquorum_core::protocol::{ActionResult, ClientMessage, DaemonMessage};
use keyquorum_core::types::ShareSubmission;

pub async fn run(share_arg: Option<String>, user: Option<String>, socket: String) -> Result<()> {
    // Get share data from arg or stdin
    let share_input = match share_arg {
        Some(s) => s.trim().to_string(),
        None => {
            eprintln!("Enter share:");
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
            buf.trim().to_string()
        }
    };

    if share_input.is_empty() {
        bail!("no share data provided");
    }

    // Parse the share (auto-detects format: PEM envelope, bare v1, legacy base64/base32)
    let parsed = keyquorum_core::share_format::parse_share(&share_input)
        .map_err(|e| anyhow::anyhow!("invalid share: {}", e))?;

    let index = parsed.index;

    // Validate it's a valid sharks share
    if sharks::Share::try_from(parsed.sharks_data.as_slice()).is_err() {
        bail!("invalid share data");
    }

    // Build the message — send the original input string so the daemon
    // can do its own full parsing (including metadata validation)
    let msg = ClientMessage::SubmitShare {
        share: ShareSubmission {
            index,
            data: share_input,
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
