use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroize;

use keyquorum_core::protocol::{ActionResult, ClientMessage, DaemonMessage};
use keyquorum_core::types::ShareSubmission;

pub async fn run(user: Option<String>, socket: String) -> Result<()> {
    // Read share from stdin (pipe or interactive).
    // share_input is zeroized at end of function to avoid lingering in memory.
    let share_input = {
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            eprintln!("Enter share (then press Enter twice, or Ctrl+D):");
        }
        let mut buf = String::new();
        let mut saw_content = false;
        let mut in_envelope = false;
        let mut saw_envelope_blank = false;
        loop {
            let mut line = String::new();
            let n = std::io::stdin().read_line(&mut line)?;
            if n == 0 {
                break; // EOF (Ctrl+D or pipe ended)
            }
            let trimmed = line.trim();
            if trimmed.starts_with("KEYQUORUM-SHARE-") {
                in_envelope = true;
            }
            if trimmed.is_empty() {
                if in_envelope && !saw_envelope_blank {
                    // Blank line inside PEM envelope separates headers from payload
                    saw_envelope_blank = true;
                    buf.push_str(&line);
                    continue;
                }
                if saw_content {
                    break; // blank line after content = done
                }
                continue; // skip leading blank lines
            }
            saw_content = true;
            buf.push_str(&line);
        }
        buf.trim().to_string()
    };

    if share_input.is_empty() {
        bail!("no share data provided");
    }

    // Parse the share (auto-detects format: PEM envelope, bare v1, legacy base64/base32)
    let parsed = keyquorum_core::share_format::parse_share(&share_input)
        .map_err(|e| anyhow::anyhow!("invalid share: {}", e))?;

    if parsed.malformed_envelope {
        eprintln!(
            "warning: share extracted from malformed envelope (missing marker or headers)"
        );
    }

    let index = parsed.index;

    // Validate it's a valid sharks share
    if blahaj::Share::try_from(parsed.sharks_data.as_slice()).is_err() {
        bail!("invalid share data");
    }

    // Build and serialize the message. share_input is moved into
    // ShareSubmission (which has ZeroizeOnDrop), so it's zeroized when
    // msg drops at the end of this block. The serialized json buffer
    // still contains the share data and is zeroized after sending.
    let mut json = {
        let msg = ClientMessage::SubmitShare {
            share: ShareSubmission {
                index,
                data: share_input,
                submitted_by: user,
            },
        };
        let mut j = serde_json::to_string(&msg)?;
        j.push('\n');
        j
        // msg drops here → ShareSubmission.data is zeroized
    };

    // Connect to daemon
    let conn = super::connect(&socket).await?;
    let (reader, mut writer) = conn.split();

    // Send the message, then zeroize the serialized buffer
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    json.zeroize();

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
