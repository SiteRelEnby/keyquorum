use std::process::Stdio;

use keyquorum_core::config::ActionConfig;
use keyquorum_core::protocol::ActionResult;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info};

/// Execute the configured action with the reconstructed secret.
pub async fn execute(config: &ActionConfig, secret: &[u8]) -> ActionResult {
    match config {
        ActionConfig::Luks { device, name } => luks_unlock(device, name, secret).await,
        ActionConfig::Stdout => stdout_write(secret),
        ActionConfig::Command { program, args } => run_command(program, args, secret).await,
    }
}

async fn luks_unlock(device: &str, name: &str, secret: &[u8]) -> ActionResult {
    info!(device = device, name = name, "unlocking LUKS device");

    let mut child = match Command::new("cryptsetup")
        .args(["luksOpen", "--key-file=-", device, name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return ActionResult::Failure {
                message: format!("Failed to spawn cryptsetup: {}", e),
            };
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(secret).await {
            let _ = child.kill().await;
            return ActionResult::Failure {
                message: format!("Failed to write secret to cryptsetup stdin: {}", e),
            };
        }
        // drop stdin to close the pipe, signaling EOF
    }

    match child.wait_with_output().await {
        Ok(output) if output.status.success() => ActionResult::Success {
            message: format!("LUKS device {} unlocked as {}", device, name),
        },
        Ok(output) => {
            debug!(
                stderr = %String::from_utf8_lossy(&output.stderr),
                exit_code = %output.status,
                "cryptsetup stderr (not sent to client)"
            );
            ActionResult::Failure {
                message: format!("cryptsetup failed (exit {})", output.status),
            }
        }
        Err(e) => ActionResult::Failure {
            message: format!("Failed to wait for cryptsetup: {}", e),
        },
    }
}

fn stdout_write(secret: &[u8]) -> ActionResult {
    use std::io::Write;
    match std::io::stdout().write_all(secret) {
        Ok(_) => {
            let _ = std::io::stdout().flush();
            ActionResult::Success {
                message: "Secret written to stdout".to_string(),
            }
        }
        Err(e) => ActionResult::Failure {
            message: format!("Failed to write to stdout: {}", e),
        },
    }
}

async fn run_command(program: &str, args: &[String], secret: &[u8]) -> ActionResult {
    info!(program = program, "running command");

    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return ActionResult::Failure {
                message: format!("Failed to spawn {}: {}", program, e),
            };
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(secret).await {
            let _ = child.kill().await;
            return ActionResult::Failure {
                message: format!("Failed to write secret to {} stdin: {}", program, e),
            };
        }
    }

    match child.wait_with_output().await {
        Ok(output) if output.status.success() => ActionResult::Success {
            message: format!("Command {} completed successfully", program,),
        },
        Ok(output) => {
            debug!(
                program = program,
                stderr = %String::from_utf8_lossy(&output.stderr),
                exit_code = %output.status,
                "command stderr (not sent to client)"
            );
            ActionResult::Failure {
                message: format!("{} failed (exit {})", program, output.status),
            }
        }
        Err(e) => ActionResult::Failure {
            message: format!("Failed to wait for {}: {}", program, e),
        },
    }
}
