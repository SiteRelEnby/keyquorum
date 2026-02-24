use std::collections::HashSet;
use std::time::Duration;

use base64::Engine;
use sharks::Sharks;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use keyquorum_core::config::{ActionConfig, SessionConfig};
use keyquorum_core::protocol::{ActionResult, DaemonMessage};
use keyquorum_core::types::{SessionState, SessionStatus, ShareSubmission};

use super::action;

/// Holds raw share bytes, securely wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecureShareData {
    bytes: Vec<u8>,
}

/// Commands sent from connection handlers to the session task.
pub enum SessionCommand {
    SubmitShare {
        share: ShareSubmission,
        respond_to: oneshot::Sender<DaemonMessage>,
    },
    GetStatus {
        respond_to: oneshot::Sender<DaemonMessage>,
    },
}

/// The session state machine. Owns all secret material.
/// Only accessed from a single tokio task (never shared).
struct Session {
    config: SessionConfig,
    action_config: ActionConfig,
    state: SessionState,
    shares: Vec<(u8, SecureShareData)>,
    received_indices: HashSet<u8>,
    started_at: Option<Instant>,
    log_participation: bool,
}

impl Session {
    fn new(config: SessionConfig, action_config: ActionConfig, log_participation: bool) -> Self {
        Self {
            config,
            action_config,
            state: SessionState::Idle,
            shares: Vec::new(),
            received_indices: HashSet::new(),
            started_at: None,
            log_participation,
        }
    }

    fn status(&self) -> SessionStatus {
        let elapsed_secs = self.started_at.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        let shares_received = self.shares.len() as u8;
        let shares_needed = self.config.threshold.saturating_sub(shares_received);

        SessionStatus {
            state: self.state.clone(),
            threshold: self.config.threshold,
            shares_received,
            shares_needed,
            timeout_secs: self.config.timeout_secs,
            elapsed_secs,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        self.started_at
            .map(|s| s + Duration::from_secs(self.config.timeout_secs))
    }

    fn submit_share(&mut self, share: ShareSubmission) -> DaemonMessage {
        // Only accept shares when Idle or Collecting
        if self.state != SessionState::Idle && self.state != SessionState::Collecting {
            return DaemonMessage::ShareRejected {
                reason: format!("Session is in {:?} state, not accepting shares", self.state),
            };
        }

        // Check for duplicate index
        if self.received_indices.contains(&share.index) {
            return DaemonMessage::ShareRejected {
                reason: format!("Share with index {} already submitted", share.index),
            };
        }

        // Decode base64 to raw bytes
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = match engine.decode(&share.data) {
            Ok(b) => b,
            Err(e) => {
                return DaemonMessage::ShareRejected {
                    reason: format!("Invalid base64: {}", e),
                };
            }
        };

        // Validate it's a valid sharks share
        if sharks::Share::try_from(bytes.as_slice()).is_err() {
            return DaemonMessage::ShareRejected {
                reason: "Invalid share data".to_string(),
            };
        }

        // Lock share bytes in memory
        let _ = keyquorum_core::memory::mlock_slice(&bytes);
        let _ = keyquorum_core::memory::madvise_dontfork(&bytes);

        // Log participation if enabled (never log share data)
        if self.log_participation {
            info!(
                index = share.index,
                user = share.submitted_by.as_deref().unwrap_or("anonymous"),
                "share submitted"
            );
        }

        // Store the share
        self.received_indices.insert(share.index);
        self.shares.push((share.index, SecureShareData { bytes }));

        // Start timer on first share
        if self.state == SessionState::Idle {
            self.started_at = Some(Instant::now());
            self.state = SessionState::Collecting;
            info!("session started, collecting shares");
        }

        info!(
            received = self.shares.len(),
            needed = self.config.threshold,
            "share accepted"
        );

        DaemonMessage::ShareAccepted {
            status: self.status(),
        }
    }

    async fn try_reconstruct(&mut self) -> Option<DaemonMessage> {
        if (self.shares.len() as u8) < self.config.threshold {
            return None;
        }

        self.state = SessionState::Reconstructing;
        info!("threshold reached, reconstructing secret");

        // Convert stored bytes back to sharks::Share
        let shark_shares: Vec<sharks::Share> = self
            .shares
            .iter()
            .filter_map(|(_, data)| sharks::Share::try_from(data.bytes.as_slice()).ok())
            .collect();

        if shark_shares.len() < self.config.threshold as usize {
            self.state = SessionState::Failed;
            let msg = DaemonMessage::QuorumReached {
                action_result: ActionResult::Failure {
                    message: "Failed to parse stored shares".to_string(),
                },
            };
            self.reset();
            return Some(msg);
        }

        // Reconstruct the secret
        let sharks_instance = Sharks(self.config.threshold);
        let mut secret: Vec<u8> = match sharks_instance.recover(&shark_shares) {
            Ok(s) => s,
            Err(e) => {
                self.state = SessionState::Failed;
                let msg = DaemonMessage::QuorumReached {
                    action_result: ActionResult::Failure {
                        message: format!("Reconstruction failed: {}", e),
                    },
                };
                self.reset();
                return Some(msg);
            }
        };

        // mlock the reconstructed secret
        let _ = keyquorum_core::memory::mlock_slice(&secret);
        let _ = keyquorum_core::memory::madvise_dontfork(&secret);

        // Execute the configured action
        let result = action::execute(&self.action_config, &secret).await;

        // Immediately zeroize the secret
        secret.zeroize();

        match &result {
            ActionResult::Success { message } => {
                self.state = SessionState::Completed;
                info!(message = message.as_str(), "action completed successfully");
            }
            ActionResult::Failure { message } => {
                self.state = SessionState::Failed;
                warn!(message = message.as_str(), "action failed");
            }
        }

        // Wipe all shares
        self.reset();

        Some(DaemonMessage::QuorumReached {
            action_result: result,
        })
    }

    fn handle_timeout(&mut self) {
        warn!("session timed out, wiping all shares");
        self.state = SessionState::TimedOut;
        self.reset();
    }

    fn reset(&mut self) {
        // ZeroizeOnDrop on SecureShareData handles wiping when Vec is cleared
        self.shares.clear();
        self.received_indices.clear();
        self.started_at = None;
        self.state = SessionState::Idle;
    }
}

/// Run the session task. This is the single owner of all secret material.
pub async fn run_session(
    mut rx: mpsc::Receiver<SessionCommand>,
    config: SessionConfig,
    action_config: ActionConfig,
    log_participation: bool,
) {
    let mut session = Session::new(config, action_config, log_participation);

    loop {
        let timeout_future = async {
            if let Some(deadline) = session.deadline() {
                tokio::time::sleep_until(deadline).await;
            } else {
                // No active session — sleep effectively forever
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            Some(cmd) = rx.recv() => {
                match cmd {
                    SessionCommand::SubmitShare { share, respond_to } => {
                        let response = session.submit_share(share);

                        // If this share was rejected, send rejection immediately
                        if matches!(response, DaemonMessage::ShareRejected { .. }) {
                            let _ = respond_to.send(response);
                            continue;
                        }

                        // If threshold reached, reconstruct before responding
                        // so the submitting client gets the action result
                        if session.shares.len() as u8 >= session.config.threshold
                            && session.state == SessionState::Collecting
                        {
                            if let Some(quorum_msg) = session.try_reconstruct().await {
                                let _ = respond_to.send(quorum_msg);
                            } else {
                                let _ = respond_to.send(response);
                            }
                        } else {
                            let _ = respond_to.send(response);
                        }
                    }
                    SessionCommand::GetStatus { respond_to } => {
                        let _ = respond_to.send(DaemonMessage::Status {
                            status: session.status(),
                        });
                    }
                }
            }
            _ = timeout_future => {
                session.handle_timeout();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use sharks::Sharks;

    fn make_shares(secret: &[u8], threshold: u8, n: u8) -> Vec<String> {
        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(secret);
        let shares: Vec<sharks::Share> = dealer.take(n as usize).collect();
        let engine = base64::engine::general_purpose::STANDARD;
        shares
            .iter()
            .map(|s| engine.encode(Vec::<u8>::from(s)))
            .collect()
    }

    fn share_index(b64: &str) -> u8 {
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = engine.decode(b64).unwrap();
        bytes[0]
    }

    fn make_test_session(threshold: u8, total: u8) -> Session {
        Session::new(
            SessionConfig {
                threshold,
                total_shares: total,
                timeout_secs: 60,
            },
            ActionConfig::Stdout,
            false,
        )
    }

    #[test]
    fn initial_state_is_idle() {
        let session = make_test_session(3, 5);
        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
        assert!(session.started_at.is_none());
    }

    #[test]
    fn first_share_starts_collecting() {
        let mut session = make_test_session(3, 5);
        let shares = make_shares(b"test-secret", 3, 5);

        let response = session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });

        assert!(matches!(response, DaemonMessage::ShareAccepted { .. }));
        assert_eq!(session.state, SessionState::Collecting);
        assert!(session.started_at.is_some());
        assert_eq!(session.shares.len(), 1);
    }

    #[test]
    fn duplicate_index_rejected() {
        let mut session = make_test_session(3, 5);
        let shares = make_shares(b"test-secret", 3, 5);
        let idx = share_index(&shares[0]);

        // Submit first share
        session.submit_share(ShareSubmission {
            index: idx,
            data: shares[0].clone(),
            submitted_by: None,
        });

        // Submit same index again
        let response = session.submit_share(ShareSubmission {
            index: idx,
            data: shares[0].clone(),
            submitted_by: None,
        });

        assert!(matches!(response, DaemonMessage::ShareRejected { .. }));
        assert_eq!(session.shares.len(), 1);
    }

    #[test]
    fn invalid_base64_rejected() {
        let mut session = make_test_session(3, 5);

        let response = session.submit_share(ShareSubmission {
            index: 1,
            data: "not-valid-base64!!!".to_string(),
            submitted_by: None,
        });

        assert!(matches!(response, DaemonMessage::ShareRejected { .. }));
        assert_eq!(session.shares.len(), 0);
    }

    #[tokio::test]
    async fn threshold_triggers_reconstruction() {
        let mut session = make_test_session(2, 3);
        let shares = make_shares(b"my-secret", 2, 3);

        // Submit first share
        session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });
        assert_eq!(session.state, SessionState::Collecting);

        // Submit second share (meets threshold)
        session.submit_share(ShareSubmission {
            index: share_index(&shares[1]),
            data: shares[1].clone(),
            submitted_by: None,
        });

        // Trigger reconstruction
        let result = session.try_reconstruct().await;
        assert!(result.is_some());

        match result.unwrap() {
            DaemonMessage::QuorumReached { action_result } => {
                assert!(matches!(action_result, ActionResult::Success { .. }));
            }
            other => panic!(
                "expected QuorumReached, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }

        // Session should be reset after reconstruction
        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
        assert!(session.received_indices.is_empty());
    }

    #[test]
    fn reset_clears_everything() {
        let mut session = make_test_session(3, 5);
        let shares = make_shares(b"test", 3, 5);

        session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });
        session.submit_share(ShareSubmission {
            index: share_index(&shares[1]),
            data: shares[1].clone(),
            submitted_by: None,
        });

        assert_eq!(session.shares.len(), 2);
        session.reset();

        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
        assert!(session.received_indices.is_empty());
        assert!(session.started_at.is_none());
    }

    #[test]
    fn timeout_wipes_shares() {
        let mut session = make_test_session(3, 5);
        let shares = make_shares(b"test", 3, 5);

        session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });

        session.handle_timeout();

        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
    }

    #[test]
    fn status_reports_correctly() {
        let mut session = make_test_session(3, 5);
        let shares = make_shares(b"test", 3, 5);

        let status = session.status();
        assert_eq!(status.state, SessionState::Idle);
        assert_eq!(status.shares_received, 0);
        assert_eq!(status.shares_needed, 3);

        session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });

        let status = session.status();
        assert_eq!(status.state, SessionState::Collecting);
        assert_eq!(status.shares_received, 1);
        assert_eq!(status.shares_needed, 2);
    }

    #[test]
    fn rejects_share_in_wrong_state() {
        let mut session = make_test_session(3, 5);
        let shares = make_shares(b"test", 3, 5);

        // Force into Reconstructing state
        session.state = SessionState::Reconstructing;

        let response = session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });

        assert!(matches!(response, DaemonMessage::ShareRejected { .. }));
    }
}
