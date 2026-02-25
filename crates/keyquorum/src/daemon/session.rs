use std::collections::HashSet;
use std::time::Duration;

use base64::Engine;
use sharks::Sharks;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use keyquorum_core::config::{ActionConfig, OnFailure, SessionConfig};
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
    retry_attempts: u8,
    lockdown: bool,
}

impl Session {
    fn new(
        config: SessionConfig,
        action_config: ActionConfig,
        log_participation: bool,
        lockdown: bool,
    ) -> Self {
        Self {
            config,
            action_config,
            state: SessionState::Idle,
            shares: Vec::new(),
            received_indices: HashSet::new(),
            started_at: None,
            log_participation,
            retry_attempts: 0,
            lockdown,
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
            retry_attempts: self.retry_attempts,
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

        // Enforce total_shares cap
        if self.shares.len() as u8 >= self.config.total_shares {
            return DaemonMessage::ShareRejected {
                reason: format!(
                    "Already received maximum number of shares ({})",
                    self.config.total_shares
                ),
            };
        }

        // Normalize whitespace from share data (copy-paste often introduces spaces/newlines)
        let cleaned: String = share.data.chars().filter(|c| !c.is_whitespace()).collect();

        // Decode base64 to raw bytes
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = match engine.decode(&cleaned) {
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

        // Derive the actual share index from the decoded data (first byte)
        // and verify it matches the client-supplied index
        let actual_index = bytes[0];
        if share.index != actual_index {
            return DaemonMessage::ShareRejected {
                reason: format!(
                    "Share index mismatch: header says {} but share data contains index {}",
                    share.index, actual_index
                ),
            };
        }

        // Check for duplicate index (using verified index)
        if self.received_indices.contains(&actual_index) {
            return DaemonMessage::ShareRejected {
                reason: format!("Share with index {} already submitted", actual_index),
            };
        }

        // Apply memory protections to share bytes
        let failures = keyquorum_core::memory::protect_secret(&bytes);
        if !failures.is_empty() {
            for (name, err) in &failures {
                warn!("memory protection {} failed for share data: {}", name, err);
            }
            if self.lockdown {
                return DaemonMessage::ShareRejected {
                    reason: "lockdown mode: failed to apply memory protections to share data"
                        .to_string(),
                };
            }
        }

        // Log participation if enabled (never log share data)
        if self.log_participation {
            info!(
                index = actual_index,
                user = share.submitted_by.as_deref().unwrap_or("anonymous"),
                "share submitted"
            );
        }

        // Store the share
        self.received_indices.insert(actual_index);
        self.shares.push((actual_index, SecureShareData { bytes }));

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
        self.retry_attempts += 1;
        info!(
            attempt = self.retry_attempts,
            shares = self.shares.len(),
            "attempting reconstruction"
        );

        let k = self.config.threshold as usize;
        let n = self.shares.len();
        let sharks_instance = Sharks(self.config.threshold);
        let combos = k_combinations(n, k);

        for combo in &combos {
            // Parse shares for this combination
            let subset: Vec<sharks::Share> = combo
                .iter()
                .filter_map(|&i| {
                    sharks::Share::try_from(self.shares[i].1.bytes.as_slice()).ok()
                })
                .collect();

            if subset.len() != k {
                continue;
            }

            let mut secret = match sharks_instance.recover(&subset) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Apply memory protections to reconstructed secret
            let failures = keyquorum_core::memory::protect_secret(&secret);
            if !failures.is_empty() {
                for (name, err) in &failures {
                    warn!("memory protection {} failed for reconstructed secret: {}", name, err);
                }
                if self.lockdown {
                    secret.zeroize();
                    self.state = SessionState::Failed;
                    self.reset();
                    return Some(DaemonMessage::QuorumReached {
                        action_result: ActionResult::Failure {
                            message: "lockdown mode: failed to apply memory protections to reconstructed secret".to_string(),
                        },
                    });
                }
            }

            // Execute the configured action
            let result = action::execute(&self.action_config, &secret).await;

            // Immediately zeroize the secret
            secret.zeroize();

            match &result {
                ActionResult::Success { message } => {
                    self.state = SessionState::Completed;
                    info!(message = message.as_str(), "action completed successfully");
                    self.reset();
                    return Some(DaemonMessage::QuorumReached {
                        action_result: result,
                    });
                }
                ActionResult::Failure { message } => {
                    if combos.len() > 1 {
                        warn!(
                            message = message.as_str(),
                            combo = ?combo,
                            "combination failed, trying next"
                        );
                    }
                }
            }
        }

        // All combinations failed
        Some(self.handle_reconstruction_failure())
    }

    fn handle_reconstruction_failure(&mut self) -> DaemonMessage {
        match self.config.on_failure {
            OnFailure::Wipe => {
                self.state = SessionState::Failed;
                warn!("all combinations failed, wiping shares (on_failure=wipe)");
                self.reset();
                DaemonMessage::QuorumReached {
                    action_result: ActionResult::Failure {
                        message: "Reconstruction failed with all share combinations".to_string(),
                    },
                }
            }
            OnFailure::Retry => {
                if self.retry_attempts >= self.config.max_retries {
                    self.state = SessionState::Failed;
                    warn!(
                        attempts = self.retry_attempts,
                        max = self.config.max_retries,
                        "max retries exhausted, wiping shares"
                    );
                    self.reset();
                    DaemonMessage::QuorumReached {
                        action_result: ActionResult::Failure {
                            message: format!(
                                "Reconstruction failed after {} attempts, all shares wiped",
                                self.retry_attempts
                            ),
                        },
                    }
                } else {
                    self.state = SessionState::Collecting;
                    warn!(
                        attempts = self.retry_attempts,
                        max = self.config.max_retries,
                        shares = self.shares.len(),
                        "reconstruction failed, continuing to accept shares (on_failure=retry)"
                    );
                    DaemonMessage::QuorumReached {
                        action_result: ActionResult::Failure {
                            message: format!(
                                "Reconstruction attempt {} failed, submitting more shares may help",
                                self.retry_attempts
                            ),
                        },
                    }
                }
            }
        }
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
        self.retry_attempts = 0;
    }
}

/// Generate all k-sized combinations of indices 0..n.
fn k_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut combo = vec![0usize; k];
    generate_combos(&mut combo, 0, n, 0, k, &mut result);
    result
}

fn generate_combos(
    combo: &mut [usize],
    start: usize,
    n: usize,
    depth: usize,
    k: usize,
    result: &mut Vec<Vec<usize>>,
) {
    if depth == k {
        result.push(combo.to_vec());
        return;
    }
    for i in start..=(n - k + depth) {
        combo[depth] = i;
        generate_combos(combo, i + 1, n, depth + 1, k, result);
    }
}

/// Run the session task. This is the single owner of all secret material.
pub async fn run_session(
    mut rx: mpsc::Receiver<SessionCommand>,
    config: SessionConfig,
    action_config: ActionConfig,
    log_participation: bool,
    lockdown: bool,
) {
    let mut session = Session::new(config, action_config, log_participation, lockdown);

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
                on_failure: OnFailure::Wipe,
                max_retries: 3,
            },
            ActionConfig::Stdout,
            false,
            false,
        )
    }

    #[test]
    fn initial_state_is_idle() {
        let session = make_test_session(3, 5);
        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
        assert!(session.started_at.is_none());
        assert_eq!(session.retry_attempts, 0);
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
        assert_eq!(session.retry_attempts, 0);
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

    #[test]
    fn mismatched_index_rejected() {
        let mut session = make_test_session(3, 5);
        let shares = make_shares(b"test-mismatch", 3, 5);
        let actual_index = share_index(&shares[0]);
        let wrong_index = actual_index.wrapping_add(1);

        let response = session.submit_share(ShareSubmission {
            index: wrong_index,
            data: shares[0].clone(),
            submitted_by: None,
        });

        match response {
            DaemonMessage::ShareRejected { reason } => {
                assert!(reason.contains("mismatch"), "reason: {}", reason);
            }
            other => panic!(
                "expected ShareRejected, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
        assert_eq!(session.shares.len(), 0);
    }

    #[test]
    fn total_shares_cap_enforced() {
        // 2-of-2 session — should accept exactly 2 shares
        let mut session = make_test_session(2, 2);
        let shares = make_shares(b"test-cap", 2, 3);

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

        // Third share should be rejected
        let response = session.submit_share(ShareSubmission {
            index: share_index(&shares[2]),
            data: shares[2].clone(),
            submitted_by: None,
        });

        match response {
            DaemonMessage::ShareRejected { reason } => {
                assert!(reason.contains("maximum"), "reason: {}", reason);
            }
            other => panic!(
                "expected ShareRejected, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
        assert_eq!(session.shares.len(), 2);
    }

    #[test]
    fn k_combinations_correctness() {
        let combos = k_combinations(4, 2);
        assert_eq!(combos.len(), 6); // C(4,2) = 6
        assert_eq!(combos[0], vec![0, 1]);
        assert_eq!(combos[5], vec![2, 3]);

        let combos = k_combinations(3, 3);
        assert_eq!(combos.len(), 1); // C(3,3) = 1
        assert_eq!(combos[0], vec![0, 1, 2]);

        let combos = k_combinations(5, 3);
        assert_eq!(combos.len(), 10); // C(5,3) = 10
    }

    #[tokio::test]
    async fn retry_mode_keeps_shares_after_failed_action() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Retry,
                max_retries: 3,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
            false,
        );

        let shares = make_shares(b"retry-test", 2, 3);

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

        // Attempt reconstruction — action will fail (/bin/false exits 1)
        let result = session.try_reconstruct().await;
        assert!(result.is_some());
        match result.unwrap() {
            DaemonMessage::QuorumReached { action_result } => {
                assert!(matches!(action_result, ActionResult::Failure { .. }));
            }
            other => panic!(
                "expected QuorumReached failure, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }

        // Session should be back to Collecting with shares preserved
        assert_eq!(session.state, SessionState::Collecting);
        assert_eq!(session.shares.len(), 2);
        assert_eq!(session.retry_attempts, 1);
    }

    #[tokio::test]
    async fn retry_mode_exhausts_max_retries() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 4,
                timeout_secs: 60,
                on_failure: OnFailure::Retry,
                max_retries: 2,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
            false,
        );

        let shares = make_shares(b"exhaust-test", 2, 4);

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

        // First attempt — should retry
        session.try_reconstruct().await;
        assert_eq!(session.state, SessionState::Collecting);
        assert_eq!(session.retry_attempts, 1);

        // Submit third share
        session.submit_share(ShareSubmission {
            index: share_index(&shares[2]),
            data: shares[2].clone(),
            submitted_by: None,
        });

        // Second attempt — max_retries=2, should wipe
        session.try_reconstruct().await;
        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
        assert_eq!(session.retry_attempts, 0);
    }

    #[tokio::test]
    async fn wipe_mode_clears_on_failure() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
            false,
        );

        let shares = make_shares(b"wipe-test", 2, 3);

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

        let result = session.try_reconstruct().await;
        assert!(result.is_some());

        // Wipe mode: shares should be gone immediately
        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
        assert_eq!(session.retry_attempts, 0);
    }
}
