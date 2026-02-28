use std::collections::HashSet;
use std::time::Duration;

use blahaj::Sharks;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use keyquorum_core::config::{ActionConfig, OnFailure, SessionConfig, Verification};
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
    strict_hardening: bool,
}

impl Session {
    fn new(
        config: SessionConfig,
        action_config: ActionConfig,
        log_participation: bool,
        lockdown: bool,
        strict_hardening: bool,
    ) -> Self {
        let _ = lockdown; // validated at config level, not needed at session level
        Self {
            config,
            action_config,
            state: SessionState::Idle,
            shares: Vec::new(),
            received_indices: HashSet::new(),
            started_at: None,
            log_participation,
            retry_attempts: 0,
            strict_hardening,
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

        // Parse share format (auto-detects: PEM envelope, bare V1, legacy base64/base32)
        let parsed = match keyquorum_core::share_format::parse_share(&share.data) {
            Ok(p) => p,
            Err(e) => {
                return DaemonMessage::ShareRejected {
                    reason: format!("invalid share format: {}", e),
                };
            }
        };

        if parsed.malformed_envelope {
            if self.log_participation {
                warn!(
                    user = share.submitted_by.as_deref().unwrap_or("anonymous"),
                    "share accepted from malformed envelope (missing marker or headers)"
                );
            } else {
                warn!("share accepted from malformed envelope (missing marker or headers)");
            }
        }

        // Validate metadata if require_metadata is enabled.
        // Requires a PEM envelope with at least the Share: header (which carries
        // share_number, total_shares, threshold). A share with only Scheme: or
        // Integrity: headers is not sufficient.
        if self.config.require_metadata {
            let has_complete_metadata = parsed.had_envelope
                && parsed.metadata.as_ref().is_some_and(|m| {
                    m.share_number.is_some() && m.total_shares.is_some() && m.threshold.is_some()
                });
            if !has_complete_metadata {
                return DaemonMessage::ShareRejected {
                    reason: "share rejected: PEM envelope with complete metadata required \
                             (Share header with share number, total, and threshold) \
                             (require_metadata = true)"
                        .to_string(),
                };
            }
            if let Some(ref meta) = parsed.metadata {
                if let Err(e) = keyquorum_core::share_format::validate_metadata(
                    meta,
                    self.config.threshold,
                    self.config.total_shares,
                ) {
                    return DaemonMessage::ShareRejected {
                        reason: format!("metadata validation failed: {}", e),
                    };
                }
            }
        }

        // Extract sharks data and index from parsed result
        let actual_index = parsed.index;
        let mut bytes = parsed.sharks_data.clone();
        drop(parsed); // zeroize the ParsedShare copy

        // Validate it's a valid sharks share
        if blahaj::Share::try_from(bytes.as_slice()).is_err() {
            bytes.zeroize();
            return DaemonMessage::ShareRejected {
                reason: "invalid share data".to_string(),
            };
        }

        // Verify index matches client-supplied value
        if share.index != actual_index {
            bytes.zeroize();
            return DaemonMessage::ShareRejected {
                reason: format!(
                    "Share index mismatch: header says {} but share data contains index {}",
                    share.index, actual_index
                ),
            };
        }

        // Check for duplicate index (using verified index)
        if self.received_indices.contains(&actual_index) {
            bytes.zeroize();
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
            if self.strict_hardening {
                bytes.zeroize();
                return DaemonMessage::ShareRejected {
                    reason: "strict_hardening: failed to apply memory protections to share data"
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
        let max_combos = self.config.max_combinations;
        let mut combos_tried = 0usize;

        for combo in ComboIter::new(n, k).take(max_combos) {
            combos_tried += 1;

            // Parse shares for this combination
            let subset: Vec<blahaj::Share> = combo
                .iter()
                .filter_map(|&i| {
                    blahaj::Share::try_from(self.shares[i].1.bytes.as_slice()).ok()
                })
                .collect();

            if subset.len() != k {
                continue;
            }

            let mut secret = match sharks_instance.recover(&subset) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Verify the reconstructed secret before running the action
            match self.config.verification {
                Verification::EmbeddedBlake3 => {
                    if secret.len() < 32 {
                        secret.zeroize();
                        continue;
                    }
                    let payload_len = secret.len() - 32;
                    let expected = blake3::hash(&secret[..payload_len]);
                    if expected.as_bytes() != &secret[payload_len..] {
                        secret.zeroize();
                        continue;
                    }
                    // Zeroize the checksum bytes before truncating so no
                    // secret-derived material remains in the Vec's capacity
                    secret[payload_len..].zeroize();
                    secret.truncate(payload_len);
                }
                Verification::None => {
                    // No verification — fall through to action execution
                }
            }

            // Apply memory protections to reconstructed secret
            let failures = keyquorum_core::memory::protect_secret(&secret);
            if !failures.is_empty() {
                for (name, err) in &failures {
                    warn!(
                        "memory protection {} failed for reconstructed secret: {}",
                        name, err
                    );
                }
                if self.strict_hardening {
                    secret.zeroize();
                    let _ = keyquorum_core::memory::munlock_slice(&secret);
                    self.state = SessionState::Failed;
                    self.reset();
                    return Some(DaemonMessage::QuorumReached {
                        action_result: ActionResult::Failure {
                            message: "strict_hardening: failed to apply memory protections to reconstructed secret".to_string(),
                        },
                    });
                }
            }

            // Execute the configured action
            let result = action::execute(&self.action_config, &secret).await;

            // Immediately zeroize and munlock the secret
            secret.zeroize();
            let _ = keyquorum_core::memory::munlock_slice(&secret);

            match &result {
                ActionResult::Success { message } => {
                    self.state = SessionState::Completed;
                    info!(message = message.as_str(), "action completed successfully");

                    // Log which shares were used vs excluded
                    let used_indices: Vec<u8> =
                        combo.iter().map(|&i| self.shares[i].0).collect();
                    let excluded_indices: Vec<u8> = self
                        .shares
                        .iter()
                        .map(|(idx, _)| *idx)
                        .filter(|idx| !used_indices.contains(idx))
                        .collect();
                    if !excluded_indices.is_empty() {
                        warn!(
                            used = ?used_indices,
                            excluded = ?excluded_indices,
                            "reconstruction succeeded with some shares excluded"
                        );
                    }

                    self.reset();
                    return Some(DaemonMessage::QuorumReached {
                        action_result: result,
                    });
                }
                ActionResult::Failure { message } => {
                    if combos_tried > 1 || n > k {
                        warn!(
                            message = message.as_str(),
                            combo = ?combo,
                            "combination failed, trying next"
                        );
                    }
                }
            }
        }

        if combos_tried >= max_combos {
            warn!(
                max_combinations = max_combos,
                "combination cap reached, stopping reconstruction"
            );
        }

        // All combinations failed (or cap reached)
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
                let at_share_cap = self.shares.len() as u8 >= self.config.total_shares;
                if self.retry_attempts >= self.config.max_retries || at_share_cap {
                    self.state = SessionState::Failed;
                    if at_share_cap {
                        warn!(
                            attempts = self.retry_attempts,
                            shares = self.shares.len(),
                            total_shares = self.config.total_shares,
                            "all shares received but reconstruction failed, wiping"
                        );
                    } else {
                        warn!(
                            attempts = self.retry_attempts,
                            max = self.config.max_retries,
                            "max retries exhausted, wiping shares"
                        );
                    }
                    let attempts = self.retry_attempts;
                    self.reset();
                    DaemonMessage::QuorumReached {
                        action_result: ActionResult::Failure {
                            message: format!(
                                "Reconstruction failed after {} attempts, all shares wiped",
                                attempts
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

/// Lazy iterator over all k-sized combinations of indices 0..n.
/// Yields one combo at a time without pre-allocating all C(n,k) results.
struct ComboIter {
    indices: Vec<usize>,
    n: usize,
    k: usize,
    finished: bool,
}

impl ComboIter {
    fn new(n: usize, k: usize) -> Self {
        if k == 0 || k > n {
            return Self {
                indices: Vec::new(),
                n,
                k,
                finished: true,
            };
        }
        let indices: Vec<usize> = (0..k).collect();
        Self {
            indices,
            n,
            k,
            finished: false,
        }
    }
}

impl Iterator for ComboIter {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let result = self.indices.clone();

        // Advance to next combination
        let mut i = self.k;
        loop {
            if i == 0 {
                self.finished = true;
                break;
            }
            i -= 1;
            self.indices[i] += 1;
            if self.indices[i] <= self.n - self.k + i {
                // Fill remaining positions
                for j in (i + 1)..self.k {
                    self.indices[j] = self.indices[j - 1] + 1;
                }
                break;
            }
        }

        Some(result)
    }
}

/// Run the session task. This is the single owner of all secret material.
pub async fn run_session(
    mut rx: mpsc::Receiver<SessionCommand>,
    config: SessionConfig,
    action_config: ActionConfig,
    log_participation: bool,
    lockdown: bool,
    strict_hardening: bool,
) {
    let mut session = Session::new(config, action_config, log_participation, lockdown, strict_hardening);

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
    use blahaj::Sharks;

    fn make_shares(secret: &[u8], threshold: u8, n: u8) -> Vec<String> {
        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(secret);
        let shares: Vec<blahaj::Share> = dealer.take(n as usize).collect();
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
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Stdout,
            false,
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
    fn combo_iter_correctness() {
        let combos: Vec<_> = ComboIter::new(4, 2).collect();
        assert_eq!(combos.len(), 6); // C(4,2) = 6
        assert_eq!(combos[0], vec![0, 1]);
        assert_eq!(combos[5], vec![2, 3]);

        let combos: Vec<_> = ComboIter::new(3, 3).collect();
        assert_eq!(combos.len(), 1); // C(3,3) = 1
        assert_eq!(combos[0], vec![0, 1, 2]);

        let combos: Vec<_> = ComboIter::new(5, 3).collect();
        assert_eq!(combos.len(), 10); // C(5,3) = 10
    }

    #[test]
    fn combo_iter_edge_cases() {
        // k > n: no combos
        let combos: Vec<_> = ComboIter::new(2, 3).collect();
        assert!(combos.is_empty());

        // k == 0: no combos
        let combos: Vec<_> = ComboIter::new(3, 0).collect();
        assert!(combos.is_empty());

        // C(1,1) = 1
        let combos: Vec<_> = ComboIter::new(1, 1).collect();
        assert_eq!(combos, vec![vec![0]]);
    }

    #[test]
    fn combo_iter_respects_take_cap() {
        // C(10,3) = 120, but we cap at 5
        let combos: Vec<_> = ComboIter::new(10, 3).take(5).collect();
        assert_eq!(combos.len(), 5);
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
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
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
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
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
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
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

    /// Helper: generate shares from a secret with an embedded blake3 checksum,
    /// matching what keyquorum-split does by default.
    fn make_shares_with_checksum(secret: &[u8], threshold: u8, n: u8) -> Vec<String> {
        let mut payload = secret.to_vec();
        let hash = blake3::hash(&payload);
        payload.extend_from_slice(hash.as_bytes());
        make_shares(&payload, threshold, n)
    }

    #[tokio::test]
    async fn embedded_blake3_verifies_correct_secret() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::EmbeddedBlake3,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Stdout,
            false,
            false,
            false,
        );

        let shares = make_shares_with_checksum(b"verified-secret", 2, 3);

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
        match result.unwrap() {
            DaemonMessage::QuorumReached {
                action_result: ActionResult::Success { message },
            } => {
                assert!(
                    message.contains("stdout"),
                    "expected stdout success, got: {}",
                    message
                );
            }
            other => panic!(
                "expected success, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[tokio::test]
    async fn embedded_blake3_rejects_wrong_combo() {
        // 2-of-3 with checksum. Submit 2 valid + 1 corrupted share.
        // Corrupt one share by flipping payload bytes (not the index).
        // Combos with the corrupted share fail verification silently;
        // the valid combo succeeds.
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::EmbeddedBlake3,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Stdout,
            false,
            false,
            false,
        );

        let shares = make_shares_with_checksum(b"real-secret", 2, 3);
        let engine = base64::engine::general_purpose::STANDARD;

        // Submit first valid share
        session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });

        // Corrupt the second share: decode, flip some payload bytes, re-encode
        let mut bad_bytes = engine.decode(&shares[1]).unwrap();
        // Flip bytes in payload (skip index byte 0)
        for b in bad_bytes[1..].iter_mut().take(4) {
            *b ^= 0xFF;
        }
        let bad_share = engine.encode(&bad_bytes);

        session.submit_share(ShareSubmission {
            index: bad_bytes[0], // keep original index
            data: bad_share,
            submitted_by: None,
        });

        // Submit third valid share
        session.submit_share(ShareSubmission {
            index: share_index(&shares[2]),
            data: shares[2].clone(),
            submitted_by: None,
        });

        // With 3 shares and threshold 2, we get C(3,2) = 3 combos.
        // Combos involving the corrupted share fail verification.
        // The combo of shares[0] + shares[2] (both valid) should pass.
        let result = session.try_reconstruct().await;
        assert!(result.is_some());
        match result.unwrap() {
            DaemonMessage::QuorumReached {
                action_result: ActionResult::Success { message },
            } => {
                assert!(
                    message.contains("stdout"),
                    "expected stdout success, got: {}",
                    message
                );
            }
            other => panic!(
                "expected success (valid combo should verify), got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[tokio::test]
    async fn embedded_blake3_all_combos_fail_verification() {
        // All shares are from the same split, but we set verification to
        // embedded-blake3 on shares that DON'T have a checksum embedded.
        // Every combo should fail verification → reconstruction failure.
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::EmbeddedBlake3,
                max_combinations: 100,
                require_metadata: false,
            },
            // Use Command /bin/echo so we can detect if action runs unexpectedly
            ActionConfig::Command {
                program: "/bin/echo".to_string(),
                args: vec!["SHOULD-NOT-RUN".to_string()],
            },
            false,
            false,
            false,
        );

        // Shares WITHOUT checksum (as if generated with --no-checksum)
        let shares = make_shares(b"no-checksum-secret", 2, 3);

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
        match result.unwrap() {
            DaemonMessage::QuorumReached {
                action_result: ActionResult::Failure { message },
            } => {
                assert!(
                    message.contains("failed"),
                    "expected failure message, got: {}",
                    message
                );
            }
            other => panic!(
                "expected failure (no valid checksum), got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[tokio::test]
    async fn verification_none_passes_checksum_to_action() {
        // Shares generated with embedded checksum but daemon set to verification=none.
        // The action receives payload+checksum (41 bytes for "my-secret" + 32 hash).
        // With stdout action this "succeeds" but outputs the wrong thing.
        // With a real action this would cause consistent failures.
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Stdout,
            false,
            false,
            false,
        );

        let shares = make_shares_with_checksum(b"my-secret", 2, 3);

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

        // Stdout action always succeeds, but the secret it outputs includes
        // the checksum bytes — confirming the mismatch behavior.
        let result = session.try_reconstruct().await;
        assert!(result.is_some());
        match result.unwrap() {
            DaemonMessage::QuorumReached {
                action_result: ActionResult::Success { .. },
            } => {
                // Expected: stdout "succeeds" but with wrong content.
                // A real action (luks, command) would fail here.
            }
            other => panic!(
                "expected success (stdout always succeeds), got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[tokio::test]
    async fn max_combinations_cap_triggers_failure() {
        // Set max_combinations=1 with 3 shares and threshold 2 (C(3,2)=3 combos).
        // Only the first combo is tried; if it fails, reconstruction stops.
        // Use /bin/false so the action always fails.
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::None,
                max_combinations: 1,
                require_metadata: false,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
            false,
            false,
        );

        let shares = make_shares(b"cap-test", 2, 3);

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
        session.submit_share(ShareSubmission {
            index: share_index(&shares[2]),
            data: shares[2].clone(),
            submitted_by: None,
        });

        let result = session.try_reconstruct().await;
        assert!(result.is_some());
        match result.unwrap() {
            DaemonMessage::QuorumReached {
                action_result: ActionResult::Failure { message },
            } => {
                assert!(
                    message.contains("failed"),
                    "expected failure, got: {}",
                    message
                );
            }
            other => panic!(
                "expected failure (cap should limit combos), got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
        // Should have wiped (on_failure=wipe)
        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
    }

    #[tokio::test]
    async fn retry_at_total_shares_cap_forces_wipe() {
        // 2-of-2 with retry mode: all shares received but action fails.
        // Can't accept more shares (at total_shares cap), so retry should
        // force wipe instead of dead-ending in Collecting.
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 2,
                timeout_secs: 60,
                on_failure: OnFailure::Retry,
                max_retries: 5, // plenty of retries left
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Command {
                program: "/bin/false".to_string(),
                args: vec![],
            },
            false,
            false,
            false,
        );

        let shares = make_shares(b"cap-retry", 2, 2);

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
        match result.unwrap() {
            DaemonMessage::QuorumReached {
                action_result: ActionResult::Failure { message },
            } => {
                assert!(
                    message.contains("wiped"),
                    "expected wipe message, got: {}",
                    message
                );
            }
            other => panic!(
                "expected failure+wipe, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
        // Must have wiped, not returned to Collecting
        assert_eq!(session.state, SessionState::Idle);
        assert!(session.shares.is_empty());
    }

    #[test]
    fn strict_hardening_rejects_share_on_protect_failure() {
        // With strict_hardening, if protect_secret fails, the share should be rejected.
        // We can't easily force mlock to fail in test, but we verify the strict_hardening
        // flag is plumbed to the session and the code path handles both outcomes.
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: false,
            },
            ActionConfig::Stdout,
            false,
            true,  // lockdown enabled
            true,  // strict_hardening (implied by lockdown)
        );

        assert!(session.strict_hardening);

        let shares = make_shares(b"lockdown-test", 2, 3);

        // Submit should succeed if mlock works (running as root),
        // or be rejected if mlock fails (lockdown hard-fail).
        let result = session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });

        match result {
            DaemonMessage::ShareAccepted { .. } => {
                // mlock succeeded as root — share accepted, strict_hardening didn't trigger
                assert_eq!(session.shares.len(), 1);
            }
            DaemonMessage::ShareRejected { reason } => {
                // mlock failed — strict_hardening correctly rejected
                assert!(
                    reason.contains("strict_hardening"),
                    "expected strict_hardening rejection, got: {}",
                    reason
                );
                assert!(session.shares.is_empty());
            }
            other => panic!(
                "unexpected response: {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    /// Helper: format raw sharks share bytes as a v1 share with given options.
    fn make_v1_share(
        sharks_data: &[u8],
        include_crc32: bool,
        include_envelope: bool,
        include_metadata: bool,
        share_number: u8,
        total_shares: u8,
        threshold: u8,
    ) -> String {
        use keyquorum_core::share_format::{ShareEncoding, ShareFormatOptions};
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base64,
            include_crc32,
            include_envelope,
            include_metadata,
            share_number,
            total_shares,
            threshold,
        };
        keyquorum_core::share_format::format_share(sharks_data, &opts)
    }

    /// Helper: generate shares and format them as v1 shares with envelopes.
    fn make_v1_shares(
        secret: &[u8],
        threshold: u8,
        total: u8,
    ) -> Vec<(u8, String)> {
        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(secret);
        let shares: Vec<blahaj::Share> = dealer.take(total as usize).collect();
        shares
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let bytes: Vec<u8> = Vec::from(s);
                let index = bytes[0];
                let formatted = make_v1_share(
                    &bytes, true, true, true,
                    (i + 1) as u8, total, threshold,
                );
                (index, formatted)
            })
            .collect()
    }

    #[test]
    fn v1_share_accepted() {
        let mut session = make_test_session(2, 3);
        let shares = make_v1_shares(b"v1-test", 2, 3);

        let response = session.submit_share(ShareSubmission {
            index: shares[0].0,
            data: shares[0].1.clone(),
            submitted_by: None,
        });

        assert!(
            matches!(response, DaemonMessage::ShareAccepted { .. }),
            "expected ShareAccepted, got {:?}",
            serde_json::to_string(&response).unwrap()
        );
        assert_eq!(session.shares.len(), 1);
    }

    #[test]
    fn legacy_share_still_accepted() {
        // Legacy = raw base64 sharks data, no KQ prefix
        let mut session = make_test_session(2, 3);
        let shares = make_shares(b"legacy-test", 2, 3);

        let response = session.submit_share(ShareSubmission {
            index: share_index(&shares[0]),
            data: shares[0].clone(),
            submitted_by: None,
        });

        assert!(matches!(response, DaemonMessage::ShareAccepted { .. }));
        assert_eq!(session.shares.len(), 1);
    }

    #[test]
    fn require_metadata_rejects_bare() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: true,
            },
            ActionConfig::Stdout,
            false,
            false,
            false,
        );

        // Submit a bare v1 share (no envelope)
        let shares_raw = make_shares(b"metadata-test", 2, 3);
        let response = session.submit_share(ShareSubmission {
            index: share_index(&shares_raw[0]),
            data: shares_raw[0].clone(),
            submitted_by: None,
        });

        match response {
            DaemonMessage::ShareRejected { reason } => {
                assert!(
                    reason.contains("metadata") || reason.contains("envelope"),
                    "expected metadata rejection, got: {}",
                    reason
                );
            }
            other => panic!(
                "expected ShareRejected, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[test]
    fn require_metadata_accepts_envelope() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: true,
            },
            ActionConfig::Stdout,
            false,
            false,
            false,
        );

        let shares = make_v1_shares(b"envelope-test", 2, 3);
        let response = session.submit_share(ShareSubmission {
            index: shares[0].0,
            data: shares[0].1.clone(),
            submitted_by: None,
        });

        assert!(
            matches!(response, DaemonMessage::ShareAccepted { .. }),
            "expected ShareAccepted, got {:?}",
            serde_json::to_string(&response).unwrap()
        );
    }

    #[test]
    fn require_metadata_rejects_wrong_threshold() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 3,
                total_shares: 5,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: true,
            },
            ActionConfig::Stdout,
            false,
            false,
            false,
        );

        // Generate shares with threshold=2 but daemon expects threshold=3
        let shares = make_v1_shares(b"mismatch-test", 2, 5);
        let response = session.submit_share(ShareSubmission {
            index: shares[0].0,
            data: shares[0].1.clone(),
            submitted_by: None,
        });

        match response {
            DaemonMessage::ShareRejected { reason } => {
                assert!(
                    reason.contains("mismatch") || reason.contains("metadata"),
                    "expected metadata mismatch, got: {}",
                    reason
                );
            }
            other => panic!(
                "expected ShareRejected, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[test]
    fn require_metadata_rejects_partial_headers() {
        let mut session = Session::new(
            SessionConfig {
                threshold: 2,
                total_shares: 3,
                timeout_secs: 60,
                on_failure: OnFailure::Wipe,
                max_retries: 3,
                verification: Verification::None,
                max_combinations: 100,
                require_metadata: true,
            },
            ActionConfig::Stdout,
            false,
            false,
            false,
        );

        // Craft an envelope with only Scheme: header (no Share: header)
        let shares_raw = make_shares(b"partial-meta", 2, 3);
        let engine = base64::engine::general_purpose::STANDARD;
        let sharks_data = engine.decode(&shares_raw[0]).unwrap();
        let index = sharks_data[0];
        let binary = keyquorum_core::share_format::encode_v1(&sharks_data, true);
        let encoded = engine.encode(&binary);
        let envelope = format!(
            "KEYQUORUM-SHARE-V1\nScheme: shamir-gf256\n\n{}",
            encoded,
        );

        let response = session.submit_share(ShareSubmission {
            index,
            data: envelope,
            submitted_by: None,
        });

        match response {
            DaemonMessage::ShareRejected { reason } => {
                assert!(
                    reason.contains("metadata") || reason.contains("require_metadata"),
                    "expected metadata rejection for partial headers, got: {}",
                    reason
                );
            }
            other => panic!(
                "expected ShareRejected, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[test]
    fn crc32_corrupt_share_rejected() {
        let mut session = make_test_session(2, 3);
        let shares = make_v1_shares(b"crc-test", 2, 3);

        // Corrupt the payload in the v1 share: find the base64 payload
        // and flip a character
        let mut corrupted = shares[0].1.clone();
        // Find the last line (payload) and corrupt it
        if let Some(pos) = corrupted.rfind('=') {
            // Replace = with A to corrupt base64 payload
            corrupted.replace_range(pos..pos + 1, "Z");
        } else {
            // Just corrupt a character near the end
            let len = corrupted.len();
            corrupted.replace_range(len - 3..len - 2, "Z");
        }

        let response = session.submit_share(ShareSubmission {
            index: shares[0].0,
            data: corrupted,
            submitted_by: None,
        });

        assert!(
            matches!(response, DaemonMessage::ShareRejected { .. }),
            "expected rejection for corrupted CRC, got {:?}",
            serde_json::to_string(&response).unwrap()
        );
    }

    #[test]
    fn base32_share_accepted() {
        use keyquorum_core::share_format::{ShareEncoding, ShareFormatOptions};

        let mut session = make_test_session(2, 3);
        let sharks_instance = Sharks(2);
        let dealer = sharks_instance.dealer(b"base32-test");
        let shares: Vec<blahaj::Share> = dealer.take(3).collect();

        let bytes: Vec<u8> = Vec::from(&shares[0]);
        let index = bytes[0];
        let opts = ShareFormatOptions {
            encoding: ShareEncoding::Base32,
            include_crc32: true,
            include_envelope: false,
            include_metadata: false,
            share_number: 1,
            total_shares: 3,
            threshold: 2,
        };
        let formatted = keyquorum_core::share_format::format_share(&bytes, &opts);

        let response = session.submit_share(ShareSubmission {
            index,
            data: formatted,
            submitted_by: None,
        });

        assert!(
            matches!(response, DaemonMessage::ShareAccepted { .. }),
            "expected ShareAccepted for base32 share, got {:?}",
            serde_json::to_string(&response).unwrap()
        );
    }
}
