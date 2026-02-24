use serde::{Deserialize, Serialize};

use crate::types::{SessionStatus, ShareSubmission};

/// Messages sent from client to daemon (newline-delimited JSON).
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "submit_share")]
    SubmitShare { share: ShareSubmission },
    #[serde(rename = "status")]
    Status,
}

/// Messages sent from daemon to client (newline-delimited JSON).
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonMessage {
    #[serde(rename = "share_accepted")]
    ShareAccepted { status: SessionStatus },
    #[serde(rename = "share_rejected")]
    ShareRejected { reason: String },
    #[serde(rename = "status")]
    Status { status: SessionStatus },
    #[serde(rename = "quorum_reached")]
    QuorumReached { action_result: ActionResult },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "result")]
pub enum ActionResult {
    #[serde(rename = "success")]
    Success { message: String },
    #[serde(rename = "failure")]
    Failure { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SessionState, SessionStatus, ShareSubmission};

    #[test]
    fn submit_share_message_roundtrip() {
        let msg = ClientMessage::SubmitShare {
            share: ShareSubmission {
                index: 3,
                data: "AwECAw==".to_string(),
                submitted_by: Some("alice".to_string()),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"submit_share""#));
        let deserialized: ClientMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            ClientMessage::SubmitShare { share } => {
                assert_eq!(share.index, 3);
                assert_eq!(share.data, "AwECAw==");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn status_message_roundtrip() {
        let msg = ClientMessage::Status;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"status""#));
        let deserialized: ClientMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, ClientMessage::Status));
    }

    #[test]
    fn share_accepted_response() {
        let msg = DaemonMessage::ShareAccepted {
            status: SessionStatus {
                state: SessionState::Collecting,
                threshold: 3,
                shares_received: 2,
                shares_needed: 1,
                timeout_secs: 1800,
                elapsed_secs: 45,
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"share_accepted""#));
        let deserialized: DaemonMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            DaemonMessage::ShareAccepted { status } => {
                assert_eq!(status.shares_received, 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn share_rejected_response() {
        let msg = DaemonMessage::ShareRejected {
            reason: "Duplicate share index".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: DaemonMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            DaemonMessage::ShareRejected { reason } => {
                assert_eq!(reason, "Duplicate share index");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn quorum_reached_success() {
        let msg = DaemonMessage::QuorumReached {
            action_result: ActionResult::Success {
                message: "LUKS device unlocked".to_string(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"quorum_reached""#));
        let deserialized: DaemonMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            DaemonMessage::QuorumReached { action_result } => match action_result {
                ActionResult::Success { message } => {
                    assert_eq!(message, "LUKS device unlocked");
                }
                _ => panic!("wrong action result"),
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_response() {
        let msg = DaemonMessage::Error {
            message: "Session timed out".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: DaemonMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            DaemonMessage::Error { message } => {
                assert_eq!(message, "Session timed out");
            }
            _ => panic!("wrong variant"),
        }
    }
}
