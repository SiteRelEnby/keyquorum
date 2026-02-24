use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A share submitted by a participant, safe for transport over the wire.
/// The `data` field is base64-encoded raw share bytes from sharks::Share.
/// The first byte of the decoded data is the x-coordinate (index).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ShareSubmission {
    /// Share index (x-coordinate from sharks), 1..=255
    #[zeroize(skip)]
    pub index: u8,
    /// Base64-encoded share bytes
    pub data: String,
    /// Optional identifier of who submitted (for participation logging)
    #[zeroize(skip)]
    pub submitted_by: Option<String>,
}

/// Current session status, sent to clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStatus {
    pub state: SessionState,
    pub threshold: u8,
    pub shares_received: u8,
    pub shares_needed: u8,
    pub timeout_secs: u64,
    pub elapsed_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Collecting,
    Reconstructing,
    Completed,
    TimedOut,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_submission_serde_roundtrip() {
        let share = ShareSubmission {
            index: 42,
            data: "dGVzdA==".to_string(),
            submitted_by: Some("alice".to_string()),
        };
        let json = serde_json::to_string(&share).unwrap();
        let deserialized: ShareSubmission = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.index, 42);
        assert_eq!(deserialized.data, "dGVzdA==");
        assert_eq!(deserialized.submitted_by.as_deref(), Some("alice"));
    }

    #[test]
    fn share_submission_without_user() {
        let share = ShareSubmission {
            index: 1,
            data: "AQID".to_string(),
            submitted_by: None,
        };
        let json = serde_json::to_string(&share).unwrap();
        let deserialized: ShareSubmission = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.index, 1);
        assert!(deserialized.submitted_by.is_none());
    }

    #[test]
    fn session_status_serde_roundtrip() {
        let status = SessionStatus {
            state: SessionState::Collecting,
            threshold: 3,
            shares_received: 2,
            shares_needed: 1,
            timeout_secs: 1800,
            elapsed_secs: 45,
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: SessionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.state, SessionState::Collecting);
        assert_eq!(deserialized.shares_received, 2);
        assert_eq!(deserialized.shares_needed, 1);
    }

    #[test]
    fn session_states_serialize_correctly() {
        let states = vec![
            SessionState::Idle,
            SessionState::Collecting,
            SessionState::Reconstructing,
            SessionState::Completed,
            SessionState::TimedOut,
            SessionState::Failed,
        ];
        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: SessionState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, state);
        }
    }
}
