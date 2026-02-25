use std::path::PathBuf;

use base64::Engine;
use sharks::Sharks;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use keyquorum_core::config::{ActionConfig, OnFailure, SessionConfig};
use keyquorum_core::protocol::{ActionResult, ClientMessage, DaemonMessage};
use keyquorum_core::types::ShareSubmission;

// Re-use internal handler and session via the binary crate
use keyquorum::daemon::handler::handle_connection;
use keyquorum::daemon::session::{run_session, SessionCommand};

/// Generate N shares from a secret with the given threshold.
fn make_shares(secret: &[u8], threshold: u8, n: u8) -> Vec<(u8, String)> {
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    let shares: Vec<sharks::Share> = dealer.take(n as usize).collect();
    let engine = base64::engine::general_purpose::STANDARD;
    shares
        .iter()
        .map(|s| {
            let bytes = Vec::<u8>::from(s);
            let index = bytes[0];
            (index, engine.encode(&bytes))
        })
        .collect()
}

/// Spin up a session task + Unix socket listener, returning the socket path
/// and a handle to shut things down.
struct TestDaemon {
    socket_path: PathBuf,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl TestDaemon {
    async fn start(threshold: u8, total: u8, timeout_secs: u64) -> Self {
        let dir = std::env::temp_dir().join(format!("kq-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join(format!("test-{}.sock", rand_suffix()));

        // Clean up stale socket if exists
        let _ = std::fs::remove_file(&socket_path);

        let (session_tx, session_rx) = mpsc::channel::<SessionCommand>(32);

        let session_config = SessionConfig {
            threshold,
            total_shares: total,
            timeout_secs,
            on_failure: OnFailure::Wipe,
            max_retries: 3,
        };
        let action_config = ActionConfig::Stdout;

        // Spawn session task
        let session_handle = tokio::spawn(async move {
            run_session(session_rx, session_config, action_config, false, false).await;
        });

        // Spawn listener task
        let listener = UnixListener::bind(&socket_path).unwrap();
        let listener_handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let tx = session_tx.clone();
                tokio::spawn(async move {
                    let (reader, writer) = tokio::io::split(stream);
                    handle_connection(reader, writer, tx).await;
                });
            }
        });

        TestDaemon {
            socket_path,
            _tasks: vec![session_handle, listener_handle],
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn rand_suffix() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Send a JSON message over a Unix stream and read the response.
async fn send_message(stream: &mut UnixStream, msg: &ClientMessage) -> DaemonMessage {
    let mut json = serde_json::to_string(msg).unwrap();
    json.push('\n');
    stream.write_all(json.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    // We need to read from the stream without consuming it for future writes.
    // Use a small buffer to read one line.
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.readable().await.unwrap();
        match tokio::io::AsyncReadExt::read(stream, &mut byte).await {
            Ok(1) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            _ => panic!("unexpected EOF or error reading response"),
        }
    }
    serde_json::from_slice(&buf).unwrap()
}

/// Submit a share and return the daemon response.
async fn submit_share(
    stream: &mut UnixStream,
    index: u8,
    data: &str,
    user: Option<&str>,
) -> DaemonMessage {
    let msg = ClientMessage::SubmitShare {
        share: ShareSubmission {
            index,
            data: data.to_string(),
            submitted_by: user.map(|s| s.to_string()),
        },
    };
    send_message(stream, &msg).await
}

async fn query_status(stream: &mut UnixStream) -> DaemonMessage {
    send_message(stream, &ClientMessage::Status).await
}

#[tokio::test]
async fn full_quorum_returns_action_result() {
    let daemon = TestDaemon::start(2, 3, 60).await;
    let shares = make_shares(b"integration-secret", 2, 3);

    // First share — accepted
    let mut conn1 = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn1, shares[0].0, &shares[0].1, Some("alice")).await;
    match resp {
        DaemonMessage::ShareAccepted { status } => {
            assert_eq!(status.shares_received, 1);
            assert_eq!(status.shares_needed, 1);
        }
        other => panic!("expected ShareAccepted, got {:?}", serde_json::to_string(&other).unwrap()),
    }

    // Second share — quorum reached, should get action result
    let mut conn2 = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn2, shares[1].0, &shares[1].1, Some("bob")).await;
    match resp {
        DaemonMessage::QuorumReached { action_result } => {
            assert!(
                matches!(action_result, ActionResult::Success { .. }),
                "expected success, got {:?}",
                action_result
            );
        }
        other => panic!(
            "expected QuorumReached, got {:?}",
            serde_json::to_string(&other).unwrap()
        ),
    }
}

#[tokio::test]
async fn status_query_reflects_session_state() {
    let daemon = TestDaemon::start(3, 5, 60).await;
    let shares = make_shares(b"status-test", 3, 5);

    // Status before any shares — idle
    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = query_status(&mut conn).await;
    match resp {
        DaemonMessage::Status { status } => {
            assert_eq!(status.shares_received, 0);
            assert_eq!(status.shares_needed, 3);
        }
        other => panic!("expected Status, got {:?}", serde_json::to_string(&other).unwrap()),
    }

    // Submit one share
    let mut conn2 = UnixStream::connect(&daemon.socket_path).await.unwrap();
    submit_share(&mut conn2, shares[0].0, &shares[0].1, None).await;

    // Status after one share — collecting
    let mut conn3 = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = query_status(&mut conn3).await;
    match resp {
        DaemonMessage::Status { status } => {
            assert_eq!(status.shares_received, 1);
            assert_eq!(status.shares_needed, 2);
        }
        other => panic!("expected Status, got {:?}", serde_json::to_string(&other).unwrap()),
    }
}

#[tokio::test]
async fn duplicate_share_rejected_over_socket() {
    let daemon = TestDaemon::start(3, 5, 60).await;
    let shares = make_shares(b"dup-test", 3, 5);

    // Submit share
    let mut conn1 = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn1, shares[0].0, &shares[0].1, None).await;
    assert!(matches!(resp, DaemonMessage::ShareAccepted { .. }));

    // Submit same index again (different connection)
    let mut conn2 = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn2, shares[0].0, &shares[0].1, None).await;
    match resp {
        DaemonMessage::ShareRejected { reason } => {
            assert!(reason.contains("already submitted"), "reason: {}", reason);
        }
        other => panic!(
            "expected ShareRejected, got {:?}",
            serde_json::to_string(&other).unwrap()
        ),
    }
}

#[tokio::test]
async fn invalid_json_returns_error() {
    let daemon = TestDaemon::start(2, 3, 60).await;

    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();

    // Send garbage
    conn.write_all(b"this is not json\n").await.unwrap();
    conn.flush().await.unwrap();

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        conn.readable().await.unwrap();
        match tokio::io::AsyncReadExt::read(&mut conn, &mut byte).await {
            Ok(1) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            _ => panic!("unexpected EOF"),
        }
    }
    let resp: DaemonMessage = serde_json::from_slice(&buf).unwrap();
    assert!(matches!(resp, DaemonMessage::Error { .. }));
}

#[tokio::test]
async fn session_resets_after_quorum_allows_new_round() {
    let daemon = TestDaemon::start(2, 3, 60).await;

    // --- Round 1 ---
    let shares1 = make_shares(b"round-one", 2, 3);

    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();
    submit_share(&mut conn, shares1[0].0, &shares1[0].1, None).await;

    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn, shares1[1].0, &shares1[1].1, None).await;
    assert!(matches!(resp, DaemonMessage::QuorumReached { .. }));

    // --- Round 2 (session should have reset back to Idle) ---
    let shares2 = make_shares(b"round-two", 2, 3);

    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn, shares2[0].0, &shares2[0].1, None).await;
    match resp {
        DaemonMessage::ShareAccepted { status } => {
            assert_eq!(status.shares_received, 1);
        }
        other => panic!(
            "expected ShareAccepted for round 2, got {:?}",
            serde_json::to_string(&other).unwrap()
        ),
    }

    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn, shares2[1].0, &shares2[1].1, None).await;
    assert!(matches!(resp, DaemonMessage::QuorumReached { .. }));
}

#[tokio::test]
async fn multiple_messages_on_same_connection() {
    let daemon = TestDaemon::start(3, 5, 60).await;
    let shares = make_shares(b"multi-msg", 3, 5);

    // Single connection, multiple messages
    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();

    // Status query
    let resp = query_status(&mut conn).await;
    assert!(matches!(resp, DaemonMessage::Status { .. }));

    // Submit a share on the same connection
    let resp = submit_share(&mut conn, shares[0].0, &shares[0].1, None).await;
    assert!(matches!(resp, DaemonMessage::ShareAccepted { .. }));

    // Another status query on the same connection
    let resp = query_status(&mut conn).await;
    match resp {
        DaemonMessage::Status { status } => {
            assert_eq!(status.shares_received, 1);
        }
        other => panic!("expected Status, got {:?}", serde_json::to_string(&other).unwrap()),
    }
}

#[tokio::test]
async fn oversized_message_disconnects() {
    let daemon = TestDaemon::start(2, 3, 60).await;

    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();

    // Send a line larger than 64 KB
    let huge = "x".repeat(70 * 1024);
    conn.write_all(huge.as_bytes()).await.unwrap();
    conn.write_all(b"\n").await.unwrap();
    conn.flush().await.unwrap();

    // The daemon should send an error and close the connection
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tokio::io::AsyncReadExt::read(&mut conn, &mut byte).await {
            Ok(0) => break, // EOF — connection closed
            Ok(1) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            _ => break,
        }
    }

    // Should get an error message about size, or connection should be closed
    if !buf.is_empty() {
        let resp: DaemonMessage = serde_json::from_slice(&buf).unwrap();
        match resp {
            DaemonMessage::Error { message } => {
                assert!(
                    message.contains("maximum size"),
                    "error should mention size limit: {}",
                    message
                );
            }
            other => panic!(
                "expected Error, got {:?}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }
    // Either way, connection should be closed after this
}

#[tokio::test]
async fn index_mismatch_rejected_over_socket() {
    let daemon = TestDaemon::start(3, 5, 60).await;
    let shares = make_shares(b"mismatch-test", 3, 5);

    let actual_index = shares[0].0;
    let wrong_index = actual_index.wrapping_add(1);

    let mut conn = UnixStream::connect(&daemon.socket_path).await.unwrap();
    let resp = submit_share(&mut conn, wrong_index, &shares[0].1, None).await;
    match resp {
        DaemonMessage::ShareRejected { reason } => {
            assert!(reason.contains("mismatch"), "reason: {}", reason);
        }
        other => panic!(
            "expected ShareRejected, got {:?}",
            serde_json::to_string(&other).unwrap()
        ),
    }
}
