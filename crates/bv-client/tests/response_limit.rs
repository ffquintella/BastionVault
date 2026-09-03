//! Response-body size limit on the `RemoteBackend` read path.
//!
//! Regression cover for the recording-replay failure: the GUI fetches
//! `rustion/recordings/<id>/blob`, which returns the artifact base64-
//! wrapped inside the JSON envelope, so a 17.8 MB recording arrives as
//! ~23.7 MB of body. `Body::read_to_vec()` caps reads at ureq's 10 MB
//! default, so the fetch failed with "the response body is larger than
//! request limit: 10485760" — and, because that surfaced as a bare
//! transport error, it was classified as `NodeUnavailable` and re-tried
//! against a second node, which failed identically.
//!
//! Same hand-rolled HTTP framer approach as
//! `cluster_discovery_e2e.rs`: no extra dev-deps, just `std::net`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bv_client::error::ClientError;
use bv_client::health::HealthConfig;
use bv_client::{Backend, Operation, RemoteBackend};

/// A node that answers `sys/health` as a healthy leader and every
/// other path with a JSON body of `payload_bytes` base64-ish filler —
/// standing in for a recording blob.
struct BigBodyNode {
    port: u16,
    /// Non-health requests served, so a test can prove no retry happened.
    payload_requests: Arc<AtomicUsize>,
    _join: thread::JoinHandle<()>,
}

impl BigBodyNode {
    fn spawn(payload_bytes: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let payload_requests = Arc::new(AtomicUsize::new(0));
        let counter = payload_requests.clone();
        let join = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let req = read_request_line(&mut stream);
                let body = if req.contains("sys/health") {
                    r#"{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"cluster_id":"cid","version":"test-0.0.0"}"#.to_string()
                } else {
                    counter.fetch_add(1, Ordering::SeqCst);
                    format!(r#"{{"data":{{"bytes_b64":"{}"}}}}"#, "A".repeat(payload_bytes))
                };
                respond(&mut stream, &body);
            }
        });
        BigBodyNode { port, payload_requests, _join: join }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// A node that only ever answers `sys/health` as a healthy follower.
/// Used as the failover target that must *not* be dialed.
struct FollowerNode {
    port: u16,
    _join: thread::JoinHandle<()>,
}

impl FollowerNode {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = read_request_line(&mut stream);
                respond(
                    &mut stream,
                    r#"{"initialized":true,"sealed":false,"standby":true,"performance_standby":false,"cluster_id":"cid","version":"test-0.0.0"}"#,
                );
            }
        });
        FollowerNode { port, _join: join }
    }
}

fn read_request_line(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).to_string()
}

fn respond(stream: &mut TcpStream, body: &str) {
    // Generous write timeout: the multi-megabyte payload is several
    // socket writes even over loopback.
    let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn health_cfg() -> HealthConfig {
    HealthConfig { probe_timeout: Duration::from_millis(800), parallelism: 4, use_system_proxy: false }
}

/// 11 MiB of payload — over ureq's 10 MB `read_to_vec()` default, well
/// under our own. This is the read that used to fail.
#[tokio::test]
async fn read_larger_than_ureq_default_limit_succeeds() {
    let node = BigBodyNode::spawn(11 * 1024 * 1024);
    let be = RemoteBackend::builder().with_address(node.url()).with_cluster_discovery(false).build();

    let resp = be
        .handle(Operation::Read, "rustion/recordings/rec_test/blob", None, "tok")
        .await
        .expect("an 11 MiB body must be readable")
        .expect("body carries a data payload");
    let data = resp.data.expect("data");
    assert_eq!(
        data.get("bytes_b64").and_then(|v| v.as_str()).map(str::len),
        Some(11 * 1024 * 1024)
    );
}

/// Over the configured limit: a named, non-retryable error. The point
/// is what it is *not* — `NodeUnavailable`, which would strand the
/// session behind a spurious "node is unavailable" reconnect prompt.
#[tokio::test]
async fn read_over_configured_limit_reports_response_too_large() {
    let node = BigBodyNode::spawn(2 * 1024 * 1024);
    let be = RemoteBackend::builder()
        .with_address(node.url())
        .with_cluster_discovery(false)
        .with_max_response_bytes(1024 * 1024)
        .build();

    let err = be
        .handle(Operation::Read, "rustion/recordings/rec_test/blob", None, "tok")
        .await
        .expect_err("a body over the limit must error");
    assert!(err.is_response_too_large(), "expected ResponseTooLarge, got {err}");
    assert!(!err.is_node_unavailable(), "an oversized body is not a node failure: {err}");
    assert!(
        matches!(err, ClientError::ResponseTooLarge { limit } if limit == 1024 * 1024),
        "error must name the configured limit"
    );
}

/// An oversized body must not engage in-session read failover: the
/// sibling node would return the same too-large body, so retrying only
/// doubles the transfer and moves the session for no reason.
#[tokio::test]
async fn oversized_body_does_not_fail_over() {
    let big = BigBodyNode::spawn(2 * 1024 * 1024);
    let follower = FollowerNode::spawn();
    let big_url = big.url();

    let be = RemoteBackend::builder()
        .with_address(&big_url)
        .with_cluster_discovery(false)
        .with_max_response_bytes(1024 * 1024)
        .with_health_config(health_cfg())
        .with_failover_candidates(vec![
            bv_client::discovery::SrvCandidate {
                target: "127.0.0.1".to_string(),
                port: big.port,
                scheme: "http".to_string(),
                priority: 10,
                weight: 50,
            },
            bv_client::discovery::SrvCandidate {
                target: "127.0.0.1".to_string(),
                port: follower.port,
                scheme: "http".to_string(),
                priority: 10,
                weight: 50,
            },
        ])
        .build();

    let err = be
        .handle(Operation::Read, "rustion/recordings/rec_test/blob", None, "tok")
        .await
        .expect_err("a body over the limit must error");
    assert!(err.is_response_too_large(), "expected ResponseTooLarge, got {err}");
    assert_eq!(be.address(), big_url, "the session must stay pinned to the node it asked");
    assert_eq!(
        big.payload_requests.load(Ordering::SeqCst),
        1,
        "the oversized read must be attempted exactly once"
    );
}
