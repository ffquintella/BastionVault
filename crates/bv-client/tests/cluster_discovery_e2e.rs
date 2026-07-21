//! Integration tests for the cluster-discovery pipeline.
//!
//! Spins up tiny in-process HTTP listeners that play the role of
//! BastionVault nodes — each responds to `/v1/sys/health` with a
//! configurable JSON body so we can simulate leader / follower /
//! sealed states without standing up a real Hiqlite cluster.
//!
//! Compared to `tests/hiqlite_ha_fault_injection.rs` (which drives
//! the storage layer directly and never speaks HTTP), this test
//! exercises the *client-side* path the feature is about:
//! `discovery::resolve` → `health::probe_all` → `health::pick`. No
//! extra dev-deps; just `std::net` + a hand-rolled HTTP framer.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use bv_client::discovery::{self, DiscoveryConfig, SrvCandidate, SrvLookup, SrvRecord};
use bv_client::error::ClientError;
use bv_client::health::{self, HealthConfig, NodeState};
use bv_client::{Backend, Operation, RemoteBackend};

/// Behaviour of one fake node. Encoded as JSON the server writes
/// back on every `/v1/sys/health` request — the surrounding harness
/// can flip an `Arc<Mutex<NodeBehavior>>` mid-test to simulate a
/// state transition (e.g. a leader sealing itself).
#[derive(Clone)]
struct NodeBehavior {
    body: String,
    /// Optional delay before responding — used to test RTT-based
    /// tie-breaking. `None` → respond as fast as possible.
    delay: Option<Duration>,
    /// When `true`, the listener accepts the TCP connection and
    /// immediately drops it. The bv-client probe then surfaces
    /// `NodeState::Unreachable`.
    drop_connection: bool,
}

impl NodeBehavior {
    fn leader(cluster_id: &str) -> Self {
        Self {
            body: format!(
                r#"{{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"cluster_id":"{cluster_id}","version":"test-0.0.0"}}"#
            ),
            delay: None,
            drop_connection: false,
        }
    }
    fn follower(cluster_id: &str) -> Self {
        Self {
            body: format!(
                r#"{{"initialized":true,"sealed":false,"standby":true,"performance_standby":false,"cluster_id":"{cluster_id}","version":"test-0.0.0"}}"#
            ),
            delay: None,
            drop_connection: false,
        }
    }
    fn sealed() -> Self {
        Self {
            body: r#"{"initialized":true,"sealed":true}"#.to_string(),
            delay: None,
            drop_connection: false,
        }
    }
    fn dead() -> Self {
        Self {
            body: String::new(),
            delay: None,
            drop_connection: true,
        }
    }
    fn slow_leader(cluster_id: &str, delay: Duration) -> Self {
        let mut n = Self::leader(cluster_id);
        n.delay = Some(delay);
        n
    }
}

/// One running fake node.
struct FakeNode {
    port: u16,
    behavior: Arc<Mutex<NodeBehavior>>,
    _join: thread::JoinHandle<()>,
}

impl FakeNode {
    fn spawn(initial: NodeBehavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let behavior = Arc::new(Mutex::new(initial));
        let b = behavior.clone();
        let join = thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let snapshot = b.lock().unwrap().clone();
                if snapshot.drop_connection {
                    drop(stream);
                    continue;
                }
                if let Some(d) = snapshot.delay {
                    thread::sleep(d);
                }
                handle(&mut stream, &snapshot.body);
            }
        });
        FakeNode { port, behavior, _join: join }
    }

    fn set(&self, b: NodeBehavior) {
        *self.behavior.lock().unwrap() = b;
    }
}

/// Minimal HTTP/1.1 framer — read the request (we ignore it), write
/// back a 200 with the configured JSON body. `Content-Length` is
/// computed up front so the body parser on the client side doesn't
/// hang waiting for EOF.
fn handle(stream: &mut TcpStream, body: &str) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    // Drain the request so the client gets a clean close after our
    // response — we don't actually inspect anything in it.
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

/// Resolver that returns a fixed list of records. Used as the seam
/// so the test doesn't need a real DNS server.
struct CannedResolver {
    records: Vec<SrvRecord>,
}

#[async_trait]
impl SrvLookup for CannedResolver {
    async fn lookup_srv(&self, _label: &str) -> Result<Vec<SrvRecord>, ClientError> {
        Ok(self.records.clone())
    }
}

fn record_for(node: &FakeNode, priority: u16, weight: u16) -> SrvRecord {
    SrvRecord {
        target: "127.0.0.1".to_string(),
        port: node.port,
        priority,
        weight,
    }
}

fn cand_for(node: &FakeNode, priority: u16, weight: u16) -> SrvCandidate {
    SrvCandidate {
        target: "127.0.0.1".to_string(),
        port: node.port,
        scheme: "http".to_string(),
        priority,
        weight,
    }
}

fn health_cfg() -> HealthConfig {
    HealthConfig {
        // Generous enough that the cargo test runner under load
        // still finishes the request before we declare a node
        // unreachable, but short enough that an unreachable node
        // doesn't slow the suite down.
        probe_timeout: Duration::from_millis(800),
        parallelism: 4,
        use_system_proxy: false,
    }
}

// -------------------------------------------------------------------

#[tokio::test]
async fn discovery_picks_leader_among_healthy_nodes() {
    let leader = FakeNode::spawn(NodeBehavior::leader("cid"));
    let follower1 = FakeNode::spawn(NodeBehavior::follower("cid"));
    let follower2 = FakeNode::spawn(NodeBehavior::follower("cid"));

    let resolver = CannedResolver {
        records: vec![
            record_for(&leader, 10, 50),
            record_for(&follower1, 10, 50),
            record_for(&follower2, 10, 50),
        ],
    };

    // Tell `discovery::resolve` to use `http://` so the probe
    // listeners don't have to terminate TLS.
    let cfg = DiscoveryConfig {
        default_scheme: "http".to_string(),
        ..Default::default()
    };
    let resolved = discovery::resolve("vault.test.local", &cfg, &resolver)
        .await
        .unwrap();
    let candidates: Vec<SrvCandidate> = resolved.into_candidates();

    let probes = health::probe_all(&candidates, &health_cfg(), None).await;
    let picked = health::pick(&probes).expect("at least one healthy node");
    assert_eq!(picked.candidate.port, leader.port);
    assert!(matches!(picked.state, NodeState::ActiveLeader));
}

#[tokio::test]
async fn discovery_respects_srv_priority_floor() {
    // High-priority node is sealed; lower-priority leader is
    // healthy. We expect "no healthy node" rather than falling
    // through — but actually wait: the spec says priority is a
    // *hard floor only over healthy peers*. So if priority 10 has
    // NO healthy peer, we should fall back to priority 20.
    //
    // Let me re-read… "SRV priority is the hard ordering. Within
    // a priority bucket, prefer the active leader". And the pick
    // implementation picks the lowest priority that has at least
    // one healthy node. So a fully-sealed priority-10 bucket
    // SHOULD let priority-20 win.
    let sealed = FakeNode::spawn(NodeBehavior::sealed());
    let leader = FakeNode::spawn(NodeBehavior::leader("cid"));

    let candidates = vec![
        cand_for(&sealed, 10, 50),
        cand_for(&leader, 20, 50),
    ];

    let probes = health::probe_all(&candidates, &health_cfg(), None).await;
    let picked = health::pick(&probes).expect("priority-20 leader should win");
    assert_eq!(picked.candidate.port, leader.port);
}

#[tokio::test]
async fn discovery_priority_floor_blocks_lower_when_higher_has_follower() {
    // Priority 10 has a healthy follower → priority 20's faster
    // leader is excluded. Confirms the hard-floor rule.
    let follower = FakeNode::spawn(NodeBehavior::follower("cid"));
    let leader = FakeNode::spawn(NodeBehavior::leader("cid"));

    let candidates = vec![
        cand_for(&follower, 10, 50),
        cand_for(&leader, 20, 50),
    ];
    let probes = health::probe_all(&candidates, &health_cfg(), None).await;
    let picked = health::pick(&probes).expect("priority-10 follower should win");
    assert_eq!(picked.candidate.port, follower.port);
}

#[tokio::test]
async fn discovery_rejects_when_all_nodes_unreachable() {
    let dead1 = FakeNode::spawn(NodeBehavior::dead());
    let dead2 = FakeNode::spawn(NodeBehavior::dead());
    let candidates = vec![cand_for(&dead1, 10, 50), cand_for(&dead2, 10, 50)];
    let probes = health::probe_all(&candidates, &health_cfg(), None).await;
    assert!(health::pick(&probes).is_none());
    // Every probe was classified as Unreachable, not erroneously
    // bubbled up as a hard error.
    for p in &probes {
        assert!(matches!(p.state, NodeState::Unreachable(_)));
    }
}

#[tokio::test]
async fn discovery_drops_minority_cluster_id() {
    // Two nodes agree on cluster "A"; a third (faster) advertises
    // "B". The minority is dropped even though it would otherwise
    // win on RTT.
    let a1 = FakeNode::spawn(NodeBehavior::follower("A"));
    let a2 = FakeNode::spawn(NodeBehavior::follower("A"));
    let rogue = FakeNode::spawn(NodeBehavior::leader("B"));

    let candidates = vec![
        cand_for(&a1, 10, 50),
        cand_for(&a2, 10, 50),
        cand_for(&rogue, 10, 50),
    ];
    let probes = health::probe_all(&candidates, &health_cfg(), None).await;
    let picked = health::pick(&probes).expect("a winner from cluster A");
    assert_eq!(picked.cluster_id.as_deref(), Some("A"));
    assert!(picked.candidate.port == a1.port || picked.candidate.port == a2.port);
}

#[tokio::test]
async fn discovery_rtt_tiebreak_prefers_faster_node() {
    // Both nodes are leaders of the same cluster; the slow one
    // sleeps before responding, so the fast one wins.
    let fast = FakeNode::spawn(NodeBehavior::leader("cid"));
    let slow = FakeNode::spawn(NodeBehavior::slow_leader(
        "cid",
        Duration::from_millis(200),
    ));
    let candidates = vec![cand_for(&fast, 10, 50), cand_for(&slow, 10, 50)];
    let probes = health::probe_all(&candidates, &health_cfg(), None).await;
    let picked = health::pick(&probes).expect("fast leader wins on RTT");
    assert_eq!(picked.candidate.port, fast.port);
}

#[tokio::test]
async fn discovery_recovers_after_leader_dies() {
    // Simulates the "sticky session ended, operator reconnects"
    // flow: first pick lands on the leader; we then flip its
    // behavior to "drop connection"; the next pick must pick a
    // surviving follower instead.
    let leader = FakeNode::spawn(NodeBehavior::leader("cid"));
    let follower = FakeNode::spawn(NodeBehavior::follower("cid"));
    let candidates = vec![cand_for(&leader, 10, 50), cand_for(&follower, 10, 50)];

    let probes1 = health::probe_all(&candidates, &health_cfg(), None).await;
    let picked1 = health::pick(&probes1).unwrap();
    assert_eq!(picked1.candidate.port, leader.port);

    // Kill the leader and re-run.
    leader.set(NodeBehavior::dead());
    let probes2 = health::probe_all(&candidates, &health_cfg(), None).await;
    let picked2 = health::pick(&probes2).unwrap();
    assert_eq!(picked2.candidate.port, follower.port);
}

#[tokio::test]
async fn read_fails_over_in_session_when_pinned_node_dies() {
    // A `RemoteBackend` pinned to the leader, but armed with the full
    // candidate set, must transparently re-pick a healthy node and
    // retry an idempotent request when the pinned node drops — no
    // operator reconnect required.
    let leader = FakeNode::spawn(NodeBehavior::leader("cid"));
    let follower = FakeNode::spawn(NodeBehavior::follower("cid"));
    let leader_url = cand_for(&leader, 10, 50).url();
    let follower_url = cand_for(&follower, 10, 50).url();

    let be = RemoteBackend::builder()
        .with_address(&leader_url)
        .with_health_config(health_cfg())
        .with_failover_candidates(vec![
            cand_for(&leader, 10, 50),
            cand_for(&follower, 10, 50),
        ])
        .build();
    assert_eq!(be.address(), leader_url);

    // Healthy: the read lands on the pinned leader.
    be.handle(Operation::Read, "sys/internal/ui/mounts", None, "tok")
        .await
        .expect("read against healthy leader");
    assert_eq!(be.address(), leader_url, "no failover while leader is up");

    // The leader drops. The next read must fail over to the follower
    // and succeed, leaving the backend pinned to the follower.
    leader.set(NodeBehavior::dead());
    be.handle(Operation::Read, "sys/internal/ui/mounts", None, "tok")
        .await
        .expect("read should succeed after failing over to follower");
    assert_eq!(
        be.address(),
        follower_url,
        "backend should now be pinned to the surviving follower"
    );
}

#[tokio::test]
async fn write_does_not_fail_over() {
    // Writes are never auto-retried (a dropped connection leaves the
    // commit ambiguous). A write to a dead pinned node surfaces
    // `NodeUnavailable` and leaves the active node unchanged, even
    // though a healthy follower exists.
    let leader = FakeNode::spawn(NodeBehavior::dead());
    let follower = FakeNode::spawn(NodeBehavior::follower("cid"));
    let leader_url = cand_for(&leader, 10, 50).url();

    let be = RemoteBackend::builder()
        .with_address(&leader_url)
        .with_health_config(health_cfg())
        .with_failover_candidates(vec![
            cand_for(&leader, 10, 50),
            cand_for(&follower, 10, 50),
        ])
        .build();

    let err = be
        .handle(Operation::Write, "sys/policies/acl/x", None, "tok")
        .await
        .expect_err("write to a dead node must error");
    assert!(err.is_node_unavailable(), "expected NodeUnavailable, got {err}");
    assert_eq!(
        be.address(),
        leader_url,
        "a write must not silently move the session to another node"
    );
}
