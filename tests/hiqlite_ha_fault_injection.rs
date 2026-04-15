//! Phase 6: HA Fault-Injection Validation Tests
//!
//! Tests multi-node hiqlite cluster behavior under various failure scenarios:
//! leader election, failover, quorum loss, node restart, and graceful leave.
//!
//! Run with: CARGO_TEST_HIQLITE=1 cargo test --test hiqlite_ha_fault_injection

#[cfg(not(feature = "storage_hiqlite"))]
fn main() {}

#[cfg(feature = "storage_hiqlite")]
mod ha_tests {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::sync::Arc;

    use serde_json::Value;
    use serial_test::serial;

    use bastion_vault::storage::hiqlite::HiqliteBackend;
    use bastion_vault::storage::{Backend, BackendEntry};

    const SECRET_RAFT: &str = "ha_test_raft_secret_1";
    const SECRET_API: &str = "ha_test_api_secret_12";
    const TABLE: &str = "vault_ha_test";

    /// Port base: node N uses raft_port = BASE_RAFT + N - 1, api_port = BASE_API + N - 1.
    const BASE_RAFT: u16 = 38210;
    const BASE_API: u16 = 38220;

    fn should_run() -> bool {
        env::var("CARGO_TEST_HIQLITE").map_or(false, |v| v == "1")
    }

    /// Build the `nodes` config string array for a 3-node cluster.
    fn nodes_config() -> Value {
        let nodes: Vec<Value> = (1..=3u64)
            .map(|id| {
                let raft_port = BASE_RAFT + (id as u16) - 1;
                let api_port = BASE_API + (id as u16) - 1;
                Value::String(format!(
                    "{id}:127.0.0.1:{raft_port}:127.0.0.1:{api_port}"
                ))
            })
            .collect();
        Value::Array(nodes)
    }

    /// Create config for a single node in a 3-node cluster.
    fn make_node_conf(test_name: &str, node_id: u64) -> HashMap<String, Value> {
        let dir = env::temp_dir()
            .join("bvault_ha_test")
            .join(test_name)
            .join(format!("node{node_id}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let raft_port = BASE_RAFT + (node_id as u16) - 1;
        let api_port = BASE_API + (node_id as u16) - 1;

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("data_dir".into(), Value::String(dir.to_string_lossy().into_owned()));
        conf.insert("node_id".into(), Value::Number(node_id.into()));
        conf.insert("secret_raft".into(), Value::String(SECRET_RAFT.into()));
        conf.insert("secret_api".into(), Value::String(SECRET_API.into()));
        conf.insert("table".into(), Value::String(TABLE.into()));
        conf.insert("listen_addr_api".into(), Value::String("127.0.0.1".into()));
        conf.insert("listen_addr_raft".into(), Value::String("127.0.0.1".into()));
        conf.insert("port_raft".into(), Value::Number(raft_port.into()));
        conf.insert("port_api".into(), Value::Number(api_port.into()));
        conf.insert("nodes".into(), nodes_config());
        conf
    }

    /// A 3-node test cluster.
    struct TestCluster {
        pub nodes: Vec<Option<Arc<HiqliteBackend>>>,
        test_name: String,
    }

    impl TestCluster {
        /// Start a 3-node cluster. All nodes start up and form a Raft group.
        async fn new(test_name: &str) -> Self {
            // Clean up any previous run
            let base_dir = env::temp_dir().join("bvault_ha_test").join(test_name);
            let _ = fs::remove_dir_all(&base_dir);

            let mut nodes: Vec<Option<Arc<HiqliteBackend>>> = Vec::new();
            for id in 1..=3u64 {
                let conf = make_node_conf(test_name, id);
                let backend = HiqliteBackend::new(&conf)
                    .unwrap_or_else(|e| panic!("Failed to create node {id}: {e}"));
                nodes.push(Some(Arc::new(backend)));
            }

            // Wait for leader election to stabilize.
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

            Self {
                nodes,
                test_name: test_name.to_string(),
            }
        }

        /// Get a reference to a running node (1-indexed).
        fn node(&self, id: usize) -> &HiqliteBackend {
            self.nodes[id - 1]
                .as_ref()
                .unwrap_or_else(|| panic!("Node {id} is stopped"))
        }

        /// Find the leader node ID (1-indexed). Returns None if no leader.
        async fn find_leader(&self) -> Option<usize> {
            for (i, node_opt) in self.nodes.iter().enumerate() {
                if let Some(node) = node_opt {
                    if node.is_leader().await {
                        return Some(i + 1);
                    }
                }
            }
            None
        }

        /// Find follower node IDs (1-indexed).
        async fn find_followers(&self) -> Vec<usize> {
            let mut followers = Vec::new();
            for (i, node_opt) in self.nodes.iter().enumerate() {
                if let Some(node) = node_opt {
                    if !node.is_leader().await {
                        followers.push(i + 1);
                    }
                }
            }
            followers
        }

        /// Stop a node by dropping it (1-indexed).
        fn stop_node(&mut self, id: usize) {
            self.nodes[id - 1] = None;
        }

        /// Restart a stopped node (1-indexed).
        fn restart_node(&mut self, id: usize) {
            let conf = make_node_conf(&self.test_name, id as u64);
            let backend = HiqliteBackend::new(&conf)
                .unwrap_or_else(|e| panic!("Failed to restart node {id}: {e}"));
            self.nodes[id - 1] = Some(Arc::new(backend));
        }

        /// Clear the test table on all running nodes.
        async fn clear_all(&self) {
            for node_opt in &self.nodes {
                if let Some(node) = node_opt {
                    let _ = node
                        .client()
                        .batch(Cow::Borrowed("DELETE FROM vault_ha_test"))
                        .await;
                }
            }
        }

        /// Wait for a leader to be elected with timeout.
        async fn wait_for_leader(&self, timeout_secs: u64) -> Option<usize> {
            let deadline = tokio::time::Instant::now()
                + tokio::time::Duration::from_secs(timeout_secs);
            loop {
                if let Some(id) = self.find_leader().await {
                    return Some(id);
                }
                if tokio::time::Instant::now() > deadline {
                    return None;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 1: Three-node cluster formation
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_cluster_formation() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let cluster = TestCluster::new("cluster_formation").await;

        // Exactly one leader should exist.
        let leader_id = cluster.find_leader().await;
        assert!(leader_id.is_some(), "No leader elected in 3-node cluster");

        // All nodes should report healthy.
        for id in 1..=3 {
            assert!(
                cluster.node(id).is_healthy().await,
                "Node {id} is not healthy"
            );
        }

        // There should be exactly 2 followers.
        let followers = cluster.find_followers().await;
        assert_eq!(followers.len(), 2, "Expected 2 followers, got {:?}", followers);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 2: Write on leader, read on follower
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_write_leader_read_follower() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let cluster = TestCluster::new("write_read").await;
        cluster.clear_all().await;

        let leader_id = cluster.find_leader().await.expect("No leader");
        let followers = cluster.find_followers().await;
        assert!(!followers.is_empty(), "No followers found");

        // Write via leader.
        let entry = BackendEntry {
            key: "ha/test/key1".to_string(),
            value: b"leader_wrote_this".to_vec(),
        };
        cluster.node(leader_id).put(&entry).await.unwrap();

        // Small delay for replication.
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Read from a follower (strong consistency via query_consistent_map).
        let follower_id = followers[0];
        let result = cluster.node(follower_id).get("ha/test/key1").await.unwrap();
        assert!(result.is_some(), "Follower did not return the entry");
        assert_eq!(result.unwrap().value, b"leader_wrote_this");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 3: Leader failover via step-down
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_leader_failover_step_down() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let cluster = TestCluster::new("failover_step_down").await;

        let old_leader_id = cluster.find_leader().await.expect("No leader");

        // Trigger step-down.
        cluster.node(old_leader_id).trigger_failover().unwrap();

        // Wait for new leader.
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        let new_leader_id = cluster.wait_for_leader(10).await;
        assert!(new_leader_id.is_some(), "No new leader elected after failover");

        // New leader should be different (or same if re-elected, both are valid).
        let new_leader_id = new_leader_id.unwrap();

        // Writes should succeed on the new leader.
        cluster.clear_all().await;
        let entry = BackendEntry {
            key: "ha/after_failover".to_string(),
            value: b"still_works".to_vec(),
        };
        cluster.node(new_leader_id).put(&entry).await.unwrap();

        let result = cluster.node(new_leader_id).get("ha/after_failover").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, b"still_works");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 4: Follower restart without data loss
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_follower_restart_no_data_loss() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let mut cluster = TestCluster::new("follower_restart").await;
        cluster.clear_all().await;

        let leader_id = cluster.find_leader().await.expect("No leader");
        let followers = cluster.find_followers().await;
        let follower_id = followers[0];

        // Write data via leader.
        let entry = BackendEntry {
            key: "ha/persist/data".to_string(),
            value: b"must_survive_restart".to_vec(),
        };
        cluster.node(leader_id).put(&entry).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Stop follower.
        cluster.stop_node(follower_id);
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Restart follower.
        cluster.restart_node(follower_id);
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Verify data persists on restarted follower.
        let result = cluster.node(follower_id).get("ha/persist/data").await.unwrap();
        assert!(result.is_some(), "Data lost after follower restart");
        assert_eq!(result.unwrap().value, b"must_survive_restart");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 5: Leader restart with re-election
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_leader_restart_reelection() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let mut cluster = TestCluster::new("leader_restart").await;
        cluster.clear_all().await;

        let old_leader_id = cluster.find_leader().await.expect("No leader");

        // Write data via leader before it goes down.
        let entry = BackendEntry {
            key: "ha/before_crash".to_string(),
            value: b"written_before_leader_crash".to_vec(),
        };
        cluster.node(old_leader_id).put(&entry).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Stop the leader (simulate crash).
        cluster.stop_node(old_leader_id);

        // Wait for new leader election from remaining 2 nodes.
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        let new_leader_id = cluster.wait_for_leader(15).await;
        assert!(
            new_leader_id.is_some(),
            "No new leader elected after leader crash"
        );
        let new_leader_id = new_leader_id.unwrap();
        assert_ne!(new_leader_id, old_leader_id, "Old leader shouldn't be leader while stopped");

        // Data should still be available on new leader.
        let result = cluster.node(new_leader_id).get("ha/before_crash").await.unwrap();
        assert!(result.is_some(), "Data lost after leader crash");
        assert_eq!(result.unwrap().value, b"written_before_leader_crash");

        // Writes should succeed on new leader.
        let entry2 = BackendEntry {
            key: "ha/after_crash".to_string(),
            value: b"written_after_leader_crash".to_vec(),
        };
        cluster.node(new_leader_id).put(&entry2).await.unwrap();

        // Restart old leader.
        cluster.restart_node(old_leader_id);
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Old leader should now be a follower and have all data.
        let result = cluster.node(old_leader_id).get("ha/after_crash").await.unwrap();
        assert!(result.is_some(), "Restarted node missing data written during its absence");
        assert_eq!(result.unwrap().value, b"written_after_leader_crash");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 6: Write during leader election (transient errors then recovery)
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_write_during_election() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let mut cluster = TestCluster::new("write_during_election").await;
        cluster.clear_all().await;

        let old_leader_id = cluster.find_leader().await.expect("No leader");
        let followers = cluster.find_followers().await;
        let follower_id = followers[0];

        // Stop the leader to trigger election.
        cluster.stop_node(old_leader_id);

        // Immediately try to write on a follower -- may fail transiently.
        let entry = BackendEntry {
            key: "ha/during_election".to_string(),
            value: b"election_write".to_vec(),
        };
        let _immediate_write = cluster.node(follower_id).put(&entry).await;
        // We don't assert success here -- it may fail during election.

        // Wait for new leader election.
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        let new_leader_id = cluster.wait_for_leader(15).await;
        assert!(new_leader_id.is_some(), "No leader elected after stopping old leader");
        let new_leader_id = new_leader_id.unwrap();

        // Now writes should succeed.
        let entry2 = BackendEntry {
            key: "ha/after_election".to_string(),
            value: b"post_election_write".to_vec(),
        };
        cluster.node(new_leader_id).put(&entry2).await.unwrap();

        let result = cluster.node(new_leader_id).get("ha/after_election").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, b"post_election_write");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 7: Quorum loss behavior
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_quorum_loss_and_recovery() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let mut cluster = TestCluster::new("quorum_loss").await;
        cluster.clear_all().await;

        let leader_id = cluster.find_leader().await.expect("No leader");

        // Write some data first.
        let entry = BackendEntry {
            key: "ha/pre_quorum_loss".to_string(),
            value: b"before_quorum_lost".to_vec(),
        };
        cluster.node(leader_id).put(&entry).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Stop 2 of 3 nodes (quorum lost).
        let followers = cluster.find_followers().await;
        cluster.stop_node(followers[0]);
        cluster.stop_node(followers[1]);
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Writes should fail (no quorum).
        let entry2 = BackendEntry {
            key: "ha/during_quorum_loss".to_string(),
            value: b"should_fail".to_vec(),
        };
        let write_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            cluster.node(leader_id).put(&entry2),
        )
        .await;
        // Should either timeout or return an error.
        let write_failed = match write_result {
            Err(_) => true, // timeout
            Ok(Err(_)) => true, // error
            Ok(Ok(())) => false, // unexpectedly succeeded
        };
        assert!(write_failed, "Write should fail without quorum");

        // Restart one node to restore quorum (2 of 3).
        cluster.restart_node(followers[0]);
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Wait for leader to be available.
        let recovered_leader = cluster.wait_for_leader(15).await;
        assert!(recovered_leader.is_some(), "No leader after quorum recovery");

        // Writes should succeed again.
        let entry3 = BackendEntry {
            key: "ha/after_recovery".to_string(),
            value: b"quorum_restored".to_vec(),
        };
        let recovered_leader_id = recovered_leader.unwrap();
        cluster.node(recovered_leader_id).put(&entry3).await.unwrap();

        let result = cluster
            .node(recovered_leader_id)
            .get("ha/after_recovery")
            .await
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, b"quorum_restored");

        // Pre-quorum-loss data should still be available.
        let old_result = cluster
            .node(recovered_leader_id)
            .get("ha/pre_quorum_loss")
            .await
            .unwrap();
        assert!(old_result.is_some(), "Pre-quorum-loss data should survive");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Test 8: Graceful leave
    // ──────────────────────────────────────────────────────────────────────

    #[serial]
    #[tokio::test]
    async fn test_graceful_leave() {
        if !should_run() {
            eprintln!("Skipping HA test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }

        let mut cluster = TestCluster::new("graceful_leave").await;
        cluster.clear_all().await;

        let leader_id = cluster.find_leader().await.expect("No leader");
        let followers = cluster.find_followers().await;
        let leaving_id = followers[0];

        // Write data before leave.
        let entry = BackendEntry {
            key: "ha/before_leave".to_string(),
            value: b"pre_leave_data".to_vec(),
        };
        cluster.node(leader_id).put(&entry).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Graceful leave (one follower departs).
        let _leave_result = cluster.node(leaving_id).leave_cluster().await;
        // leave_cluster may succeed or fail depending on whether the node
        // is the leader; we just stop it afterwards.
        cluster.stop_node(leaving_id);
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Cluster should still function with 2 remaining nodes.
        let leader_id = cluster.wait_for_leader(10).await;
        assert!(leader_id.is_some(), "No leader after graceful leave");
        let leader_id = leader_id.unwrap();

        // Data should still be available.
        let result = cluster.node(leader_id).get("ha/before_leave").await.unwrap();
        assert!(result.is_some(), "Data lost after graceful leave");

        // Writes should still succeed with 2 nodes.
        let entry2 = BackendEntry {
            key: "ha/after_leave".to_string(),
            value: b"post_leave_data".to_vec(),
        };
        cluster.node(leader_id).put(&entry2).await.unwrap();

        let result = cluster.node(leader_id).get("ha/after_leave").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, b"post_leave_data");
    }
}

#[cfg(feature = "storage_hiqlite")]
#[tokio::main]
async fn main() {
    // This file is compiled as an integration test binary.
    // Tests are run via: cargo test --test hiqlite_ha_fault_injection
}
