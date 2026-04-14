use std::{any::Any, borrow::Cow, collections::HashMap};

use hiqlite::{Client, Node, NodeConfig, Param};
use serde_json::Value;

use crate::{
    errors::RvError,
    storage::{Backend, BackendEntry},
};

fn map_hiqlite_error(e: hiqlite::Error) -> RvError {
    match &e {
        hiqlite::Error::CheckIsLeaderError(_) => RvError::ErrClusterNoLeader,
        hiqlite::Error::LeaderChange(_) => RvError::ErrClusterNoLeader,
        hiqlite::Error::ClientWriteError(_) => {
            if e.is_forward_to_leader().is_some() {
                // hiqlite should auto-forward; if we get here, forward failed
                RvError::ErrClusterNoLeader
            } else {
                RvError::ErrCluster(e.to_string())
            }
        }
        hiqlite::Error::Connect(_) => RvError::ErrClusterUnhealthy,
        hiqlite::Error::Timeout(_) => RvError::ErrClusterUnhealthy,
        hiqlite::Error::RaftError(_) => RvError::ErrCluster(e.to_string()),
        hiqlite::Error::RaftErrorFatal(_) => RvError::ErrCluster(e.to_string()),
        _ => RvError::ErrCluster(e.to_string()),
    }
}

pub struct HiqliteBackend {
    client: Client,
    table: String,
    /// Hiqlite API address for management HTTP calls (e.g., "http://127.0.0.1:8100")
    api_addr: String,
    /// Shared API secret for hiqlite management endpoints
    secret_api: String,
    /// This node's ID
    node_id: u64,
}

struct VaultRow {
    vault_key: String,
    vault_value: Vec<u8>,
}

impl<'a, 'r> From<&'a mut hiqlite::Row<'r>> for VaultRow {
    fn from(row: &'a mut hiqlite::Row<'r>) -> Self {
        Self {
            vault_key: row.get("vault_key"),
            vault_value: row.get("vault_value"),
        }
    }
}

#[maybe_async::must_be_async]
impl Backend for HiqliteBackend {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }

        let rows: Vec<VaultRow> = self
            .client
            .query_consistent_map(
                Cow::Owned(format!(
                    "SELECT vault_key, vault_value FROM {} WHERE vault_key LIKE ?",
                    self.table
                )),
                vec![Param::from(format!("{prefix}%"))],
            )
            .await
            .map_err(map_hiqlite_error)?;

        let mut keys: Vec<String> = Vec::new();
        for entry in rows.iter() {
            let key = entry.vault_key.trim_start_matches(prefix);
            match key.find('/') {
                Some(i) => {
                    let key = &key[0..i + 1];
                    if !keys.contains(&key.to_string()) {
                        keys.push(key.to_string());
                    }
                }
                None => {
                    keys.push(key.to_string());
                }
            }
        }
        Ok(keys)
    }

    async fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let result: Option<VaultRow> = self
            .client
            .query_consistent_map(
                Cow::Owned(format!(
                    "SELECT vault_key, vault_value FROM {} WHERE vault_key = ?",
                    self.table
                )),
                vec![Param::from(key)],
            )
            .await
            .map_err(|e| RvError::ErrResponse(e.to_string()))?
            .into_iter()
            .next();

        match result {
            Some(row) => Ok(Some(BackendEntry {
                key: row.vault_key,
                value: row.vault_value,
            })),
            None => Ok(None),
        }
    }

    async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        if entry.key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        self.client
            .execute(
                Cow::Owned(format!(
                    "INSERT OR REPLACE INTO {} (vault_key, vault_value) VALUES (?, ?)",
                    self.table
                )),
                vec![Param::from(entry.key.clone()), Param::from(entry.value.clone())],
            )
            .await
            .map_err(map_hiqlite_error)?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        self.client
            .execute(
                Cow::Owned(format!("DELETE FROM {} WHERE vault_key = ?", self.table)),
                vec![Param::from(key)],
            )
            .await
            .map_err(map_hiqlite_error)?;

        Ok(())
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        let lock = self
            .client
            .lock(Cow::Owned(lock_name.to_string()))
            .await
            .map_err(map_hiqlite_error)?;
        Ok(Box::new(lock))
    }
}

fn parse_nodes(nodes_val: &Value) -> Result<Vec<Node>, RvError> {
    let nodes_arr = nodes_val.as_array().ok_or(RvError::ErrPhysicalConfigItemMissing)?;
    let mut nodes = Vec::new();
    for node_val in nodes_arr {
        let s = node_val.as_str().ok_or(RvError::ErrPhysicalConfigItemMissing)?;
        // Format: "id:raft_host:raft_port:api_host:api_port"
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 5 {
            return Err(RvError::ErrPhysicalConfigItemMissing);
        }
        let id: u64 = parts[0].parse().map_err(|_| RvError::ErrPhysicalConfigItemMissing)?;
        let addr_raft = format!("{}:{}", parts[1], parts[2]);
        let addr_api = format!("{}:{}", parts[3], parts[4]);
        nodes.push(Node {
            id,
            addr_raft,
            addr_api,
        });
    }
    Ok(nodes)
}

impl HiqliteBackend {
    async fn new_backend(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        let data_dir = conf
            .get("data_dir")
            .and_then(|v| v.as_str())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let node_id = conf
            .get("node_id")
            .and_then(|v| v.as_u64())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let secret_raft = conf
            .get("secret_raft")
            .and_then(|v| v.as_str())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let secret_api = conf
            .get("secret_api")
            .and_then(|v| v.as_str())
            .ok_or(RvError::ErrPhysicalConfigItemMissing)?;

        let table = conf
            .get("table")
            .and_then(|v| v.as_str())
            .unwrap_or("vault")
            .to_string();

        let listen_addr_api = conf
            .get("listen_addr_api")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0:8100");

        let listen_addr_raft = conf
            .get("listen_addr_raft")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0:8200");

        let nodes = if let Some(nodes_val) = conf.get("nodes") {
            parse_nodes(nodes_val)?
        } else {
            vec![Node {
                id: node_id,
                addr_raft: listen_addr_raft.to_string(),
                addr_api: listen_addr_api.to_string(),
            }]
        };

        // hiqlite requires encryption keys for backup/cookie encryption
        let mut enc_keys = cryptr::EncKeys {
            enc_key_active: String::new(),
            enc_keys: Vec::new(),
        };
        enc_keys
            .append_new_random_with_id("bvault-default".to_string())
            .map_err(|e| RvError::ErrCluster(e.to_string()))?;

        let node_config = NodeConfig {
            node_id,
            nodes,
            data_dir: Cow::Owned(data_dir.to_string()),
            listen_addr_api: Cow::Owned(listen_addr_api.to_string()),
            listen_addr_raft: Cow::Owned(listen_addr_raft.to_string()),
            secret_raft: secret_raft.to_string(),
            secret_api: secret_api.to_string(),
            enc_keys,
            ..Default::default()
        };

        let client = hiqlite::start_node(node_config)
            .await
            .map_err(map_hiqlite_error)?;

        // Create the vault table if it doesn't exist
        client
            .batch(Cow::Owned(format!(
                "CREATE TABLE IF NOT EXISTS {} (vault_key TEXT NOT NULL PRIMARY KEY, vault_value BLOB NOT NULL)",
                table
            )))
            .await
            .map_err(map_hiqlite_error)?;

        let api_addr = format!("http://{listen_addr_api}");

        Ok(HiqliteBackend {
            client,
            table,
            api_addr,
            secret_api: secret_api.to_string(),
            node_id,
        })
    }

    /// Returns a reference to the underlying hiqlite client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Returns true if this node is the current Raft leader.
    pub async fn is_leader(&self) -> bool {
        self.client.is_leader_db().await
    }

    /// Returns true if the Raft database cluster is healthy.
    pub async fn is_healthy(&self) -> bool {
        self.client.is_healthy_db().await.is_ok()
    }

    /// Returns Raft cluster metrics as a JSON value.
    pub async fn cluster_metrics(&self) -> Result<Value, RvError> {
        let metrics = self.client.metrics_db().await.map_err(map_hiqlite_error)?;
        serde_json::to_value(metrics).map_err(|e| RvError::ErrCluster(e.to_string()))
    }

    /// Returns this node's ID.
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Remove a node from the Raft cluster. Must be called on the leader.
    /// If `stay_as_learner` is true, the node is demoted to learner instead of fully removed.
    pub fn remove_node(&self, target_node_id: u64, stay_as_learner: bool) -> Result<(), RvError> {
        let url = format!("{}/cluster/membership/db", self.api_addr);
        let body = serde_json::json!({
            "node_id": target_node_id,
            "stay_as_learner": stay_as_learner,
        });

        let agent = ureq::Agent::new_with_defaults();
        let req = http::Request::builder()
            .method("DELETE")
            .uri(&url)
            .header("X-API-SECRET", &self.secret_api)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&body).map_err(|e| RvError::ErrCluster(e.to_string()))?)
            .map_err(|e| RvError::ErrCluster(e.to_string()))?;

        let resp = agent.run(req).map_err(|e| RvError::ErrCluster(e.to_string()))?;
        let status = resp.status().as_u16();

        if (200..300).contains(&status) {
            Ok(())
        } else {
            let text = resp.into_body().read_to_string().unwrap_or_default();
            Err(RvError::ErrCluster(format!("remove_node failed (HTTP {status}): {text}")))
        }
    }

    /// Gracefully shut down this node and leave the cluster.
    pub async fn leave_cluster(&self) -> Result<(), RvError> {
        self.client.shutdown().await.map_err(map_hiqlite_error)
    }

    pub fn new(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        // hiqlite is async-only; use a nested-runtime pattern to bridge sync construction
        match tokio::runtime::Handle::try_current() {
            Ok(_handle) => std::thread::scope(|s| {
                let conf = conf.clone();
                let handle = s.spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async { Self::new_backend(&conf).await })
                });
                handle.join().unwrap()
            }),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async { Self::new_backend(conf).await })
            }
        }
    }
}

impl Drop for HiqliteBackend {
    fn drop(&mut self) {
        // Attempt graceful shutdown; ignore errors during drop
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let client = self.client.clone();
            handle.spawn(async move {
                let _ = client.shutdown().await;
            });
        }
    }
}

#[cfg(all(test, feature = "storage_hiqlite"))]
mod test {
    use std::{collections::HashMap, env, fs};

    use serde_json::Value;
    use serial_test::serial;

    use super::HiqliteBackend;
    use crate::storage::test::{test_backend_curd, test_backend_list_prefix};
    use crate::test_utils::TEST_DIR;

    /// Returns true if hiqlite integration tests should run.
    /// Set CARGO_TEST_HIQLITE=1 to enable (requires free ports 18100/18200).
    fn should_run() -> bool {
        env::var("CARGO_TEST_HIQLITE").map_or(false, |v| v == "1")
    }

    fn make_test_conf(test_name: &str) -> HashMap<String, Value> {
        let dir = env::temp_dir().join(*TEST_DIR).join(test_name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("data_dir".to_string(), Value::String(dir.to_string_lossy().into_owned()));
        conf.insert("node_id".to_string(), Value::Number(1.into()));
        conf.insert("secret_raft".to_string(), Value::String("test_raft_secret_1234".to_string()));
        conf.insert("secret_api".to_string(), Value::String("test_api_secret_12345".to_string()));
        conf.insert("table".to_string(), Value::String("vault_test".to_string()));
        conf.insert("listen_addr_api".to_string(), Value::String("127.0.0.1:18100".to_string()));
        conf.insert("listen_addr_raft".to_string(), Value::String("127.0.0.1:18200".to_string()));
        conf
    }

    #[serial]
    #[tokio::test]
    async fn test_hiqlite_backend() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        let conf = make_test_conf("test_hiqlite_backend");
        let backend = HiqliteBackend::new(&conf);
        assert!(backend.is_ok(), "Failed to create backend: {:?}", backend.err());
        let backend = backend.unwrap();

        // Clear the test table
        let _ = backend
            .client()
            .batch(std::borrow::Cow::Borrowed("DELETE FROM vault_test"))
            .await;

        test_backend_curd(&backend).await;

        // Clear again before prefix test
        let _ = backend
            .client()
            .batch(std::borrow::Cow::Borrowed("DELETE FROM vault_test"))
            .await;

        test_backend_list_prefix(&backend).await;
    }

    #[serial]
    #[tokio::test]
    async fn test_hiqlite_cluster_health() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        let conf = make_test_conf("test_hiqlite_cluster_health");
        let backend = HiqliteBackend::new(&conf);
        assert!(backend.is_ok(), "Failed to create backend: {:?}", backend.err());
        let backend = backend.unwrap();

        // Single-node cluster should be leader
        assert!(backend.is_leader().await, "Single-node should be leader");

        // Single-node cluster should be healthy
        assert!(backend.is_healthy().await, "Single-node should be healthy");

        // Cluster metrics should be available
        let metrics = backend.cluster_metrics().await;
        assert!(metrics.is_ok(), "Cluster metrics should be available: {:?}", metrics.err());

        // Node ID should match config
        assert_eq!(backend.node_id(), 1);
    }

    #[serial]
    #[tokio::test]
    async fn test_hiqlite_migrate_from_file() {
        if !should_run() {
            eprintln!("Skipping hiqlite test (set CARGO_TEST_HIQLITE=1 to enable)");
            return;
        }
        use std::sync::Arc;
        use crate::storage::{new_backend, migrate::migrate_backend, Backend, BackendEntry};

        // Create source file backend with test data
        let source_dir = env::temp_dir().join(*TEST_DIR).join("test_migrate_source");
        let _ = fs::remove_dir_all(&source_dir);
        fs::create_dir_all(&source_dir).unwrap();

        let mut source_conf: HashMap<String, Value> = HashMap::new();
        source_conf.insert("path".to_string(), Value::String(source_dir.to_string_lossy().into_owned()));
        let source = new_backend("file", &source_conf).unwrap();

        // Write test entries
        let entries = vec![
            BackendEntry { key: "core/test".to_string(), value: b"core_data".to_vec() },
            BackendEntry { key: "logical/mount1/secret".to_string(), value: b"secret_data".to_vec() },
            BackendEntry { key: "logical/mount1/nested/key".to_string(), value: b"nested_data".to_vec() },
        ];
        for entry in &entries {
            source.put(entry).await.unwrap();
        }

        // Create destination hiqlite backend
        let dest_conf = make_test_conf("test_migrate_dest");
        let dest = new_backend("hiqlite", &dest_conf).unwrap();

        // Clear destination
        let dest_any = dest.as_ref() as &dyn std::any::Any;
        if let Some(hiqlite) = dest_any.downcast_ref::<HiqliteBackend>() {
            let _ = hiqlite.client().batch(std::borrow::Cow::Borrowed("DELETE FROM vault_test")).await;
        }

        // Run migration
        let result = migrate_backend(&source, &dest).await.unwrap();
        assert_eq!(result.entries_copied, 3);
        assert_eq!(result.entries_skipped, 0);

        // Verify all entries exist in destination
        for entry in &entries {
            let got = dest.get(&entry.key).await.unwrap();
            assert!(got.is_some(), "Entry {} not found in destination", entry.key);
            assert_eq!(got.unwrap().value, entry.value);
        }
    }
}
