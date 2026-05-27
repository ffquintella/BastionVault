#[cfg(not(feature = "storage_hiqlite"))]
fn main() {}

#[cfg(feature = "storage_hiqlite")]
mod inner {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::sync::{Arc, OnceLock};

    use cucumber::{given, then, when, World};
    use serde_json::Value;

    use bastion_vault::storage::hiqlite::HiqliteBackend;
    use bastion_vault::storage::{Backend, BackendEntry};

    #[derive(Debug, World)]
    #[world(init = Self::new)]
    pub struct HiqliteWorld {
        backend: Option<Arc<HiqliteBackend>>,
        last_get_result: Option<Option<BackendEntry>>,
        last_list_result: Option<Vec<String>>,
        data_dir: String,
    }

    impl HiqliteWorld {
        fn new() -> Self {
            Self {
                backend: None,
                last_get_result: None,
                last_list_result: None,
                data_dir: String::new(),
            }
        }

        fn backend(&self) -> &HiqliteBackend {
            self.backend.as_ref().expect("backend not initialized")
        }
    }

    // A hiqlite node binds fixed raft/api ports and runs background tasks
    // that are not torn down between scenarios. cucumber builds a fresh
    // `World` per scenario, so creating a backend per scenario would try to
    // re-bind the same ports and fail with `Address already in use`. Share a
    // single process-global backend instead; each scenario clears the table
    // via the "the vault table is empty" step, so state stays isolated.
    static SHARED_BACKEND: OnceLock<Arc<HiqliteBackend>> = OnceLock::new();

    fn shared_backend() -> Arc<HiqliteBackend> {
        SHARED_BACKEND
            .get_or_init(|| {
                let dir = env::temp_dir().join("bvault_cucumber_hiqlite");
                let _ = fs::remove_dir_all(&dir);
                fs::create_dir_all(&dir).unwrap();

                let mut conf: HashMap<String, Value> = HashMap::new();
                conf.insert(
                    "data_dir".to_string(),
                    Value::String(dir.to_string_lossy().into_owned()),
                );
                conf.insert("node_id".to_string(), Value::Number(1.into()));
                conf.insert(
                    "secret_raft".to_string(),
                    Value::String("cucumber_raft_secret_".to_string()),
                );
                conf.insert(
                    "secret_api".to_string(),
                    Value::String("cucumber_api_secret_1".to_string()),
                );
                conf.insert("table".to_string(), Value::String("vault".to_string()));
                // `listen_addr_{api,raft}` are host-only; the port comes from
                // the separate `port_{api,raft}` keys (HiqliteBackend builds
                // the node address as `host:port`). Embedding the port in the
                // host string yields a malformed `host:port:port` address that
                // fails to resolve.
                conf.insert(
                    "listen_addr_api".to_string(),
                    Value::String("127.0.0.1".to_string()),
                );
                conf.insert(
                    "listen_addr_raft".to_string(),
                    Value::String("127.0.0.1".to_string()),
                );
                conf.insert("port_api".to_string(), Value::Number(28100.into()));
                conf.insert("port_raft".to_string(), Value::Number(28200.into()));

                Arc::new(
                    HiqliteBackend::new(&conf).expect("failed to create hiqlite backend"),
                )
            })
            .clone()
    }

    #[given("a hiqlite backend")]
    async fn given_a_hiqlite_backend(world: &mut HiqliteWorld) {
        let backend = shared_backend();
        world.data_dir = env::temp_dir()
            .join("bvault_cucumber_hiqlite")
            .to_string_lossy()
            .into_owned();
        world.backend = Some(backend);
    }

    #[given("the vault table is empty")]
    async fn given_table_empty(world: &mut HiqliteWorld) {
        let backend = world.backend();
        backend
            .client()
            .batch(Cow::Borrowed("DELETE FROM vault"))
            .await
            .expect("failed to clear table");
    }

    #[when(expr = "I store key {string} with value {string}")]
    async fn when_store_key(world: &mut HiqliteWorld, key: String, value: String) {
        let entry = BackendEntry {
            key,
            value: value.into_bytes(),
        };
        world.backend().put(&entry).await.expect("put failed");
    }

    #[when(expr = "I get key {string}")]
    async fn when_get_key(world: &mut HiqliteWorld, key: String) {
        let result = world.backend().get(&key).await.expect("get failed");
        world.last_get_result = Some(result);
    }

    #[when(expr = "I delete key {string}")]
    async fn when_delete_key(world: &mut HiqliteWorld, key: String) {
        world.backend().delete(&key).await.expect("delete failed");
    }

    #[when(expr = "I list keys with prefix {string}")]
    async fn when_list_keys(world: &mut HiqliteWorld, prefix: String) {
        let result = world.backend().list(&prefix).await.expect("list failed");
        world.last_list_result = Some(result);
    }

    #[then(expr = "the result should contain key {string}")]
    async fn then_result_contains_key(world: &mut HiqliteWorld, expected_key: String) {
        let result = world.last_get_result.as_ref().expect("no get result");
        let entry = result.as_ref().expect("expected Some, got None");
        assert_eq!(entry.key, expected_key);
    }

    #[then(expr = "the result should contain value {string}")]
    async fn then_result_contains_value(world: &mut HiqliteWorld, expected_value: String) {
        let result = world.last_get_result.as_ref().expect("no get result");
        let entry = result.as_ref().expect("expected Some, got None");
        assert_eq!(entry.value, expected_value.as_bytes());
    }

    #[then("the result should be empty")]
    async fn then_result_empty(world: &mut HiqliteWorld) {
        let result = world.last_get_result.as_ref().expect("no get result");
        assert!(result.is_none(), "expected None, got {:?}", result);
    }

    #[then(expr = "the key list should have {int} entries")]
    async fn then_list_has_n_entries(world: &mut HiqliteWorld, n: usize) {
        let result = world.last_list_result.as_ref().expect("no list result");
        assert_eq!(result.len(), n, "expected {} entries, got {:?}", n, result);
    }

    #[then(expr = "the key list should contain {string}")]
    async fn then_list_contains(world: &mut HiqliteWorld, expected: String) {
        let result = world.last_list_result.as_ref().expect("no list result");
        assert!(
            result.contains(&expected),
            "expected list to contain {:?}, got {:?}",
            expected,
            result
        );
    }

    pub async fn run() {
        // Scenarios share one process-global backend + table (see
        // SHARED_BACKEND), so they must run serially — cucumber's default
        // concurrent execution would let scenarios race on the same table
        // (one clearing it while another reads), producing flaky value/count
        // mismatches.
        HiqliteWorld::cucumber()
            .max_concurrent_scenarios(1)
            .run_and_exit("tests/features/hiqlite_storage.feature")
            .await;
    }
}

#[cfg(feature = "storage_hiqlite")]
#[tokio::main]
async fn main() {
    inner::run().await;
}
