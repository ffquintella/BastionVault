//! Backend tests that need a second vault *process*.
//!
//! Everything else about the storage backends is tested next to the code, in
//! `bv-storage`. These two are here because `test_utils::test_multi_routine`
//! spawns the `bvault` CLI against a running vault — a harness that lives in
//! this crate and cannot travel down into the storage substrate without a
//! dependency cycle. See roadmaps/workspace-decomposition.md § Phase 1.
//!
//! The shared CRUD assertions they run come from `bv_storage::test`, which the
//! `test-support` feature exposes (enabled through this crate's
//! dev-dependency on `bv-storage`).

use crate::test_utils::{new_test_file_backend, new_test_temp_dir, test_multi_routine};

/// Drives a second vault process against the same backend via the `bvault`
/// CLI, so the project's runnable binary must be pre-built before this test
/// will succeed.
///
/// Run with:
///
/// ```sh
/// cargo build --bin bvault
/// cargo test --lib test_file_backend_multi_routine -- --ignored
/// ```
///
/// Marked `#[ignore]` so a plain `cargo test` doesn't surface a spawn failure
/// that actually means "the operator forgot to build the bin." The MySQL
/// sibling below has the same prerequisite and is only run behind the
/// `storage_mysql` feature flag, which similarly gates it from default test
/// runs.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
#[ignore]
async fn test_file_backend_multi_routine() {
    let dir = new_test_temp_dir("test_file_backend_multi_routine");
    let backend = new_test_file_backend(&dir);
    test_multi_routine(backend);
}

#[cfg(feature = "storage_mysql")]
#[test]
fn test_mysql_backend_multi_routine() {
    use std::{collections::HashMap, env, sync::Arc};

    use serde_json::Value;

    use crate::storage::mysql::mysql_backend::MysqlBackend;

    let mysql_pwd = env::var("CARGO_TEST_MYSQL_PASSWORD").unwrap_or("password".into());
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("address".to_string(), Value::String("127.0.0.1:3306".to_string()));
    conf.insert("username".to_string(), Value::String("root".to_string()));
    conf.insert("password".to_string(), Value::String(mysql_pwd));

    let backend = MysqlBackend::new(&conf).unwrap();

    test_multi_routine(Arc::new(backend));
}
