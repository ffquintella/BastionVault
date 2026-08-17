//! Backend fixtures shared by this crate's tests and the root crate's.
//!
//! These four used to live in `bastion_vault::test_utils`, which is where the
//! root crate still reaches them from — it re-exports this module's contents
//! under the same names, so no existing call site changed. They moved here
//! because the barrier and backend tests that use them travelled with
//! `bv-storage`, and a test in this crate cannot import from the crate that
//! depends on it.
//!
//! Compiled only under `cfg(test)` or the `test-support` feature, so a normal
//! `cargo build` never sees them.

use std::{
    collections::HashMap,
    env, fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

use crate::{new_backend, Backend};

/// Directory under the system temp dir that every test fixture writes below.
/// A single well-known name so a developer can wipe the lot in one `rm -rf`.
pub const TEST_DIR: &str = "bastion_vault_test";

/// Create a fresh, uniquely-named temp directory for one test and return its
/// path. Unique per call — the nanosecond suffix keeps concurrently running
/// tests of the same name from sharing state.
pub fn new_test_temp_dir(name: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let test_dir = env::temp_dir().join(format!("{}/{}-{}", TEST_DIR, name, now).as_str());
    let dir = test_dir.to_string_lossy().into_owned();
    assert!(fs::create_dir_all(&test_dir).is_ok());
    println!("new_test_temp_dir: {}", dir);
    dir
}

/// A file backend rooted at a fresh temp directory named after the test.
pub fn new_test_backend(name: &str) -> Arc<dyn Backend> {
    let dir = new_test_temp_dir(name);
    println!("new_test_backend, dir: {}", dir);
    new_test_file_backend(&dir)
}

/// A file backend rooted at an existing path. Use when a test needs two
/// backends over the same directory.
pub fn new_test_file_backend(path: &str) -> Arc<dyn Backend> {
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".to_string(), Value::String(path.to_string()));

    let backend = new_backend("file", &conf);
    assert!(backend.is_ok());

    backend.unwrap()
}
