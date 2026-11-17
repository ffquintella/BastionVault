//! A KV key-split datafix that fails at unseal is retried in the background (T511).
//!
//! Before, the node kept the pre-T499 keys until the next unseal. The unseal
//! hook (`NsScopeDatafix::run_if_needed`, what `Core::post_unseal` calls) now
//! schedules one bounded retry task per node, which a seal aborts.

use std::{sync::Arc, time::Duration};

use serde_json::json;

use super::kv_secret_keys::owner_store;
use crate::{
    core::Core,
    kernel_api::{pipeline::NsScopeDatafix, VaultCtx},
    modules::identity::{kv_key_split_migrate, IdentityModule},
    storage::StorageEntry,
    test_utils::{new_unseal_test_bastion_vault, test_write_api},
};

fn identity(core: &Arc<Core>) -> Arc<IdentityModule> {
    core.module_manager().get_module::<IdentityModule>("identity").expect("identity module")
}

/// Garble the mount table of a new namespace so the datafix fails, and undo
/// the marker as before the upgrade. Returns the table's original entry.
async fn break_the_datafix(core: &Arc<Core>, root: &str) -> StorageEntry {
    let created = test_write_api(core.as_ref(), root, "sys/namespaces/broken", true, json!({}).as_object().cloned());
    let uuid = created.await.unwrap().unwrap().data.unwrap()["uuid"].as_str().unwrap().to_string();
    let key = crate::modules::namespace::router::namespace_mount_config_path(&uuid);
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let original = storage.get(&key).await.unwrap().expect("the namespace has a mount table");
    storage.put(&StorageEntry { key, value: b"not a mount table".to_vec() }).await.unwrap();
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    original
}

/// Poll `done` every 20 ms for up to `secs` seconds.
async fn eventually<F: FnMut() -> bool>(secs: u64, what: &str, mut done: F) {
    for _ in 0..secs * 50 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

/// The unseal pass fails, a background retry fails while the table is still
/// garbled, and a later one completes the datafix and sets the marker.
#[tokio::test]
async fn a_failed_unseal_pass_is_retried_until_it_completes() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_split_retry_completes").await;
    let original = break_the_datafix(&core, &root).await;
    let identity = identity(&core);
    identity.kv_split_retry.set_first_delay_for_test(Duration::from_millis(100));

    assert!(identity.run_if_needed().await.is_err(), "the unseal pass fails");
    assert!(identity.kv_split_retry.running(), "a background retry is scheduled");
    eventually(10, "a failed retry", || identity.kv_split_retry.failures_for_test() >= 1).await;
    assert!(!owner_store(&core).await.kv_keys_split().await.unwrap(), "no marker while it fails");

    core.barrier().as_storage().put(&original).await.unwrap();
    let store = owner_store(&core).await;
    for _ in 0..500 {
        if store.kv_keys_split().await.unwrap() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(store.kv_keys_split().await.unwrap(), "a later retry set the marker");
    eventually(5, "the task to end", || !identity.kv_split_retry.running()).await;
}

/// One task per node: a second failed pass while one runs starts no other.
/// A seal aborts it.
#[tokio::test]
async fn one_retry_task_runs_and_a_seal_cancels_it() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_split_retry_seal").await;
    break_the_datafix(&core, &root).await;
    let identity = identity(&core);
    identity.kv_split_retry.set_first_delay_for_test(Duration::from_secs(60));

    assert!(identity.run_if_needed().await.is_err());
    assert!(identity.run_if_needed().await.is_err(), "a second failed pass");
    assert!(identity.kv_split_retry.running(), "still one task, waiting its first minute");
    core.seal().await.unwrap();
    assert!(!identity.kv_split_retry.running(), "the seal cancelled it");
    assert_eq!(identity.kv_split_retry.failures_for_test(), 0, "it never ran an attempt");
}

/// With the marker set the unseal pass is a no-op and nothing is scheduled.
#[tokio::test]
async fn no_retry_once_the_marker_is_set() {
    let (_bvault, core, _root) = new_unseal_test_bastion_vault("kv_split_retry_marker").await;
    let identity = identity(&core);
    assert!(owner_store(&core).await.kv_keys_split().await.unwrap(), "the unseal pass completed");
    let summary = identity.run_if_needed().await.unwrap();
    assert_eq!(summary, None, "both datafixes skipped");
    assert!(!identity.kv_split_retry.running(), "no retry scheduled");
}
