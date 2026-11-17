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
    modules::identity::{kv_key_split_migrate, kv_key_split_retry, IdentityModule},
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
/// garbled, and a later one completes the datafix and sets the marker. The
/// half-second base leaves the later attempts 1 to 8 s of margin.
#[tokio::test]
async fn a_failed_unseal_pass_is_retried_until_it_completes() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_split_retry_completes").await;
    let original = break_the_datafix(&core, &root).await;
    let identity = identity(&core);
    identity.kv_split_retry.set_first_delay_for_test(Duration::from_millis(500));

    assert!(identity.run_if_needed().await.is_err(), "the unseal pass fails");
    assert!(identity.kv_split_retry.running(), "a background retry is scheduled");
    eventually(30, "a failed retry", || identity.kv_split_retry.failures_for_test() >= 1).await;
    assert!(!owner_store(&core).await.kv_keys_split().await.unwrap(), "no marker while it fails");

    core.barrier().as_storage().put(&original).await.unwrap();
    let store = owner_store(&core).await;
    for _ in 0..1500 {
        if store.kv_keys_split().await.unwrap() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(store.kv_keys_split().await.unwrap(), "a later retry set the marker");
    eventually(10, "the task to end", || !identity.kv_split_retry.running()).await;
    let failures = identity.kv_split_retry.failures_for_test();
    assert!((1..kv_key_split_retry::MAX_RETRIES).contains(&failures), "it completed before giving up: {failures}");
}

/// One task per node: a second failed pass while one runs starts no other.
/// A seal aborts it: past its first wait, it never woke.
#[tokio::test]
async fn one_retry_task_runs_and_a_seal_cancels_it() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_split_retry_seal").await;
    break_the_datafix(&core, &root).await;
    let identity = identity(&core);
    identity.kv_split_retry.set_first_delay_for_test(Duration::from_secs(2));

    assert!(identity.run_if_needed().await.is_err());
    assert!(identity.run_if_needed().await.is_err(), "a second failed pass");
    assert!(identity.kv_split_retry.running(), "still one task, in its first wait");
    core.seal().await.unwrap();
    assert!(!identity.kv_split_retry.running(), "the seal took the task");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(identity.kv_split_retry.wakes_for_test(), 0, "aborted: it never finished its first wait");
    assert_eq!(identity.kv_split_retry.failures_for_test(), 0, "and never ran an attempt");
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

/// While the key switch is pending (a datafix not yet complete, as while the
/// background retry runs and the node serves), a write, delete, owner change
/// or share on a secret whose key moves at the switch is refused with a 503:
/// a record written under the old key would be left behind. Others proceed.
#[tokio::test]
async fn while_the_switch_is_pending_a_moving_key_takes_no_record() {
    use super::kv_secret_keys::{kv_owner, login, send, status};
    use crate::logical::Operation;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let (_bvault, core, root) = new_unseal_test_bastion_vault("kv_split_pending_moving_key").await;
    test_write_api(core.as_ref(), &root, "sys/auth/pass", true, json!({ "type": "userpass" }).as_object().cloned())
        .await
        .unwrap();
    let sharer = r#"path "identity/sharing/by-target/*" { capabilities = ["create", "update", "read", "list"] }"#;
    let body = json!({ "policy": sharer }).as_object().cloned();
    test_write_api(core.as_ref(), &root, "sys/policy/sharer", true, body).await.unwrap();
    let (bob, bob_id) = login(&core, &root, "bob", "standard-user,default,sharer").await;
    let (_, carol_id) = login(&core, &root, "carol", "standard-user,default").await;
    kv_key_split_migrate::reset_for_test(core.as_ref()).await.unwrap();
    let data = |v: &str| json!({ "data": { "v": v } });
    let share = |target: &str, grantee: &str| {
        format!("identity/sharing/by-target/kv-secret/{}/{grantee}", URL_SAFE_NO_PAD.encode(target))
    };
    let grant = json!({ "grantee_kind": "entity", "capabilities": ["read"] });

    // `data/y` keys as `secret/y` before the switch and `secret/data/y` after.
    for api in [1u8, 2] {
        let r = send(&core, &bob, api, Operation::Write, "secret/data/data/y", None, data("bob's")).await;
        assert_eq!(status(&r), 503, "api {api}: bob's first write of data/y: {r:?}");
    }
    let r = send(&core, &root, 1, Operation::Write, "secret/data/data/z", None, data("root's")).await;
    assert_eq!(status(&r), 503, "root too: {r:?}");
    let r = send(&core, &root, 1, Operation::Delete, "secret/metadata/data/z", None, json!({})).await;
    assert_eq!(status(&r), 503, "a delete forgets records under the old key: {r:?}");
    let r =
        send(&core, &bob, 1, Operation::Write, "sys/kv-owner/claim", None, json!({ "path": "secret/data/q" })).await;
    assert_eq!(status(&r), 503, "a claim of data/q: {r:?}");
    let r = send(&core, &bob, 1, Operation::Write, &share("secret/data/y", &carol_id), None, grant.clone()).await;
    assert_eq!(status(&r), 503, "a share of data/y: {r:?}");
    assert_eq!(kv_owner(&core, "secret/y").await, None, "nothing stamped under the old key");

    // `y` keys as `secret/y` either way: unaffected, and so is another engine.
    let r = send(&core, &bob, 1, Operation::Write, "secret/data/y", None, data("bob's")).await;
    assert_eq!(status(&r), 200, "bob's first write of y: {r:?}");
    assert_eq!(kv_owner(&core, "secret/y").await, Some(bob_id.clone()));
    assert_eq!(status(&send(&core, &bob, 2, Operation::Read, "secret/y", None, json!({})).await), 200);
    let r = send(&core, &bob, 1, Operation::Write, &share("secret/y", &carol_id), None, grant.clone()).await;
    assert_eq!(status(&r), 200, "a share of y: {r:?}");
    let meta = json!({ "type": "server", "hostname": "bob.example" });
    let r = send(&core, &bob, 1, Operation::Write, "resources/resources/bob-srv", None, meta).await;
    assert_eq!(status(&r), 200, "a resource: {r:?}");

    // Once the datafix completes the refusal is gone.
    kv_key_split_migrate::run_if_needed(core.as_ref()).await.unwrap();
    let r = send(&core, &bob, 1, Operation::Write, "secret/data/data/y", None, data("bob's")).await;
    assert_eq!(status(&r), 200, "after the switch: {r:?}");
    assert_eq!(kv_owner(&core, "secret/data/y").await, Some(bob_id));
    let r = send(&core, &bob, 1, Operation::Write, &share("secret/data/y", &carol_id), None, grant).await;
    assert_eq!(status(&r), 200, "a share of data/y after the switch: {r:?}");
}
