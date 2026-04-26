use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn test_read_api(core: &Core, token: &str, path: &str, is_ok: bool, expect: Option<Map<String, Value>>) {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert_eq!(resp.is_ok(), is_ok);
    if expect.is_some() {
        let resp = resp.unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().data.as_ref().unwrap(), expect.as_ref().unwrap());
    } else if is_ok {
        let resp = resp.unwrap();
        assert!(resp.is_none());
    }
}

#[maybe_async::maybe_async]
async fn test_write_api(core: &Core, token: &str, path: &str, is_ok: bool, data: Option<Map<String, Value>>) {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = data;

    let ret = core.handle_request(&mut req).await;

    assert_eq!(ret.is_ok(), is_ok);
}

#[maybe_async::maybe_async]
async fn test_delete_api(core: &Core, token: &str, path: &str, is_ok: bool) {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();

    let ret = core.handle_request(&mut req).await;

    assert_eq!(ret.is_ok(), is_ok);
}

#[maybe_async::maybe_async]
async fn test_list_api(core: &Core, token: &str, path: &str, is_ok: bool, keys_len: usize) {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert_eq!(resp.is_ok(), is_ok);
    if is_ok {
        let resp = resp.unwrap();
        assert!(resp.is_some());
        let data = resp.unwrap().data.unwrap();
        let keys = data["keys"].as_array();
        assert_eq!(keys.unwrap().len(), keys_len);
    }
}

#[maybe_async::maybe_async]
async fn test_default_secret(core: &Core, token: &str) {
    // default secret/ mount is now kv-v2, so use data/ prefix
    let kv_data = json!({
        "data": {
            "foo": "bar",
            "zip": "zap",
        }
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "secret/data/goo", true, Some(kv_data.clone())).await;

    // get secret - kv-v2 returns nested data
    let mut req = Request::new("secret/data/goo");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert!(resp.is_some());
    let data = resp.unwrap().data.unwrap();
    assert_eq!(data["data"]["foo"].as_str().unwrap(), "bar");
    assert_eq!(data["data"]["zip"].as_str().unwrap(), "zap");
    assert_eq!(data["metadata"]["version"].as_u64().unwrap(), 1);

    // non-existent secret returns None
    test_read_api(core, token, "secret/data/foo", true, None).await;

    // non-existent mount
    test_read_api(core, token, "secret1/foo", false, None).await;

    // list metadata
    test_list_api(core, token, "secret/metadata/", true, 1).await;
}

#[maybe_async::maybe_async]
async fn test_kv_logical_backend(core: &Core, token: &str) {
    // mount kv backend to path: kv/
    let mount_data = json!({
        "type": "kv",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/mounts/kv/", true, Some(mount_data)).await;

    let kv_data = json!({
        "foo": "bar",
        "zip": "zap",
    })
    .as_object()
    .unwrap()
    .clone();

    test_read_api(core, token, "secret/data/foo", true, None).await;

    // create secret
    test_write_api(core, token, "kv/secret", true, Some(kv_data.clone())).await;
    test_write_api(core, token, "kv1/secret", false, Some(kv_data.clone())).await;

    // get secret
    test_read_api(core, token, "kv/secret", true, Some(kv_data)).await;
    test_read_api(core, token, "kv/secret1", true, None).await;

    // list secret
    test_list_api(core, token, "kv/", true, 1).await;

    // update secret
    let kv_data = json!({
        "foo": "bar",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "kv/secret", true, Some(kv_data.clone())).await;

    // check whether the secret is updated successfully
    test_read_api(core, token, "kv/secret", true, Some(kv_data)).await;

    // add secret
    let kv_data = json!({
        "foo": "bar",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "kv/foo", true, Some(kv_data.clone())).await;

    // list secret
    test_list_api(core, token, "kv/", true, 2).await;

    // delete secret
    test_delete_api(core, token, "kv/secret", true).await;
    test_delete_api(core, token, "kv/secret11", true).await;

    // list secret again
    test_list_api(core, token, "kv/", true, 1).await;

    // remount kv backend to path: kv/
    let remount_data = json!({
        "from": "kv",
        "to": "vk",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/remount", true, Some(remount_data)).await;

    // get secret from new mount path
    test_read_api(core, token, "vk/foo", true, Some(kv_data)).await;

    // unmount
    test_delete_api(core, token, "sys/mounts/vk/", true).await;

    // Getting the secret should fail
    test_read_api(core, token, "vk/foo", false, None).await;
}

#[maybe_async::maybe_async]
async fn test_kv_v2_logical_backend(core: &Core, token: &str) {
    // mount kv-v2 backend to path: kvv2/
    let mount_data = json!({
        "type": "kv-v2",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/mounts/kvv2/", true, Some(mount_data)).await;

    // --- Write v1 ---
    let write_data = json!({
        "data": { "username": "admin", "password": "secret1" }
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(write_data);
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["version"].as_u64().unwrap(), 1);

    // --- Write v2 ---
    let write_data = json!({
        "data": { "username": "admin", "password": "secret2" }
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(write_data);
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["version"].as_u64().unwrap(), 2);

    // --- Read latest (should be v2) ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["data"]["password"].as_str().unwrap(), "secret2");
    assert_eq!(data["metadata"]["version"].as_u64().unwrap(), 2);

    // --- Read specific version (v1) ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    req.body = Some(json!({"version": 1}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["data"]["password"].as_str().unwrap(), "secret1");
    assert_eq!(data["metadata"]["version"].as_u64().unwrap(), 1);

    // --- Soft-delete v1 ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    req.body = Some(json!({"versions": [1]}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());

    // --- Read soft-deleted v1 — should return with warning ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    req.body = Some(json!({"version": 1}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    assert!(!resp.warnings.is_empty());

    // --- Undelete v1 ---
    let mut req = Request::new("kvv2/undelete/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(json!({"versions": [1]}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());

    // --- Read v1 again — should succeed ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    req.body = Some(json!({"version": 1}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["data"]["password"].as_str().unwrap(), "secret1");

    // --- Destroy v1 (permanent) ---
    let mut req = Request::new("kvv2/destroy/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(json!({"versions": [1]}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());

    // --- Read destroyed v1 — should fail ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    req.body = Some(json!({"version": 1}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_err());

    // --- Undelete destroyed v1 should not work ---
    let mut req = Request::new("kvv2/undelete/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(json!({"versions": [1]}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());

    // --- v1 still destroyed after undelete attempt ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    req.body = Some(json!({"version": 1}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_err());

    // --- CAS: write with correct cas ---
    let write_data = json!({
        "data": { "username": "admin", "password": "secret3" },
        "options": { "cas": 2 }
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(write_data);
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["version"].as_u64().unwrap(), 3);

    // --- CAS: write with wrong cas (should fail) ---
    let write_data = json!({
        "data": { "username": "admin", "password": "secret4" },
        "options": { "cas": 1 }
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(write_data);
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_err());

    // --- Engine config: set max_versions ---
    let config_data = json!({
        "max_versions": 2,
        "cas_required": false,
        "delete_version_after": "0s"
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("kvv2/config");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(config_data);
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());

    // --- Read config ---
    let mut req = Request::new("kvv2/config");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["max_versions"].as_u64().unwrap(), 2);

    // --- Write v4, v5 to trigger max_versions pruning ---
    let write_data = json!({
        "data": { "username": "admin", "password": "secret4" }
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(write_data);
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let data = resp.unwrap().unwrap().data.unwrap();
    assert_eq!(data["version"].as_u64().unwrap(), 4);

    let write_data = json!({
        "data": { "username": "admin", "password": "secret5" }
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(write_data);
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let data = resp.unwrap().unwrap().data.unwrap();
    assert_eq!(data["version"].as_u64().unwrap(), 5);

    // --- Read metadata to verify pruning ---
    let mut req = Request::new("kvv2/metadata/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["current_version"].as_u64().unwrap(), 5);
    let versions = data["versions"].as_object().unwrap();
    assert_eq!(versions.len(), 2); // only 2 versions kept due to max_versions

    // --- List metadata ---
    let mut req = Request::new("kvv2/metadata/");
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap().unwrap();
    let data = resp.data.unwrap();
    let keys = data["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);

    // --- Metadata hard-delete ---
    let mut req = Request::new("kvv2/metadata/myapp");
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());

    // --- Verify secret is gone ---
    let mut req = Request::new("kvv2/data/myapp");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    assert!(resp.unwrap().is_none());

    // --- Unmount ---
    test_delete_api(core, token, "sys/mounts/kvv2/", true).await;
}

#[maybe_async::maybe_async]
async fn test_sys_mount_feature(core: &Core, token: &str) {
    // test api: "mounts"
    let mut req = Request::new("sys/mounts");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert!(resp.is_some());
    let data = resp.unwrap().data;
    assert!(data.is_some());
    // Default core mounts: secret/, resources/, files/, identity/,
    // resource-group/, sys/.
    assert_eq!(data.as_ref().unwrap().len(), 6);

    // test api: "mounts/kv" with valid type
    let mount_data = json!({
        "type": "kv",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/mounts/kv/", true, Some(mount_data.clone())).await;

    // test api: "mounts/kv" with path conflict
    test_write_api(core, token, "sys/mounts/kv/", false, Some(mount_data)).await;

    // test api: "mounts/nope" with valid type
    let mount_data = json!({
        "type": "nope",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/mounts/nope/", false, Some(mount_data)).await;

    // test api: "remount" with valid path
    let remount_data = json!({
        "from": "kv",
        "to": "vk",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/remount", true, Some(remount_data)).await;

    // test api: "remount" with invalid path
    let remount_data = json!({
        "from": "unknow",
        "to": "vvk",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/remount", false, Some(remount_data)).await;

    // test api: "remount" with dis-path conflict
    let remount_data = json!({
        "from": "vk",
        "to": "secret",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/remount", false, Some(remount_data)).await;

    // test api: "remount" with protect path
    let remount_data = json!({
        "from": "sys",
        "to": "foo",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/remount", false, Some(remount_data)).await;

    // test api: "remount" with default src-path
    let remount_data = json!({
        "from": "secret",
        "to": "bar",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/remount", true, Some(remount_data)).await;
}

#[maybe_async::maybe_async]
async fn test_sys_raw_api_feature(core: &Core, token: &str) {
    // test raw read
    let mut req = Request::new("sys/raw/core/mounts");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let data = resp.unwrap().data;
    assert!(data.is_some());
    assert_ne!(data.as_ref().unwrap().len(), 0);
    assert!(data.as_ref().unwrap()["value"].as_str().unwrap().starts_with('{'));

    // test raw write
    let test_data = json!({
        "value": "my test data",
    })
    .as_object()
    .unwrap()
    .clone();
    test_write_api(core, token, "sys/raw/test", true, Some(test_data.clone())).await;

    // test raw read again
    let mut req = Request::new("sys/raw/test");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let data = resp.unwrap().data;
    assert!(data.is_some());
    assert_eq!(data.as_ref().unwrap()["value"].as_str().unwrap(), test_data["value"].as_str().unwrap());

    // test raw delete
    test_delete_api(core, token, "sys/raw/test", true).await;

    // test raw read again
    test_read_api(core, token, "sys/raw/test", true, None).await;
}

#[maybe_async::maybe_async]
async fn test_rvualt_mount(bvault: &BastionVault, token: &str) {
    let ret = bvault.mount(Some(token), "kv9/test", "kv").await;
    assert!(ret.is_ok());

    let ret = bvault
        .write(
            Some(token),
            "kv9/test/foo",
            Some(
                json!({
                    "foo": "bar",
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;
    assert!(ret.is_ok());

    let ret = bvault.read(Some(token), "kv9/test/foo").await;
    assert!(ret.is_ok());
    let ret = ret.unwrap();
    assert!(ret.is_some());
    let data = ret.unwrap().data;
    assert!(data.is_some());
    assert_eq!(data.as_ref().unwrap()["foo"].as_str().unwrap(), "bar");

    let ret = bvault
        .write(
            Some(token),
            "kv9/test/bar/foo",
            Some(
                json!({
                    "bar": "foo",
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await;
    assert!(ret.is_ok());

    let ret = bvault.read(Some(token), "kv9/test/bar/foo").await;
    assert!(ret.is_ok());
    let ret = ret.unwrap();
    assert!(ret.is_some());
    let data = ret.unwrap().data;
    assert!(data.is_some());
    assert_eq!(data.as_ref().unwrap()["bar"].as_str().unwrap(), "foo");

    let ret = bvault.list(Some(token), "kv9/test/").await;
    assert!(ret.is_ok());
    let ret = ret.unwrap();
    assert!(ret.is_some());
    let data = ret.unwrap().data;
    assert!(data.is_some());
    assert_eq!(data.as_ref().unwrap()["keys"].as_array().unwrap().len(), 2);

    let ret = bvault.delete(Some(token), "kv9/test/foo", None).await;
    assert!(ret.is_ok());

    let ret = bvault.list(Some(token), "kv9/test/").await;
    assert!(ret.is_ok());
    let ret = ret.unwrap();
    assert!(ret.is_some());
    let data = ret.unwrap().data;
    assert!(data.is_some());
    assert_eq!(data.as_ref().unwrap()["keys"].as_array().unwrap().len(), 1);

    let ret = bvault.unmount(Some(token), "kv9/test").await;
    assert!(ret.is_ok());

    let ret = bvault.list(Some(token), "kv9/test/").await;
    assert!(ret.is_err());
}

#[maybe_async::maybe_async]
async fn test_sys_logical_backend(core: &Core, token: &str) {
    test_sys_mount_feature(core, token).await;
    test_sys_raw_api_feature(core, token).await;
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_default_logical() {
    use bastion_vault::BastionVault;

    let dir = env::temp_dir().join("bastion_vault_core_init");
    let _ = fs::remove_dir_all(&dir);
    assert!(fs::create_dir_all(&dir).is_ok());
    defer! (
        assert!(fs::remove_dir_all(&dir).is_ok());
    );

    let mut root_token = String::new();
    println!("root_token: {:?}", root_token);

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

    let backend = storage::new_backend("file", &conf).unwrap();

    let bvault = BastionVault::new(backend, None).unwrap();
    let core = bvault.core.load();

    let seal_config = SealConfig { secret_shares: 10, secret_threshold: 5 };

    let result = bvault.init(&seal_config).await;
    assert!(result.is_ok());
    let init_result = result.unwrap();
    println!("init_result: {:?}", init_result);

    let mut unsealed = false;
    for i in 0..seal_config.secret_threshold {
        let key = &init_result.secret_shares[i as usize];
        let unseal = bvault.unseal(&[key]).await;
        assert!(unseal.is_ok());
        unsealed = unseal.unwrap();
    }

    root_token = init_result.root_token.clone();

    assert!(unsealed);

    {
        println!("root_token: {:?}", root_token);
        test_default_secret(&core, &root_token).await;
        test_kv_logical_backend(&core, &root_token).await;
        test_kv_v2_logical_backend(&core, &root_token).await;
        test_kv_v2_version_history_tracking(&core, &root_token).await;
        test_resource_metadata_history(&core, &root_token).await;
        test_resource_secret_versioning(&core, &root_token).await;
        test_sys_logical_backend(&core, &root_token).await;
        test_rvualt_mount(&bvault, &root_token).await;
    }
}

// ── History / versioning tests ─────────────────────────────────────

/// Verify KV-v2 now records `username` and `operation` on each version so
/// the GUI can render a who/when/what timeline.
#[maybe_async::maybe_async]
async fn test_kv_v2_version_history_tracking(core: &Core, token: &str) {
    // Mount a fresh kv-v2 engine for this test.
    let mount_data = json!({"type": "kv-v2"})
        .as_object()
        .unwrap()
        .clone();
    test_write_api(core, token, "sys/mounts/hist-kv/", true, Some(mount_data)).await;

    // v1 + v2 writes.
    for i in 1..=2u64 {
        let mut req = Request::new("hist-kv/data/app");
        req.operation = Operation::Write;
        req.client_token = token.to_string();
        req.body = Some(
            json!({ "data": { "k": format!("v{i}") } })
                .as_object()
                .unwrap()
                .clone(),
        );
        let resp = core.handle_request(&mut req).await;
        assert!(resp.is_ok(), "write v{i} failed: {:?}", resp.err());
    }

    // Read latest -> metadata must carry username + operation fields.
    let mut req = Request::new("hist-kv/data/app");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    let meta = &resp.data.as_ref().unwrap()["metadata"];
    assert_eq!(meta["version"].as_u64().unwrap(), 2);
    assert!(meta.get("username").is_some(), "missing username in metadata");
    assert_eq!(meta["operation"].as_str().unwrap(), "update");

    // Read v1 -> operation must be "create".
    let mut req = Request::new("hist-kv/data/app");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    req.body = Some(json!({"version": 1}).as_object().unwrap().clone());
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    let meta = &resp.data.as_ref().unwrap()["metadata"];
    assert_eq!(meta["version"].as_u64().unwrap(), 1);
    assert_eq!(meta["operation"].as_str().unwrap(), "create");

    // metadata/ endpoint should serialize the HashMap including the new fields.
    let mut req = Request::new("hist-kv/metadata/app");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    let versions = resp.data.as_ref().unwrap()["versions"].as_object().unwrap();
    assert_eq!(versions.len(), 2);
    for (_, vm) in versions {
        assert!(vm.get("username").is_some(), "version entry missing username");
        assert!(vm.get("operation").is_some(), "version entry missing operation");
    }

    // Clean up so the mount count check in test_sys_mount_feature (which
    // runs later in the same test_default_logical chain) still matches the
    // number of default mounts.
    test_delete_api(core, token, "sys/mounts/hist-kv/", true).await;
}

/// Verify the resource backend appends an entry to `hist/<name>/...` on
/// create, on update (only when a tracked field changes), and on delete;
/// that the diff identifies the right fields; and that a redundant save
/// (same payload) does NOT generate spurious history.
#[maybe_async::maybe_async]
async fn test_resource_metadata_history(core: &Core, token: &str) {
    // Create
    let mut req = Request::new("resources/resources/web-01");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(
        json!({
            "name": "web-01",
            "type": "server",
            "hostname": "web-01.example.com",
            "owner": "alice",
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    assert!(core.handle_request(&mut req).await.is_ok());

    // Update a real field (hostname)
    let mut req = Request::new("resources/resources/web-01");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(
        json!({
            "name": "web-01",
            "type": "server",
            "hostname": "web-01.new.example.com",
            "owner": "alice",
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    assert!(core.handle_request(&mut req).await.is_ok());

    // No-op write (same payload minus the autogenerated updated_at, which is
    // in the ignored-fields list) -- should NOT append a history entry.
    let mut req = Request::new("resources/resources/web-01");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(
        json!({
            "name": "web-01",
            "type": "server",
            "hostname": "web-01.new.example.com",
            "owner": "alice",
            "updated_at": "2030-01-01T00:00:00Z",
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    assert!(core.handle_request(&mut req).await.is_ok());

    // Fetch the history.
    let mut req = Request::new("resources/resources/web-01/history");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    let entries = resp.data.as_ref().unwrap()["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "expected create + one update, got {}", entries.len());

    // Newest first: the most recent entry is the hostname update.
    let latest = &entries[0];
    assert_eq!(latest["op"].as_str().unwrap(), "update");
    let changed: Vec<String> = latest["changed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(changed, vec!["hostname".to_string()]);

    let oldest = &entries[1];
    assert_eq!(oldest["op"].as_str().unwrap(), "create");

    // Delete the resource -> a new history entry (op="delete") should be appended.
    let mut req = Request::new("resources/resources/web-01");
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    assert!(core.handle_request(&mut req).await.is_ok());

    let mut req = Request::new("resources/resources/web-01/history");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    let entries = resp.data.as_ref().unwrap()["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["op"].as_str().unwrap(), "delete");
}

/// Verify resource secrets now retain every version with its own
/// timestamp / user / operation, and that the historical value can be
/// read back via the `/version/<n>` endpoint.
#[maybe_async::maybe_async]
async fn test_resource_secret_versioning(core: &Core, token: &str) {
    // Create the parent resource first (not strictly required by the
    // secret handlers, but realistic).
    let mut req = Request::new("resources/resources/db-01");
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(
        json!({ "name": "db-01", "type": "database" })
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(core.handle_request(&mut req).await.is_ok());

    // Write the secret three times -- three versions.
    for pass in ["s3cr3t-a", "s3cr3t-b", "s3cr3t-c"] {
        let mut req = Request::new("resources/secrets/db-01/admin");
        req.operation = Operation::Write;
        req.client_token = token.to_string();
        req.body = Some(
            json!({ "password": pass })
                .as_object()
                .unwrap()
                .clone(),
        );
        assert!(core.handle_request(&mut req).await.is_ok());
    }

    // History list (newest first).
    let mut req = Request::new("resources/secrets/db-01/admin/history");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    let data = resp.data.as_ref().unwrap();
    assert_eq!(data["current_version"].as_u64().unwrap(), 3);
    let versions = data["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0]["version"].as_u64().unwrap(), 3);
    assert_eq!(versions[0]["operation"].as_str().unwrap(), "update");
    assert_eq!(versions[2]["version"].as_u64().unwrap(), 1);
    assert_eq!(versions[2]["operation"].as_str().unwrap(), "create");

    // Read back v1 -- old value must still be retrievable.
    let mut req = Request::new("resources/secrets/db-01/admin/version/1");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    let data = resp.data.as_ref().unwrap();
    assert_eq!(data["version"].as_u64().unwrap(), 1);
    assert_eq!(data["data"]["password"].as_str().unwrap(), "s3cr3t-a");
    assert_eq!(data["operation"].as_str().unwrap(), "create");

    // v2 carries the middle value.
    let mut req = Request::new("resources/secrets/db-01/admin/version/2");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    assert_eq!(
        resp.data.as_ref().unwrap()["data"]["password"].as_str().unwrap(),
        "s3cr3t-b"
    );

    // Current read (non-versioned path) still returns the latest.
    let mut req = Request::new("resources/secrets/db-01/admin");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    assert_eq!(
        resp.data.as_ref().unwrap()["password"].as_str().unwrap(),
        "s3cr3t-c"
    );

    // Delete the secret -> history is purged (we do not keep tombstones
    // after explicit deletion; current-value is also gone).
    let mut req = Request::new("resources/secrets/db-01/admin");
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    assert!(core.handle_request(&mut req).await.is_ok());

    let mut req = Request::new("resources/secrets/db-01/admin/history");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap().unwrap();
    assert_eq!(resp.data.as_ref().unwrap()["current_version"].as_u64().unwrap(), 0);
    assert_eq!(
        resp.data.as_ref().unwrap()["versions"].as_array().unwrap().len(),
        0
    );
}
