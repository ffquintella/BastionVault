//! PKI certificate ↔ managed-key CRUD lifecycle.
//!
//! Regression coverage for the L8 PKI page bugs:
//!
//! 1. A managed key that backs an issuer must NOT be removable via
//!    `force=true` while the issuer is still mounted — the legacy
//!    migration shim deletes the issuer's own private-key copy after
//!    mirroring it into the managed-key store, so the managed-key entry
//!    is the only signing material the issuer has. Force-deleting it
//!    silently bricks the issuer (revoke + CRL rebuild start failing).
//!
//! 2. Deleting an issuer must clear the issuer→key binding recorded in
//!    `KeyRefs.issuer_ids`. Otherwise a downstream `DELETE pki/key/<id>`
//!    refuses forever, citing a phantom issuer that no longer exists.
//!
//! 3. A cert issued via `key_ref` keeps working (read + delete) even
//!    after its bound managed key is force-dropped from cert refs —
//!    cert reads don't need the key, and `delete_cert` is best-effort
//!    on the binding record.
//!
//! Together these tests exercise the full CRUD loop:
//!
//! - generate / list / read managed key
//! - generate root issuer (which auto-creates the shadow managed-key)
//! - issue cert with `key_ref` → cert record carries `key_id`
//! - read cert → revoke cert → delete cert
//! - delete key (refused while bound) / delete key (allowed once free)
//! - delete issuer → key's issuer ref cleared → key now deletable

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn write(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, String> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req)
        .await
        .map(|r| r.and_then(|x| x.data))
        .map_err(|e| format!("{e:?}"))
}

#[maybe_async::maybe_async]
async fn write_ok(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Map<String, Value> {
    write(core, token, path, body)
        .await
        .unwrap_or_else(|e| panic!("write {path}: {e}"))
        .unwrap_or_else(|| panic!("write {path}: empty response"))
}

#[maybe_async::maybe_async]
async fn read(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core
        .handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("read {path}: {e:?}"));
    resp.and_then(|r| r.data)
        .unwrap_or_else(|| panic!("read {path}: empty response"))
}

#[maybe_async::maybe_async]
async fn read_opt(core: &Core, token: &str, path: &str) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    core.handle_request(&mut req)
        .await
        .ok()
        .and_then(|r| r.and_then(|x| x.data))
}

#[maybe_async::maybe_async]
async fn list(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core
        .handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("list {path}: {e:?}"));
    resp.and_then(|r| r.data)
        .unwrap_or_else(|| panic!("list {path}: empty response"))
}

#[maybe_async::maybe_async]
async fn delete_req(core: &Core, token: &str, path: &str) -> Result<(), String> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    core.handle_request(&mut req)
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

#[maybe_async::maybe_async]
async fn delete_with_body(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Result<(), String> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req)
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

fn boot() -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_pki_cert_key_lifecycle_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

#[maybe_async::maybe_async]
async fn boot_with_root() -> (BastionVault, std::path::PathBuf, String) {
    let (bvault, dir) = boot();
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    write(
        &core,
        &token,
        "sys/mounts/pki/",
        json!({"type": "pki"}).as_object().unwrap().clone(),
    )
    .await
    .expect("mount pki failed");
    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Lifecycle Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("root generate")
    .expect("root response had no data");
    write(
        &core,
        &token,
        "pki/roles/leaf",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
            "allow_key_reuse": true,
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("write role");
    drop(core);
    (bvault, dir, token)
}

/// L8 #1 — `force=true` is **not** sufficient to drop a managed key
/// while it still backs an issuer. The migration shim removed the
/// issuer's `issuers/<id>/key` copy, so the managed-key store is the
/// only signing material the issuer has. Allowing force here would
/// silently brick revoke / CRL rebuild for that issuer.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn test_force_delete_refuses_issuer_bound_key() {
    let (bvault, dir, token) = boot_with_root().await;
    defer!(let _ = fs::remove_dir_all(&dir););
    let core = bvault.core.load();

    // The shadow managed-key the engine minted alongside the root.
    // It's named "<issuer-name>-key" by `add_issuer`. The default
    // root we just generated lands as the only issuer with name
    // "default", so the shadow is "default-key".
    let key = read(&core, &token, "pki/key/default-key").await;
    let key_id = key["key_id"].as_str().unwrap().to_string();
    assert_eq!(key["issuer_ref_count"], 1, "shadow key must record the issuer binding");

    // `force=false` (default): refused with a non-empty refs message.
    let blocked = delete_req(&core, &token, &format!("pki/key/{key_id}")).await;
    assert!(blocked.is_err(), "delete must refuse while issuer-bound: {blocked:?}");

    // `force=true`: still refused — issuer bindings are not bypassable.
    let blocked_force = delete_with_body(
        &core,
        &token,
        &format!("pki/key/{key_id}"),
        json!({"force": true}).as_object().unwrap().clone(),
    )
    .await;
    let err_msg = blocked_force.expect_err("force-delete must refuse issuer-bound key");
    assert!(
        err_msg.to_lowercase().contains("issuer"),
        "error must mention the issuer binding, got: {err_msg}"
    );

    // Sanity: the key, the issuer, and the issuer's signing path
    // are all still intact — issue a cert to confirm.
    let issued = write_ok(
        &core,
        &token,
        "pki/issue/leaf",
        json!({"common_name": "after-blocked-force.example.com"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert!(issued["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
}

/// L8 #2 — Deleting an issuer must clear the matching entry in
/// `KeyRefs.issuer_ids`. Otherwise the shadow managed-key keeps a
/// phantom issuer reference and refuses every subsequent
/// `DELETE pki/key/<id>` (even with `force=true`, by the rule
/// established in test #1).
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn test_delete_issuer_clears_key_refs() {
    let (bvault, dir, token) = boot_with_root().await;
    defer!(let _ = fs::remove_dir_all(&dir););
    let core = bvault.core.load();

    let key_before = read(&core, &token, "pki/key/default-key").await;
    let key_id = key_before["key_id"].as_str().unwrap().to_string();
    assert_eq!(key_before["issuer_ref_count"], 1);

    // Delete the only issuer. The mount goes back to "no CA configured".
    delete_req(&core, &token, "pki/issuer/default")
        .await
        .expect("delete issuer");

    // The shadow managed-key entry is still there (issuer delete does
    // NOT cascade to the key — that's a separate explicit operation),
    // but its issuer_ref_count must now be zero.
    let key_after = read(&core, &token, &format!("pki/key/{key_id}")).await;
    assert_eq!(
        key_after["issuer_ref_count"], 0,
        "issuer-delete must clear the issuer→key binding"
    );

    // And now the key can be deleted without `force`, since refs are empty.
    delete_req(&core, &token, &format!("pki/key/{key_id}"))
        .await
        .expect("delete unbound key");

    let listed = list(&core, &token, "pki/keys").await;
    let ids: Vec<String> = listed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(!ids.contains(&key_id), "unbound key should be gone: {ids:?}");
}

/// L8 #3 — Full CRUD loop for a leaf cert that was issued with
/// `key_ref` (managed-key reuse). Exercises:
///
/// - cert read by serial returns a populated record
/// - revoke clears the cert→key binding so a future force-delete
///   succeeds
/// - cert delete is allowed for revoked records without `force`
/// - and: even if an operator force-drops the cert→key binding while
///   the cert was still active, the cert remains readable and
///   deletable (cert reads are independent of the signing key).
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn test_cert_crud_with_key_ref() {
    let (bvault, dir, token) = boot_with_root().await;
    defer!(let _ = fs::remove_dir_all(&dir););
    let core = bvault.core.load();

    // Generate a leaf-key managed entry the role can reuse.
    let leaf_key = write_ok(
        &core,
        &token,
        "pki/keys/generate/internal",
        json!({"key_type": "ec", "key_bits": 256, "name": "leaf-key"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let leaf_key_id = leaf_key["key_id"].as_str().unwrap().to_string();

    // Allow `key_ref` on the role — boot_with_root already set
    // `allow_key_reuse=true`, but tighten `allowed_key_refs` so the
    // gate's allow-list path is exercised too.
    write(
        &core,
        &token,
        "pki/roles/leaf",
        json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
            "allow_key_reuse": true, "allowed_key_refs": "leaf-key",
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await
    .expect("update role");

    // Issue two certs against the same managed key.
    let issued1 = write_ok(
        &core,
        &token,
        "pki/issue/leaf",
        json!({"common_name": "alpha.example.com", "key_ref": "leaf-key"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let serial1 = issued1["serial_number"].as_str().unwrap().to_string();
    assert_eq!(issued1["key_id"].as_str().unwrap(), leaf_key_id);

    let issued2 = write_ok(
        &core,
        &token,
        "pki/issue/leaf",
        json!({"common_name": "beta.example.com", "key_ref": "leaf-key"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let serial2 = issued2["serial_number"].as_str().unwrap().to_string();

    // ── READ: both certs must be visible. ──
    let r1 = read(&core, &token, &format!("pki/cert/{serial1}")).await;
    assert!(r1["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    assert_eq!(r1["serial_number"].as_str().unwrap(), serial1);

    let key_now = read(&core, &token, "pki/key/leaf-key").await;
    assert_eq!(key_now["cert_ref_count"], 2, "two issuances bound to the same key");

    // ── DELETE-key while bound: refused without force. ──
    let blocked =
        delete_req(&core, &token, &format!("pki/key/{leaf_key_id}")).await;
    assert!(blocked.is_err(), "key delete must refuse while certs are bound");

    // ── REVOKE serial1 → that cert's binding clears → ref count drops. ──
    write(
        &core,
        &token,
        "pki/revoke",
        json!({"serial_number": serial1.clone()})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("revoke serial1")
    .expect("revoke response had no data");
    let after_rev = read(&core, &token, "pki/key/leaf-key").await;
    assert_eq!(
        after_rev["cert_ref_count"], 1,
        "revoke must clear the cert→key binding for serial1"
    );

    // ── DELETE serial1: revoked records can be removed without force. ──
    delete_req(&core, &token, &format!("pki/cert/{serial1}"))
        .await
        .expect("delete revoked serial1");
    assert!(
        read_opt(&core, &token, &format!("pki/cert/{serial1}"))
            .await
            .is_none(),
        "deleted cert must be gone"
    );

    // ── DELETE-key with force while serial2 is still active: allowed
    //    (force bypasses cert-level bindings). serial2's cert record
    //    survives the binding being dropped — cert reads do not need
    //    the signing key.
    delete_with_body(
        &core,
        &token,
        &format!("pki/key/{leaf_key_id}"),
        json!({"force": true}).as_object().unwrap().clone(),
    )
    .await
    .expect("force delete unbinds active cert");
    let key_after_force = read_opt(&core, &token, "pki/key/leaf-key").await;
    assert!(
        key_after_force.as_ref().map(|m| m.is_empty()).unwrap_or(true),
        "leaf key should be gone after force-delete, got: {key_after_force:?}"
    );

    // serial2 — the still-active cert — must remain readable.
    let r2 = read(&core, &token, &format!("pki/cert/{serial2}")).await;
    assert!(
        r2["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"),
        "active cert must survive force-delete of its leaf managed-key"
    );

    // And serial2 must still be deletable; the issuer's own signing
    // key is independent of the leaf managed key, so revoke + delete
    // works end-to-end.
    write(
        &core,
        &token,
        "pki/revoke",
        json!({"serial_number": serial2.clone()})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("revoke serial2")
    .expect("revoke response had no data");
    delete_req(&core, &token, &format!("pki/cert/{serial2}"))
        .await
        .expect("delete revoked serial2");
}

/// L8 #4 — Sanity for the "cert with no managed-key binding" path:
/// engine-issued certs that did **not** use `key_ref` carry no
/// `record.key_id`, so revoke / delete / read all work without ever
/// touching the managed-key store. Adds a regression guard that the
/// fresh-key path stays decoupled from L3 binding bookkeeping.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn test_cert_crud_without_key_ref() {
    let (bvault, dir, token) = boot_with_root().await;
    defer!(let _ = fs::remove_dir_all(&dir););
    let core = bvault.core.load();

    let issued = write_ok(
        &core,
        &token,
        "pki/issue/leaf",
        json!({"common_name": "fresh.example.com"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let serial = issued["serial_number"].as_str().unwrap().to_string();
    // Fresh-key path must NOT echo `key_id` (renewal-binding marker).
    assert!(issued.get("key_id").is_none());

    // List + read.
    let listed = list(&core, &token, "pki/certs").await;
    let serials: Vec<String> = listed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(serials.contains(&serial));
    let r = read(&core, &token, &format!("pki/cert/{serial}")).await;
    assert_eq!(r["serial_number"].as_str().unwrap(), serial);

    // Revoke + delete must succeed without ever touching managed-keys.
    write(
        &core,
        &token,
        "pki/revoke",
        json!({"serial_number": serial.clone()})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("revoke")
    .expect("revoke response had no data");
    delete_req(&core, &token, &format!("pki/cert/{serial}"))
        .await
        .expect("delete revoked cert");

    // Read after delete: gone (None / no data).
    assert!(
        read_opt(&core, &token, &format!("pki/cert/{serial}"))
            .await
            .is_none(),
        "deleted cert must be gone"
    );
}
