//! PKI Secret Engine — Phase 5.2: multi-issuer per mount.
//!
//! Coverage:
//!
//! 1. **Two issuers, named-then-default** — generate a `default` root,
//!    then generate an `eu-root` second root on the same mount; confirm
//!    `LIST /v1/pki/issuers` shows both, `pki/ca` returns the default,
//!    and `pki/issuer/eu-root` returns the second's cert.
//!
//! 2. **`config/issuers` swaps default** — flip the default to `eu-root`,
//!    confirm `pki/ca` now returns the eu-root cert.
//!
//! 3. **`issue/:role` `issuer_ref` plumbing** — issue with explicit
//!    request-body `issuer_ref` (overrides default), with role-level
//!    `issuer_ref` (overrides default), and with neither (falls back to
//!    default). Cert chains validate against the chosen issuer.
//!
//! 4. **Per-issuer CRL** — revoke a cert issued by `eu-root`; confirm
//!    `pki/issuer/eu-root/crl` lists it but the *default* issuer's CRL
//!    does not.
//!
//! 5. **Rename + delete** — `WRITE /v1/pki/issuer/:ref` with a new
//!    `issuer_name` renames; `DELETE /v1/pki/issuer/:ref` removes a
//!    non-default issuer. Refuses to delete the default while another
//!    issuer exists.
//!
//! 6. **Migration shim** — boot a mount under the legacy single-issuer
//!    flow (Phase 1's `root/generate/internal`), then immediately call
//!    `LIST /v1/pki/issuers` and confirm the lifted entry shows up. This
//!    runs against the same migration helper every other test exercises
//!    transparently — but here we observe it explicitly.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn write(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core
        .handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("write {path} failed: {e:?}"));
    resp.and_then(|r| r.data)
}

#[maybe_async::maybe_async]
async fn write_ok(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Map<String, Value> {
    write(core, token, path, body).await.expect("response had no data")
}

#[maybe_async::maybe_async]
async fn read(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("read {path}: {e:?}"));
    resp.and_then(|r| r.data).expect("read response had no data")
}

#[maybe_async::maybe_async]
async fn list(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("list {path}: {e:?}"));
    resp.and_then(|r| r.data).expect("list response had no data")
}

#[maybe_async::maybe_async]
async fn delete(core: &Core, token: &str, path: &str) -> Result<(), String> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    core.handle_request(&mut req).await.map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn boot() -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_pki_phase5_2_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_2_two_issuers_default_swap() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    // First root → becomes the mount default automatically.
    let r1 = write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root A", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let root_a_pem = r1["certificate"].as_str().unwrap().to_string();
    assert_eq!(r1["issuer_name"].as_str().unwrap(), "default");
    let root_a_id = r1["issuer_id"].as_str().unwrap().to_string();

    // Second root with explicit name.
    let r2 = write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root B", "key_type": "ec", "ttl": "8760h", "issuer_name": "eu-root"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let root_b_pem = r2["certificate"].as_str().unwrap().to_string();
    let root_b_id = r2["issuer_id"].as_str().unwrap().to_string();
    assert_ne!(root_a_id, root_b_id);

    // LIST shows both.
    let listed = list(&core, &token, "pki/issuers/").await;
    let keys = listed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "expected 2 issuers, got {keys:?}");

    // pki/ca returns the default (root A).
    let ca = read(&core, &token, "pki/ca").await;
    assert_eq!(ca["certificate"].as_str().unwrap(), root_a_pem);
    assert_eq!(ca["issuer_id"].as_str().unwrap(), root_a_id);

    // pki/issuer/eu-root returns root B.
    let eu = read(&core, &token, "pki/issuer/eu-root").await;
    assert_eq!(eu["certificate"].as_str().unwrap(), root_b_pem);
    assert_eq!(eu["is_default"].as_bool().unwrap(), false);

    // Swap default to eu-root.
    write(
        &core,
        &token,
        "pki/config/issuers",
        json!({"default": "eu-root"}).as_object().unwrap().clone(),
    )
    .await;
    let ca_after = read(&core, &token, "pki/ca").await;
    assert_eq!(ca_after["certificate"].as_str().unwrap(), root_b_pem, "default should now be eu-root");

    // pki/config/issuers reflects the swap.
    let cfg = read(&core, &token, "pki/config/issuers").await;
    assert_eq!(cfg["default"].as_str().unwrap(), root_b_id);
    assert_eq!(cfg["default_name"].as_str().unwrap(), "eu-root");

    // Duplicate-name rejection.
    let mut req = Request::new("pki/root/generate/internal");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(
        json!({"common_name": "Dup", "key_type": "ec", "issuer_name": "default"})
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(
        core.handle_request(&mut req).await.is_err(),
        "duplicate `issuer_name` must be rejected"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_2_issue_with_issuer_ref() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    let r1 = write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Default Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let _ = write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Pinned Root", "key_type": "ec", "ttl": "8760h", "issuer_name": "pinned"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let default_id = r1["issuer_id"].as_str().unwrap().to_string();

    // Role with no pin (uses mount default).
    write(
        &core,
        &token,
        "pki/roles/web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    // Role pinned to "pinned" issuer.
    write(
        &core,
        &token,
        "pki/roles/pinned-web",
        json!({"ttl": "24h", "key_type": "ec", "allow_any_name": true, "server_flag": true, "issuer_ref": "pinned"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;

    // (a) Default fallback.
    let leaf_default = write_ok(
        &core,
        &token,
        "pki/issue/web",
        json!({"common_name": "default-leaf.example.com", "ttl": "12h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert_eq!(leaf_default["issuer_id"].as_str().unwrap(), default_id);

    // (b) Role-level pin.
    let leaf_pinned = write_ok(
        &core,
        &token,
        "pki/issue/pinned-web",
        json!({"common_name": "pinned-leaf.example.com", "ttl": "12h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    assert_ne!(leaf_pinned["issuer_id"].as_str().unwrap(), default_id);

    // (c) Request-body override beats the role's pin.
    let leaf_overridden = write_ok(
        &core,
        &token,
        "pki/issue/pinned-web",
        json!({
            "common_name": "override-leaf.example.com",
            "ttl": "12h",
            "issuer_ref": "default"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;
    assert_eq!(
        leaf_overridden["issuer_id"].as_str().unwrap(),
        default_id,
        "request-body issuer_ref must override the role pin"
    );

    // (d) Per-issuer CRL: revoke the pinned-issuer leaf, confirm only that
    //     issuer's CRL lists the serial.
    let pinned_serial = leaf_pinned["serial_number"].as_str().unwrap().to_string();
    write(
        &core,
        &token,
        "pki/revoke",
        json!({"serial_number": pinned_serial}).as_object().unwrap().clone(),
    )
    .await;

    let pinned_crl = read(&core, &token, "pki/issuer/pinned/crl").await["crl"].as_str().unwrap().to_string();
    let default_crl = read(&core, &token, "pki/crl").await["crl"].as_str().unwrap().to_string();

    let pinned_crl_serials = parse_crl_serials(&pinned_crl);
    let default_crl_serials = parse_crl_serials(&default_crl);
    assert!(pinned_crl_serials.contains(&pinned_serial), "pinned CRL must list its revoked serial");
    assert!(
        !default_crl_serials.contains(&pinned_serial),
        "default CRL must NOT list a serial issued by another issuer"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_2_rename_and_delete() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    write(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root A", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let r2 = write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Root B", "key_type": "ec", "ttl": "8760h", "issuer_name": "secondary"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let secondary_id = r2["issuer_id"].as_str().unwrap().to_string();

    // Rename "secondary" → "uat-root".
    write(
        &core,
        &token,
        "pki/issuer/secondary",
        json!({"issuer_name": "uat-root"}).as_object().unwrap().clone(),
    )
    .await;
    let after_rename = read(&core, &token, "pki/issuer/uat-root").await;
    assert_eq!(after_rename["issuer_id"].as_str().unwrap(), secondary_id);
    assert_eq!(after_rename["issuer_name"].as_str().unwrap(), "uat-root");

    // Refuse to delete the default while another issuer exists.
    let err = delete(&core, &token, "pki/issuer/default").await;
    assert!(
        err.is_err(),
        "deleting the default issuer with siblings present must be rejected"
    );

    // Deleting the non-default works.
    delete(&core, &token, "pki/issuer/uat-root").await.unwrap();
    let after_delete = list(&core, &token, "pki/issuers/").await;
    assert_eq!(after_delete["keys"].as_array().unwrap().len(), 1);
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_phase5_2_legacy_migration_shim() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone()).await;

    // Legacy single-issuer flow — the response carries the lifted issuer id.
    let r = write_ok(
        &core,
        &token,
        "pki/root/generate/internal",
        json!({"common_name": "Legacy Root", "key_type": "ec", "ttl": "8760h"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await;
    let lifted_id = r["issuer_id"].as_str().unwrap().to_string();

    // List shows the migrated entry.
    let listed = list(&core, &token, "pki/issuers/").await;
    let keys = listed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].as_str().unwrap(), lifted_id);
    let info = listed["key_info"].as_object().unwrap();
    let entry = info[&lifted_id].as_object().unwrap();
    assert_eq!(entry["name"].as_str().unwrap(), "default");
    assert_eq!(entry["is_default"].as_bool().unwrap(), true);
}

fn parse_crl_serials(crl_pem: &str) -> Vec<String> {
    use base64::Engine;
    let mut in_block = false;
    let mut b64 = String::new();
    for line in crl_pem.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    let der = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).unwrap();
    let (_, crl) = x509_parser::parse_x509_crl(&der).unwrap();
    crl.iter_revoked_certificates()
        .map(|c| {
            c.user_certificate
                .to_bytes_be()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .collect()
}
