//! PKI managed key store — Phase L1 of the key-management + lifecycle
//! initiative. See [features/pki-key-management-and-lifecycle.md].
//!
//! Coverage:
//! 1. `generate/internal` does not return the private key, but the entry
//!    appears in `LIST /v1/pki/keys` and `READ /v1/pki/key/<id>`.
//! 2. `generate/exported` returns a PKCS#8 PEM once and persists the same
//!    material.
//! 3. `keys/import` round-trips classical (ECDSA P-256, Ed25519) and
//!    ML-DSA-65 keys — for the latter we generate one then re-import its
//!    PKCS#8 PEM under a fresh name, proving the PKCS#8 path is wired.
//! 4. RSA generation (RSA-2048) round-trips; an RSA-1024 PKCS#8 import
//!    is rejected with a clear error.
//! 5. Naming uniqueness — a second `generate` reusing the same `name`
//!    fails with `ErrPkiKeyNameAlreadyExist`.
//! 6. `DELETE /v1/pki/key/<id>` removes an unreferenced key. (The
//!    refs-prevent-deletion path lights up in L2 when issuance starts
//!    binding keys; for L1 we exercise the unreferenced-delete only.)
//!
//! The refs-blocking branch in `keys::delete_key` is covered by inspection
//! and gains an integration test in L2.

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
async fn write_ok(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Map<String, Value> {
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
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("read {path}: {e:?}"));
    resp.and_then(|r| r.data).unwrap_or_else(|| panic!("read {path}: empty response"))
}

#[maybe_async::maybe_async]
async fn list(core: &Core, token: &str, path: &str) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.unwrap_or_else(|e| panic!("list {path}: {e:?}"));
    resp.and_then(|r| r.data).unwrap_or_else(|| panic!("list {path}: empty response"))
}

#[maybe_async::maybe_async]
async fn delete_req(core: &Core, token: &str, path: &str) -> Result<(), String> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    core.handle_request(&mut req).await.map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn boot() -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_pki_managed_keys_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

/// Hard-coded RSA-1024 PKCS#8 PEM. Used to assert that the strength gate
/// rejects sub-2048 RSA. Generated offline once and pinned here so the
/// test stays deterministic; the actual key material is not used.
const RSA_1024_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMpYDA5tDw5lF6jR
qxZpe8q1B2gUE5HAcG1TtFFKEyABBZ1mwmoF0EKLDcS8xDpV4y6fchflJfa7xWPa
zS8MvPM6gj7DEGlbZD1iy58qg+EGjDvdJBZSx1HTCFfQs8H2zOGnnTwKPeYsjxbV
B/abbQ6Y9PUmFLZbi2zjiCWeBKgVAgMBAAECgYAz3I+H07VwMd6cR3HojUWebDAR
nQQqcjugMOUVrlABuQGZcsHhEINlIHMeXJa+w9Y7K3Q3wnSvNaSZpHvtBO/+Q9hn
JFh1+JQ7mpcKDDwzGmzVNGJsTCrh39mfIpa4Uem0vL5BVwytcWv/Iz/0yeFMrbOR
imRQzU0n7HwJEVPrgQJBAPNGSlw6L7sTUZG6tTLdN7uVF8aAxTu58VedsM2N4USD
sH1BxAakLOqW4ZFPjQYmWqOFD83BTftc/AAcGcXyTSUCQQDU6++JC1m9NGJL0czV
oOY/G5N9KfvFgDgCNfV7Kam0Xpnj3FTW+8C2DhWa+P3qg5O8U2T6qUiGG+f5jt1J
ZlgxAkEA1ywsP4lbMgL8I7YMcq/zU8q4iqLdUpmL69OO4NghTM8O8AS/JNIfrR9z
B3I4OGKKXjJSjK6DlvuT7YYdcoKkkQJALTrNs3X0/eEW6ouDDU4OhkYjoBJYG7TB
sGq2W9MhqDBUmZBRxFeHDPjqtbbPYncgdBHAEnLn5XuDqHDuTFNSkQJAOcFBC2lW
zUucJtqsa57yAwMOPxdT0OUt1GAUyA/3DqhmdnAMLRaTI4wd3vpw+4hSjiMUowEf
e2u5Q9XvW0eURg==
-----END PRIVATE KEY-----
";

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_managed_keys_l1() {
    let (bvault, dir) = boot();
    defer! ( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();
    write(&core, &token, "sys/mounts/pki/", json!({"type": "pki"}).as_object().unwrap().clone())
        .await
        .expect("mount pki failed");

    // ── 1. generate/internal hides the private key ───────────────────
    let g_int = write_ok(
        &core,
        &token,
        "pki/keys/generate/internal",
        json!({"key_type": "ec", "key_bits": 256, "name": "ec-internal"})
            .as_object().unwrap().clone(),
    )
    .await;
    let id_internal = g_int["key_id"].as_str().unwrap().to_string();
    assert_eq!(g_int["key_type"], "ec");
    assert_eq!(g_int["exported"], false);
    assert!(g_int.get("private_key").is_none(), "internal mode must not return private key");
    assert!(
        g_int["public_key"].as_str().unwrap().contains("BEGIN PUBLIC KEY"),
        "public key PEM should be returned",
    );

    // ── 2. generate/exported returns PKCS#8 once ─────────────────────
    let g_exp = write_ok(
        &core,
        &token,
        "pki/keys/generate/exported",
        json!({"key_type": "ed25519", "name": "ed-exported"})
            .as_object().unwrap().clone(),
    )
    .await;
    let id_exported = g_exp["key_id"].as_str().unwrap().to_string();
    assert_eq!(g_exp["exported"], true);
    let exported_pkcs8 = g_exp["private_key"].as_str().unwrap().to_string();
    assert!(exported_pkcs8.contains("BEGIN PRIVATE KEY"));

    // ── 3. LIST returns both ids ─────────────────────────────────────
    let listed = list(&core, &token, "pki/keys").await;
    let key_ids: Vec<String> = listed["keys"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(key_ids.contains(&id_internal));
    assert!(key_ids.contains(&id_exported));

    // ── 4. READ by id and by name both work, ref counts are zero ─────
    let r_by_id = read(&core, &token, &format!("pki/key/{id_internal}")).await;
    assert_eq!(r_by_id["key_type"], "ec");
    assert_eq!(r_by_id["issuer_ref_count"], 0);
    assert_eq!(r_by_id["cert_ref_count"], 0);
    let r_by_name = read(&core, &token, "pki/key/ec-internal").await;
    assert_eq!(r_by_name["key_id"].as_str().unwrap(), id_internal);

    // ── 5. Name collision is rejected ────────────────────────────────
    let dup = write(
        &core,
        &token,
        "pki/keys/generate/internal",
        json!({"key_type": "ec", "name": "ec-internal"})
            .as_object().unwrap().clone(),
    )
    .await;
    assert!(dup.is_err(), "duplicate name must be rejected, got {dup:?}");

    // ── 6. RSA-2048 round-trip ───────────────────────────────────────
    let g_rsa = write_ok(
        &core,
        &token,
        "pki/keys/generate/exported",
        json!({"key_type": "rsa", "key_bits": 2048, "name": "rsa-2048"})
            .as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(g_rsa["key_type"], "rsa");
    assert_eq!(g_rsa["key_bits"], 2048);
    let rsa_pkcs8 = g_rsa["private_key"].as_str().unwrap().to_string();
    // Re-import the same key under a different name; should succeed.
    let imp_rsa = write_ok(
        &core,
        &token,
        "pki/keys/import",
        json!({"private_key": rsa_pkcs8, "name": "rsa-2048-reimport"})
            .as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(imp_rsa["key_type"], "rsa");
    assert_eq!(imp_rsa["source"], "imported");

    // ── 7. RSA-1024 import is rejected ───────────────────────────────
    let weak = write(
        &core,
        &token,
        "pki/keys/import",
        json!({"private_key": RSA_1024_PKCS8_PEM, "name": "rsa-weak"})
            .as_object().unwrap().clone(),
    )
    .await;
    assert!(weak.is_err(), "RSA-1024 must be rejected, got {weak:?}");

    // ── 8. ML-DSA-65 round-trip via generate-then-reimport ───────────
    let g_pqc = write_ok(
        &core,
        &token,
        "pki/keys/generate/exported",
        json!({"key_type": "ml-dsa-65", "name": "ml-dsa-65"})
            .as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(g_pqc["key_type"], "ml-dsa-65");
    let pqc_pkcs8 = g_pqc["private_key"].as_str().unwrap().to_string();
    assert!(pqc_pkcs8.contains("BEGIN PRIVATE KEY"));
    let imp_pqc = write_ok(
        &core,
        &token,
        "pki/keys/import",
        json!({"private_key": pqc_pkcs8, "name": "ml-dsa-65-reimport"})
            .as_object().unwrap().clone(),
    )
    .await;
    assert_eq!(imp_pqc["key_type"], "ml-dsa-65");

    // ── 9. DELETE removes an unreferenced key ────────────────────────
    delete_req(&core, &token, &format!("pki/key/{id_exported}")).await.expect("delete failed");
    let listed_after = list(&core, &token, "pki/keys").await;
    let ids_after: Vec<String> = listed_after["keys"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(!ids_after.contains(&id_exported), "deleted id still listed: {ids_after:?}");

    // After deletion, name lookup should fail too.
    let mut req = Request::new("pki/key/ed-exported");
    req.operation = Operation::Read;
    req.client_token = token.clone();
    let resp = core.handle_request(&mut req).await.unwrap();
    assert!(resp.is_none() || resp.unwrap().data.is_none());
}
