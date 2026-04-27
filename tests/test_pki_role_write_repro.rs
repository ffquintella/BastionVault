//! Reproducer for the GUI's silent PKI-role-create failure.
//!
//! From a live MCP-driven session against the desktop GUI:
//! clicking **Create role** with TTL `"720"` (no unit), Key type `RSA`,
//! Key bits `0`, Issuer ref `default` produced no toast, no modal close,
//! no console log — and eventually wedged the webview JS bridge.
//!
//! This test reproduces the same body shape the GUI's
//! `pki_write_role` Tauri command builds, and asserts what
//! `core.handle_request` returns. If it returns a clean `Err`, the GUI's
//! catch-block should be firing a toast — and the *secondary* bug is in
//! the GUI's error pipeline. If it deadlocks (test times out via
//! tokio's runtime), the engine itself is the bug.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::SealConfig,
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Value};

#[tokio::test]
async fn test_pki_role_write_with_ttl_missing_unit_repro() {
    let dir = env::temp_dir().join("bastion_vault_pki_role_repro");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    defer!(let _ = fs::remove_dir_all(&dir););

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    // Mount and generate a root so the role write isn't blocked on a
    // missing issuer.
    {
        let mut req = Request::new("sys/mounts/pki/");
        req.operation = Operation::Write;
        req.client_token = token.clone();
        req.body = Some(json!({"type": "pki"}).as_object().unwrap().clone());
        core.handle_request(&mut req).await.unwrap();
    }
    {
        let mut req = Request::new("pki/root/generate/internal");
        req.operation = Operation::Write;
        req.client_token = token.clone();
        req.body = Some(
            json!({
                "common_name": "repro-root.example",
                "key_type": "ec",
                "key_bits": 256,
                "ttl": "8760h"
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        core.handle_request(&mut req).await.unwrap();
    }

    // The exact body shape `commands::pki::pki_write_role` builds when
    // the GUI's Create role modal is submitted with the user's input.
    // Note `ttl: "720"` with no unit — that's what the React state
    // carries when the operator types "720" into the TTL field which
    // shows "720h" only as a placeholder.
    let body = json!({
        "ttl": "720",
        "max_ttl": "",
        "key_type": "rsa",
        "key_bits": 0u64,
        "allow_localhost": true,
        "allow_any_name": true,
        "allow_subdomains": false,
        "allow_bare_domains": false,
        "allow_ip_sans": true,
        "server_flag": true,
        "client_flag": true,
        "use_csr_sans": true,
        "use_csr_common_name": true,
        "key_usage": "DigitalSignature,KeyEncipherment",
        "ext_key_usage": "",
        "country": "",
        "province": "",
        "locality": "",
        "organization": "",
        "ou": "",
        "no_store": false,
        "generate_lease": false,
        "issuer_ref": "default"
    })
    .as_object()
    .unwrap()
    .clone();

    let mut req = Request::new("pki/roles/web-server");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(body);
    let result = core.handle_request(&mut req).await;

    // What we expect: clean Err with a parseable error message —
    // *not* a hang, *not* a panic. If this is the user-visible bug,
    // the GUI's surfacing path is what's broken (toast not firing).
    println!("pki_write_role result with ttl='720': {result:?}");
    assert!(
        result.is_err(),
        "ttl '720' (no unit) must reject; got Ok which means humantime quietly accepted it"
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    println!("error message: {msg}");
    // Regression for the GUI's "silent failure" report: the error must
    // (a) name the field, (b) echo the bad value, and (c) point at the
    // fix. A generic "Request field is invalid." is what we used to
    // emit and is what made the failure look silent.
    assert!(msg.contains("ttl"), "error must name the field, got: {msg}");
    assert!(msg.contains("'720'"), "error must echo the bad value, got: {msg}");
    assert!(
        msg.contains("720h") || msg.contains("unit"),
        "error must point at the fix, got: {msg}"
    );

    // Sanity: with a valid TTL the same call must succeed. Establishes
    // that the only thing wrong with the original body is the TTL.
    let mut good_body = json!({
        "ttl": "720h",
        "max_ttl": "",
        "key_type": "rsa",
        "key_bits": 0u64,
        "issuer_ref": "default"
    })
    .as_object()
    .unwrap()
    .clone();
    // Carry forward the rest of the GUI's defaults so the only delta
    // between the failing call above and this one is the unit on TTL.
    for (k, v) in [
        ("allow_localhost", json!(true)),
        ("allow_any_name", json!(true)),
        ("allow_subdomains", json!(false)),
        ("allow_bare_domains", json!(false)),
        ("allow_ip_sans", json!(true)),
        ("server_flag", json!(true)),
        ("client_flag", json!(true)),
        ("use_csr_sans", json!(true)),
        ("use_csr_common_name", json!(true)),
        ("key_usage", json!("DigitalSignature,KeyEncipherment")),
        ("ext_key_usage", json!("")),
        ("organization", json!("")),
        ("no_store", json!(false)),
        ("generate_lease", json!(false)),
    ] {
        good_body.insert(k.into(), v);
    }
    let mut req = Request::new("pki/roles/web-server");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(good_body);
    let ok = core.handle_request(&mut req).await;
    assert!(
        ok.is_ok(),
        "the same body with ttl='720h' must succeed; got: {ok:?}"
    );
}
