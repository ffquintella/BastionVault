//! PKI emission controls — Phase L4 of the key-management +
//! lifecycle initiative. See [features/pki-key-management-and-lifecycle.md].
//!
//! Coverage:
//! 1. `allow_any_name = false` + `allowed_domains = [example.com]` +
//!    `allow_subdomains` → bare `example.com` rejected, `web.example.com`
//!    accepted, `evil.com` rejected. Adding `allow_bare_domains` lets
//!    the bare name through.
//! 2. `allow_glob_domains` enables single-label `*` patterns:
//!    `*-prod.example.com` matches `web-prod.example.com` but not
//!    `web.prod.example.com` and not `notprod.example.com`.
//! 3. DNS SANs are validated alongside the CN — a permitted CN with a
//!    forbidden SAN is rejected.
//! 4. `acme_enabled = false` rejects `pki/acme/new-order` (with an
//!    operator-friendly message) even when ACME is otherwise
//!    configured.
//! 5. Leaf TTL clamped to issuer's remaining NotAfter — a 24h root with
//!    a 168h-requested leaf produces a leaf whose NotAfter does NOT
//!    exceed the root's NotAfter.

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

fn boot() -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_pki_emission_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

fn pem_first_der(pem_text: &str) -> Vec<u8> {
    pem::parse(pem_text.as_bytes()).expect("PEM parse").into_contents()
}

fn cert_not_after(cert_pem: &str) -> i64 {
    let der = pem_first_der(cert_pem);
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
    parsed.tbs_certificate.validity.not_after.timestamp()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_pki_emission_controls_l4() {
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
        .expect("mount pki");

    // Short-lived root (24h) so we can test the issuer-NotAfter clamp
    // against a longer requested leaf TTL.
    let root_resp = write_ok(
        &core, &token, "pki/root/generate/internal",
        json!({"common_name": "L4 Root", "key_type": "ec", "ttl": "24h"})
            .as_object().unwrap().clone(),
    ).await;
    let root_pem = root_resp["certificate"].as_str().unwrap().to_string();
    let root_not_after = cert_not_after(&root_pem);

    // ── 1. allow_subdomains-only role ───────────────────────────────
    write(
        &core, &token, "pki/roles/sub-only",
        json!({
            "ttl": "1h", "max_ttl": "12h", "key_type": "ec",
            "allow_any_name": false,
            "allowed_domains": "example.com",
            "allow_subdomains": true,
            "allow_bare_domains": false,
            "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("write sub-only role");

    let bare = write(
        &core, &token, "pki/issue/sub-only",
        json!({"common_name": "example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(bare.is_err(), "bare domain must be rejected: {bare:?}");
    let evil = write(
        &core, &token, "pki/issue/sub-only",
        json!({"common_name": "evil.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(evil.is_err(), "off-list domain must be rejected: {evil:?}");
    let sub_ok = write_ok(
        &core, &token, "pki/issue/sub-only",
        json!({"common_name": "web.example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(sub_ok["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));

    // ── 2. allow_bare_domains lets the bare name through ────────────
    write(
        &core, &token, "pki/roles/bare-ok",
        json!({
            "ttl": "1h", "max_ttl": "12h", "key_type": "ec",
            "allow_any_name": false,
            "allowed_domains": "example.com",
            "allow_subdomains": true,
            "allow_bare_domains": true,
            "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("write bare-ok role");
    let bare_ok = write_ok(
        &core, &token, "pki/issue/bare-ok",
        json!({"common_name": "example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(bare_ok["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));

    // ── 3. allow_glob_domains for single-label patterns ─────────────
    write(
        &core, &token, "pki/roles/glob",
        json!({
            "ttl": "1h", "max_ttl": "12h", "key_type": "ec",
            "allow_any_name": false,
            "allowed_domains": "*-prod.example.com",
            "allow_glob_domains": true,
            "allow_subdomains": false,
            "allow_bare_domains": false,
            "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("write glob role");
    let g_ok = write_ok(
        &core, &token, "pki/issue/glob",
        json!({"common_name": "web-prod.example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(g_ok["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    let g_dot = write(
        &core, &token, "pki/issue/glob",
        json!({"common_name": "web.prod.example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(g_dot.is_err(), "glob must not span dots: {g_dot:?}");
    let g_no_anchor = write(
        &core, &token, "pki/issue/glob",
        json!({"common_name": "notprod.example.com"}).as_object().unwrap().clone(),
    ).await;
    assert!(g_no_anchor.is_err(), "glob trailing anchor must hold: {g_no_anchor:?}");

    // ── 4. DNS SAN validated alongside CN ───────────────────────────
    let san_bad = write(
        &core, &token, "pki/issue/sub-only",
        json!({
            "common_name": "web.example.com",
            "alt_names": "evil.com",
        }).as_object().unwrap().clone(),
    ).await;
    assert!(san_bad.is_err(), "off-list DNS SAN must be rejected: {san_bad:?}");

    // ── 5. ACME per-role kill-switch ────────────────────────────────
    // Spin up the ACME surface and a role with acme_enabled=false.
    write(
        &core, &token, "pki/roles/no-acme",
        json!({
            "ttl": "1h", "max_ttl": "12h", "key_type": "ec",
            "allow_any_name": true,
            "acme_enabled": false,
        }).as_object().unwrap().clone(),
    ).await.expect("write no-acme role");
    write(
        &core, &token, "pki/acme/config",
        json!({"enabled": true, "default_role": "no-acme"})
            .as_object().unwrap().clone(),
    ).await.expect("write acme config");

    // Construct an ACME new-order envelope minimally — the engine
    // rejects before JWS verification because the role gate fires
    // up-front. We send an empty body; the engine should still
    // surface the role-disabled error before envelope parsing.
    //
    // (Calling `pki/acme/new-order` directly skips JWS — the engine
    // checks `cfg.enabled` and the role gate first.)
    let new_order = write(
        &core, &token, "pki/acme/new-order",
        Map::new(),
    ).await;
    assert!(
        new_order.as_ref()
            .err()
            .map(|e| e.contains("acme_enabled=false"))
            .unwrap_or(false),
        "acme_enabled=false role must reject new-order: {new_order:?}",
    );

    // ── 6. Leaf TTL clamped to issuer's remaining lifetime ──────────
    write(
        &core, &token, "pki/roles/long-ttl",
        json!({
            "ttl": "1h", "max_ttl": "8760h", "key_type": "ec",
            "allow_any_name": true,
            "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("write long-ttl role");
    // Request 168h — root only has 24h left.
    let long = write_ok(
        &core, &token, "pki/issue/long-ttl",
        json!({"common_name": "long.example.com", "ttl": "168h"})
            .as_object().unwrap().clone(),
    ).await;
    let leaf_pem = long["certificate"].as_str().unwrap().to_string();
    let leaf_not_after = cert_not_after(&leaf_pem);
    assert!(
        leaf_not_after <= root_not_after,
        "leaf NotAfter {leaf_not_after} must not exceed root NotAfter {root_not_after}",
    );
}
