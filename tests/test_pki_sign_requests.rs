//! PKI inbound sign-request queue — `pki/sign-request/*`.
//!
//! Covers the whole decision loop for a CSR that was generated somewhere
//! else: import (with self-signature verification and duplicate refusal),
//! the preflight dry run across every role, approval under a role and in
//! verbatim mode, refusal with a recorded reason, the terminality of a
//! decision, and deletion.
//!
//! See features/pki-inbound-sign-requests.md.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::{json, Map, Value};

#[maybe_async::maybe_async]
async fn write(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> Map<String, Value> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core
        .handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("write {path} failed: {e:?}"));
    resp.and_then(|r| r.data).unwrap_or_default()
}

/// Perform a write that is expected to be refused, returning the error text.
#[maybe_async::maybe_async]
async fn write_expect_err(core: &Core, token: &str, path: &str, body: Map<String, Value>) -> String {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    match core.handle_request(&mut req).await {
        Ok(_) => panic!("write {path} was expected to fail but succeeded"),
        Err(e) => format!("{e}"),
    }
}

#[maybe_async::maybe_async]
async fn read(core: &Core, token: &str, path: &str) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core
        .handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("read {path} failed: {e:?}"));
    resp.and_then(|r| r.data)
}

#[maybe_async::maybe_async]
async fn list(core: &Core, token: &str, path: &str) -> Vec<String> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core
        .handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("list {path} failed: {e:?}"));
    resp.and_then(|r| r.data)
        .and_then(|d| d.get("keys").cloned())
        .and_then(|v| v.as_array().cloned())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

#[maybe_async::maybe_async]
async fn delete(core: &Core, token: &str, path: &str) {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    core.handle_request(&mut req)
        .await
        .unwrap_or_else(|e| panic!("delete {path} failed: {e:?}"));
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn boot() -> (BastionVault, std::path::PathBuf) {
    let dir = env::temp_dir().join(format!("bastion_vault_pki_signreq_{}", rand_suffix()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

fn rand_suffix() -> String {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    format!("{n:08x}")
}

/// A CSR built the way a third party would: our own keypair, our own DN.
fn build_csr(common_name: &str, sans: &[&str]) -> String {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.serialize_request(&kp).unwrap().pem().unwrap()
}

fn pem_decode_first(pem: &str) -> Vec<u8> {
    use base64::Engine;
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
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
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

/// Mount a PKI engine with a CA, a permissive role and a role locked to
/// one domain, so the preflight has something to refuse.
#[maybe_async::maybe_async]
async fn setup(core: &Core, token: &str) {
    write(core, token, "sys/mounts/pki/", obj(json!({"type": "pki"}))).await;
    write(
        core,
        token,
        "pki/root/generate/internal",
        obj(json!({"common_name": "signreq-root.example.com", "key_type": "ec", "ttl": "8760h"})),
    )
    .await;
    write(
        core,
        token,
        "pki/roles/open",
        obj(json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": false,
            "use_csr_common_name": true, "use_csr_sans": true
        })),
    )
    .await;
    write(
        core,
        token,
        "pki/roles/locked",
        obj(json!({
            "ttl": "24h", "max_ttl": "72h", "key_type": "rsa", "key_bits": 2048,
            "allow_any_name": false, "allow_localhost": false,
            "allowed_domains": ["allowed.example.com"], "allow_subdomains": true,
            "use_csr_common_name": true, "use_csr_sans": true
        })),
    )
    .await;
}

#[maybe_async::maybe_async]
async fn unsealed(bvault: &BastionVault) -> String {
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    init.root_token.clone()
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sign_request_import_records_the_parsed_csr() {
    let (bvault, dir) = boot();
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unsealed(&bvault).await;
    setup(&core, &token).await;

    let csr = build_csr("leaf.example.com", &["leaf.example.com", "leaf-alt.example.com"]);
    let imported = write(
        &core,
        &token,
        "pki/sign-request/import",
        obj(json!({"csr": csr, "requester": "ops@example.com", "notes": "TICKET-42", "suggested_role": "open"})),
    )
    .await;

    let id = imported["request_id"].as_str().unwrap().to_string();
    assert!(!id.is_empty());
    assert_eq!(imported["status"], json!("pending"));
    assert_eq!(imported["common_name"], json!("leaf.example.com"));
    assert_eq!(imported["key_description"], json!("ec-p256"));
    assert_eq!(imported["requester"], json!("ops@example.com"));
    assert_eq!(imported["notes"], json!("TICKET-42"));
    assert_eq!(imported["suggested_role"], json!("open"));
    assert_eq!(imported["spki_sha256"].as_str().unwrap().len(), 64);
    let sans: Vec<String> = imported["dns_sans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(sans.contains(&"leaf-alt.example.com".to_string()), "SANs: {sans:?}");
    // The import response must never carry a private key — the engine
    // never had one for an inbound CSR.
    assert!(imported.get("private_key").is_none());

    // Listed, and readable with the CSR served back verbatim.
    assert!(list(&core, &token, "pki/sign-request").await.contains(&id));
    let record = read(&core, &token, &format!("pki/sign-request/{id}")).await.unwrap();
    assert_eq!(record["status"], json!("pending"));
    assert!(record["csr"].as_str().unwrap().contains("BEGIN CERTIFICATE REQUEST"));

    // A resend of the same key is refused rather than silently parked twice.
    let err = write_expect_err(
        &core,
        &token,
        "pki/sign-request/import",
        obj(json!({"csr": csr})),
    )
    .await;
    assert!(err.contains(&id), "duplicate refusal should name the pending request: {err}");
    // …unless the operator says so explicitly.
    let dup = write(
        &core,
        &token,
        "pki/sign-request/import",
        obj(json!({"csr": csr, "allow_duplicate": true})),
    )
    .await;
    assert_ne!(dup["request_id"], imported["request_id"]);

    // A CSR whose self-signature does not verify is refused outright, not
    // parked for someone to approve later.
    let before = list(&core, &token, "pki/sign-request").await.len();
    let _ = write_expect_err(
        &core,
        &token,
        "pki/sign-request/import",
        obj(json!({"csr": csr.replace('A', "B")})),
    )
    .await;
    assert_eq!(list(&core, &token, "pki/sign-request").await.len(), before);
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sign_request_preflight_reports_every_role() {
    let (bvault, dir) = boot();
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unsealed(&bvault).await;
    setup(&core, &token).await;

    let csr = build_csr("leaf.example.com", &["leaf.example.com"]);
    let imported = write(&core, &token, "pki/sign-request/import", obj(json!({"csr": csr}))).await;
    let id = imported["request_id"].as_str().unwrap().to_string();

    // No mode, no role → verbatim plus every role on the mount.
    let pre = write(
        &core,
        &token,
        &format!("pki/sign-request/{id}/preflight"),
        Map::new(),
    )
    .await;
    let verdicts = pre["verdicts"].as_array().unwrap().clone();
    assert_eq!(verdicts.len(), 3, "verbatim + 2 roles: {verdicts:?}");

    let find = |mode: &str, role: &str| -> Value {
        verdicts
            .iter()
            .find(|v| v["mode"] == json!(mode) && v["role"] == json!(role))
            .cloned()
            .unwrap_or_else(|| panic!("no verdict for {mode}/{role} in {verdicts:?}"))
    };

    let open = find("role", "open");
    assert_eq!(open["allowed"], json!(true));
    assert_eq!(open["common_name"], json!("leaf.example.com"));
    assert_eq!(open["ttl_seconds"], json!(24 * 3600));
    assert!(!open["issuer_id"].as_str().unwrap().is_empty());

    // The locked role refuses this CN, and says which value it refused.
    let locked = find("role", "locked");
    assert_eq!(locked["allowed"], json!(false));
    let hints = locked["hints"].as_array().unwrap();
    assert!(
        hints.iter().any(|h| h.as_str().unwrap().contains("leaf.example.com")),
        "hints should name the refused CN: {hints:?}"
    );

    // Verbatim is allowed but flagged as policy-bypassing.
    let verbatim = find("verbatim", "");
    assert_eq!(verbatim["allowed"], json!(true));
    let warnings = verbatim["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|w| w.as_str().unwrap().contains("bypasses role policy")),
        "verbatim must warn: {warnings:?}"
    );

    // The role key-type mismatch is a warning on the open role's sibling,
    // not a refusal: signing a foreign CSR never enforced role.key_type.
    let locked_hints_only = find("role", "locked");
    assert!(locked_hints_only["allowed"] == json!(false));

    // Preflight is a dry run: the record is untouched and nothing issued.
    let record = read(&core, &token, &format!("pki/sign-request/{id}")).await.unwrap();
    assert_eq!(record["status"], json!("pending"));
    assert_eq!(record["serial_number"], json!(""));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sign_request_approve_issues_and_is_terminal() {
    let (bvault, dir) = boot();
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unsealed(&bvault).await;
    setup(&core, &token).await;

    let csr = build_csr("leaf.example.com", &["leaf.example.com"]);
    let imported = write(&core, &token, "pki/sign-request/import", obj(json!({"csr": csr}))).await;
    let id = imported["request_id"].as_str().unwrap().to_string();

    // A role that refuses the CN refuses the approval too, and the
    // request stays pending — a failed approval is not a decision.
    let _ = write_expect_err(
        &core,
        &token,
        &format!("pki/sign-request/{id}/approve"),
        obj(json!({"role": "locked"})),
    )
    .await;
    let still = read(&core, &token, &format!("pki/sign-request/{id}")).await.unwrap();
    assert_eq!(still["status"], json!("pending"));

    // Approving under the permissive role issues the cert and records it.
    let approved = write(
        &core,
        &token,
        &format!("pki/sign-request/{id}/approve"),
        obj(json!({"role": "open", "ttl": "12h"})),
    )
    .await;
    assert_eq!(approved["status"], json!("signed"));
    assert_eq!(approved["sign_mode"], json!("role"));
    assert_eq!(approved["role"], json!("open"));
    let cert_pem = approved["certificate"].as_str().unwrap().to_string();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    let serial = approved["serial_number"].as_str().unwrap().to_string();
    assert!(!serial.is_empty());
    assert!(!approved["ca_chain"].as_array().unwrap().is_empty());
    assert!(approved.get("private_key").is_none());

    // It chains to the mount's CA and carries the CSR's CN.
    let leaf_der = pem_decode_first(&cert_pem);
    let ca_der = pem_decode_first(approved["issuing_ca"].as_str().unwrap());
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
    assert_eq!(leaf.issuer().to_string(), ca.subject().to_string());
    assert!(leaf.subject().to_string().contains("leaf.example.com"));

    // The issued cert is in the mount's index, so revocation works on it.
    assert!(read(&core, &token, &format!("pki/cert/{serial}")).await.is_some());

    // The decision is terminal in both directions.
    let err = write_expect_err(
        &core,
        &token,
        &format!("pki/sign-request/{id}/approve"),
        obj(json!({"role": "open"})),
    )
    .await;
    assert!(err.contains("signed"), "re-approval should be refused: {err}");
    let err = write_expect_err(
        &core,
        &token,
        &format!("pki/sign-request/{id}/reject"),
        obj(json!({"reason": "changed my mind"})),
    )
    .await;
    assert!(err.contains("signed"), "rejecting a signed request should be refused: {err}");

    // The record keeps the outcome, and read still returns the CSR.
    let record = read(&core, &token, &format!("pki/sign-request/{id}")).await.unwrap();
    assert_eq!(record["serial_number"], json!(serial));
    assert!(record["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));

    delete(&core, &token, &format!("pki/sign-request/{id}")).await;
    assert!(read(&core, &token, &format!("pki/sign-request/{id}")).await.is_none());
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sign_request_verbatim_bypasses_role_policy() {
    let (bvault, dir) = boot();
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unsealed(&bvault).await;
    setup(&core, &token).await;

    // A CN no role on this mount permits, and an IP SAN.
    let csr = build_csr("nobody.invalid", &["nobody.invalid", "10.0.0.7"]);
    let imported = write(&core, &token, "pki/sign-request/import", obj(json!({"csr": csr}))).await;
    let id = imported["request_id"].as_str().unwrap().to_string();

    let approved = write(
        &core,
        &token,
        &format!("pki/sign-request/{id}/approve-verbatim"),
        Map::new(),
    )
    .await;
    assert_eq!(approved["status"], json!("signed"));
    assert_eq!(approved["sign_mode"], json!("verbatim"));
    assert_eq!(approved["role"], json!(""));
    // 30-day ceiling for the role-less path.
    assert_eq!(approved["ttl_seconds"], json!(30 * 24 * 3600));
    let leaf_der = pem_decode_first(approved["certificate"].as_str().unwrap());
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
    assert!(leaf.subject().to_string().contains("nobody.invalid"));

    // Verbatim has no role to authorise a key pin or an AD claim against,
    // so both are refused rather than silently dropped.
    let csr2 = build_csr("other.invalid", &["other.invalid"]);
    let second = write(&core, &token, "pki/sign-request/import", obj(json!({"csr": csr2}))).await;
    let id2 = second["request_id"].as_str().unwrap().to_string();
    // `approve-verbatim` does not even declare a `key_ref` field, and the
    // role path requires a role — so there is no way to smuggle a key pin
    // into a role-less signature.
    let err = write_expect_err(
        &core,
        &token,
        &format!("pki/sign-request/{id2}/approve"),
        obj(json!({"key_ref": "some-key"})),
    )
    .await;
    assert!(
        err.contains("role") || err.contains("required"),
        "role-mode approval must require a role: {err}"
    );
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sign_request_reject_requires_a_reason_and_is_recorded() {
    let (bvault, dir) = boot();
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unsealed(&bvault).await;
    setup(&core, &token).await;

    let csr = build_csr("unwanted.example.com", &["unwanted.example.com"]);
    let imported = write(&core, &token, "pki/sign-request/import", obj(json!({"csr": csr}))).await;
    let id = imported["request_id"].as_str().unwrap().to_string();

    // No reason → refused. A rejection with no reason is not a record.
    let _ = write_expect_err(
        &core,
        &token,
        &format!("pki/sign-request/{id}/reject"),
        obj(json!({"reason": "   "})),
    )
    .await;
    assert_eq!(
        read(&core, &token, &format!("pki/sign-request/{id}")).await.unwrap()["status"],
        json!("pending")
    );

    let rejected = write(
        &core,
        &token,
        &format!("pki/sign-request/{id}/reject"),
        obj(json!({"reason": "no ticket, requester unverified"})),
    )
    .await;
    assert_eq!(rejected["status"], json!("rejected"));
    assert_eq!(rejected["reject_reason"], json!("no ticket, requester unverified"));
    assert!(rejected["decided_at"].as_u64().unwrap() > 0);

    // Terminal: a refusal cannot be quietly turned into an approval.
    let err = write_expect_err(
        &core,
        &token,
        &format!("pki/sign-request/{id}/approve"),
        obj(json!({"role": "open"})),
    )
    .await;
    assert!(err.contains("rejected"), "approval after rejection must be refused: {err}");

    // The record survives for the audit trail until explicitly deleted.
    let record = read(&core, &token, &format!("pki/sign-request/{id}")).await.unwrap();
    assert_eq!(record["status"], json!("rejected"));
    assert_eq!(record["serial_number"], json!(""));
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sign_request_unknown_id_is_a_404_not_a_panic() {
    let (bvault, dir) = boot();
    defer!( let _ = fs::remove_dir_all(&dir); );
    let core = bvault.core.load();
    let token = unsealed(&bvault).await;
    setup(&core, &token).await;

    assert!(read(&core, &token, "pki/sign-request/does-not-exist").await.is_none());
    let err = write_expect_err(
        &core,
        &token,
        "pki/sign-request/does-not-exist/approve",
        obj(json!({"role": "open"})),
    )
    .await;
    assert!(err.contains("does-not-exist"), "error should name the id: {err}");
}
