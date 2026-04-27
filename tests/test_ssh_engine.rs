//! SSH Secret Engine — Phase 1 (CA mode, Ed25519) integration test.
//!
//! End-to-end: mount the engine, generate the CA, create a role, sign a
//! freshly-generated client public key, and parse the returned cert with
//! `ssh-key` to assert the policy actually landed in the wire format.

use std::{collections::HashMap, env, fs};

use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use go_defer::defer;
use serde_json::{json, Map, Value};
use ssh_key::{rand_core::OsRng, Algorithm, PrivateKey};

#[maybe_async::maybe_async]
async fn write(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    let resp = core.handle_request(&mut req).await.expect("write failed");
    resp.and_then(|r| r.data)
}

#[maybe_async::maybe_async]
async fn read(core: &Core, token: &str, path: &str) -> Option<Map<String, Value>> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await.expect("read failed");
    resp.and_then(|r| r.data)
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn test_ssh_phase1_end_to_end() {
    let dir = env::temp_dir().join("bastion_vault_ssh_phase1");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    defer! ( let _ = fs::remove_dir_all(&dir); );

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert(
        "path".into(),
        Value::String(dir.to_string_lossy().into_owned()),
    );
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    let core = bvault.core.load();
    let seal = SealConfig { secret_shares: 5, secret_threshold: 3 };
    let init = bvault.init(&seal).await.unwrap();
    for i in 0..seal.secret_threshold {
        bvault.unseal(&[&init.secret_shares[i as usize]]).await.unwrap();
    }
    let token = init.root_token.clone();

    // Mount the SSH engine.
    let mount_body = json!({"type": "ssh"}).as_object().unwrap().clone();
    write(&core, &token, "sys/mounts/ssh/", mount_body).await;

    // Generate the CA (no body → auto-generate Ed25519).
    let ca_resp = write(&core, &token, "ssh/config/ca", Map::new())
        .await
        .expect("CA generate returned no data");
    let ca_pub = ca_resp["public_key"].as_str().unwrap().to_string();
    assert!(
        ca_pub.starts_with("ssh-ed25519 "),
        "CA public key not Ed25519: {ca_pub}"
    );
    assert_eq!(ca_resp["algorithm"].as_str().unwrap(), "ssh-ed25519");

    // Read-back via the dedicated public_key endpoint.
    let pk_resp = read(&core, &token, "ssh/public_key")
        .await
        .expect("public_key read returned no data");
    assert_eq!(pk_resp["public_key"].as_str().unwrap(), ca_pub);

    // Create a role: alice/bob principals, permit-pty extension on by
    // default, force-command on the critical-options whitelist.
    let role_body = json!({
        "key_type": "ca",
        "allowed_users": "alice,bob",
        "default_user": "alice",
        "allowed_extensions": "permit-pty,permit-port-forwarding",
        "default_extensions": {"permit-pty": ""},
        "allowed_critical_options": "force-command",
        "ttl": "10m",
        "max_ttl": "30m"
    })
    .as_object()
    .unwrap()
    .clone();
    write(&core, &token, "ssh/roles/devs", role_body).await;

    let role_back = read(&core, &token, "ssh/roles/devs")
        .await
        .expect("role read returned nothing");
    assert_eq!(role_back["allowed_users"].as_str().unwrap(), "alice,bob");
    assert_eq!(role_back["default_user"].as_str().unwrap(), "alice");

    // Generate a client keypair and pull its public-key string.
    let client_priv = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let client_pub_openssh = client_priv.public_key().to_openssh().unwrap();

    // Sign — request bob, force-command, ttl 5m (under role.ttl).
    let sign_body = json!({
        "public_key": client_pub_openssh,
        "valid_principals": "bob",
        "ttl": "5m",
        "critical_options": {"force-command": "/usr/bin/whoami"},
        "extensions": {"permit-port-forwarding": ""}
    })
    .as_object()
    .unwrap()
    .clone();
    let sign_resp = write(&core, &token, "ssh/sign/devs", sign_body)
        .await
        .expect("sign returned no data");

    let signed_key = sign_resp["signed_key"].as_str().unwrap();
    assert!(
        signed_key.starts_with("ssh-ed25519-cert-v01@openssh.com "),
        "unexpected cert prefix: {signed_key}"
    );
    let serial_hex = sign_resp["serial_number"].as_str().unwrap();
    assert_eq!(serial_hex.len(), 16, "serial not 16 hex chars");

    // Parse the cert and check policy actually landed.
    let cert = ssh_key::Certificate::from_openssh(signed_key).expect("cert parse failed");
    assert_eq!(cert.cert_type(), ssh_key::certificate::CertType::User);
    assert_eq!(
        cert.valid_principals(),
        &vec!["bob".to_string()],
        "principal subset filter broke"
    );
    assert!(
        cert.extensions().contains_key("permit-pty"),
        "default extension missing"
    );
    assert!(
        cert.extensions().contains_key("permit-port-forwarding"),
        "whitelisted caller-supplied extension missing"
    );
    assert_eq!(
        cert.critical_options().get("force-command").map(|s| s.as_str()),
        Some("/usr/bin/whoami"),
        "critical option not honoured"
    );

    // Validity ≈ 5m.
    let validity = cert.valid_before() - cert.valid_after();
    // not_before backdates by 30s, so the window is ≈ 5m + 30s.
    assert!(
        (300..=400).contains(&validity),
        "validity window out of range: {validity}s"
    );

    // ── Negative cases ──────────────────────────────────────────────
    // Caller asks for a principal not in allowed_users.
    let bad_body = json!({
        "public_key": client_pub_openssh,
        "valid_principals": "carol"
    })
    .as_object()
    .unwrap()
    .clone();
    let mut req = Request::new("ssh/sign/devs");
    req.operation = Operation::Write;
    req.client_token = token.clone();
    req.body = Some(bad_body);
    let err = core.handle_request(&mut req).await.unwrap_err();
    assert!(
        format!("{err}").contains("carol"),
        "expected disallowed-principal error, got: {err}"
    );
}
