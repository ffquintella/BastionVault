//! SSH Secret Engine — Phase 3 (ML-DSA-65 PQC) integration test.
//!
//! Gated on the `ssh_pqc` feature so default-build runs skip it; the
//! PQC code path doesn't compile without the flag. Run with:
//!
//! ```text
//! cargo test --features ssh_pqc --test test_ssh_pqc
//! ```
//!
//! The test mounts the engine, generates an ML-DSA-65 CA, creates a
//! `pqc_only` role, signs a fresh ML-DSA-65 client public key, and
//! verifies the wire-format envelope (algo prefix, base64-decodable,
//! signature wrapper at the tail). It also exercises two negatives:
//! a classical client key against a `pqc_only` role gets rejected,
//! and the GUI-facing `algorithm` field surfaces the PQC name on
//! `GET /config/ca`.

#![cfg(feature = "ssh_pqc")]

use std::{collections::HashMap, env, fs};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bastion_vault::{
    core::{Core, SealConfig},
    logical::{Operation, Request},
    storage, BastionVault,
};
use bv_crypto::MlDsa65Provider;
use go_defer::defer;
use serde_json::{json, Map, Value};

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

#[maybe_async::maybe_async]
async fn write_err(
    core: &Core,
    token: &str,
    path: &str,
    body: Map<String, Value>,
) -> bastion_vault::errors::RvError {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = Some(body);
    core.handle_request(&mut req)
        .await
        .err()
        .expect("expected write to fail")
}

#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn test_ssh_phase3_pqc_end_to_end() {
    let dir = env::temp_dir().join("bastion_vault_ssh_phase3");
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

    // Mount + generate PQC CA.
    write(&core, &token, "sys/mounts/ssh/", json!({"type": "ssh"}).as_object().unwrap().clone()).await;
    let ca_resp = write(
        &core,
        &token,
        "ssh/config/ca",
        json!({"algorithm": "mldsa65"}).as_object().unwrap().clone(),
    )
    .await
    .expect("PQC CA generate returned no data");
    assert_eq!(
        ca_resp["algorithm"].as_str().unwrap(),
        "ssh-mldsa65@openssh.com"
    );
    let ca_pub = ca_resp["public_key"].as_str().unwrap();
    assert!(
        ca_pub.starts_with("ssh-mldsa65@openssh.com "),
        "PQC CA public-key prefix wrong: {ca_pub}"
    );

    // Read-back: GET /config/ca surfaces the same algorithm string.
    let ca_read = read(&core, &token, "ssh/config/ca").await.expect("ca read");
    assert_eq!(ca_read["algorithm"].as_str().unwrap(), "ssh-mldsa65@openssh.com");

    // Create a pqc_only role.
    write(
        &core,
        &token,
        "ssh/roles/pqc-devs",
        json!({
            "key_type": "ca",
            "allowed_users": "alice",
            "default_user": "alice",
            "ttl": "10m",
            "max_ttl": "30m",
            "pqc_only": true
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .await;

    // Sign a freshly-generated ML-DSA-65 client public key.
    let client = MlDsa65Provider.generate_keypair().unwrap();
    let mut blob = Vec::new();
    use ssh_encoding::Encode;
    "ssh-mldsa65@openssh.com".encode(&mut blob).unwrap();
    client.public_key().encode(&mut blob).unwrap();
    let client_pk_line = format!(
        "ssh-mldsa65@openssh.com {} client@bvault",
        B64.encode(&blob)
    );

    let sign_resp = write(
        &core,
        &token,
        "ssh/sign/pqc-devs",
        json!({"public_key": client_pk_line, "ttl": "5m"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .await
    .expect("sign returned no data");
    let signed = sign_resp["signed_key"].as_str().unwrap();
    assert!(
        signed.starts_with("ssh-mldsa65-cert-v01@openssh.com "),
        "PQC cert prefix wrong: {signed}"
    );
    assert_eq!(sign_resp["algorithm"].as_str().unwrap(), "ssh-mldsa65@openssh.com");
    let serial_hex = sign_resp["serial_number"].as_str().unwrap();
    assert_eq!(serial_hex.len(), 16);

    // Decode the cert blob and confirm the trailing signature
    // envelope is well-formed (string algo || string sig_bytes).
    let cert_b64 = signed.split_whitespace().nth(1).unwrap();
    let cert_blob = B64.decode(cert_b64).expect("cert base64 decode");
    // The blob is large (TBS + signature); a sanity check is that
    // the trailing bytes contain the algo string followed by
    // ML-DSA-65 sig_len. We don't fully parse the TBS here — that's
    // covered by the unit tests in `pqc.rs`.
    let needle = b"ssh-mldsa65@openssh.com";
    let occurrences = cert_blob
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count();
    // The exact `ssh-mldsa65@openssh.com` string appears at: the
    // CA pubkey blob inside `signature_key`, and the signature
    // envelope's algo header. (The wrapper at the top uses
    // `ssh-mldsa65-cert-v01@openssh.com`, which contains the
    // substring but isn't a match for our exact-needle scan.) So
    // two is the floor — anything less means we forgot to embed
    // either the CA pubkey or the signature algo.
    assert!(
        occurrences >= 2,
        "expected ≥2 algo-string references in cert blob, got {occurrences}"
    );

    // ── Negatives ───────────────────────────────────────────────
    // Classical Ed25519 client key against pqc_only role → rejected.
    let classical_pk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7x9ln6uZLLkfXM8iatrnAAuytVHeCznU8VlEgx7TvL ed25519-key";
    let err = write_err(
        &core,
        &token,
        "ssh/sign/pqc-devs",
        json!({"public_key": classical_pk}).as_object().unwrap().clone(),
    )
    .await;
    assert!(
        format!("{err}").contains("pqc") || format!("{err}").contains("ML-DSA") || format!("{err}").contains("ssh-mldsa65"),
        "classical client against pqc_only role should be rejected explicitly: {err}"
    );
}
