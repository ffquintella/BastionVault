//! Cert-lifecycle plugin trait + built-in deliverers — Phase L7 of
//! the PKI key-management + lifecycle initiative. See
//! [features/pki-key-management-and-lifecycle.md].
//!
//! Coverage:
//! 1. `sys/deliverers` lists the registered plugin names. The
//!    built-in registry carries `file` and `http-push`.
//! 2. `kind = http-push` with a non-URL `address` is rejected at
//!    target-write time.
//! 3. Renewing an `http-push` target POSTs a JSON envelope (target,
//!    serial, certificate, private_key, ca_chain) to the configured
//!    URL. The cert-lifecycle response surfaces `delivery_kind =
//!    http-push` and the receipt's destination + note.
//! 4. After a successful HTTP push, target state carries the new
//!    serial.

use std::{
    collections::HashMap,
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

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

fn boot() -> (BastionVault, std::path::PathBuf) {
    use rand::RngExt;
    let n: u32 = rand::rng().random();
    let dir = env::temp_dir().join(format!("bastion_vault_cert_lifecycle_plugin_{n:08x}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".into(), Value::String(dir.to_string_lossy().into_owned()));
    let backend = storage::new_backend("file", &conf).unwrap();
    let bvault = BastionVault::new(backend, None).unwrap();
    (bvault, dir)
}

/// Minimal one-shot HTTP server. Binds to 127.0.0.1:0, accepts ONE
/// connection, reads the request bytes, captures the body into a
/// shared slot, replies `204 No Content`. Returns the bound port and
/// the slot the body lands in.
fn spawn_capture_server() -> (u16, Arc<Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let slot = Arc::new(Mutex::new(None));
    let slot_clone = slot.clone();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 65536];
        let mut total = Vec::new();
        // Read until we see the body length specified by Content-Length.
        // For simplicity, just slurp until the peer's write buffer drains
        // and we have at least the headers + the announced body.
        let mut content_length: Option<usize> = None;
        let mut header_end: Option<usize> = None;
        loop {
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            total.extend_from_slice(&buf[..n]);
            if header_end.is_none() {
                if let Some(idx) = find_header_end(&total) {
                    header_end = Some(idx);
                    let head_str = std::str::from_utf8(&total[..idx]).unwrap_or("");
                    for line in head_str.split("\r\n") {
                        if let Some(rest) = line.strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                        {
                            if let Ok(v) = rest.trim().parse::<usize>() {
                                content_length = Some(v);
                            }
                        }
                    }
                }
            }
            if let (Some(he), Some(cl)) = (header_end, content_length) {
                if total.len() >= he + 4 + cl {
                    break;
                }
            }
        }
        if let (Some(he), Some(_cl)) = (header_end, content_length) {
            let body = String::from_utf8_lossy(&total[he + 4..]).to_string();
            *slot_clone.lock().unwrap() = Some(body);
        }
        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.flush();
    });
    (port, slot)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    let needle = b"\r\n\r\n";
    buf.windows(needle.len()).position(|w| w == needle)
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_cert_lifecycle_plugin_l7() {
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
        .await.expect("mount pki");
    write(&core, &token, "sys/mounts/cert-lifecycle/",
        json!({"type": "cert-lifecycle"}).as_object().unwrap().clone(),
    ).await.expect("mount cert-lifecycle");
    write(&core, &token, "pki/root/generate/internal",
        json!({"common_name": "L7 Root", "key_type": "ec", "ttl": "8760h"}).as_object().unwrap().clone(),
    ).await.expect("root");
    write(&core, &token, "pki/roles/web",
        json!({
            "ttl": "168h", "max_ttl": "720h", "key_type": "ec",
            "allow_any_name": true, "server_flag": true, "client_flag": true,
        }).as_object().unwrap().clone(),
    ).await.expect("role");

    // ── 1. sys/deliverers lists the built-ins ────────────────────────
    let listed = read(&core, &token, "cert-lifecycle/sys/deliverers").await;
    let names: Vec<String> = listed["deliverers"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(names.contains(&"file".to_string()));
    assert!(names.contains(&"http-push".to_string()));

    // ── 2. http-push with non-URL address rejected ───────────────────
    let bad = write(&core, &token, "cert-lifecycle/targets/bogus",
        json!({
            "kind": "http-push",
            "role_ref": "web",
            "common_name": "bogus.example.com",
            "address": "/tmp/not-a-url",
        }).as_object().unwrap().clone(),
    ).await;
    assert!(bad.is_err(), "non-URL http-push must be rejected: {bad:?}");

    // ── 3 + 4. Real http-push end-to-end ─────────────────────────────
    let (port, captured) = spawn_capture_server();
    let url = format!("http://127.0.0.1:{port}/hook");
    write(&core, &token, "cert-lifecycle/targets/web-hook",
        json!({
            "kind": "http-push",
            "role_ref": "web",
            "common_name": "web-hook.example.com",
            "address": &url,
        }).as_object().unwrap().clone(),
    ).await.expect("write http-push target");

    let resp = write_ok(&core, &token, "cert-lifecycle/renew/web-hook", Map::new()).await;
    assert_eq!(resp["delivery_kind"].as_str().unwrap(), "http-push");
    assert_eq!(resp["delivered_to"].as_str().unwrap(), url);
    let serial = resp["serial_number"].as_str().unwrap().to_string();
    assert!(!serial.is_empty());

    // The capture server got the POST body. Give the OS a beat to
    // flush the write before we read the slot.
    let mut tries = 0;
    let body_str = loop {
        if let Some(b) = captured.lock().unwrap().clone() {
            break b;
        }
        tries += 1;
        if tries > 50 {
            panic!("capture server never recorded a body");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let body: Value = serde_json::from_str(&body_str).expect("posted body is JSON");
    assert_eq!(body["target"].as_str().unwrap(), "web-hook");
    assert_eq!(body["serial"].as_str().unwrap(), serial);
    assert!(body["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    assert!(body["private_key"].as_str().unwrap().contains("BEGIN PRIVATE KEY"));
    assert!(body["ca_chain"].is_array());

    // State reflects the new serial.
    let state = read(&core, &token, "cert-lifecycle/state/web-hook").await;
    assert_eq!(state["current_serial"].as_str().unwrap(), serial);
    assert_eq!(state["last_error"].as_str().unwrap(), "");
}
