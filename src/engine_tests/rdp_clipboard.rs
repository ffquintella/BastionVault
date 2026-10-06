//! End-to-end tests for the server half of RDP clipboard redirection (T35,
//! features/rdp-clipboard-redirection.md): the clipboard knobs on the Rustion
//! policy tiers and `resources/v2/connect/clipboard/audit`.
//!
//! Both engines unit-test their pure halves (the resolver, the knob parser,
//! the batch validator) in-crate; these drive the real routes through the
//! request pipeline, so the field declarations, the grants and the
//! write-time lock guard are exercised as an operator would hit them.

use serde_json::{json, Map, Value};

use crate::errors::RvError;
use crate::kernel_api::VaultCtx;
use crate::logical::{Operation, Request};
use crate::test_utils::{new_unseal_test_bastion_vault, test_write_api};

const LOGIN_PASSWORD: &str = "hunter22XX!";
const AUDIT: &str = "resources/v2/connect/clipboard/audit";

async fn call(
    core: &dyn VaultCtx,
    token: &str,
    op: Operation,
    path: &str,
    body: Option<Value>,
) -> Result<Map<String, Value>, (u16, String)> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.and_then(|b| b.as_object().cloned());
    match core.handle_request(&mut req).await {
        Ok(resp) => Ok(resp.and_then(|r| r.data).unwrap_or_default()),
        Err(RvError::ErrResponseStatus(s, m)) => Err((s, m)),
        Err(RvError::ErrPermissionDenied) => Err((403, "permission denied".into())),
        Err(e) => Err((0, e.to_string())),
    }
}

async fn write(core: &dyn VaultCtx, token: &str, path: &str, body: Value) -> Result<Map<String, Value>, (u16, String)> {
    call(core, token, Operation::Write, path, Some(body)).await
}

fn status(r: Result<Map<String, Value>, (u16, String)>) -> u16 {
    match r {
        Ok(_) => 200,
        Err((s, _)) => s,
    }
}

async fn userpass_user(core: &dyn VaultCtx, root: &str, user: &str, policy_hcl: &str) -> String {
    // Mounted on the first call; later calls get "path already in use".
    let _ = write(core, root, "sys/auth/userpass", json!({ "type": "userpass" })).await;
    test_write_api(
        core,
        root,
        &format!("sys/policy/p-{user}"),
        true,
        json!({ "policy": policy_hcl }).as_object().cloned(),
    )
    .await
    .unwrap();
    test_write_api(
        core,
        root,
        &format!("auth/userpass/users/{user}"),
        true,
        json!({ "password": LOGIN_PASSWORD, "token_policies": format!("p-{user}"), "ttl": 0 }).as_object().cloned(),
    )
    .await
    .unwrap();
    let mut req = Request::new(format!("auth/userpass/login/{user}"));
    req.operation = Operation::Write;
    req.body = json!({ "password": LOGIN_PASSWORD }).as_object().cloned();
    core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap().client_token
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn clipboard_knobs_ride_the_transport_tiers_and_a_lock_pins_them() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_rdp_clipboard_policy").await;
    seed_rdp_resource(&core, &root).await;
    let global = "rustion/policy/global";

    // An administrator pins the clipboard off for the deployment.
    write(&core, &root, global, json!({ "clipboard": "off", "clipboard_files": "off", "lock": true })).await.unwrap();
    let g = call(&core, &root, Operation::Read, global, None).await.unwrap();
    assert_eq!(g["clipboard"], json!("off"));
    assert_eq!(g["clipboard_files"], json!("off"));

    // A later transport-only write — the shape an older client sends —
    // leaves the pin alone instead of erasing it by omission.
    write(&core, &root, global, json!({ "transport": "direct", "lock": true })).await.unwrap();
    let g = call(&core, &root, Operation::Read, global, None).await.unwrap();
    assert_eq!(g["clipboard"], json!("off"), "absent means unchanged");
    assert_eq!(g["transport"], json!("direct"));

    // Strict parsing: a typo is refused, never stored as a default.
    for bad in [json!({ "clipboard": "sideways" }), json!({ "clipboard_files": "on" }), json!({ "clipboard": true })] {
        assert_eq!(status(write(&core, &root, global, bad.clone()).await), 400, "{bad} must be refused");
    }
    let g = call(&core, &root, Operation::Read, global, None).await.unwrap();
    assert_eq!(g["clipboard"], json!("off"), "a refused write changes nothing");

    // The resource owner cannot widen past the locked global tier …
    let res = "rustion/policy/resource/srv1";
    assert_eq!(status(write(&core, &root, res, json!({ "clipboard": "bidirectional" })).await), 403);
    // … but may narrow.
    write(&core, &root, res, json!({ "clipboard_files": "off" })).await.unwrap();

    // The resolver reports the ceiling and who set it, separately from the
    // transport `lock_violation` the connect path refuses on.
    let eff = write(&core, &root, "rustion/policy/effective", json!({ "resource_id": "srv1" })).await.unwrap();
    assert_eq!(eff["clipboard"], json!("off"));
    assert_eq!(eff["clipboard_source"], json!("global"));
    assert_eq!(eff["clipboard_files"], json!("off"));
    assert_eq!(eff["clipboard_locked_by"], json!(["global"]));
    assert!(eff.get("lock_violation").is_none());

    // Clearing the global knob (empty string) lifts its ceiling; the
    // resource tier's own narrowing remains.
    write(&core, &root, global, json!({ "clipboard": "", "clipboard_files": "", "lock": false })).await.unwrap();
    let eff = write(&core, &root, "rustion/policy/effective", json!({ "resource_id": "srv1" })).await.unwrap();
    assert_eq!(eff["clipboard"], json!("bidirectional"));
    assert_eq!(eff["clipboard_source"], json!("default"));
    assert_eq!(eff["clipboard_files"], json!("off"));
    assert_eq!(eff["clipboard_files_source"], json!("resource"));
}

async fn seed_rdp_resource(core: &dyn VaultCtx, root: &str) {
    let meta = json!({
        "name": "srv1",
        "type": "server",
        "hostname": "srv1.example",
        "connection_profiles": [
            { "id": "p_rdp", "name": "RDP", "protocol": "rdp", "credential_source": { "kind": "secret", "secret_id": "admin" } },
            { "id": "p_ssh", "name": "SSH", "protocol": "ssh", "credential_source": { "kind": "secret", "secret_id": "admin" } }
        ]
    });
    test_write_api(core, root, "resources/resources/srv1", true, meta.as_object().cloned()).await.unwrap();
}

fn batch(transfers: Value) -> Value {
    json!({ "resource": "srv1", "profile_id": "p_rdp", "session": "rdp_0123abcd", "seq": 0, "transfers": transfers })
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_clipboard_audit_endpoint_is_connect_gated_and_metadata_only() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_rdp_clipboard_audit").await;
    seed_rdp_resource(&core, &root).await;
    // Only `connect` on the resource: the endpoint itself comes from the
    // `default` baseline every token carries.
    let alice =
        userpass_user(&core, &root, "alice", r#"path "resources/secrets/srv1/*" { capabilities = ["connect"] }"#).await;
    let mallory =
        userpass_user(&core, &root, "mallory", r#"path "resources/secrets/other/*" { capabilities = ["connect"] }"#)
            .await;

    let ok = write(
        &core,
        &alice,
        AUDIT,
        batch(json!({ "session-to-host.text.ok": [120, 33], "host-to-session.image.oversize": [40000000] })),
    )
    .await
    .unwrap();
    assert_eq!(ok["accepted"], json!(3));
    assert_eq!(ok["seq"], json!(0));

    // A caller who cannot connect to the resource cannot write its trail.
    assert_eq!(status(write(&core, &mallory, AUDIT, batch(json!({ "session-to-host.text.ok": [1] }))).await), 403);

    // No slot for a file name, in a key or in a value.
    for bad in
        [json!({ "session-to-host.file.ok.secret.docx": [1] }), json!({ "session-to-host.file.ok": ["secret.docx"] })]
    {
        assert_eq!(status(write(&core, &alice, AUDIT, batch(bad.clone())).await), 400, "{bad}");
    }

    // RDP profiles only, and the profile must exist.
    let mut ssh = batch(json!({ "session-to-host.text.ok": [1] }));
    ssh["profile_id"] = json!("p_ssh");
    assert_eq!(status(write(&core, &alice, AUDIT, ssh).await), 400);
    let mut missing = batch(json!({ "session-to-host.text.ok": [1] }));
    missing["profile_id"] = json!("p_missing");
    assert_eq!(status(write(&core, &alice, AUDIT, missing).await), 404);

    // Only the session's final batch may be empty.
    assert_eq!(status(write(&core, &alice, AUDIT, batch(json!({}))).await), 400);
    let mut close = batch(json!({}));
    close["final"] = json!(true);
    close["seq"] = json!(1);
    assert_eq!(write(&core, &alice, AUDIT, close).await.unwrap()["accepted"], json!(0));

    // The session token is bounded caller text.
    let mut odd = batch(json!({ "session-to-host.text.ok": [1] }));
    odd["session"] = json!("../../etc");
    assert_eq!(status(write(&core, &alice, AUDIT, odd).await), 400);
}
