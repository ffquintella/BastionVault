//! End-to-end tests for `resources/v2/connect/session/open`: the vault-side
//! audit row written before a desktop host dials a session target.

use serde_json::{json, Map, Value};

use crate::audit::{entry::AuditEntry, hash_chain};
use crate::errors::RvError;
use crate::kernel_api::VaultCtx;
use crate::logical::{Operation, Request};
use crate::test_utils::{new_unseal_test_bastion_vault, test_write_api};

const OPEN: &str = "resources/v2/connect/session/open";
const TARGET_HOST: &str = "srv1.internal.example";

async fn call(core: &dyn VaultCtx, token: &str, path: &str, body: Value) -> Result<Map<String, Value>, (u16, String)> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    match core.handle_request(&mut req).await {
        Ok(resp) => Ok(resp.and_then(|r| r.data).unwrap_or_default()),
        Err(RvError::ErrResponseStatus(s, m)) => Err((s, m)),
        Err(RvError::ErrPermissionDenied) => Err((403, "permission denied".into())),
        Err(e) => Err((0, e.to_string())),
    }
}

fn status(r: Result<Map<String, Value>, (u16, String)>) -> u16 {
    match r {
        Ok(_) => 200,
        Err((s, _)) => s,
    }
}

async fn seed_resource(core: &dyn VaultCtx, root: &str) {
    let meta = json!({
        "name": "srv1",
        "type": "server",
        "hostname": TARGET_HOST,
        "connection_profiles": [
            { "id": "p_ssh", "name": "SSH", "protocol": "ssh", "credential_source": { "kind": "secret", "secret_id": "admin" } }
        ]
    });
    test_write_api(core, root, "resources/resources/srv1", true, meta.as_object().cloned()).await.unwrap();
}

fn open(protocol: &str) -> Value {
    json!({
        "resource": "srv1",
        "profile_id": "p_ssh",
        "protocol": protocol,
        "transport": "direct",
        "host": TARGET_HOST,
        "port": 22
    })
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_session_open_is_written_to_the_audit_device() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_connect_session_open_audit").await;
    seed_resource(&core, &root).await;

    let log_path = {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        std::env::temp_dir().join(format!("bv-connect-session-open-{nanos}.log"))
    };
    call(
        &core,
        &root,
        "sys/audit/primary",
        json!({
            "type": "file",
            "description": "connect session open test",
            "options": { "file_path": log_path.display().to_string() }
        }),
    )
    .await
    .unwrap();

    assert_eq!(status(call(&core, &root, OPEN, open("ssh")).await), 200);

    let body = tokio::fs::read_to_string(&log_path).await.unwrap();
    let entries: Vec<AuditEntry> = body.lines().map(|l| serde_json::from_str(l).expect("valid entry")).collect();
    let row = entries
        .iter()
        .find(|e| e.request.path == OPEN && e.request.operation == "write")
        .expect("the session open must be audited");
    assert_eq!(row.request.data.as_ref().and_then(|d| d.get("port")), Some(&json!(22)));
    assert!(!body.contains(TARGET_HOST), "the target host must be HMAC-redacted in the audit row");
    hash_chain::verify(&entries, &hash_chain::genesis()).expect("the audit chain verifies");
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_session_open_must_match_the_profile_and_the_vocabulary() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_connect_session_open_vocab").await;
    seed_resource(&core, &root).await;

    // The profile is SSH; declaring RDP must be refused.
    assert_eq!(status(call(&core, &root, OPEN, open("rdp")).await), 400);
    // Only the four protocols and the two transports are accepted.
    assert_eq!(status(call(&core, &root, OPEN, open("telnet")).await), 400);
    let mut bad_transport = open("ssh");
    bad_transport["transport"] = json!("tor");
    assert_eq!(status(call(&core, &root, OPEN, bad_transport).await), 400);
    // A host carrying free text is refused.
    let mut free_text = open("ssh");
    free_text["host"] = json!("srv1 password=hunter2");
    assert_eq!(status(call(&core, &root, OPEN, free_text).await), 400);
    // Port 0 is not a dialable target.
    let mut zero_port = open("ssh");
    zero_port["port"] = json!(0);
    assert_eq!(status(call(&core, &root, OPEN, zero_port).await), 400);
}
