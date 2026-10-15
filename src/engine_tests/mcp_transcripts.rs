//! MCP brokered-session transcripts over the API
//! (`features/mcp-brokered-sessions.md` §10, T136): the store the resource
//! engine will write (`bv_kernel_api::mcp_transcripts`) read back through
//! `sys/mcp/transcripts`, which needs `read`/`list` *and* `sudo` and audits
//! every read.
//!
//! Here rather than in `bv-kernel` because it stands a whole vault up through
//! `test_utils`, with an audit device to search.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    kernel_api::mcp_transcripts::{
        transcript_id, McpSessionTranscript, SshTranscript, TranscriptBody, TranscriptScrubber, TranscriptStore,
        TranscriptStream, TranscriptSummary, MCP_TRANSCRIPTS_SUB_PATH,
    },
    kernel_api::VaultCtx,
    logical::{McpOperatorRef, Operation, Request},
    storage::{Storage, StorageEntry},
    test_utils::{new_unseal_test_bastion_vault, test_list_api, test_mount_auth_api, test_read_api, test_write_api},
};

/// The session's credential, which must reach no transcript.
const CREDENTIAL: &str = "hunter2-session-pw";
/// A secret a command printed: kept in the transcript (that is why it is
/// sudo-gated), never in the audit log.
const PRINTED_SECRET: &str = "DB_PASSWORD=s3cr3t-db-91c";

/// Replaces the credential, as the resource engine's scrubber does in every
/// encoding it knows.
struct Scrub;
impl TranscriptScrubber for Scrub {
    fn scrub(&self, text: &str) -> (String, bool) {
        (text.replace(CREDENTIAL, "<redacted:credential>"), text.contains(CREDENTIAL))
    }
}

fn transcript(session_id: &str) -> McpSessionTranscript {
    McpSessionTranscript {
        summary: TranscriptSummary {
            session_id: session_id.into(),
            tool: "bv_resource_ssh_exec".into(),
            resource: "web-01".into(),
            profile_id: "p_agent".into(),
            operator: Some(McpOperatorRef {
                username: "felipe".into(),
                mount_path: "userpass/".into(),
                ..Default::default()
            }),
            pairing_id: "pair-1".into(),
            client_name: "claude-code".into(),
            operator_confirmation: Some("asserted-by-local-host".into()),
            started_at_ms: 1_760_000_000_000,
            finished_at_ms: 1_760_000_000_812,
            ..Default::default()
        },
        body: TranscriptBody::Ssh(SshTranscript {
            command: format!("echo {CREDENTIAL} | sudo -S cat /srv/app/.env"),
            target: "10.0.0.9:22".into(),
            host_key_fingerprint: "SHA256:k3y".into(),
            login: "password".into(),
            exit_status: Some(0),
            stdout: TranscriptStream {
                text: format!("[sudo] password for agent: {CREDENTIAL}\n{PRINTED_SECRET}\n\u{1b}[0m"),
                seen_bytes: 80,
                ..Default::default()
            },
            stderr: TranscriptStream::default(),
            ..Default::default()
        }),
    }
}

/// A file audit device in a fresh directory, so the test can search what was
/// written. Returns the directory (removed by the caller) and the log path.
async fn enable_audit_file(core: &Core, name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "bv-mcp-transcripts-{name}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.log");
    let broker = core.audit_broker.load().as_ref().cloned().expect("broker installed at unseal");
    let mut options = HashMap::new();
    options.insert("file_path".to_string(), log.display().to_string());
    broker
        .enable_device(crate::audit::AuditDeviceConfig {
            path: format!("mcp-{name}"),
            device_type: "file".into(),
            description: String::new(),
            options,
            namespace: String::new(),
            mirror: false,
        })
        .await
        .unwrap();
    (dir, log)
}

fn audit_entries(log: &PathBuf) -> Vec<Value> {
    std::fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// A userpass user holding `policy_hcl`, logged in.
async fn user_token(core: &Core, root: &str, user: &str, policy_hcl: &str) -> String {
    let _ = test_write_api(
        core,
        root,
        &format!("sys/policy/{user}-policy"),
        true,
        json!({ "policy": policy_hcl }).as_object().cloned(),
    )
    .await;
    let _ = test_write_api(
        core,
        root,
        &format!("auth/userpass/users/{user}"),
        true,
        json!({ "password": "pw-transcripts", "policies": format!("{user}-policy") }).as_object().cloned(),
    )
    .await;
    let mut req = Request::new(format!("auth/userpass/login/{user}"));
    req.operation = Operation::Write;
    req.body = json!({ "password": "pw-transcripts" }).as_object().cloned();
    core.handle_request(&mut req)
        .await
        .unwrap()
        .expect("login response")
        .auth
        .expect("login mints a token")
        .client_token
}

fn transcripts_view(core: &Core) -> Arc<crate::storage::barrier_view::BarrierView> {
    Arc::new(core.system_view().unwrap().new_sub_view(MCP_TRANSCRIPTS_SUB_PATH))
}

fn status_of(err: &RvError) -> Option<u16> {
    match err {
        RvError::ErrResponseStatus(status, _) => Some(*status),
        _ => None,
    }
}

/// A recorded session lists and reads back for a `sudo` holder, scrubbed of
/// its credential; `read`/`list` without `sudo` is refused; every read is
/// audited as `mcp.transcript.accessed`, and the audit log holds neither the
/// credential nor what the command printed.
#[tokio::test]
async fn transcripts_need_sudo_and_every_read_is_audited() {
    let (_vault, core, root) = new_unseal_test_bastion_vault("test_mcp_transcripts_sudo").await;
    let core: Arc<Core> = core;
    let (audit_dir, audit_log) = enable_audit_file(&core, "sudo").await;

    let store = TranscriptStore::from_ctx(core.as_ref()).unwrap();
    let id = store.record(transcript("as_6f0c01"), &Scrub).await.unwrap();
    assert!(id.ends_with("-as_6f0c01"), "{id}");

    // Root (sudo on everything).
    let listed = test_list_api(core.as_ref(), &root, "sys/mcp/transcripts", true).await.unwrap().unwrap().data.unwrap();
    assert_eq!(listed["keys"], json!([id.clone()]));
    assert_eq!(listed["key_info"][&id]["session_id"], json!("as_6f0c01"));
    assert!(listed["key_info"][&id]["recorded_at"].as_str().is_some_and(|t| t.contains('T')));

    let read = test_read_api(core.as_ref(), &root, &format!("sys/mcp/transcripts/{id}"), true)
        .await
        .unwrap()
        .unwrap()
        .data
        .unwrap();
    assert_eq!(read["id"], json!(id));
    assert_eq!(read["version"], json!(1));
    assert_eq!(read["protocol"], json!("ssh"));
    assert_eq!(read["summary"]["resource"], json!("web-01"));
    assert_eq!(read["summary"]["operator"]["username"], json!("felipe"));
    assert_eq!(read["summary"]["credential_echo_redacted"], json!(true));
    let command = read["body"]["command"].as_str().unwrap();
    assert_eq!(command, "echo <redacted:credential> | sudo -S cat /srv/app/.env");
    let stdout = read["body"]["stdout"]["text"].as_str().unwrap();
    assert!(stdout.contains(PRINTED_SECRET), "what the command printed is kept: {stdout:?}");
    assert!(stdout.contains('\u{1b}'), "ANSI bytes are kept for forensics (no model sanitization)");
    assert!(!Value::Object(read.clone()).to_string().contains(CREDENTIAL), "the session credential is in no field");

    // `read` and `list` without `sudo`: refused by the root-path (sudo) gate,
    // which reports itself as the policy store's root-path error — the same
    // for every sudo-gated `sys/` path (see `audit_retention.rs`).
    test_mount_auth_api(core.as_ref(), &root, "userpass", "userpass").await;
    let no_sudo = user_token(
        core.as_ref(),
        &root,
        "nosudo",
        r#"
            path "sys/mcp/transcripts"   { capabilities = ["list"] }
            path "sys/mcp/transcripts/*" { capabilities = ["read", "list"] }
        "#,
    )
    .await;
    let err = test_list_api(core.as_ref(), &no_sudo, "sys/mcp/transcripts", false).await.unwrap_err();
    assert!(err.to_string().contains("root path"), "refused by the sudo gate: {err}");
    let err = test_read_api(core.as_ref(), &no_sudo, &format!("sys/mcp/transcripts/{id}"), false).await.unwrap_err();
    assert!(err.to_string().contains("root path"), "refused by the sudo gate: {err}");

    // `sudo` alone is not enough either: the operation's own capability is needed.
    let sudo_only = user_token(
        core.as_ref(),
        &root,
        "sudoonly",
        r#"
            path "sys/mcp/transcripts"   { capabilities = ["sudo"] }
            path "sys/mcp/transcripts/*" { capabilities = ["sudo"] }
        "#,
    )
    .await;
    assert!(test_read_api(core.as_ref(), &sudo_only, &format!("sys/mcp/transcripts/{id}"), false).await.is_err());

    // With `sudo` as well: allowed.
    let investigator = user_token(
        core.as_ref(),
        &root,
        "investigator",
        r#"
            path "sys/mcp/transcripts"   { capabilities = ["list", "sudo"] }
            path "sys/mcp/transcripts/*" { capabilities = ["read", "list", "sudo"] }
        "#,
    )
    .await;
    let listed =
        test_list_api(core.as_ref(), &investigator, "sys/mcp/transcripts", true).await.unwrap().unwrap().data.unwrap();
    assert_eq!(listed["keys"], json!([id.clone()]));
    let read = test_read_api(core.as_ref(), &investigator, &format!("sys/mcp/transcripts/{id}"), true)
        .await
        .unwrap()
        .unwrap()
        .data
        .unwrap();
    assert_eq!(read["summary"]["session_id"], json!("as_6f0c01"));

    // Every read is audited: an `mcp.transcript.accessed` event per list and
    // per read, attributed to the caller, beside the standard entry.
    let entries = audit_entries(&audit_log);
    let accessed: Vec<&Value> =
        entries.iter().filter(|e| e["type"] == "event" && e["request"]["path"] == "mcp.transcript.accessed").collect();
    let reads: Vec<&&Value> = accessed.iter().filter(|e| e["request"]["data"]["operation"] == "read").collect();
    let lists: Vec<&&Value> = accessed.iter().filter(|e| e["request"]["data"]["operation"] == "list").collect();
    assert_eq!((reads.len(), lists.len()), (2, 2), "{accessed:#?}");
    assert!(reads
        .iter()
        .all(|e| e["request"]["data"]["transcript_id"] == json!(id) && e["request"]["data"]["found"] == true));
    assert!(lists.iter().all(|e| e["request"]["data"]["listed"] == json!(1)));
    assert!(reads.iter().any(|e| e["auth"]["display_name"].as_str().is_some_and(|n| n.contains("investigator"))));
    assert!(
        entries
            .iter()
            .any(|e| e["type"] == "response" && e["request"]["path"] == json!(format!("sys/mcp/transcripts/{id}"))),
        "the standard audit entry is there too"
    );
    let raw = std::fs::read_to_string(&audit_log).unwrap();
    assert!(!raw.contains(CREDENTIAL), "the audit log holds no credential");
    assert!(!raw.contains("s3cr3t-db-91c"), "the audit log holds no transcript output");
    assert!(!raw.contains("/srv/app/.env"), "the audit log holds no command text");

    let _ = std::fs::remove_dir_all(audit_dir);
}

/// Records as the first version wrote them read back; malformed ones are a
/// 500 naming why; a malformed id is a 400 and an unknown one a 404; chunk
/// keys are never listed or addressable as transcripts.
#[tokio::test]
async fn malformed_and_old_transcript_records_over_the_api() {
    let (_vault, core, root) = new_unseal_test_bastion_vault("test_mcp_transcripts_malformed").await;
    let core: Arc<Core> = core;
    let view = transcripts_view(&core);
    let put = |key: String, value: Vec<u8>| {
        let view = view.clone();
        async move { view.put(&StorageEntry { key, value }).await.unwrap() }
    };
    let read = |id: String, ok: bool| {
        let core = core.clone();
        let root = root.clone();
        async move { test_read_api(core.as_ref(), &root, &format!("sys/mcp/transcripts/{id}"), ok).await }
    };

    // As the first version wrote it, without any later optional field.
    let old = transcript_id(1_760_000_000_000_000_000, "as_old");
    let body = br#"{"protocol":"ssh","command":"uptime","target":"10.0.0.9:22","host_key_fingerprint":"SHA256:k","login":"certificate","stdout":{"text":"up 3 days\n","seen_bytes":10},"stderr":{"text":"","seen_bytes":0}}"#;
    put(format!("{old}.1"), body.to_vec()).await;
    let head = format!(
        r#"{{"version":1,"protocol":"ssh","summary":{{"session_id":"as_old","tool":"bv_resource_ssh_exec","resource":"web-01","profile_id":"p","started_at_ms":1,"finished_at_ms":2}},"chunks":1,"body_bytes":{}}}"#,
        body.len()
    );
    put(old.clone(), head.into_bytes()).await;
    let data = read(old.clone(), true).await.unwrap().unwrap().data.unwrap();
    assert_eq!(data["body"]["command"], json!("uptime"));
    assert_eq!(data["summary"]["operator"], Value::Null);

    // Malformed records: a 500 naming the reason, never a partial answer.
    let garbage = transcript_id(1_760_000_000_000_000_001, "as_garbage");
    put(garbage.clone(), b"{garbage".to_vec()).await;
    let future = transcript_id(1_760_000_000_000_000_002, "as_future");
    put(future.clone(), br#"{"version":2,"protocol":"ssh","layout":"new"}"#.to_vec()).await;
    let orphan = transcript_id(1_760_000_000_000_000_003, "as_orphan");
    put(
        orphan.clone(),
        format!(
            r#"{{"version":1,"protocol":"ssh","summary":{{"session_id":"as_orphan","tool":"t","resource":"r","profile_id":"p","started_at_ms":1,"finished_at_ms":2}},"chunks":2,"body_bytes":{}}}"#,
            body.len()
        )
        .into_bytes(),
    )
    .await;
    put(format!("{orphan}.1"), body.to_vec()).await;
    for (id, needle) in [
        (garbage, "not JSON"),
        (future, "unsupported transcript version 2"),
        (orphan.clone(), "body chunk 2 is missing"),
    ] {
        let err = read(id.clone(), false).await.unwrap_err();
        assert_eq!(status_of(&err), Some(500), "{id}: {err}");
        assert!(err.to_string().contains("unreadable") && err.to_string().contains(needle), "{id}: {err}");
    }

    // Ids: malformed (a chunk key among them) is a 400, unknown a 404.
    for bad in ["abc", &format!("{old}.1"), "01760000000000000000-UPPER"] {
        let err = read(bad.to_string(), false).await.unwrap_err();
        assert_eq!(status_of(&err), Some(400), "{bad}: {err}");
    }
    let err = read(transcript_id(1, "as_missing"), false).await.unwrap_err();
    assert_eq!(status_of(&err), Some(404), "{err}");

    // The listing shows heads only, newest first.
    let listed = test_list_api(core.as_ref(), &root, "sys/mcp/transcripts", true).await.unwrap().unwrap().data.unwrap();
    let keys: Vec<&str> = listed["keys"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert_eq!(keys.len(), 4, "{keys:?}");
    assert!(keys.iter().all(|k| !k.contains('.')), "chunk keys are not listed: {keys:?}");
    assert_eq!(keys.last(), Some(&old.as_str()), "newest first: {keys:?}");
}
