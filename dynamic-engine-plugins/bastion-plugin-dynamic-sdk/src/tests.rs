//! Dispatch, error mapping, redaction and lease registration, driven through
//! the in-memory [`MockHost`] (same gate as the server and the testkit).

use std::cell::RefCell;

use serde_json::{json, Value};

use crate::{
    status,
    testing::{invoke, MockHost},
    AuditEvent, Connection, ConnectionSchema, DynamicCredentialBackend, DynamicCtx, DynamicError, EventKind,
    GenerateRequest, Generated, LeaseTerms, RenewRequest, Renewed, RevokeRequest, RotateRootRequest,
};

const PASSWORD: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
const ROOT: &str = "root-password-very-secret";

#[derive(Default)]
struct Fake {
    /// What to do on generate: "ok", "fail", "leak_data", "leak_internal".
    mode: RefCell<&'static str>,
    seen: RefCell<Vec<String>>,
    rotated_to: RefCell<Option<String>>,
}

#[async_trait::async_trait(?Send)]
impl DynamicCredentialBackend for Fake {
    fn engine_type(&self) -> &'static str {
        "database"
    }

    fn connection_schema(&self) -> ConnectionSchema {
        ConnectionSchema { settings: &["url"], secrets: &["password"], required: &["url"] }
    }

    async fn generate(&self, ctx: &mut DynamicCtx<'_>, req: GenerateRequest) -> Result<Generated, DynamicError> {
        let grant = ctx.pool_checkout(&req.connection.name).await?;
        assert!(grant.tls.verify);
        self.seen.borrow_mut().push(format!("generate {} {}", req.username, req.statements.len()));
        let mode = *self.mode.borrow();
        match mode {
            "fail" => Err(DynamicError::target(format!("syntax error at or near '{}'", req.password.expose()))),
            "leak_data" => {
                let mut g = Generated::new(LeaseTerms::new(req.ttl_secs));
                g.data.insert("echo".into(), Value::String(req.password.expose().to_string()));
                Ok(g)
            }
            "leak_internal" => {
                Ok(Generated::new(LeaseTerms::new(60).with_internal(json!({ "pw": req.password.expose() }))))
            }
            _ => {
                ctx.emit(&AuditEvent::new(EventKind::Generate).identity_type("fake_user")?).await?;
                let mut g = Generated::new(LeaseTerms::new(req.ttl_secs).with_internal(json!({ "v": 1 })));
                g.data.insert("hint".into(), json!("ok"));
                g.data.insert("password".into(), json!("plugin-chosen"));
                Ok(g)
            }
        }
    }

    async fn renew(&self, _ctx: &mut DynamicCtx<'_>, req: RenewRequest) -> Result<Renewed, DynamicError> {
        self.seen.borrow_mut().push(format!("renew {} {}", req.username, req.expiration));
        Ok(Renewed { internal: Some(json!({ "v": 1, "renewed": true })) })
    }

    async fn revoke(&self, _ctx: &mut DynamicCtx<'_>, req: RevokeRequest) -> Result<(), DynamicError> {
        self.seen.borrow_mut().push(format!("revoke {} {:?}", req.username, req.statements));
        Ok(())
    }

    async fn rotate_root(&self, ctx: &mut DynamicCtx<'_>, req: RotateRootRequest) -> Result<(), DynamicError> {
        let mut conn: Connection = req.connection;
        *self.rotated_to.borrow_mut() = Some(req.new_secret.expose().to_string());
        conn.set_secret("password", req.new_secret);
        ctx.save_connection(&conn).await
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

async fn configured(fake: &Fake, host: &mut MockHost) {
    let write = json!({ "op": "write", "path": "config/prod", "data": {
        "url": "fake://db", "password": ROOT, "allowed_roles": ["readonly"] } });
    let (r, _) = invoke(fake, host, &write).await;
    assert_eq!(r.status, 0, "{:?}", r.json());
    let role = json!({ "op": "write", "path": "roles/readonly", "data": {
        "connection": "prod", "creation_statements": ["CREATE {{name}} {{password}}"], "default_ttl": "10m" } });
    let (r, _) = invoke(fake, host, &role).await;
    assert_eq!(r.status, 0, "{:?}", r.json());
}

fn generate_envelope() -> Value {
    json!({
        "op": "dynamic.generate", "role": "readonly", "connection": "prod",
        "statements": [format!("CREATE v-root-readonly-1-abcd {PASSWORD}")],
        "credential": { "username": "v-root-readonly-1-abcd", "password": PASSWORD, "expiration": "2026-10-26T18:32:11Z" },
        "ttl_secs": 600,
    })
}

fn lease_envelope(op: &str) -> Value {
    json!({ "op": op, "role": "readonly", "connection": "prod", "username": "v-root-readonly-1-abcd",
            "statements": ["DROP v-root-readonly-1-abcd"], "expiration": "2026-10-26T19:00:00Z",
            "ttl_secs": 300, "internal": { "v": 1 } })
}

fn count(host: &MockHost, method: &str) -> usize {
    host.calls.iter().filter(|c| c.as_str() == method).count()
}

#[test]
fn generate_registers_exactly_one_lease_and_never_returns_the_password() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all().with_connection("prod");
        configured(&fake, &mut host).await;
        let (reply, diag) = invoke(&fake, &mut host, &generate_envelope()).await;
        assert_eq!(reply.status, 0, "{:?}", reply.json());
        assert_eq!(count(&host, "dynamic_lease_register"), 1);
        assert_eq!(host.leases, [json!({"internal": {"v": 1}, "ttl_secs": 600, "max_ttl_secs": 0, "renewable": true})]);
        assert_eq!(host.events, [json!({"event": "generate", "target_identity_type": "fake_user"})]);
        let body = String::from_utf8_lossy(&reply.body).to_string();
        assert!(!body.contains(PASSWORD) && !body.contains(ROOT), "{body}");
        assert_eq!(reply.json().unwrap(), json!({ "data": { "hint": "ok" } }), "the host's keys are dropped");
        assert!(diag.is_empty(), "{diag:?}");
        assert_eq!(fake.seen.borrow()[0], "generate v-root-readonly-1-abcd 1");
    });
}

#[test]
fn a_failing_generate_registers_nothing_and_redacts_the_password() {
    rt().block_on(async {
        let fake = Fake::default();
        *fake.mode.borrow_mut() = "fail";
        let mut host = MockHost::granting_all().with_connection("prod");
        configured(&fake, &mut host).await;
        let (reply, diag) = invoke(&fake, &mut host, &generate_envelope()).await;
        assert_eq!(reply.status, status::TARGET);
        assert!(host.leases.is_empty());
        let body = String::from_utf8_lossy(&reply.body).to_string();
        assert!(!body.contains(PASSWORD) && body.contains("<redacted>"), "{body}");
        assert_eq!(diag, ["[database] dynamic.generate failed (target)"], "op and kind only");
    });
}

#[test]
fn credential_material_cannot_leave_through_data_or_the_lease_blob() {
    rt().block_on(async {
        for mode in ["leak_data", "leak_internal"] {
            let fake = Fake::default();
            *fake.mode.borrow_mut() = mode;
            let mut host = MockHost::granting_all().with_connection("prod");
            configured(&fake, &mut host).await;
            let (reply, diag) = invoke(&fake, &mut host, &generate_envelope()).await;
            assert_eq!(reply.status, status::INVALID, "{mode}");
            let body = String::from_utf8_lossy(&reply.body).to_string();
            assert!(!body.contains(PASSWORD), "{mode}: {body}");
            assert!(diag.iter().all(|l| !l.contains(PASSWORD)));
            // A leaking blob is refused before the host sees it.
            if mode == "leak_internal" {
                assert!(host.leases.is_empty());
            }
        }
    });
}

#[test]
fn renew_revoke_and_proxied_calls_never_register_a_lease() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all().with_connection("prod");
        configured(&fake, &mut host).await;
        let (r, _) = invoke(&fake, &mut host, &lease_envelope("dynamic.renew")).await;
        assert_eq!(r.json().unwrap(), json!({ "data": { "internal": { "v": 1, "renewed": true } } }));
        let (r, _) = invoke(&fake, &mut host, &lease_envelope("dynamic.revoke")).await;
        assert_eq!((r.status, r.json().unwrap()), (0, json!({})));
        assert_eq!(count(&host, "dynamic_lease_register"), 0);
        assert_eq!(fake.seen.borrow()[1], "revoke v-root-readonly-1-abcd [\"DROP v-root-readonly-1-abcd\"]");
    });
}

#[test]
fn the_role_recipe_is_refused_for_a_connection_that_does_not_allow_it() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all().with_connection("prod");
        configured(&fake, &mut host).await;
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "dynamic.role", "role": "readonly" })).await;
        let data = r.json().unwrap()["data"].clone();
        assert_eq!(data["connection"], "prod");
        assert_eq!(data["default_ttl_secs"], 600);
        assert!(data.get("v").is_none(), "the storage version is not a recipe field");
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "dynamic.role", "role": "missing" })).await;
        assert_eq!(r.json().unwrap(), json!({ "data": null }));

        let other = json!({ "op": "write", "path": "roles/admin", "data": { "connection": "prod" } });
        invoke(&fake, &mut host, &other).await;
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "dynamic.role", "role": "admin" })).await;
        assert_eq!(r.status, status::INVALID);
        assert!(String::from_utf8_lossy(&r.body).contains("allowed_roles"));
    });
}

#[test]
fn config_reads_answer_metadata_only() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all();
        configured(&fake, &mut host).await;
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "read", "path": "config/prod", "data": {} })).await;
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert!(!body.contains(ROOT), "{body}");
        assert_eq!(r.json().unwrap(), json!({ "data": { "url": "fake://db", "allowed_roles": ["readonly"] } }));
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "list", "path": "config/", "data": {} })).await;
        assert_eq!(r.json().unwrap(), json!({ "data": { "keys": ["prod"] } }));
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "read", "path": "config/none", "data": {} })).await;
        assert_eq!(r.json().unwrap(), json!({ "data": null }));
        let bad = json!({ "op": "write", "path": "config/prod", "data": { "passwrd": "x" } });
        assert_eq!(invoke(&fake, &mut host, &bad).await.0.status, status::INVALID);
        let unknown = json!({ "op": "write", "path": "creds/x", "data": {} });
        assert_eq!(invoke(&fake, &mut host, &unknown).await.0.status, status::UNSUPPORTED);
    });
}

#[test]
fn host_refusals_map_to_the_refused_status_and_are_recorded() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all().with_connection("prod");
        host.pool_checkout = false;
        configured(&fake, &mut host).await;
        let (r, diag) = invoke(&fake, &mut host, &generate_envelope()).await;
        assert_eq!(r.status, status::HOST_REFUSED);
        assert_eq!(host.violations, ["dynamic_pool_checkout"]);
        assert!(host.leases.is_empty());
        assert_eq!(diag, ["[database] dynamic.generate failed (forbidden)"]);

        let mut host = MockHost::granting_all().with_connection("prod");
        configured(&fake, &mut host).await;
        host.fail_next = Some((crate::host::DynamicMethod::LeaseRegister, "unavailable: storage".into()));
        let (r, _) = invoke(&fake, &mut host, &generate_envelope()).await;
        assert_eq!(r.status, status::UNAVAILABLE, "a failed registration fails the generate");
    });
}

#[test]
fn revoking_on_a_deleted_connection_fails_explicitly() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all();
        let (r, _) = invoke(&fake, &mut host, &lease_envelope("dynamic.revoke")).await;
        assert_eq!(r.status, status::NOT_FOUND, "the host keeps the lease revoke_failed");
    });
}

#[test]
fn rotate_root_takes_the_host_secret_and_needs_one() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all();
        configured(&fake, &mut host).await;
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "dynamic.rotate_root", "connection": "prod" })).await;
        assert_eq!(r.status, status::PROTOCOL, "no plugin-generated fallback");
        let rotate = json!({ "op": "dynamic.rotate_root", "connection": "prod", "credential": { "password": "new-root-secret-42" } });
        let (r, _) = invoke(&fake, &mut host, &rotate).await;
        assert_eq!(r.status, 0, "{:?}", r.json());
        assert_eq!(fake.rotated_to.borrow().as_deref(), Some("new-root-secret-42"));
        let stored = String::from_utf8_lossy(&host.storage["config/prod"]).to_string();
        assert!(stored.contains("new-root-secret-42") && !stored.contains(ROOT));
    });
}

#[test]
fn malformed_envelopes_are_protocol_errors_that_quote_nothing() {
    rt().block_on(async {
        let fake = Fake::default();
        let mut host = MockHost::granting_all();
        let bad = json!({ "op": "dynamic.generate", "role": "readonly", "connection": "prod",
                          "credential": { "username": "u", "password": 42 }, "ttl_secs": PASSWORD });
        let (r, _) = invoke(&fake, &mut host, &bad).await;
        assert_eq!(r.status, status::PROTOCOL);
        assert!(!String::from_utf8_lossy(&r.body).contains(PASSWORD));
        let (r, _) = invoke(&fake, &mut host, &json!({ "op": "dynamic.nope" })).await;
        assert_eq!(r.status, status::UNSUPPORTED);
    });
}

#[cfg(feature = "process")]
mod process_loop {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::process::{serve, ProcessError};

    /// Drive [`serve`] with a scripted host: `first` is the host's first
    /// line; host calls are answered by `answer`. Returns what the plugin wrote.
    async fn drive(
        first: Value,
        then: Vec<Value>,
        answer: fn(&Value) -> Value,
    ) -> (Result<(), ProcessError>, Vec<Value>) {
        let (host_to_plugin, plugin_in) = tokio::io::duplex(1 << 16);
        let (plugin_out, plugin_to_host) = tokio::io::duplex(1 << 16);
        let fake = Fake::default();
        let mut diag = |_: &str| {};
        let plugin = serve(&fake, BufReader::new(plugin_in), plugin_out, "tok", &mut diag);
        let host = async move {
            let mut w = host_to_plugin;
            let mut r = BufReader::new(plugin_to_host).lines();
            let mut seen = Vec::new();
            w.write_all(format!("{first}\n").as_bytes()).await.unwrap();
            for line in &then {
                w.write_all(format!("{line}\n").as_bytes()).await.unwrap();
            }
            while let Ok(Some(line)) = r.next_line().await {
                let msg: Value = serde_json::from_str(&line).unwrap();
                if msg["type"] == "host_call" {
                    let reply = json!({ "type": "host_reply", "id": msg["id"], "result": answer(&msg) });
                    w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                }
                let end = msg["type"] == "done" || msg["type"] == "invoke_done";
                seen.push(msg);
                if end {
                    break;
                }
            }
            drop(w);
            seen
        };
        tokio::join!(plugin, host)
    }

    fn init(token: &str, envelope: Value) -> Value {
        json!({ "type": "init", "token": token, "input": B64.encode(envelope.to_string()), "plugin_name": "fake" })
    }

    fn no_storage(_: &Value) -> Value {
        Value::Null
    }

    #[test]
    fn single_shot_answers_set_response_then_done() {
        rt().block_on(async {
            let env = json!({ "op": "list", "path": "roles", "data": {} });
            let (res, seen) = drive(init("tok", env), vec![], |_| json!({ "keys": ["readonly", "nested/"] })).await;
            res.unwrap();
            assert_eq!(seen[0]["type"], "host_call");
            assert_eq!(seen[0]["method"], "storage_list");
            assert_eq!(seen[1]["type"], "set_response");
            let body: Value =
                serde_json::from_slice(&B64.decode(seen[1]["data_b64"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(body, json!({ "data": { "keys": ["readonly"] } }));
            assert_eq!(seen[2], json!({ "type": "done", "status": 0 }));
        });
    }

    #[test]
    fn a_wrong_bootstrap_token_is_refused_before_anything_runs() {
        rt().block_on(async {
            let env = json!({ "op": "list", "path": "roles", "data": {} });
            let (res, seen) = drive(init("not-the-token", env), vec![], no_storage).await;
            assert!(matches!(res, Err(ProcessError::Bootstrap)));
            assert!(seen.is_empty(), "{seen:?}");
        });
    }

    #[test]
    fn long_lived_says_hello_then_serves_invokes() {
        rt().block_on(async {
            let env = json!({ "op": "dynamic.nope" });
            let invoke = json!({ "type": "invoke", "id": 5, "input": B64.encode(env.to_string()) });
            let (res, seen) = drive(json!({ "type": "init", "plugin_name": "fake" }), vec![invoke], no_storage).await;
            res.unwrap();
            assert_eq!(seen[0], json!({ "type": "hello", "token": "tok" }));
            assert_eq!(seen[1]["type"], "invoke_done");
            assert_eq!(seen[1]["id"], 5);
            assert_eq!(seen[1]["status"], status::UNSUPPORTED);
        });
    }

    #[test]
    fn host_reply_errors_are_read_under_either_tag() {
        rt().block_on(async {
            let (host_to_plugin, plugin_in) = tokio::io::duplex(4096);
            let (plugin_out, _plugin_to_host) = tokio::io::duplex(4096);
            let mut w = host_to_plugin;
            let reply = json!({ "type": "host_reply_error", "id": 1, "error": "forbidden" });
            w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
            let (mut r, mut wr, mut id) = (BufReader::new(plugin_in), plugin_out, 0u64);
            let mut host = crate::process::StdioHost::new(&mut r, &mut wr, &mut id);
            let err = crate::host::HostCalls::dynamic_call(
                &mut host,
                crate::host::DynamicMethod::PoolCheckout,
                json!({ "connection": "prod" }),
            )
            .await
            .unwrap_err();
            assert_eq!(err, DynamicError::Forbidden("dynamic_pool_checkout"));
        });
    }
}
