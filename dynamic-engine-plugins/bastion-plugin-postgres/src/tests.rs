//! The engine against a fake PostgreSQL (statement order, quoting, revoke
//! idempotence, error mapping), through the SDK's in-memory host.

use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

use async_trait::async_trait;
use bastion_plugin_dynamic_sdk::{
    status,
    testing::{invoke, MockHost},
    DynamicError, TlsPolicy,
};
use serde_json::{json, Value};

use crate::{
    target::{Connector, Session, Target},
    PostgresBackend,
};

const PASSWORD: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
const ROOT: &str = "root-password-very-secret";
const USER: &str = "v-root-readonly-1793000000-0a1b2c3d";

#[derive(Default)]
struct FakeDb {
    roles: RefCell<BTreeSet<String>>,
    /// Every committed transaction, statement by statement.
    committed: RefCell<Vec<Vec<String>>>,
    /// A statement containing this text fails (and its transaction with it).
    fail_on: RefCell<Option<String>>,
    /// (root user, root password, TLS policy) of every connection opened.
    dials: RefCell<Vec<(String, String, TlsPolicy)>>,
}

fn quoted_name(statement: &str) -> Option<String> {
    let start = statement.find('"')? + 1;
    let rest = &statement[start..];
    let mut name = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if chars.peek() == Some(&'"') {
                chars.next();
                name.push('"');
                continue;
            }
            return Some(name);
        }
        name.push(c);
    }
    None
}

struct FakeSession(Rc<FakeDb>);

#[async_trait(?Send)]
impl Session for FakeSession {
    async fn execute_in_transaction(&mut self, statements: &[&str]) -> Result<(), DynamicError> {
        if let Some(bad) = self.0.fail_on.borrow().as_deref() {
            if let Some(s) = statements.iter().find(|s| s.contains(bad)) {
                return Err(DynamicError::target(format!("postgres error 42601: syntax error near {s}")));
            }
        }
        let mut roles = self.0.roles.borrow_mut();
        for s in statements {
            let name = quoted_name(s).unwrap_or_default();
            if s.starts_with("CREATE ROLE") {
                roles.insert(name);
            } else if s.starts_with("DROP ROLE IF EXISTS") {
                roles.remove(&name);
            } else if s.starts_with("DROP ROLE") && !roles.remove(&name) {
                return Err(DynamicError::target("postgres error 42704: role does not exist"));
            }
        }
        self.0.committed.borrow_mut().push(statements.iter().map(|s| s.to_string()).collect());
        Ok(())
    }

    async fn role_exists(&mut self, name: &str) -> Result<bool, DynamicError> {
        Ok(self.0.roles.borrow().contains(name))
    }
}

struct FakeConnector(Rc<FakeDb>);

#[async_trait(?Send)]
impl Connector for FakeConnector {
    async fn connect(&self, target: &Target, tls: &TlsPolicy) -> Result<Box<dyn Session>, DynamicError> {
        let dial = (target.username.clone(), target.password.expose().to_string(), tls.clone());
        self.0.dials.borrow_mut().push(dial);
        Ok(Box::new(FakeSession(self.0.clone())))
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

fn engine() -> (PostgresBackend<FakeConnector>, Rc<FakeDb>) {
    let db = Rc::new(FakeDb::default());
    (PostgresBackend::new(FakeConnector(db.clone())), db)
}

async fn configured(engine: &PostgresBackend<FakeConnector>) -> MockHost {
    let mut host = MockHost::granting_all().with_connection("prod");
    let conn = json!({ "op": "write", "path": "config/prod", "data": {
        "connection_url": "postgres://db.internal:5432/app", "username": "vault", "password": ROOT,
        "allowed_roles": ["readonly"] } });
    let (r, _) = invoke(engine, &mut host, &conn).await;
    assert_eq!(r.status, 0, "{:?}", r.json());
    let role = json!({ "op": "write", "path": "roles/readonly", "data": {
        "connection": "prod",
        "creation_statements": [
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'",
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\""
        ] } });
    let (r, _) = invoke(engine, &mut host, &role).await;
    assert_eq!(r.status, 0, "{:?}", r.json());
    host
}

fn generate() -> Value {
    json!({
        "op": "dynamic.generate", "role": "readonly", "connection": "prod",
        "statements": [
            format!("CREATE ROLE \"{USER}\" WITH LOGIN PASSWORD '{PASSWORD}' VALID UNTIL '2026-10-26T18:32:11Z'"),
            format!("GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{USER}\""),
        ],
        "credential": { "username": USER, "password": PASSWORD, "expiration": "2026-10-26T18:32:11Z" },
        "ttl_secs": 600,
    })
}

fn lease_op(op: &str, statements: Value) -> Value {
    json!({ "op": op, "role": "readonly", "connection": "prod", "username": USER, "statements": statements,
            "expiration": "2026-10-26T19:00:00Z", "ttl_secs": 300, "internal": { "v": 1 } })
}

fn body(r: &bastion_plugin_dynamic_sdk::dispatch::Reply) -> String {
    String::from_utf8_lossy(&r.body).to_string()
}

#[test]
fn generate_runs_the_host_statements_in_one_transaction_and_leases_once() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        let (r, diag) = invoke(&engine, &mut host, &generate()).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        let committed = db.committed.borrow().clone();
        assert_eq!(committed.len(), 1, "one transaction");
        assert_eq!(
            committed[0],
            generate()["statements"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect::<Vec<_>>()
        );
        assert!(db.roles.borrow().contains(USER));
        assert_eq!(host.leases.len(), 1);
        assert_eq!(
            host.events,
            [json!({ "event": "generate", "target_identity_type": "postgres_role", "detail": { "statements": "2" } })]
        );
        assert!(!body(&r).contains(PASSWORD) && !body(&r).contains(ROOT));
        assert!(diag.is_empty());
        let dial = db.dials.borrow()[0].clone();
        assert_eq!(
            (dial.0.as_str(), dial.1.as_str(), dial.2.verify),
            ("vault", ROOT, true),
            "root creds, verified TLS"
        );
    });
}

#[test]
fn a_failing_statement_leaves_nothing_and_its_error_is_redacted() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        *db.fail_on.borrow_mut() = Some("PASSWORD".into());
        let (r, diag) = invoke(&engine, &mut host, &generate()).await;
        assert_eq!(r.status, status::TARGET);
        assert!(db.roles.borrow().is_empty(), "the transaction rolled back");
        assert!(host.leases.is_empty());
        let text = body(&r);
        assert!(text.contains("42601") && text.contains("<redacted>") && !text.contains(PASSWORD), "{text}");
        assert!(diag.iter().all(|l| !l.contains(PASSWORD)), "{diag:?}");
    });
}

#[test]
fn revoke_drops_owned_objects_then_the_role_and_is_idempotent() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        invoke(&engine, &mut host, &generate()).await;
        let (r, _) = invoke(&engine, &mut host, &lease_op("dynamic.revoke", json!([]))).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        let last = db.committed.borrow().last().cloned().unwrap();
        assert_eq!(last, [format!("DROP OWNED BY \"{USER}\""), format!("DROP ROLE IF EXISTS \"{USER}\"")]);
        assert!(db.roles.borrow().is_empty());

        let before = db.committed.borrow().len();
        let (r, _) =
            invoke(&engine, &mut host, &lease_op("dynamic.revoke", json!([format!("DROP ROLE \"{USER}\"")]))).await;
        assert_eq!(r.status, 0, "a second revoke succeeds: {}", body(&r));
        assert_eq!(db.committed.borrow().len(), before, "nothing ran against a role that is gone");
        assert_eq!(host.events.last().unwrap()["detail"], json!({ "already_absent": "true" }));
    });
}

#[test]
fn operator_revocation_statements_run_as_rendered() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        invoke(&engine, &mut host, &generate()).await;
        let custom = json!([format!("REVOKE ALL ON DATABASE app FROM \"{USER}\""), format!("DROP ROLE \"{USER}\"")]);
        let (r, _) = invoke(&engine, &mut host, &lease_op("dynamic.revoke", custom.clone())).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        assert_eq!(Value::from(db.committed.borrow().last().cloned().unwrap()), custom);
    });
}

#[test]
fn a_hostile_username_stays_one_quoted_identifier() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        let evil = "x\"; DROP TABLE users; --";
        db.roles.borrow_mut().insert(evil.to_string());
        let mut env = lease_op("dynamic.revoke", json!([]));
        env["username"] = json!(evil);
        let (r, _) = invoke(&engine, &mut host, &env).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        let last = db.committed.borrow().last().cloned().unwrap();
        assert_eq!(last[1], "DROP ROLE IF EXISTS \"x\"\"; DROP TABLE users; --\"");
    });
}

#[test]
fn renew_extends_valid_until_by_default() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        invoke(&engine, &mut host, &generate()).await;
        let (r, _) = invoke(&engine, &mut host, &lease_op("dynamic.renew", json!([]))).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        let last = db.committed.borrow().last().cloned().unwrap();
        assert_eq!(last, [format!("ALTER ROLE \"{USER}\" VALID UNTIL '2026-10-26T19:00:00Z'")]);
        let mut bad = lease_op("dynamic.renew", json!([]));
        bad["expiration"] = json!("tomorrow'; DROP ROLE vault; --");
        assert_eq!(invoke(&engine, &mut host, &bad).await.0.status, status::PROTOCOL);
    });
}

#[test]
fn rotate_root_alters_the_root_role_and_stores_the_host_secret() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        let new_root = "Zq9-host-generated-root-secret";
        let rotate =
            json!({ "op": "dynamic.rotate_root", "connection": "prod", "credential": { "password": new_root } });
        let (r, _) = invoke(&engine, &mut host, &rotate).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        assert_eq!(
            db.committed.borrow().last().unwrap(),
            &[format!("ALTER ROLE \"vault\" WITH PASSWORD '{new_root}'")]
        );
        assert!(!body(&r).contains(new_root));
        // The next call dials with the new root credential.
        invoke(&engine, &mut host, &generate()).await;
        assert_eq!(db.dials.borrow().last().unwrap().1, new_root);
    });
}

#[test]
fn rotate_root_puts_the_old_password_back_when_it_cannot_store_the_new_one() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        host.fail_storage_put = true;
        let new_root = "Zq9-host-generated-root-secret";
        let rotate =
            json!({ "op": "dynamic.rotate_root", "connection": "prod", "credential": { "password": new_root } });
        let (r, _) = invoke(&engine, &mut host, &rotate).await;
        assert_eq!(r.status, status::UNAVAILABLE, "{}", body(&r));
        assert_eq!(db.committed.borrow().last().unwrap(), &[format!("ALTER ROLE \"vault\" WITH PASSWORD '{ROOT}'")]);
        assert!(!body(&r).contains(new_root) && !body(&r).contains(ROOT), "{}", body(&r));
    });
}

#[test]
fn connections_and_roles_are_checked_when_written() {
    rt().block_on(async {
        let (engine, _) = engine();
        let mut host = configured(&engine).await;
        for bad in [
            json!({ "connection_url": "postgres://vault:hunter2@db/app" }),
            json!({ "connection_url": "host=db user=vault" }),
            json!({ "username": "a\u{0}b" }),
            json!({ "tls_ca_pem": "x" }),
        ] {
            let w = json!({ "op": "write", "path": "config/prod", "data": bad });
            assert_eq!(invoke(&engine, &mut host, &w).await.0.status, status::INVALID, "{w}");
        }
        let read = json!({ "op": "read", "path": "config/prod", "data": {} });
        let (r, _) = invoke(&engine, &mut host, &read).await;
        assert!(!body(&r).contains(ROOT) && !body(&r).contains("hunter2"), "{}", body(&r));
        assert_eq!(r.json().unwrap()["data"]["username"], "vault");

        let role = json!({ "op": "write", "path": "roles/empty", "data": { "connection": "prod" } });
        assert_eq!(
            invoke(&engine, &mut host, &role).await.0.status,
            status::INVALID,
            "creation statements are required"
        );
    });
}

#[test]
fn insecure_tls_comes_only_from_the_host_and_is_warned_about() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured(&engine).await;
        host.tls = Some(json!({ "verify": false }));
        let (r, diag) = invoke(&engine, &mut host, &generate()).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        assert!(!db.dials.borrow()[0].2.verify);
        assert!(diag.iter().any(|l| l.contains("insecure_skip_tls_verify")), "{diag:?}");
    });
}

// ── A host with a `postgres` connector runs the statements itself ──────

async fn configured_on_executing_host(engine: &PostgresBackend<FakeConnector>) -> MockHost {
    let mut host = configured(engine).await;
    host.host_execute.insert("postgres".into());
    host
}

#[test]
fn an_executing_host_runs_generate_renew_and_revoke_and_the_plugin_never_dials() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured_on_executing_host(&engine).await;
        for env in [generate(), lease_op("dynamic.renew", json!([])), lease_op("dynamic.revoke", json!([]))] {
            let (r, diag) = invoke(&engine, &mut host, &env).await;
            assert_eq!(r.status, 0, "{}: {}", env["op"], body(&r));
            assert!(!body(&r).contains(ROOT) && diag.iter().all(|l| !l.contains(ROOT)), "{diag:?}");
        }
        assert!(db.dials.borrow().is_empty(), "the host dialled, not the plugin");
        assert!(db.committed.borrow().is_empty());
        let ops: Vec<&str> = host.executions.iter().map(|e| e["op"].as_str().unwrap()).collect();
        assert_eq!(ops, ["dynamic.generate", "dynamic.renew", "dynamic.revoke"]);
        for e in &host.executions {
            assert_eq!((e["kind"].as_str(), e["username"].as_str()), (Some("postgres"), Some("vault")));
            assert_eq!(e["url"], "postgres://db.internal:5432/app");
            assert!(!e.to_string().contains(ROOT), "the mock records no root secret");
        }
        assert_eq!(host.leases.len(), 1, "the lease is still registered once, after the host ran the statements");
    });
}

#[test]
fn an_executing_host_reports_an_absent_role_and_its_refusal_is_final() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured_on_executing_host(&engine).await;
        host.execution_reply = Some(json!({ "executed": 0, "identity_absent": true }));
        let (r, _) = invoke(&engine, &mut host, &lease_op("dynamic.revoke", json!([]))).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        assert_eq!(host.events.last().unwrap()["detail"], json!({ "already_absent": "true" }));

        // A refused host execution (here: a TLS failure the host reports) is
        // the operation's failure; the plugin does not dial around it.
        host.fail_execution = Some(format!("unavailable: certificate verify failed for root {ROOT}"));
        let (r, _) = invoke(&engine, &mut host, &generate()).await;
        assert_eq!(r.status, status::UNAVAILABLE, "{}", body(&r));
        assert!(!body(&r).contains(ROOT), "the root secret is redacted: {}", body(&r));
        assert!(db.dials.borrow().is_empty(), "no fallback dial");
        assert!(host.leases.is_empty());
    });
}

#[test]
fn rotate_root_dials_even_on_an_executing_host() {
    rt().block_on(async {
        let (engine, db) = engine();
        let mut host = configured_on_executing_host(&engine).await;
        let new_root = "Zq9-host-generated-root-secret";
        let rotate =
            json!({ "op": "dynamic.rotate_root", "connection": "prod", "credential": { "password": new_root } });
        let (r, _) = invoke(&engine, &mut host, &rotate).await;
        assert_eq!(r.status, 0, "{}", body(&r));
        assert_eq!(db.dials.borrow().len(), 1);
        assert!(host.executions.is_empty(), "the host renders no rotate-root statement to execute");
        // The next generate goes through the host with the new root secret.
        invoke(&engine, &mut host, &generate()).await;
        assert_eq!(host.executions.len(), 1);
    });
}
