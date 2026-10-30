//! ABI 1.4 host calls: refusal order, grants, release rules and the release
//! audit (features/sql-browser.md Testing Plan, "Kernel and host").

use std::sync::Arc;

use serde_json::{json, Value};

use super::*;
use crate::{
    logical::Auth,
    modules::system::denial_audit_store::{DenialAuditStore, SQL_PRIVILEGE_REASON},
    plugins::sql_grants::tests_support::sql_manifest,
    test_utils::{new_unseal_test_bastion_vault, test_write_api},
};

const PASSWORD: &str = "S3cr3t-db-password-never-logged";

fn caller_req(policies: &[&str], entity: &str) -> Request {
    let mut auth = Auth { policies: policies.iter().map(|p| p.to_string()).collect(), ..Default::default() };
    auth.display_name = "userpass-ana".into();
    auth.metadata.insert("entity_id".into(), entity.into());
    let mut req = Request::new("dbms/v2/sessions");
    req.auth = Some(auth);
    req.client_token = "caller-token".into();
    req
}

fn caller(policies: &[&str]) -> InvocationCaller {
    InvocationCaller::from_request(&caller_req(policies, "ent-ana")).unwrap()
}

fn params_for(method: &str) -> Value {
    match method {
        "resource_sql_target" => json!({"resource": "netrisk-db"}),
        "resource_sql_authorize" => {
            json!({"resource": "netrisk-db", "checks": [{"capability": "sql_select", "target": "server"}]})
        }
        "resource_sql_credential" => json!({"resource": "netrisk-db", "profile": "ro", "session_ref": "s-1"}),
        "connect_ticket_redeem" => json!({"resource": "netrisk-db", "profile": "ro", "ticket": "t-1"}),
        other => panic!("{other}"),
    }
}

struct FakeSource {
    protocol: &'static str,
    transport: &'static str,
    sql_endpoint: Option<Value>,
    require_mfa: bool,
}

impl FakeSource {
    fn bound() -> Self {
        Self { protocol: "sql", transport: "direct", sql_endpoint: Some(json!("db1.example.net:5432")), require_mfa: false }
    }
}

impl SqlResourceSource for FakeSource {
    fn sql_target<'a>(&'a self, _: &'a dyn VaultCtx, ns: &'a str, resource: &'a str) -> SqlFuture<'a, Value> {
        Box::pin(async move { Ok(json!({"engine": "postgresql", "ns": ns, "resource": resource})) })
    }
    fn sql_release_material<'a>(
        &'a self,
        _: &'a dyn VaultCtx,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> SqlFuture<'a, SqlReleaseMaterial> {
        Box::pin(async move { Ok(SqlReleaseMaterial {
            protocol: self.protocol.into(),
            endpoint: SqlEndpoint::parse("DB1.example.net:5432").unwrap(),
            transport: self.transport.into(),
            transport_source: "resource tier".into(),
            secret_id: "svc_netrisk_ro".into(),
            sql_endpoint: self.sql_endpoint.clone(),
            username: "svc_netrisk_ro".into(),
            password: Zeroizing::new(PASSWORD.to_string()),
            require_mfa: self.require_mfa,
        }) })
    }
}

fn code(e: &str) -> &str {
    e.split(':').next().unwrap_or(e)
}

// ── pure rules ──────────────────────────────────────────────────────────

#[test]
fn endpoints_parse_strictly() {
    let ok = |s: &str| SqlEndpoint::parse(s).unwrap_or_else(|| panic!("{s}"));
    assert_eq!(ok("DB.example:5432"), SqlEndpoint { host: "db.example".into(), port: 5432 });
    assert_eq!(ok("[::1]:1433").host, "::1");
    assert_eq!(ok("[::1]:1433").to_string(), "[::1]:1433");
    assert_eq!(ok("10.0.0.1:3306").to_string(), "10.0.0.1:3306");
    for bad in ["", "db", "db:", "db:0", "db:65536", ":5432", "db :1", "::1:5432", "[::1]5432", "a/b:1", "db:x"] {
        assert!(SqlEndpoint::parse(bad).is_none(), "{bad:?}");
    }
}

fn material(protocol: &str, transport: &str, bound: Option<Value>) -> SqlReleaseMaterial {
    SqlReleaseMaterial {
        protocol: protocol.into(),
        endpoint: SqlEndpoint::parse("db1.example.net:5432").unwrap(),
        transport: transport.into(),
        transport_source: "asset group prod".into(),
        secret_id: "s".into(),
        sql_endpoint: bound,
        username: "u".into(),
        password: Zeroizing::new("p".into()),
        require_mfa: false,
    }
}

/// §5.4 rules 3–5, each refusal named.
#[test]
fn release_rules_refuse_each_violation() {
    use ReleaseRefusal::*;
    let ep = Some(json!("db1.example.net:5432"));
    assert_eq!(check_release(&material("sql", "direct", ep.clone())), Ok(()));
    assert_eq!(check_release(&material("sql", "rustion-preferred", ep.clone())), Ok(()));
    assert_eq!(check_release(&material("SQL", "direct", ep.clone())), Err(ProfileNotSql));
    assert_eq!(check_release(&material("ssh", "direct", ep.clone())), Err(ProfileNotSql));
    assert_eq!(
        check_release(&material("sql", "rustion-required", ep.clone())),
        Err(RustionRequired { source: "asset group prod".into() })
    );
    assert_eq!(check_release(&material("sql", "rustion", ep.clone())), Err(TransportUnknown));
    assert_eq!(check_release(&material("sql", "", ep)), Err(TransportUnknown));
    for unbound in [None, Some(Value::Null), Some(json!([]))] {
        assert_eq!(check_release(&material("sql", "direct", unbound.clone())), Err(EndpointUnbound), "{unbound:?}");
    }
    for invalid in [json!(5432), json!({"host": "db1"}), json!(["db1.example.net:5432", "nope"]), json!("db1")] {
        assert_eq!(check_release(&material("sql", "direct", Some(invalid.clone()))), Err(EndpointInvalid), "{invalid}");
    }
    for other in [json!("db1.example.net:5433"), json!("db2.example.net:5432"), json!(["evil.example:5432"])] {
        assert_eq!(check_release(&material("sql", "direct", Some(other.clone()))), Err(EndpointMismatch), "{other}");
    }
    let list = json!(["db0.example.net:5432", "DB1.EXAMPLE.NET:5432"]);
    assert_eq!(check_release(&material("sql", "direct", Some(list))), Ok(()));
}

#[test]
fn checks_parse_strictly() {
    assert_eq!(
        parse_check(&json!({"capability": "sql_update", "target": {"catalog": "c", "schema": "s", "object": "o"}}))
            .unwrap(),
        SqlCheck {
            capability: SqlCapability::Update,
            target: SqlTarget::Object { catalog: "c".into(), schema: "s".into(), object: "o".into() }
        }
    );
    for bad in [
        json!({"capability": "sql_select"}),
        json!({"capability": "select", "target": "server"}),
        json!({"capability": "sql_select", "target": "objects"}),
        json!({"capability": "sql_select", "target": "server", "plugin": "x"}),
        json!({"capability": "sql_select", "target": {"catalog": "c", "schema": "s"}}),
        json!({"capability": "sql_select", "target": {"catalog": "c", "schema": "s", "object": 1}}),
        json!({"capability": "sql_select", "target": {"catalog": "c", "schema": "s", "object": "o", "x": "y"}}),
        json!("sql_select"),
    ] {
        assert_eq!(code(&parse_check(&bad).unwrap_err()), codes::BAD_REQUEST, "{bad}");
    }
}

// ── refusal order, no core needed ───────────────────────────────────────

/// Outside an invocation every call is refused, before any grant or core
/// is consulted.
#[tokio::test]
async fn every_call_is_refused_outside_an_invocation() {
    let m = sql_manifest();
    for method in METHODS {
        let e = handle(&m, None, method, &params_for(method), None).await.unwrap_err();
        assert_eq!(e, codes::NO_INVOCATION, "{method}");
    }
}

#[tokio::test]
async fn every_call_is_forbidden_without_its_manifest_capability() {
    let mut m = sql_manifest();
    m.capabilities.sql_gate = false;
    m.capabilities.resource_credentials.clear();
    let c = caller(&["default"]);
    for method in METHODS {
        let e = handle(&m, None, method, &params_for(method), Some(&c)).await.unwrap_err();
        assert_eq!(e, codes::FORBIDDEN, "{method}");
    }
}

// ── with a vault ────────────────────────────────────────────────────────

async fn grant_all(core: &Arc<dyn VaultCtx>, m: &PluginManifest) {
    for k in SqlGrantKind::ALL {
        sql_grants::put(core.barrier().as_storage(), k, m, "admin", "t".into()).await.unwrap();
    }
}

async fn reader_policy(core: &Arc<crate::core::Core>, root: &str) {
    test_write_api(
        core.as_ref(),
        root,
        "sys/policy/sql-reader",
        true,
        json!({"policy": "path \"resources/resources/netrisk-db/sql/*\" {\n  capabilities = [\"sql_select\"]\n}\n"})
            .as_object()
            .cloned(),
    )
    .await
    .unwrap();
}

/// No grant → `not_granted`; a grant pinned to another capability block
/// is void, the same as no grant.
#[tokio::test]
async fn calls_need_a_live_grant_and_a_changed_manifest_voids_it() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("sql_host_grants").await;
    reader_policy(&core, &root).await;
    let core: Arc<dyn VaultCtx> = core;
    let m = sql_manifest();
    let c = caller(&["sql-reader"]);
    for method in METHODS {
        let e = handle(&m, Some(&core), method, &params_for(method), Some(&c)).await.unwrap_err();
        assert_eq!(code(&e), codes::NOT_GRANTED, "{method}: {e}");
    }

    grant_all(&core, &m).await;
    let v = handle(&m, Some(&core), "resource_sql_authorize", &params_for("resource_sql_authorize"), Some(&c))
        .await
        .unwrap();
    assert_eq!(v["verdicts"][0]["allowed"], true);

    let mut changed = m.clone();
    changed.capabilities.storage_prefix = Some("dbms/".into());
    for method in METHODS {
        let e = handle(&changed, Some(&core), method, &params_for(method), Some(&c)).await.unwrap_err();
        assert_eq!(code(&e), codes::NOT_GRANTED, "{method} after a manifest change: {e}");
    }
}

/// `resource_sql_authorize` decides with `Enforce { plugin }`: refusals land
/// in the denial store naming the plugin.
#[tokio::test]
async fn authorize_records_refusals_for_the_plugin() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("sql_host_authorize").await;
    reader_policy(&core, &root).await;
    let vault: Arc<dyn VaultCtx> = core.clone();
    let m = sql_manifest();
    grant_all(&vault, &m).await;
    let p = json!({"resource": "NetRisk-DB", "checks": [
        {"capability": "sql_select", "target": {"catalog": "netrisk", "schema": "public", "object": "users"}},
        {"capability": "sql_drop", "target": "server"},
    ]});
    let v = handle(&m, Some(&vault), "resource_sql_authorize", &p, Some(&caller(&["sql-reader"]))).await.unwrap();
    assert_eq!(v["resource"], "netrisk-db");
    assert_eq!(v["verdicts"][0]["allowed"], true);
    assert_eq!(v["verdicts"][1]["allowed"], false);
    assert_eq!(v["verdicts"][1]["path"], "resources/resources/netrisk-db/sql/server");

    let store = DenialAuditStore::from_core(core.as_ref()).unwrap();
    let denials: Vec<_> =
        store.list_all().await.unwrap().into_iter().filter(|e| e.reason == SQL_PRIVILEGE_REASON).collect();
    assert_eq!(denials.len(), 1, "{denials:?}");
    assert_eq!(denials[0].capability, "sql_drop");
    assert_eq!(denials[0].plugin, "dbms-management");

    let bad = json!({"resource": "netrisk-db", "checks": [{"capability": "sql_nope", "target": "server"}]});
    let e = handle(&m, Some(&vault), "resource_sql_authorize", &bad, Some(&caller(&["sql-reader"]))).await;
    assert_eq!(code(&e.unwrap_err()), codes::BAD_REQUEST);
}

/// A host without the resource engine's seam refuses explicitly; the vault
/// installs the real one at assembly, which answers `not_found` for a
/// resource that does not exist.
#[tokio::test]
async fn the_seam_is_explicit_and_the_vault_installs_the_engine() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("sql_host_unavailable").await;
    reader_policy(&core, &root).await;
    let core: Arc<dyn VaultCtx> = core;
    let m = sql_manifest();
    grant_all(&core, &m).await;
    let c = caller(&["sql-reader"]);
    let p = params_for("resource_sql_target");
    let e = sql_target(&m, Some(&core), &p, Some(&c), &UnavailableSqlSource).await.unwrap_err();
    assert_eq!(code(&e), codes::NOT_AVAILABLE, "{e}");
    let p = params_for("resource_sql_credential");
    let e = sql_credential(&m, Some(&core), &p, Some(&c), &UnavailableSqlSource).await.unwrap_err();
    assert_eq!(code(&e), codes::NOT_AVAILABLE, "{e}");
    for method in ["resource_sql_target", "resource_sql_credential"] {
        let e = handle(&m, Some(&core), method, &params_for(method), Some(&c)).await.unwrap_err();
        assert_eq!(code(&e), codes::NOT_FOUND, "{method}: {e}");
        assert!(e.contains("resource_not_found"), "{e}");
    }
}

/// `sql.require_mfa`: the release needs a ticket redeemed for that profile by
/// the same invocation, spent once; a refusal the operator can fix does not
/// spend it.
#[tokio::test]
async fn an_mfa_gated_profile_releases_only_after_a_redemption_in_the_invocation() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("sql_host_release_mfa").await;
    reader_policy(&core, &root).await;
    let vault: Arc<dyn VaultCtx> = core.clone();
    let m = sql_manifest();
    grant_all(&vault, &m).await;
    let p = params_for("resource_sql_credential");
    let gated = FakeSource { require_mfa: true, ..FakeSource::bound() };
    let c = caller(&["sql-reader"]);

    let e = sql_credential(&m, Some(&vault), &p, Some(&c), &gated).await.unwrap_err();
    assert_eq!(e.split(": ").nth(1), Some("mfa_required"), "{e}");

    c.record_mfa_redemption("", "netrisk-db", "other-profile");
    let e = sql_credential(&m, Some(&vault), &p, Some(&c), &gated).await.unwrap_err();
    assert!(e.contains("mfa_required"), "a ticket for another profile does not count: {e}");

    c.record_mfa_redemption("", "netrisk-db", "ro");
    let unbound = FakeSource { sql_endpoint: None, ..FakeSource { require_mfa: true, ..FakeSource::bound() } };
    let e = sql_credential(&m, Some(&vault), &p, Some(&c), &unbound).await.unwrap_err();
    assert!(e.contains("endpoint_unbound"), "{e}");
    let ok = sql_credential(&m, Some(&vault), &p, Some(&c), &gated).await.unwrap();
    assert_eq!(ok["password"], PASSWORD, "the binding refusal did not spend the redemption");
    let e = sql_credential(&m, Some(&vault), &p, Some(&c), &gated).await.unwrap_err();
    assert!(e.contains("mfa_required"), "one redemption, one release: {e}");

    let other = caller(&["sql-reader"]);
    other.record_mfa_redemption("", "netrisk-db", "ro");
    let e = sql_credential(&m, Some(&vault), &p, Some(&c), &gated).await.unwrap_err();
    assert!(e.contains("mfa_required"), "another invocation's redemption does not count: {e}");
}

/// §5.4: every refusal case of a credential release, and the one success.
/// The released password never reaches an error or the audit log.
#[tokio::test]
async fn credential_release_refusals_and_the_release_audit() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("sql_host_release").await;
    reader_policy(&core, &root).await;
    let log_path = std::env::temp_dir().join(format!(
        "bv-sql-release-{}.log",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    test_write_api(
        core.as_ref(),
        &root,
        "sys/audit/primary",
        true,
        json!({"type": "file", "options": {"file_path": log_path.display().to_string()}}).as_object().cloned(),
    )
    .await
    .unwrap();
    let vault: Arc<dyn VaultCtx> = core.clone();
    let m = sql_manifest();
    grant_all(&vault, &m).await;
    let p = params_for("resource_sql_credential");
    let reader = caller(&["sql-reader"]);

    let refusals: [(FakeSource, &str); 5] = [
        (FakeSource { sql_endpoint: None, ..FakeSource::bound() }, "endpoint_unbound"),
        (FakeSource { sql_endpoint: Some(json!("attacker.example:5432")), ..FakeSource::bound() }, "endpoint_mismatch"),
        (FakeSource { sql_endpoint: Some(json!(["db1.example.net"])), ..FakeSource::bound() }, "endpoint_invalid"),
        (FakeSource { protocol: "ssh", ..FakeSource::bound() }, "profile_not_sql"),
        (FakeSource { transport: "rustion-required", ..FakeSource::bound() }, "rustion_required"),
    ];
    for (source, reason) in refusals {
        let e = sql_credential(&m, Some(&vault), &p, Some(&reader), &source).await.unwrap_err();
        assert_eq!(code(&e), codes::REFUSED, "{reason}: {e}");
        assert!(e.contains(reason), "{reason}: {e}");
        assert!(!e.contains(PASSWORD));
    }

    // A caller holding no SQL capability is refused before the material is read.
    let nobody = caller(&["default"]);
    let e = sql_credential(&m, Some(&vault), &p, Some(&nobody), &FakeSource::bound()).await.unwrap_err();
    assert_eq!(code(&e), codes::NO_SQL_PRIVILEGE, "{e}");

    // Malformed parameters.
    for bad in [
        json!({"resource": "netrisk-db", "profile": "ro"}),
        json!({"resource": "netrisk-db", "profile": "ro", "session_ref": "s", "secret_id": "x"}),
        json!({"resource": "a/b", "profile": "ro", "session_ref": "s"}),
        json!({"resource": "netrisk-db", "profile": "", "session_ref": "s"}),
        json!({"resource": "netrisk-db", "profile": "ro", "session_ref": "s\n"}),
    ] {
        let e = sql_credential(&m, Some(&vault), &bad, Some(&reader), &FakeSource::bound()).await.unwrap_err();
        assert_eq!(code(&e), codes::BAD_REQUEST, "{bad}: {e}");
    }

    let ok = sql_credential(&m, Some(&vault), &p, Some(&reader), &FakeSource::bound()).await.unwrap();
    assert_eq!(ok["username"], "svc_netrisk_ro");
    assert_eq!(ok["password"], PASSWORD);
    assert_eq!(ok["endpoint"], "db1.example.net:5432");
    assert_eq!(ok["secret_id"], "svc_netrisk_ro");

    let log = tokio::fs::read_to_string(&log_path).await.unwrap();
    assert!(!log.contains(PASSWORD), "a released credential reached the audit log");
    let releases: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["request"]["path"] == RELEASE_EVENT)
        .collect();
    let outcomes: Vec<(&str, &str)> = releases
        .iter()
        .map(|e| (e["request"]["data"]["outcome"].as_str().unwrap(), e["request"]["data"]["reason"].as_str().unwrap_or("")))
        .collect();
    assert!(outcomes.contains(&("released", "")), "{outcomes:?}");
    for reason in ["endpoint_unbound", "endpoint_mismatch", "profile_not_sql", "rustion_required", "no_sql_privilege"] {
        assert!(outcomes.contains(&("refused", reason)), "{reason} missing from {outcomes:?}");
    }
    let released = releases.iter().find(|e| e["request"]["data"]["outcome"] == "released").unwrap();
    assert_eq!(released["request"]["data"]["plugin"], "dbms-management");
    assert_eq!(released["request"]["data"]["session_ref"], "s-1");
    assert_eq!(released["request"]["data"]["secret_id"], "svc_netrisk_ro");
    assert_eq!(released["auth"]["metadata"]["entity_id"], "ent-ana");
    assert!(released["auth"]["client_token"].as_str().unwrap().starts_with("hmac:"));
    let _ = std::fs::remove_file(&log_path);
}

#[tokio::test]
async fn target_returns_the_seam_view_with_the_held_privileges() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("sql_host_target").await;
    reader_policy(&core, &root).await;
    let vault: Arc<dyn VaultCtx> = core;
    let m = sql_manifest();
    grant_all(&vault, &m).await;
    let p = json!({"resource": " NetRisk-DB "});
    let v = sql_target(&m, Some(&vault), &p, Some(&caller(&["sql-reader"])), &FakeSource::bound()).await.unwrap();
    assert_eq!(v["resource"], "netrisk-db");
    assert_eq!(v["privileges"], json!(["sql_select"]));
    assert_eq!(v["target"]["engine"], "postgresql");
    let e = sql_target(&m, Some(&vault), &p, Some(&caller(&["default"])), &FakeSource::bound()).await.unwrap_err();
    assert_eq!(code(&e), codes::NO_SQL_PRIVILEGE);
}

/// T126: a malformed step-up action is refused as `bad_request` before any
/// privilege is read; a well-formed one goes to the action redemption,
/// which refuses a ticket it cannot bind (here: no userpass principal).
/// The end-to-end binding cases are in `engine_tests/resource_sql.rs`.
#[tokio::test]
async fn ticket_redeem_parses_the_action_strictly() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("sql_host_ticket").await;
    reader_policy(&core, &root).await;
    let vault: Arc<dyn VaultCtx> = core;
    let m = sql_manifest();
    grant_all(&vault, &m).await;
    let c = caller(&["sql-reader"]);
    for bad in [json!(""), json!("drop"), json!("sql_drop,sql_drop"), json!("sql_drop, sql_script"), json!(["sql_drop"])]
    {
        let p = json!({"resource": "netrisk-db", "profile": "ro", "ticket": "t-1", "action": bad});
        let e = handle(&m, Some(&vault), "connect_ticket_redeem", &p, Some(&c)).await.unwrap_err();
        assert_eq!(code(&e), codes::BAD_REQUEST, "{bad}: {e}");
    }
    let nobody = caller(&["default"]);
    let p = json!({"resource": "netrisk-db", "profile": "ro", "ticket": "t-1", "action": "sql_drop"});
    let e = handle(&m, Some(&vault), "connect_ticket_redeem", &p, Some(&nobody)).await.unwrap_err();
    assert_eq!(code(&e), codes::NO_SQL_PRIVILEGE, "{e}");
    let e = handle(&m, Some(&vault), "connect_ticket_redeem", &p, Some(&c)).await.unwrap_err();
    assert_eq!(code(&e), codes::REFUSED, "{e}");
    assert!(!c.take_mfa_redemption("", "netrisk-db", "ro"), "a refused action records nothing");
}
