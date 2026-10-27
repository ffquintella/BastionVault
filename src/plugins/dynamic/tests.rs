//! A mock dynamic plugin driven through a real vault: mount, lease manager
//! (slice 1), dynamic host and the shared host-call gate.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use serde_json::{json, Value};

use super::mock::{self, MockHost, MockPlugin};
use crate::{
    errors::RvError,
    kernel_api::{namespace::NAMESPACE_HEADER, VaultCtx},
    logical::{Operation, Request, Response},
    modules::auth::expiration::LEASE_VIEW_PREFIX,
    plugins::{
        manifest::{Capabilities, PluginManifest, RuntimeKind, PLUGIN_TYPE_DYNAMIC},
        PluginCatalog,
    },
    storage::Storage,
    test_utils::new_unseal_test_bastion_vault,
};

const BINARY: &[u8] = b"mock dynamic plugin";

/// A fake database: records every envelope and the identities it holds.
#[derive(Default)]
struct FakeDb {
    envelopes: Mutex<Vec<Value>>,
    users: Mutex<BTreeSet<String>>,
    roles: Mutex<BTreeMap<String, Value>>,
    failing_revokes: AtomicU32,
    skip_lease: AtomicBool,
    /// Create the identity, then fail before registering its lease.
    fail_after_create: AtomicBool,
    /// A failing revoke names the last generated password in its error.
    echo_password_on_revoke: AtomicBool,
    /// `(token, namespace)`: once, while generating, read `database/creds/readonly`
    /// again as that token, so a lease lands while this one is in flight.
    reenter: Mutex<Option<(String, String)>>,
}

impl FakeDb {
    fn with_role(self: Arc<Self>, name: &str, recipe: Value) -> Arc<Self> {
        self.roles.lock().unwrap().insert(name.to_string(), recipe);
        self
    }

    fn ops(&self) -> Vec<String> {
        self.envelopes.lock().unwrap().iter().map(|e| e["op"].as_str().unwrap_or("").to_string()).collect()
    }

    fn last(&self, op: &str) -> Value {
        self.envelopes.lock().unwrap().iter().rev().find(|e| e["op"] == op).cloned().unwrap_or(Value::Null)
    }
}

fn host_err(e: String) -> (i32, String) {
    (3, e)
}

#[async_trait::async_trait]
impl MockPlugin for FakeDb {
    async fn handle(&self, env: Value, host: &MockHost<'_>) -> Result<Value, (i32, String)> {
        self.envelopes.lock().unwrap().push(env.clone());
        let user = env["username"].as_str().unwrap_or("").to_string();
        match env["op"].as_str().unwrap_or("") {
            "dynamic.role" => {
                let role = env["role"].as_str().unwrap_or("");
                Ok(json!({ "data": self.roles.lock().unwrap().get(role).cloned() }))
            }
            "dynamic.generate" => {
                host.call("dynamic_pool_checkout", json!({ "connection": env["connection"] }))
                    .await
                    .map_err(host_err)?;
                let created = env["credential"]["username"].as_str().unwrap_or("").to_string();
                self.users.lock().unwrap().insert(created);
                let reenter = self.reenter.lock().unwrap().take();
                if let Some((token, namespace)) = reenter {
                    let mut req = Request::new("database/creds/readonly");
                    req.operation = Operation::Read;
                    req.client_token = token;
                    req.headers = Some([(NAMESPACE_HEADER.to_string(), namespace)].into_iter().collect());
                    host.core().handle_request(&mut req).await.expect("the inner request gets its lease");
                }
                if self.fail_after_create.load(Ordering::SeqCst) {
                    return Err((5, "lost the connection after CREATE ROLE".into()));
                }
                if !self.skip_lease.load(Ordering::SeqCst) {
                    let lease = json!({ "internal": {"oid": 7}, "ttl_secs": 600, "max_ttl_secs": 1200 });
                    host.call("dynamic_lease_register", lease).await.map_err(host_err)?;
                }
                let event = json!({ "event": "generate", "target_identity_type": "postgres_user" });
                host.call("dynamic_audit_emit", event).await.map_err(host_err)?;
                Ok(json!({ "data": { "connection_url": "postgres://db.example/app", "password": "plugin-chosen" } }))
            }
            "dynamic.renew" => Ok(json!({ "data": { "internal": { "oid": 7, "renewed": true } } })),
            "dynamic.revoke" => {
                if self.failing_revokes.load(Ordering::SeqCst) > 0 {
                    self.failing_revokes.fetch_sub(1, Ordering::SeqCst);
                    if self.echo_password_on_revoke.load(Ordering::SeqCst) {
                        let generated = self.last("dynamic.generate");
                        let password = generated["credential"]["password"].as_str().unwrap_or("");
                        return Err((1, format!("DROP ROLE failed: role {user} still logged in with {password}")));
                    }
                    return Err((1, "target unreachable".into()));
                }
                self.users.lock().unwrap().remove(&user);
                Ok(json!({}))
            }
            "dynamic.rotate_root" => Ok(json!({ "data": { "new_root_password": "must-not-leak" } })),
            // Proxied `config/` and `roles/` requests: echo what arrived, and
            // try to hand out a lease (which the host must drop).
            _ => Ok(json!({
                "data": { "seen": env["data"], "path": env["path"] },
                "secret": { "ttl_secs": 60, "internal_data": {} },
            })),
        }
    }
}

fn manifest(name: &str, caps: Capabilities) -> PluginManifest {
    use sha2::{Digest, Sha256};
    PluginManifest {
        name: name.to_string(),
        version: "0.1.0".to_string(),
        plugin_type: PLUGIN_TYPE_DYNAMIC.to_string(),
        engine_type: Some("database".to_string()),
        runtime: RuntimeKind::Wasm,
        abi_version: "1.5".to_string(),
        sha256: hex::encode(Sha256::digest(BINARY)),
        size: BINARY.len() as u64,
        capabilities: caps,
        description: String::new(),
        config_schema: vec![],
        signature: String::new(),
        signing_key: String::new(),
        surface: None,
        client_assets: vec![],
    }
}

fn all_caps() -> Capabilities {
    Capabilities {
        dynamic_lease_register: true,
        dynamic_audit_emit: true,
        dynamic_pool_checkout: true,
        ..Default::default()
    }
}

const RECIPE: &str = r#"{
    "connection": "prod",
    "creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'"],
    "revocation_statements": ["DROP ROLE \"{{name}}\""],
    "renew_statements": ["ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}'"],
    "default_ttl_secs": 900,
    "max_ttl_secs": 3600
}"#;

struct Fixture {
    _bv: crate::BastionVault,
    core: Arc<dyn VaultCtx>,
    root: String,
    db: Arc<FakeDb>,
    name: String,
}

impl Fixture {
    async fn new(name: &str, caps: Capabilities) -> Self {
        let (bv, core, root) = new_unseal_test_bastion_vault(name).await;
        let core: Arc<dyn VaultCtx> = core;
        let db = Arc::new(FakeDb::default()).with_role("readonly", serde_json::from_str(RECIPE).unwrap());
        let plugin = format!("dyn-{name}");
        mock::register(&plugin, db.clone());
        let storage = core.barrier();
        crate::plugins::verifier::write_accept_unsigned(storage.as_storage(), true).await.unwrap();
        PluginCatalog::new().put(storage.as_storage(), &manifest(&plugin, caps), BINARY).await.unwrap();
        crate::test_utils::test_mount_api(core.as_ref(), &root, &format!("plugin:{plugin}"), "database").await;
        let fx = Self { _bv: bv, core, root, db, name: plugin };
        fx.write("database/config/prod", json!({ "connection_url": "postgres://db.example/app" })).await.unwrap();
        fx
    }

    async fn call(&self, op: Operation, path: &str, body: Value) -> Result<Option<Response>, RvError> {
        self.call_as(&self.root, None, op, path, body).await
    }

    async fn call_as(
        &self,
        token: &str,
        namespace: Option<&str>,
        op: Operation,
        path: &str,
        body: Value,
    ) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = op;
        req.client_token = token.to_string();
        req.body = body.as_object().cloned();
        if let Some(ns) = namespace {
            req.headers = Some([(NAMESPACE_HEADER.to_string(), ns.to_string())].into_iter().collect());
        }
        self.core.handle_request(&mut req).await
    }

    async fn write(&self, path: &str, body: Value) -> Result<Option<Response>, RvError> {
        self.call(Operation::Write, path, body).await
    }

    async fn creds(&self) -> Result<Response, RvError> {
        Ok(self.call(Operation::Read, "database/creds/readonly", Value::Null).await?.expect("a credential"))
    }

    async fn lease_row(&self, lease_id: &str) -> bool {
        let view = self.core.system_view().unwrap().new_sub_view(LEASE_VIEW_PREFIX);
        view.get(lease_id).await.unwrap().is_some()
    }

    async fn revoke_failed_ids(&self) -> Value {
        let resp = self.call(Operation::List, "sys/leases/revoke-failed", Value::Null).await.unwrap().unwrap();
        resp.data.unwrap()["keys"].clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        mock::unregister(&self.name);
    }
}

fn status_of(r: &Result<Option<Response>, RvError>) -> Option<u16> {
    match r {
        Err(RvError::ErrResponseStatus(s, _)) => Some(*s),
        _ => None,
    }
}

#[tokio::test]
async fn generate_renew_revoke_through_the_lease_manager() {
    let fx = Fixture::new("dyn_lifecycle", all_caps()).await;

    let resp = fx.creds().await.unwrap();
    let data = resp.data.clone().unwrap();
    let username = data["username"].as_str().unwrap().to_string();
    let password = data["password"].as_str().unwrap().to_string();
    assert!(username.starts_with("v-root-readonly-"), "{username}");
    assert_eq!(password.len(), bv_dynamic::credential::PASSWORD_LEN, "the host's password, not the plugin's");
    assert_ne!(password, "plugin-chosen");
    assert_eq!(data["connection_url"], "postgres://db.example/app");

    // The lease is the kernel's (slice 1): registered even without
    // `leased_passthrough`, clamped to the plugin's 600 s.
    let secret = resp.secret.unwrap();
    assert!(secret.lease_id.starts_with("database/creds/readonly/"), "{}", secret.lease_id);
    assert_eq!(secret.ttl.as_secs(), 600);
    assert!(fx.lease_row(&secret.lease_id).await);

    // The host rendered the statements; the plugin got values, no tokens.
    let generate = fx.db.last("dynamic.generate");
    let statement = generate["statements"][0].as_str().unwrap();
    assert!(statement.contains(&username) && statement.contains(&password), "{statement}");
    assert!(!statement.contains("{{"), "{statement}");
    assert!(fx.db.users.lock().unwrap().contains(&username));

    // Renew through `sys/renew`: the plugin is asked, with a rendered renew
    // statement and the opaque internal blob it registered.
    let renewed = fx.write(&format!("sys/renew/{}", secret.lease_id), json!({ "increment": 300 })).await.unwrap();
    assert_eq!(renewed.unwrap().secret.unwrap().ttl.as_secs(), 300);
    let renew = fx.db.last("dynamic.renew");
    assert_eq!(renew["username"], username.as_str());
    assert_eq!(renew["internal"], json!({ "oid": 7 }));
    assert!(renew["statements"][0].as_str().unwrap().starts_with(&format!("ALTER ROLE \"{username}\" VALID UNTIL '")));

    // Revoke: the plugin drops the identity with the pre-rendered statement
    // and the internal blob as the renewal left it. No password goes along.
    fx.write(&format!("sys/revoke/{}", secret.lease_id), Value::Null).await.unwrap();
    let revoke = fx.db.last("dynamic.revoke");
    assert_eq!(revoke["statements"], json!([format!("DROP ROLE \"{username}\"")]));
    assert_eq!(revoke["internal"], json!({ "oid": 7, "renewed": true }));
    assert!(!revoke.to_string().contains(&password), "a revoke never carries the credential");
    assert!(!renew.to_string().contains(&password), "a renew never carries the credential");
    assert!(fx.db.users.lock().unwrap().is_empty());
    assert!(!fx.lease_row(&secret.lease_id).await);
    // The fixture's `config/prod` write was proxied as a generic envelope.
    assert_eq!(fx.db.ops(), ["write", "dynamic.role", "dynamic.generate", "dynamic.renew", "dynamic.revoke"]);
}

#[tokio::test]
async fn a_failed_revoke_is_kept_as_revoke_failed_and_a_retry_revokes_it() {
    let fx = Fixture::new("dyn_revoke_failed", all_caps()).await;
    let lease_id = fx.creds().await.unwrap().secret.unwrap().lease_id;

    fx.db.failing_revokes.store(1, Ordering::SeqCst);
    let first = fx.write(&format!("sys/revoke/{lease_id}"), Value::Null).await;
    assert_eq!(status_of(&first), Some(502), "{first:?}");
    assert!(fx.lease_row(&lease_id).await, "a failed revoke must not drop the lease");
    assert_eq!(fx.revoke_failed_ids().await, json!([lease_id]));
    assert_eq!(fx.db.users.lock().unwrap().len(), 1, "the identity is still in the target");

    fx.write(&format!("sys/revoke/{lease_id}"), Value::Null).await.unwrap();
    assert!(!fx.lease_row(&lease_id).await);
    assert!(fx.db.users.lock().unwrap().is_empty());
    assert_eq!(fx.revoke_failed_ids().await, json!([]));
}

/// A lease outlives its plugin: with the plugin deleted (quarantined) the
/// revoke fails and the lease is kept; once the plugin is registered again
/// the host loads it to revoke. Nothing needs the plugin resident.
#[tokio::test]
async fn a_lease_outlives_its_plugin_and_the_host_reloads_it_to_revoke() {
    let fx = Fixture::new("dyn_unloaded", all_caps()).await;
    let lease_id = fx.creds().await.unwrap().secret.unwrap().lease_id;
    let storage = fx.core.barrier();

    PluginCatalog::new().delete(storage.as_storage(), &fx.name).await.unwrap();
    crate::plugins::process_supervisor::shutdown_for(&fx.name).await;
    let refused = fx.write(&format!("sys/revoke/{lease_id}"), Value::Null).await;
    assert!(refused.is_err());
    assert!(fx.lease_row(&lease_id).await, "the host never silently drops a lease it could not revoke");
    assert_eq!(fx.revoke_failed_ids().await, json!([lease_id]));
    assert!(!fx.db.ops().contains(&"dynamic.revoke".to_string()), "the plugin was unreachable");

    PluginCatalog::new().put(storage.as_storage(), &manifest(&fx.name, all_caps()), BINARY).await.unwrap();
    fx.write(&format!("sys/revoke/{lease_id}"), Value::Null).await.unwrap();
    assert!(fx.db.ops().contains(&"dynamic.revoke".to_string()));
    assert!(fx.db.users.lock().unwrap().is_empty());
    assert!(!fx.lease_row(&lease_id).await);
}

#[tokio::test]
async fn a_plugin_that_registers_no_lease_has_its_credential_revoked() {
    let fx = Fixture::new("dyn_no_lease", all_caps()).await;
    fx.db.skip_lease.store(true, Ordering::SeqCst);
    let refused = fx.call(Operation::Read, "database/creds/readonly", Value::Null).await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    assert_eq!(fx.db.ops().last().map(String::as_str), Some("dynamic.revoke"), "the host took the identity back");
    assert!(fx.db.users.lock().unwrap().is_empty(), "no orphaned target identity");
    let view = fx.core.system_view().unwrap().new_sub_view(LEASE_VIEW_PREFIX);
    assert!(view.list("database/creds/readonly/").await.unwrap().is_empty());
}

/// A plugin failing after it created the identity: the host revokes it,
/// and the plugin's error reaches the caller without the password.
#[tokio::test]
async fn a_plugin_failing_half_way_has_its_identity_revoked() {
    let fx = Fixture::new("dyn_half_way", all_caps()).await;
    fx.db.fail_after_create.store(true, Ordering::SeqCst);
    let refused = fx.call(Operation::Read, "database/creds/readonly", Value::Null).await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    assert!(format!("{refused:?}").contains("lost the connection"), "{refused:?}");
    let password = fx.db.last("dynamic.generate")["credential"]["password"].as_str().unwrap().to_string();
    assert!(!format!("{refused:?}").contains(&password));
    assert_eq!(fx.db.ops().last().map(String::as_str), Some("dynamic.revoke"));
    assert!(fx.db.users.lock().unwrap().is_empty(), "no orphaned target identity");
}

/// A plugin making a dynamic host call it did not declare fails the request
/// and is quarantined; its mount refuses everything until re-registered.
#[tokio::test]
async fn an_out_of_manifest_call_fails_closed_and_quarantines() {
    let caps = Capabilities { dynamic_pool_checkout: false, ..all_caps() };
    let fx = Fixture::new("dyn_violation", caps).await;
    let refused = fx.call(Operation::Read, "database/creds/readonly", Value::Null).await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let storage = fx.core.barrier();
    let rec = crate::plugins::quarantine::lookup(storage.as_storage(), &fx.name).await.unwrap().unwrap();
    assert!(rec.reason.contains("dynamic_pool_checkout"), "{}", rec.reason);
    assert!(fx.db.users.lock().unwrap().is_empty(), "the refused plugin created nothing");
    let after = fx.call(Operation::Read, "database/creds/readonly", Value::Null).await;
    assert!(format!("{after:?}").contains("quarantined"), "{after:?}");
}

#[tokio::test]
async fn unknown_roles_and_unsafe_templates_are_refused_before_generation() {
    let fx = Fixture::new("dyn_refusals", all_caps()).await;
    let missing = fx.call(Operation::Read, "database/creds/nope", Value::Null).await;
    assert_eq!(status_of(&missing), Some(404), "{missing:?}");

    let bad = json!({ "connection": "prod", "creation_statements": ["CREATE ROLE {{user}}"] });
    fx.db.roles.lock().unwrap().insert("bad".into(), bad);
    let refused = fx.call(Operation::Read, "database/creds/bad", Value::Null).await;
    assert_eq!(status_of(&refused), Some(400), "{refused:?}");

    let leaky = json!({ "connection": "prod", "revocation_statements": ["DROP ROLE {{name}} -- {{password}}"] });
    fx.db.roles.lock().unwrap().insert("leaky".into(), leaky);
    assert_eq!(status_of(&fx.call(Operation::Read, "database/creds/leaky", Value::Null).await), Some(400));

    assert!(!fx.db.ops().contains(&"dynamic.generate".to_string()), "nothing reached the target");
    let other = fx.call(Operation::Read, "database/anything", Value::Null).await;
    assert_eq!(status_of(&other), Some(404));
}

#[tokio::test]
async fn config_tls_is_host_owned_and_rotate_root_drains_the_pool() {
    let fx = Fixture::new("dyn_rotate", all_caps()).await;
    let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
    let wrote = fx
        .write("database/config/prod", json!({ "connection_url": "postgres://x", "tls_ca_pem": pem }))
        .await
        .unwrap()
        .unwrap();
    // The plugin never sees the TLS policy, and no proxied path leases.
    assert!(wrote.data.unwrap()["seen"].get("tls_ca_pem").is_none());
    assert!(wrote.secret.is_none());

    fx.creds().await.unwrap();
    let read = fx.call(Operation::Read, "database/config/prod", Value::Null).await.unwrap().unwrap();
    let data = read.data.unwrap();
    assert_eq!(data["tls_ca_pem"], pem);
    assert_eq!(data["insecure_skip_tls_verify"], false);
    assert_eq!(data["root_credential_version"], 1);

    let rotated = fx.write("database/rotate-root/prod", Value::Null).await.unwrap().unwrap();
    let rotated = rotated.data.unwrap();
    assert_eq!(rotated["root_credential_version"], 2);
    assert!(rotated.get("new_root_password").is_none(), "the plugin's answer is not relayed");
    // The new root credential is the host's, like every credential it makes.
    let envelope = fx.db.last("dynamic.rotate_root");
    let new_root = envelope["credential"]["password"].as_str().unwrap().to_string();
    assert_eq!(new_root.len(), bv_dynamic::credential::PASSWORD_LEN);
    assert!(!Value::Object(rotated.clone()).to_string().contains(&new_root), "never answered to the caller");
    let read = fx.call(Operation::Read, "database/config/prod", Value::Null).await.unwrap().unwrap();
    assert_eq!(read.data.unwrap()["root_credential_version"], 2);

    let insecure = fx.write("database/config/prod", json!({ "insecure_skip_tls_verify": "nope" })).await;
    assert_eq!(status_of(&insecure), Some(400));
}

#[test]
fn the_host_pool_drains_a_rotated_target() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pool = super::pool::host_pool();
        let key = super::pool::target_key("mount-test", "prod");
        let settings = bv_dynamic::pool::TargetSettings {
            root_credential_version: 1,
            config_generation: 0,
            tls: bv_dynamic::pool::TlsPolicy::default(),
        };
        pool.configure(&key, settings);
        drop(pool.checkout(&key).await.unwrap());
        assert_eq!(pool.idle_count(&key), 1);
        pool.rotate(&key, 2).unwrap();
        assert_eq!(pool.idle_count(&key), 0);
        let grant = pool.checkout(&key).await.unwrap();
        assert_eq!(grant.key().root_credential_version, 2);
        assert!(grant.tls.verifies(), "TLS verification is the default");
    });
}

#[test]
fn a_session_accepts_one_lease_request() {
    let s = super::DynamicSession::new(super::DynamicVerb::Generate, "m", None);
    let req = bv_dynamic::records::LeaseRequest::parse(&json!({ "ttl_secs": 1 })).unwrap();
    s.set_lease_request(req.clone()).unwrap();
    assert!(s.set_lease_request(req).is_err(), "a second registration for one credential is refused");
}

// ── Fix pass: lease registration, audit, storage scope, credential cache ──

/// A process-wide `log` sink. nextest runs each test in its own process, so
/// the first `install` sees every line the server writes, events included
/// (`mcp_events::emit` logs each one on target `security`).
mod capture {
    use std::sync::{Mutex, OnceLock};

    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    const QUIET: [&str; 4] = ["cranelift", "wasmtime", "regalloc", "wasmparser"];

    struct Capture;

    impl log::Log for Capture {
        fn enabled(&self, m: &log::Metadata<'_>) -> bool {
            !QUIET.iter().any(|q| m.target().starts_with(q))
        }
        fn log(&self, r: &log::Record<'_>) {
            if self.enabled(r.metadata()) {
                let line = format!("{} {} {}", r.level(), r.target(), r.args());
                LINES.get_or_init(Default::default).lock().unwrap().push(line);
            }
        }
        fn flush(&self) {}
    }

    static LOGGER: Capture = Capture;

    pub fn install() -> bool {
        *INSTALLED.get_or_init(|| {
            let ok = log::set_logger(&LOGGER).is_ok();
            if ok {
                log::set_max_level(log::LevelFilter::Debug);
            }
            ok
        })
    }

    pub fn lines() -> Vec<String> {
        LINES.get_or_init(Default::default).lock().unwrap().clone()
    }
}

const LOGIN_PASSWORD: &str = "hunter22XX!";

impl Fixture {
    /// The namespace `ns` (at most `max_leases` leases) with the plugin
    /// mounted at `database/` and `config/prod` written in it.
    async fn namespace_mount(&self, ns: &str, max_leases: u64) {
        self.write(&format!("sys/namespaces/{ns}"), json!({ "max_leases": max_leases })).await.unwrap();
        let mount = json!({ "type": format!("plugin:{}", self.name) });
        self.call_as(&self.root, Some(ns), Operation::Write, "sys/mounts/database", mount).await.unwrap();
        let config = json!({ "connection_url": "postgres://db.example/app" });
        self.call_as(&self.root, Some(ns), Operation::Write, "database/config/prod", config).await.unwrap();
    }

    /// Userpass logins for `names`: `(token, entity id)` each.
    async fn logins(&self, names: &[&str]) -> Vec<(String, String)> {
        let policy = r#"path "database/creds/*" { capabilities = ["read"] }"#;
        self.write("sys/policy/dyn-user", json!({ "policy": policy })).await.unwrap();
        self.write("sys/auth/pass", json!({ "type": "userpass" })).await.unwrap();
        let mut out = Vec::new();
        for name in names {
            let user = json!({ "password": LOGIN_PASSWORD, "token_policies": "dyn-user" });
            self.write(&format!("auth/pass/users/{name}"), user).await.unwrap();
            let login = json!({ "password": LOGIN_PASSWORD });
            let resp = self.call_as("", None, Operation::Write, &format!("auth/pass/login/{name}"), login).await;
            let auth = resp.unwrap().unwrap().auth.unwrap();
            let entity = auth.metadata.get("entity_id").cloned().unwrap_or_default();
            assert!(!entity.is_empty(), "a userpass login is entity-backed");
            out.push((auth.client_token, entity));
        }
        out
    }

    /// `role` with RECIPE's statements and a credential-cache window.
    fn cached_role(&self, role: &str, cache_ttl_secs: u64) {
        let mut recipe: Value = serde_json::from_str(RECIPE).unwrap();
        recipe["cache_ttl_secs"] = json!(cache_ttl_secs);
        self.db.roles.lock().unwrap().insert(role.to_string(), recipe);
    }

    async fn creds_as(&self, token: &str, role: &str) -> Response {
        let path = format!("database/creds/{role}");
        self.call_as(token, None, Operation::Read, &path, Value::Null).await.unwrap().expect("a credential")
    }

    fn generates(&self) -> usize {
        self.db.ops().iter().filter(|op| *op == "dynamic.generate").count()
    }
}

fn generated(fx: &Fixture, field: &str) -> String {
    fx.db.last("dynamic.generate")["credential"][field].as_str().unwrap().to_string()
}

fn data_str(resp: &Response, key: &str) -> String {
    resp.data.as_ref().unwrap()[key].as_str().unwrap_or_default().to_string()
}

/// A (security review): the namespace's lease quota is checked before the
/// plugin is asked to create anything on the target.
#[tokio::test]
async fn a_namespace_at_its_lease_quota_is_refused_before_the_plugin_creates_anything() {
    let fx = Fixture::new("dyn_quota_precheck", all_caps()).await;
    fx.namespace_mount("ns1", 1).await;
    let path = "database/creds/readonly";
    fx.call_as(&fx.root, Some("ns1"), Operation::Read, path, Value::Null).await.unwrap();
    let refused = fx.call_as(&fx.root, Some("ns1"), Operation::Read, path, Value::Null).await;
    assert!(format!("{refused:?}").contains("leases"), "{refused:?}");
    assert_eq!(fx.generates(), 1, "the plugin was never asked for a second credential");
    assert_eq!(fx.db.users.lock().unwrap().len(), 1, "nothing was left on the target");
}

/// A: a credential whose lease cannot be registered (the quota filled while
/// it was being created) is revoked on the target, not left there.
#[tokio::test]
async fn a_credential_whose_lease_cannot_be_registered_is_revoked_on_the_target() {
    let fx = Fixture::new("dyn_take_back", all_caps()).await;
    fx.namespace_mount("ns1", 1).await;
    *fx.db.reenter.lock().unwrap() = Some((fx.root.clone(), "ns1".to_string()));
    let path = "database/creds/readonly";
    let refused = fx.call_as(&fx.root, Some("ns1"), Operation::Read, path, Value::Null).await;
    assert!(format!("{refused:?}").contains("leases"), "{refused:?}");

    let created: Vec<String> = fx
        .db
        .envelopes
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e["op"] == "dynamic.generate")
        .map(|e| e["credential"]["username"].as_str().unwrap().to_string())
        .collect();
    let [outer, inner] = created.as_slice() else { panic!("two credentials were created: {created:?}") };
    assert_eq!(*fx.db.users.lock().unwrap(), BTreeSet::from([inner.clone()]), "the unleased identity is gone");
    assert_eq!(fx.db.last("dynamic.revoke")["username"], outer.as_str());
    assert_eq!(fx.revoke_failed_ids().await, json!([]));
}

/// A: ... and when that revoke fails too, it is kept as `revoke_failed`.
#[tokio::test]
async fn an_unregistered_credential_whose_revoke_fails_is_kept_as_revoke_failed() {
    let fx = Fixture::new("dyn_take_back_failed", all_caps()).await;
    fx.namespace_mount("ns1", 1).await;
    *fx.db.reenter.lock().unwrap() = Some((fx.root.clone(), "ns1".to_string()));
    fx.db.failing_revokes.store(1, Ordering::SeqCst);
    let path = "database/creds/readonly";
    assert!(fx.call_as(&fx.root, Some("ns1"), Operation::Read, path, Value::Null).await.is_err());
    let ids = fx.revoke_failed_ids().await;
    let ids = ids.as_array().cloned().unwrap_or_default();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert!(ids[0].as_str().unwrap().starts_with("ns1/database/creds/readonly/"), "{ids:?}");
}

/// B: a plugin quarantined half-way through `generate` is not called again,
/// but the identity it may have created is named in the log and the audit.
#[tokio::test]
async fn an_out_of_manifest_call_after_creating_the_identity_is_audited_as_revoke_failed() {
    assert!(capture::install(), "this test needs the process logger");
    // Undeclared, and called after the identity was created and leased.
    let caps = Capabilities { dynamic_audit_emit: false, ..all_caps() };
    let fx = Fixture::new("dyn_violation_audit", caps).await;
    let refused = fx.call(Operation::Read, "database/creds/readonly", Value::Null).await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let (username, password) = (generated(&fx, "username"), generated(&fx, "password"));
    assert!(fx.db.users.lock().unwrap().contains(&username), "the identity exists on the target");
    assert!(!fx.db.ops().contains(&"dynamic.revoke".to_string()), "the quarantined plugin is not called again");

    let lines = capture::lines();
    let names_it = |l: &String| l.contains(&username) && l.contains("readonly") && l.contains("prod");
    assert!(lines.iter().any(|l| l.starts_with("ERROR") && names_it(l)), "{lines:#?}");
    let audited = |l: &String| l.contains("dynamic_secret") && l.contains("\"revoke_failed\"") && names_it(l);
    assert!(lines.iter().any(audited), "{lines:#?}");
    assert!(!lines.iter().any(|l| l.contains(&password)), "the password reached a log line");
}

/// C: a compensation revoke whose error echoes the password is redacted in
/// both the ERROR log line and the `revoke_failed` event.
#[tokio::test]
async fn a_failed_compensation_never_logs_or_audits_the_password() {
    assert!(capture::install(), "this test needs the process logger");
    let fx = Fixture::new("dyn_compensation_redacted", all_caps()).await;
    fx.db.fail_after_create.store(true, Ordering::SeqCst);
    fx.db.failing_revokes.store(1, Ordering::SeqCst);
    fx.db.echo_password_on_revoke.store(true, Ordering::SeqCst);
    let refused = fx.call(Operation::Read, "database/creds/readonly", Value::Null).await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let password = generated(&fx, "password");

    let lines = capture::lines();
    assert!(lines.iter().any(|l| l.starts_with("ERROR") && l.contains("<redacted>")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.contains("\"revoke_failed\"") && l.contains("<redacted>")), "{lines:#?}");
    assert!(!lines.iter().any(|l| l.contains(&password)), "the password reached a log line: {lines:#?}");
}

/// D: the lease row of a dynamic credential does not keep its password.
#[tokio::test]
async fn a_dynamic_lease_row_does_not_keep_the_password() {
    let fx = Fixture::new("dyn_row_no_password", all_caps()).await;
    let resp = fx.creds().await.unwrap();
    let password = data_str(&resp, "password");
    let lease_id = resp.secret.unwrap().lease_id;
    let view = fx.core.system_view().unwrap().new_sub_view(LEASE_VIEW_PREFIX);
    let raw = view.get(&lease_id).await.unwrap().expect("the lease row");
    assert!(!String::from_utf8_lossy(&raw.value).contains(&password));
}

/// A plugin that keeps proxied writes in its own storage (`storage_*`).
struct StoredDb;

#[async_trait::async_trait]
impl MockPlugin for StoredDb {
    async fn handle(&self, env: Value, host: &MockHost<'_>) -> Result<Value, (i32, String)> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let key = env["path"].as_str().unwrap_or("").to_string();
        match env["op"].as_str().unwrap_or("") {
            "write" => {
                let value = b64.encode(env["data"].to_string());
                host.call("storage_put", json!({ "key": key, "value_b64": value })).await.map_err(host_err)?;
                Ok(json!({ "data": null }))
            }
            "read" => match host.call("storage_get", json!({ "key": key })).await {
                Ok(v) => {
                    let bytes = b64.decode(v["value_b64"].as_str().unwrap_or("")).unwrap();
                    Ok(json!({ "data": serde_json::from_slice::<Value>(&bytes).unwrap() }))
                }
                Err(e) if e == "not_found" => Ok(json!({ "data": null })),
                Err(e) => Err(host_err(e)),
            },
            _ => Ok(json!({ "data": null })),
        }
    }
}

/// F: two mounts of one dynamic plugin never see each other's `config/` or
/// `roles/` (the plugin's storage is scoped to the mount).
#[tokio::test]
async fn two_mounts_of_one_dynamic_plugin_keep_separate_plugin_storage() {
    let (_bv, core, root) = new_unseal_test_bastion_vault("dyn_two_mounts").await;
    let core: Arc<dyn VaultCtx> = core;
    let plugin = "dyn-two-mounts";
    mock::register(plugin, Arc::new(StoredDb));
    let caps = Capabilities { storage_prefix: Some(String::new()), ..all_caps() };
    let storage = core.barrier();
    crate::plugins::verifier::write_accept_unsigned(storage.as_storage(), true).await.unwrap();
    PluginCatalog::new().put(storage.as_storage(), &manifest(plugin, caps), BINARY).await.unwrap();
    for mount in ["db-a", "db-b"] {
        crate::test_utils::test_mount_api(core.as_ref(), &root, &format!("plugin:{plugin}"), mount).await;
    }
    let call = |op: Operation, path: &str, body: Value| {
        let mut req = Request::new(path);
        req.operation = op;
        req.client_token = root.clone();
        req.body = body.as_object().cloned();
        let core = core.clone();
        async move { core.handle_request(&mut req).await }
    };
    call(Operation::Write, "db-a/roles/readonly", json!({ "connection": "prod" })).await.unwrap();
    call(Operation::Write, "db-a/config/prod", json!({ "connection_url": "postgres://a.example/app" })).await.unwrap();
    let own = call(Operation::Read, "db-a/roles/readonly", Value::Null).await.unwrap();
    assert_eq!(own.and_then(|r| r.data).unwrap()["connection"], "prod", "a mount reads its own role");

    let other_role = call(Operation::Read, "db-b/roles/readonly", Value::Null).await.unwrap();
    assert!(other_role.is_none(), "another mount's role leaked: {other_role:?}");
    let other_config = call(Operation::Read, "db-b/config/prod", Value::Null).await.unwrap();
    assert!(other_config.is_none(), "another mount's connection leaked: {other_config:?}");
    mock::unregister(plugin);
}

/// G: no role opts in by default; every read is a new credential.
#[tokio::test]
async fn the_credential_cache_is_off_unless_the_role_opts_in() {
    let fx = Fixture::new("dyn_cache_off", all_caps()).await;
    let alice = fx.logins(&["alice"]).await.remove(0).0;
    let first = fx.creds_as(&alice, "readonly").await;
    let second = fx.creds_as(&alice, "readonly").await;
    assert_ne!(data_str(&first, "username"), data_str(&second, "username"));
    assert!(first.secret.is_some() && second.secret.is_some());
    assert_eq!(fx.generates(), 2);
}

/// G: a hit hands the same credential and lease back, mints nothing, calls
/// no plugin, registers no lease and is audited without the credential; a
/// second identity never gets the first one's credential.
#[tokio::test]
async fn a_cached_credential_is_served_once_per_identity_without_a_second_lease() {
    assert!(capture::install(), "this test needs the process logger");
    let fx = Fixture::new("dyn_cache_hit", all_caps()).await;
    fx.cached_role("cached", 60);
    let users = fx.logins(&["alice", "bob"]).await;
    let (alice, bob) = (&users[0].0, &users[1].0);

    let miss = fx.creds_as(alice, "cached").await;
    let lease_id = miss.secret.clone().expect("a miss is leased").lease_id;
    let ops = fx.db.ops().len();
    let hit = fx.creds_as(alice, "cached").await;
    assert_eq!(fx.db.ops().len(), ops, "a hit never reaches the plugin");
    assert!(hit.secret.is_none(), "a hit carries no new lease");
    for key in ["username", "password", "connection_url"] {
        assert_eq!(data_str(&hit, key), data_str(&miss, key), "{key}");
    }
    assert_eq!(data_str(&hit, "lease_id"), lease_id, "the shared lease is named");
    let view = fx.core.system_view().unwrap().new_sub_view(LEASE_VIEW_PREFIX);
    assert_eq!(view.list("database/creds/cached/").await.unwrap().len(), 1, "one lease");

    let lines = capture::lines();
    let hit_event = lines.iter().find(|l| l.contains("dynamic_secret") && l.contains("\"cache_hit\""));
    let hit_event = hit_event.unwrap_or_else(|| panic!("no cache_hit event: {lines:#?}"));
    assert!(hit_event.contains(&lease_id) && hit_event.contains("\"cached\"") && hit_event.contains("\"prod\""));
    assert!(!lines.iter().any(|l| l.contains(&data_str(&miss, "password"))), "the credential reached a log");

    let other = fx.creds_as(bob, "cached").await;
    assert_ne!(data_str(&other, "username"), data_str(&miss, "username"), "never shared across identities");
    assert!(other.secret.is_some());
    assert_eq!(fx.generates(), 2);
}

/// G: revoking or renewing the lease, rotating the root credential and
/// unloading the plugin all drop the cached credential.
#[tokio::test]
async fn revoke_renew_rotate_root_and_unload_invalidate_the_cache() {
    let fx = Fixture::new("dyn_cache_invalidate", all_caps()).await;
    fx.cached_role("cached", 60);
    let alice = fx.logins(&["alice"]).await.remove(0).0;
    let username = |r: &Response| data_str(r, "username");

    let first = fx.creds_as(&alice, "cached").await;
    let lease = first.secret.clone().unwrap().lease_id;
    fx.write(&format!("sys/revoke/{lease}"), Value::Null).await.unwrap();
    let second = fx.creds_as(&alice, "cached").await;
    assert_ne!(username(&second), username(&first), "revoked: not served again");

    let lease = second.secret.clone().unwrap().lease_id;
    fx.write(&format!("sys/renew/{lease}"), json!({ "increment": 300 })).await.unwrap();
    let third = fx.creds_as(&alice, "cached").await;
    assert_ne!(username(&third), username(&second), "renewed: the cached expiry is stale");

    fx.write("database/rotate-root/prod", Value::Null).await.unwrap();
    let fourth = fx.creds_as(&alice, "cached").await;
    assert_ne!(username(&fourth), username(&third), "rotated root: dropped");

    let storage = fx.core.barrier();
    PluginCatalog::new().delete(storage.as_storage(), &fx.name).await.unwrap();
    PluginCatalog::new().put(storage.as_storage(), &manifest(&fx.name, all_caps()), BINARY).await.unwrap();
    let fifth = fx.creds_as(&alice, "cached").await;
    assert_ne!(username(&fifth), username(&fourth), "unloaded plugin: dropped");
    assert_eq!(fx.generates(), 5);
}

/// G: an entry lives no longer than the role's window.
#[tokio::test]
async fn a_cached_credential_expires_with_its_window() {
    let fx = Fixture::new("dyn_cache_expiry", all_caps()).await;
    fx.cached_role("cached", 1);
    let alice = fx.logins(&["alice"]).await.remove(0).0;
    let first = fx.creds_as(&alice, "cached").await;
    assert_eq!(data_str(&fx.creds_as(&alice, "cached").await, "username"), data_str(&first, "username"));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let later = fx.creds_as(&alice, "cached").await;
    assert_ne!(data_str(&later, "username"), data_str(&first, "username"));
    assert_eq!(fx.generates(), 2);
}

// ── Host-side connectors ─────────────────────────────────────────────────

use super::test_support::{fake_target, MemStorage};

const ROOT_SECRET: &str = "root-secret-of-the-fake-target";

/// A plugin that has the host execute: it checks out a slot, then asks for
/// `execute` on it, presenting its stored connection. `mode` makes it
/// misbehave in one named way.
struct HostExecDb {
    url: String,
    mode: Mutex<&'static str>,
    /// The host's answer to each `execute`, or its error.
    answers: Mutex<Vec<Result<Value, String>>>,
    /// The root secret the plugin has stored (what it presents).
    stored_root: Mutex<String>,
    /// The new secret of the last rotate-root envelope.
    rotated_to: Mutex<String>,
}

impl HostExecDb {
    fn new(url: &str) -> Arc<Self> {
        Arc::new(Self {
            url: url.to_string(),
            mode: Mutex::new("normal"),
            answers: Mutex::default(),
            stored_root: Mutex::new(ROOT_SECRET.to_string()),
            rotated_to: Mutex::default(),
        })
    }

    async fn execute(&self, host: &MockHost<'_>, connection: &Value) -> Result<Value, (i32, String)> {
        let mode = *self.mode.lock().unwrap();
        let grant = host.call("dynamic_pool_checkout", json!({ "connection": connection })).await.map_err(host_err)?;
        let kinds = grant["host_execute"].as_array().cloned().unwrap_or_default();
        if !kinds.contains(&json!("fake")) {
            return Err((6, "the host does not grant host execution".into()));
        }
        let slot = if mode == "unheld_slot" { json!(999_999) } else { grant["slot"].clone() };
        let mut execute = json!({
            "slot": slot,
            "connector": {
                "kind": "fake", "url": self.url, "username": "vault-root", "password": *self.stored_root.lock().unwrap()
            },
        });
        if mode == "smuggle_statements" {
            execute["statements"] = json!(["DROP DATABASE app"]);
        }
        if mode == "smuggle_tls" {
            execute["connector"]["insecure_skip_tls_verify"] = json!(true);
        }
        if mode == "other_url" {
            // An endpoint the operator never configured (a port-scan probe).
            execute["connector"]["url"] = json!("host=127.0.0.1 port=22");
        }
        let target = if mode == "other_connection" { json!("other") } else { connection.clone() };
        let request = json!({ "connection": target, "execute": execute });
        let mut answer = host.call("dynamic_pool_checkout", request.clone()).await;
        if mode == "execute_twice" && answer.is_ok() {
            answer = host.call("dynamic_pool_checkout", request).await;
        }
        self.answers.lock().unwrap().push(answer.clone());
        answer.map_err(host_err)
    }
}

#[async_trait::async_trait]
impl MockPlugin for HostExecDb {
    async fn handle(&self, env: Value, host: &MockHost<'_>) -> Result<Value, (i32, String)> {
        match env["op"].as_str().unwrap_or("") {
            "dynamic.role" => Ok(json!({ "data": serde_json::from_str::<Value>(RECIPE).unwrap() })),
            "dynamic.generate" => {
                self.execute(host, &env["connection"]).await?;
                let lease = json!({ "internal": {}, "ttl_secs": 600 });
                host.call("dynamic_lease_register", lease).await.map_err(host_err)?;
                Ok(json!({ "data": {} }))
            }
            "dynamic.renew" | "dynamic.revoke" => {
                self.execute(host, &env["connection"]).await?;
                Ok(json!({}))
            }
            "dynamic.rotate_root" => {
                let new = env["credential"]["password"].as_str().unwrap_or_default().to_string();
                *self.rotated_to.lock().unwrap() = new.clone();
                let mode = *self.mode.lock().unwrap();
                match mode {
                    // The runtime cuts the call short while the host still runs.
                    "abandon_execute" => {
                        let limit = std::time::Duration::from_millis(300);
                        if tokio::time::timeout(limit, self.execute(host, &env["connection"])).await.is_err() {
                            return Err((5, "the plugin call was cut short".into()));
                        }
                    }
                    "ignore_execute_error" => {
                        let _ = self.execute(host, &env["connection"]).await;
                    }
                    _ => {
                        self.execute(host, &env["connection"]).await?;
                    }
                }
                match mode {
                    // Ran to the end and says it did not store (the SDK's RootNotStored).
                    "fail_store" => Err((5, r#"{"error":"storage_put failed","root_stored":false}"#.into())),
                    // Stored, then failed without saying so.
                    "store_then_fail" => {
                        *self.stored_root.lock().unwrap() = new;
                        Err((5, "lost the host connection after storing".into()))
                    }
                    _ => {
                        *self.stored_root.lock().unwrap() = new;
                        Ok(json!({}))
                    }
                }
            }
            // A proxied call has no plan: an `execute` from it is refused.
            "write" if *self.mode.lock().unwrap() == "execute_on_proxy" => {
                self.execute(host, &json!("prod")).await?;
                Ok(json!({ "data": null }))
            }
            _ => Ok(json!({ "data": null })),
        }
    }
}

/// A vault with `plugin` mounted at `database/` and `config/prod` written.
async fn host_exec_vault(name: &str, plugin: Arc<HostExecDb>) -> (crate::BastionVault, Arc<dyn VaultCtx>, String) {
    let url = plugin.url.clone();
    let (bv, core, root) = new_unseal_test_bastion_vault(name).await;
    let core: Arc<dyn VaultCtx> = core;
    let plugin_name = format!("dyn-{name}");
    mock::register(&plugin_name, plugin);
    let storage = core.barrier();
    crate::plugins::verifier::write_accept_unsigned(storage.as_storage(), true).await.unwrap();
    PluginCatalog::new().put(storage.as_storage(), &manifest(&plugin_name, all_caps()), BINARY).await.unwrap();
    crate::test_utils::test_mount_api(core.as_ref(), &root, &format!("plugin:{plugin_name}"), "database").await;
    for conn in ["prod", "other"] {
        let mut req = Request::new(&format!("database/config/{conn}"));
        req.operation = Operation::Write;
        req.client_token = root.clone();
        // The host pins this endpoint; the plugin must present exactly it.
        req.body = json!({ "connection_url": url, "username": "vault-root" }).as_object().cloned();
        core.handle_request(&mut req).await.unwrap();
    }
    (bv, core, root)
}

async fn root_call(
    core: &Arc<dyn VaultCtx>,
    root: &str,
    op: Operation,
    path: &str,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = root.to_string();
    if op == Operation::Write {
        req.body = Some(serde_json::Map::new());
    }
    core.handle_request(&mut req).await
}

/// The host dials (once, with the operator's verifying TLS policy and the
/// plugin's stored root secret) and runs exactly the statements it rendered:
/// the role's creation, renew and revocation statements, on one pooled socket.
#[tokio::test]
async fn the_host_executes_its_rendered_statements_on_a_pooled_connection() {
    assert!(capture::install(), "this test needs the process logger");
    let url = "fake://host-exec-lifecycle";
    let target = fake_target(url);
    let (_bv, core, root) = host_exec_vault("dyn_host_exec", HostExecDb::new(url)).await;

    let resp = root_call(&core, &root, Operation::Read, "database/creds/readonly").await.unwrap().unwrap();
    let username = data_str(&resp, "username");
    let password = data_str(&resp, "password");
    let lease_id = resp.secret.unwrap().lease_id;
    {
        let committed = target.committed.lock().unwrap();
        assert_eq!(committed.len(), 1);
        let create = &committed[0][0];
        assert!(
            create.starts_with(&format!("CREATE ROLE \"{username}\" WITH LOGIN PASSWORD '{password}'")),
            "{create}"
        );
        assert!(target.identities.lock().unwrap().contains(&username));
    }

    root_call(&core, &root, Operation::Write, &format!("sys/renew/{lease_id}")).await.unwrap();
    root_call(&core, &root, Operation::Write, &format!("sys/revoke/{lease_id}")).await.unwrap();
    let committed = target.committed.lock().unwrap().clone();
    assert_eq!(committed.len(), 3, "{committed:?}");
    assert!(committed[1][0].starts_with(&format!("ALTER ROLE \"{username}\" VALID UNTIL '")), "{committed:?}");
    assert_eq!(committed[2], [format!("DROP ROLE \"{username}\"")]);
    assert!(target.identities.lock().unwrap().is_empty());

    let dials = target.dials.lock().unwrap().clone();
    assert_eq!(dials.len(), 1, "one host socket for generate, renew and revoke");
    assert_eq!((dials[0].0.as_str(), dials[0].1.as_str()), ("vault-root", ROOT_SECRET));
    assert!(dials[0].2.verifies(), "the operator's default policy verifies TLS");
    let lines = capture::lines();
    assert!(!lines.iter().any(|l| l.contains(ROOT_SECRET) || l.contains(&password)), "a secret reached a log line");
}

/// A plugin cannot widen what the host runs: no statements of its own, no TLS
/// override, no second run, no other connection, no slot it does not hold,
/// nothing for rotate-root. And a revoke of an identity already gone runs
/// nothing. Every refusal is redacted of the root secret.
#[tokio::test]
async fn a_plugin_cannot_widen_what_the_host_executes() {
    let url = "fake://host-exec-refusals";
    let target = fake_target(url);
    let plugin = HostExecDb::new(url);
    let (_bv, core, root) = host_exec_vault("dyn_host_exec_refusals", plugin.clone()).await;

    for mode in ["smuggle_statements", "smuggle_tls", "other_connection", "unheld_slot", "other_url"] {
        *plugin.mode.lock().unwrap() = mode;
        let refused = root_call(&core, &root, Operation::Read, "database/creds/readonly").await;
        assert_eq!(status_of(&refused), Some(502), "{mode}: {refused:?}");
        assert!(!format!("{refused:?}").contains(ROOT_SECRET), "{mode}: {refused:?}");
        let answer = plugin.answers.lock().unwrap().last().cloned().unwrap();
        assert!(matches!(&answer, Err(e) if e.starts_with("invalid:")), "{mode}: {answer:?}");
    }
    assert!(target.committed.lock().unwrap().iter().all(|t| !t[0].starts_with("CREATE")), "nothing was created");

    *plugin.mode.lock().unwrap() = "execute_twice";
    let refused = root_call(&core, &root, Operation::Read, "database/creds/readonly").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let answer = plugin.answers.lock().unwrap().last().cloned().unwrap();
    assert!(matches!(&answer, Err(e) if e.contains("already ran")), "{answer:?}");
    // The first run created the identity; the failed generate took it back
    // through the host too (the compensation revoke has its own plan).
    assert!(target.identities.lock().unwrap().is_empty(), "no orphaned identity");

    // A proxied call (here a role write) has no plan: refused.
    *plugin.mode.lock().unwrap() = "execute_on_proxy";
    let mut req = Request::new("database/roles/other");
    req.operation = Operation::Write;
    req.client_token = root.clone();
    req.body = json!({ "connection": "prod" }).as_object().cloned();
    assert!(core.handle_request(&mut req).await.is_err());
    let answer = plugin.answers.lock().unwrap().last().cloned().unwrap();
    assert!(matches!(&answer, Err(e) if e.starts_with("invalid:")), "{answer:?}");
    *plugin.mode.lock().unwrap() = "normal";

    // Revoking an identity the target no longer has runs nothing and succeeds.
    let resp = root_call(&core, &root, Operation::Read, "database/creds/readonly").await.unwrap().unwrap();
    target.identities.lock().unwrap().clear();
    let before = target.committed.lock().unwrap().len();
    let lease_id = resp.secret.unwrap().lease_id;
    root_call(&core, &root, Operation::Write, &format!("sys/revoke/{lease_id}")).await.unwrap();
    assert_eq!(target.committed.lock().unwrap().len(), before);
    let answer = plugin.answers.lock().unwrap().last().cloned().unwrap();
    assert_eq!(answer.unwrap()["identity_absent"], true);
}

/// A failing statement's error, which quotes the statement and so the
/// generated password, reaches neither the caller nor the log unredacted.
#[tokio::test]
async fn a_host_execution_error_is_redacted() {
    assert!(capture::install(), "this test needs the process logger");
    let url = "fake://host-exec-redaction";
    let target = fake_target(url);
    *target.fail_on.lock().unwrap() = Some("PASSWORD".into());
    let plugin = HostExecDb::new(url);
    let (_bv, core, root) = host_exec_vault("dyn_host_exec_redaction", plugin.clone()).await;
    let refused = root_call(&core, &root, Operation::Read, "database/creds/readonly").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let answer = plugin.answers.lock().unwrap().first().cloned().unwrap().unwrap_err();
    assert!(answer.contains("syntax error"), "{answer}");
    assert!(answer.contains("PASSWORD '<redacted>'"), "the generated password is redacted: {answer}");
    let text = format!("{refused:?}");
    assert!(!text.contains(ROOT_SECRET), "{text}");
    let lines = capture::lines();
    assert!(!lines.iter().any(|l| l.contains(ROOT_SECRET)), "the root secret reached a log line");
}

// ── Cluster-wide cache invalidation ─────────────────────────────────────

fn issued<'a>(data: &'a serde_json::Map<String, Value>, username: &'a str) -> super::cache::Issued<'a> {
    super::cache::Issued {
        data,
        lease_ttl: std::time::Duration::from_secs(3600),
        renewable: true,
        plugin: "pg",
        plugin_build: "pg@1#aa",
        role: "ro",
        connection: "prod",
        username,
    }
}

fn fill(slot: &super::cache::LeaseSlot, lease_id: &str) {
    let mut guard = slot.write().unwrap();
    *guard.downcast_mut::<Option<String>>().unwrap() = Some(lease_id.to_string());
}

/// Two nodes, one replicated mount storage: node B cached a credential; node
/// A revokes its lease, rewrites a role or rotates the root; B never serves
/// it again. Unreadable storage on B is a miss, never a stale hit.
#[tokio::test]
async fn two_nodes_a_revoke_or_epoch_on_one_refuses_the_others_cached_hit() {
    use super::cache::{bump_epoch, forget_credential, read_epoch, NodeCache};
    use bv_dynamic::cache::CacheKey;
    let storage = MemStorage::default();
    let node_b = NodeCache::new(16);
    let key = CacheKey::new("m1", "ro", "entity-alice").unwrap();
    let window = std::time::Duration::from_secs(60);
    let mut data = serde_json::Map::new();
    data.insert("password".into(), json!("cached-password-1234"));

    let cache_on_b = |username: &'static str| {
        let (storage, node_b, key, data) = (&storage, &node_b, key.clone(), data.clone());
        async move {
            let epoch = read_epoch(storage).await;
            let slot = node_b.remember(storage, key, issued(&data, username), window, &epoch).await.expect("cached");
            fill(&slot, &format!("lease-of-{username}"));
        }
    };

    cache_on_b("v-alice-1").await;
    let (hit, lease) = node_b.lookup(&storage, &key, "pg@1#aa").await.expect("a hit on B");
    assert_eq!((hit.username.as_str(), lease.as_str()), ("v-alice-1", "lease-of-v-alice-1"));
    assert!(!storage.keys().iter().any(|k| k.contains("cached-password")), "no credential in the records");

    // Node A revokes (or renews) the lease: its marker goes.
    forget_credential(&storage, "v-alice-1").await.unwrap();
    assert!(node_b.lookup(&storage, &key, "pg@1#aa").await.is_none(), "revoked on A: refused on B");
    assert_eq!(node_b.len(), 0, "and dropped there");

    // Node A rewrites a role or rotates the root: a new epoch.
    cache_on_b("v-alice-2").await;
    assert!(node_b.lookup(&storage, &key, "pg@1#aa").await.is_some());
    bump_epoch(&storage, "m1").await.unwrap();
    assert!(node_b.lookup(&storage, &key, "pg@1#aa").await.is_none(), "new epoch on A: refused on B");

    // A new build of the plugin activated on A.
    cache_on_b("v-alice-3").await;
    assert!(node_b.lookup(&storage, &key, "pg@2#bb").await.is_none(), "another build: refused");

    // Storage down on B: a miss (fail closed), and nothing new is cached.
    cache_on_b("v-alice-4").await;
    storage.down.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(node_b.lookup(&storage, &key, "pg@1#aa").await.is_none(), "unreadable records: a miss");
    let epoch = read_epoch(&storage).await;
    assert!(node_b.remember(&storage, key.clone(), issued(&data, "v-alice-5"), window, &epoch).await.is_none());
    assert!(forget_credential(&storage, "v-alice-5").await.is_err(), "a marker that cannot go is an error");
    assert!(bump_epoch(&storage, "m1").await.is_err());
}

/// The mount storage prefix (`logical/<uuid>/`) of the dynamic mount, found
/// by its `bv-dynamic/mount-id` record, so a test can act as another node.
async fn dynamic_mount_prefix(core: &Arc<dyn VaultCtx>) -> String {
    // `logical/<uuid>/`, or under `namespaces/<root>/` once re-rooted.
    let barrier = core.barrier();
    let mut stack = vec![String::new()];
    while let Some(dir) = stack.pop() {
        for child in barrier.as_storage().list(&dir).await.unwrap() {
            let path = format!("{dir}{child}");
            if path.ends_with("bv-dynamic/mount-id") {
                return path.trim_end_matches("bv-dynamic/mount-id").to_string();
            }
            if child.ends_with('/') {
                stack.push(path);
            }
        }
    }
    panic!("no dynamic mount in the barrier")
}

/// Through the real backend: another node's revoke (its marker removed) and
/// another node's role write (a new epoch) both refuse this node's hit.
#[tokio::test]
async fn another_nodes_revoke_or_role_write_refuses_a_cached_hit_here() {
    let fx = Fixture::new("dyn_cache_cluster", all_caps()).await;
    fx.cached_role("cached", 60);
    let alice = fx.logins(&["alice"]).await.remove(0).0;
    let first = fx.creds_as(&alice, "cached").await;
    let username = data_str(&first, "username");
    assert_eq!(data_str(&fx.creds_as(&alice, "cached").await, "username"), username, "a hit");

    let prefix = dynamic_mount_prefix(&fx.core).await;
    let barrier = fx.core.barrier();
    let storage = barrier.as_storage();
    let marker = format!("{prefix}{}", bv_dynamic::cache::marker_key(&username).unwrap());
    assert!(storage.get(&marker).await.unwrap().is_some(), "the miss wrote a marker");
    storage.delete(&marker).await.unwrap();
    let second = fx.creds_as(&alice, "cached").await;
    assert_ne!(data_str(&second, "username"), username, "revoked elsewhere: not served here");

    let username = data_str(&second, "username");
    assert_eq!(data_str(&fx.creds_as(&alice, "cached").await, "username"), username);
    let epoch = bv_dynamic::cache::EpochRecord::fresh().unwrap();
    let entry = crate::storage::StorageEntry {
        key: format!("{prefix}{}", bv_dynamic::cache::EPOCH_KEY),
        value: serde_json::to_vec(&epoch).unwrap(),
    };
    storage.put(&entry).await.unwrap();
    let third = fx.creds_as(&alice, "cached").await;
    assert_ne!(data_str(&third, "username"), username, "role rewritten elsewhere: not served here");

    // A revoke here removes the marker for every node, and the row says so.
    let marker = format!("{prefix}{}", bv_dynamic::cache::marker_key(&data_str(&third, "username")).unwrap());
    let lease = third.secret.unwrap().lease_id;
    assert!(storage.get(&marker).await.unwrap().is_some());
    fx.write(&format!("sys/revoke/{lease}"), Value::Null).await.unwrap();
    assert!(storage.get(&marker).await.unwrap().is_none(), "the revoke removed the marker");
}

/// Egress: host execution is offered only for a connection whose endpoint
/// the host pinned from the operator's write; an unpinned one (a record from
/// before pinning, or a write that cleared a half) gets no `host_execute`, so
/// the plugin dials as before and the host dials nothing for it.
#[tokio::test]
async fn host_execution_is_offered_only_for_a_pinned_endpoint() {
    let url = "fake://host-exec-pinning";
    let target = fake_target(url);
    let plugin = HostExecDb::new(url);
    let (_bv, core, root) = host_exec_vault("dyn_host_exec_pinning", plugin.clone()).await;
    let mut req = Request::new("database/config/prod");
    req.operation = Operation::Write;
    req.client_token = root.clone();
    req.body = json!({ "username": null }).as_object().cloned();
    core.handle_request(&mut req).await.unwrap();
    let refused = root_call(&core, &root, Operation::Read, "database/creds/readonly").await;
    assert!(format!("{refused:?}").contains("does not grant host execution"), "{refused:?}");
    assert!(plugin.answers.lock().unwrap().is_empty(), "no execute was even attempted");
    assert!(target.dials.lock().unwrap().is_empty());
}

/// A config write or delete (any node) drops cached credentials: a new
/// mount epoch, and this node's entries go at once.
#[tokio::test]
async fn a_config_write_drops_cached_credentials_everywhere() {
    let fx = Fixture::new("dyn_cache_config", all_caps()).await;
    fx.cached_role("cached", 60);
    let alice = fx.logins(&["alice"]).await.remove(0).0;
    let first = data_str(&fx.creds_as(&alice, "cached").await, "username");
    assert_eq!(data_str(&fx.creds_as(&alice, "cached").await, "username"), first, "a hit");
    let prefix = dynamic_mount_prefix(&fx.core).await;
    let barrier = fx.core.barrier();
    let epoch_key = format!("{prefix}{}", bv_dynamic::cache::EPOCH_KEY);
    let before = barrier.as_storage().get(&epoch_key).await.unwrap().map(|e| e.value);

    fx.write("database/config/prod", json!({ "connection_url": "postgres://db.example/other" })).await.unwrap();
    let after = barrier.as_storage().get(&epoch_key).await.unwrap().map(|e| e.value);
    assert!(after.is_some() && after != before, "a new epoch for every node");
    assert_ne!(data_str(&fx.creds_as(&alice, "cached").await, "username"), first, "not served after the write");
}

// ── Rotate-root through the host connector ──────────────────────────────

/// A vault whose fake target's root secret is ROOT_SECRET, as the plugin stored it.
async fn rooted_vault(
    name: &str,
) -> (crate::BastionVault, Arc<dyn VaultCtx>, String, Arc<HostExecDb>, Arc<super::test_support::FakeTarget>) {
    let url = format!("fake://{name}");
    let target = fake_target(&url);
    *target.root.lock().unwrap() = Some(ROOT_SECRET.to_string());
    let plugin = HostExecDb::new(&url);
    let (bv, core, root) = host_exec_vault(name, plugin.clone()).await;
    (bv, core, root, plugin, target)
}

/// The host's own record of `config/prod`, read from the mount's storage.
async fn root_version(core: &Arc<dyn VaultCtx>, _root: &str) -> Value {
    let prefix = dynamic_mount_prefix(core).await;
    let barrier = core.barrier();
    let entry = barrier.as_storage().get(&format!("{prefix}bv-dynamic/connections/prod")).await.unwrap().unwrap();
    let record = bv_dynamic::records::ConnectionRecord::decode(&entry.value).unwrap();
    Value::from(record.root_credential_version)
}

/// The host sets the new secret over the old-secret connection, proves it by
/// a fresh login, the plugin stores it, and the next call dials with it.
#[tokio::test]
async fn the_host_rotates_the_root_and_the_plugin_stores_it() {
    assert!(capture::install(), "this test needs the process logger");
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate").await;
    let rotated = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await.unwrap().unwrap();
    assert_eq!(rotated.data.unwrap()["root_credential_version"], 2);
    let new = plugin.rotated_to.lock().unwrap().clone();
    assert_eq!(target.root.lock().unwrap().as_deref(), Some(new.as_str()), "the target has the host's new secret");
    assert_eq!(*plugin.stored_root.lock().unwrap(), new, "and the plugin stored it");
    assert_eq!(target.dials.lock().unwrap().last().unwrap().1, new, "verified by a login with it");
    assert_eq!(plugin.answers.lock().unwrap().last().unwrap().as_ref().unwrap()["rotated"], true);
    // A credential afterwards: dialled with the new root.
    root_call(&core, &root, Operation::Read, "database/creds/readonly").await.unwrap().unwrap();
    assert!(capture::lines().iter().all(|l| !l.contains(&new) && !l.contains(ROOT_SECRET)));
}

/// The new secret does not log in: the host puts the old one back over the
/// still-open old connection; nothing changed.
#[tokio::test]
async fn a_rotation_whose_new_secret_cannot_log_in_is_rolled_back() {
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate_verify").await;
    *target.only_login.lock().unwrap() = Some(ROOT_SECRET.to_string());
    let refused = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    assert!(format!("{refused:?}").contains("put back"), "{refused:?}");
    assert_eq!(target.root.lock().unwrap().as_deref(), Some(ROOT_SECRET), "the target change was rolled back");
    assert_eq!(*plugin.stored_root.lock().unwrap(), ROOT_SECRET, "and nothing new was stored");
    assert_eq!(root_version(&core, &root).await, 1);
}

/// The plugin cannot store the new secret: the host undoes the target change
/// over a login with the new secret and says so.
#[tokio::test]
async fn a_rotation_the_plugin_cannot_store_is_undone_by_the_host() {
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate_store").await;
    *plugin.mode.lock().unwrap() = "fail_store";
    let refused = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let text = format!("{refused:?}");
    assert!(text.contains("was undone") && text.contains("put the previous secret back"), "{text}");
    assert_eq!(target.root.lock().unwrap().as_deref(), Some(ROOT_SECRET), "target and stored secret agree");
    assert_eq!(*plugin.stored_root.lock().unwrap(), ROOT_SECRET);
    assert_eq!(root_version(&core, &root).await, 1);
    let new = plugin.rotated_to.lock().unwrap().clone();
    assert!(!text.contains(&new) && !text.contains(ROOT_SECRET));
}

/// ... and when undoing it fails too: an explicit error naming the connection
/// and saying the target holds the new secret, logged at ERROR and audited.
#[tokio::test]
async fn a_failed_undo_after_a_failed_store_is_an_explicit_audited_error() {
    assert!(capture::install(), "this test needs the process logger");
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate_stranded").await;
    *plugin.mode.lock().unwrap() = "fail_store";
    // The undo statement names the old secret: make it fail, echoing it.
    *target.fail_on.lock().unwrap() = Some(ROOT_SECRET.to_string());
    let refused = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let text = format!("{refused:?}");
    assert!(text.contains("`prod`") && text.contains("may be on the target and not stored"), "{text}");
    let again = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&again), Some(409), "a stranded rotation blocks the next: {again:?}");
    let new = plugin.rotated_to.lock().unwrap().clone();
    assert_eq!(target.root.lock().unwrap().as_deref(), Some(new.as_str()));
    let lines = capture::lines();
    assert!(
        lines.iter().any(|l| l.starts_with("ERROR") && l.contains("`prod`") && l.contains("not stored")),
        "{lines:#?}"
    );
    let audited =
        |l: &&String| l.contains("dynamic_secret") && l.contains("\"rotate_root\"") && l.contains("not stored");
    assert!(lines.iter().any(|l| audited(&l)), "{lines:#?}");
    assert!(!lines.iter().chain([&text]).any(|l| l.contains(&new) || l.contains(ROOT_SECRET)), "a secret leaked");
}

/// A rotation presenting an endpoint other than the pinned one is refused
/// before anything is dialled.
#[tokio::test]
async fn a_rotation_to_a_foreign_endpoint_is_refused() {
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate_foreign").await;
    *plugin.mode.lock().unwrap() = "other_url";
    let refused = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    let answer = plugin.answers.lock().unwrap().last().cloned().unwrap();
    assert!(matches!(&answer, Err(e) if e.contains("not the one configured")), "{answer:?}");
    assert!(target.dials.lock().unwrap().is_empty());
    assert_eq!(target.root.lock().unwrap().as_deref(), Some(ROOT_SECRET));
}

// ── Rotate-root hardening: cut-short calls, unknown stores, concurrency ──

async fn host_record(core: &Arc<dyn VaultCtx>) -> bv_dynamic::records::ConnectionRecord {
    let prefix = dynamic_mount_prefix(core).await;
    let barrier = core.barrier();
    let entry = barrier.as_storage().get(&format!("{prefix}bv-dynamic/connections/prod")).await.unwrap().unwrap();
    bv_dynamic::records::ConnectionRecord::decode(&entry.value).unwrap()
}

async fn put_host_record(core: &Arc<dyn VaultCtx>, record: &bv_dynamic::records::ConnectionRecord) {
    let prefix = dynamic_mount_prefix(core).await;
    let entry = crate::storage::StorageEntry {
        key: format!("{prefix}bv-dynamic/connections/prod"),
        value: serde_json::to_vec(record).unwrap(),
    };
    core.barrier().as_storage().put(&entry).await.unwrap();
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// The runtime drops the plugin call (its timeout) after the host set the new
/// secret: the in-flight record makes it stranded, not a plain timeout.
#[tokio::test]
async fn a_rotation_cut_short_mid_flight_is_stranded() {
    assert!(capture::install(), "this test needs the process logger");
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate_cut").await;
    target.hang_after_rotate.store(true, Ordering::SeqCst);
    *plugin.mode.lock().unwrap() = "abandon_execute";
    let refused = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    assert!(format!("{refused:?}").contains("cut short"), "{refused:?}");
    let new = plugin.rotated_to.lock().unwrap().clone();
    assert_eq!(target.root.lock().unwrap().as_deref(), Some(new.as_str()), "the target did change");
    let lines = capture::lines();
    assert!(lines.iter().any(|l| l.starts_with("ERROR") && l.contains("`prod`")), "{lines:#?}");
    assert!(host_record(&core).await.rotation_pending.unwrap().stranded);
}

/// The plugin stored the new secret and then failed without saying whether:
/// the host does not undo (that would leave the target old and the store new).
#[tokio::test]
async fn a_plugin_that_stored_then_failed_is_stranded_not_undone() {
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate_stored").await;
    *plugin.mode.lock().unwrap() = "store_then_fail";
    let refused = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    assert!(format!("{refused:?}").contains("unknown which root secret the plugin stored"), "{refused:?}");
    let new = plugin.rotated_to.lock().unwrap().clone();
    assert_eq!(target.root.lock().unwrap().as_deref(), Some(new.as_str()), "not undone");
    assert_eq!(*plugin.stored_root.lock().unwrap(), new, "target and store agree");
}

/// A plugin that ignores a failed host execution and reports success: the
/// host had rolled back, so it is unknown what the plugin stored.
#[tokio::test]
async fn a_plugin_ignoring_a_failed_host_execution_is_stranded_and_audited() {
    assert!(capture::install(), "this test needs the process logger");
    let (_bv, core, root, plugin, target) = rooted_vault("dyn_host_rotate_ignored").await;
    *target.only_login.lock().unwrap() = Some(ROOT_SECRET.to_string());
    *plugin.mode.lock().unwrap() = "ignore_execute_error";
    let refused = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&refused), Some(502), "{refused:?}");
    assert!(format!("{refused:?}").contains("reported success although"), "{refused:?}");
    let lines = capture::lines();
    let audited =
        |l: &String| l.contains("dynamic_secret") && l.contains("\"rotate_root\"") && l.contains("not stored");
    assert!(lines.iter().any(|l| audited(l) && l.contains("reported success")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.starts_with("ERROR") && l.contains("`prod`")), "{lines:#?}");
}

/// Two rotate-roots at once: one is refused with a conflict, the other
/// completes, and its version bump is not lost.
#[tokio::test]
async fn concurrent_rotations_conflict_and_no_update_is_lost() {
    let (_bv, core, root, _plugin, target) = rooted_vault("dyn_host_rotate_race").await;
    target.delay_ms.store(300, Ordering::SeqCst);
    let (a, b) = tokio::join!(
        root_call(&core, &root, Operation::Write, "database/rotate-root/prod"),
        root_call(&core, &root, Operation::Write, "database/rotate-root/prod"),
    );
    let statuses = [status_of(&a), status_of(&b)];
    assert!(statuses.contains(&Some(409)) && (a.is_ok() || b.is_ok()), "{a:?} / {b:?}");
    let conflict = if a.is_err() { &a } else { &b };
    assert!(format!("{conflict:?}").contains("in progress"), "{conflict:?}");
    let record = host_record(&core).await;
    assert_eq!(record.root_credential_version, 2);
    assert!(record.rotation_pending.is_none());
}

/// A config write during a rotation is kept: the rotation's write-back merges
/// only its own change into the record it re-reads.
#[tokio::test]
async fn a_config_write_during_a_rotation_is_not_reverted() {
    let (_bv, core, root, _plugin, target) = rooted_vault("dyn_host_rotate_config").await;
    target.delay_ms.store(400, Ordering::SeqCst);
    let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
    let write = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut req = Request::new("database/config/prod");
        req.operation = Operation::Write;
        req.client_token = root.clone();
        req.body = json!({ "tls_ca_pem": pem }).as_object().cloned();
        core.handle_request(&mut req).await
    };
    let (rotated, written) =
        tokio::join!(root_call(&core, &root, Operation::Write, "database/rotate-root/prod"), write);
    rotated.unwrap();
    written.unwrap();
    let record = host_record(&core).await;
    assert_eq!(record.tls_ca_pem.as_deref(), Some(pem), "the config write survived");
    assert_eq!(record.root_credential_version, 2, "and so did the rotation");
}

/// A marker left by a node that died mid-rotation: rotate-root refuses with
/// a clear message, a config read shows it, deleting the connection is
/// refused, and only an operator's DELETE rotate-root clears it.
#[tokio::test]
async fn a_leftover_marker_is_surfaced_and_only_an_operator_clears_it() {
    let (_bv, core, root, _plugin, _target) = rooted_vault("dyn_host_rotate_marker").await;
    let mut record = host_record(&core).await;
    let fresh = bv_dynamic::records::RotationPending {
        started_at: unix_secs(),
        node: "raft node 7".into(),
        nonce: "n".into(),
        stranded: false,
        reason: None,
    };
    record.rotation_pending = Some(fresh.clone());
    put_host_record(&core, &record).await;
    let busy = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    assert_eq!(status_of(&busy), Some(409));
    assert!(format!("{busy:?}").contains("in progress") && format!("{busy:?}").contains("raft node 7"), "{busy:?}");

    record.rotation_pending = Some(bv_dynamic::records::RotationPending { started_at: 1, ..fresh });
    put_host_record(&core, &record).await;
    let stale = root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await;
    let text = format!("{stale:?}");
    assert!(
        text.contains("`prod`") && text.contains("never finished") && text.contains("DELETE rotate-root/prod"),
        "{text}"
    );
    let read = root_call(&core, &root, Operation::Read, "database/config/prod").await.unwrap().unwrap();
    assert_eq!(read.data.as_ref().unwrap()["rotation_pending"]["possibly_stranded"], true);
    assert!(read.warnings.iter().any(|w| w.contains("`prod`")), "{:?}", read.warnings);
    assert_eq!(status_of(&root_call(&core, &root, Operation::Delete, "database/config/prod").await), Some(409));

    let cleared = root_call(&core, &root, Operation::Delete, "database/rotate-root/prod").await.unwrap().unwrap();
    assert_eq!(cleared.data.unwrap()["cleared"]["node"], "raft node 7");
    assert!(host_record(&core).await.rotation_pending.is_none());
    assert_eq!(status_of(&root_call(&core, &root, Operation::Delete, "database/rotate-root/prod").await), Some(400));
    root_call(&core, &root, Operation::Write, "database/rotate-root/prod").await.unwrap();
}
