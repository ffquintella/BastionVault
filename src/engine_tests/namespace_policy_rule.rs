//! The namespace policy path rule (T519, T520), with real tokens through
//! `Core::handle_request`: a policy in namespace `a` names only `a/` paths
//! (and the exact transfer routes): at write time, on `.bvx` import, and, for
//! a document that got into `a`'s keyspace some other way, when the ACL is built.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request, Response},
    modules::{
        namespace::{ns_assignment::NsAssignmentStore, NamespaceModule, NAMESPACE_MODULE_NAME},
        policy::{Policy, PolicyModule, PolicyType},
    },
    test_utils::new_unseal_test_bastion_vault,
};

const PASSWORD: &str = "hunter22XX!";
/// Seeded secret values: the log must never carry them.
const IN_A: &str = "value-in-a-7c1d";
const IN_AB: &str = "value-in-ab-91fe";
const IN_ROOT: &str = "value-in-root-0b3a";

/// T519: a glob ending inside the namespace's own name, beside a confined rule.
const PARTIAL_GLOB: &str = r#"
path "a*" { capabilities = ["read", "list"] }
path "a/secret/*" { capabilities = ["read", "list"] }
"#;

/// T520: bare `sys/` and `auth/` rules, beside a confined rule.
const BARE: &str = r#"
path "sys/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "a/resources/*" { capabilities = ["read", "list"] }
"#;

/// A process-wide `log` sink (nextest runs each test in its own process).
mod capture {
    use std::sync::{Mutex, OnceLock};

    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    struct Capture;
    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, r: &log::Record<'_>) {
            LINES.get_or_init(Default::default).lock().unwrap().push(format!("{} {}", r.target(), r.args()));
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

async fn send(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    ns: Option<&str>,
    body: Value,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body.as_object().cloned();
    if let Some(ns) = ns {
        req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
    }
    core.handle_request(&mut req).await
}

fn denied(r: &Result<Option<Response>, RvError>) -> bool {
    matches!(r, Err(RvError::ErrPermissionDenied))
}

/// [`denied`], or the refusal a sudo-gated `sys/` path gives without `sudo` there.
fn refused(r: &Result<Option<Response>, RvError>) -> bool {
    denied(r) || message(r).contains("cannot access root path")
}

fn message(r: &Result<Option<Response>, RvError>) -> String {
    match r {
        Ok(_) => String::new(),
        Err(RvError::ErrResponseStatus(_, m)) => m.clone(),
        Err(e) => e.to_string(),
    }
}

/// Namespaces `a` and its name-prefix sibling `ab`, each with a KV v2 secret;
/// a root KV mount `apps/` whose name also starts with `a`; userpass at root.
async fn vault(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    for ns in ["a", "ab"] {
        send(&core, &root, Operation::Write, &format!("sys/namespaces/{ns}"), None, json!({})).await.unwrap();
    }
    let secret = |v: &str| json!({ "data": { "v": v } });
    send(&core, &root, Operation::Write, "secret/data/team/db", Some("a"), secret(IN_A)).await.unwrap();
    send(&core, &root, Operation::Write, "secret/data/team/db", Some("ab"), secret(IN_AB)).await.unwrap();
    send(&core, &root, Operation::Write, "sys/mounts/apps/", None, json!({ "type": "kv" })).await.unwrap();
    send(&core, &root, Operation::Write, "apps/team", None, json!({ "v": IN_ROOT })).await.unwrap();
    send(&core, &root, Operation::Write, "sys/auth/userpass", None, json!({ "type": "userpass" })).await.unwrap();
    (bvault, core, root)
}

fn policy_store(core: &Arc<Core>) -> Arc<crate::modules::policy::policy_store::PolicyStore> {
    let module = core.module_manager().get_module::<PolicyModule>("policy").expect("policy module");
    module.policy_store.load_full()
}

/// `hcl` as policy `name` in namespace `ns`'s keyspace, past the write-time
/// guard: what a `.bvx` import, a backup restore or an older build left there.
async fn plant(core: &Arc<Core>, ns: &str, name: &str, hcl: &str) {
    let mut policy = Policy::from_str(hcl).unwrap();
    policy.name = name.to_string();
    policy_store(core).set_policy_ns(policy, ns).await.unwrap();
}

/// A userpass sign-in bound to `a` carrying `policies` (resolved in `a`), whom
/// an operator's assignment also lets work in `ab` and in root.
async fn tenant_token(core: &Arc<Core>, root: &str, policies: &str) -> String {
    let body = json!({ "password": PASSWORD, "token_policies": policies, "ttl": 0 });
    send(core, root, Operation::Write, "auth/userpass/users/tenant", None, body).await.unwrap();
    let ns_store =
        core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME).and_then(|m| m.store()).unwrap();
    let assigned = vec!["a".to_string(), "ab".to_string(), String::new()];
    NsAssignmentStore::new(core.as_ref()).unwrap().set(&ns_store, "userpass/", "tenant", assigned).await.unwrap();
    let login =
        send(core, "", Operation::Write, "auth/userpass/login/tenant", Some("a"), json!({ "password": PASSWORD }))
            .await
            .unwrap()
            .unwrap();
    let auth = login.auth.unwrap();
    let bound = auth.metadata.get(crate::modules::namespace::token_binding::NS_PATH_META).map(String::as_str);
    assert_eq!(bound, Some("a"), "bound to `a`: {:?}", auth.metadata);
    auth.client_token
}

/// Resource `srv1` in `a`'s `resources/` mount.
async fn seed_resource(core: &Arc<Core>, root: &str) {
    let meta = json!({ "type": "server", "hostname": "srv1.example" });
    send(core, root, Operation::Write, "resources/resources/srv1", Some("a"), meta).await.unwrap();
}

fn secret_value(r: Result<Option<Response>, RvError>) -> String {
    let data = r.unwrap().unwrap().data.unwrap();
    data.get("data").and_then(|d| d.get("v")).or_else(|| data.get("v")).and_then(Value::as_str).unwrap().to_string()
}

/// T519 at write time: `a*` in `a` is refused with a 403 that says why and
/// what to write instead; `a/*` and the two transfer routes are accepted; a
/// root policy keeps every shape, `secret/*` and `a*` included.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_partial_namespace_glob_is_refused_at_write_time() {
    let (_bvault, core, root) = vault("ns_policy_rule_write").await;
    let write = |ns: Option<&'static str>, name: &'static str, path: &'static str| {
        let core = core.clone();
        let root = root.clone();
        async move {
            let hcl = format!("path \"{path}\" {{ capabilities = [\"update\"] }}");
            send(&core, &root, Operation::Write, &format!("sys/policy/{name}"), ns, json!({ "policy": hcl })).await
        }
    };

    let refused = write(Some("a"), "glob", "a*").await;
    match &refused {
        Err(RvError::ErrResponseStatus(403, m)) => {
            assert!(m.contains("\"a*\"") && m.contains("\"a/*\"") && m.contains("outside the namespace"), "{m}");
        }
        other => panic!("`a*` in `a` must be refused with a 403, got {other:?}"),
    }
    for path in ["ab*", "A*", "*", "+/x", "a+", "secret/*", "sys/*", "auth/*", "apps/*"] {
        let r = write(Some("a"), "other", path).await;
        assert!(matches!(r, Err(RvError::ErrResponseStatus(403, _))), "{path}: {r:?}");
    }
    for path in ["a/*", "a/", "a//x", "a/secret/*", "sys/namespace-transfer/copy", "sys/namespace-transfer/move"] {
        let r = write(Some("a"), "ok", path).await;
        assert!(r.is_ok(), "{path}: {}", message(&r));
    }
    for path in ["secret/*", "a*", "sys/*"] {
        let r = write(None, "root-policy", path).await;
        assert!(r.is_ok(), "root, {path}: {}", message(&r));
    }
    let store = policy_store(&core);
    assert!(store.get_policy_ns("glob", PolicyType::Acl, "a").await.unwrap().is_none(), "nothing was written");
}

/// T519 for a stored policy: `a*` planted in `a` grants a token bound to `a`
/// nothing in `ab` or at root, even where an operator's assignment lets it
/// work; the confined rule beside it still works; the WARN names the policy,
/// the namespace and the pattern, and no secret value.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_stored_partial_namespace_glob_grants_nothing_outside_the_namespace() {
    let logging = capture::install();
    let (_bvault, core, root) = vault("ns_policy_rule_stored_glob").await;
    plant(&core, "a", "planted-glob", PARTIAL_GLOB).await;
    let token = tenant_token(&core, &root, "planted-glob").await;

    let own = send(&core, &token, Operation::Read, "secret/data/team/db", Some("a"), json!({})).await;
    assert_eq!(secret_value(own), IN_A, "the confined rule still grants");

    let sibling = send(&core, &token, Operation::Read, "secret/data/team/db", Some("ab"), json!({})).await;
    assert!(denied(&sibling), "the sibling `ab` through `a*`: {sibling:?}");
    let root_mount = send(&core, &token, Operation::Read, "apps/team", None, json!({})).await;
    assert!(denied(&root_mount), "the root mount `apps/` through `a*`: {root_mount:?}");

    if logging {
        let lines = capture::lines();
        let warn = lines
            .iter()
            .find(|l| l.starts_with("security ") && l.contains("policy \"planted-glob\" in namespace \"a\""))
            .unwrap_or_else(|| panic!("no WARN for planted-glob: {lines:#?}"));
        assert!(warn.contains("1 rule(s)") && warn.contains("[a*]") && warn.contains("\"a/\""), "{warn}");
        for value in [IN_A, IN_AB, IN_ROOT, PASSWORD] {
            assert!(lines.iter().all(|l| !l.contains(value)), "a secret value reached the log");
        }
    }
}

/// T520: bare `sys/` and `auth/` rules in a stored policy of `a` grant a
/// token bound to `a` nothing (it could otherwise write `a`'s policies and
/// list its mounts); the confined rule and the injected self-service policy
/// still work.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn stored_bare_sys_and_auth_rules_grant_a_namespace_token_nothing() {
    let logging = capture::install();
    let (_bvault, core, root) = vault("ns_policy_rule_stored_bare").await;
    plant(&core, "a", "planted-sys", BARE).await;
    seed_resource(&core, &root).await;
    let token = tenant_token(&core, &root, "planted-sys").await;
    let a = Some("a");

    let evil = json!({ "policy": "path \"a/*\" { capabilities = [\"sudo\", \"read\"] }" });
    let r = send(&core, &token, Operation::Write, "sys/policy/evil", a, evil).await;
    assert!(refused(&r), "sys/policy write: {r:?}");
    let r = send(&core, &token, Operation::Read, "sys/mounts", a, json!({})).await;
    assert!(refused(&r), "sys/mounts read: {r:?}");
    let r = send(&core, &token, Operation::List, "sys/policy", a, json!({})).await;
    assert!(refused(&r), "sys/policy list: {r:?}");
    let r = send(&core, &token, Operation::Write, "auth/token/create", a, json!({ "ttl": "1h" })).await;
    assert!(denied(&r), "auth/token/create: {r:?}");
    assert!(policy_store(&core).get_policy_ns("evil", PolicyType::Acl, "a").await.unwrap().is_none());

    let r = send(&core, &token, Operation::Read, "resources/resources/srv1", a, json!({})).await;
    assert!(r.is_ok(), "the confined rule still grants: {}", message(&r));
    let r = send(&core, &token, Operation::Write, "sys/capabilities-self", a, json!({ "paths": ["sys/mounts"] })).await;
    let caps = r.unwrap().unwrap().data.unwrap();
    assert_eq!(caps["capabilities"]["sys/mounts"], json!(["deny"]), "`namespace-self` still answers: {caps:?}");

    if logging {
        let lines = capture::lines();
        let warn = lines
            .iter()
            .find(|l| l.starts_with("security ") && l.contains("policy \"planted-sys\" in namespace \"a\""))
            .unwrap_or_else(|| panic!("no WARN for planted-sys: {lines:#?}"));
        assert!(warn.contains("2 rule(s)") && warn.contains("sys/*") && warn.contains("auth/*"), "{warn}");
        assert!(!warn.contains("a/resources"), "only the dropped rules are named: {warn}");
    }
}

/// T520, `.bvx` import: an import wrote a namespace's policy documents as
/// raw barrier keys, past the rule `sys/policy` applies there. One that rule
/// refuses (a bare `sys/` or `auth/` rule, `a*`, text that does not parse) is
/// skipped with a warning naming it, in the preview too; a clean one imports
/// as before; root's policies are unrestricted.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn an_import_skips_a_namespace_policy_the_path_rule_refuses() {
    use crate::exchange::{
        export_all_namespaces, import_all_namespaces, ConflictPolicy, ExporterInfo, ScopeKind, ScopeSpec,
    };

    let (_bvault, core, root) = vault("ns_policy_rule_import").await;
    let clean = "path \"a/secret/*\" { capabilities = [\"read\"] }";
    send(&core, &root, Operation::Write, "sys/policy/reader", Some("a"), json!({ "policy": clean })).await.unwrap();
    let scope = ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] };
    let mut doc = export_all_namespaces(&core, ExporterInfo::default(), scope).await.unwrap();
    send(&core, &root, Operation::Delete, "sys/policy/reader", Some("a"), json!({})).await.unwrap();

    // Planted beside it: what `sys/policy` refuses in `a`.
    let bundle = doc.items.namespaces.iter_mut().find(|b| b.path == "a").expect("bundle for `a`");
    let template = bundle.items.policies.iter().find(|p| p.name == "reader").expect("exported").clone();
    let planted = [
        ("bare-sys", "path \"sys/*\" { capabilities = [\"read\", \"update\", \"sudo\"] }"),
        ("bare-auth", "path \"auth/*\" { capabilities = [\"update\"] }"),
        ("partial-glob", "path \"a*\" { capabilities = [\"read\"] }"),
        ("broken", "path \"a/x\" { capabilities = "),
    ];
    for (name, hcl) in planted {
        let mut item = template.clone();
        item.name = name.to_string();
        item.value["raw"] = json!(hcl);
        bundle.items.policies.push(item);
    }
    let mut root_item = template.clone();
    root_item.name = "root-wide".into();
    root_item.value["raw"] = json!("path \"sys/*\" { capabilities = [\"read\"] }");
    doc.items.policies.push(root_item);

    let skipped = |warnings: &[String], name: &str| {
        warnings.iter().any(|w| w.starts_with(&format!("policy {name:?} in namespace \"a\" skipped: ")))
    };
    for dry_run in [true, false] {
        let result = import_all_namespaces(&core, &doc, ConflictPolicy::Overwrite, dry_run).await.unwrap();
        for (name, _) in planted {
            assert!(skipped(&result.warnings, name), "dry_run {dry_run}: {name}: {:?}", result.warnings);
            assert!(!result.items.iter().any(|i| i.path == format!("policy/{name}")), "{name} is not an item");
        }
        let glob = result.warnings.iter().find(|w| w.contains("partial-glob")).unwrap();
        assert!(glob.contains("\"a*\"") && glob.contains("\"a/*\""), "{glob}");
        let sys = result.warnings.iter().find(|w| w.contains("bare-sys")).unwrap();
        assert!(sys.contains("\"sys/\"") && sys.contains("belongs to namespace root"), "{sys}");
        assert!(!skipped(&result.warnings, "reader"), "{:?}", result.warnings);
    }

    let store = policy_store(&core);
    for (name, _) in planted {
        assert!(store.get_policy_ns(name, PolicyType::Acl, "a").await.unwrap().is_none(), "{name} was written");
    }
    let reader = store.get_policy_ns("reader", PolicyType::Acl, "a").await.unwrap();
    assert_eq!(reader.map(|p| p.raw.clone()).as_deref(), Some(clean), "a clean policy imports as before");
    assert!(store.get_policy("root-wide", PolicyType::Acl).await.unwrap().is_some(), "root's are unrestricted");
}

/// T520, backup restore: a restore writes a namespace's policies as they are
/// in the backup (refusing one would fail the whole restore); the ACL then
/// keeps only the confined rules, exactly as for any stored document.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_restored_namespace_policy_is_confined_when_the_acl_is_built() {
    let (_bvault, core, root) = vault("ns_policy_rule_restore").await;
    plant(&core, "a", "planted-sys", BARE).await;
    seed_resource(&core, &root).await;
    let token = tenant_token(&core, &root, "planted-sys").await;

    let hmac_key = core.barrier.derive_hmac_key().unwrap();
    let mut backup = Vec::new();
    crate::backup::create::create_backup(core.physical.as_ref(), &hmac_key, &mut backup, false).await.unwrap();
    policy_store(&core).delete_policy_ns("planted-sys", PolicyType::Acl, "a").await.unwrap();

    let mut reader = std::io::Cursor::new(backup);
    crate::backup::restore::restore_backup_live(&core, &mut reader).await.unwrap();
    core.flush_caches();

    let restored = policy_store(&core).get_policy_ns("planted-sys", PolicyType::Acl, "a").await.unwrap();
    assert!(restored.expect("the restore wrote it back").raw.contains("sys/*"), "written as it was");
    let r = send(&core, &token, Operation::Read, "sys/mounts", Some("a"), json!({})).await;
    assert!(refused(&r), "sys/mounts read after the restore: {r:?}");
    let r = send(&core, &token, Operation::Read, "resources/resources/srv1", Some("a"), json!({})).await;
    assert!(r.is_ok(), "the confined rule still grants after the restore: {}", message(&r));
}

/// T520 regression: the WARN for a stored policy's dropped rules comes once
/// for a load, not once per request; a change to the policy is seen by the
/// very next request (the policy cache never holds a filtered copy) and, when
/// it drops a different rule, is warned about at once; a clean rewrite
/// through `sys/policy` grants as written and warns about nothing.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_drop_warning_comes_once_per_load_and_a_change_is_seen_at_once() {
    let logging = capture::install();
    let (_bvault, core, root) = vault("ns_policy_rule_warn_once").await;
    seed_resource(&core, &root).await;
    plant(&core, "a", "planted-glob", PARTIAL_GLOB).await;
    let token = tenant_token(&core, &root, "planted-glob").await;
    let read = |path: &'static str, ns: Option<&'static str>| {
        let core = core.clone();
        let token = token.clone();
        async move { send(&core, &token, Operation::Read, path, ns, json!({})).await }
    };

    for _ in 0..5 {
        assert_eq!(secret_value(read("secret/data/team/db", Some("a")).await), IN_A);
        assert!(denied(&read("secret/data/team/db", Some("ab")).await));
    }
    assert!(denied(&read("resources/resources/srv1", Some("a")).await), "not granted by the first version");

    // Changed in place (another planted version): seen by the next request.
    let second = r#"
path "apps/*" { capabilities = ["read"] }
path "a/resources/*" { capabilities = ["read"] }
"#;
    plant(&core, "a", "planted-glob", second).await;
    assert!(read("resources/resources/srv1", Some("a")).await.is_ok(), "the new confined rule grants at once");
    assert!(denied(&read("secret/data/team/db", Some("a")).await), "the removed rule no longer grants");
    assert!(denied(&read("apps/team", None).await), "the new unconfined rule grants nothing");

    // Rewritten clean through `sys/policy`: grants as written, nothing dropped.
    let clean = json!({ "policy": "path \"a/secret/*\" { capabilities = [\"read\"] }" });
    send(&core, &root, Operation::Write, "sys/policy/planted-glob", Some("a"), clean).await.unwrap();
    assert_eq!(secret_value(read("secret/data/team/db", Some("a")).await), IN_A);
    assert!(denied(&read("resources/resources/srv1", Some("a")).await));

    if logging {
        let warns: Vec<String> = capture::lines()
            .into_iter()
            .filter(|l| l.starts_with("security ") && l.contains("policy \"planted-glob\" in namespace \"a\""))
            .collect();
        let with = |pattern: &str| warns.iter().filter(|l| l.contains(pattern)).count();
        assert_eq!(with("[a*]"), 1, "one WARN for the first load, not one per request: {warns:#?}");
        assert_eq!(with("[apps/*]"), 1, "the changed policy is warned about at once: {warns:#?}");
        assert_eq!(warns.len(), 2, "nothing for the clean rewrite: {warns:#?}");
    }
}
