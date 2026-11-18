//! The namespace policy path rule (T519, T520), with real tokens through
//! `Core::handle_request`: a policy in namespace `a` names only `a/` paths
//! (and the exact transfer routes), whether written through `sys/policy` or
//! brought in by a `.bvx` import.

use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request, Response},
    modules::policy::{PolicyModule, PolicyType},
    test_utils::new_unseal_test_bastion_vault,
};

/// Seeded secret values.
const IN_A: &str = "value-in-a-7c1d";
const IN_AB: &str = "value-in-ab-91fe";
const IN_ROOT: &str = "value-in-root-0b3a";

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
