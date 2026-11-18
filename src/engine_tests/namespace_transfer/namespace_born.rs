//! A token born in a namespace runs `sys/namespace-transfer/{copy|move}`
//! (T513): its namespace's policy names the two routes exactly, the grant
//! counts only while the token works in the namespace it was born in, and
//! every read, write and delete is still the token's own sub-request.

use std::sync::Arc;

use serde_json::{json, Value};

use super::{get, message, result, seed_resource, send, status, user_in, write_policy};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Response},
    test_utils::new_unseal_test_bastion_vault,
};

/// The two routes, named the only way a namespace policy may name them.
const ROUTES: &str = r#"
path "sys/namespace-transfer/copy" { capabilities = ["update"] }
path "sys/namespace-transfer/move" { capabilities = ["update"] }
"#;

/// Full rights on namespace `a`'s two resource and two KV mounts.
const A_DATA: &str = r#"
path "a/resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "a/resources2/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "a/secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "a/secret2/*" { capabilities = ["create", "read", "update", "delete", "list"] }
"#;

const ALL: &str = r#"["create", "read", "update", "delete", "list", "sudo"]"#;

/// Namespaces `a`, its child `a/b` and the sibling `c`; `a` also has a second
/// resource mount `resources2/` and a second KV v2 mount `secret2/`.
async fn tenants(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    for ns in ["a", "a/b", "c"] {
        send(&core, &root, Operation::Write, &format!("sys/namespaces/{ns}"), None, json!({})).await.unwrap();
    }
    let a = Some("a");
    send(&core, &root, Operation::Write, "sys/mounts/secret2/", a, json!({ "type": "kv-v2" })).await.unwrap();
    send(&core, &root, Operation::Write, "sys/mounts/resources2/", a, json!({ "type": "resource" })).await.unwrap();
    (bvault, core, root)
}

/// Write policy `name` in namespace `ns` as root.
async fn ns_policy(core: &Arc<Core>, root: &str, ns: &str, name: &str, hcl: &str) -> Result<Option<Response>, RvError> {
    send(core, root, Operation::Write, &format!("sys/policy/{name}"), Some(ns), json!({ "policy": hcl })).await
}

/// A token created inside `ns` carrying `policies` (names resolved there).
async fn born_in(core: &Arc<Core>, root: &str, ns: &str, policies: &[&str], child_visible: bool) -> String {
    let b = json!({ "policies": policies, "child_visible": child_visible, "ttl": "1h" });
    let created = send(core, root, Operation::Write, "auth/token/create", Some(ns), b).await.unwrap().unwrap();
    created.auth.unwrap().client_token
}

/// A KV secret or resource transfer between two places, each `(namespace, mount, path)`.
fn between(kind: &str, from: (&str, &str, &str), to: (&str, &str, &str)) -> Value {
    json!({
        "kind": kind,
        "source": { "namespace": from.0, "mount": from.1, "path": from.2 },
        "destination": { "namespace": to.0, "mount": to.1, "path": to.2 },
    })
}

async fn run(
    core: &Arc<Core>,
    token: &str,
    op: &str,
    header: Option<&str>,
    b: Value,
) -> Result<Option<Response>, RvError> {
    send(core, token, Operation::Write, &format!("sys/namespace-transfer/{op}"), header, b).await
}

/// What `sys/capabilities-self` reports for each path, as `token` in `header`.
async fn capabilities(core: &Arc<Core>, token: &str, header: Option<&str>, paths: &[&str]) -> Vec<Value> {
    let r = send(core, token, Operation::Write, "sys/capabilities-self", header, json!({ "paths": paths })).await;
    let data = r.unwrap().unwrap().data.unwrap();
    paths.iter().map(|p| data["capabilities"][*p].clone()).collect()
}

/// Seed `a`: resource `srv1` in `resources/` and KV secret `team/db` (two versions) in `secret/`.
async fn seed_a(core: &Arc<Core>, root: &str) {
    seed_resource(core, root, Some("a"), "srv1").await;
    for v in ["one", "two"] {
        let b = json!({ "data": { "v": v } });
        send(core, root, Operation::Write, "secret/data/team/db", Some("a"), b).await.unwrap();
    }
}

fn denied(r: &Result<Option<Response>, RvError>) -> bool {
    matches!(r, Err(RvError::ErrPermissionDenied))
}

/// [`denied`], or the refusal a sudo-gated `sys/` path gives without `sudo` there.
fn refused(r: &Result<Option<Response>, RvError>) -> bool {
    denied(r) || message(r).contains("cannot access root path")
}

/// A token born in `a` whose own policy grants the routes copies a resource
/// and a KV secret between two mounts of `a`, and moves one, with its own
/// rights: everything arrives, the copy leaves its source, the move does not.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespace_born_token_transfers_between_mounts_of_its_namespace() {
    let (_bvault, core, root) = tenants("ns_born_transfer_own_mounts").await;
    seed_a(&core, &root).await;
    ns_policy(&core, &root, "a", "mover", &format!("{ROUTES}{A_DATA}")).await.unwrap();
    let token = born_in(&core, &root, "a", &["mover"], false).await;
    let a = Some("a");

    let b = between("resource", ("a", "resources", "srv1"), ("a", "resources2", "srv1"));
    let out = result(run(&core, &token, "copy", a, b).await);
    assert_eq!(out["transferred"]["versions"], json!(3), "{out}");
    let copied = get(&core, &root, a, "resources2/resources/srv1").await.expect("the record arrived");
    assert_eq!(copied["hostname"], json!("h2.example"));
    let login = get(&core, &root, a, "resources2/secrets/srv1/login").await.expect("the secret arrived");
    assert_eq!(login["value"], json!("pw-2"));
    assert!(get(&core, &root, a, "resources/resources/srv1").await.is_some(), "a copy leaves the source");

    let b = between("kv-secret", ("a", "secret", "team/db"), ("a", "secret2", "team/db"));
    let out = result(run(&core, &token, "copy", a, b).await);
    assert_eq!(out["transferred"]["versions"], json!(2), "{out}");
    let kv = get(&core, &root, a, "secret2/data/team/db").await.expect("the secret arrived");
    assert_eq!(kv["data"], json!({ "v": "two" }));

    let b = between("kv-secret", ("a", "secret", "team/db"), ("a", "secret2", "team/moved"));
    result(run(&core, &token, "move", a, b).await);
    assert!(get(&core, &root, a, "secret2/data/team/moved").await.is_some(), "the move arrived");
    assert!(get(&core, &root, a, "secret/data/team/db").await.is_none(), "the move deleted its source");
}

/// With `child_visible`, the same grant copies from `a` into its child `a/b`,
/// where the token's rights come from `a/b`'s own policy. Without it, `a/b`
/// is a namespace the token cannot see. The route itself is granted only in
/// `a`: sent with the `a/b` header it is refused.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_child_visible_token_transfers_into_a_descendant() {
    let (_bvault, core, root) = tenants("ns_born_transfer_descendant").await;
    seed_a(&core, &root).await;
    ns_policy(&core, &root, "a", "mover", &format!("{ROUTES}{A_DATA}")).await.unwrap();
    let child = r#"
        path "a/b/secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
        path "a/b/resources/*" { capabilities = ["create", "read", "update", "delete", "list"] }
    "#;
    ns_policy(&core, &root, "a/b", "child-writer", child).await.unwrap();
    let token = born_in(&core, &root, "a", &["mover", "child-writer"], true).await;
    let a = Some("a");

    let kv = between("kv-secret", ("a", "secret", "team/db"), ("a/b", "secret", "team/db"));
    let out = result(run(&core, &token, "copy", a, kv.clone()).await);
    assert_eq!(out["destination"]["namespace"], json!("a/b"), "{out}");
    let arrived = get(&core, &root, Some("a/b"), "secret/data/team/db").await.expect("the secret arrived in a/b");
    assert_eq!(arrived["data"], json!({ "v": "two" }));
    let res = between("resource", ("a", "resources", "srv1"), ("a/b", "resources", "srv1"));
    result(run(&core, &token, "copy", a, res).await);
    assert!(get(&core, &root, Some("a/b"), "resources/resources/srv1").await.is_some(), "the resource arrived");

    let header_b = run(&core, &token, "copy", Some("a/b"), kv.clone()).await;
    assert!(denied(&header_b), "the grant is a's, not a/b's: {header_b:?}");

    let hidden = born_in(&core, &root, "a", &["mover", "child-writer"], false).await;
    let mut again = kv;
    again["destination"]["path"] = json!("team/other");
    let r = run(&core, &hidden, "copy", a, again).await;
    assert_eq!(status(&r), 400, "{r:?}");
    let expected = "invalid namespace transfer: destination: namespace 'a/b' has no kv-v2 mount 'secret/' the caller can see (a namespace \
                    that does not exist, or that the token may not operate in, shows none)";
    assert_eq!(message(&r), expected);
    assert!(get(&core, &root, Some("a/b"), "secret/data/team/other").await.is_none(), "nothing written");
}

/// The same token never reaches a sibling (`c`) or an ancestor (root, or `a`
/// for a token born in `a/b`): each is a namespace it cannot see, refused
/// before anything is read, and nothing is written there.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespace_born_token_cannot_transfer_to_a_sibling_or_an_ancestor() {
    let (_bvault, core, root) = tenants("ns_born_transfer_sibling_ancestor").await;
    seed_a(&core, &root).await;
    ns_policy(&core, &root, "a", "mover", &format!("{ROUTES}{A_DATA}")).await.unwrap();
    let token = born_in(&core, &root, "a", &["mover"], true).await;
    let a = Some("a");

    let sibling =
        run(&core, &token, "copy", a, between("kv-secret", ("a", "secret", "team/db"), ("c", "secret", "x"))).await;
    assert_eq!(status(&sibling), 400, "{sibling:?}");
    let expected = "invalid namespace transfer: destination: namespace 'c' has no kv-v2 mount 'secret/' the caller can see (a namespace that \
                    does not exist, or that the token may not operate in, shows none)";
    assert_eq!(message(&sibling), expected);
    let from_sibling =
        run(&core, &token, "copy", a, between("kv-secret", ("c", "secret", "x"), ("a", "secret", "y"))).await;
    assert_eq!(message(&from_sibling), expected.replace("destination:", "source:"));

    let up = run(&core, &token, "copy", a, between("kv-secret", ("a", "secret", "team/db"), ("", "secret", "x"))).await;
    assert_eq!(status(&up), 400, "{up:?}");
    let expected = "invalid namespace transfer: destination: the root namespace has no kv-v2 mount 'secret/' the caller can see (a namespace \
                    that does not exist, or that the token may not operate in, shows none)";
    assert_eq!(message(&up), expected);

    let grandchild = format!("{ROUTES}path \"a/b/secret/*\" {{ capabilities = {ALL} }}");
    ns_policy(&core, &root, "a/b", "mover", &grandchild).await.unwrap();
    let in_b = born_in(&core, &root, "a/b", &["mover"], true).await;
    send(&core, &root, Operation::Write, "secret/data/x", Some("a/b"), json!({ "data": { "v": "b" } })).await.unwrap();
    let to_parent = between("kv-secret", ("a/b", "secret", "x"), ("a", "secret", "x"));
    let r = run(&core, &in_b, "copy", Some("a/b"), to_parent).await;
    assert_eq!(status(&r), 400, "{r:?}");
    let expected = "invalid namespace transfer: destination: namespace 'a' has no kv-v2 mount";
    assert!(message(&r).starts_with(expected), "{}", message(&r));

    for (ns, path) in [(Some("c"), "secret/data/x"), (None, "secret/data/x"), (a, "secret/data/x")] {
        assert!(get(&core, &root, ns, path).await.is_none(), "nothing written in {ns:?}");
    }
}

/// A token without the grant gets one 403 whatever the header names (its own
/// namespace, a missing one, a sibling, none) and whatever the body names; a
/// token holding the grant gets the same 403 outside its own namespace.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn the_route_refuses_alike_whether_the_namespace_exists() {
    let (_bvault, core, root) = tenants("ns_born_transfer_no_oracle").await;
    seed_a(&core, &root).await;
    ns_policy(&core, &root, "a", "data-only", A_DATA).await.unwrap();
    ns_policy(&core, &root, "a", "mover", &format!("{ROUTES}{A_DATA}")).await.unwrap();
    let no_grant = born_in(&core, &root, "a", &["data-only"], true).await;
    let granted = born_in(&core, &root, "a", &["mover"], true).await;

    let mut answers = Vec::new();
    for header in [Some("a"), Some("zz"), Some("c"), None] {
        for dst in ["a/b", "zz", "c", ""] {
            let b = between("kv-secret", ("a", "secret", "team/db"), (dst, "secret", "x"));
            let r = run(&core, &no_grant, "copy", header, b).await;
            answers.push((format!("no grant, header {header:?}, destination {dst:?}"), status(&r), message(&r)));
        }
    }
    for header in [Some("zz"), Some("c"), Some("a/b"), None] {
        let b = between("kv-secret", ("a", "secret", "team/db"), ("a", "secret2", "x"));
        let r = run(&core, &granted, "move", header, b).await;
        answers.push((format!("granted, header {header:?}"), status(&r), message(&r)));
    }
    let first = (answers[0].1, answers[0].2.clone());
    assert_eq!(first.0, 403, "{answers:?}");
    for (case, s, m) in &answers {
        assert_eq!((*s, m.clone()), first, "{case}");
    }
    assert!(get(&core, &root, Some("a"), "secret/data/team/db").await.is_some(), "nothing moved");
}

/// A policy in `a` authorises nothing elsewhere: a token born in `c` carrying
/// the same name (absent in `c`, or present without the routes) is refused,
/// and a root sign-in assigned to `a` is not granted the route by `a`'s
/// policy: it still needs a root-namespace policy, as before T513.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_policy_in_one_namespace_grants_the_route_nowhere_else() {
    let (_bvault, core, root) = tenants("ns_born_transfer_other_namespace").await;
    seed_a(&core, &root).await;
    send(&core, &root, Operation::Write, "secret/data/x", Some("c"), json!({ "data": { "v": "c" } })).await.unwrap();
    ns_policy(&core, &root, "a", "mover", &format!("{ROUTES}{A_DATA}")).await.unwrap();
    let in_c = born_in(&core, &root, "c", &["mover"], false).await;
    let c_move = || between("kv-secret", ("c", "secret", "x"), ("c", "secret", "y"));
    assert!(denied(&run(&core, &in_c, "copy", Some("c"), c_move()).await), "no `mover` in c");
    ns_policy(
        &core,
        &root,
        "c",
        "mover",
        r#"path "c/secret/*" { capabilities = ["create", "read", "update", "list"] }"#,
    )
    .await
    .unwrap();
    let in_c = born_in(&core, &root, "c", &["mover"], false).await;
    assert!(denied(&run(&core, &in_c, "copy", Some("c"), c_move()).await), "c's `mover` names no route");
    let caps = capabilities(&core, &in_c, Some("c"), &["sys/namespace-transfer/copy"]).await;
    assert_eq!(caps, vec![json!(["deny"])]);

    // A sign-in assigned to root and `a` is bound to root at login.
    send(&core, &root, Operation::Write, "sys/auth/userpass", None, json!({ "type": "userpass" })).await.unwrap();
    let (assigned, _) = user_in(&core, &root, "assigned", "mover", &["", "a"]).await;
    let a_copy = |to: &str| between("kv-secret", ("a", "secret", "team/db"), ("a", "secret2", to));
    let r = run(&core, &assigned, "copy", Some("a"), a_copy("team/db")).await;
    assert!(denied(&r), "a's policy does not grant a root sign-in the route: {r:?}");
    write_policy(&core, &root, "route-at-root", "path \"sys/namespace-transfer/*\" { capabilities = [\"update\"] }")
        .await;
    let (rooted, _) = user_in(&core, &root, "rooted", "mover,route-at-root", &["", "a"]).await;
    let out = result(run(&core, &rooted, "copy", Some("a"), a_copy("team/db")).await);
    assert_eq!(out["transferred"]["versions"], json!(2), "a root-namespace grant works as before: {out}");

    // Assigned to `a` only, a sign-in is bound to `a` at login: born there.
    let (only_a, _) = user_in(&core, &root, "only-a", "mover", &["a"]).await;
    result(run(&core, &only_a, "copy", Some("a"), a_copy("team/other")).await);
}

/// `sys/capabilities-self` reports the route as the pipeline decides it:
/// `update` for the token in its own namespace, `deny` in a descendant, at
/// root, and for a token without the grant.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn capabilities_self_reports_the_route_for_a_namespace_born_token() {
    let (_bvault, core, root) = tenants("ns_born_transfer_capabilities").await;
    ns_policy(&core, &root, "a", "data-only", A_DATA).await.unwrap();
    ns_policy(&core, &root, "a", "mover", &format!("{ROUTES}{A_DATA}")).await.unwrap();
    let granted = born_in(&core, &root, "a", &["mover"], true).await;
    let no_grant = born_in(&core, &root, "a", &["data-only"], true).await;
    let routes = ["sys/namespace-transfer/copy", "sys/namespace-transfer/move"];

    let update = vec![json!(["update"]), json!(["update"])];
    let deny = vec![json!(["deny"]), json!(["deny"])];
    assert_eq!(capabilities(&core, &granted, Some("a"), &routes).await, update);
    assert_eq!(capabilities(&core, &granted, Some("a/b"), &routes).await, deny, "in the child");
    assert_eq!(capabilities(&core, &granted, None, &routes).await, deny, "at root");
    assert_eq!(capabilities(&core, &no_grant, Some("a"), &routes).await, deny, "without the grant");
}

/// The exception is exactly two paths. At write time a namespace policy may
/// name `sys/namespace-transfer/copy` and `.../move` and no other root-owned
/// path (no glob, no other operation, no `..`); at request time a token born
/// in `a` holding every right on `a/` and `a/sys/` reaches those two routes and
/// `sys/capabilities-self` (granted to every namespace token) and no other
/// `sys/` path, by request and by `sys/capabilities-self`.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_namespace_policy_names_no_other_sys_path() {
    let (_bvault, core, root) = tenants("ns_born_transfer_sys_table").await;
    for path in ["sys/namespace-transfer/copy", "sys/namespace-transfer/move"] {
        let hcl = format!("path \"{path}\" {{ capabilities = [\"update\"] }}");
        ns_policy(&core, &root, "a", "one", &hcl).await.unwrap_or_else(|e| panic!("{path}: {e:?}"));
    }
    for path in [
        "sys/namespace-transfer/*",
        "sys/namespace-transfer/+",
        "sys/namespace-transfer/copy*",
        "sys/namespace-transfer/copy/*",
        "sys/namespace-transfer",
        "sys/namespace-transfer/",
        "sys/namespace-transfer/delete",
        "sys/namespace-transfer/../mounts",
        "sys/namespace-transfer/copy/../../policy/x",
        "SYS/namespace-transfer/copy",
        "sys/namespace-transfer-x/copy",
        "sys/*",
        "sys/policy",
        "sys/policy/*",
        "sys/mounts",
        "sys/mounts/*",
        "sys/namespaces",
        "sys/namespaces/*",
        "sys/seal",
        "sys/capabilities",
        "sys/capabilities-self",
        "sys/internal/*",
        "sys/internal/ui/mounts",
        "auth/token/create",
        "*",
    ] {
        let hcl = format!("path \"{path}\" {{ capabilities = [\"update\"] }}");
        let r = ns_policy(&core, &root, "a", "other", &hcl).await;
        assert_eq!(status(&r), 403, "{path}: {r:?}");
        assert!(message(&r).contains("may not reference path"), "{path}: {}", message(&r));
    }

    let wide = format!("{ROUTES}path \"a/*\" {{ capabilities = {ALL} }}\npath \"a/sys/*\" {{ capabilities = {ALL} }}");
    ns_policy(&core, &root, "a", "wide", &wide).await.unwrap();
    let token = born_in(&core, &root, "a", &["wide"], true).await;
    let a = Some("a");
    for (op, path) in [
        (Operation::Read, "sys/mounts"),
        (Operation::List, "sys/policy"),
        (Operation::Write, "sys/policy/evil"),
        (Operation::List, "sys/namespaces"),
        (Operation::Write, "sys/namespaces/evil"),
        (Operation::Write, "sys/capabilities"),
        (Operation::Write, "sys/mounts/evil"),
        (Operation::Write, "sys/namespace-transfer"),
        (Operation::Write, "sys/namespace-transfer/delete"),
        (Operation::Write, "sys/namespace-transfer/../mounts/evil"),
    ] {
        let b = json!({ "policy": "path \"*\" { capabilities = [\"sudo\"] }", "type": "kv-v2", "paths": ["x"] });
        let r = send(&core, &token, op, path, a, b).await;
        assert!(refused(&r), "{op:?} {path}: {r:?}");
    }
    let reached = run(&core, &token, "copy", a, json!({})).await;
    assert_eq!(status(&reached), 400, "the grant reaches the handler: {reached:?}");
    assert!(message(&reached).starts_with("invalid namespace transfer"), "{}", message(&reached));

    let probes = [
        "sys/namespace-transfer/copy",
        "sys/namespace-transfer/move",
        "sys/capabilities-self",
        "sys/namespace-transfer",
        "sys/namespace-transfer/delete",
        "sys/namespace-transfer/../mounts",
        "sys/policy",
        "sys/policy/x",
        "sys/mounts",
        "sys/namespaces",
        "sys/seal",
        "sys/capabilities",
        "sys/internal/counters/requests",
    ];
    let caps = capabilities(&core, &token, a, &probes).await;
    for (path, caps) in probes.iter().zip(caps) {
        let reachable =
            matches!(*path, "sys/namespace-transfer/copy" | "sys/namespace-transfer/move" | "sys/capabilities-self");
        let expected = if reachable { json!(["update"]) } else { json!(["deny"]) };
        assert_eq!(caps, expected, "{path}");
    }
}
