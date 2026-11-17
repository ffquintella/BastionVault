//! A deny on a KV v2 secret holds whichever path form it is written in (T504).
//!
//! An API version 2 request names a secret `secret/<name>`, the Vault form is
//! `secret/data/<name>`, and the ACL matched only the form the request used. A
//! deny in either form now refuses every route to the secret; allows match as
//! before. Real tokens through `Core::handle_request`.

use std::sync::Arc;

use serde_json::{json, Value};

use super::{
    kernel_policy_deny::{write, write_policy},
    kv_secret_keys::{is_denied, login, send},
};
use crate::{core::Core, logical::Operation, test_utils::new_unseal_test_bastion_vault};

/// Every capability on the whole mount, in every path form.
const OPEN: &str = r#"path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }"#;

/// `(api, operation, path, body)` for every route that reaches the KV v2
/// secret `<dir>/x` or lists `<dir>/`.
fn routes(dir: &str) -> Vec<(u8, Operation, String, Value)> {
    let data = json!({ "data": { "v": "w" } });
    let versions = json!({ "versions": [1] });
    let mut out = Vec::new();
    for api in [1u8, 2] {
        out.push((api, Operation::Write, format!("secret/data/{dir}/x"), data.clone()));
        out.push((api, Operation::Read, format!("secret/data/{dir}/x"), json!({})));
        out.push((api, Operation::Read, format!("secret/metadata/{dir}/x"), json!({})));
        out.push((api, Operation::List, format!("secret/metadata/{dir}/"), json!({})));
        out.push((api, Operation::Write, format!("secret/destroy/{dir}/x"), versions.clone()));
        out.push((api, Operation::Write, format!("secret/undelete/{dir}/x"), versions.clone()));
        out.push((api, Operation::Delete, format!("secret/data/{dir}/x"), json!({})));
        out.push((api, Operation::Delete, format!("secret/metadata/{dir}/x"), json!({})));
    }
    out.push((2, Operation::Write, format!("secret/{dir}/x"), data));
    out.push((2, Operation::Read, format!("secret/{dir}/x"), json!({})));
    out.push((2, Operation::Delete, format!("secret/{dir}/x"), json!({})));
    out
}

async fn vault(name: &str) -> (crate::BastionVault, Arc<Core>, String) {
    let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write_policy(&core, &root, "open", OPEN).await;
    for dir in ["prod", "dev"] {
        write(&core, &root, &format!("secret/data/{dir}/x"), json!({ "data": { "v": "seed" } })).await;
    }
    (bvault, core, root)
}

/// Every route to `dir`'s secret is refused (`want_denied`) or not refused.
async fn check(core: &Arc<Core>, root: &str, token: &str, dir: &str, want_denied: bool, why: &str) {
    for (api, op, path, body) in routes(dir) {
        // A delete or destroy earlier in the list may have removed the seed.
        write(core, root, &format!("secret/data/{dir}/x"), json!({ "data": { "v": "seed" } })).await;
        let r = send(core, token, api, op, &path, None, body).await;
        assert_eq!(is_denied(&r), want_denied, "{why}: api {api} {op:?} {path}: {r:?}");
    }
}

/// A Vault-style deny on `secret/data/prod/*` refuses the version 2 short
/// form, metadata, list, destroy and undelete too; `dev` stays open.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_deny_in_the_data_form_refuses_every_route() {
    let (_bvault, core, root) = vault("deny_data_form").await;
    write_policy(&core, &root, "no-prod", r#"path "secret/data/prod/*" { capabilities = ["deny"] }"#).await;
    let (token, _) = login(&core, &root, "user", "open,no-prod").await;
    check(&core, &root, &token, "prod", true, "deny in the data form").await;
    check(&core, &root, &token, "dev", false, "outside the deny").await;
}

/// The same deny written in the logical form `secret/prod/*` refuses the
/// version 1 `data/` routes as well.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_deny_in_the_logical_form_refuses_every_route() {
    let (_bvault, core, root) = vault("deny_logical_form").await;
    write_policy(&core, &root, "no-prod", r#"path "secret/prod/*" { capabilities = ["deny"] }"#).await;
    let (token, _) = login(&core, &root, "user", "open,no-prod").await;
    check(&core, &root, &token, "prod", true, "deny in the logical form").await;
    check(&core, &root, &token, "dev", false, "outside the deny").await;
}

/// A deny on a sub-command path keeps refusing that sub-command at both API
/// versions; no route around it opened.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_deny_on_a_sub_command_holds_on_both_api_versions() {
    let (_bvault, core, root) = vault("deny_sub_command").await;
    for (sub, op, tail, body) in [
        ("metadata", Operation::Read, "x", json!({})),
        ("metadata", Operation::List, "", json!({})),
        ("metadata", Operation::Delete, "x", json!({})),
        ("destroy", Operation::Write, "x", json!({ "versions": [1] })),
        ("undelete", Operation::Write, "x", json!({ "versions": [1] })),
    ] {
        let name = format!("no-{sub}");
        let hcl = format!("path \"secret/{sub}/prod/*\" {{ capabilities = [\"deny\"] }}");
        write_policy(&core, &root, &name, &hcl).await;
        let (token, _) = login(&core, &root, &format!("u-{sub}"), &format!("open,{name}")).await;
        for api in [1u8, 2] {
            let r = send(&core, &token, api, op, &format!("secret/{sub}/prod/{tail}"), None, body.clone()).await;
            assert!(is_denied(&r), "deny on {sub}/: api {api} {op:?}: {r:?}");
            let r = send(&core, &token, api, op, &format!("secret/{sub}/dev/{tail}"), None, body.clone()).await;
            assert!(!is_denied(&r), "{sub}/ outside the deny: api {api} {op:?}: {r:?}");
        }
    }
}

/// Allows match exactly as before: one form suffices for the routes that use
/// it, and a grant in one form does not reach a route in the other.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn allows_still_match_the_form_they_are_written_in() {
    let (_bvault, core, root) = vault("allow_forms_unchanged").await;
    write_policy(&core, &root, "vault-style", r#"path "secret/data/*" { capabilities = ["read"] }"#).await;
    write_policy(&core, &root, "logical", r#"path "secret/dev/*" { capabilities = ["read"] }"#).await;
    let (vault_style, _) = login(&core, &root, "vaultstyle", "vault-style").await;
    let (logical, _) = login(&core, &root, "logicaluser", "logical").await;

    let r = send(&core, &vault_style, 1, Operation::Read, "secret/data/dev/x", None, json!({})).await;
    assert!(r.is_ok(), "a data-form allow reads at version 1: {r:?}");
    let r = send(&core, &vault_style, 2, Operation::Read, "secret/dev/x", None, json!({})).await;
    assert!(is_denied(&r), "a data-form allow never covered the short form: {r:?}");
    let r = send(&core, &logical, 2, Operation::Read, "secret/dev/x", None, json!({})).await;
    assert!(r.is_ok(), "a logical-form allow reads the short form: {r:?}");
    let r = send(&core, &logical, 1, Operation::Read, "secret/data/dev/x", None, json!({})).await;
    assert!(is_denied(&r), "a logical-form allow never covered data/: {r:?}");
}

/// Deny precedence keeps Vault's most-specific rule: a narrower allow under a
/// denied prefix still reads, in both forms; the rest of the prefix does not.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_more_specific_allow_under_a_deny_still_reads() {
    let (_bvault, core, root) = vault("specific_allow_under_deny").await;
    write(&core, &root, "secret/data/prod/public/x", json!({ "data": { "v": "seed" } })).await;
    let hcl = r#"
path "secret/data/prod/*" { capabilities = ["deny"] }
path "secret/data/prod/public/*" { capabilities = ["read"] }
"#;
    write_policy(&core, &root, "prod-public", hcl).await;
    let (token, _) = login(&core, &root, "user", "open,prod-public").await;
    for (api, path) in [(1u8, "secret/data/prod/public/x"), (2, "secret/prod/public/x")] {
        let r = send(&core, &token, api, Operation::Read, path, None, json!({})).await;
        assert!(r.is_ok(), "api {api}: the narrower allow wins: {r:?}");
    }
    for (api, path) in [(1u8, "secret/data/prod/x"), (2, "secret/prod/x")] {
        let r = send(&core, &token, api, Operation::Read, path, None, json!({})).await;
        assert!(is_denied(&r), "api {api}: the deny holds outside it: {r:?}");
    }
}

/// The transfer's KV import (authorized as `<mount><path>`) honours a deny
/// written in the `data/` form too.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn a_kv_import_honours_a_deny_in_the_data_form() {
    let (_bvault, core, root) = vault("import_deny_data_form").await;
    write_policy(&core, &root, "no-prod", r#"path "secret/data/prod/*" { capabilities = ["deny"] }"#).await;
    let (token, _) = login(&core, &root, "user", "open,no-prod").await;
    let bundle = json!({
        "versions": [{ "version": 1, "created_time": "2025-01-01T00:00:00Z", "data": { "v": "imported" } }],
        "current": 1
    });
    for (dir, want_denied) in [("prod", true), ("dev", false)] {
        let mut req = crate::logical::Request::new(format!("secret/v2/transfer/import/{dir}/new"));
        req.operation = Operation::Write;
        req.client_token = token.clone();
        req.body = bundle.as_object().cloned();
        req.mark_internal_transfer_import();
        let r = core.handle_request(&mut req).await;
        assert_eq!(is_denied(&r), want_denied, "import into {dir}/: {r:?}");
    }
}
