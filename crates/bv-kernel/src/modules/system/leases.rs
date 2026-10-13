//! The Vault lease endpoints: `sys/renew/<lease_id>`, `sys/revoke/<lease_id>`
//! and `sys/revoke-prefix/<prefix>` (routes in `mod.rs`).
//!
//! These were stubs that answered success without touching a lease. Revocation
//! now goes to the [`ExpirationManager`]; renewal is refused explicitly (see
//! [`SystemBackend::handle_renew`]).
//!
//! `bv-server`'s `/v1/sys` and `/v2/sys` scopes route none of these paths, so
//! plain HTTP gets a 404. They are reached through `Core::handle_request`:
//! embedded vault mode, the in-process API and `POST /v2/sys/batch`.

use std::sync::Arc;

use super::SystemBackend;
use crate::{
    bv_error_response_status,
    errors::RvError,
    logical::{Backend, Request, Response},
    modules::{
        auth::{AuthModule, ExpirationManager},
        namespace::token_binding::token_operable_resolved,
    },
};

#[maybe_async::maybe_async]
impl SystemBackend {
    /// `sys/renew/<lease_id>`: refused with 501.
    ///
    /// [`ExpirationManager::renew`] has never had a production caller, and
    /// wired as it stands it would report renewals that did not happen: a
    /// backend renew that returns nothing comes back as `Ok(None)`, which
    /// `LogicalBackend::handle_revoke_renew` does for every token lease (no
    /// secret) and for an unsupported secret type; a renewed secret without a
    /// TTL is returned as success with the lease's expiry unchanged; and token
    /// leases are not refused, where Vault sends them to `auth/token/renew`.
    /// Renewal is deferred to the dynamic-secrets framework (T62).
    pub async fn handle_renew(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Err(bv_error_response_status!(
            501,
            "sys/renew is not implemented: leases cannot be renewed through this endpoint yet; \
             renew a token with auth/token/renew-self or auth/token/renew"
        ))
    }

    /// `sys/revoke/<lease_id>`: revoke one lease, or refuse with 400 when no
    /// lease has that id.
    ///
    /// A secret lease's revoke error is still logged and swallowed by
    /// `ExpirationManager::revoke_lease_entry`, which deletes the lease row
    /// anyway. Every secret type in the tree revokes with a no-op today, so
    /// only routing can fail there (a removed mount, say); surfacing that
    /// failure is part of T62.
    pub async fn handle_revoke(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        self.ensure_deployment_lease_caller(req).await?;
        let lease_id = lease_key(req, "lease_id")?;
        match self.expiration_manager()?.revoke_named_lease(&lease_id).await {
            Err(RvError::ErrLeaseNotFound) => {
                Err(bv_error_response_status!(400, "invalid lease: no lease has this id, nothing was revoked"))
            }
            result => result.map(|()| None),
        }
    }

    /// `sys/revoke-prefix/<prefix>`: revoke every lease under `<prefix>/`,
    /// matched on whole path segments. Needs `sudo`: `revoke-prefix/*` is in
    /// the backend's `root_paths`. As in Vault, a prefix with no leases under it
    /// is not an error.
    pub async fn handle_revoke_prefix(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.ensure_deployment_lease_caller(req).await?;
        let prefix = lease_key(req, "prefix")?;
        self.expiration_manager()?.revoke_prefix(&prefix).await?;
        Ok(None)
    }

    fn expiration_manager(&self) -> Result<Arc<ExpirationManager>, RvError> {
        self.get_module::<AuthModule>("auth")?.expiration.load_full().ok_or(RvError::ErrBarrierSealed)
    }

    /// Lease ids share one deployment-wide keyspace. A namespaced secret's
    /// lease id starts with its namespace path, but a token's auth lease
    /// (`auth/<mount>/…`) carries no namespace at all, so neither the path nor
    /// the namespace header can confine a lease operation to one tenant. `sys/`
    /// is exempt from `enforce_request_token_binding`, which leaves that scoping
    /// to its handlers: these serve only callers operable in the root
    /// namespace, and refuse a namespace header rather than act on the root
    /// namespace's leases for a request addressed to a tenant.
    async fn ensure_deployment_lease_caller(&self, req: &Request) -> Result<(), RvError> {
        if self.resolve_request_namespace(req).await?.is_some() {
            return Err(bv_error_response_status!(
                400,
                "lease revocation is not namespace-scoped yet: send the request without \
                 X-BastionVault-Namespace, from the root namespace, with the full lease id"
            ));
        }
        let auth = req.auth.as_ref().ok_or(RvError::ErrPermissionDenied)?;
        if !token_operable_resolved(&self.core, auth, "").await {
            return Err(RvError::ErrPermissionDenied);
        }
        Ok(())
    }
}

/// The lease id or prefix captured from the request path.
fn lease_key(req: &Request, field: &str) -> Result<String, RvError> {
    let value = req.get_data(field)?;
    let value = value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;
    validate_lease_key(field, value)?;
    Ok(value.to_string())
}

/// `revoke_prefix` builds a sub-view from the prefix, and
/// `BarrierView::new_sub_view` skips the view's key sanity check, so a `..`
/// prefix would list keys outside the lease view. Apply the same rule as
/// `BarrierView::sanity_check` up front. Every stored lease row already passed
/// it, so no lease that exists is refused.
fn validate_lease_key(field: &str, value: &str) -> Result<(), RvError> {
    if value.is_empty() || value.starts_with('/') || value.contains("..") {
        return Err(bv_error_response_status!(
            400,
            "invalid {}: must be a non-empty relative lease path without '..'",
            field
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{json, Map, Value};

    use super::*;
    use crate::{
        kernel_api::VaultCtx,
        logical::{Auth, Operation},
        modules::{auth::expiration::LEASE_VIEW_PREFIX, namespace::token_binding::stamp_binding},
        storage::Storage,
        test_utils::{new_unseal_test_bastion_vault, TestHttpServer},
    };

    const NAMESPACE_HEADER: &str = "x-bastionvault-namespace";

    fn body(value: Value) -> Option<Map<String, Value>> {
        value.as_object().cloned()
    }

    /// One request through `Core::handle_request`: the entry point embedded
    /// vault mode, the in-process API and `sys/batch` use. It is the only one
    /// these endpoints have, since `bv-server`'s `/v1/sys` and `/v2/sys` scopes
    /// do not route them and answer 404 before the logical catch-all.
    #[maybe_async::maybe_async]
    async fn call(
        core: &dyn VaultCtx,
        operation: Operation,
        path: &str,
        token: &str,
        namespace: Option<&str>,
        data: Value,
    ) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = operation;
        req.client_token = token.to_string();
        req.body = body(data);
        if let Some(ns) = namespace {
            req.headers = Some(HashMap::from([(NAMESPACE_HEADER.to_string(), ns.to_string())]));
        }
        core.handle_request(&mut req).await
    }

    fn assert_status(result: &Result<Option<Response>, RvError>, status: u16) {
        assert!(
            matches!(result, Err(RvError::ErrResponseStatus(s, _)) if *s == status),
            "expected an explicit {status}, got {result:?}"
        );
    }

    /// Mount a KV v1 engine at `leased/` whose reads are registered as leases
    /// (`leased_passthrough`): apart from token auth, the only configuration in
    /// the tree that issues leases today.
    #[maybe_async::maybe_async]
    async fn mount_leased_kv(core: &dyn VaultCtx, root: &str) {
        let options = json!({ "type": "kv", "options": { "leased_passthrough": "true" } });
        call(core, Operation::Write, "sys/mounts/leased", root, None, options).await.expect("mount leased kv");
    }

    /// Write `leased/<path>` and read it back; returns the lease id the read
    /// registered.
    #[maybe_async::maybe_async]
    async fn lease_for(core: &dyn VaultCtx, root: &str, path: &str) -> String {
        let path = format!("leased/{path}");
        call(core, Operation::Write, &path, root, None, json!({ "value": "v", "ttl": "1h" })).await.expect("write");
        let resp = call(core, Operation::Read, &path, root, None, Value::Null).await.expect("read").expect("data");
        let lease_id = resp.secret.map(|s| s.lease_id).unwrap_or_default();
        assert!(lease_id.starts_with(&format!("{path}/")), "the read must register a lease, got {lease_id:?}");
        lease_id
    }

    /// Whether the lease row is still in storage, read straight from the
    /// barrier rather than through the endpoints under test.
    #[maybe_async::maybe_async]
    async fn lease_row_exists(core: &dyn VaultCtx, lease_id: &str) -> bool {
        let view = core.system_view().expect("an unsealed vault has a system view");
        view.new_sub_view(LEASE_VIEW_PREFIX).get(lease_id).await.expect("read lease row").is_some()
    }

    #[maybe_async::maybe_async]
    async fn token_with(core: &dyn VaultCtx, root: &str, policy: &str) -> String {
        let resp = call(core, Operation::Write, "auth/token/create", root, None, json!({ "policies": [policy] }))
            .await
            .expect("token create")
            .expect("token create response");
        resp.auth.expect("token create returns an auth block").client_token
    }

    /// The stub this replaced answered success for any id, so a caller was
    /// told a mistyped or stale lease had been revoked.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sys_revoke_of_an_unknown_lease_is_an_error() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_revoke_unknown_lease").await;
        let path = "sys/revoke/leased/app/db/00000000-0000-4000-8000-000000000000";
        assert_status(&call(&*core, Operation::Write, path, &root, None, Value::Null).await, 400);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sys_revoke_removes_the_lease() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_revoke_removes_lease").await;
        let core = &*core;
        mount_leased_kv(core, &root).await;
        let lease_id = lease_for(core, &root, "app/db").await;
        assert!(lease_row_exists(core, &lease_id).await);

        let path = format!("sys/revoke/{lease_id}");
        let result = call(core, Operation::Write, &path, &root, None, Value::Null).await;
        assert!(matches!(result, Ok(None)), "revoke of a live lease: {result:?}");
        assert!(!lease_row_exists(core, &lease_id).await, "a revoked lease must be gone from storage");

        // Gone now, so naming it again is the unknown-lease case.
        assert_status(&call(core, Operation::Write, &path, &root, None, Value::Null).await, 400);
    }

    /// A token's auth lease revokes the token itself (`revoke_tree`).
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sys_revoke_of_a_token_lease_revokes_the_token() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_revoke_token_lease").await;
        let core = &*core;
        let token = token_with(core, &root, "default").await;
        call(core, Operation::Read, "auth/token/lookup-self", &token, None, Value::Null).await.expect("token is live");

        // The lease id is `auth/token/create/<salted token id>` and the salt is
        // internal, so find it in the lease view.
        let view = core.system_view().expect("an unsealed vault has a system view").new_sub_view(LEASE_VIEW_PREFIX);
        let salted = view.list("auth/token/create/").await.expect("list token leases");
        assert_eq!(salted.len(), 1, "exactly the token created above: {salted:?}");
        let path = format!("sys/revoke/auth/token/create/{}", salted[0]);

        let result = call(core, Operation::Write, &path, &root, None, Value::Null).await;
        assert!(matches!(result, Ok(None)), "revoke of a token lease: {result:?}");
        let lookup = call(core, Operation::Read, "auth/token/lookup-self", &token, None, Value::Null).await;
        assert!(lookup.is_err(), "the token must be revoked with its lease: {lookup:?}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sys_revoke_prefix_needs_sudo_and_revokes_only_its_subtree() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_revoke_prefix").await;
        let core = &*core;
        mount_leased_kv(core, &root).await;
        let team_a = [lease_for(core, &root, "team-a/db").await, lease_for(core, &root, "team-a/cache").await];
        // Shares the string prefix `team-a` but not the path segment.
        let team_ab = lease_for(core, &root, "team-ab/db").await;

        for (name, caps) in [("prefix-update", r#"["update"]"#), ("prefix-sudo", r#"["update", "sudo"]"#)] {
            let policy = format!("path \"sys/revoke-prefix/*\" {{ capabilities = {caps} }}");
            let path = format!("sys/policies/acl/{name}");
            call(core, Operation::Write, &path, &root, None, json!({ "policy": policy })).await.expect("write policy");
        }

        // `revoke-prefix/*` is a root path: `update` alone must not reach it.
        let update_only = token_with(core, &root, "prefix-update").await;
        let result =
            call(core, Operation::Write, "sys/revoke-prefix/leased/team-a", &update_only, None, Value::Null).await;
        // The root-path gate refuses with this `ErrString` today (an HTTP 500);
        // accept `ErrPermissionDenied` too so fixing that mapping does not
        // break the test.
        let refused_by_sudo_gate = matches!(&result, Err(RvError::ErrPermissionDenied))
            || matches!(&result, Err(RvError::ErrString(m)) if m.contains("root path"));
        assert!(refused_by_sudo_gate, "revoke-prefix without sudo: {result:?}");
        for lease_id in team_a.iter().chain([&team_ab]) {
            assert!(lease_row_exists(core, lease_id).await, "a refused revoke-prefix must leave {lease_id}");
        }

        let sudo = token_with(core, &root, "prefix-sudo").await;
        let result = call(core, Operation::Write, "sys/revoke-prefix/leased/team-a", &sudo, None, Value::Null).await;
        assert!(matches!(result, Ok(None)), "revoke-prefix with sudo: {result:?}");
        for lease_id in &team_a {
            assert!(!lease_row_exists(core, lease_id).await, "{lease_id} is under the prefix and must be revoked");
        }
        assert!(lease_row_exists(core, &team_ab).await, "{team_ab} is outside leased/team-a/ and must survive");
    }

    /// Renewal is refused outright rather than wired: see `handle_renew`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sys_renew_is_refused_explicitly() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_renew_refused").await;
        let core = &*core;
        mount_leased_kv(core, &root).await;
        let lease_id = lease_for(core, &root, "app/db").await;

        for path in [format!("sys/renew/{lease_id}"), "sys/renew/leased/app/db/unknown".to_string()] {
            let result = call(core, Operation::Write, &path, &root, None, json!({ "increment": 3600 })).await;
            assert_status(&result, 501);
        }
        assert!(lease_row_exists(core, &lease_id).await);
    }

    /// Lease ids are deployment-wide, so a namespace header cannot scope these
    /// endpoints yet. Honouring the request anyway would act on the root
    /// namespace's `leased/` leases for a request addressed to `nsx`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_lease_revocation_refuses_a_namespace_header() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_revoke_ns_header").await;
        let core = &*core;
        mount_leased_kv(core, &root).await;
        call(core, Operation::Write, "sys/namespaces/nsx", &root, None, json!({})).await.expect("create namespace");
        let lease_id = lease_for(core, &root, "app/db").await;

        for path in [format!("sys/revoke/{lease_id}"), "sys/revoke-prefix/leased".to_string()] {
            assert_status(&call(core, Operation::Write, &path, &root, Some("nsx"), Value::Null).await, 400);
        }
        assert!(lease_row_exists(core, &lease_id).await, "a refused request must not revoke anything");
    }

    /// `sys/` is exempt from `enforce_request_token_binding`, which leaves a
    /// namespace-bound token to these handlers. No tenant-authored policy can
    /// grant `sys/revoke*` today (`refuse_cross_namespace_paths`), so the
    /// request pipeline cannot reach this branch; drive the handlers directly
    /// to pin it.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_lease_revocation_refuses_a_namespace_bound_token() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_lease_revoke_ns_bound_token").await;
        let sys = SystemBackend::new(core);
        let backend = sys.new_backend();

        let mut metadata = HashMap::new();
        stamp_binding(&mut metadata, "nsx", "nsx-uuid", false);
        let auth = Auth { policies: vec!["lease-admin".into()], metadata, ..Default::default() };

        let request = |path: &str, field: &str, value: &str| {
            let mut req = Request::new(path);
            req.operation = Operation::Write;
            req.auth = Some(auth.clone());
            req.data = body(json!({ field: value }));
            req
        };

        let mut req = request("revoke/leased/app/db/x", "lease_id", "leased/app/db/x");
        assert_eq!(sys.handle_revoke(&backend, &mut req).await.err(), Some(RvError::ErrPermissionDenied));
        let mut req = request("revoke-prefix/leased", "prefix", "leased");
        assert_eq!(sys.handle_revoke_prefix(&backend, &mut req).await.err(), Some(RvError::ErrPermissionDenied));
    }

    /// `sys/batch` hands each operation to `Core::handle_request`, which makes
    /// it the HTTP route to these handlers, and the one where the old stub's
    /// success reached a remote client as a 204.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sys_batch_revoke_is_not_a_silent_success() {
        let mut server = TestHttpServer::new("test_sys_batch_revoke", true).await;
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();
        let root = server.root_token.clone();
        let core = server.core.clone();
        mount_leased_kv(&*core, &root).await;
        let lease_id = lease_for(&*core, &root, "app/db").await;

        let operations = json!({ "operations": [
            { "operation": "write", "path": "sys/revoke/leased/app/db/00000000-0000-4000-8000-000000000000" },
            { "operation": "write", "path": format!("sys/revoke/{lease_id}") },
        ]});
        let (status, resp) = server.write("v2/sys/batch", body(operations), Some(&root)).unwrap();
        assert_eq!(status, 200, "batch: {resp:?}");
        let unknown = &resp["results"][0];
        assert_ne!(unknown["status"], json!(204), "an unknown lease must not be reported revoked: {resp:?}");
        assert!(unknown["errors"].as_array().is_some_and(|e| !e.is_empty()), "the refusal must say why: {resp:?}");
        assert_eq!(resp["results"][1]["status"], json!(204), "revoke of a live lease: {resp:?}");
        assert!(!lease_row_exists(&*core, &lease_id).await, "a revoked lease must be gone from storage");
    }

    /// A `..` in any earlier segment is refused before routing, by the
    /// namespace path resolver; one in the last segment reaches the handler.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_lease_revocation_refuses_paths_outside_the_lease_view() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_lease_revoke_outside_view").await;
        for path in ["sys/revoke/leased/app/..", "sys/revoke-prefix/leased/..", "sys/revoke-prefix/leased/a..b"] {
            assert_status(&call(&*core, Operation::Write, path, &root, None, Value::Null).await, 400);
        }
    }

    #[test]
    fn test_lease_key_validation_rejects_keys_outside_the_lease_view() {
        for bad in ["", "/leased/app", "..", "../core/mounts", "leased/../core", "leased/.."] {
            assert!(validate_lease_key("lease_id", bad).is_err(), "{bad:?} must be refused");
        }
        for good in ["leased/app/db/0e7a", "auth/token/create/5f1c", "leased"] {
            assert!(validate_lease_key("lease_id", good).is_ok(), "{good:?} must be accepted");
        }
    }
}
