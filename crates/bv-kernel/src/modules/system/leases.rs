//! The Vault lease endpoints `sys/renew/<lease_id>`, `sys/revoke/<lease_id>`
//! and `sys/revoke-prefix/<prefix>`, and the v2-only `revoke_failed`
//! surface `sys/leases/revoke-failed[/<lease_id>]` (routes in `mod.rs`).
//!
//! `bv-server` routes only the `revoke_failed` paths, under `/v2/sys`. The
//! Vault paths are reached through `Core::handle_request`: embedded vault
//! mode, the in-process API and `POST /v2/sys/batch`.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::SystemBackend;
use crate::{
    bv_error_response_status,
    errors::RvError,
    logical::{Backend, Lease, Request, Response, SecretData},
    modules::{
        auth::{expiration::RevokeFailedLease, lease_state::rfc3339, AuthModule, ExpirationManager},
        namespace::token_binding::token_operable_resolved,
    },
};

#[maybe_async::maybe_async]
impl SystemBackend {
    /// `sys/renew/<lease_id>`: renew a secret lease whose backend really
    /// renews it (T62), clamped to the lease's max_ttl. Answers only for a
    /// renewal that happened, with the lease id, duration and renewability,
    /// never the backend's data. `400`: unknown, expired, non-renewable or
    /// past max_ttl. `409`: another renew/revoke is running, or the lease is
    /// `revoke_failed`. `501`: a token's lease (use `auth/token/renew`), or a
    /// backend with no renew hook or that answers without a lease.
    pub async fn handle_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        self.ensure_deployment_lease_caller(req).await?;
        let lease_id = lease_key(req, "lease_id")?;
        let increment = renew_increment(req)?;
        let renewal = match self.expiration_manager()?.renew(&lease_id, increment).await {
            Err(RvError::ErrLeaseNotFound) => {
                return Err(bv_error_response_status!(400, "invalid lease: no lease has this id, nothing was renewed"))
            }
            Err(RvError::ErrLeaseNotRenewable) => {
                return Err(bv_error_response_status!(
                    400,
                    "lease not renewed: it has expired or was issued non-renewable"
                ))
            }
            result => result?,
        };
        let lease = Lease { ttl: renewal.ttl, renewable: renewal.renewable, ..Default::default() };
        let secret = SecretData { lease, lease_id: renewal.lease_id, internal_data: Map::new() };
        Ok(Some(Response { secret: Some(secret), ..Default::default() }))
    }

    /// `sys/revoke/<lease_id>`: revoke one lease, or refuse with 400 when no
    /// lease has that id.
    ///
    /// A secret backend's failed revoke is a `502`, and the lease is kept as
    /// `revoke_failed` and retried (see `v2/sys/leases/revoke-failed`)
    /// instead of being deleted with its credential still live.
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

    /// `LIST v2/sys/leases/revoke-failed`: every lease whose secret backend
    /// failed to revoke it, with its attempts, last error (bounded) and next
    /// retry. Needs `list` and `sudo` (`root_paths`). No secret data is read
    /// into the answer, only the lease's identity and revoke state.
    pub async fn handle_revoke_failed_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.ensure_deployment_lease_caller(req).await?;
        let leases = self.expiration_manager()?.list_revoke_failed().await?;
        let keys: Vec<String> = leases.iter().map(|l| l.lease_id.clone()).collect();
        let key_info: Map<String, Value> = leases.iter().map(|l| (l.lease_id.clone(), revoke_failed_info(l))).collect();
        let mut data = Map::new();
        data.insert("keys".into(), json!(keys));
        data.insert("key_info".into(), Value::Object(key_info));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `DELETE v2/sys/leases/revoke-failed/<lease_id>`: drop a `revoke_failed`
    /// lease without its backend revoking it, after the operator has cleaned
    /// the target up by hand. Needs `delete` and `sudo`. `400` for a lease
    /// that is not `revoke_failed` (revoke it instead) or an unknown id; the
    /// `lease.revoke_failed_cleared` audit event must be written first.
    pub async fn handle_revoke_failed_clear(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.ensure_deployment_lease_caller(req).await?;
        let lease_id = lease_key(req, "lease_id")?;
        match self.expiration_manager()?.force_clear_revoke_failed(&lease_id, Some(req)).await {
            Err(RvError::ErrLeaseNotFound) => {
                Err(bv_error_response_status!(400, "invalid lease: no lease has this id, nothing was cleared"))
            }
            result => result.map(|()| None),
        }
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

/// One listing row: the revoke state, never the lease's data.
fn revoke_failed_info(lease: &RevokeFailedLease) -> Value {
    let failure = &lease.failure;
    json!({
        "path": lease.path,
        "issue_time": rfc3339(lease.issue_time),
        "expire_time": rfc3339(lease.expire_time),
        "attempts": failure.attempts,
        "max_attempts": lease.max_attempts,
        "exhausted": lease.exhausted,
        "first_failed_at": rfc3339(failure.first_failed_at),
        "last_failed_at": rfc3339(failure.last_failed_at),
        "next_attempt_at": (!lease.exhausted).then(|| rfc3339(failure.next_attempt_at)),
        "last_error": failure.last_error,
        "origin": failure.origin,
    })
}

/// `increment`, in seconds; absent or 0 asks for the backend's own TTL.
fn renew_increment(req: &Request) -> Result<std::time::Duration, RvError> {
    let value = req.get_data_or_default("increment")?;
    let secs = value.as_i64().or_else(|| value.as_str().and_then(|s| s.trim().parse::<i64>().ok()));
    match secs {
        Some(secs) if secs >= 0 => Ok(std::time::Duration::from_secs(secs as u64)),
        _ => Err(bv_error_response_status!(400, "invalid increment: must be a non-negative number of seconds")),
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

    /// T62: `sys/renew` renews a lease whose backend really renews it (KV v1
    /// re-reads the value) and still refuses the rest: a token's lease is
    /// `501`, an unknown id `400`. The answer carries no KV data.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sys_renew_renews_only_leases_that_really_renew() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_renew_real_only").await;
        let core = &*core;
        mount_leased_kv(core, &root).await;
        let lease_id = lease_for(core, &root, "app/db").await;

        let path = format!("sys/renew/{lease_id}");
        let resp = call(core, Operation::Write, &path, &root, None, json!({ "increment": 600 }))
            .await
            .expect("a KV v1 lease renews")
            .expect("the renewal is answered");
        let secret = resp.secret.expect("the renewed lease");
        assert_eq!(secret.lease_id, lease_id);
        assert_eq!(secret.ttl, std::time::Duration::from_secs(600));
        assert!(resp.data.is_none(), "sys/renew must not hand out the secret's data: {:?}", resp.data);
        assert!(lease_row_exists(core, &lease_id).await);

        let unknown = call(core, Operation::Write, "sys/renew/leased/app/db/unknown", &root, None, Value::Null).await;
        assert_status(&unknown, 400);

        token_with(core, &root, "default").await;
        let view = core.system_view().expect("an unsealed vault has a system view").new_sub_view(LEASE_VIEW_PREFIX);
        let salted = view.list("auth/token/create/").await.expect("list token leases");
        let token_lease = format!("sys/renew/auth/token/create/{}", salted[0]);
        assert_status(&call(core, Operation::Write, &token_lease, &root, None, Value::Null).await, 501);
    }

    /// T62: a lease whose backend cannot revoke it (here: its mount is gone)
    /// is kept as `revoke_failed`, listed, and force-cleared only on request.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_revoke_failed_leases_are_kept_listed_and_force_cleared() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_revoke_failed_listing").await;
        let core = &*core;
        mount_leased_kv(core, &root).await;
        let lease_id = lease_for(core, &root, "app/db").await;
        let clear = format!("sys/leases/revoke-failed/{lease_id}");

        let healthy = call(core, Operation::Delete, &clear, &root, None, Value::Null).await;
        assert_status(&healthy, 400);
        assert!(lease_row_exists(core, &lease_id).await, "a healthy lease is revoked, not cleared");

        call(core, Operation::Delete, "sys/mounts/leased", &root, None, Value::Null).await.expect("unmount");
        let revoke = call(core, Operation::Write, &format!("sys/revoke/{lease_id}"), &root, None, Value::Null).await;
        assert_status(&revoke, 502);
        assert!(lease_row_exists(core, &lease_id).await, "a failed revoke must not delete the lease");

        let list = call(core, Operation::List, "sys/leases/revoke-failed", &root, None, Value::Null).await;
        let data = list.expect("list").expect("listing").data.expect("listing data");
        assert_eq!(data["keys"], json!([lease_id]));
        let info = &data["key_info"][&lease_id];
        assert_eq!((info["attempts"].clone(), info["origin"].clone()), (json!(1), json!("operator")));
        assert!(info.get("data").is_none() && !info.to_string().contains("\"value\""), "no lease data: {info}");

        let cleared = call(core, Operation::Delete, &clear, &root, None, Value::Null).await;
        assert!(matches!(cleared, Ok(None)), "force-clear: {cleared:?}");
        assert!(!lease_row_exists(core, &lease_id).await);
        let list = call(core, Operation::List, "sys/leases/revoke-failed", &root, None, Value::Null).await;
        assert_eq!(list.unwrap().unwrap().data.unwrap()["keys"], json!([]));
    }

    /// The `revoke_failed` surface is in the sys backend's `root_paths`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_revoke_failed_surface_needs_sudo() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_sys_revoke_failed_sudo").await;
        let core = &*core;
        let policy = r#"path "sys/leases/revoke-failed*" { capabilities = ["list", "delete"] }"#;
        let write =
            call(core, Operation::Write, "sys/policies/acl/lease-ops", &root, None, json!({ "policy": policy }));
        write.await.expect("write policy");
        let token = token_with(core, &root, "lease-ops").await;

        for (operation, path) in
            [(Operation::List, "sys/leases/revoke-failed"), (Operation::Delete, "sys/leases/revoke-failed/kv/a/1")]
        {
            let result = call(core, operation, path, &token, None, Value::Null).await;
            let refused = matches!(&result, Err(RvError::ErrPermissionDenied))
                || matches!(&result, Err(RvError::ErrString(m)) if m.contains("root path"));
            assert!(refused, "{path} without sudo: {result:?}");
        }
    }

    /// The kernel contract an engine uses to end its own lease early.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_a_mount_revokes_its_own_lease_through_the_kernel_contract() {
        use crate::kernel_api::leases::LeaseRevocation;

        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_owner_lease_revoke").await;
        let core = &*core;
        mount_leased_kv(core, &root).await;
        let lease_id = lease_for(core, &root, "app/db").await;
        let revoker = core.lease_revoker().expect("the auth module publishes the lease revoker");

        let foreign = revoker.revoke_owned_lease("secret/", &lease_id).await;
        assert_eq!(foreign.err(), Some(RvError::ErrPermissionDenied));
        assert!(lease_row_exists(core, &lease_id).await);

        assert_eq!(revoker.revoke_owned_lease("leased/", &lease_id).await, Ok(LeaseRevocation::Revoked));
        assert!(!lease_row_exists(core, &lease_id).await);
    }

    /// Served over HTTP under `/v2/sys`. That it is *only* there (`/v1/sys`
    /// is frozen) is pinned by bv-server's golden route inventory.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_revoke_failed_surface_is_served_under_v2() {
        let mut server = TestHttpServer::new("test_revoke_failed_http", true).await;
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();
        let root = server.root_token.clone();

        let (status, resp) = server.read("v2/sys/leases/revoke-failed", Some(&root)).unwrap();
        assert_eq!(status, 200, "{resp:?}");
        // The harness hands back the response's `data` object.
        assert_eq!(resp["keys"], json!([]), "{resp:?}");
        let (status, resp) =
            server.delete("v2/sys/leases/revoke-failed/leased/app/db/0e7a", None, Some(&root)).unwrap();
        assert_eq!(status, 400, "an unknown lease is not cleared: {resp:?}");
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
