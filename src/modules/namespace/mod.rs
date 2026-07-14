//! Namespaces / multi-tenancy module.
//!
//! A namespace is an addressable container that isolates a tenant's mounts,
//! policies, identities, tokens, audit devices, and quotas from every other
//! tenant in the same deployment. Namespaces nest under a parent and inherit
//! nothing automatically — the same blast-radius model Vault Enterprise uses.
//!
//! This module owns the namespace *registry* ([`store::NamespaceStore`]) and
//! the request → namespace *resolver* ([`router`]). The CRUD HTTP surface is
//! served by the system backend under `sys/namespaces/*` (reached via the
//! `v2/` API prefix) because `sys/` is the only mount that may host
//! deployment-wide control endpoints.
//!
//! See `features/namespaces-multitenancy.md` for the full design.
//!
//! ## Phase status
//! - Phase 1 (this module): namespace container, path↔UUID registry,
//!   request resolver, per-namespace mount-router registry, and the
//!   barrier re-rooting migration.
//! - Phases 2–4 add per-namespace policy/token/audit, per-namespace
//!   identity + cross-tenant linking, and quota enforcement + GUI.

use std::{any::Any, sync::Arc};

use arc_swap::ArcSwap;

use super::Module;
use crate::{core::Core, errors::RvError};

pub mod identity_link;
pub mod migrate;
pub mod mount_registry;
pub mod ns_assignment;
pub mod policy_scope;
pub mod quota;
pub mod router;
pub mod store;
pub mod token_binding;

pub use identity_link::{IdentityLink, IdentityLinkMember, IdentityLinkStore};
pub use mount_registry::NamespaceMountRegistry;
pub use ns_assignment::{NsAssignment, NsAssignmentStore};
pub use router::ResolvedNamespace;
pub use store::{Namespace, NamespaceQuotas, NamespaceStore};

/// Logical module name; used for `module_manager.get_module`.
pub const NAMESPACE_MODULE_NAME: &str = "namespace";

pub struct NamespaceModule {
    pub name: String,
    pub core: Arc<Core>,
    pub store: ArcSwap<Option<Arc<NamespaceStore>>>,
    /// Per-namespace mount routers. Shared (cheap to clone) so the system
    /// backend and the request resolver see the same registered mounts.
    pub registry: Arc<NamespaceMountRegistry>,
    /// Cross-tenant identity links (Phase 3). Installed at unseal alongside
    /// the registry.
    pub link_store: ArcSwap<Option<Arc<IdentityLinkStore>>>,
    /// Per-namespace request-rate limiter (Phase 4 quota enforcement). Lives
    /// for the module's lifetime; buckets are created lazily per namespace.
    pub rate_limiter: quota::RateLimiter,
}

impl NamespaceModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: NAMESPACE_MODULE_NAME.to_string(),
            core,
            store: ArcSwap::new(Arc::new(None)),
            registry: Arc::new(NamespaceMountRegistry::new()),
            link_store: ArcSwap::new(Arc::new(None)),
            rate_limiter: quota::RateLimiter::new(),
        }
    }

    pub fn store(&self) -> Option<Arc<NamespaceStore>> {
        self.store.load().as_ref().clone()
    }

    pub fn link_store(&self) -> Option<Arc<IdentityLinkStore>> {
        self.link_store.load().as_ref().clone()
    }
}

#[maybe_async::maybe_async]
impl Module for NamespaceModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    async fn init(&self, core: &Core) -> Result<(), RvError> {
        let store = Arc::new(NamespaceStore::new(core)?);
        // Mint (or read back) the implicit root namespace. This is the anchor
        // the re-rooting migration and the per-namespace router registry both
        // depend on, so it must succeed before either runs.
        store.ensure_root().await?;
        self.store.store(Arc::new(Some(store)));
        let link_store = Arc::new(IdentityLinkStore::new(core)?);
        self.link_store.store(Arc::new(Some(link_store)));
        Ok(())
    }

    fn cleanup(&self, _core: &Core) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        self.link_store.store(Arc::new(None));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_read_api, test_write_api,
    };
    use serde_json::json;

    fn store_of(core: &Arc<Core>) -> Arc<NamespaceStore> {
        core.module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .expect("namespace store must be installed after unseal")
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_root_namespace_exists_after_unseal() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_root_exists").await;
        let store = store_of(&core);
        let root_uuid = store.root_uuid().unwrap();
        assert!(!root_uuid.is_empty());
        let root = store.get_by_path("").await.unwrap().unwrap();
        assert!(root.is_root());
        assert_eq!(root.uuid, root_uuid);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_store_crud_and_delete_guards() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_store_crud").await;
        let store = store_of(&core);

        // Create a child and a grandchild.
        let eng = store.create("engineering", NamespaceQuotas::default(), false).await.unwrap();
        assert_eq!(eng.path, "engineering");
        assert!(!eng.parent_uuid.is_empty());
        let plat = store
            .create("engineering/platform", NamespaceQuotas::default(), false)
            .await
            .unwrap();
        assert_eq!(plat.parent_uuid, eng.uuid);

        // Duplicate create is refused.
        assert!(store.create("engineering", NamespaceQuotas::default(), false).await.is_err());
        // Creating under a non-existent parent is refused.
        assert!(store.create("marketing/team", NamespaceQuotas::default(), false).await.is_err());

        // list_children of root and of engineering.
        assert_eq!(store.list_children("").await.unwrap(), vec!["engineering".to_string()]);
        assert_eq!(
            store.list_children("engineering").await.unwrap(),
            vec!["platform".to_string()]
        );

        // Cannot delete the root, nor a namespace with children.
        assert!(store.delete("", 0).await.is_err());
        assert!(store.delete("engineering", 0).await.is_err());
        // Cannot delete a namespace that still has mounts.
        assert!(store.delete("engineering/platform", 1).await.is_err());

        // Delete leaf, then parent.
        store.delete("engineering/platform", 0).await.unwrap();
        store.delete("engineering", 0).await.unwrap();
        assert!(store.get_by_path("engineering").await.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_request_resolver_header_and_path_prefix() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_resolver").await;
        let store = store_of(&core);
        store.create("engineering", NamespaceQuotas::default(), false).await.unwrap();
        store
            .create("engineering/platform", NamespaceQuotas::default(), false)
            .await
            .unwrap();

        // Path-prefix form, longest match wins.
        let r = store.resolve_request(None, "engineering/platform/secret/foo").await.unwrap();
        assert_eq!(r.namespace.path, "engineering/platform");
        assert_eq!(r.mount_path, "secret/foo");

        let r = store.resolve_request(None, "engineering/secret/foo").await.unwrap();
        assert_eq!(r.namespace.path, "engineering");
        assert_eq!(r.mount_path, "secret/foo");

        // Header form leaves the path untouched.
        let r = store.resolve_request(Some("engineering/platform"), "secret/foo").await.unwrap();
        assert_eq!(r.namespace.path, "engineering/platform");
        assert_eq!(r.mount_path, "secret/foo");

        // No header, no namespace prefix → root.
        let r = store.resolve_request(None, "secret/foo").await.unwrap();
        assert!(r.namespace.is_root());
        assert_eq!(r.mount_path, "secret/foo");

        // Header naming a missing namespace is a hard error (404-style).
        assert!(store.resolve_request(Some("nope"), "secret/foo").await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_crud_via_sys_api() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_ns_sys_api").await;

        // Create engineering and engineering/platform via the v2 sys surface.
        test_write_api(&core, &root, "sys/namespaces/engineering", true, json!({}).as_object().cloned())
            .await
            .unwrap();
        test_write_api(
            &core,
            &root,
            "sys/namespaces/engineering/platform",
            true,
            json!({ "max_mounts": 5, "child_visible_default": true }).as_object().cloned(),
        )
        .await
        .unwrap();

        // Read back metadata + quotas.
        let resp = test_read_api(&core, &root, "sys/namespaces/engineering/platform", true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["path"], "engineering/platform");
        assert_eq!(data["quotas"]["max_mounts"], 5);
        assert_eq!(data["child_visible_default"], true);

        // List children of root.
        let resp = test_list_api(&core, &root, "sys/namespaces", true).await.unwrap().unwrap();
        let keys = resp.data.unwrap()["keys"].as_array().unwrap().clone();
        assert!(keys.iter().any(|k| k == "engineering"));

        // Delete with a child is refused; delete leaf then parent succeeds.
        let _ = test_delete_api(&core, &root, "sys/namespaces/engineering", false, None).await;
        test_delete_api(&core, &root, "sys/namespaces/engineering/platform", true, None)
            .await
            .unwrap();
        test_delete_api(&core, &root, "sys/namespaces/engineering", true, None).await.unwrap();
        let _ = test_read_api(&core, &root, "sys/namespaces/engineering", false).await;
    }

    /// The root namespace's `child_visible_default` is configurable through the
    /// dedicated self-config route (`sys/namespaces`, empty path) — the by-path
    /// catch-all cannot address it. Flipping it on makes tokens minted at a root
    /// login child-visible, so they can reach descendant namespaces.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_root_child_visible_via_self_config_route() {
        use crate::modules::namespace::token_binding::login_child_visible;

        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_ns_root_self_config").await;
        let store = store_of(&core);

        // Read the root config through the self-route. Default: not child-visible.
        let resp = test_read_api(&core, &root, "sys/namespaces", true).await.unwrap().unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["path"], "");
        assert_eq!(data["child_visible_default"], false);

        // A token minted at a root login is confined to root by default.
        assert!(!login_child_visible(&core, "").await);

        // Flip child_visible_default on for root via the self-route, and set a
        // quota to confirm quotas are updatable here too.
        test_write_api(
            &core,
            &root,
            "sys/namespaces",
            true,
            json!({ "child_visible_default": true, "max_mounts": 7 }).as_object().cloned(),
        )
        .await
        .unwrap();

        // Persisted: read back through the route and directly from the store.
        let resp = test_read_api(&core, &root, "sys/namespaces", true).await.unwrap().unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["child_visible_default"], true);
        assert_eq!(data["quotas"]["max_mounts"], 7);
        let stored = store.get_by_path("").await.unwrap().unwrap();
        assert!(stored.is_root());
        assert!(stored.child_visible_default);

        // Now a root-login token is child-visible → reaches every descendant.
        assert!(login_child_visible(&core, "").await);

        // Turning it back off is likewise honored.
        test_write_api(
            &core,
            &root,
            "sys/namespaces",
            true,
            json!({ "child_visible_default": false }).as_object().cloned(),
        )
        .await
        .unwrap();
        assert!(!login_child_visible(&core, "").await);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_per_namespace_mount_isolation_end_to_end() {
        use crate::logical::{Operation, Request};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_mount_isolation").await;

        // Helper: issue a request scoped to a namespace via the header form.
        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
        store.create("tenant-b", NamespaceQuotas::default(), false).await.unwrap();

        // Mount a KV-v1 engine at cubby/ inside tenant-a only.
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/mounts/cubby/",
            "tenant-a",
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await
        .unwrap();

        // Write + read a secret in tenant-a's cubby.
        ns_req(
            &core,
            &root,
            Operation::Write,
            "cubby/foo",
            "tenant-a",
            json!({ "v": "hello-a" }).as_object().cloned(),
        )
        .await
        .unwrap();
        let resp = ns_req(&core, &root, Operation::Read, "cubby/foo", "tenant-a", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["v"], "hello-a");

        // tenant-b has no cubby mount: the same read must not find tenant-a's
        // secret — it routes into tenant-b's (empty) mount table and fails.
        let err = ns_req(&core, &root, Operation::Read, "cubby/foo", "tenant-b", None).await;
        assert!(err.is_err(), "tenant-b must not see tenant-a's mount/secret");

        // The namespace mount table lists cubby/ for tenant-a, nothing for b.
        let registry = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .unwrap()
            .registry
            .clone();
        let a_uuid = store.get_by_path("tenant-a").await.unwrap().unwrap().uuid;
        let b_uuid = store.get_by_path("tenant-b").await.unwrap().unwrap().uuid;
        let a_mounts = registry.list_mounts(&core, &a_uuid, "tenant-a").await.unwrap();
        assert!(a_mounts.iter().any(|(p, _, _)| p == "cubby/"));
        let b_mounts = registry.list_mounts(&core, &b_uuid, "tenant-b").await.unwrap();
        assert!(b_mounts.is_empty());

        // Deleting tenant-a is refused while it holds the cubby mount.
        assert!(store.delete("tenant-a", registry.mount_count(&a_uuid)).await.is_err());
    }

    /// Regression for "HTTP 500: Router mount conflict" when acting on a
    /// namespace whose mounts are already present in the shared router trie
    /// but whose per-namespace `MountsRouter` is no longer cached.
    ///
    /// The GUI fires `list_mounts` + `list_auth_methods` concurrently on every
    /// namespace page load; both route through `ensure_router`, whose
    /// check-then-insert let the loser re-run `setup()` against a trie the
    /// winner had already populated, and `Router::mount` hard-errored on the
    /// duplicate. `forget()` reproduces the same desync deterministically: it
    /// drops the cache (via `unload` = `MountTable::clear`) but leaves the
    /// trie and the persisted table intact, so the next `ensure_router` rebuilds
    /// and re-runs `setup()` over already-mounted prefixes. That second setup
    /// must be a no-op, not a 500.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ensure_router_setup_is_idempotent_over_shared_trie() {
        use crate::logical::{Operation, Request};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_ensure_router_idempotent").await;

        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);
        store.create("tenant-x", NamespaceQuotas::default(), false).await.unwrap();

        // Mount an engine in the namespace: `ensure_router` builds + caches the
        // router and mounts `tenant-x/secret/` into the shared trie.
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/mounts/secret/",
            "tenant-x",
            json!({ "type": "kv-v2" }).as_object().cloned(),
        )
        .await
        .unwrap();

        let registry = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .unwrap()
            .registry
            .clone();
        let uuid = store.get_by_path("tenant-x").await.unwrap().unwrap().uuid;

        // Evict the cached router while leaving the trie (and persisted table)
        // populated — the desync that concurrent first-touch requests produce.
        registry.forget(&uuid);

        // The next `ensure_router` rebuilds and re-runs `setup()` over the
        // already-mounted `tenant-x/secret/`. Pre-fix this returned
        // `ErrRouterMountConflict`; it must now succeed and still see the mount.
        let mounts = registry
            .list_mounts(&core, &uuid, "tenant-x")
            .await
            .expect("re-setup over a populated trie must not conflict");
        assert!(
            mounts.iter().any(|(p, _, _)| p == "secret/"),
            "rebuilt namespace router must still expose secret/, got {mounts:?}"
        );

        // And a fresh mount alongside it must still work (guarded path).
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/mounts/resources/",
            "tenant-x",
            json!({ "type": "resource" }).as_object().cloned(),
        )
        .await
        .expect("mounting a new engine after re-setup must succeed");
    }

    /// End-to-end regression for the "secret shows as unowned in a
    /// non-root namespace" bug. A KV secret created through the namespace
    /// header must be reported as *owned* by the `identity/owner/kv`
    /// endpoint (the GUI badge path). Before the namespace-scoped owner
    /// key landed, the write stamped ownership under a namespace-prefixed,
    /// `data`-infixed key (`tenant-a/secret/data/github`) while the
    /// header-scoped owner read looked up the mount-relative key
    /// (`secret/github`) — they never matched, so the badge read "unowned".
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_kv_owner_scoped_to_namespace() {
        use crate::logical::{Operation, Request};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use serde_json::Value;
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_kv_owner_scoped").await;

        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: Option<&str>,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            if let Some(ns) = ns {
                let mut h = HashMap::new();
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
                req.headers = Some(h);
            }
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();

        // Mount kv-v2 at secret/ inside tenant-a and create a secret via the
        // namespace header — exactly the GUI's create flow.
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/mounts/secret/",
            Some("tenant-a"),
            json!({ "type": "kv-v2" }).as_object().cloned(),
        )
        .await
        .unwrap();
        ns_req(
            &core,
            &root,
            Operation::Write,
            "secret/data/github",
            Some("tenant-a"),
            json!({ "data": { "token": "ghp_x" } }).as_object().cloned(),
        )
        .await
        .unwrap();

        // The owner-read endpoint must report the secret as owned inside
        // tenant-a. The GUI sends the mount-relative path; the namespace
        // rides in the header.
        let seg = URL_SAFE_NO_PAD.encode("secret/github");
        let owned = ns_req(
            &core,
            &root,
            Operation::Read,
            &format!("identity/owner/kv/{seg}"),
            Some("tenant-a"),
            None,
        )
        .await
        .unwrap()
        .unwrap()
        .data
        .unwrap();
        assert_eq!(
            owned["owned"],
            Value::Bool(true),
            "a secret created in a child namespace must show as owned",
        );
        assert_eq!(owned["entity_id"], Value::String("root".into()));

        // Isolation: the same mount-relative path in the ROOT namespace keys
        // to a different owner record, which does not exist.
        let root_view = ns_req(
            &core,
            &root,
            Operation::Read,
            &format!("identity/owner/kv/{seg}"),
            None,
            None,
        )
        .await
        .unwrap()
        .unwrap()
        .data
        .unwrap();
        assert_eq!(
            root_view["owned"],
            Value::Bool(false),
            "root namespace must not see the child namespace's owner record",
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_namespace_binding_enforced() {
        use crate::logical::{Operation, Request};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_token_binding").await;

        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
        store.create("tenant-b", NamespaceQuotas::default(), false).await.unwrap();

        // Mount kv + seed a secret in tenant-a (root, which bypasses binding).
        ns_req(&core, &root, Operation::Write, "sys/mounts/cubby/", "tenant-a", json!({"type":"kv"}).as_object().cloned()).await.unwrap();
        ns_req(&core, &root, Operation::Write, "cubby/foo", "tenant-a", json!({"v":"secret-a"}).as_object().cloned()).await.unwrap();

        // Tenant-a-scoped policy permitting tenant-a's cubby paths. Authored
        // *inside* tenant-a (header form) so it lands in tenant-a's own policy
        // store; with per-namespace policy storage a token bound to tenant-a
        // resolves "p-ns" from tenant-a, not from root. (A tenant policy may
        // only reference its own namespace's paths, so the tenant-b rule that
        // an earlier revision carried would now be refused at write time.)
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/policy/p-ns",
            "tenant-a",
            json!({ "policy": r#"
                path "tenant-a/cubby/*" { capabilities = ["read","create","update"] }
            "# }).as_object().cloned(),
        )
        .await
        .unwrap();

        // Create a token bound to tenant-a (header at create time), not child-visible.
        let resp = ns_req(
            &core,
            &root,
            Operation::Write,
            "auth/token/create",
            "tenant-a",
            json!({ "policies": ["p-ns"], "child_visible": false, "ttl": "1h" }).as_object().cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let token_a = resp.auth.unwrap().client_token;

        // Same namespace: allowed (binding ok, ACL ok, mount exists).
        let r = ns_req(&core, &token_a, Operation::Read, "cubby/foo", "tenant-a", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.data.unwrap()["v"], "secret-a");

        // Sibling namespace: token binding denies before any backend dispatch.
        let err = ns_req(&core, &token_a, Operation::Read, "cubby/foo", "tenant-b", None).await;
        assert_eq!(err.unwrap_err(), RvError::ErrPermissionDenied);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_cross_namespace_policy_path_refusal() {
        use crate::logical::{Operation, Request};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_policy_refusal").await;

        async fn write_policy_in_ns(
            core: &Arc<Core>,
            token: &str,
            name: &str,
            hcl: &str,
            ns: &str,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(format!("sys/policy/{name}"));
            req.operation = Operation::Write;
            req.client_token = token.to_string();
            req.body = json!({ "policy": hcl }).as_object().cloned();
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);
        store.create("engineering", NamespaceQuotas::default(), false).await.unwrap();
        store.create("marketing", NamespaceQuotas::default(), false).await.unwrap();

        // Root may author a policy referencing any tenant's paths.
        write_policy_in_ns(
            &core,
            &root,
            "root-cross",
            r#"path "marketing/secret/*" { capabilities = ["read"] }"#,
            "",
        )
        .await
        .unwrap();

        // engineering-scoped write referencing its own namespace: allowed.
        write_policy_in_ns(
            &core,
            &root,
            "eng-ok",
            r#"path "engineering/secret/*" { capabilities = ["read"] }"#,
            "engineering",
        )
        .await
        .unwrap();

        // engineering-scoped write referencing marketing: refused.
        let err = write_policy_in_ns(
            &core,
            &root,
            "eng-bad",
            r#"path "marketing/secret/*" { capabilities = ["read"] }"#,
            "engineering",
        )
        .await;
        assert!(err.is_err(), "cross-namespace policy path must be refused");

        // engineering-scoped write with a bare (root-owned) path: refused too,
        // since it does not belong to engineering.
        let err = write_policy_in_ns(
            &core,
            &root,
            "eng-bare",
            r#"path "secret/*" { capabilities = ["read"] }"#,
            "engineering",
        )
        .await;
        assert!(err.is_err(), "bare root-owned path in a namespace policy must be refused");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_per_namespace_policy_storage_isolation() {
        use crate::logical::{Operation, Request};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_policy_storage").await;

        // Issue a request scoped to a namespace via the header form.
        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
        store.create("tenant-b", NamespaceQuotas::default(), false).await.unwrap();

        // A policy named "admin" authored in each tenant — same name, different
        // document, each referencing only its own namespace's paths.
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/policy/admin",
            "tenant-a",
            json!({ "policy": r#"path "tenant-a/cubby/*" { capabilities = ["read"] }"# })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/policy/admin",
            "tenant-b",
            json!({ "policy": r#"path "tenant-b/cubby/*" { capabilities = ["create","update","delete"] }"# })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // Read back: each namespace sees its own "admin" document.
        let a = ns_req(&core, &root, Operation::Read, "sys/policy/admin", "tenant-a", None)
            .await
            .unwrap()
            .unwrap();
        assert!(a.data.unwrap()["rules"].as_str().unwrap().contains("tenant-a/cubby/*"));
        let b = ns_req(&core, &root, Operation::Read, "sys/policy/admin", "tenant-b", None)
            .await
            .unwrap()
            .unwrap();
        assert!(b.data.unwrap()["rules"].as_str().unwrap().contains("tenant-b/cubby/*"));

        // List in tenant-a returns only tenant-a's policies — never the root
        // seeded set (e.g. "default") and never the synthetic "root".
        let list_a = ns_req(&core, &root, Operation::List, "sys/policy", "tenant-a", None)
            .await
            .unwrap()
            .unwrap();
        let keys_a = list_a.data.unwrap()["keys"].as_array().unwrap().clone();
        assert!(keys_a.iter().any(|k| k == "admin"));
        assert!(!keys_a.iter().any(|k| k == "default"));
        assert!(!keys_a.iter().any(|k| k == "root"));

        // Root list still carries the seeded set + "root", and NOT the tenant
        // "admin" documents (different keyspace).
        let list_root = ns_req(&core, &root, Operation::List, "sys/policy", "", None)
            .await
            .unwrap()
            .unwrap();
        let keys_root = list_root.data.unwrap()["keys"].as_array().unwrap().clone();
        assert!(keys_root.iter().any(|k| k == "default"));
        assert!(keys_root.iter().any(|k| k == "root"));

        // Deleting tenant-a's "admin" leaves tenant-b's "admin" intact.
        ns_req(&core, &root, Operation::Delete, "sys/policy/admin", "tenant-a", None)
            .await
            .unwrap();
        let gone = ns_req(&core, &root, Operation::Read, "sys/policy/admin", "tenant-a", None).await;
        assert!(gone.is_err(), "tenant-a admin must be deleted");
        let still = ns_req(&core, &root, Operation::Read, "sys/policy/admin", "tenant-b", None)
            .await
            .unwrap()
            .unwrap();
        assert!(still.data.unwrap()["rules"].as_str().unwrap().contains("tenant-b/cubby/*"));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_per_namespace_identity_login() {
        use crate::logical::{Operation, Request};
        use crate::test_utils::{test_mount_auth_api, test_write_api};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_identity_login").await;

        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        // Auth mount + a credential in the (root) userpass store.
        test_mount_auth_api(&core, &root, "userpass", "userpass").await;
        test_write_api(
            &core,
            &root,
            "auth/userpass/users/alice",
            true,
            json!({ "password": "pw-123456" }).as_object().cloned(),
        )
        .await
        .unwrap();

        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();

        // tenant-a policy "p" + a tenant-a user-group "devs" granting it to alice.
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/policy/p",
            "tenant-a",
            json!({ "policy": r#"path "tenant-a/cubby/*" { capabilities = ["read","create","update"] }"# })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();
        ns_req(
            &core,
            &root,
            Operation::Write,
            "identity/group/user/devs",
            "tenant-a",
            json!({ "members": ["alice"], "policies": ["p"] }).as_object().cloned(),
        )
        .await
        .unwrap();

        // Mount + seed a secret in tenant-a.
        ns_req(&core, &root, Operation::Write, "sys/mounts/cubby/", "tenant-a", json!({"type":"kv"}).as_object().cloned()).await.unwrap();
        ns_req(&core, &root, Operation::Write, "cubby/foo", "tenant-a", json!({"v":"hi-a"}).as_object().cloned()).await.unwrap();

        // Login helper.
        async fn login(core: &Arc<Core>, ns: &str) -> crate::logical::Auth {
            let mut req = Request::new("auth/userpass/login/alice");
            req.operation = Operation::Write;
            req.body = json!({ "password": "pw-123456" }).as_object().cloned();
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap()
        }

        // Login into tenant-a: token bound there, entity created in tenant-a,
        // and the tenant-a group grants policy "p".
        let auth_a = login(&core, "tenant-a").await;
        assert!(auth_a.policies.iter().any(|p| p == "p"), "tenant-a group must grant p");
        let entity_a = auth_a.metadata.get("entity_id").cloned().unwrap_or_default();
        assert!(!entity_a.is_empty());

        // Login at root: a *different* entity, and no "p" (root has no devs group).
        let auth_root = login(&core, "").await;
        let entity_root = auth_root.metadata.get("entity_id").cloned().unwrap_or_default();
        assert!(!entity_root.is_empty());
        assert_ne!(entity_a, entity_root, "same principal must be a distinct entity per namespace");
        assert!(!auth_root.policies.iter().any(|p| p == "p"), "root login must not see tenant-a's group");

        // The tenant-a token can read tenant-a's secret.
        let r = ns_req(&core, &auth_a.client_token, Operation::Read, "cubby/foo", "tenant-a", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.data.unwrap()["v"], "hi-a");

        // The tenant-a token is refused at root (namespace binding).
        let err = ns_req(&core, &auth_a.client_token, Operation::Read, "cubby/foo", "", None).await;
        assert!(err.is_err(), "tenant-a token must not operate at root");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_login_assignment_enforced() {
        use crate::logical::{Operation, Request};
        use crate::test_utils::{test_mount_auth_api, test_write_api};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_login_assignment").await;

        // Root-token sys request scoped to a namespace header.
        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        // Returns Ok/Err so we can assert both success and denial.
        async fn try_login(core: &Arc<Core>, ns: &str) -> Result<(), RvError> {
            let mut req = Request::new("auth/userpass/login/alice");
            req.operation = Operation::Write;
            req.body = json!({ "password": "pw-123456" }).as_object().cloned();
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await.map(|_| ())
        }

        test_mount_auth_api(&core, &root, "userpass", "userpass").await;
        test_write_api(
            &core,
            &root,
            "auth/userpass/users/alice",
            true,
            json!({ "password": "pw-123456" }).as_object().cloned(),
        )
        .await
        .unwrap();

        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
        store.create("tenant-a/sub", NamespaceQuotas::default(), false).await.unwrap();
        store.create("tenant-b", NamespaceQuotas::default(), false).await.unwrap();

        // No assignment ⇒ unrestricted: alice may log in everywhere.
        try_login(&core, "tenant-a").await.unwrap();
        try_login(&core, "tenant-b").await.unwrap();
        try_login(&core, "").await.unwrap();

        // Assign alice → tenant-a via the sys endpoint (root-scoped).
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/identity/ns-assignment/userpass/alice",
            "",
            json!({ "namespaces": ["tenant-a"] }).as_object().cloned(),
        )
        .await
        .unwrap();

        // Readback reflects the assignment.
        let read = ns_req(
            &core,
            &root,
            Operation::Read,
            "sys/identity/ns-assignment/userpass/alice",
            "",
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(read.data.unwrap()["namespaces"][0], "tenant-a");

        // tenant-a and its descendant are allowed; tenant-b and root are denied.
        try_login(&core, "tenant-a").await.unwrap();
        try_login(&core, "tenant-a/sub").await.unwrap();
        assert!(try_login(&core, "tenant-b").await.is_err(), "unassigned namespace must be denied");
        assert!(try_login(&core, "").await.is_err(), "root must be denied once restricted");

        // Clearing the restriction (empty list) restores unrestricted access.
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/identity/ns-assignment/userpass/alice",
            "",
            json!({ "namespaces": [] }).as_object().cloned(),
        )
        .await
        .unwrap();
        try_login(&core, "tenant-b").await.unwrap();
        try_login(&core, "").await.unwrap();
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_quota_enforcement() {
        use crate::logical::{Operation, Request};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_quota").await;

        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);

        // max_child_namespaces = 1: the second child under "acme" is refused.
        let mut q = NamespaceQuotas::default();
        q.max_child_namespaces = 1;
        store.create("acme", q, false).await.unwrap();
        store.create("acme/a", NamespaceQuotas::default(), false).await.unwrap();
        let err = store.create("acme/b", NamespaceQuotas::default(), false).await;
        assert!(err.is_err(), "second child must exceed max_child_namespaces=1");

        // max_mounts = 1: the second mount in "lim" is refused.
        let mut qm = NamespaceQuotas::default();
        qm.max_mounts = 1;
        store.create("lim", qm, false).await.unwrap();
        ns_req(&core, &root, Operation::Write, "sys/mounts/one/", "lim", json!({"type":"kv"}).as_object().cloned())
            .await
            .unwrap();
        let err = ns_req(&core, &root, Operation::Write, "sys/mounts/two/", "lim", json!({"type":"kv"}).as_object().cloned()).await;
        assert!(err.is_err(), "second mount must exceed max_mounts=1");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_accounting_quotas() {
        use crate::logical::{Operation, Request};
        use crate::test_utils::{test_mount_auth_api, test_write_api};
        use std::collections::HashMap;

        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_ns_acct_quota").await;

        async fn ns_req(
            core: &Arc<Core>,
            token: &str,
            op: Operation,
            path: &str,
            ns: &str,
            body: Option<serde_json::Map<String, serde_json::Value>>,
        ) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            req.body = body;
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        async fn login(core: &Arc<Core>, user: &str, ns: &str) -> Result<Option<crate::logical::Response>, RvError> {
            let mut req = Request::new(format!("auth/userpass/login/{user}").as_str());
            req.operation = Operation::Write;
            req.body = json!({ "password": "pw-123456" }).as_object().cloned();
            let mut h = HashMap::new();
            if !ns.is_empty() {
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            }
            req.headers = Some(h);
            core.handle_request(&mut req).await
        }

        let store = store_of(&core);

        // ---- max_entities = 1 ----
        let mut qe = NamespaceQuotas::default();
        qe.max_entities = 1;
        store.create("ent", qe, false).await.unwrap();
        test_mount_auth_api(&core, &root, "userpass", "userpass").await;
        for u in ["alice", "bob"] {
            test_write_api(&core, &root, &format!("auth/userpass/users/{u}"), true, json!({"password":"pw-123456"}).as_object().cloned()).await.unwrap();
        }
        // alice logs into "ent" → first entity, allowed.
        login(&core, "alice", "ent").await.unwrap();
        // alice re-login → existing entity, still allowed.
        login(&core, "alice", "ent").await.unwrap();
        // bob would create a 2nd entity → refused by max_entities=1.
        assert!(login(&core, "bob", "ent").await.is_err(), "2nd entity must exceed max_entities=1");

        // ---- max_storage_bytes ----
        let mut qs = NamespaceQuotas::default();
        qs.max_storage_bytes = 500;
        store.create("stor", qs, false).await.unwrap();
        ns_req(&core, &root, Operation::Write, "sys/mounts/cubby/", "stor", json!({"type":"kv"}).as_object().cloned()).await.unwrap();

        let val = "x".repeat(80);
        let mut first_ok = false;
        let mut hit_limit = false;
        for i in 0..50 {
            let r = ns_req(
                &core,
                &root,
                Operation::Write,
                &format!("cubby/k{i}"),
                "stor",
                json!({ "v": val }).as_object().cloned(),
            )
            .await;
            if i == 0 {
                first_ok = r.is_ok();
            }
            if r.is_err() {
                hit_limit = true;
                break;
            }
        }
        assert!(first_ok, "first write under the cap must succeed");
        assert!(hit_limit, "writes must eventually be refused by max_storage_bytes");
    }
}
