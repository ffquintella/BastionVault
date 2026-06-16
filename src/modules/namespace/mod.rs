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

pub mod migrate;
pub mod mount_registry;
pub mod policy_scope;
pub mod router;
pub mod store;
pub mod token_binding;

pub use mount_registry::NamespaceMountRegistry;
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
}

impl NamespaceModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: NAMESPACE_MODULE_NAME.to_string(),
            core,
            store: ArcSwap::new(Arc::new(None)),
            registry: Arc::new(NamespaceMountRegistry::new()),
        }
    }

    pub fn store(&self) -> Option<Arc<NamespaceStore>> {
        self.store.load().as_ref().clone()
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
        Ok(())
    }

    fn cleanup(&self, _core: &Core) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
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

        // Policy that (deliberately) permits the namespaced paths in both
        // tenants, so ACL is never the differentiator — only token binding is.
        let _ = test_write_api(
            &core,
            &root,
            "sys/policy/p-ns",
            true,
            json!({ "policy": r#"
                path "tenant-a/cubby/*" { capabilities = ["read","create","update"] }
                path "tenant-b/cubby/*" { capabilities = ["read","create","update"] }
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
}
