//! Deployment-wide (all-namespaces) export and import.
//!
//! [`scope::export_to_document`] resolves exactly one namespace: the caller
//! hands it a [`MountIndex`], and every key it reads comes from that index's
//! barrier prefixes. A root-scoped full export therefore captures the root
//! namespace only — a tenant's `secret/` lives under
//! `namespaces/<tenant_uuid>/logical/…`, which the root index never addresses.
//!
//! This module fans that out. An `all_namespaces` export runs the same
//! resolver once per namespace and packs the result as:
//!
//! ```text
//! items.{kv,resources,files,…}   <- the root namespace
//! items.namespaces[]             <- one NamespaceBundle per child namespace
//! ```
//!
//! Root items stay at the top level so an `all_namespaces` document is a
//! superset of a plain `full` one: any importer that ignores the `namespaces`
//! field still restores the root namespace correctly.
//!
//! Two namespaces routinely hold identically-named mounts (`secret/`), so the
//! bundles are what keep them apart — collapsing everything into one flat item
//! list would have one tenant's `secret/db` overwrite another's on import.
//!
//! Scope: like [`ScopeKind::Full`], this is the **data plane** only. The
//! namespace registry, mount tables, policies, and identities are control
//! plane; use the operator backup (`crate::backup`, a raw physical-backend
//! sweep that already spans every namespace) to capture those.

use std::sync::Arc;

use crate::{
    core::Core,
    errors::RvError,
    exchange::{
        schema::{ExchangeDocument, ExchangeItems, ExporterInfo, NamespaceBundle, ScopeSpec},
        scope::{self, ConflictPolicy, ImportResult, MountIndex},
    },
    modules::namespace::{NamespaceModule, NAMESPACE_MODULE_NAME},
    storage::Storage,
};

/// A namespace and the index that addresses its storage.
pub struct NamespaceIndex {
    /// Canonical namespace path; `""` for the root namespace.
    pub path: String,
    pub mounts: MountIndex,
}

/// Build a [`MountIndex`] for every namespace in the deployment, root first.
///
/// Namespaces whose mount router cannot be built are reported as warnings
/// rather than failing the whole export: one broken tenant must not cost the
/// operator a deployment-wide backup.
pub async fn all_namespace_indexes(
    core: &Arc<Core>,
    warnings: &mut Vec<String>,
) -> Result<Vec<NamespaceIndex>, RvError> {
    let mut out = vec![NamespaceIndex {
        path: String::new(),
        mounts: MountIndex::from_core(core)?,
    }];

    let Some(module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
    else {
        return Ok(out);
    };
    let Some(store) = module.store() else {
        return Ok(out);
    };

    let mut namespaces = store.list_all().await?;
    // Deterministic bundle order — canonical JSON must not depend on the
    // registry's listing order.
    namespaces.sort_by(|a, b| a.path.cmp(&b.path));
    for ns in namespaces {
        if ns.is_root() {
            continue;
        }
        match module.registry.ensure_router(core, &ns.uuid, &ns.path).await {
            Ok(router) => match MountIndex::from_namespace_router(&router, &ns.uuid) {
                Ok(mounts) => out.push(NamespaceIndex { path: ns.path.clone(), mounts }),
                Err(e) => warnings
                    .push(format!("namespace {:?} skipped: mount index failed: {e:?}", ns.path)),
            },
            Err(e) => warnings
                .push(format!("namespace {:?} skipped: mount router failed: {e:?}", ns.path)),
        }
    }
    Ok(out)
}

/// Export `scope` across every namespace. The root namespace's items land at
/// the document's top level; each non-root namespace becomes a
/// [`NamespaceBundle`].
///
/// Empty bundles are dropped — a namespace with no mounts (or no data) adds
/// nothing but noise to the file.
pub async fn export_all_namespaces(
    core: &Arc<Core>,
    exporter: ExporterInfo,
    scope: ScopeSpec,
) -> Result<ExchangeDocument, RvError> {
    let storage = core.barrier.as_storage();
    let mut warnings: Vec<String> = Vec::new();
    let indexes = all_namespace_indexes(core, &mut warnings).await?;

    let mut root_items = ExchangeItems::default();
    let mut bundles: Vec<NamespaceBundle> = Vec::new();

    for ns in &indexes {
        let (items, mut ns_warnings) = scope::resolve_scope(storage, &ns.mounts, &scope).await?;
        if ns.path.is_empty() {
            root_items = items;
            warnings.append(&mut ns_warnings);
            continue;
        }
        // Tag a tenant's warnings so an operator reading the file knows which
        // namespace produced them.
        for w in ns_warnings.drain(..) {
            warnings.push(format!("[namespace {}] {w}", ns.path));
        }
        if items.local_len() > 0 {
            bundles.push(NamespaceBundle { path: ns.path.clone(), items });
        }
    }

    root_items.namespaces = bundles;
    let mut doc = ExchangeDocument::new(exporter, scope, root_items);
    doc.warnings = warnings;
    Ok(doc)
}

/// Import a document that may carry namespace bundles.
///
/// Top-level items go to the root namespace exactly as
/// [`scope::import_from_document`] would; each bundle is written through the
/// matching namespace's own [`MountIndex`]. A bundle naming a namespace that
/// does not exist here is skipped with a warning — creating tenants as a side
/// effect of a restore is the namespace API's job, not the importer's.
pub async fn import_document(
    core: &Arc<Core>,
    document: &ExchangeDocument,
    policy: ConflictPolicy,
    dry_run: bool,
) -> Result<ImportResult, RvError> {
    document.validate_schema_tag().map_err(|_| RvError::ErrRequestInvalid)?;
    let storage: &dyn Storage = core.barrier.as_storage();

    let mut result = ImportResult::default();
    let mut warnings: Vec<String> = Vec::new();
    let indexes = all_namespace_indexes(core, &mut warnings).await?;
    result.warnings.append(&mut warnings);

    let root = indexes
        .iter()
        .find(|n| n.path.is_empty())
        .ok_or(RvError::ErrUnknown)?;
    scope::apply_items(storage, &root.mounts, &document.items, policy, dry_run, "", &mut result)
        .await?;

    for bundle in &document.items.namespaces {
        match indexes.iter().find(|n| n.path == bundle.path) {
            Some(ns) => {
                scope::apply_items(
                    storage,
                    &ns.mounts,
                    &bundle.items,
                    policy,
                    dry_run,
                    &ns.path,
                    &mut result,
                )
                .await?;
            }
            None => result.warnings.push(format!(
                "namespace {:?} does not exist on this vault: {} item(s) skipped (create the namespace, then re-import)",
                bundle.path,
                bundle.items.local_len()
            )),
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;
    use crate::exchange::schema::{ScopeKind, ScopeSpec};
    use crate::logical::{Operation, Request, Response};
    use crate::modules::namespace::{NamespaceQuotas, NamespaceStore};
    use crate::test_utils::new_unseal_test_bastion_vault;

    fn store_of(core: &Arc<Core>) -> Arc<NamespaceStore> {
        core.module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .expect("namespace store must be installed after unseal")
    }

    /// Issue a request scoped to `ns` via the header addressing form. `ns = ""`
    /// targets the root namespace.
    async fn ns_req(
        core: &Arc<Core>,
        token: &str,
        op: Operation,
        path: &str,
        ns: &str,
        body: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = op;
        req.client_token = token.to_string();
        req.body = body;
        if !ns.is_empty() {
            let mut h = HashMap::new();
            h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            req.headers = Some(h);
        }
        core.handle_request(&mut req).await
    }

    async fn put_secret(core: &Arc<Core>, token: &str, ns: &str, path: &str, value: &str) {
        ns_req(
            core,
            token,
            Operation::Write,
            path,
            ns,
            json!({ "v": value }).as_object().cloned(),
        )
        .await
        .unwrap();
    }

    async fn read_secret(core: &Arc<Core>, token: &str, ns: &str, path: &str) -> String {
        ns_req(core, token, Operation::Read, path, ns, None)
            .await
            .unwrap()
            .unwrap()
            .data
            .unwrap()["v"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Two tenants holding the *same* mount path with different secrets: the
    /// export must keep them in separate bundles, and the import must put each
    /// back in its own namespace rather than collapsing them into the root.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn all_namespaces_export_round_trips_each_tenant() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_exchange_all_namespaces").await;
        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
        store.create("tenant-b", NamespaceQuotas::default(), false).await.unwrap();

        // The same mount path in all three namespaces, root included — the
        // collision the bundles have to survive.
        for ns in ["", "tenant-a", "tenant-b"] {
            ns_req(
                &core,
                &root,
                Operation::Write,
                "sys/mounts/cubby/",
                ns,
                json!({ "type": "kv" }).as_object().cloned(),
            )
            .await
            .unwrap();
        }
        put_secret(&core, &root, "tenant-a", "cubby/foo", "from-a").await;
        put_secret(&core, &root, "tenant-b", "cubby/foo", "from-b").await;
        put_secret(&core, &root, "", "cubby/foo", "from-root").await;

        let doc = export_all_namespaces(
            &core,
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] },
        )
        .await
        .unwrap();

        // One bundle per tenant, in sorted order, and neither tenant's secret
        // leaked into the root namespace's own items.
        let paths: Vec<&str> =
            doc.items.namespaces.iter().map(|b| b.path.as_str()).collect();
        assert_eq!(paths, vec!["tenant-a", "tenant-b"]);
        let root_values: Vec<String> =
            doc.items.kv.iter().map(|k| k.value.to_string()).collect();
        assert!(root_values.iter().any(|v| v.contains("from-root")));
        assert!(
            !root_values.iter().any(|v| v.contains("from-a") || v.contains("from-b")),
            "tenant data must not appear in the root namespace's items: {root_values:?}"
        );
        for (bundle, expected) in doc.items.namespaces.iter().zip(["from-a", "from-b"]) {
            let joined: String =
                bundle.items.kv.iter().map(|k| k.value.to_string()).collect();
            assert!(
                joined.contains(expected),
                "bundle {} must carry {expected}, got {joined}",
                bundle.path
            );
        }

        // Clobber both tenants, then restore from the document: each bundle
        // must land back in its own namespace.
        put_secret(&core, &root, "tenant-a", "cubby/foo", "clobbered-a").await;
        put_secret(&core, &root, "tenant-b", "cubby/foo", "clobbered-b").await;

        let result =
            import_document(&core, &doc, ConflictPolicy::Overwrite, false).await.unwrap();
        assert!(result.written > 0);
        assert!(
            result.warnings.is_empty(),
            "no namespace should be skipped: {:?}",
            result.warnings
        );
        assert_eq!(read_secret(&core, &root, "tenant-a", "cubby/foo").await, "from-a");
        assert_eq!(read_secret(&core, &root, "tenant-b", "cubby/foo").await, "from-b");
        assert_eq!(read_secret(&core, &root, "", "cubby/foo").await, "from-root");
    }

    /// A root-scoped `full` export must NOT reach into tenants — that is what
    /// the `all_namespaces` kind is for. Guards against a future change making
    /// the root index address namespace prefixes.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn full_export_stays_inside_the_root_namespace() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_exchange_full_is_root_only").await;
        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
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
        put_secret(&core, &root, "tenant-a", "cubby/foo", "from-a").await;

        let mounts = crate::exchange::scope::MountIndex::from_core(&core).unwrap();
        let doc = crate::exchange::scope::export_to_document(
            core.barrier.as_storage(),
            &mounts,
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::Full, include: vec![] },
        )
        .await
        .unwrap();

        assert!(doc.items.namespaces.is_empty());
        let joined: String = doc.items.kv.iter().map(|k| k.value.to_string()).collect();
        assert!(!joined.contains("from-a"), "root full export leaked tenant data");
    }

    /// A bundle naming a namespace this vault does not have is reported, not
    /// silently written into the root namespace.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_skips_bundles_for_unknown_namespaces() {
        let (_bvault, core, _root) =
            new_unseal_test_bastion_vault("test_exchange_unknown_namespace").await;

        let mut items = ExchangeItems::default();
        items.namespaces.push(NamespaceBundle {
            path: "does-not-exist".to_string(),
            items: ExchangeItems {
                kv: vec![crate::exchange::KvItem {
                    mount: "secret/".to_string(),
                    path: "orphan".to_string(),
                    value: json!({ "v": "x" }),
                }],
                ..Default::default()
            },
        });
        let doc = ExchangeDocument::new(
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] },
            items,
        );

        let result = import_document(&core, &doc, ConflictPolicy::Overwrite, false).await.unwrap();
        assert_eq!(result.written, 0);
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("does-not-exist"));
    }
}
