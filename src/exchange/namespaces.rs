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
//! Scope: like [`ScopeKind::Full`], this is the data plane plus each
//! namespace's **ACL policies** — data without the authorization that governs
//! it restores a vault nobody but root can use. The namespace registry, mount
//! tables, and identities remain out of scope; use the operator backup
//! (`crate::backup`, a raw physical-backend sweep that already spans every
//! namespace) to capture those.

use std::sync::Arc;

use crate::kernel_api::VaultCtx;
use crate::{
    core::Core,
    errors::RvError,
    exchange::{
        schema::{ExchangeDocument, ExchangeItems, ExporterInfo, NamespaceBundle, ScopeSpec},
        scope::{self, ConflictPolicy, ImportResult, MountIndex},
        sql_gate::{self, SqlGate},
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
    let mut out = vec![NamespaceIndex { path: String::new(), mounts: MountIndex::from_core(core)? }];

    let Some(module) = core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME) else {
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
        match module.registry.ensure_router(core.clone(), &ns.uuid, &ns.path).await {
            Ok(router) => match MountIndex::from_namespace_router(core, &router, &ns.uuid, &ns.path) {
                Ok(mounts) => out.push(NamespaceIndex { path: ns.path.clone(), mounts }),
                Err(e) => warnings.push(format!("namespace {:?} skipped: mount index failed: {e:?}", ns.path)),
            },
            Err(e) => warnings.push(format!("namespace {:?} skipped: mount router failed: {e:?}", ns.path)),
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
    export_namespaces(core, exporter, scope, &[]).await
}

/// Normalise a caller-supplied namespace selector to the canonical path the
/// bundles use: no leading/trailing slash, and `""` (or the alias `root`) for
/// the root namespace.
pub fn normalize_namespace_selector(raw: &str) -> String {
    let t = raw.trim().trim_matches('/');
    if t == "root" {
        String::new()
    } else {
        t.to_string()
    }
}

fn normalize_selectors(only: &[String]) -> Vec<String> {
    // `*` means "every namespace": it cancels the filter.
    if only.iter().any(|s| s.trim() == "*") {
        return Vec::new();
    }
    let mut v: Vec<String> = only.iter().map(|s| normalize_namespace_selector(s)).collect();
    v.sort();
    v.dedup();
    v
}

/// Like [`export_all_namespaces`], restricted to `only` (canonical paths,
/// `""`/`root` = the root namespace). An empty `only` selects every
/// namespace. A selector naming a namespace this vault does not have is a
/// warning, not an error, so a typo is visible in the file but a partially
/// valid list still exports.
///
/// A selected namespace is exported by exactly the same resolver as in the
/// unrestricted case; unselected namespaces are never read at all.
pub async fn export_namespaces(
    core: &Arc<Core>,
    exporter: ExporterInfo,
    scope: ScopeSpec,
    only: &[String],
) -> Result<ExchangeDocument, RvError> {
    let only = normalize_selectors(only);
    let selected = |path: &str| only.is_empty() || only.iter().any(|o| o == path);
    let __barrier = core.barrier();
    let storage = __barrier.as_storage();
    let mut warnings: Vec<String> = Vec::new();
    let indexes = all_namespace_indexes(core, &mut warnings).await?;
    for o in &only {
        if !indexes.iter().any(|n| &n.path == o) {
            warnings.push(format!("namespace {o:?} does not exist on this vault: nothing exported for it"));
        }
    }

    let mut root_items = ExchangeItems::default();
    let mut bundles: Vec<NamespaceBundle> = Vec::new();

    for ns in &indexes {
        if !selected(&ns.path) {
            continue;
        }
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

/// Which namespaces a document carries: `""` for the root namespace when it
/// has top-level items, then each bundle's path, in document order.
pub fn document_namespaces(document: &ExchangeDocument) -> Vec<String> {
    let mut out = Vec::new();
    if document.items.local_len() > 0 {
        out.push(String::new());
    }
    out.extend(document.items.namespaces.iter().map(|b| b.path.clone()));
    out
}

/// Refuse to hand an operator an export that carries nothing.
///
/// An empty document is a ~800-byte `.bvx` that looks like a successful
/// export and is discovered only on restore. It happens when the selected
/// namespace or engine matched no data, or when a server that predates
/// namespace selection silently ignored the selection and exported root. The
/// error carries the exporter's own warnings so the cause is visible.
pub fn ensure_not_empty(document: &ExchangeDocument) -> Result<(), RvError> {
    if !document_namespaces(document).is_empty() {
        return Ok(());
    }
    let detail =
        if document.warnings.is_empty() { String::new() } else { format!(" ({})", document.warnings.join("; ")) };
    Err(RvError::ErrString(format!(
        "export matched no data: the selected namespaces and engines contain nothing to export{detail}"
    )))
}

/// Split a document into one standalone document per namespace it carries.
///
/// The root namespace's document keeps its items at the top level; every other
/// namespace becomes a document with **empty** top-level items and a single
/// [`NamespaceBundle`]. That is deliberate: the importer decides the target
/// namespace from where an item sits, so a tenant's part must stay a bundle —
/// hoisting it to the top level would restore it into the root namespace.
/// Each part is therefore importable on its own, through the same path as the
/// combined document, and re-importing all of them is equivalent to importing
/// the original. Parts inherit `exporter`, `scope` and `exported_at`;
/// document-level warnings are repeated on each so none is lost.
pub fn split_by_namespace(document: &ExchangeDocument) -> Vec<(String, ExchangeDocument)> {
    let part = |items: ExchangeItems| ExchangeDocument {
        schema: document.schema.clone(),
        exported_at: document.exported_at.clone(),
        exporter: document.exporter.clone(),
        scope: document.scope.clone(),
        items,
        warnings: document.warnings.clone(),
    };
    let mut out = Vec::new();
    let mut root = document.items.clone();
    root.namespaces.clear();
    if root.local_len() > 0 {
        out.push((String::new(), part(root)));
    }
    for b in &document.items.namespaces {
        out.push((b.path.clone(), part(ExchangeItems { namespaces: vec![b.clone()], ..Default::default() })));
    }
    out
}

/// Narrow a document to the namespaces in `only` (same selector rules as
/// [`export_namespaces`]; empty = keep everything). Applied before preview or
/// import, so the classification, the `sql_*` gate and the write all see
/// exactly the selected part and nothing else. A selector matching nothing in
/// the document is reported in the returned warnings.
pub fn retain_namespaces(document: &mut ExchangeDocument, only: &[String]) -> Vec<String> {
    let only = normalize_selectors(only);
    if only.is_empty() {
        return Vec::new();
    }
    let mut warnings = Vec::new();
    let present = document_namespaces(document);
    for o in &only {
        if !present.contains(o) {
            warnings.push(format!("namespace {o:?} is not in this document: nothing to import for it"));
        }
    }
    if !only.iter().any(String::is_empty) {
        let namespaces = std::mem::take(&mut document.items.namespaces);
        document.items = ExchangeItems { namespaces, ..Default::default() };
    }
    document.items.namespaces.retain(|b| only.contains(&b.path));
    warnings
}

/// Narrow a document to the named mounts (`pki/`, `secret/`), in the root
/// namespace and in every bundle. Empty `only` keeps everything.
///
/// KV and raw (non-KV engine) entries carry their mount, so they are filtered
/// exactly. Resources, files, groups and policies carry no mount, so they
/// cannot be attributed to one and are dropped — with a warning naming what
/// was dropped, since an engine-scoped import must never write more than it
/// was asked to.
pub fn retain_mounts(document: &mut ExchangeDocument, only: &[String]) -> Vec<String> {
    let mut only: Vec<String> =
        only.iter().map(|m| m.trim().trim_matches('/')).filter(|m| !m.is_empty()).map(|m| format!("{m}/")).collect();
    only.sort();
    only.dedup();
    if only.is_empty() {
        return Vec::new();
    }
    let mut dropped = 0usize;
    let mut narrow = |items: &mut ExchangeItems| {
        items.kv.retain(|k| only.contains(&k.mount));
        items.raw.retain(|r| only.contains(&r.mount));
        dropped += items.resources.len()
            + items.files.len()
            + items.asset_groups.len()
            + items.resource_groups.len()
            + items.policies.len();
        items.resources.clear();
        items.files.clear();
        items.asset_groups.clear();
        items.resource_groups.clear();
        items.policies.clear();
    };
    narrow(&mut document.items);
    for b in &mut document.items.namespaces {
        narrow(&mut b.items);
    }
    document.items.namespaces.retain(|b| b.items.local_len() > 0);
    let mut warnings = Vec::new();
    if dropped > 0 {
        warnings.push(format!(
            "mount filter {only:?}: {dropped} resource/file/group/policy item(s) cannot be attributed to a mount and were not imported"
        ));
    }
    warnings
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
    import_document_gated(core, document, policy, dry_run, &SqlGate::of(core)).await
}

/// [`import_document`] against an explicit `sql_*` write gate. Policies are
/// written as raw barrier keys, past the policy store's own gate, so one
/// naming `sql_*` refuses the whole import while `gate` is closed (a dry run
/// warns instead), before anything is written.
pub(crate) async fn import_document_gated(
    core: &Arc<Core>,
    document: &ExchangeDocument,
    policy: ConflictPolicy,
    dry_run: bool,
    gate: &SqlGate,
) -> Result<ImportResult, RvError> {
    document.validate_schema_tag().map_err(|_| RvError::ErrRequestInvalid)?;
    let barrier = core.barrier();
    let storage: &dyn Storage = barrier.as_storage();

    let mut result = ImportResult::default();
    let sql_policies = sql_gate::sql_policies_in(document);
    if !sql_policies.is_empty() {
        if dry_run {
            if let Err(reason) = gate.writable_now().await {
                result.warnings.push(sql_gate::import_warning(&sql_policies, &reason));
            }
        } else {
            gate.open_or_reason().await.map_err(|reason| sql_gate::import_refused(&sql_policies, &reason))?;
        }
    }
    let mut warnings: Vec<String> = Vec::new();
    let indexes = all_namespace_indexes(core, &mut warnings).await?;
    result.warnings.append(&mut warnings);

    let root = indexes.iter().find(|n| n.path.is_empty()).ok_or(RvError::ErrUnknown)?;
    scope::apply_items(storage, &root.mounts, &document.items, policy, dry_run, "", &mut result).await?;

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

    // Imported policies were written straight to the barrier, behind the policy
    // store's in-memory LRU. Without a flush, a token whose policy was just
    // overwritten keeps being authorized against the pre-import document until
    // the entry is evicted or the vault is sealed — an authorization decision
    // made on data the operator has already replaced.
    if !dry_run && document_carries_policies(document) {
        if let Some(policy_module) = core.module_manager().get_module::<crate::modules::policy::PolicyModule>("policy")
        {
            policy_module.policy_store.load().flush_caches();
        }
    }

    Ok(result)
}

/// Did this document ask for a policy write anywhere — root namespace or any
/// bundle? Drives the post-import cache flush.
fn document_carries_policies(document: &ExchangeDocument) -> bool {
    !document.items.policies.is_empty() || document.items.namespaces.iter().any(|b| !b.items.policies.is_empty())
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
        ns_req(core, token, Operation::Write, path, ns, json!({ "v": value }).as_object().cloned()).await.unwrap();
    }

    async fn read_secret(core: &Arc<Core>, token: &str, ns: &str, path: &str) -> String {
        ns_req(core, token, Operation::Read, path, ns, None).await.unwrap().unwrap().data.unwrap()["v"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Two tenants holding the *same* mount path with different secrets: the
    /// export must keep them in separate bundles, and the import must put each
    /// back in its own namespace rather than collapsing them into the root.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn all_namespaces_export_round_trips_each_tenant() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_exchange_all_namespaces").await;
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
        let paths: Vec<&str> = doc.items.namespaces.iter().map(|b| b.path.as_str()).collect();
        assert_eq!(paths, vec!["tenant-a", "tenant-b"]);
        let root_values: Vec<String> = doc.items.kv.iter().map(|k| k.value.to_string()).collect();
        assert!(root_values.iter().any(|v| v.contains("from-root")));
        assert!(
            !root_values.iter().any(|v| v.contains("from-a") || v.contains("from-b")),
            "tenant data must not appear in the root namespace's items: {root_values:?}"
        );
        for (bundle, expected) in doc.items.namespaces.iter().zip(["from-a", "from-b"]) {
            let joined: String = bundle.items.kv.iter().map(|k| k.value.to_string()).collect();
            assert!(joined.contains(expected), "bundle {} must carry {expected}, got {joined}", bundle.path);
        }

        // Clobber both tenants, then restore from the document: each bundle
        // must land back in its own namespace.
        put_secret(&core, &root, "tenant-a", "cubby/foo", "clobbered-a").await;
        put_secret(&core, &root, "tenant-b", "cubby/foo", "clobbered-b").await;

        let result = import_document(&core, &doc, ConflictPolicy::Overwrite, false).await.unwrap();
        assert!(result.written > 0);
        assert!(result.warnings.is_empty(), "no namespace should be skipped: {:?}", result.warnings);
        assert_eq!(read_secret(&core, &root, "tenant-a", "cubby/foo").await, "from-a");
        assert_eq!(read_secret(&core, &root, "tenant-b", "cubby/foo").await, "from-b");
        assert_eq!(read_secret(&core, &root, "", "cubby/foo").await, "from-root");
    }

    /// A root-scoped `full` export must NOT reach into tenants — that is what
    /// the `all_namespaces` kind is for. Guards against a future change making
    /// the root index address namespace prefixes.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn full_export_stays_inside_the_root_namespace() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_exchange_full_is_root_only").await;
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
            core.barrier().as_storage(),
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

    /// Policies belong in a backup: a vault whose secrets are restored but whose
    /// ACL policies are not is a vault only root can use. Each namespace's
    /// policies must travel in that namespace's own items, restore into that
    /// namespace's own keyspace, and be served — post-import — from storage
    /// rather than from the policy store's stale LRU entry.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn all_namespaces_export_round_trips_policies() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_exchange_ns_policies").await;
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

        // One policy per namespace, each granting `read`.
        let root_hcl = "path \"secret/*\" { capabilities = [\"read\"] }";
        // A namespace policy must address its own namespace-prefixed paths.
        let tenant_hcl = "path \"tenant-a/cubby/*\" { capabilities = [\"read\"] }";
        for (ns, name, hcl) in [("", "reader", root_hcl), ("tenant-a", "tenant-reader", tenant_hcl)] {
            ns_req(
                &core,
                &root,
                Operation::Write,
                &format!("sys/policy/{name}"),
                ns,
                json!({ "policy": hcl }).as_object().cloned(),
            )
            .await
            .unwrap();
        }

        let doc = export_all_namespaces(
            &core,
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] },
        )
        .await
        .unwrap();

        let root_names: Vec<&str> = doc.items.policies.iter().map(|p| p.name.as_str()).collect();
        assert!(root_names.contains(&"reader"), "root policies: {root_names:?}");
        assert!(
            !root_names.contains(&"tenant-reader"),
            "a tenant's policy must not surface as the root namespace's: {root_names:?}"
        );
        let bundle = doc.items.namespaces.iter().find(|b| b.path == "tenant-a").expect("tenant-a bundle");
        let tenant_names: Vec<&str> = bundle.items.policies.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(tenant_names, vec!["tenant-reader"], "tenant policies");

        // Clobber both policies, then restore from the document. Reading back
        // through the request path exercises the policy store's cache, which
        // the import must have invalidated.
        for (ns, name, clobbered) in [
            ("", "reader", "path \"clobbered/*\" { capabilities = [\"list\"] }"),
            ("tenant-a", "tenant-reader", "path \"tenant-a/clobbered/*\" { capabilities = [\"list\"] }"),
        ] {
            ns_req(
                &core,
                &root,
                Operation::Write,
                &format!("sys/policy/{name}"),
                ns,
                json!({ "policy": clobbered }).as_object().cloned(),
            )
            .await
            .unwrap();
        }

        let result = import_document(&core, &doc, ConflictPolicy::Overwrite, false).await.unwrap();
        assert!(result.written > 0);

        for (ns, name, expected) in [("", "reader", root_hcl), ("tenant-a", "tenant-reader", tenant_hcl)] {
            let resp =
                ns_req(&core, &root, Operation::Read, &format!("sys/policy/{name}"), ns, None).await.unwrap().unwrap();
            let rules = resp.data.unwrap()["rules"].as_str().unwrap().to_string();
            assert_eq!(rules, expected, "policy {name:?} in namespace {ns:?}");
        }
    }

    /// Regression (sql-browser subsystem 4's open gap): an import wrote
    /// policy documents as raw barrier keys, past the `sql_*` write gate.
    /// Closed, a document carrying a `sql_*` policy anywhere refuses the whole
    /// import before the first write and a dry run warns; open, it imports.
    #[tokio::test]
    async fn a_closed_sql_gate_refuses_an_import_that_carries_sql_policies() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_exchange_sql_gate").await;
        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
        ns_req(&core, &root, Operation::Write, "sys/mounts/cubby/", "", json!({ "type": "kv" }).as_object().cloned())
            .await
            .unwrap();
        put_secret(&core, &root, "", "cubby/app", "v1").await;
        let sql_hcl = "path \"tenant-a/resources/resources/db/sql/*\" { capabilities = [\"sql_select\"] }";
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/policy/analysts",
            "tenant-a",
            json!({ "policy": sql_hcl }).as_object().cloned(),
        )
        .await
        .unwrap();
        let doc = export_all_namespaces(
            &core,
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] },
        )
        .await
        .unwrap();
        // The stored `default` names `sql_*` once the gate is open, so every
        // export from an upgraded vault carries one.
        let named = sql_gate::sql_policies_in(&doc);
        assert!(
            named.contains(&"tenant-a/analysts".to_string()) && named.contains(&"default".to_string()),
            "{named:?}"
        );

        // Remove what the import would restore, so a write would show.
        ns_req(&core, &root, Operation::Delete, "sys/policy/analysts", "tenant-a", None).await.unwrap();
        ns_req(&core, &root, Operation::Delete, "cubby/app", "", None).await.unwrap();
        let absent = |ns: &'static str, path: &'static str| {
            let core = core.clone();
            let root = root.clone();
            async move {
                ns_req(&core, &root, Operation::Read, path, ns, None)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|r| r.data)
                    .is_none()
            }
        };

        let closed = SqlGate::Fixed(Err("node 2: no version record".into()));
        let e = import_document_gated(&core, &doc, ConflictPolicy::Overwrite, false, &closed).await.unwrap_err();
        let RvError::ErrResponseStatus(409, m) = e else { panic!("expected a 409") };
        assert!(m.contains("tenant-a/analysts") && m.contains("node 2: no version record"), "{m}");
        assert!(absent("tenant-a", "sys/policy/analysts").await, "the sql_* policy must not be written");
        assert!(absent("", "cubby/app").await, "nothing else may be written either");

        let preview = import_document_gated(&core, &doc, ConflictPolicy::Overwrite, true, &closed).await.unwrap();
        assert!(preview.warnings.iter().any(|w| w.contains("tenant-a/analysts")), "{:?}", preview.warnings);

        let open = SqlGate::Fixed(Ok(()));
        import_document_gated(&core, &doc, ConflictPolicy::Overwrite, false, &open).await.unwrap();
        assert!(!absent("tenant-a", "sys/policy/analysts").await);
        assert_eq!(read_secret(&core, &root, "", "cubby/app").await, "v1");
    }

    /// Three namespaces holding the same mount path with different secrets.
    async fn three_namespace_vault(name: &str) -> (Arc<Core>, String, ExchangeDocument) {
        let (_bvault, core, root) = new_unseal_test_bastion_vault(name).await;
        std::mem::forget(_bvault);
        let store = store_of(&core);
        store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();
        store.create("tenant-b", NamespaceQuotas::default(), false).await.unwrap();
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
        put_secret(&core, &root, "", "cubby/foo", "from-root").await;
        put_secret(&core, &root, "tenant-a", "cubby/foo", "from-a").await;
        put_secret(&core, &root, "tenant-b", "cubby/foo", "from-b").await;
        let doc = export_all_namespaces(
            &core,
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] },
        )
        .await
        .unwrap();
        (core, root, doc)
    }

    /// `export_namespaces` reads only the selected namespaces; `root` and `""`
    /// both name the root, slashes are tolerated, and a typo is a warning.
    #[tokio::test]
    async fn export_can_be_restricted_to_selected_namespaces() {
        let (core, _root, _full) = three_namespace_vault("test_exchange_ns_filter_export").await;
        let scope = || ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] };

        let only_a =
            export_namespaces(&core, ExporterInfo::default(), scope(), &["/tenant-a/".to_string()]).await.unwrap();
        assert_eq!(document_namespaces(&only_a), vec!["tenant-a".to_string()]);
        assert!(only_a.items.kv.is_empty(), "root must not be exported when unselected");

        let root_and_b = export_namespaces(
            &core,
            ExporterInfo::default(),
            scope(),
            &["root".to_string(), "tenant-b".to_string(), "nope".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(document_namespaces(&root_and_b), vec![String::new(), "tenant-b".to_string()]);
        assert!(root_and_b.warnings.iter().any(|w| w.contains("nope")), "{:?}", root_and_b.warnings);

        let everything = export_namespaces(&core, ExporterInfo::default(), scope(), &[]).await.unwrap();
        assert_eq!(document_namespaces(&everything).len(), 3);
    }

    /// Splitting yields one importable document per namespace, a tenant's part
    /// stays a bundle (never hoisted into the root), and importing every part
    /// restores the same state as importing the combined document.
    #[tokio::test]
    async fn split_parts_each_restore_only_their_own_namespace() {
        let (core, root, doc) = three_namespace_vault("test_exchange_ns_split").await;
        let parts = split_by_namespace(&doc);
        let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["", "tenant-a", "tenant-b"]);
        for (ns, part) in &parts {
            assert_eq!(document_namespaces(part), vec![ns.clone()], "part {ns:?} must carry only itself");
            if !ns.is_empty() {
                assert!(part.items.kv.is_empty(), "tenant part must not hoist items to the root level");
            }
        }

        for (ns, v) in [("", "x-root"), ("tenant-a", "x-a"), ("tenant-b", "x-b")] {
            put_secret(&core, &root, ns, "cubby/foo", v).await;
        }
        // Restore only tenant-a's part: the others must stay clobbered.
        let (_, a_part) = parts.iter().find(|(n, _)| n == "tenant-a").unwrap();
        import_document(&core, a_part, ConflictPolicy::Overwrite, false).await.unwrap();
        assert_eq!(read_secret(&core, &root, "tenant-a", "cubby/foo").await, "from-a");
        assert_eq!(read_secret(&core, &root, "tenant-b", "cubby/foo").await, "x-b");
        assert_eq!(read_secret(&core, &root, "", "cubby/foo").await, "x-root");

        for (_, part) in &parts {
            import_document(&core, part, ConflictPolicy::Overwrite, false).await.unwrap();
        }
        assert_eq!(read_secret(&core, &root, "tenant-b", "cubby/foo").await, "from-b");
        assert_eq!(read_secret(&core, &root, "", "cubby/foo").await, "from-root");
    }

    /// `retain_namespaces` narrows a combined document before import, so an
    /// operator can restore one tenant out of a whole-deployment file.
    #[tokio::test]
    async fn import_can_be_restricted_to_selected_namespaces() {
        let (core, root, doc) = three_namespace_vault("test_exchange_ns_filter_import").await;
        for (ns, v) in [("", "x-root"), ("tenant-a", "x-a"), ("tenant-b", "x-b")] {
            put_secret(&core, &root, ns, "cubby/foo", v).await;
        }

        let mut narrowed = doc.clone();
        let warnings = retain_namespaces(&mut narrowed, &["tenant-b".to_string(), "ghost".to_string()]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("ghost"));
        assert_eq!(document_namespaces(&narrowed), vec!["tenant-b".to_string()]);
        assert!(narrowed.items.kv.is_empty(), "root items must be dropped when root is not selected");

        import_document(&core, &narrowed, ConflictPolicy::Overwrite, false).await.unwrap();
        assert_eq!(read_secret(&core, &root, "tenant-b", "cubby/foo").await, "from-b");
        assert_eq!(read_secret(&core, &root, "tenant-a", "cubby/foo").await, "x-a");
        assert_eq!(read_secret(&core, &root, "", "cubby/foo").await, "x-root");

        // Selecting the root keeps its items and drops every bundle.
        let mut root_only = doc.clone();
        assert!(retain_namespaces(&mut root_only, &["".to_string()]).is_empty());
        assert_eq!(document_namespaces(&root_only), vec![String::new()]);

        // An empty selector list is "everything".
        let mut all = doc.clone();
        assert!(retain_namespaces(&mut all, &[]).is_empty());
        assert_eq!(all, doc);
    }

    /// Engine-scoped export: one mount (or one engine type) out of chosen
    /// namespaces, and nothing else — no sibling mount, no policies.
    #[tokio::test]
    async fn engine_scoped_export_and_mount_filtered_import() {
        use crate::exchange::schema::ScopeSelector;
        let (core, root, _full) = three_namespace_vault("test_exchange_engine_scope").await;
        for ns in ["", "tenant-a"] {
            ns_req(
                &core,
                &root,
                Operation::Write,
                "sys/mounts/other/",
                ns,
                json!({ "type": "kv" }).as_object().cloned(),
            )
            .await
            .unwrap();
            put_secret(&core, &root, ns, "other/bar", "other-val").await;
        }
        let sel = |s: ScopeSelector| ScopeSpec { kind: ScopeKind::Selective, include: vec![s] };

        // One mount, two chosen namespaces.
        let doc = export_namespaces(
            &core,
            ExporterInfo::default(),
            sel(ScopeSelector::Mount { mount: "cubby".to_string() }),
            &["tenant-a".to_string(), "tenant-b".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(document_namespaces(&doc), vec!["tenant-a".to_string(), "tenant-b".to_string()]);
        for b in &doc.items.namespaces {
            assert!(b.items.kv.iter().all(|k| k.mount == "cubby/"), "only the selected mount: {:?}", b.items.kv);
            assert!(!b.items.kv.is_empty());
            assert!(b.items.policies.is_empty(), "an engine export must not ship policies");
        }

        // Engine type `kv` with the `*` wildcard reaches every namespace and both mounts.
        let all_kv = export_namespaces(
            &core,
            ExporterInfo::default(),
            sel(ScopeSelector::EngineType { engine: "secrets".to_string() }),
            &["*".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(document_namespaces(&all_kv).len(), 3);
        assert!(all_kv.items.kv.iter().any(|k| k.mount == "other/"));

        // Import only `cubby/` out of the combined document.
        for (ns, v) in [("", "x"), ("tenant-a", "x")] {
            put_secret(&core, &root, ns, "cubby/foo", v).await;
            put_secret(&core, &root, ns, "other/bar", v).await;
        }
        let mut narrowed = all_kv.clone();
        assert!(retain_mounts(&mut narrowed, &["cubby".to_string()]).is_empty());
        import_document(&core, &narrowed, ConflictPolicy::Overwrite, false).await.unwrap();
        assert_eq!(read_secret(&core, &root, "tenant-a", "cubby/foo").await, "from-a");
        assert_eq!(read_secret(&core, &root, "tenant-a", "other/bar").await, "x", "unselected mount untouched");

        // A mount that exists nowhere is reported, not silently empty.
        let none = export_namespaces(
            &core,
            ExporterInfo::default(),
            sel(ScopeSelector::Mount { mount: "pki/".to_string() }),
            &["*".to_string()],
        )
        .await
        .unwrap();
        assert!(none.warnings.iter().any(|w| w.contains("matched no data")), "{:?}", none.warnings);
    }

    /// File blobs of a tenant namespace must survive an engine-scoped export
    /// chosen from the root session, byte for byte.
    #[tokio::test]
    async fn tenant_file_content_is_exported_from_a_root_session() {
        use crate::exchange::schema::ScopeSelector;
        use base64::Engine;
        let (core, root, _full) = three_namespace_vault("test_exchange_ns_files").await;
        store_of(&core).create("tenant-a/child", NamespaceQuotas::default(), false).await.unwrap();
        const NS: &str = "tenant-a/child";
        let payload = vec![0xA5u8; 300_000];
        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/mounts/files/",
            NS,
            json!({ "type": "files" }).as_object().cloned(),
        )
        .await
        .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
        ns_req(
            &core,
            &root,
            Operation::Write,
            "files/files/f1",
            NS,
            json!({ "name": "big.xdb", "content_base64": b64 }).as_object().cloned(),
        )
        .await
        .unwrap();
        for scope in [
            ScopeSpec {
                kind: ScopeKind::Selective,
                include: vec![ScopeSelector::EngineType { engine: "files".into() }],
            },
            ScopeSpec { kind: ScopeKind::Selective, include: vec![ScopeSelector::Mount { mount: "files/".into() }] },
            ScopeSpec { kind: ScopeKind::AllNamespaces, include: vec![] },
        ] {
            let doc = export_namespaces(&core, ExporterInfo::default(), scope, &[NS.to_string()]).await.unwrap();
            let bundle = doc.items.namespaces.iter().find(|b| b.path == NS).expect("tenant-a bundle");
            assert_eq!(bundle.items.files.len(), 1, "warnings: {:?}", doc.warnings);
            let got = base64::engine::general_purpose::STANDARD.decode(&bundle.items.files[0].content_b64).unwrap();
            assert_eq!(got, payload, "blob bytes must be exported");
        }
    }

    /// A bundle naming a namespace this vault does not have is reported, not
    /// silently written into the root namespace.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_skips_bundles_for_unknown_namespaces() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_exchange_unknown_namespace").await;

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
