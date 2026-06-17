//! Request → namespace resolution.
//!
//! Two equivalent addressing forms are supported, mirroring Vault Enterprise:
//!
//! 1. **Header** — `X-BastionVault-Namespace: engineering/platform`. The
//!    request path (`secret/foo`) is left untouched; it is the mount-relative
//!    path *within* the named namespace.
//! 2. **Path prefix** — `engineering/platform/secret/foo` with no header. The
//!    resolver peels the longest leading path segments that name an existing
//!    namespace, and the remainder (`secret/foo`) becomes the mount path.
//!
//! A request that supplies neither form targets the root namespace. When both
//! are supplied the header wins and the path is treated as mount-relative —
//! mixing the two (a path prefix *and* a header) is refused to avoid an
//! ambiguous double-scoping.

use std::sync::Arc;

use crate::{bv_error_string, core::Core, errors::RvError, logical::Request};

use super::store::{normalize_path, Namespace, NamespaceStore};
use super::{NamespaceModule, NAMESPACE_MODULE_NAME};

/// Canonical header name carrying the target namespace path.
pub const NAMESPACE_HEADER: &str = "x-bastionvault-namespace";

/// Outcome of resolving a request to a namespace.
pub struct ResolvedNamespace {
    pub namespace: Namespace,
    /// Mount-relative path within the namespace (the leading namespace path
    /// segments, if any, have been stripped).
    pub mount_path: String,
}

#[maybe_async::maybe_async]
impl NamespaceStore {
    /// Resolve `(header, request_path)` to a namespace and the mount-relative
    /// path. `header` is the value of `X-BastionVault-Namespace` if present.
    ///
    /// Errors with a 404-style error when a header names a namespace that does
    /// not exist; an unmatched path prefix is *not* an error (it simply means
    /// the whole path is mount-relative to the root namespace).
    pub async fn resolve_request(
        &self,
        header: Option<&str>,
        request_path: &str,
    ) -> Result<ResolvedNamespace, RvError> {
        if let Some(raw) = header {
            let raw = raw.trim();
            if !raw.is_empty() {
                // A header plus an in-path namespace prefix would double-scope
                // the request; refuse rather than silently pick one.
                let ns = self.get_by_path(raw).await?.ok_or_else(|| {
                    let p = normalize_path(raw).unwrap_or_else(|_| raw.to_string());
                    crate::bv_error_response_status!(404, &format!("no such namespace: {p:?}"))
                })?;
                return Ok(ResolvedNamespace { namespace: ns, mount_path: request_path.to_string() });
            }
        }

        // No header: peel the longest leading namespace path from request_path.
        let trimmed = request_path.trim_start_matches('/');
        let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();

        // Try the longest prefix first; a namespace path can be multiple
        // segments deep. We stop before consuming the final segment so that a
        // bare `secret/foo` is never mistaken for a namespace named `secret`.
        for i in (1..segments.len()).rev() {
            let candidate = segments[..i].join("/");
            if let Some(ns) = self.get_by_path(&candidate).await? {
                if ns.is_root() {
                    continue;
                }
                let mount_path = segments[i..].join("/");
                return Ok(ResolvedNamespace { namespace: ns, mount_path });
            }
        }

        // Fall through to the root namespace; whole path is mount-relative.
        let root_uuid = self.root_uuid()?;
        let root = self
            .get_by_uuid(&root_uuid)
            .await?
            .ok_or_else(|| bv_error_string!("root namespace missing from registry"))?;
        Ok(ResolvedNamespace { namespace: root, mount_path: request_path.to_string() })
    }
}

/// Extract the namespace header value from a request's header map, if present.
/// Header lookup is case-insensitive (HTTP header names are).
pub fn namespace_header_from_map(
    headers: Option<&std::collections::HashMap<String, String>>,
) -> Option<String> {
    let headers = headers?;
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(NAMESPACE_HEADER))
        .map(|(_, v)| v.clone())
}

/// Compute the barrier-storage prefix for a namespace's logical mounts:
/// `namespaces/<uuid>/logical/`. The root namespace's data is re-rooted to
/// `namespaces/<root_uuid>/logical/` by the migration; child namespaces use
/// the same shape from creation.
pub fn namespace_logical_prefix(uuid: &str) -> String {
    format!("namespaces/{uuid}/logical/")
}

/// Barrier-storage prefix for a namespace's system view:
/// `namespaces/<uuid>/sys/`.
pub fn namespace_system_prefix(uuid: &str) -> String {
    format!("namespaces/{uuid}/sys/")
}

/// Barrier-storage key for a namespace's mount-table config:
/// `namespaces/<uuid>/core/mounts`.
pub fn namespace_mount_config_path(uuid: &str) -> String {
    format!("namespaces/{uuid}/core/mounts")
}

/// Wrap a resolved namespace in an `Arc` for cheap propagation through the
/// request pipeline.
pub fn arc_namespace(ns: Namespace) -> Arc<Namespace> {
    Arc::new(ns)
}

/// Normalise a request's namespace into a single addressing form before
/// routing. When `X-BastionVault-Namespace` names a non-root namespace, the
/// request path is rewritten to `<ns_path>/<path>` so the shared router (which
/// registers a namespace's mounts under `<ns_path>/...`) dispatches uniformly
/// for both the header form and the path-prefix form. Called at the very top
/// of [`Core::handle_request`].
///
/// Cheap no-op when no namespace header is present (the common case) or when
/// it names the root namespace.
///
/// **Phase 1 limitation:** the header scopes *logical mount* access only;
/// `sys/` and `auth/` paths stay root-scoped (per-namespace sys/auth is
/// Phase 2), so they are left unrewritten.
#[maybe_async::maybe_async]
pub async fn rewrite_request_for_namespace(core: &Core, req: &mut Request) -> Result<(), RvError> {
    let Some(raw) = namespace_header_from_map(req.headers.as_ref()) else {
        return Ok(());
    };
    let raw = raw.trim().to_string();
    if raw.is_empty() {
        return Ok(());
    }
    let ns_path = normalize_path(&raw)?;
    if ns_path.is_empty() {
        return Ok(());
    }

    // Deployment-level backends are addressed at the root mount and scope
    // themselves by the namespace *header* (not by path rewriting): `sys/`
    // (incl. policy + audit + namespace CRUD), `auth/` logins, and the
    // `identity/` backend (per-namespace entities/groups via the header). Their
    // handlers read the header directly, so leave the path untouched — rewriting
    // would misroute them into the namespace's logical mount table.
    if req.path.starts_with("sys/")
        || req.path.starts_with("auth/")
        || req.path.starts_with("identity/")
    {
        return Ok(());
    }

    let Some(module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME) else {
        return Ok(());
    };
    let Some(store) = module.store() else {
        return Ok(());
    };

    let ns = store.get_by_path(&ns_path).await?.ok_or_else(|| {
        crate::bv_error_response_status!(404, &format!("no such namespace: {ns_path:?}"))
    })?;
    if ns.is_root() {
        return Ok(());
    }

    // Make sure the namespace's mounts are wired into the shared router before
    // we route into them.
    if let Some(core_arc) = core.self_ptr.upgrade() {
        module.registry.ensure_router(&core_arc, &ns.uuid, &ns.path).await?;
    }

    let prefix = format!("{}/", ns.path);
    if !req.path.starts_with(&prefix) {
        req.path = format!("{prefix}{}", req.path);
    }
    Ok(())
}
