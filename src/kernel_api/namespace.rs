//! Namespaces, as an engine sees them.
//!
//! Two kinds of thing live here, and the split is the point.
//!
//! **Pure helpers** — reading the namespace header off a request, validating
//! and normalising a namespace path, stamping a namespace binding into token
//! metadata and reading it back. These touch no store and no kernel state, so
//! they are plain functions, and they moved here from
//! `modules::namespace::{router, store, token_binding, policy_scope}` rather
//! than becoming trait methods. Each is re-exported from its old home, so no
//! call site outside those files changed.
//!
//! That also retires a cross-layer wart the decomposition roadmap tracked
//! separately: `src/audit/entry.rs` reached into `crate::modules` for exactly
//! one constant, [`NS_PATH_META`].
//!
//! **[`NamespaceRegistry`]** — everything that needs the namespace store: path
//! resolution, the login-time namespace binding, per-namespace mount routers,
//! assignment and quota enforcement.
//!
//! The trait's methods take no context parameter. The registry is the
//! namespace module, which already holds the kernel handle it needs; making
//! callers thread one through was the old shape and it only existed because
//! these were free functions reaching for `get_module`.

use std::{collections::HashMap, sync::Arc};

use crate::{bv_error_string, errors::RvError, logical::Request, mount::MountsRouter};

use super::VaultCtx;

/// Request header naming the namespace a call targets. Lowercase; callers
/// compare case-insensitively.
pub const NAMESPACE_HEADER: &str = "x-bastionvault-namespace";

/// Token metadata key holding the namespace path the token is bound to.
pub const NS_PATH_META: &str = "namespace_path";

/// Token metadata key holding the namespace uuid the token is bound to.
pub const NS_ID_META: &str = "namespace_id";

/// Token metadata key: may this token see into child namespaces?
pub const CHILD_VISIBLE_META: &str = "child_visible";

/// The namespace header value on a request, if present. Case-insensitive.
pub fn namespace_header_from_map(headers: Option<&HashMap<String, String>>) -> Option<String> {
    let headers = headers?;
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(NAMESPACE_HEADER))
        .map(|(_, v)| v.clone())
}

/// Barrier-storage prefix for a namespace's logical mounts.
pub fn namespace_logical_prefix(uuid: &str) -> String {
    format!("namespaces/{uuid}/logical/")
}

/// Read a token's namespace binding back out of its metadata:
/// `(namespace_path, child_visible)`. Absent keys read as root, not visible.
pub fn binding_from_metadata(meta: &HashMap<String, String>) -> (String, bool) {
    let ns_path = meta.get(NS_PATH_META).cloned().unwrap_or_default();
    let child_visible = meta.get(CHILD_VISIBLE_META).map(|v| v == "true").unwrap_or(false);
    (ns_path, child_visible)
}

/// Stamp a namespace binding into a token metadata map at create time.
pub fn stamp_binding(
    meta: &mut HashMap<String, String>,
    ns_path: &str,
    ns_uuid: &str,
    child_visible: bool,
) {
    meta.insert(NS_PATH_META.to_string(), ns_path.to_string());
    meta.insert(NS_ID_META.to_string(), ns_uuid.to_string());
    meta.insert(CHILD_VISIBLE_META.to_string(), child_visible.to_string());
}

/// Validate a single namespace path segment. Rejects empty segments and any
/// segment containing a path separator, parent-traversal, or wildcard. These
/// are the characters that would let a namespace name escape its registry key
/// or alias another namespace's storage prefix.
pub fn validate_segment(segment: &str) -> Result<(), RvError> {
    if segment.is_empty() {
        return Err(bv_error_string!("namespace segment must not be empty"));
    }
    if segment.contains('/') || segment.contains("..") || segment.contains('*') {
        return Err(bv_error_string!(format!(
            "invalid namespace segment {segment:?}: must not contain '/', '..', or '*'"
        )));
    }
    // Defense in depth: the segment becomes part of a storage key, so refuse
    // control characters and leading/trailing whitespace that could confuse
    // path comparisons.
    if segment.trim() != segment || segment.chars().any(|c| c.is_control()) {
        return Err(bv_error_string!(format!(
            "invalid namespace segment {segment:?}: surrounding whitespace or control characters"
        )));
    }
    Ok(())
}

/// Normalize a caller-supplied namespace path: strip surrounding slashes and
/// whitespace, reject empties, and validate every segment. Returns the
/// canonical form (no leading/trailing slash). The empty string maps to the
/// root namespace.
pub fn normalize_path(raw: &str) -> Result<String, RvError> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let mut segments = Vec::new();
    for seg in trimmed.split('/') {
        validate_segment(seg)?;
        segments.push(seg);
    }
    Ok(segments.join("/"))
}

/// The namespace a *write* from this request is scoped to, from the header
/// alone. Empty means root.
///
/// An unparseable header reads as root rather than erroring: the write itself
/// is authorized separately, and a malformed header must not be a way to write
/// somewhere unexpected.
pub fn writer_namespace_path(headers: Option<&HashMap<String, String>>) -> String {
    namespace_header_from_map(headers).and_then(|h| normalize_path(&h).ok()).unwrap_or_default()
}

/// A resolved namespace: enough to key storage and build a mount prefix,
/// nothing more.
///
/// Not the stored `Namespace` record — that carries the parent link, quotas,
/// timestamps and the storage shape, all of which belong to the namespace
/// module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceRef {
    pub uuid: String,
    /// Canonical path with no leading or trailing slash. Empty for root.
    pub path: String,
}

impl NamespaceRef {
    pub fn is_root(&self) -> bool {
        self.path.is_empty()
    }

    /// The request-path prefix for this namespace: `""` for root, else
    /// `"<path>/"`.
    pub fn request_prefix(&self) -> String {
        if self.is_root() {
            String::new()
        } else {
            format!("{}/", self.path.trim_end_matches('/'))
        }
    }
}

/// Namespace resolution and the login-time namespace binding.
#[maybe_async::maybe_async]
pub trait NamespaceRegistry: Send + Sync {
    /// Resolve a raw (possibly un-normalised) namespace path. `Ok(None)` means
    /// no such namespace — which is a real answer, not an error: a caller
    /// naming an unknown namespace owns nothing in it.
    async fn resolve(&self, raw: &str) -> Result<Option<NamespaceRef>, RvError>;

    /// Ensure the namespace's own mount router exists and is wired, returning
    /// it.
    ///
    /// Header-scoped mounts (`rustion/`, `sys/`) are dispatched without the
    /// request pipeline having rewritten the path, so the namespace's mounts
    /// are not in the shared router trie yet. This is what puts them there.
    async fn ensure_router(&self, uuid: &str, path: &str) -> Result<Arc<MountsRouter>, RvError>;

    /// The namespace a login on `mount`/`name` lands in, as `(path, uuid)`.
    ///
    /// An explicit namespace header wins. Otherwise the principal's own
    /// assignment decides, so a tenant user logging in with no header still
    /// gets a token bound to their namespace rather than to root.
    async fn resolve_login_namespace_for_principal(
        &self,
        req: &Request,
        mount: &str,
        name: &str,
    ) -> Result<(String, String), RvError>;

    /// Refuse a login whose principal is not assigned to `ns_path`.
    async fn enforce_login_assignment(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<(), RvError>;

    /// Refuse an entity creation that would exceed the namespace's quota.
    async fn check_entity_create(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<(), RvError>;

    /// Whether tokens bound to `ns_path` may see into child namespaces.
    async fn login_child_visible(&self, ns_path: &str) -> bool;

    /// The namespace owning `req_path` and its `max_leases` quota.
    ///
    /// `None` for root — root has no lease cap — and for a path that resolves
    /// to no namespace. `req_path` must already be in its namespace-normalised
    /// form, which the request pipeline guarantees.
    ///
    /// On the trait rather than resolved by the caller because the lease
    /// manager is the one asking, and it holds only a `Weak<dyn VaultCtx>`:
    /// giving it the namespace store would hand the lease subsystem the whole
    /// tenancy registry to satisfy one integer.
    async fn lease_quota_for_path(
        &self,
        req_path: &str,
    ) -> Result<Option<(String, u64)>, RvError>;
}

// ── Login-path helpers ─────────────────────────────────────────────────
//
// Four one-liners over [`NamespaceRegistry`], and they exist for one reason:
// the "no namespace module at all" arm is not the same answer for all four,
// and every auth backend was open-coding it. Getting one of them wrong is a
// tenancy bug, so they are written down once.

/// The namespace a login on `mount`/`name` binds to, as `(path, uuid)`.
///
/// **Fails closed.** A request that names a namespace while the namespace
/// module is unavailable is an error, not a silent fall back to root: a caller
/// that asked for a tenant must never be handed a root-bound token. A request
/// that names none binds to root (or, via the registry, to the principal's own
/// assigned namespace).
#[maybe_async::maybe_async]
pub async fn login_namespace_for_principal(
    ctx: &dyn VaultCtx,
    req: &Request,
    mount: &str,
    name: &str,
) -> Result<(String, String), RvError> {
    let Some(registry) = ctx.namespaces() else {
        let named = namespace_header_from_map(req.headers.as_ref())
            .map(|s| s.trim().to_string())
            .is_some_and(|s| !s.is_empty());
        if named {
            return Err(crate::bv_error_string!(
                "namespace header set but the namespace module is unavailable"
            ));
        }
        return Ok((String::new(), String::new()));
    };
    registry.resolve_login_namespace_for_principal(req, mount, name).await
}

/// Refuse a login whose principal is not assigned to `ns_path`.
///
/// No namespace module means no assignments to enforce, so this passes — the
/// deployment is single-tenant and `ns_path` can only be root.
#[maybe_async::maybe_async]
pub async fn enforce_login_assignment(
    ctx: &dyn VaultCtx,
    mount: &str,
    name: &str,
    ns_path: &str,
) -> Result<(), RvError> {
    let Some(registry) = ctx.namespaces() else {
        return Ok(());
    };
    registry.enforce_login_assignment(mount, name, ns_path).await
}

/// Refuse an entity creation that would exceed the namespace's quota.
///
/// No namespace module means no quotas; passes.
#[maybe_async::maybe_async]
pub async fn check_entity_create(
    ctx: &dyn VaultCtx,
    mount: &str,
    name: &str,
    ns_path: &str,
) -> Result<(), RvError> {
    let Some(registry) = ctx.namespaces() else {
        return Ok(());
    };
    registry.check_entity_create(mount, name, ns_path).await
}

/// Whether a token minted in `ns_path` may see into child namespaces.
///
/// **Fails safe to `false`.** A lookup that cannot run must never *widen* a
/// token's reach, so an absent module, an unreadable record and "the flag is
/// off" all give the same answer.
#[maybe_async::maybe_async]
pub async fn login_child_visible(ctx: &dyn VaultCtx, ns_path: &str) -> bool {
    let Some(registry) = ctx.namespaces() else {
        return false;
    };
    registry.login_child_visible(ns_path).await
}

/// The caller's namespace as a canonical path (`""` = root).
///
/// Prefers the `namespace_path` the request pipeline stamped, falling back to
/// the raw header for callers that dispatch straight into a backend (tests,
/// in-process embedded callers). An unresolvable namespace reads as root,
/// matching the router's own best-effort behaviour.
#[maybe_async::maybe_async]
pub async fn caller_namespace(ctx: &dyn VaultCtx, req: &Request) -> Result<String, RvError> {
    let Some(ns) = resolve_caller_namespace(ctx, req).await? else {
        return Ok(String::new());
    };
    Ok(ns.path)
}

/// As [`caller_namespace`], but also ensures the namespace's mount router is
/// wired, and returns a request *prefix* (`""` or `"<path>/"`).
///
/// For header-scoped mounts, which the request pipeline does not rewrite.
#[maybe_async::maybe_async]
pub async fn caller_namespace_prefix(ctx: &dyn VaultCtx, req: &Request) -> Result<String, RvError> {
    let Some(ns) = resolve_caller_namespace(ctx, req).await? else {
        return Ok(String::new());
    };
    if ns.is_root() {
        return Ok(String::new());
    }
    let Some(registry) = ctx.namespaces() else {
        return Ok(String::new());
    };
    registry.ensure_router(&ns.uuid, &ns.path).await?;
    Ok(ns.request_prefix())
}

/// Shared front half: header → resolved namespace. `None` when the request
/// names no namespace, names an unknown one, or names root.
#[maybe_async::maybe_async]
async fn resolve_caller_namespace(
    ctx: &dyn VaultCtx,
    req: &Request,
) -> Result<Option<NamespaceRef>, RvError> {
    let raw = req
        .namespace_path
        .clone()
        .or_else(|| namespace_header_from_map(req.headers.as_ref()))
        .unwrap_or_default();
    let raw = raw.trim().to_string();
    if raw.is_empty() {
        return Ok(None);
    }
    let Some(registry) = ctx.namespaces() else {
        return Ok(None);
    };
    let Some(ns) = registry.resolve(&raw).await? else {
        return Ok(None);
    };
    if ns.is_root() {
        return Ok(None);
    }
    Ok(Some(ns))
}
