//! Namespace token binding (Phase 2).
//!
//! Every token records the namespace it was issued in and whether it is
//! *child-visible*. The binding is carried in the token's metadata map (which
//! flows into `Auth.metadata` on lookup), so no token storage-format change is
//! needed and pre-existing tokens deserialize as root-bound, non-child-visible
//! — the safe default.
//!
//! ## Usage rules (enforced by [`token_may_operate`])
//!
//! A token bound to namespace `T` may be used:
//! - in `T` itself — always;
//! - in a **descendant** of `T` — only if `child_visible == true` (lets a
//!   parent admin operate inside a child without a separate login);
//! - in a **parent**, **sibling**, or unrelated namespace — never.
//!
//! `child_visible` is opt-in at create time and immutable.

use std::collections::HashMap;

use crate::errors::RvError;

/// Metadata key holding the token's issuing-namespace path (canonical, no
/// trailing slash; `""` = root). Absent ⇒ root.
pub const NS_PATH_META: &str = "namespace_path";
/// Metadata key holding the token's issuing-namespace UUID. Informational;
/// enforcement keys off the path so descendant checks are cheap.
pub const NS_ID_META: &str = "namespace_id";
/// Metadata key holding the child-visible flag (`"true"`/`"false"`).
pub const CHILD_VISIBLE_META: &str = "child_visible";

/// True if `descendant` is a strict descendant of `ancestor` in the namespace
/// tree. The root (`""`) is an ancestor of every non-root namespace.
pub fn is_descendant(descendant: &str, ancestor: &str) -> bool {
    if descendant == ancestor {
        return false;
    }
    if ancestor.is_empty() {
        return !descendant.is_empty();
    }
    descendant.starts_with(&format!("{ancestor}/"))
}

/// Core token-binding decision. `token_ns_path` is the namespace the token was
/// issued in; `request_ns_path` is the namespace the request targets.
pub fn token_may_operate(token_ns_path: &str, child_visible: bool, request_ns_path: &str) -> bool {
    if token_ns_path == request_ns_path {
        return true; // same namespace — always allowed
    }
    // Child namespace, only with the opt-in flag.
    child_visible && is_descendant(request_ns_path, token_ns_path)
}

/// Extract `(namespace_path, child_visible)` from a token/auth metadata map.
/// Defaults to root + not-child-visible when the keys are absent (legacy
/// tokens), which preserves pre-namespace behaviour.
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

/// Resolve the namespace an auth-backend login targets, from the request's
/// `X-BastionVault-Namespace` header. Returns `(path, uuid)` — root is
/// `("", "")`. Fails closed: a header naming a namespace that does not exist
/// (or set while namespaces are unavailable) is a hard error, so a login can
/// never silently fall back to root when the caller asked for a tenant.
///
/// Used by auth backends to bind the issued token to the login namespace and to
/// scope entity/group resolution. Login paths are not namespace-rewritten, so
/// the header is read directly here.
#[maybe_async::maybe_async]
pub async fn resolve_login_namespace(
    core: &crate::core::Core,
    req: &crate::logical::Request,
) -> Result<(String, String), crate::errors::RvError> {
    use super::{router::namespace_header_from_map, NamespaceModule, NAMESPACE_MODULE_NAME};

    let raw = namespace_header_from_map(req.headers.as_ref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(raw) = raw else {
        return Ok((String::new(), String::new()));
    };

    let module = core
        .module_manager
        .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
        .ok_or_else(|| {
            crate::bv_error_string!("namespace header set but the namespace module is unavailable")
        })?;
    let store = module
        .store()
        .ok_or_else(|| crate::bv_error_string!("namespace store not initialized"))?;
    let ns = store.get_by_path(&raw).await?.ok_or_else(|| {
        let p = super::store::normalize_path(&raw).unwrap_or(raw);
        crate::bv_error_response_status!(404, &format!("no such namespace: {p:?}"))
    })?;
    Ok((ns.path, ns.uuid))
}

/// Enforce token namespace binding for a routed request. Called after the
/// pre-route auth phase (so `req.auth` is populated) and before dispatch. A
/// request whose token may not operate in the target namespace is rejected
/// with `permission_denied` before any backend sees it.
///
/// `sys/` and `auth/` paths are root-scoped in the current phase and skipped.
/// Legacy/root-bound tokens operating at root are always allowed, so this is a
/// no-op for non-multi-tenant deployments.
#[maybe_async::maybe_async]
pub async fn enforce_request_token_binding(
    core: &crate::core::Core,
    req: &crate::logical::Request,
) -> Result<(), crate::errors::RvError> {
    use super::{NamespaceModule, NAMESPACE_MODULE_NAME};

    if req.path.starts_with("sys/") || req.path.starts_with("auth/") {
        return Ok(());
    }
    let Some(auth) = req.auth.as_ref() else {
        return Ok(());
    };
    // Root is superuser and operates in every namespace.
    if auth.policies.iter().any(|p| p == "root") {
        return Ok(());
    }
    let (token_ns_path, child_visible) = binding_from_metadata(&auth.metadata);

    let Some(module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
    else {
        return Ok(());
    };
    let Some(store) = module.store() else {
        return Ok(());
    };

    // The request path has already been normalised to its namespaced form by
    // `router::rewrite_request_for_namespace`, so resolve the target namespace
    // directly from it.
    let resolved = store.resolve_request(None, &req.path).await?;
    if token_may_operate(&token_ns_path, child_visible, &resolved.namespace.path) {
        Ok(())
    } else {
        Err(crate::errors::RvError::ErrPermissionDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_descendant() {
        assert!(is_descendant("engineering", "")); // root is ancestor of all
        assert!(is_descendant("engineering/platform", "engineering"));
        assert!(is_descendant("a/b/c", "a"));
        assert!(!is_descendant("engineering", "engineering")); // strict
        assert!(!is_descendant("", "")); // root is not its own descendant
        assert!(!is_descendant("marketing", "engineering")); // sibling
        assert!(!is_descendant("engineering", "engineering/platform")); // parent
        // Prefix that is not a path-segment boundary must not count.
        assert!(!is_descendant("engineering-x", "engineering"));
    }

    #[test]
    fn test_token_may_operate() {
        // Same namespace always allowed.
        assert!(token_may_operate("engineering", false, "engineering"));
        assert!(token_may_operate("", false, "")); // root token at root
        // Child only with child_visible.
        assert!(token_may_operate("engineering", true, "engineering/platform"));
        assert!(!token_may_operate("engineering", false, "engineering/platform"));
        // Child-visible root token can reach any child.
        assert!(token_may_operate("", true, "tenant-a"));
        assert!(!token_may_operate("", false, "tenant-a"));
        // Parent and sibling never.
        assert!(!token_may_operate("engineering/platform", true, "engineering"));
        assert!(!token_may_operate("tenant-a", true, "tenant-b"));
    }

    #[test]
    fn test_metadata_roundtrip() {
        let mut m = HashMap::new();
        stamp_binding(&mut m, "engineering", "uuid-1", true);
        let (path, cv) = binding_from_metadata(&m);
        assert_eq!(path, "engineering");
        assert!(cv);
        // Legacy token (no keys) → root, not child-visible.
        let (path, cv) = binding_from_metadata(&HashMap::new());
        assert_eq!(path, "");
        assert!(!cv);
    }
}
