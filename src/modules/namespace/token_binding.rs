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

/// Decide whether an already-authenticated `auth` may operate in the namespace
/// `request_ns_path`. Encapsulates the two exemptions the request-time enforcer
/// applies so other call sites (e.g. `sys/capabilities-self`, which is a `sys/`
/// path and therefore skipped by [`enforce_request_token_binding`]) reach the
/// exact same verdict instead of re-deriving it:
/// - a `root`-policy token operates in every namespace;
/// - otherwise the token's stored binding governs via [`token_may_operate`].
pub fn token_operable(auth: &crate::logical::Auth, request_ns_path: &str) -> bool {
    if auth.policies.iter().any(|p| p == "root") {
        return true;
    }
    let (token_ns_path, child_visible) = binding_from_metadata(&auth.metadata);
    token_may_operate(&token_ns_path, child_visible, request_ns_path)
}

/// Metadata key holding the auth mount a token was minted by (`"userpass/"`,
/// `"approle/"`, …). Stamped by every login backend; mirrored here so the
/// request-time assignment lookup keys off the exact same `(mount, name)` the
/// login handed to [`super::ns_assignment::enforce_login_assignment`].
pub const MOUNT_PATH_META: &str = "mount_path";

/// Recover the `(mount, principal_name)` an assignment record is keyed by from a
/// token's metadata. `userpass`/FIDO2 stamp the principal under `username`;
/// `approle` stamps it under `role_name`; both stamp the mount under
/// [`MOUNT_PATH_META`]. `None` when the token lacks these keys (a legacy or
/// non-principal token), in which case the caller keeps the strict binding
/// verdict rather than widening access.
fn assignment_principal(meta: &HashMap<String, String>) -> Option<(String, String)> {
    let mount = meta.get(MOUNT_PATH_META)?.clone();
    let name = meta.get("username").or_else(|| meta.get("role_name"))?.clone();
    Some((mount, name))
}

/// Request-time operability verdict that also honors the principal's
/// operator-authored **namespace assignment**.
///
/// The pure [`token_operable`] verdict (root bypass, same-namespace, or a
/// child-visible token reaching a descendant) is evaluated first — it needs no
/// storage, so the common case stays a cheap in-memory check. Only when that
/// denies do we consult the principal's assignment record: an admin
/// **explicitly assigned** a namespace (or an ancestor of it) may operate there
/// from any session, so the assignment governs *authorization*, not merely
/// where the credential may authenticate.
///
/// This widens access **only on an explicit record**. The login-time
/// "no record ⇒ unrestricted" convenience is deliberately NOT applied here: a
/// token with no assignment keeps the strict binding verdict, so an absent
/// record can never promote a bound token into a cross-tenant superuser. The
/// lookup is **live** (not a login-time snapshot), so granting or revoking an
/// assignment takes effect on the next request without re-minting the token,
/// and it **fails closed** on any store error.
#[maybe_async::maybe_async]
pub async fn token_operable_resolved(
    core: &crate::core::Core,
    auth: &crate::logical::Auth,
    request_ns_path: &str,
) -> bool {
    if token_operable(auth, request_ns_path) {
        return true;
    }
    let Some((mount, name)) = assignment_principal(&auth.metadata) else {
        return false;
    };
    let Ok(store) = super::ns_assignment::NsAssignmentStore::new(core) else {
        return false;
    };
    match store.get(&mount, &name).await {
        Ok(Some(assignment)) => {
            super::ns_assignment::namespace_allowed(&assignment.namespaces, request_ns_path)
        }
        // No record (unrestricted for *login*) or a read error: no explicit
        // cross-namespace grant, so keep the strict binding verdict.
        _ => false,
    }
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
    if token_operable_resolved(core, auth, &resolved.namespace.path).await {
        Ok(())
    } else {
        Err(crate::errors::RvError::ErrPermissionDenied)
    }
}

/// The `child_visible` value a token minted at login in `ns_path` should carry:
/// the login namespace's stored `child_visible_default` flag. Fails safe to
/// `false` when the namespace module/store is unavailable or the record can't
/// be read, so a lookup hiccup never silently *widens* a token's reach. Handles
/// the root namespace (`""`) transparently — it has a stored record too (minted
/// by `NamespaceStore::ensure_root`).
#[maybe_async::maybe_async]
pub async fn login_child_visible(core: &crate::core::Core, ns_path: &str) -> bool {
    use super::{NamespaceModule, NAMESPACE_MODULE_NAME};

    let Some(module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
    else {
        return false;
    };
    let Some(store) = module.store() else {
        return false;
    };
    store
        .get_by_path(ns_path)
        .await
        .ok()
        .flatten()
        .map(|ns| ns.child_visible_default)
        .unwrap_or(false)
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
    fn test_token_operable() {
        use crate::logical::Auth;

        // A root-policy token operates in every namespace, regardless of its
        // stored binding (mirrors the request-time enforcer's exemption).
        let mut root = Auth { policies: vec!["root".into()], ..Default::default() };
        stamp_binding(&mut root.metadata, "engineering", "u1", false);
        assert!(token_operable(&root, "engineering"));
        assert!(token_operable(&root, "marketing"));
        assert!(token_operable(&root, ""));

        // A non-root token bound to `engineering`, not child-visible: itself
        // yes, descendants/siblings/root no.
        let mut eng = Auth { policies: vec!["eng-admin".into()], ..Default::default() };
        stamp_binding(&mut eng.metadata, "engineering", "u2", false);
        assert!(token_operable(&eng, "engineering"));
        assert!(!token_operable(&eng, "engineering/platform"));
        assert!(!token_operable(&eng, "marketing"));
        assert!(!token_operable(&eng, ""));

        // Same token, child-visible: descendants become operable, siblings/
        // parent still not.
        let mut engcv = Auth { policies: vec!["eng-admin".into()], ..Default::default() };
        stamp_binding(&mut engcv.metadata, "engineering", "u3", true);
        assert!(token_operable(&engcv, "engineering/platform"));
        assert!(!token_operable(&engcv, "marketing"));

        // The concrete GUI bug: a non-root token bound to root, not
        // child-visible, is denied in every child namespace.
        let mut rootbound = Auth { policies: vec!["felipe".into()], ..Default::default() };
        stamp_binding(&mut rootbound.metadata, "", "u4", false);
        assert!(token_operable(&rootbound, ""));
        assert!(!token_operable(&rootbound, "dti"));
        assert!(!token_operable(&rootbound, "dti/esi"));

        // A child-visible root-bound admin token reaches every descendant.
        let mut rootcv = Auth { policies: vec!["felipe".into()], ..Default::default() };
        stamp_binding(&mut rootcv.metadata, "", "u5", true);
        assert!(token_operable(&rootcv, "dti"));
        assert!(token_operable(&rootcv, "dti/esi"));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_operable_resolved_honors_assignment() {
        use crate::logical::Auth;
        use crate::modules::namespace::ns_assignment::NsAssignmentStore;
        use crate::modules::namespace::store::NamespaceQuotas;
        use crate::modules::namespace::{NamespaceModule, NAMESPACE_MODULE_NAME};
        use crate::test_utils::new_unseal_test_bastion_vault;

        let (_bvault, core, _root) =
            new_unseal_test_bastion_vault("test_token_operable_resolved").await;
        let ns_store = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        ns_store.create("dti", NamespaceQuotas::default(), false).await.unwrap();
        ns_store.create("dti/esi", NamespaceQuotas::default(), false).await.unwrap();

        // A root-bound, non-child-visible userpass admin — exactly felipe's
        // session. Metadata mirrors what the login backend stamps.
        let mut felipe = Auth { policies: vec!["administrator".into()], ..Default::default() };
        stamp_binding(&mut felipe.metadata, "", "root-uuid", false);
        felipe.metadata.insert(MOUNT_PATH_META.into(), "userpass/".into());
        felipe.metadata.insert("username".into(), "felipe".into());

        // No assignment record yet: binding alone governs. Root-bound ⇒ operable
        // at root itself, but NOT in any descendant (absence must never widen a
        // bound token).
        assert!(token_operable_resolved(&core, &felipe, "").await);
        assert!(!token_operable_resolved(&core, &felipe, "dti").await);
        assert!(!token_operable_resolved(&core, &felipe, "dti/esi").await);

        // Assign felipe → dti/esi. Now the descendant is operable, but a
        // non-assigned sibling/parent stays denied.
        let store = NsAssignmentStore::new(&core).unwrap();
        store
            .set(&ns_store, "userpass/", "felipe", vec!["dti/esi".into()])
            .await
            .unwrap()
            .unwrap();
        assert!(token_operable_resolved(&core, &felipe, "dti/esi").await);
        assert!(token_operable_resolved(&core, &felipe, "dti/esi/sub").await);
        // `dti` is the *parent* of the assigned namespace, not covered.
        assert!(!token_operable_resolved(&core, &felipe, "dti").await);

        // A principal with no identifying metadata never widens.
        let mut anon = Auth { policies: vec!["administrator".into()], ..Default::default() };
        stamp_binding(&mut anon.metadata, "", "root-uuid", false);
        assert!(!token_operable_resolved(&core, &anon, "dti/esi").await);
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
