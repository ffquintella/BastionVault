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

/// Token metadata keys carrying a token's namespace binding: the issuing
/// namespace path (canonical, no trailing slash; `""` = root; absent ⇒ root),
/// its UUID (informational — enforcement keys off the path so descendant
/// checks are cheap), and the child-visible flag.
///
/// Re-exported from `kernel_api::namespace`, where they moved so `src/audit`
/// can read a token's namespace without reaching into `crate::modules` for one
/// constant — a cross-layer wart the decomposition roadmap tracked separately.
pub use crate::kernel_api::namespace::{CHILD_VISIBLE_META, NS_ID_META, NS_PATH_META};

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
    use super::router::namespace_header_from_map;

    let raw = namespace_header_from_map(req.headers.as_ref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(raw) = raw else {
        return Ok((String::new(), String::new()));
    };

    resolve_namespace_by_path(core, &raw).await
}

/// Resolve a namespace path to its canonical `(path, uuid)`. Fails closed: an
/// unknown path (or an unavailable namespace module/store) is a hard error, so no
/// caller can silently fall back to root after asking for a tenant.
#[maybe_async::maybe_async]
async fn resolve_namespace_by_path(
    core: &crate::core::Core,
    raw: &str,
) -> Result<(String, String), crate::errors::RvError> {
    use super::{NamespaceModule, NAMESPACE_MODULE_NAME};

    let module = core
        .module_manager()
        .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
        .ok_or_else(|| {
            crate::bv_error_string!("namespace header set but the namespace module is unavailable")
        })?;
    let store = module
        .store()
        .ok_or_else(|| crate::bv_error_string!("namespace store not initialized"))?;
    let ns = store.get_by_path(raw).await?.ok_or_else(|| {
        let p = super::store::normalize_path(raw).unwrap_or_else(|_| raw.to_string());
        crate::bv_error_response_status!(404, &format!("no such namespace: {p:?}"))
    })?;
    Ok((ns.path, ns.uuid))
}

/// [`resolve_login_namespace`], plus the principal's *default* namespace when the
/// client named none.
///
/// A login request that carries no `X-BastionVault-Namespace` header is asking
/// for the deployment default, not for root specifically. For a principal whose
/// namespace assignment excludes root, binding that login to root only to deny it
/// a moment later in
/// [`enforce_login_assignment`](super::ns_assignment::enforce_login_assignment)
/// leaves the credential unable to authenticate at all through a client that has
/// no namespace picker (the GUI login page, the CLI without `-namespace`). So the
/// login instead binds to the principal's first assigned namespace.
///
/// This cannot widen access: the chosen path always comes from the principal's
/// own assignment, so the subsequent `enforce_login_assignment` still holds. An
/// **explicitly** named namespace is never rewritten — it resolves exactly as
/// [`resolve_login_namespace`] does and fails closed when the assignment
/// excludes it.
#[maybe_async::maybe_async]
pub async fn resolve_login_namespace_for_principal(
    core: &crate::core::Core,
    req: &crate::logical::Request,
    mount: &str,
    name: &str,
) -> Result<(String, String), crate::errors::RvError> {
    use super::router::namespace_header_from_map;

    let explicit = namespace_header_from_map(req.headers.as_ref())
        .map(|s| s.trim().to_string())
        .is_some_and(|s| !s.is_empty());
    if explicit {
        return resolve_login_namespace(core, req).await;
    }

    match super::ns_assignment::default_login_namespace_for(core, mount, name).await? {
        Some(path) => {
            let resolved = resolve_namespace_by_path(core, &path).await?;
            log::info!(
                target: "security",
                "login for '{mount}{name}' defaulted to assigned namespace {:?} \
                 (no namespace requested; root is not assigned)",
                resolved.0
            );
            Ok(resolved)
        }
        None => Ok((String::new(), String::new())),
    }
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

    // Header-scoped paths carry no namespace prefix by design, so resolving a
    // target namespace from the path below would always answer "root" and refuse
    // every namespace-bound token — on paths whose own handlers do the
    // per-namespace scoping. Exempt exactly the set the router leaves
    // un-rewritten; the two must not drift apart (see `is_header_scoped_path`).
    if super::router::is_header_scoped_path(&req.path) {
        return Ok(());
    }
    let Some(auth) = req.auth.as_ref() else {
        return Ok(());
    };
    // Root is superuser and operates in every namespace.
    if auth.policies.iter().any(|p| p == "root") {
        return Ok(());
    }

    let Some(module) = core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
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

    let Some(module) = core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
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


