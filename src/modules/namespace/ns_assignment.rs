//! Per-principal namespace assignment (Phase 5 — login-restriction).
//!
//! Auth *mounts* are not namespace-scoped in the current phases (the router
//! skips rewriting `auth/`), so a single global `auth/<mount>/` table backs
//! every namespace. By itself that means any credential can authenticate
//! against any namespace — it simply binds to whichever one the
//! `X-BastionVault-Namespace` header names. This module adds an explicit,
//! operator-authored *assignment list* that restricts which namespaces a given
//! credential may authenticate into.
//!
//! ## Semantics
//!
//! - **No record ⇒ unrestricted.** A principal with no assignment may log in at
//!   any namespace — exactly the pre-Phase-5 behaviour, so single-tenant
//!   installs are unaffected.
//! - **A non-empty record narrows.** Login is permitted only at a listed
//!   namespace *or a descendant of one* (so assigning `engineering` also
//!   covers `engineering/platform`). Enforcement [`fails closed`](enforce_login_assignment):
//!   a record that does not permit the target namespace yields
//!   `permission_denied`; there is no silent fallback to root.
//! - **Empty list is normalized to no record** ([`NsAssignmentStore::set`]), so
//!   "unrestricted" has exactly one representation.
//!
//! This restricts *authentication* (where a credential may bind), not
//! *authorization* within a namespace — a bound token still needs policies in
//! that namespace to do anything.
//!
//! ## Storage layout (barrier-root, alongside the namespace registry)
//!
//! ```text
//! namespaces/ns-assignment/<b64url(mount)>.<b64url(name)> -> NsAssignment (JSON)
//! ```
//!
//! The record lives at the raw barrier root (outside every per-tenant prefix)
//! because it *governs* cross-namespace access and must be readable regardless
//! of the caller's active namespace. Mount and principal name are base64url
//! encoded into a single flat key so an arbitrary name can never break out of
//! its key segment and a `list("")` enumerates every assignment.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

use super::store::{normalize_path, NamespaceStore};
use super::token_binding::is_descendant;

/// Barrier-root prefix for namespace assignments. Distinct from the registry
/// prefix (`namespaces/registry/`), the identity-link prefix
/// (`namespaces/identity-links/`), and every per-namespace data prefix
/// (`namespaces/<uuid>/`) — `ns-assignment` can never equal a UUID.
pub const NS_ASSIGNMENT_PREFIX: &str = "namespaces/ns-assignment/";

/// An operator-authored restriction on where a single credential may
/// authenticate. `mount`/`name` identify the principal (`userpass/` + `alice`,
/// `approle/` + `ci-deploy`, `cert/` + `<name>`, …).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NsAssignment {
    pub mount: String,
    pub name: String,
    /// Allowed namespace paths (canonical, no trailing slash; `""` = root).
    /// Never persisted empty — an empty list deletes the record.
    pub namespaces: Vec<String>,
    pub updated_at: String,
}

/// Flat barrier key for `(mount, name)`. Both components are base64url-encoded
/// so neither a `/` in the mount (`userpass/`) nor an arbitrary principal name
/// can escape the key segment. The `.` separator is outside the base64url
/// alphabet, so the split is unambiguous.
fn assignment_key(mount: &str, name: &str) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(mount.as_bytes()),
        URL_SAFE_NO_PAD.encode(name.as_bytes())
    )
}

/// The pure assignment decision, isolated for testing. `allowed` is the
/// principal's assignment list; `request_ns` is the namespace being
/// authenticated into (canonical path, `""` = root).
///
/// - An **empty** list means unrestricted ⇒ always allowed.
/// - Otherwise allowed iff `request_ns` exactly matches an assigned path or is a
///   descendant of one.
pub fn namespace_allowed(allowed: &[String], request_ns: &str) -> bool {
    if allowed.is_empty() {
        return true;
    }
    allowed
        .iter()
        .any(|a| a == request_ns || is_descendant(request_ns, a))
}

pub struct NsAssignmentStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl NsAssignmentStore {
    pub fn new(core: &Core) -> Result<Self, RvError> {
        let view = Arc::new(BarrierView::new(core.barrier.clone(), NS_ASSIGNMENT_PREFIX));
        Ok(Self { view })
    }

    /// Read the assignment for a principal. `None` ⇒ unrestricted.
    pub async fn get(&self, mount: &str, name: &str) -> Result<Option<NsAssignment>, RvError> {
        match self.view.get(&assignment_key(mount, name)).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    /// Set (or clear) a principal's allowed namespaces. Each path is normalized
    /// and must name an existing namespace (root `""` always exists). Passing an
    /// **empty** list deletes the record (back to unrestricted) and returns
    /// `None`; otherwise the persisted record is returned.
    pub async fn set(
        &self,
        ns_store: &NamespaceStore,
        mount: &str,
        name: &str,
        namespaces: Vec<String>,
    ) -> Result<Option<NsAssignment>, RvError> {
        if mount.trim().is_empty() || name.trim().is_empty() {
            return Err(crate::bv_error_string!(
                "namespace assignment requires a non-empty mount and principal name"
            ));
        }

        // Normalize + validate, dropping duplicates. An empty result clears.
        let mut normalized: Vec<String> = Vec::with_capacity(namespaces.len());
        for ns in namespaces {
            let p = normalize_path(&ns)?;
            if !p.is_empty() && ns_store.get_by_path(&p).await?.is_none() {
                return Err(crate::bv_error_response_status!(
                    404,
                    &format!("no such namespace: {p:?}")
                ));
            }
            if !normalized.contains(&p) {
                normalized.push(p);
            }
        }

        if normalized.is_empty() {
            self.delete(mount, name).await?;
            return Ok(None);
        }

        let record = NsAssignment {
            mount: mount.to_string(),
            name: name.to_string(),
            namespaces: normalized,
            updated_at: Utc::now().to_rfc3339(),
        };
        let value = serde_json::to_vec(&record)?;
        self.view
            .put(&StorageEntry { key: assignment_key(mount, name), value })
            .await?;
        Ok(Some(record))
    }

    /// Remove a principal's restriction (back to unrestricted). Idempotent.
    pub async fn delete(&self, mount: &str, name: &str) -> Result<(), RvError> {
        self.view.delete(&assignment_key(mount, name)).await
    }

    /// Every assignment on record (principals without a restriction are absent).
    pub async fn list(&self) -> Result<Vec<NsAssignment>, RvError> {
        let keys = self.view.list("").await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(e) = self.view.get(k.trim_end_matches('/')).await? {
                out.push(serde_json::from_slice(&e.value)?);
            }
        }
        Ok(out)
    }
}

/// Enforce a principal's namespace assignment at login time. Called after the
/// login namespace is resolved and before the token is stamped. A principal
/// with no record (or an empty list — never persisted) is unrestricted; a
/// record that does not permit `ns_path` fails the login with
/// `permission_denied`. Fails closed: there is no silent fallback to root.
#[maybe_async::maybe_async]
pub async fn enforce_login_assignment(
    core: &Arc<Core>,
    mount: &str,
    name: &str,
    ns_path: &str,
) -> Result<(), RvError> {
    let store = NsAssignmentStore::new(core)?;
    if let Some(assignment) = store.get(mount, name).await? {
        if !namespace_allowed(&assignment.namespaces, ns_path) {
            log::warn!(
                target: "security",
                "login denied: principal '{mount}{name}' is not assigned to namespace {ns_path:?}"
            );
            return Err(RvError::ErrPermissionDenied);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::namespace::{store::NamespaceQuotas, NamespaceModule, NAMESPACE_MODULE_NAME};
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[test]
    fn test_namespace_allowed() {
        // Empty list ⇒ unrestricted.
        assert!(namespace_allowed(&[], ""));
        assert!(namespace_allowed(&[], "engineering"));
        assert!(namespace_allowed(&[], "engineering/platform"));

        let allowed = vec!["engineering".to_string()];
        // Exact match.
        assert!(namespace_allowed(&allowed, "engineering"));
        // Descendant of an assigned path.
        assert!(namespace_allowed(&allowed, "engineering/platform"));
        // Sibling, parent (root), and unrelated are refused.
        assert!(!namespace_allowed(&allowed, "marketing"));
        assert!(!namespace_allowed(&allowed, ""));
        assert!(!namespace_allowed(&allowed, "engineering-x")); // not a segment boundary

        // Multiple assignments union.
        let multi = vec!["engineering".to_string(), "ops".to_string()];
        assert!(namespace_allowed(&multi, "ops"));
        assert!(namespace_allowed(&multi, "engineering/platform"));
        assert!(!namespace_allowed(&multi, "sales"));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ns_assignment_store_roundtrip() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_assignment_store").await;
        let ns_store = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        ns_store.create("engineering", NamespaceQuotas::default(), false).await.unwrap();
        ns_store.create("marketing", NamespaceQuotas::default(), false).await.unwrap();

        let store = NsAssignmentStore::new(&core).unwrap();

        // No record ⇒ unrestricted (enforcement is a no-op).
        assert!(store.get("userpass/", "alice").await.unwrap().is_none());
        enforce_login_assignment(&core, "userpass/", "alice", "marketing").await.unwrap();

        // Assign alice → engineering.
        let rec = store
            .set(&ns_store, "userpass/", "alice", vec!["engineering".into()])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.namespaces, vec!["engineering".to_string()]);

        // Login at engineering (and a descendant) is allowed; marketing/root denied.
        enforce_login_assignment(&core, "userpass/", "alice", "engineering").await.unwrap();
        ns_store.create("engineering/platform", NamespaceQuotas::default(), false).await.unwrap();
        enforce_login_assignment(&core, "userpass/", "alice", "engineering/platform").await.unwrap();
        assert!(enforce_login_assignment(&core, "userpass/", "alice", "marketing").await.is_err());
        assert!(enforce_login_assignment(&core, "userpass/", "alice", "").await.is_err());

        // A different, unassigned principal is still unrestricted.
        enforce_login_assignment(&core, "userpass/", "bob", "marketing").await.unwrap();

        // Listing surfaces the one record.
        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "alice");

        // Setting a non-existent namespace is refused.
        assert!(store
            .set(&ns_store, "userpass/", "alice", vec!["nope".into()])
            .await
            .is_err());

        // Empty list clears the restriction (back to unrestricted).
        assert!(store.set(&ns_store, "userpass/", "alice", vec![]).await.unwrap().is_none());
        assert!(store.get("userpass/", "alice").await.unwrap().is_none());
        enforce_login_assignment(&core, "userpass/", "alice", "marketing").await.unwrap();
        assert!(store.list().await.unwrap().is_empty());
    }
}
