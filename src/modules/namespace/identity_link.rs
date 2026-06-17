//! Cross-tenant identity linking (Phase 3).
//!
//! For the SaaS / MSP case where a single human spans tenants, a **parent**
//! namespace may declare that an entity in one child and an entity in another
//! child are the same person — purely for audit correlation. The link is
//! one-way: it is visible from the namespace that created it (and, transitively,
//! ancestors), never from a sibling or from the linked children themselves.
//! This prevents a child operator from enumerating which of their users also
//! exist in sibling namespaces.
//!
//! Enforcement of the one-way property is structural: a link may only reference
//! namespaces inside the creating namespace's own subtree (the parent itself or
//! any descendant), and links are stored partitioned by their parent namespace,
//! so a `list` scoped to one namespace never returns another's links.
//!
//! Storage layout (barrier-root, alongside the namespace registry):
//! ```text
//! namespaces/identity-links/<b64url(parent_path)>/<link_uuid> -> IdentityLink (JSON)
//! ```
//! `parent_path` is base64url-encoded (the empty root path encodes to the empty
//! string, giving keys of the form `/<uuid>`), so a path can never break out of
//! its key segment.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    bv_error_response_status, bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    utils::generate_uuid,
};

use super::store::{normalize_path, NamespaceStore};
use super::token_binding::is_descendant;

/// Barrier-root prefix for identity links. Distinct from the registry prefix
/// (`namespaces/registry/`) and every per-namespace data prefix
/// (`namespaces/<uuid>/`), since `identity-links` can never equal a UUID.
pub const IDENTITY_LINK_PREFIX: &str = "namespaces/identity-links/";

/// One side of a cross-tenant identity link: an entity in a specific namespace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityLinkMember {
    pub namespace: String,
    pub entity_id: String,
}

/// A declaration that several namespace-scoped entities are the same person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityLink {
    pub id: String,
    /// The namespace that owns (and can see) this link.
    pub parent_namespace: String,
    #[serde(default)]
    pub label: String,
    pub members: Vec<IdentityLinkMember>,
    pub created_at: String,
}

fn parent_key_prefix(parent_path: &str) -> String {
    format!("{}/", URL_SAFE_NO_PAD.encode(parent_path.as_bytes()))
}

fn link_key(parent_path: &str, id: &str) -> String {
    format!("{}{}", parent_key_prefix(parent_path), id)
}

pub struct IdentityLinkStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl IdentityLinkStore {
    pub fn new(core: &Core) -> Result<Self, RvError> {
        let view = Arc::new(BarrierView::new(core.barrier.clone(), IDENTITY_LINK_PREFIX));
        Ok(Self { view })
    }

    /// Create a link owned by `parent_path`. Every member namespace must be the
    /// parent itself or a descendant of it (enforcing the one-way property) and
    /// must exist. At least two members are required for a link to mean
    /// anything. Returns the persisted record.
    pub async fn create(
        &self,
        ns_store: &NamespaceStore,
        parent_path: &str,
        label: &str,
        members: Vec<IdentityLinkMember>,
    ) -> Result<IdentityLink, RvError> {
        let parent = normalize_path(parent_path)?;
        // The owning namespace must exist (root always does).
        if !parent.is_empty() && ns_store.get_by_path(&parent).await?.is_none() {
            return Err(bv_error_response_status!(
                404,
                &format!("no such namespace: {parent:?}")
            ));
        }
        if members.len() < 2 {
            return Err(bv_error_string!("an identity link needs at least two members"));
        }

        let mut normalized = Vec::with_capacity(members.len());
        for m in members {
            let ns = normalize_path(&m.namespace)?;
            // One-way property: a link may only reference the owning subtree.
            if ns != parent && !is_descendant(&ns, &parent) {
                return Err(bv_error_response_status!(
                    403,
                    &format!(
                        "identity link in namespace {parent:?} may not reference {ns:?}: \
                         members must be the owning namespace or a descendant of it"
                    )
                ));
            }
            if ns.is_empty() {
                // The root has no parent that could own a link reaching "up".
                // (parent must therefore also be root, already allowed above.)
            } else if ns_store.get_by_path(&ns).await?.is_none() {
                return Err(bv_error_response_status!(
                    404,
                    &format!("no such namespace: {ns:?}")
                ));
            }
            if m.entity_id.trim().is_empty() {
                return Err(bv_error_string!("identity link member entity_id must not be empty"));
            }
            normalized.push(IdentityLinkMember { namespace: ns, entity_id: m.entity_id });
        }

        let link = IdentityLink {
            id: generate_uuid(),
            parent_namespace: parent.clone(),
            label: label.to_string(),
            members: normalized,
            created_at: Utc::now().to_rfc3339(),
        };
        let value = serde_json::to_vec(&link)?;
        self.view
            .put(&StorageEntry { key: link_key(&parent, &link.id), value })
            .await?;
        Ok(link)
    }

    /// Fetch one link owned by `parent_path`.
    pub async fn get(&self, parent_path: &str, id: &str) -> Result<Option<IdentityLink>, RvError> {
        let parent = normalize_path(parent_path)?;
        match self.view.get(&link_key(&parent, id)).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    /// List every link owned by `parent_path` (newest entries are unordered;
    /// callers sort by `created_at` if needed).
    pub async fn list(&self, parent_path: &str) -> Result<Vec<IdentityLink>, RvError> {
        let parent = normalize_path(parent_path)?;
        let keys = self.view.list(&parent_key_prefix(&parent)).await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(link) = self.get(&parent, k.trim_end_matches('/')).await? {
                out.push(link);
            }
        }
        Ok(out)
    }

    /// Delete a link owned by `parent_path`. Idempotent.
    pub async fn delete(&self, parent_path: &str, id: &str) -> Result<(), RvError> {
        let parent = normalize_path(parent_path)?;
        self.view.delete(&link_key(&parent, id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::namespace::{
        store::NamespaceQuotas, NamespaceModule, NAMESPACE_MODULE_NAME,
    };
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_link_subtree_enforced() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_identity_link").await;
        let ns_store = core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        ns_store.create("acme", NamespaceQuotas::default(), false).await.unwrap();
        ns_store.create("acme/team-a", NamespaceQuotas::default(), false).await.unwrap();
        ns_store.create("acme/team-b", NamespaceQuotas::default(), false).await.unwrap();
        ns_store.create("globex", NamespaceQuotas::default(), false).await.unwrap();

        let links = IdentityLinkStore::new(&core).unwrap();

        // acme links two of its descendants — allowed.
        let link = links
            .create(
                &ns_store,
                "acme",
                "alice",
                vec![
                    IdentityLinkMember { namespace: "acme/team-a".into(), entity_id: "e1".into() },
                    IdentityLinkMember { namespace: "acme/team-b".into(), entity_id: "e2".into() },
                ],
            )
            .await
            .unwrap();
        assert_eq!(link.parent_namespace, "acme");

        // Visible from acme, and acme only.
        assert_eq!(links.list("acme").await.unwrap().len(), 1);
        assert!(links.list("globex").await.unwrap().is_empty());
        assert!(links.list("acme/team-a").await.unwrap().is_empty());

        // acme cannot link a sibling tenant's namespace (outside its subtree).
        let err = links
            .create(
                &ns_store,
                "acme",
                "bad",
                vec![
                    IdentityLinkMember { namespace: "acme/team-a".into(), entity_id: "e1".into() },
                    IdentityLinkMember { namespace: "globex".into(), entity_id: "e9".into() },
                ],
            )
            .await;
        assert!(err.is_err(), "linking a namespace outside the subtree must be refused");

        // A child cannot link its parent (reaching "up" is refused).
        let err = links
            .create(
                &ns_store,
                "acme/team-a",
                "up",
                vec![
                    IdentityLinkMember { namespace: "acme/team-a".into(), entity_id: "e1".into() },
                    IdentityLinkMember { namespace: "acme".into(), entity_id: "e2".into() },
                ],
            )
            .await;
        assert!(err.is_err(), "a child may not link its ancestor");

        // Delete round-trips.
        links.delete("acme", &link.id).await.unwrap();
        assert!(links.list("acme").await.unwrap().is_empty());
    }
}
