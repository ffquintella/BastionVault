//! Lifted from `crates/bv-kernel/src/modules/namespace/identity_link.rs`.
//!
//! These tests build a whole vault through `test_utils`, then look modules and
//! stores back up by type. That only works where the vault is *constructed* —
//! `bv-kernel`'s own test binary is a separate compilation of the crate from
//! the rlib `bastion_vault` links, so `get_module::<T>()` sees two different
//! `TypeId`s for the same type and every lookup returns `None`. Fifth instance
//! of "tests that could not travel", and the first caused by type identity
//! rather than by a missing dependency. See
//! roadmaps/workspace-decomposition.md § Phase 4.5.

// The parent's import list, written out. A `use super::*` glob sees a module's
// *private* `use` statements only from inside the same crate, so lifting these
// blocks out of `bv-kernel` cost them every name the parent had imported. This
// is the fourth time this decomposition has hit that (Phase 3 § "The alias
// preamble"); the fix is the same one.
#[allow(unused_imports)]
use std::{collections::HashMap, sync::Arc};
#[allow(unused_imports)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use crate::{
    core::Core,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request},
    storage::StorageEntry,
};


use crate::modules::namespace::identity_link::*;
    use crate::modules::namespace::{
        store::NamespaceQuotas, NamespaceModule, NAMESPACE_MODULE_NAME,
    };
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_link_subtree_enforced() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_identity_link").await;
        let ns_store = core
            .module_manager()
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
