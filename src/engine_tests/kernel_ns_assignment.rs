//! Lifted from `crates/bv-kernel/src/modules/namespace/ns_assignment.rs`.
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


use crate::modules::namespace::ns_assignment::*;
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

    #[test]
    fn test_default_login_namespace() {
        // Unrestricted ⇒ no redirection; the login stays at root.
        assert_eq!(default_login_namespace(&[]), None);
        // Root explicitly assigned ⇒ stay at root even with tenants alongside.
        assert_eq!(
            default_login_namespace(&["".to_string(), "engineering".to_string()]),
            None
        );
        // Root excluded ⇒ land in the first assigned namespace (operator order).
        assert_eq!(
            default_login_namespace(&["engineering".to_string(), "ops".to_string()]),
            Some("engineering")
        );
        assert_eq!(
            default_login_namespace(&["dti/esi".to_string()]),
            Some("dti/esi")
        );
        // Whatever it returns is a namespace the assignment already permits, so
        // the redirection can never widen where a credential may authenticate.
        for allowed in [vec!["engineering".to_string(), "ops".to_string()], vec!["dti/esi".to_string()]] {
            let picked = default_login_namespace(&allowed).unwrap();
            assert!(namespace_allowed(&allowed, picked));
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ns_assignment_store_roundtrip() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_assignment_store").await;
        let ns_store = core
            .module_manager()
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
