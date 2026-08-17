//! Lifted from `crates/bv-kernel/src/modules/namespace/token_binding.rs`.
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


use crate::modules::namespace::token_binding::*;

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
            .module_manager()
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
