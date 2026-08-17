//! Lifted from `crates/bv-kernel/src/modules/namespace/migrate.rs`.
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


use crate::modules::namespace::migrate::*;
use crate::modules::namespace::store::NAMESPACE_REGISTRY_PREFIX;
    use crate::modules::namespace::{NamespaceModule, NAMESPACE_MODULE_NAME};
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_reroot_activated_by_default_on_new_install() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_reroot_activation").await;
        let store = core
            .module_manager()
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        let core_arc = core.weak_ctx().upgrade().unwrap();
        let root_uuid = store.root_uuid().unwrap();
        let __barrier = core.barrier();
        let barrier = __barrier.as_storage();

        // New installs activate re-rooting by default: the root tenant's mount
        // table lives under `namespaces/<root_uuid>/`, the legacy location is
        // never written, and Core is repointed at the active prefix.
        let dst = format!("namespaces/{root_uuid}/core/mounts");
        assert!(barrier.get(&dst).await.unwrap().is_some(), "activated mount table must exist");
        assert!(
            barrier.get("core/mounts").await.unwrap().is_none(),
            "legacy mount table must not be written on an activated new install"
        );
        assert_eq!(
            core.root_storage_prefix.load().as_str(),
            format!("namespaces/{root_uuid}/").as_str(),
            "Core must be repointed at the active root prefix"
        );

        // The copy stage is a no-op on a new install (nothing to copy; the
        // version marker was set when activation was recorded).
        let report = migrate_root_copy(&core_arc, &store).await.unwrap();
        assert!(report.already_done, "copy must be a no-op for an activated new install");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_reroot_activates_existing_install_by_default() {
        let (_bvault, core, _root) = new_unseal_test_bastion_vault("test_ns_reroot_existing").await;
        let store = core
            .module_manager()
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .unwrap();
        let core_arc = core.weak_ctx().upgrade().unwrap();
        let __barrier = core.barrier();
        let barrier = __barrier.as_storage();

        // Simulate a pre-namespace existing install: a legacy root mount table
        // + a legacy logical secret present, and the activation/version markers
        // cleared so the decision runs as if upgrading for the first time.
        barrier
            .put(&StorageEntry { key: "core/mounts".into(), value: b"legacy-table".to_vec() })
            .await
            .unwrap();
        barrier
            .put(&StorageEntry { key: "logical/seed/secret".into(), value: b"legacy-secret".to_vec() })
            .await
            .unwrap();
        barrier
            .delete(&format!("{NAMESPACE_REGISTRY_PREFIX}{ACTIVATION_MARKER_KEY}"))
            .await
            .unwrap();
        barrier
            .delete(&format!("{NAMESPACE_REGISTRY_PREFIX}{MIGRATION_VERSION_KEY}"))
            .await
            .unwrap();
        assert!(!activation_active(barrier).await.unwrap(), "precondition: not activated");

        // Re-root is the default with no opt-in: an existing install copies +
        // verifies and activates this boot.
        let res = resolve_root_activation(&core_arc, &store).await.unwrap();
        let root_uuid = res.expect("existing install must activate by default");

        // The legacy secret was copied under the re-rooted prefix and the
        // marker is now set; legacy keys are retained (non-destructive).
        assert!(
            barrier
                .get(&format!("namespaces/{root_uuid}/logical/seed/secret"))
                .await
                .unwrap()
                .is_some(),
            "legacy data must be copied under the re-rooted prefix"
        );
        assert!(activation_active(barrier).await.unwrap(), "activation marker must be set");
        assert!(
            barrier.get("logical/seed/secret").await.unwrap().is_some(),
            "legacy keys must be retained (non-destructive)"
        );
    }

    #[test]
    fn test_reroot_destination_mapping() {
        assert_eq!(
            reroot_destination("ROOT", "logical/abc/secret"),
            Some("namespaces/ROOT/logical/abc/secret".to_string())
        );
        assert_eq!(
            reroot_destination("ROOT", "sys/policy/admin"),
            Some("namespaces/ROOT/sys/policy/admin".to_string())
        );
        assert_eq!(
            reroot_destination("ROOT", "core/mounts"),
            Some("namespaces/ROOT/core/mounts".to_string())
        );
        // Physical-layer / unrelated keys are left untouched.
        assert_eq!(reroot_destination("ROOT", "core/seal-config"), None);
        assert_eq!(reroot_destination("ROOT", "barrier/init"), None);
    }
