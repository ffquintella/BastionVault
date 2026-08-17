//! Mount-table management that only `Core` can do.
//!
//! The mount table itself — [`MountEntry`], [`MountTable`], [`MountsRouter`]
//! and [`MountsMonitor`] — lives in `bv-kernel-api` and is re-exported here so
//! `bastion_vault::mount::*` paths are unchanged. It had to move: an engine
//! resolves its own mount through [`VaultCtx::mounts_router`], so the mount
//! table is part of the kernel contract and sits below every engine crate.
//!
//! What stayed is this file: `Core::mount`, `unmount`, `remount` and
//! `unload_mounts`. Those are the *management* operations, deliberately absent
//! from `VaultCtx` — an engine that cannot name them cannot grow a dependency
//! on them — so they belong with `Core`, not with the table.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

use std::sync::{Arc, RwLock};

pub use bv_kernel_api::mount::*;

use crate::{
    core::Core,
    errors::RvError,
    storage::barrier_view::BarrierView,
    utils::generate_uuid,
};

#[maybe_async::maybe_async]
impl Core {
    pub async fn mount(&self, me: &MountEntry) -> Result<(), RvError> {
        let mounts_router = self.mounts_router();
        {
            let mut table = mounts_router.entries.write()?;
            let mut entry = me.clone();

            if !entry.path.ends_with('/') {
                entry.path += "/";
            }

            if is_protected_mount(&[&entry.path]) {
                return Err(RvError::ErrMountPathProtected);
            }

            if entry.table.is_empty() {
                entry.table = MOUNT_TABLE_TYPE.to_string();
            }

            let match_mount_path = self.router.matching_mount(&entry.path)?;
            if !match_mount_path.is_empty() {
                return Err(RvError::ErrMountPathExist);
            }

            let backend_new_func = self.get_logical_backend(&me.logical_type)?;
            let backend = backend_new_func(self.self_ptr.upgrade().unwrap().clone())?;

            entry.uuid = generate_uuid();

            // Re-root aware: root mounts live under the active root logical
            // prefix (`logical/` legacy, or `namespaces/<root_uuid>/logical/`
            // when re-root activation is in effect).
            let prefix = format!("{}{}/", self.root_logical_prefix(), &entry.uuid);
            let view = BarrierView::new(self.barrier.clone(), &prefix);

            let path = entry.path.clone();

            entry.calc_hmac(&self.state.load().hmac_key)?;

            let mount_entry = Arc::new(RwLock::new(entry));

            self.router.mount(backend, &path, mount_entry.clone(), view)?;

            table.insert(path, mount_entry);
        }

        self.mounts_router().persist(self.barrier.as_storage()).await?;

        Ok(())
    }

    pub async fn unmount(&self, path: &str) -> Result<(), RvError> {
        let mut path = path.to_string();
        if !path.ends_with('/') {
            path += "/";
        }

        if is_protected_mount(&[&path]) {
            return Err(RvError::ErrMountPathProtected);
        }

        let match_mount = self.router.matching_mount(&path)?;
        if match_mount.is_empty() || match_mount != path {
            return Err(RvError::ErrMountNotMatch);
        }

        let view = self.router.matching_view(&path)?;

        self.taint_mount_entry(&path).await?;

        self.router.taint(&path)?;

        self.router.unmount(&path)?;

        if view.is_some() {
            view.unwrap().clear().await?;
        }

        self.remove_mount_entry(&path).await?;

        Ok(())
    }

    pub async fn remount(&self, src: &str, dst: &str) -> Result<(), RvError> {
        let mut src = src.to_string();
        let mut dst = dst.to_string();

        if !src.ends_with('/') {
            src += "/";
        }

        if !dst.ends_with('/') {
            dst += "/";
        }

        if is_protected_mount(&[&src, &dst]) {
            return Err(RvError::ErrMountPathProtected);
        }

        let dst_match = self.router.matching_mount(&dst)?;
        if !dst_match.is_empty() {
            return Err(RvError::ErrMountPathExist);
        }

        let Some(src_match) = self.router.matching_mount_entry(&src)? else {
            return Err(RvError::ErrMountNotMatch);
        };

        let src_path;
        {
            let mut src_entry = src_match.write()?;
            src_entry.tainted = true;

            self.router.taint(&src)?;

            if !(self.router.matching_mount(&dst)?).is_empty() {
                return Err(RvError::ErrMountPathExist);
            }

            src_path = src_entry.path.clone();
            src_entry.path.clone_from(&dst);
            src_entry.tainted = false;
            src_entry.calc_hmac(&self.state.load().hmac_key)?;

            std::mem::drop(src_entry);
        }

        // Rekey the mounts_router HashMap so subsequent `delete(dst)` lookups
        // hit the correct entry. Without this, `unmount(dst)` silently no-ops
        // on the table and the entry survives until restart even though the
        // router trie no longer routes to it.
        {
            let mounts_router = self.mounts_router();
            let mut entries = mounts_router.entries.write()?;
            if let Some(entry) = entries.remove(&src) {
                entries.insert(dst.clone(), entry);
            }
        }

        if let Err(e) = self.mounts_router().persist(self.barrier.as_storage()).await {
            // Best-effort rollback: put the entry back under its original key
            // and restore the path field so the in-memory state matches what
            // is on disk.
            {
                let mounts_router = self.mounts_router();
                let mut entries = mounts_router.entries.write()?;
                if let Some(entry) = entries.remove(&dst) {
                    entries.insert(src.clone(), entry);
                }
            }
            let mut src_entry = src_match.write()?;
            src_entry.path = src_path;
            src_entry.tainted = true;
            src_entry.calc_hmac(&self.state.load().hmac_key)?;
            return Err(e);
        }

        self.router.remount(&dst, &src)?;

        self.router.untaint(&dst)?;

        Ok(())
    }

    pub fn unload_mounts(&self) -> Result<(), RvError> {
        let _ = self.router.clear();
        let _ = self.mounts_router().clear();
        Ok(())
    }

    async fn taint_mount_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts_router().set_taint(path, true) {
            self.mounts_router().persist(self.barrier.as_storage()).await?;
        }
        Ok(())
    }

    async fn remove_mount_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts_router().delete(path) {
            self.mounts_router().persist(self.barrier.as_storage()).await?;
        }
        Ok(())
    }
}
