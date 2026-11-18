//! This module provides the 'auth/' path and relevant authentication features.
//!
//! After a successful authentication, a client will be granted a token for further operations.

use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, RwLock},
};

use arc_swap::ArcSwapOption;
use lazy_static::lazy_static;

use crate::kernel_api::{
    auth::{AuthMountPrincipals, AuthMountRegistry, AuthMountView},
    MountEntryHMACLevel, VaultCtx,
};
use crate::{
    bv_error_response_status,
    core::{Core, LogicalBackendNewFunc},
    errors::RvError,
    handler::{AuthHandler, Handler},
    logical::Backend,
    modules::{identity::IdentityModule, Module},
    mount::{MountEntry, MountTable, MountsRouter},
    storage::{barrier::SecurityBarrier, barrier_view::BarrierView},
    utils::{generate_uuid, is_protect_path},
};

pub mod expiration;
pub mod kernel_service;
pub(crate) mod lease_state;
pub mod token_store;
pub use expiration::ExpirationManager;
pub use token_store::TokenStore;

const AUTH_CONFIG_PATH: &str = "core/auth";
const AUTH_BARRIER_PREFIX: &str = "auth/";

pub const AUTH_ROUTER_PREFIX: &str = "auth/";
pub const AUTH_TABLE_TYPE: &str = "auth";

lazy_static! {
    static ref PROTECTED_AUTHS: Vec<&'static str> = vec!["auth/token",];
    static ref DEFAULT_AUTH_MOUNTS: Vec<MountEntry> = vec![MountEntry {
        table: AUTH_TABLE_TYPE.to_string(),
        tainted: false,
        uuid: generate_uuid(),
        path: "token/".to_string(),
        logical_type: "token".to_string(),
        description: "token based credentials".to_string(),
        ..Default::default()
    }];
}

pub struct AuthModule {
    pub name: String,
    pub core: Arc<Core>,
    pub barrier: Arc<dyn SecurityBarrier>,
    pub mounts_router: Arc<MountsRouter>,
    pub token_store: ArcSwapOption<TokenStore>,
    pub expiration: ArcSwapOption<ExpirationManager>,
    /// How each credential backend type names its principals, so disabling
    /// one of its mounts forgets their entity aliases (T522).
    pub principals: RwLock<HashMap<String, Arc<dyn AuthMountPrincipals>>>,
}

/// What T500's keeping rule decided for a disabled mount's principals.
#[derive(Debug, Default, PartialEq, Eq)]
struct KeepDecision {
    /// Another mount of the type holds the name: its aliases stay.
    kept: Vec<String>,
    /// No other mount holds it: forget its aliases everywhere.
    forget: Vec<String>,
    /// The other mounts could not be read: kept, and reported.
    undecided: Vec<String>,
}

#[maybe_async::maybe_async]
impl AuthModule {
    pub fn new(core: Arc<Core>) -> Result<Self, RvError> {
        Ok(Self {
            name: "auth".to_string(),
            core: core.clone(),
            barrier: core.barrier(),
            mounts_router: Arc::new(MountsRouter::new(
                Arc::new(MountTable::new(AUTH_CONFIG_PATH)),
                core.router(),
                core.barrier(),
                AUTH_BARRIER_PREFIX,
                AUTH_ROUTER_PREFIX,
            )),
            token_store: ArcSwapOption::empty(),
            expiration: ArcSwapOption::empty(),
            principals: RwLock::new(HashMap::new()),
        })
    }

    pub fn set_auth_handlers(&self, handlers: Arc<Vec<Arc<dyn AuthHandler>>>) {
        self.token_store.load().as_ref().unwrap().auth_handlers.store(handlers);
    }

    pub async fn enable_auth(&self, me: &MountEntry) -> Result<(), RvError> {
        let mounts_router = &self.mounts_router;
        {
            let mut auth_table = mounts_router.mounts.entries.write()?;
            let mut entry = me.clone();

            if !entry.path.ends_with('/') {
                entry.path += "/";
            }

            if entry.path == "/" {
                return Err(RvError::ErrMountPathProtected);
            }

            if entry.logical_type == "token" {
                return Err(RvError::ErrMountFailed);
            }

            if is_protect_path(&PROTECTED_AUTHS, &[&entry.path]) {
                return Err(RvError::ErrMountPathProtected);
            }

            for (_, mount_entry) in auth_table.iter() {
                let ent = mount_entry.read()?;
                if ent.path.starts_with(&entry.path) || entry.path.starts_with(&ent.path) {
                    return Err(bv_error_response_status!(409, &format!("path is already in use at {}", &entry.path)));
                }
            }

            let match_mount_path = mounts_router.router.matching_mount(&entry.path)?;
            if !match_mount_path.is_empty() {
                return Err(bv_error_response_status!(409, &format!("path is already in use at {match_mount_path}")));
            }

            let backend_new_func = self.get_auth_backend(&entry.logical_type)?;
            let backend = backend_new_func(self.core.clone())?;

            entry.uuid = generate_uuid();

            let prefix = format!("{}{}/", AUTH_BARRIER_PREFIX, &entry.uuid);
            let view = BarrierView::new(self.barrier.clone(), &prefix);

            let path = format!("{}{}", AUTH_ROUTER_PREFIX, &entry.path);
            let key = entry.path.clone();

            let mount_entry = Arc::new(RwLock::new(entry));

            mounts_router.router.mount(backend, &path, mount_entry.clone(), view)?;

            auth_table.insert(key, mount_entry);
        }

        mounts_router.persist(self.barrier.as_storage()).await?;

        Ok(())
    }

    /// Disable the auth mount at `path`. Once no login can reach it, the
    /// entity aliases of the principals it held are forgotten in every
    /// namespace (T522); that step never fails the disable, and what it could
    /// not do is returned as warnings for the response.
    pub async fn disable_auth(&self, path: &str) -> Result<Vec<String>, RvError> {
        let mounts_router = &self.mounts_router;

        let mut path = path.to_string();
        if !path.ends_with('/') {
            path += "/";
        }

        if path == "token/" {
            return Err(RvError::ErrMountPathProtected);
        }

        let full_path = format!("{}{}", AUTH_ROUTER_PREFIX, &path);
        let view = mounts_router.router.matching_view(&full_path)?;
        let logical_type = match mounts_router.entries.read()?.get(&path) {
            Some(entry) => Some(entry.read()?.logical_type.clone()),
            None => None,
        };

        self.taint_auth_entry(&path).await?;

        mounts_router.router.taint(&full_path)?;

        mounts_router.router.unmount(&full_path)?;

        let mut warnings = Vec::new();
        if let Some(view) = view {
            if let Some(logical_type) = logical_type {
                warnings = self.forget_principal_aliases(&path, &logical_type, &view).await;
            }
            view.clear().await?;
        }

        self.remove_auth_entry(&path).await?;

        Ok(warnings)
    }

    /// Forget in every namespace the aliases of the principals the mount at
    /// `path` holds, keeping a name another mount of its type still holds
    /// (T500's rule). Never fails: problems are logged and returned as warnings.
    async fn forget_principal_aliases(&self, path: &str, logical_type: &str, view: &BarrierView) -> Vec<String> {
        let mount = format!("{AUTH_ROUTER_PREFIX}{path}");
        let source = match self.principals.read() {
            Ok(sources) => sources.get(logical_type).cloned(),
            Err(_) => {
                log::warn!(target: "security", "disabling {mount}: the principal registry is poisoned; no entity alias was forgotten");
                return vec![format!("the entity aliases of the principals of {mount} were not forgotten")];
            }
        };
        let Some(source) = source else {
            // A backend that keeps no principals of its own (OIDC, SAML, ...).
            return Vec::new();
        };
        let Some(identity) = self.core.module_manager().get_module::<IdentityModule>("identity") else {
            return Vec::new();
        };
        let names = match source.principals(view).await {
            Ok(names) => names,
            Err(e) => {
                log::warn!(target: "security", "disabling {mount}: its principals could not be listed ({e}); their entity aliases were not forgotten and the mount's storage is cleared");
                return vec![format!(
                    "the principals of {mount} could not be listed, so their entity aliases were not forgotten: \
                     compare GET identity/entity/aliases (at root and in each namespace) with the principals \
                     of the remaining {logical_type} mounts, and delete each leftover name on a \
                     {logical_type} mount that does not hold it"
                )];
            }
        };
        if names.is_empty() {
            return Vec::new();
        }

        let siblings = self
            .auth_mounts_of_type(logical_type)
            .map(|mounts| mounts.into_iter().filter(|m| m.path != path).collect::<Vec<_>>());
        let decision = Self::decide_keeping(source.as_ref(), siblings, names, &mount).await;
        if !decision.kept.is_empty() {
            log::warn!(target: "security", "disabling {mount}: kept the entity aliases of {} principal(s) another {logical_type} mount still holds: {}", decision.kept.len(), decision.kept.join(", "));
        }

        let mut failed = decision.undecided;
        match identity.forget_principals(&source.alias_mount(), &decision.forget).await {
            Ok(names) => failed.extend(names),
            Err(e) => {
                log::warn!(target: "security", "disabling {mount}: the alias indexes could not be read ({e})");
                failed.extend(decision.forget.iter().cloned());
            }
        }
        log::info!(
            "disabling {mount}: forgot the entity aliases of {} principal(s) in every namespace",
            decision.forget.iter().filter(|name| !failed.contains(name)).count()
        );
        if failed.is_empty() {
            return Vec::new();
        }
        let names = failed.join(", ");
        log::warn!(target: "security", "disabling {mount}: the entity aliases of {} principal(s) were not forgotten: {names}; to retry, delete each name on a {logical_type} mount that does not hold it", failed.len());
        vec![format!(
            "the entity aliases of {} principal(s) were not forgotten ({names}): a principal re-created \
             under one of these names would sign in as its old entity; to retry, delete each name on a \
             {logical_type} mount that does not hold it",
            failed.len()
        )]
    }

    /// T500's keeping rule for a disabled mount's principals: a name another
    /// mount of the type (`siblings`) holds is kept, one none holds is to be
    /// forgotten. Any error while deciding keeps the name and reports it
    /// undecided: a forget can be retried, the plugin-data purge cannot.
    async fn decide_keeping(
        source: &dyn AuthMountPrincipals,
        siblings: Result<Vec<AuthMountView>, RvError>,
        names: Vec<String>,
        mount: &str,
    ) -> KeepDecision {
        let mut decision = KeepDecision::default();
        let siblings = match siblings {
            Ok(siblings) => siblings,
            Err(e) => {
                log::warn!(target: "security", "disabling {mount}: the other mounts of its type could not be listed ({e}); every alias is kept");
                decision.undecided = names;
                return decision;
            }
        };
        'names: for name in names {
            for sibling in &siblings {
                match source.holds(&sibling.view, &name).await {
                    Ok(true) => {
                        decision.kept.push(name);
                        continue 'names;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        log::warn!(target: "security", "disabling {mount}: could not read whether auth/{} holds '{name}' ({e}); its aliases are kept", sibling.path);
                        decision.undecided.push(name);
                        continue 'names;
                    }
                }
            }
            decision.forget.push(name);
        }
        decision
    }

    pub async fn remount_auth(&self, src: &str, dst: &str) -> Result<(), RvError> {
        let mut src = src.to_string();
        let mut dst = dst.to_string();

        if !src.ends_with('/') {
            src += "/";
        }

        if !dst.ends_with('/') {
            dst += "/";
        }

        if !src.starts_with(AUTH_ROUTER_PREFIX) {
            return Err(bv_error_response_status!(400, &format!("cannot remount non-auth mount {src}")));
        }

        if !dst.starts_with(AUTH_ROUTER_PREFIX) {
            return Err(bv_error_response_status!(400, &format!("cannot remount auth mount to non-auth mount {dst}")));
        }

        if is_protect_path(&PROTECTED_AUTHS, &[&src, &dst]) {
            return Err(RvError::ErrMountPathProtected);
        }

        let mounts_router = &self.mounts_router;

        let dst_match = mounts_router.router.matching_mount(&dst)?;
        if !dst_match.is_empty() {
            return Err(RvError::ErrMountPathExist);
        }

        let Some(src_match) = mounts_router.router.matching_mount_entry(&src)? else {
            return Err(RvError::ErrMountNotMatch);
        };

        let src_path;
        {
            let mut src_entry = src_match.write()?;
            src_entry.tainted = true;

            mounts_router.router.taint(&src)?;

            if !(mounts_router.router.matching_mount(&dst)?).is_empty() {
                return Err(RvError::ErrMountPathExist);
            }

            src_path = src_entry.path.clone();
            src_entry.path = dst.as_str().trim_start_matches(AUTH_ROUTER_PREFIX).to_string();
            src_entry.tainted = false;

            std::mem::drop(src_entry);
        }

        if let Err(e) = mounts_router.mounts.persist(self.barrier.as_storage()).await {
            let mut src_entry = src_match.write()?;
            src_entry.path = src_path;
            src_entry.tainted = true;
            return Err(e);
        }

        mounts_router.router.remount(&dst, &src)?;

        mounts_router.router.untaint(&dst)?;

        Ok(())
    }

    pub async fn remove_auth_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts_router.delete(path) {
            self.mounts_router.persist(self.barrier.as_storage()).await?;
        }
        Ok(())
    }

    pub async fn taint_auth_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts_router.set_taint(path, true) {
            self.mounts_router.persist(self.barrier.as_storage()).await?;
        }
        Ok(())
    }

    pub fn teardown_auth(&self) -> Result<(), RvError> {
        let _ = self.mounts_router.mounts.clear();
        // TODO
        let _ = self.mounts_router.router.clear();
        Ok(())
    }

    pub async fn load_auth(&self, hmac_key: Option<&[u8]>, hmac_level: MountEntryHMACLevel) -> Result<(), RvError> {
        let mounts_router = &self.mounts_router;
        if mounts_router.mounts.load(self.barrier.as_storage(), hmac_key, hmac_level).await.is_err() {
            mounts_router.mounts.set_default(DEFAULT_AUTH_MOUNTS.to_vec(), hmac_key)?;
            mounts_router.mounts.persist(self.barrier.as_storage()).await?;
        }

        self.update_auth_mount(hmac_key, hmac_level).await
    }

    pub async fn persist_auth(&self) -> Result<(), RvError> {
        self.mounts_router.persist(self.barrier.as_storage()).await
    }

    pub fn setup_auth(&self) -> Result<(), RvError> {
        self.mounts_router.setup(self.core.clone())
    }

    pub fn get_auth_backend(&self, logical_type: &str) -> Result<Arc<LogicalBackendNewFunc>, RvError> {
        self.mounts_router.get_backend(logical_type)
    }

    pub fn add_auth_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        self.mounts_router.add_backend(logical_type, backend)
    }

    pub fn delete_auth_backend(&self, logical_type: &str) -> Result<(), RvError> {
        self.mounts_router.delete_backend(logical_type)
    }

    async fn update_auth_mount(&self, hmac_key: Option<&[u8]>, hmac_level: MountEntryHMACLevel) -> Result<(), RvError> {
        let mut need_persist = false;
        {
            let mounts = self.mounts_router.mounts.entries.read()?;

            for mount_entry in mounts.values() {
                let mut entry = mount_entry.write()?;
                if entry.table.is_empty() {
                    entry.table = AUTH_TABLE_TYPE.to_string();
                    need_persist = true;
                }

                if entry.hmac.is_empty() && hmac_key.is_some() && hmac_level == MountEntryHMACLevel::Compat {
                    entry.calc_hmac(hmac_key.unwrap())?;
                    need_persist = true;
                }
            }
        }

        if need_persist {
            self.persist_auth().await?;
        }

        Ok(())
    }
}

#[maybe_async::maybe_async]
impl Module for AuthModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn register(self: Arc<Self>, services: &crate::kernel_api::KernelServices) {
        kernel_service::register(self, services);
    }

    fn flush_caches(&self) {
        if let Some(token_store) = self.token_store.load_full() {
            token_store.flush_cache();
        }
    }

    async fn init(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let expiration = ExpirationManager::new(&self.core)?.wrap();
        let token_store = TokenStore::new(&self.core, expiration.clone()).await?.wrap();

        expiration.set_token_store(&token_store)?;

        self.expiration.store(Some(expiration.clone()));
        self.token_store.store(Some(token_store.clone()));

        let ts = token_store.clone();

        let token_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut backend = token_store.new_backend();
            backend.init()?;
            Ok(Arc::new(backend))
        };

        self.add_auth_backend("token", Arc::new(token_backend_new_func))?;
        self.load_auth(Some(&core.hmac_key()), core.mount_entry_hmac_level()).await?;
        self.setup_auth()?;

        if let Some(mounts_monitor) = core.mounts_monitor().as_ref() {
            mounts_monitor.add_mounts_router(self.mounts_router.clone());
        }

        expiration.restore().await?;
        expiration.start_check_expired_lease_entries();

        core.add_handler(ts as Arc<dyn Handler>)?;

        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if let Some(mounts_monitor) = core.mounts_monitor().as_ref() {
            mounts_monitor.remove_mounts_router(self.mounts_router.clone());
        }
        core.delete_handler(self.token_store.load().as_ref().unwrap().clone() as Arc<dyn Handler>)?;
        self.delete_auth_backend("token")?;
        self.teardown_auth()?;
        Ok(())
    }
}

/// T500's keeping rule on disable (T522): an unreadable sibling keeps the
/// name and reports it, never reads as "not held".
#[cfg(test)]
mod keep_rule_tests {
    use super::*;
    use crate::{modules::identity::fault_storage, storage::Storage, storage::StorageEntry};

    /// A mount holds `name` when its storage has a key `name`.
    struct ByKey;

    #[maybe_async::maybe_async]
    impl AuthMountPrincipals for ByKey {
        fn alias_mount(&self) -> String {
            "stub/".to_string()
        }

        async fn principals(&self, view: &BarrierView) -> Result<Vec<String>, RvError> {
            view.list("").await
        }

        async fn holds(&self, view: &BarrierView, name: &str) -> Result<bool, RvError> {
            Ok(view.get(name).await?.is_some())
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn a_name_a_sibling_cannot_answer_for_is_kept_and_reported() {
        let (_, s1) = fault_storage::view("auth/s1/").await;
        let (faulty, s2) = fault_storage::view("auth/s2/").await;
        s1.put(&StorageEntry { key: "carol".into(), value: b"{}".to_vec() }).await.unwrap();
        faulty.fail_under("auth/s2/erin");
        let siblings =
            vec![AuthMountView { path: "s1/".into(), view: s1 }, AuthMountView { path: "s2/".into(), view: s2 }];

        let decision =
            AuthModule::decide_keeping(&ByKey, Ok(siblings), names(&["carol", "dave", "erin"]), "auth/gone/").await;
        let want = KeepDecision { kept: names(&["carol"]), forget: names(&["dave"]), undecided: names(&["erin"]) };
        assert_eq!(decision, want, "erin is kept, never read as not held");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn siblings_that_cannot_be_listed_keep_every_name() {
        let listed = Err(RvError::ErrString("injected".into()));
        let decision = AuthModule::decide_keeping(&ByKey, listed, names(&["carol", "dave"]), "auth/gone/").await;
        assert_eq!(decision, KeepDecision { undecided: names(&["carol", "dave"]), ..Default::default() });
    }
}
