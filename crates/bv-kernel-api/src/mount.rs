//! Simply speaking, the `bastion_vault::mount` module manages the relationship between a 'path' and
//! the real BastionVault module which is responsible for that feature. In BastionVault, everything is
//! exposed to outside by RESTful API, which is defined by 'path'.
//!
//! The binding logic here is managed by `MountEntry` struct.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, OnceLock, RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crossbeam_channel::{select, tick};
use dashmap::DashMap;
use derive_more::Deref;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use bv_errors::RvError;
use bv_storage::{barrier::SecurityBarrier, barrier_view::BarrierView, Storage, StorageEntry};
use bv_utils::{generate_uuid, hmac_sha256_hex, is_protect_path, verify_hmac_sha256_hex};

use crate::{
    ctx::{LogicalBackendNewFunc, MountEntryHMACLevel, VaultCtx},
    router::Router,
};

pub const LOGICAL_BARRIER_PREFIX: &str = "logical/";
pub const CORE_MOUNT_CONFIG_PATH: &str = "core/mounts";
pub const SYSTEM_BARRIER_PREFIX: &str = "sys/";
pub const MOUNT_TABLE_TYPE: &str = "mounts";

/// Resolves a mount type that no statically registered factory covers.
///
/// [`MountsRouter::get_backend`] used to reach into `crate::plugins` itself to
/// turn a `plugin:<name>` mount type into a backend factory. That was the
/// mount table naming the plugin runtime — the wrong direction, and the last
/// edge keeping this file above the runtime in the crate graph. See
/// roadmaps/workspace-decomposition.md § "Cross-layer warts to fix first".
///
/// The runtime registers a resolver instead. `None` means "not a mount type I
/// own", and `get_backend` then reports it unknown exactly as before.
pub type DynamicBackendResolver = dyn Fn(&str) -> Option<Arc<LogicalBackendNewFunc>> + Send + Sync;

static DYNAMIC_BACKEND_RESOLVER: OnceLock<Arc<DynamicBackendResolver>> = OnceLock::new();

/// Install the process-wide resolver consulted by [`MountsRouter::get_backend`].
///
/// The first registration wins and later ones are discarded, which is not a
/// silent fallback but the intended semantics: every caller installs the same
/// resolver, and a process runs many vaults in the test suite.
pub fn set_dynamic_backend_resolver(resolver: Arc<DynamicBackendResolver>) {
    let _ = DYNAMIC_BACKEND_RESOLVER.set(resolver);
}

fn dynamic_backend_resolver() -> Option<&'static Arc<DynamicBackendResolver>> {
    DYNAMIC_BACKEND_RESOLVER.get()
}

/// Whether any of `paths` names a mount the vault owns and refuses to let an
/// operator mount over, unmount or remount (`audit/`, `auth/`, `sys/`).
///
/// The list itself stays private: `Core`'s own mount management lives in the
/// root crate and has to ask the same question, and two copies of a
/// security-relevant allowlist is one too many.
pub fn is_protected_mount(paths: &[&str]) -> bool {
    is_protect_path(&PROTECTED_MOUNTS, paths)
}

lazy_static! {
    static ref PROTECTED_MOUNTS: Vec<&'static str> = vec!["audit/", "auth/", "sys/",];
    static ref DEFAULT_CORE_MOUNTS: Vec<MountEntry> = vec![
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "secret/".to_string(),
            logical_type: "kv-v2".to_string(),
            description: "key/value secret storage".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "resources/".to_string(),
            logical_type: "resource".to_string(),
            description: "infrastructure resource storage".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "files/".to_string(),
            logical_type: "files".to_string(),
            description: "binary file resources (keys, certs, configs)".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "identity/".to_string(),
            logical_type: "identity".to_string(),
            description: "user and application group management".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "resource-group/".to_string(),
            logical_type: "resource-group".to_string(),
            description: "named collections of resources".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "notifications/".to_string(),
            logical_type: "notifications".to_string(),
            description: "in-app notifications, targeting, and delivery channels".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "sys/".to_string(),
            logical_type: "system".to_string(),
            description: "system endpoints used for control, policy and debugging".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "rustion/".to_string(),
            logical_type: "rustion".to_string(),
            description: "Rustion PQC bastion fleet — targets, master cert, recordings, policy".to_string(),
            ..Default::default()
        },
        MountEntry {
            table: MOUNT_TABLE_TYPE.to_string(),
            tainted: false,
            uuid: generate_uuid(),
            path: "ssh-broker/".to_string(),
            logical_type: "ssh-broker".to_string(),
            description: "SSH login-class (broker) policy — shared-credential vs brokered, four-tier lockable".to_string(),
            ..Default::default()
        }
    ];
}

pub struct MountsMonitor {
    core: Arc<dyn VaultCtx>,
    interval: u64,
    tables: Arc<RwLock<Vec<Arc<MountsRouter>>>>,
    running: Arc<AtomicBool>,
    stop_condvar: Arc<(Mutex<bool>, Condvar)>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Deref)]
pub struct MountsRouter {
    #[deref]
    pub mounts: Arc<MountTable>,
    pub router: Arc<Router>,
    pub barrier: Arc<dyn SecurityBarrier>,
    pub barrier_prefix: String,
    pub router_prefix: String,
    pub backends: DashMap<String, Arc<LogicalBackendNewFunc>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountEntry {
    #[serde(default)]
    pub table: String,
    pub tainted: bool,
    pub uuid: String,
    pub path: String,
    pub logical_type: String,
    pub description: String,
    pub options: Option<HashMap<String, String>>,
    #[serde(default)]
    pub hmac: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MountTable {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub id: RwLock<String>,
    pub entries: RwLock<HashMap<String, Arc<RwLock<MountEntry>>>>,
}

impl MountsRouter {
    pub fn new(
        mounts: Arc<MountTable>,
        router: Arc<Router>,
        barrier: Arc<dyn SecurityBarrier>,
        barrier_prefix: &str,
        router_prefix: &str,
    ) -> Self {
        Self {
            mounts,
            router,
            barrier,
            barrier_prefix: barrier_prefix.to_string(),
            router_prefix: router_prefix.to_string(),
            backends: DashMap::new(),
        }
    }

    pub fn setup(&self, core: Arc<dyn VaultCtx>) -> Result<(), RvError> {
        let mounts = self.mounts.entries.read()?;

        for mount_entry in mounts.values() {
            let entry = mount_entry.read()?;
            let barrier_path = format!("{}{}/", self.barrier_prefix, &entry.uuid);

            let backend_new_func = self.get_backend(&entry.logical_type)?;
            let backend = backend_new_func(core.clone())?;

            let view = BarrierView::new(self.barrier.clone(), &barrier_path);
            let path = format!("{}{}", self.router_prefix, &entry.path);

            // Idempotent: a namespace's router may be set up more than once
            // (the shared trie outlives the per-namespace `MountsRouter` cache,
            // and two concurrent `ensure_router` calls can race on first
            // access). Re-mounting the exact same prefix must not error.
            self.router.mount_idempotent(backend, &path, mount_entry.clone(), view)?;

            if entry.tainted {
                self.router.taint(&entry.path)?;
            }
        }

        Ok(())
    }

    pub fn unload(&self) -> Result<(), RvError> {
        self.mounts.clear()
    }

    pub fn get_backend(&self, logical_type: &str) -> Result<Arc<LogicalBackendNewFunc>, RvError> {
        if let Some(backend) = self.backends.get(logical_type) {
            return Ok(backend.clone());
        }
        // Mount types that no static table can hold — today only
        // `plugin:<name>` — are resolved by whoever registered a
        // [`DynamicBackendResolver`]. See that type for why the mount table
        // asks rather than calls.
        if let Some(resolver) = dynamic_backend_resolver() {
            if let Some(backend) = resolver(logical_type) {
                return Ok(backend);
            }
        }
        Err(RvError::ErrCoreLogicalBackendNoExist)
    }

    pub fn add_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        let result = self.backends.entry(logical_type.to_string()).or_try_insert_with(|| Ok::<_, ()>(backend));

        if result.is_err() {
            return Err(RvError::ErrCoreLogicalBackendExist);
        }

        Ok(())
    }

    pub fn delete_backend(&self, logical_type: &str) -> Result<(), RvError> {
        self.backends.remove(logical_type);
        Ok(())
    }
}

#[maybe_async::maybe_async]
impl MountsRouter {
    /// Mount a single backend into this router, honouring the router's own
    /// `barrier_prefix` and `router_prefix`. This is the multi-tenant analogue
    /// of [`Core::mount`]: a namespace's router carries `barrier_prefix =
    /// namespaces/<uuid>/logical/` and `router_prefix = <ns_path>/`, so the
    /// same logic yields a mount that is storage-isolated under the namespace
    /// and addressable at `<ns_path>/<mount>` in the shared router trie.
    pub async fn mount_one(&self, core: Arc<dyn VaultCtx>, me: &MountEntry, hmac_key: &[u8]) -> Result<(), RvError> {
        let mut entry = me.clone();
        if !entry.path.ends_with('/') {
            entry.path += "/";
        }
        if is_protect_path(&PROTECTED_MOUNTS, &[&entry.path]) {
            return Err(RvError::ErrMountPathProtected);
        }
        if entry.table.is_empty() {
            entry.table = MOUNT_TABLE_TYPE.to_string();
        }

        let router_path = format!("{}{}", self.router_prefix, &entry.path);
        if !self.router.matching_mount(&router_path)?.is_empty() {
            return Err(RvError::ErrMountPathExist);
        }

        let backend_new_func = self.get_backend(&entry.logical_type)?;
        let backend = backend_new_func(core)?;

        entry.uuid = generate_uuid();
        let barrier_path = format!("{}{}/", self.barrier_prefix, &entry.uuid);
        let view = BarrierView::new(self.barrier.clone(), &barrier_path);

        entry.calc_hmac(hmac_key)?;

        let table_key = entry.path.clone();
        let mount_entry = Arc::new(RwLock::new(entry));
        self.router.mount(backend, &router_path, mount_entry.clone(), view)?;
        self.mounts.entries.write()?.insert(table_key, mount_entry);

        self.mounts.persist(self.barrier.as_storage()).await?;
        Ok(())
    }

    /// Unmount a single mount from this router (namespace analogue of
    /// [`Core::unmount`]). `path` is the mount-relative path (e.g. `secret/`).
    pub async fn unmount_one(&self, path: &str) -> Result<(), RvError> {
        let mut path = path.to_string();
        if !path.ends_with('/') {
            path += "/";
        }
        if is_protect_path(&PROTECTED_MOUNTS, &[&path]) {
            return Err(RvError::ErrMountPathProtected);
        }
        let router_path = format!("{}{}", self.router_prefix, &path);
        let match_mount = self.router.matching_mount(&router_path)?;
        if match_mount.is_empty() || match_mount != router_path {
            return Err(RvError::ErrMountNotMatch);
        }

        if let Some(view) = self.router.matching_view(&router_path)? {
            self.router.taint(&router_path)?;
            self.router.unmount(&router_path)?;
            view.clear().await?;
        }
        self.mounts.delete(&path);
        self.mounts.persist(self.barrier.as_storage()).await?;
        Ok(())
    }
}

impl MountEntry {
    pub fn new(table: &str, path: &str, logical_type: &str, desc: &str) -> Self {
        Self {
            table: table.into(),
            tainted: false,
            uuid: String::new(),
            path: path.to_string(),
            logical_type: logical_type.to_string(),
            description: desc.to_string(),
            options: None,
            hmac: String::new(),
        }
    }

    pub fn calc_hmac(&mut self, key: &[u8]) -> Result<(), RvError> {
        let msg = self.get_hmac_msg();
        self.hmac = hmac_sha256_hex(key, msg.as_bytes())?;

        Ok(())
    }

    pub fn verify_hmac(&self, key: &[u8]) -> Result<bool, RvError> {
        let msg = self.get_hmac_msg();
        verify_hmac_sha256_hex(key, msg.as_bytes(), &self.hmac)
    }

    pub fn get_hmac_msg(&self) -> String {
        let mut msg = format!("{}-{}-{}-{}", self.table, self.path, self.logical_type, self.description);

        if let Some(options) = &self.options {
            let options_btree: BTreeMap<String, String> = options.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            for (key, value) in options_btree.iter() {
                msg = format!("{msg}-{key}:{value}");
            }
        }

        msg
    }
}

#[maybe_async::maybe_async]
impl MountTable {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string(), id: RwLock::new(generate_uuid()), entries: RwLock::new(HashMap::new()) }
    }

    pub fn clear(&self) -> Result<(), RvError> {
        let mut entries_write = self.entries.write()?;
        entries_write.clear();
        Ok(())
    }

    pub fn get(&self, path: &str) -> Result<Option<Arc<RwLock<MountEntry>>>, RvError> {
        let mounts = self.entries.read()?;
        Ok(mounts.get(path).cloned())
    }

    pub fn delete(&self, path: &str) -> bool {
        match self.entries.write() {
            Ok(mut mounts) => mounts.remove(path).is_some(),
            Err(_) => false,
        }
    }

    pub fn set_taint(&self, path: &str, value: bool) -> bool {
        match self.entries.write() {
            Ok(mounts) => {
                if let Some(mount_entry) = mounts.get(path) {
                    if let Ok(mut entry) = mount_entry.write() {
                        entry.tainted = value;
                        return true;
                    }
                }
            }
            Err(_) => {
                return false;
            }
        }
        false
    }

    pub fn set_default(&self, mounts: Vec<MountEntry>, hmac_key: Option<&[u8]>) -> Result<(), RvError> {
        let mut table = self.entries.write()?;
        for mut mount in mounts {
            if let Some(key) = hmac_key {
                mount.calc_hmac(key)?;
            }
            table.insert(mount.path.clone(), Arc::new(RwLock::new(mount)));
        }
        Ok(())
    }

    pub async fn load_or_default(
        &self,
        storage: &dyn Storage,
        hmac_key: Option<&[u8]>,
        hmac_level: MountEntryHMACLevel,
    ) -> Result<(), RvError> {
        match self.load(storage, hmac_key, hmac_level).await {
            Err(RvError::ErrConfigLoadFailed) => {
                self.set_default(DEFAULT_CORE_MOUNTS.to_vec(), hmac_key)?;
                self.persist(storage).await?;
                return Ok(());
            }
            Err(err) => {
                return Err(err);
            }
            _ => {}
        }

        self.mount_update(storage, hmac_key, hmac_level).await
    }

    pub async fn load(
        &self,
        storage: &dyn Storage,
        hmac_key: Option<&[u8]>,
        hmac_level: MountEntryHMACLevel,
    ) -> Result<Option<()>, RvError> {
        let entry = storage.get(&self.path).await?;
        if entry.is_none() {
            return Err(RvError::ErrConfigLoadFailed);
        }

        let new_table: MountTable = serde_json::from_slice(entry.unwrap().value.as_slice())?;
        let mut new_entries = new_table.entries.write()?;
        let mut entries = self.entries.write()?;
        let new_id = new_table.id.read()?;
        let mut id = self.id.write()?;

        if id.to_string() == new_id.to_string() && entries.len() == new_entries.len() {
            return Ok(None);
        }

        entries.clear();

        if hmac_level != MountEntryHMACLevel::None && hmac_key.is_some() {
            let key = hmac_key.unwrap();
            new_entries.retain(|_, me| {
                let entry = me.read().unwrap();
                match entry.verify_hmac(key) {
                    Ok(ret) => {
                        if !ret {
                            log::error!("load mount entry failed, path: {}, err: HMAC validation failed", entry.path);
                        }
                        ret
                    }
                    Err(e) => {
                        log::error!("load mount entry failed, path: {}, err: {:?}", entry.path, e);
                        false
                    }
                }
            });
        }

        entries.extend(new_entries.drain());
        *id = new_id.to_string();

        Ok(Some(()))
    }

    pub async fn persist(&self, storage: &dyn Storage) -> Result<(), RvError> {
        let value = serde_json::to_string(self)?;
        storage.put(&StorageEntry { key: self.path.clone(), value: value.into_bytes() }).await?;
        Ok(())
    }

    async fn mount_update(
        &self,
        storage: &dyn Storage,
        hmac_key: Option<&[u8]>,
        hmac_level: MountEntryHMACLevel,
    ) -> Result<(), RvError> {
        let mut need_persist = false;
        {
            let mounts = self.entries.read()?;

            for mount_entry in mounts.values() {
                let mut entry = mount_entry.write()?;
                if entry.table.is_empty() {
                    entry.table = MOUNT_TABLE_TYPE.to_string();
                    need_persist = true;
                }

                if entry.hmac.is_empty() && hmac_key.is_some() && hmac_level == MountEntryHMACLevel::Compat {
                    entry.calc_hmac(hmac_key.unwrap())?;
                    need_persist = true;
                }
            }
        }

        // Upgrade path: ensure any default core mounts that were introduced
        // after the original install are present. Only add missing ones; never
        // overwrite an existing entry.
        {
            let mut entries = self.entries.write()?;
            for default in DEFAULT_CORE_MOUNTS.iter() {
                if entries.contains_key(&default.path) {
                    continue;
                }
                let mut new_entry = default.clone();
                if let Some(key) = hmac_key {
                    new_entry.calc_hmac(key)?;
                }
                entries.insert(default.path.clone(), Arc::new(RwLock::new(new_entry)));
                need_persist = true;
            }
        }

        if need_persist {
            self.persist(storage).await?;
        }

        Ok(())
    }
}

impl MountsMonitor {
    pub fn new(core: Arc<dyn VaultCtx>, interval: u64) -> Self {
        Self {
            core,
            interval,
            tables: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            stop_condvar: Arc::new((Mutex::new(false), Condvar::new())),
            handle: Mutex::new(None),
        }
    }

    pub fn add_mounts_router(&self, table: Arc<MountsRouter>) {
        let mut tables = self.tables.write().unwrap();
        tables.push(table);
    }

    pub fn remove_mounts_router(&self, table: Arc<MountsRouter>) {
        let mut tables = self.tables.write().unwrap();
        tables.retain(|mt| mt.path != table.path);
    }

    pub fn start(&self) {
        if self.running.load(Ordering::Relaxed) {
            return;
        }

        self.running.store(true, Ordering::Relaxed);
        let running_flag = self.running.clone();
        let stop_condvar = self.stop_condvar.clone();

        let core = self.core.clone();
        let mount_tables = self.tables.clone();

        let ticker = tick(Duration::from_secs(self.interval));
        let handle = thread::spawn(move || {
            // Was `actix_rt::Runtime::new()`, which is this builder plus a
            // `LocalSet`. The monitor's future spawns nothing and is `Send`,
            // so the `LocalSet` bought nothing — and actix-web must not be a
            // dependency of a crate every leaf engine compiles against. Same
            // reason the DoS and metrics middlewares stayed in the root crate.
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                while running_flag.load(Ordering::Relaxed) {
                    select! {
                        recv(ticker) -> _ => {
                            let mut changed = false;

                            // Snapshot the routers and release the guard before the
                            // awaits below. `std::sync::RwLock` is not guaranteed fair:
                            // a writer arriving while this future is parked on
                            // `table.load` can block every subsequent reader, wedging
                            // the monitor on a current-thread runtime. The elements are
                            // `Arc`s, so cloning the vec is just refcount bumps.
                            let tables: Vec<Arc<MountsRouter>> = mount_tables.read().unwrap().clone();

                            for table in tables.iter() {
                                #[cfg(not(feature = "sync_handler"))]
                                match table.load(core.barrier().as_storage(), Some(&core.hmac_key()), core.mount_entry_hmac_level()).await {
                                    Ok(Some(())) => changed = true,
                                    _ => continue,
                                }
                                #[cfg(feature = "sync_handler")]
                                match table.load(core.barrier().as_storage(), Some(&core.hmac_key()), core.mount_entry_hmac_level()) {
                                    Ok(Some(())) => changed = true,
                                    _ => continue,
                                }
                            }

                            if changed {
                                let _ = core.router().clear();

                                for table in tables.iter() {
                                    if let Err(err) = table.setup(core.clone()) {
                                        log::error!("update mount table failed, path: {}, err: {:?}", table.path, err);
                                    }
                                }
                            }
                        }
                        default => {
                            let (stop_mutex, stop_condvar) = &*stop_condvar;
                            let stop_guard = stop_mutex.lock().unwrap();
                            if *stop_guard {
                                break;
                            }
                            let _ = stop_condvar.wait_timeout(stop_guard, Duration::from_millis(10)).unwrap();
                        }
                    }
                }
            });
        });

        self.handle.lock().unwrap().replace(handle);
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let (stop_mutex, stop_condvar) = &*self.stop_condvar;
        {
            let mut stop_guard = stop_mutex.lock().unwrap();
            *stop_guard = true;
        }
        stop_condvar.notify_one();
        if let Some(handle) = self.handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}
