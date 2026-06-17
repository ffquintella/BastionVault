//! The `bastion_vault::core` module implements several key functions that are
//! in charge of the whole process of BastionVault. For instance, to seal or unseal the BastionVault we
//! have the `seal()` and `unseal()` functions in this module. Also, the `handle_request()`
//! function in this module is to route an API call to its correct backend and get the result back
//! to the caller.
//!
//! This module is very low-level and usually it should not disturb end users and module developers
//! of BastionVault.

use std::{
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
};

use arc_swap::{ArcSwap, ArcSwapOption};
use go_defer::defer;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    cache::CacheConfig,
    cli::config::MountEntryHMACLevel,
    errors::RvError,
    handler::{AuthHandler, HandlePhase, Handler},
    logical::{Backend, Request, Response},
    module_manager::ModuleManager,
    modules::auth::AuthModule,
    mount::{
        MountTable, MountsMonitor, MountsRouter, CORE_MOUNT_CONFIG_PATH, LOGICAL_BARRIER_PREFIX, SYSTEM_BARRIER_PREFIX,
    },
    router::Router,
    shamir::{ShamirSecret, SHAMIR_OVERHEAD},
    storage::{
        barrier::SecurityBarrier, barrier_view::BarrierView, new_barrier, physical, Backend as PhysicalBackend,
        BackendEntry as PhysicalBackendEntry, BarrierType, Storage, StorageEntry,
    },
    utils::BHashSet,
};

pub type LogicalBackendNewFunc = dyn Fn(Arc<Core>) -> Result<Arc<dyn Backend>, RvError> + Send + Sync;

const SEAL_CONFIG_PATH: &str = "core/seal-config";
const DEPRECATED_UNSEAL_KEY_SET_PATH: &str = "core/used-unseal-keys-set";
/// System-view key mirroring the FerroGate `require_machine_identity` flag.
/// The canonical operator value lives in the `auth/ferrogate/config` blob; this
/// mirror is the restart-durable enforcement cache the token layer reads
/// (loaded into [`Core::require_machine_identity`] at unseal).
const FERROGATE_REQUIRE_MI_PATH: &str = "core/ferrogate-require-machine-identity";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealConfig {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

impl SealConfig {
    pub fn validate(&self) -> Result<(), RvError> {
        if self.secret_threshold > self.secret_shares {
            return Err(RvError::ErrCoreSealConfigInvalid);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct InitResult {
    pub secret_shares: Zeroizing<Vec<Vec<u8>>>,
    pub root_token: String,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CoreState {
    #[zeroize(skip)]
    pub system_view: Option<Arc<BarrierView>>,
    pub sealed: bool,
    pub hmac_key: Vec<u8>,
    unseal_key_shares: Vec<Vec<u8>>,
    kek: Vec<u8>,
}

pub struct Core {
    pub self_ptr: Weak<Core>,
    pub physical: Arc<dyn PhysicalBackend>,
    pub barrier: Arc<dyn SecurityBarrier>,
    /// Root-namespace mount router. Swappable so re-root activation can rebuild
    /// it at unseal pointing at `namespaces/<root_uuid>/…` (see
    /// [`Core::root_storage_prefix`]). Access via [`Core::mounts_router`].
    pub mounts_router_swap: ArcSwap<MountsRouter>,
    /// Storage-prefix root for the root tenant. Empty (legacy `logical/`,
    /// `sys/`, `core/mounts`) unless re-root activation is in effect, in which
    /// case it is `namespaces/<root_uuid>/`. Set at `post_unseal`.
    pub root_storage_prefix: ArcSwap<String>,
    pub router: Arc<Router>,
    pub handlers: ArcSwap<Vec<Arc<dyn Handler>>>,
    pub auth_handlers: ArcSwap<Vec<Arc<dyn AuthHandler>>>,
    pub module_manager: ModuleManager,
    pub mount_entry_hmac_level: MountEntryHMACLevel,
    pub mounts_monitor: ArcSwapOption<MountsMonitor>,
    pub mounts_monitor_interval: u64,
    /// Cache subsystem configuration. Slice 1 wires this through but only
    /// `policy_cache_size` is consumed today (by `PolicyStore::new`). Token
    /// and secret caches will read from this in later slices.
    pub cache_config: CacheConfig,
    pub state: ArcSwap<CoreState>,
    /// Audit broker — Some once the vault is unsealed and the
    /// audit subsystem is ready. Handle is installed by
    /// `post_unseal_init_audit` and cleared on seal.
    pub audit_broker: ArcSwapOption<crate::audit::AuditBroker>,
    /// In-memory preview store backing the two-step
    /// `/v1/sys/exchange/import/preview` -> `/import/apply` flow.
    /// Tokens are TTL'd, single-use, and owner-bound. State is
    /// process-local on purpose: previews carry decrypted plaintext, so
    /// keeping them out of the barrier minimises the persistence surface.
    pub exchange_preview_store: crate::exchange::PreviewStore,
    /// Fast-path mirror of the FerroGate mount's `require_machine_identity`
    /// flag. When `true`, every authenticated request must present a
    /// FerroGate machine-bound token (or a root token) — enforced in
    /// [`crate::modules::auth::token_store::TokenStore::pre_route`]. Loaded
    /// from the system view at `post_unseal` and updated whenever the
    /// `auth/ferrogate/config` write handler runs, so the token layer never
    /// touches storage to read it.
    pub require_machine_identity: Arc<AtomicBool>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self { system_view: None, sealed: true, unseal_key_shares: Vec::new(), hmac_key: Vec::new(), kek: Vec::new() }
    }
}

impl Default for Core {
    fn default() -> Self {
        let backend: Arc<dyn PhysicalBackend> = Arc::new(physical::mock::MockBackend::new());
        let barrier = new_barrier(BarrierType::Chacha20Poly1305, backend.clone());
        let router = Arc::new(Router::new());

        Core {
            self_ptr: Weak::new(),
            physical: backend,
            barrier: barrier.clone(),
            router: router.clone(),
            mounts_router_swap: ArcSwap::from_pointee(MountsRouter::new(
                Arc::new(MountTable::new(CORE_MOUNT_CONFIG_PATH)),
                router.clone(),
                barrier.clone(),
                LOGICAL_BARRIER_PREFIX,
                "",
            )),
            root_storage_prefix: ArcSwap::from_pointee(String::new()),
            handlers: ArcSwap::from_pointee(vec![router]),
            auth_handlers: ArcSwap::from_pointee(Vec::new()),
            module_manager: ModuleManager::new(),
            mount_entry_hmac_level: MountEntryHMACLevel::None,
            mounts_monitor: ArcSwapOption::empty(),
            mounts_monitor_interval: 0,
            cache_config: CacheConfig::default(),
            state: ArcSwap::from_pointee(CoreState::default()),
            audit_broker: ArcSwapOption::empty(),
            exchange_preview_store: crate::exchange::PreviewStore::default(),
            require_machine_identity: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[maybe_async::maybe_async]
impl Core {
    pub fn new(backend: Arc<dyn PhysicalBackend>) -> Self {
        Self::new_with_barrier(backend, BarrierType::Chacha20Poly1305)
    }

    pub fn new_with_barrier(backend: Arc<dyn PhysicalBackend>, barrier_type: BarrierType) -> Self {
        let barrier = new_barrier(barrier_type, backend.clone());
        let router = Arc::new(Router::new());

        Core {
            handlers: ArcSwap::from_pointee(vec![router.clone()]),
            physical: backend,
            barrier: barrier.clone(),
            router: router.clone(),
            mounts_router_swap: ArcSwap::from_pointee(MountsRouter::new(
                Arc::new(MountTable::new(CORE_MOUNT_CONFIG_PATH)),
                router,
                barrier,
                LOGICAL_BARRIER_PREFIX,
                "",
            )),
            ..Default::default()
        }
    }

    pub fn wrap(self) -> Arc<Self> {
        let mut wrap_self = Arc::new(self);
        let weak_self = Arc::downgrade(&wrap_self);
        unsafe {
            let ptr_self = Arc::into_raw(wrap_self) as *mut Self;
            (*ptr_self).self_ptr = weak_self;
            wrap_self = Arc::from_raw(ptr_self);
        }

        wrap_self
    }

    /// The current root-namespace mount router. Cheap `Arc` clone; callers hold
    /// it for the duration of an operation. Swapped only at unseal by re-root
    /// activation, so a held handle stays consistent for the call.
    pub fn mounts_router(&self) -> Arc<MountsRouter> {
        self.mounts_router_swap.load_full()
    }

    /// Barrier prefix for the root tenant's logical mounts — `logical/` by
    /// default, or `namespaces/<root_uuid>/logical/` when re-root activation is
    /// in effect.
    pub fn root_logical_prefix(&self) -> String {
        format!("{}{}", self.root_storage_prefix.load(), LOGICAL_BARRIER_PREFIX)
    }

    /// Barrier prefix for the root tenant's system view.
    pub fn root_system_prefix(&self) -> String {
        format!("{}{}", self.root_storage_prefix.load(), SYSTEM_BARRIER_PREFIX)
    }

    /// Barrier key for the root tenant's mount-table config.
    pub fn root_mount_config_path(&self) -> String {
        format!("{}{}", self.root_storage_prefix.load(), CORE_MOUNT_CONFIG_PATH)
    }

    /// Repoint the root tenant's storage at `namespaces/<root_uuid>/…` (re-root
    /// activation). Sets [`Core::root_storage_prefix`], rebuilds the system view
    /// and the root mount router at the new prefix. Called once at the top of
    /// `post_unseal`, before any view/mount-table use, so every downstream
    /// subsystem (policies, identity, audit, mounts) builds on the active root.
    fn activate_reroot(&self, root_uuid: &str) -> Result<(), RvError> {
        self.root_storage_prefix.store(Arc::new(format!("namespaces/{root_uuid}/")));

        let mut state = (*self.state.load_full()).clone();
        state.system_view =
            Some(Arc::new(BarrierView::new(self.barrier.clone(), &self.root_system_prefix())));
        self.state.store(Arc::new(state));

        let new_router = MountsRouter::new(
            Arc::new(MountTable::new(&self.root_mount_config_path())),
            self.router.clone(),
            self.barrier.clone(),
            &self.root_logical_prefix(),
            "",
        );
        self.mounts_router_swap.store(Arc::new(new_router));
        Ok(())
    }

    pub async fn inited(&self) -> Result<bool, RvError> {
        self.barrier.inited().await
    }

    pub async fn init(&self, seal_config: &SealConfig) -> Result<InitResult, RvError> {
        let inited = self.inited().await?;
        if inited {
            return Err(RvError::ErrBarrierAlreadyInit);
        }

        seal_config.validate()?;

        // Encode the seal configuration
        let serialized_seal_config = serde_json::to_string(seal_config)?;

        // Store the seal configuration
        let pe = PhysicalBackendEntry {
            key: SEAL_CONFIG_PATH.to_string(),
            value: serialized_seal_config.as_bytes().to_vec(),
        };
        self.physical.put(&pe).await?;

        let deprecated_key_set = BHashSet::default();
        let pe = PhysicalBackendEntry {
            key: DEPRECATED_UNSEAL_KEY_SET_PATH.to_string(),
            value: serde_json::to_string(&deprecated_key_set)?.as_bytes().to_vec(),
        };
        self.physical.put(&pe).await?;

        let barrier = &self.barrier;
        // Generate a key encryption key, will be zeroized on drop.
        let kek = barrier.generate_key()?;

        // Initialize the barrier
        barrier.init(kek.deref().as_slice()).await?;

        let mut init_result = InitResult { secret_shares: Zeroizing::new(Vec::new()), root_token: String::new() };

        // Unseal the barrier
        barrier.unseal(kek.deref().as_slice()).await?;

        let state_old = self.state.load_full();
        let mut state = (*self.state.load_full()).clone();

        state.hmac_key = barrier.derive_hmac_key()?;
        state.system_view = Some(Arc::new(BarrierView::new(barrier.clone(), SYSTEM_BARRIER_PREFIX)));
        state.sealed = false;
        state.kek = kek.deref().clone();
        self.state.store(Arc::new(state));

        if seal_config.secret_shares == 1 {
            init_result.secret_shares.deref_mut().push(kek.deref().clone());
        } else {
            init_result.secret_shares = self.generate_unseal_keys().await?;
        }

        defer! (
            // Ensure the barrier is re-sealed
            let _ = barrier.seal();
            self.state.store(state_old);
        );

        // Perform initial setup
        self.post_unseal().await?;

        // Generate a new root token
        if let Some(auth_module) = self.module_manager.get_module::<AuthModule>("auth") {
            let te = auth_module.token_store.load().as_ref().unwrap().root_token().await?;
            init_result.root_token = te.id;
        } else {
            log::error!("get auth module failed!");
        }

        // Prepare to re-seal
        self.pre_seal()?;

        Ok(init_result)
    }

    pub fn get_system_view(&self) -> Option<Arc<BarrierView>> {
        self.state.load().system_view.clone()
    }

    /// Persist the FerroGate `require_machine_identity` enforcement flag to the
    /// system view and update the in-memory fast-path mirror. Called by the
    /// `auth/ferrogate/config` write handler. A `false` value is persisted too
    /// (rather than deleting the key) so the stored state is unambiguous.
    pub async fn set_require_machine_identity(&self, required: bool) -> Result<(), RvError> {
        if let Some(view) = self.get_system_view() {
            let entry = StorageEntry {
                key: FERROGATE_REQUIRE_MI_PATH.to_string(),
                value: if required { b"true".to_vec() } else { b"false".to_vec() },
            };
            view.put(&entry).await?;
        }
        self.require_machine_identity.store(required, Ordering::Relaxed);
        Ok(())
    }

    /// Load the FerroGate `require_machine_identity` flag from the system view
    /// into the in-memory mirror. Absent key (mount never configured) ⇒
    /// `false`. Called once at `post_unseal` so the very first authenticated
    /// request after unseal sees the correct, restart-durable value.
    pub async fn load_require_machine_identity(&self) -> Result<(), RvError> {
        let required = match self.get_system_view() {
            Some(view) => view
                .get(FERROGATE_REQUIRE_MI_PATH)
                .await?
                .is_some_and(|e| e.value == b"true"),
            None => false,
        };
        self.require_machine_identity.store(required, Ordering::Relaxed);
        Ok(())
    }

    pub fn get_logical_backend(&self, logical_type: &str) -> Result<Arc<LogicalBackendNewFunc>, RvError> {
        self.mounts_router().get_backend(logical_type)
    }

    pub fn add_logical_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        self.mounts_router().add_backend(logical_type, backend)
    }

    pub fn delete_logical_backend(&self, logical_type: &str) -> Result<(), RvError> {
        self.mounts_router().delete_backend(logical_type)
    }

    pub fn add_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        let handlers = self.handlers.load();
        if handlers.iter().any(|h| h.name() == handler.name()) {
            return Err(RvError::ErrCoreHandlerExist);
        }

        let mut handlers = (*self.handlers.load_full()).clone();

        handlers.push(handler);
        self.handlers.store(Arc::new(handlers));
        Ok(())
    }

    pub fn delete_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        let mut handlers = (*self.handlers.load_full()).clone();
        handlers.retain(|h| h.name() != handler.name());
        self.handlers.store(Arc::new(handlers));
        Ok(())
    }

    pub fn add_auth_handler(&self, auth_handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        let auth_handlers = self.auth_handlers.load();
        if auth_handlers.iter().any(|h| h.name() == auth_handler.name()) {
            return Err(RvError::ErrCoreHandlerExist);
        }

        let mut auth_handlers = (*self.auth_handlers.load_full()).clone();

        auth_handlers.push(auth_handler);
        self.auth_handlers.store(Arc::new(auth_handlers));

        // update auth_module
        if let Some(auth_module) = self.module_manager.get_module::<AuthModule>("auth") {
            auth_module.set_auth_handlers(self.auth_handlers.load().clone());
        }

        Ok(())
    }

    pub fn delete_auth_handler(&self, auth_handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        let mut auth_handlers = (*self.auth_handlers.load_full()).clone();
        auth_handlers.retain(|h| h.name() != auth_handler.name());
        self.auth_handlers.store(Arc::new(auth_handlers));

        // update auth_module
        if let Some(auth_module) = self.module_manager.get_module::<AuthModule>("auth") {
            auth_module.set_auth_handlers(self.auth_handlers.load().clone());
        }

        Ok(())
    }

    pub async fn seal_config(&self) -> Result<SealConfig, RvError> {
        let pe = self.physical.get(SEAL_CONFIG_PATH).await?;

        if pe.is_none() {
            return Err(RvError::ErrCoreSealConfigNotFound);
        }

        let config: SealConfig = serde_json::from_slice(pe.unwrap().value.as_slice())?;
        config.validate()?;
        Ok(config)
    }

    pub async fn deprecated_unseal_keys_set(&self) -> Result<BHashSet, RvError> {
        let pe = self
            .physical
            .get(DEPRECATED_UNSEAL_KEY_SET_PATH)
            .await?
            .ok_or(RvError::ErrCoreDeprecatedUnsealKeySetNotFound)?;
        let used_key_set: BHashSet = serde_json::from_slice(pe.value.as_slice())?;
        Ok(used_key_set)
    }

    pub fn sealed(&self) -> bool {
        self.state.load().sealed
    }

    pub fn unseal_progress(&self) -> usize {
        self.state.load().unseal_key_shares.len()
    }

    pub async fn do_unseal(&self, key: &[u8], once: bool) -> Result<bool, RvError> {
        let inited = self.barrier.inited().await?;
        if !inited {
            return Err(RvError::ErrBarrierNotInit);
        }

        let sealed = self.barrier.sealed()?;
        if !sealed {
            return Err(RvError::ErrBarrierUnsealed);
        }

        let (min, mut max) = self.barrier.key_length_range();
        max += SHAMIR_OVERHEAD;
        if key.len() < min || key.len() > max {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        let mut state = (*self.state.load_full()).clone();
        let config = self.seal_config().await?;
        if state.unseal_key_shares.iter().any(|v| *v == key) {
            return Ok(false);
        }

        let mut deprecated_key_set = self.deprecated_unseal_keys_set().await;
        if let Ok(deprecated_key_set) = &deprecated_key_set {
            if deprecated_key_set.contains(key) {
                return Err(RvError::ErrBarrierKeyDeprecated);
            }
        }

        state.unseal_key_shares.push(key.to_vec());
        if state.unseal_key_shares.len() < config.secret_threshold as usize {
            self.state.store(Arc::new(state));
            return Ok(false);
        }

        let kek: Zeroizing<Vec<u8>>;
        if config.secret_threshold == 1 {
            kek = Zeroizing::new(state.unseal_key_shares[0].clone());
        } else if let Some(res) = ShamirSecret::combine(state.unseal_key_shares.clone()) {
            kek = Zeroizing::new(res);
        } else {
            //TODO
            state.unseal_key_shares.clear();
            self.state.store(Arc::new(state));
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        // Unseal the barrier
        if let Err(e) = self.barrier.unseal(kek.as_slice()).await {
            state.unseal_key_shares.clear();
            self.state.store(Arc::new(state));
            return Err(e);
        }

        let unseal_key_shares = Zeroizing::new(state.unseal_key_shares.clone());
        state.unseal_key_shares.clear();
        state.hmac_key = self.barrier.derive_hmac_key()?;
        state.system_view = Some(Arc::new(BarrierView::new(self.barrier.clone(), SYSTEM_BARRIER_PREFIX)));
        state.sealed = false;
        state.kek = kek.deref().clone();
        self.state.store(Arc::new(state));

        log::info!(target: "security", "vault unsealed");

        // Perform initial setup
        if let Err(e) = self.post_unseal().await {
            let mut state = (*self.state.load_full()).clone();
            state.unseal_key_shares.clear();
            state.kek.clear();
            state.hmac_key.clear();
            state.system_view = None;
            state.sealed = true;
            self.state.store(Arc::new(state));
            return Err(e);
        }

        if once {
            if let Ok(deprecated_key_set) = &mut deprecated_key_set {
                for key in unseal_key_shares.iter() {
                    deprecated_key_set.insert(key);
                }

                let pe = PhysicalBackendEntry {
                    key: DEPRECATED_UNSEAL_KEY_SET_PATH.to_string(),
                    value: serde_json::to_string(deprecated_key_set)?.as_bytes().to_vec(),
                };
                self.physical.put(&pe).await?;
            }
        }

        Ok(true)
    }

    pub async fn unseal(&self, key: &[u8]) -> Result<bool, RvError> {
        self.do_unseal(key, false).await
    }

    /// Unseals the bastion_vault once and immediately generates new unseal keys.
    ///
    /// This method performs a one-time unseal operation that automatically invalidates
    /// the used unseal keys and generates a fresh set of keys for future use. This is
    /// a security feature that prevents replay attacks and ensures that unseal keys
    /// can only be used once.
    ///
    /// # Arguments
    /// - `key`: The unseal key to use for the unseal operation
    ///
    /// # Returns
    /// A `Result` containing new unseal keys if successful, or an error if the operation fails.
    ///
    /// # Errors
    /// - Returns `RvError::ErrBarrierUnsealing` if the unseal operation fails or insufficient keys
    /// - Returns errors from `do_unseal()` if the unseal process encounters issues
    /// - Returns errors from `generate_unseal_keys()` if key generation fails
    ///
    /// # Security Features
    /// - Marks used unseal keys as deprecated to prevent reuse
    /// - Automatically generates fresh unseal keys after successful unseal
    /// - Provides protection against replay attacks
    /// - Ensures forward secrecy by invalidating old keys
    ///
    /// # Usage
    /// This method is typically used in high-security environments where unseal keys
    /// should only be valid for a single use, or in automated systems that need to
    /// rotate keys after each unseal operation.
    pub async fn unseal_once(&self, key: &[u8]) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        let unseal = self.do_unseal(key, true).await?;
        if unseal {
            self.generate_unseal_keys().await
        } else {
            Err(RvError::ErrBarrierUnsealing)
        }
    }

    pub async fn seal(&self) -> Result<(), RvError> {
        let inited = self.barrier.inited().await?;
        if !inited {
            return Err(RvError::ErrBarrierNotInit);
        }

        let sealed = self.barrier.sealed()?;
        if sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        self.pre_seal()?;

        let mut state = (*self.state.load_full()).clone();
        state.sealed = true;
        state.system_view = None;
        state.unseal_key_shares.clear();
        state.hmac_key.clear();
        state.kek.clear();
        self.state.store(Arc::new(state));

        log::info!(target: "security", "vault sealed");
        self.barrier.seal()
    }

    /// Generates new unseal keys using Shamir's Secret Sharing.
    ///
    /// This method creates a new set of unseal keys by splitting the current Key Encryption Key (KEK)
    /// using Shamir's Secret Sharing scheme. The generated keys can be used to unseal the bastion_vault
    /// in the future. This is typically called after a successful unseal operation to provide
    /// new keys for the next seal/unseal cycle.
    ///
    /// # Returns
    /// A `Result` containing a zeroizing vector of unseal key shares, or an error if generation fails.
    ///
    /// # Errors
    /// - Returns `RvError::ErrBarrierSealed` if the barrier is currently sealed
    /// - Returns `RvError::ErrBarrierKeyInvalid` if the KEK is empty or invalid
    /// - Returns Shamir secret splitting errors if the key splitting process fails
    ///
    /// # Security
    /// - Uses the current KEK as the source for key generation
    /// - Applies Shamir's Secret Sharing with configured threshold and share count
    /// - Returns zeroizing vector to ensure secure memory cleanup
    /// - Generated keys are cryptographically independent of previous keys
    ///
    /// # Usage
    /// This method should only be called when the bastion_vault is unsealed and a valid KEK exists.
    /// It's commonly used in key rotation scenarios or after unseal_once operations.
    pub async fn generate_unseal_keys(&self) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        if self.state.load().sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        let kek = self.state.load().kek.clone();
        if kek.is_empty() {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        let config = self.seal_config().await?;
        ShamirSecret::split(kek.as_slice(), config.secret_shares, config.secret_threshold)
    }

    async fn post_unseal(&self) -> Result<(), RvError> {
        // Multi-tenancy: re-root activation is the default for every install. We
        // decide and (for existing installs) run the non-destructive copy +
        // verify *before* any system view or root mount table is built, so the
        // root tenant's reads and writes land at the active prefix from the
        // first operation. Fails safe: an unverifiable copy leaves the legacy
        // layout authoritative for this boot (see
        // `modules::namespace::migrate::resolve_root_activation`).
        if let Some(core_arc) = self.self_ptr.upgrade() {
            let store = crate::modules::namespace::store::NamespaceStore::new(&core_arc)?;
            store.ensure_root().await?;
            if let Some(root_uuid) =
                crate::modules::namespace::migrate::resolve_root_activation(&core_arc, &store).await?
            {
                self.activate_reroot(&root_uuid)?;
            }
        }

        self.module_manager.setup(self)?;

        // Perform initial setup
        self.mounts_router()
            .load_or_default(self.barrier.as_storage(), Some(&self.state.load().hmac_key), self.mount_entry_hmac_level)
            .await?;

        self.mounts_router().setup(self.self_ptr.upgrade().unwrap().clone())?;

        self.module_manager.init(self).await?;

        // (Re-root copy + activation already ran at the top of post_unseal, via
        // `resolve_root_activation`, before any view/mount-table was built.)

        // Load the restart-durable FerroGate machine-identity enforcement flag
        // into its in-memory mirror before serving requests. Best-effort: a
        // read failure leaves the safe default (false) rather than blocking
        // unseal — operators can re-assert it via the config endpoint.
        if let Err(e) = self.load_require_machine_identity().await {
            log::warn!("failed to load ferrogate require_machine_identity flag: {e}");
        }

        if let Some(mounts_monitor) = self.mounts_monitor.load().as_ref() {
            mounts_monitor.add_mounts_router(self.mounts_router().clone());
            mounts_monitor.start();
        }

        // Install the audit broker. Uses the barrier-derived HMAC
        // key for entry redaction. Re-hydrates any persisted device
        // configs. Silent on failure — the broker is optional
        // infrastructure; ops continue, just without audit, unless
        // operators require it via the fail-closed policy.
        let hmac_key = self.state.load().hmac_key.clone();
        if !hmac_key.is_empty() {
            match crate::audit::AuditBroker::new(self, hmac_key).await {
                Ok(broker) => {
                    // First-boot convenience: if the operator pointed
                    // `log_dir` at a directory but never enabled any
                    // audit device, register a file device on
                    // `<log_dir>/audit.log` so the third structured
                    // stream lights up alongside operations + security.
                    // No-ops on re-unseal once a device exists.
                    if let Some((path, rotate_size, rotate_keep)) =
                        crate::logging::default_audit_options()
                    {
                        if !broker.has_devices() {
                            let mut opts = std::collections::HashMap::new();
                            opts.insert(
                                "file_path".to_string(),
                                path.to_string_lossy().into_owned(),
                            );
                            opts.insert(
                                "rotate_size_bytes".to_string(),
                                rotate_size.to_string(),
                            );
                            opts.insert("rotate_keep".to_string(), rotate_keep.to_string());
                            let cfg = crate::audit::AuditDeviceConfig {
                                path: "file/".to_string(),
                                device_type: "file".to_string(),
                                description: "default file audit device".to_string(),
                                options: opts,
                                ..Default::default()
                            };
                            if let Err(e) = broker.enable_device(cfg).await {
                                log::warn!(
                                    "audit: failed to auto-enable default file device at {}: {e}",
                                    path.display()
                                );
                            } else {
                                log::info!(
                                    "audit: auto-enabled default file device at {}",
                                    path.display()
                                );
                            }
                        }
                    }
                    self.audit_broker.store(Some(broker));
                }
                Err(e) => log::warn!("audit broker init failed: {e}. Audit disabled."),
            }
        }

        // Boot the scheduled-exports tick loop. Single-process scheduler;
        // HA leader gating lands in a follow-up. Detached task — the
        // returned JoinHandle is dropped intentionally so the loop runs
        // until the process exits. The loop self-skips when sealed.
        if let Some(core_arc) = self.self_ptr.upgrade() {
            let _ = crate::scheduled_exports::start_scheduler(core_arc);
        }

        // Boot the PKI auto-tidy scheduler (Phase 4.1). Same lifecycle
        // pattern as scheduled-exports above — detached task, self-skip
        // when sealed, single-process scheduler, HA leader gating
        // deferred. Tick fires every 30s; per-mount cadence comes from
        // each mount's persisted `pki/config/auto-tidy`.
        if let Some(core_arc) = self.self_ptr.upgrade() {
            let _ = crate::modules::pki::scheduler::start_pki_tidy_scheduler(core_arc);
        }

        // Boot the Rustion target-health pinger. Same lifecycle
        // pattern as the schedulers above. Ticks every 30s; an empty
        // target registry is a no-op so it's safe to start
        // unconditionally before any operator enrols a bastion.
        if let Some(core_arc) = self.self_ptr.upgrade() {
            let _ = crate::modules::rustion::probe::start_pinger(core_arc.clone());
            // Phase 6.4: 24h recording-fallback poller. Same lifecycle
            // pattern; ticks every hour, falls back to GET
            // /v1/sessions/{sid}/recording for sessions whose
            // recording.ready webhook didn't land.
            let _ = crate::modules::rustion::poller::start_poller(core_arc.clone());
            // Phase 8.1: 60s telemetry poller pulling
            // /v1/sessions/{active,history} + /v1/stats from every
            // enabled bastion into the in-memory cache the GUI reads.
            let _ = crate::modules::rustion::telemetry::start_poller(core_arc.clone());
            // Phase 9.2: weekly re-attestation sweep. Walks every
            // enrolled bastion and sends a signed `attest` envelope
            // so Rustion can bump the authority record's
            // attestation_renew_at deadline.
            let _ = crate::modules::rustion::attest_timer::start_attest_timer(core_arc);
        }

        // Boot the OpenLDAP / AD static-role auto-rotation scheduler
        // (Phase 3). Same lifecycle pattern: detached task, self-skip
        // when sealed, single-process scheduler. Tick fires every 60s;
        // per-role cadence comes from each role's persisted
        // `rotation_period`. Roles with `rotation_period = 0` are
        // skipped (manual rotation only).
        if let Some(core_arc) = self.self_ptr.upgrade() {
            let _ = crate::modules::ldap::scheduler::start_ldap_rotation_scheduler(core_arc);
        }

        // Boot the File Resources periodic sync scheduler. Same
        // single-process posture as the LDAP / PKI schedulers — every
        // node in a Hiqlite cluster runs its own; the sync push
        // itself is idempotent (tmp+rename), so a double-push is
        // wasteful but not incorrect. Per-mount config can disable
        // the sweep so an operator who prefers external scheduling
        // can drive `POST /v1/<mount>/sync-tick` from cron instead.
        if let Some(core_arc) = self.self_ptr.upgrade() {
            let _ = crate::modules::files::scheduler::start_files_sync_scheduler(core_arc);
        }

        // Boot the cert-lifecycle renewal scheduler (Phase L6). Same
        // single-process posture as the schedulers above. Each
        // cert-lifecycle mount opts in via
        // `cert-lifecycle/scheduler/config`; un-configured mounts get
        // skipped on every tick. The renewal call goes through
        // `Core::handle_request` with the operator-supplied
        // `client_token` so the existing PKI ACL boundary applies.
        if let Some(core_arc) = self.self_ptr.upgrade() {
            let _ = crate::modules::cert_lifecycle::scheduler::start_cert_lifecycle_scheduler(core_arc);
        }

        Ok(())
    }

    /// Flush every cache layer (policy, token, secret) and zeroize the
    /// held payloads. Called from `pre_seal` and from the
    /// `sys/cache/flush` admin endpoint. Never returns an error — any
    /// individual flush failure is logged and the rest of the layers
    /// still get flushed, because half-flushed is worse than
    /// best-effort-flushed on a seal hot path.
    pub fn flush_caches(&self) {
        // Policy cache
        if let Some(policy_module) =
            self.module_manager.get_module::<crate::modules::policy::PolicyModule>("policy")
        {
            policy_module.policy_store.load().flush_caches();
        }

        // Token cache
        if let Some(auth_module) =
            self.module_manager.get_module::<crate::modules::auth::AuthModule>("auth")
        {
            if let Some(token_store) = auth_module.token_store.load_full() {
                token_store.flush_cache();
            }
        }

        // Secret read cache (ciphertext-only `CachingBackend` decorator).
        // `Backend: Any` gives us a runtime downcast without wiring a
        // dedicated trait method.
        let any_backend: &dyn std::any::Any = &*self.physical;
        if let Some(caching) = any_backend.downcast_ref::<crate::cache::CachingBackend>() {
            caching.clear();
        }
    }

    fn pre_seal(&self) -> Result<(), RvError> {
        // Flush every cache layer before releasing the unseal key: cached
        // material must not survive into the sealed state even briefly.
        self.flush_caches();
        // Drop the audit broker so a subsequent unseal gets a fresh
        // one tied to the new hmac_key.
        self.audit_broker.store(None);
        if let Some(mounts_monitor) = self.mounts_monitor.load().as_ref() {
            mounts_monitor.remove_mounts_router(self.mounts_router().clone());
            mounts_monitor.stop();
        }
        self.module_manager.cleanup(self)?;
        self.unload_mounts()?;
        Ok(())
    }

    pub async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut resp = None;
        let mut err: Option<RvError> = None;
        let handlers = self.handlers.load();

        if self.state.load().sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        // Multi-tenancy: converge the X-BastionVault-Namespace header onto the
        // path-prefix form so the shared router dispatches namespace mounts
        // uniformly. No-op when no namespace header is present.
        crate::modules::namespace::router::rewrite_request_for_namespace(self, req).await?;

        match self.handle_pre_route_phase(&handlers, req).await {
            Ok(ret) => resp = ret,
            Err(e) => err = Some(e),
        }

        // Multi-tenancy: enforce token namespace binding once auth is resolved
        // and before any backend dispatch. A token may not be used outside its
        // namespace (except a child_visible token into a descendant).
        if resp.is_none() && err.is_none() {
            if let Err(e) =
                crate::modules::namespace::token_binding::enforce_request_token_binding(self, req)
                    .await
            {
                err = Some(e);
            }
        }

        // Multi-tenancy: per-namespace request-rate quota (429 when exhausted).
        // A no-op for root / unlimited namespaces.
        if resp.is_none() && err.is_none() {
            if let Err(e) = crate::modules::namespace::quota::enforce_request_rate(self, req).await {
                err = Some(e);
            }
        }

        // Multi-tenancy: per-namespace storage-bytes quota (507 when the write
        // would cross the cap). A no-op for non-writes / root / unlimited.
        if resp.is_none() && err.is_none() {
            if let Err(e) =
                crate::modules::namespace::quota::enforce_write_storage_quota(self, req).await
            {
                err = Some(e);
            }
        }

        if resp.is_none() && err.is_none() {
            match self.handle_route_phase(&handlers, req).await {
                Ok(ret) => resp = ret,
                Err(e) => err = Some(e),
            }

            if err.is_none() {
                if let Err(e) = self.handle_post_route_phase(&handlers, req, &mut resp).await {
                    err = Some(e)
                }
            }
        }

        if err.is_none() {
            self.handle_log_phase(&handlers, req, &mut resp).await?;
        }

        if err.is_some() {
            return Err(err.unwrap());
        }

        Ok(resp)
    }

    async fn handle_pre_route_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        req.handle_phase = HandlePhase::PreRoute;
        for handler in handlers.iter() {
            match handler.pre_route(req).await {
                Ok(Some(res)) => return Ok(Some(res)),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        Ok(None)
    }

    async fn handle_route_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        req.handle_phase = HandlePhase::Route;
        if let Some(bind_handler) = req.get_handler() {
            match bind_handler.route(req).await {
                Ok(res) => return Ok(res),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => {}
            }
        }

        for handler in handlers.iter() {
            match handler.route(req).await {
                Ok(Some(res)) => return Ok(Some(res)),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        Ok(None)
    }

    async fn handle_post_route_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
        resp: &mut Option<Response>,
    ) -> Result<(), RvError> {
        req.handle_phase = HandlePhase::PostRoute;
        if let Some(bind_handler) = req.get_handler() {
            match bind_handler.post_route(req, resp).await {
                Ok(_) => return Ok(()),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => {}
            }
        }

        for handler in handlers.iter() {
            match handler.post_route(req, resp).await {
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        Ok(())
    }

    async fn handle_log_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
        resp: &mut Option<Response>,
    ) -> Result<(), RvError> {
        req.handle_phase = HandlePhase::Log;
        if let Some(bind_handler) = req.get_handler() {
            match bind_handler.log(req, resp).await {
                Ok(_) => return Ok(()),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => {}
            }
        }

        for handler in handlers.iter() {
            match handler.log(req, resp).await {
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        // Audit broker fan-out. Emits one `response`-type entry per
        // request covering the final state. Phase-1 simplification:
        // the spec calls for separate pre-dispatch request entries;
        // those require a second hook higher in the pipeline and are
        // deferred. Fail-closed per design — if any device errors,
        // the request fails here.
        if let Some(broker) = self.audit_broker.load().as_ref().cloned() {
            if broker.has_devices() {
                let mut entry = crate::audit::AuditEntry::from_response(
                    req,
                    resp,
                    None,
                    broker.hmac_key(),
                    false,
                );
                broker.log(&mut entry).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{errors::RvError, test_utils::new_unseal_test_bastion_vault};

    #[test]
    fn test_core_init() {
        let _ = new_unseal_test_bastion_vault("test_core_init");
    }

    /// `Core::flush_caches` must clear the token cache so a previously
    /// cached entry can no longer be served without a storage re-read.
    /// Regression for the seal path: pre_seal invokes this helper, and
    /// a missed flush would leave live token payloads in memory after
    /// the unseal key has been released.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_core_flush_caches_empties_token_cache() {
        use crate::modules::auth::{
            token_store::TokenEntry, AuthModule,
        };

        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_core_flush_caches_empties_token_cache").await;

        let auth_module = core
            .module_manager
            .get_module::<AuthModule>("auth")
            .expect("auth module must exist in a default unseal");
        let token_store =
            auth_module.token_store.load_full().expect("token store must be installed");

        // The root token is already in storage; force a cache-populating
        // lookup, then verify the cache has it.
        let _ = token_store.lookup(&root_token).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let salted = token_store.salt_id(&root_token);
        assert!(
            token_store.token_cache.as_ref().unwrap().lookup(&salted).is_some(),
            "precondition: cache must be populated before flush"
        );

        // Also populate with a freshly created token so the test isn't
        // contingent on lookup behaviour alone.
        let mut entry = TokenEntry {
            policies: vec!["default".into()],
            path: "auth/token/create".into(),
            display_name: "flush-probe".into(),
            ..TokenEntry::default()
        };
        token_store.create(&mut entry).await.unwrap();
        token_store.lookup(&entry.id).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let salted_probe = token_store.salt_id(&entry.id);
        assert!(token_store.token_cache.as_ref().unwrap().lookup(&salted_probe).is_some());

        core.flush_caches();
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(
            token_store.token_cache.as_ref().unwrap().lookup(&salted).is_none(),
            "flush_caches must drop the root-token entry"
        );
        assert!(
            token_store.token_cache.as_ref().unwrap().lookup(&salted_probe).is_none(),
            "flush_caches must drop every token cache entry"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_generate_unseal_keys_basic() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_generate_unseal_keys_basic").await;

        // Test that generate_unseal_keys works when unsealed
        let result = core.generate_unseal_keys().await;
        assert!(result.is_ok());

        let keys = result.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(keys.len(), seal_config.secret_shares as usize); // Default test configuration: 3 shares

        // Each key should have the expected length (key bytes + 1 byte Shamir overhead)
        // ChaCha20Poly1305 barrier uses 64-byte ML-KEM-768 seeds, AES-GCM uses 32-byte keys
        let (min_key_len, _) = core.barrier.key_length_range();
        let expected_key_len = min_key_len + crate::shamir::SHAMIR_OVERHEAD;
        for key in keys.iter() {
            assert_eq!(key.len(), expected_key_len);
        }

        // Keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_generate_unseal_keys_when_sealed() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_generate_unseal_keys_when_sealed").await;

        // Seal the vault
        let seal_result = core.seal().await;
        assert!(seal_result.is_ok());

        // Should fail when sealed
        let result = core.generate_unseal_keys().await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_generate_unseal_keys_multiple_calls() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_generate_unseal_keys_multiple_calls").await;

        // Generate keys multiple times
        let keys1 = core.generate_unseal_keys().await.unwrap();
        let keys2 = core.generate_unseal_keys().await.unwrap();
        let keys3 = core.generate_unseal_keys().await.unwrap();

        // All should succeed and produce the same number of keys
        assert_eq!(keys1.len(), keys2.len());
        assert_eq!(keys2.len(), keys3.len());

        // But keys should be different (due to randomness in Shamir sharing)
        assert_ne!(keys1[0], keys2[0]);
        assert_ne!(keys2[0], keys3[0]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_basic() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_basic").await;

        // Get initial keys for testing
        let initial_keys = core.generate_unseal_keys().await.unwrap();

        // Seal the vault
        core.seal().await.unwrap();

        // Test unseal_once with sufficient keys
        let mut new_keys = None;
        for key in initial_keys.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    new_keys = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys.is_some());
        let new_keys = new_keys.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(new_keys.len(), seal_config.secret_shares as usize); // Should generate new keys

        // Vault should be unsealed
        assert!(!core.sealed());

        // New keys should be different from initial keys
        assert_ne!(initial_keys[0], new_keys[0]);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_insufficient_keys() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_insufficient_keys").await;

        // Get initial keys
        let initial_keys = core.generate_unseal_keys().await.unwrap();

        // Seal the vault
        core.seal().await.unwrap();

        // Try unseal_once with just one key (insufficient for threshold=2)
        let result = core.unseal_once(&initial_keys[0]).await;
        assert!(result.is_err());

        // Vault should still be sealed
        assert!(core.sealed());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_key_deprecation() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_key_deprecation").await;

        // Get initial keys
        let initial_keys = core.generate_unseal_keys().await.unwrap();

        // Seal the vault
        core.seal().await.unwrap();

        // Use unseal_once to unseal
        let mut new_keys = None;
        for key in initial_keys.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    new_keys = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys.is_some());
        let new_keys = new_keys.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(new_keys.len(), seal_config.secret_shares as usize);

        // Seal again
        core.seal().await.unwrap();

        // Try to use the same key again - should fail due to deprecation
        for i in 0..5 {
            let result = core.unseal_once(&initial_keys[i]).await;
            assert!(matches!(result, Err(RvError::ErrBarrierKeyDeprecated)));
        }

        for i in 5..initial_keys.len() {
            let result = core.unseal_once(&initial_keys[i]).await;
            assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        }
        let result = core.unseal_once(&new_keys[0]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealFailed)));

        // But new keys should work
        let mut new_keys2 = None;
        for key in new_keys.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    new_keys2 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys2.is_some());
        let new_keys2 = new_keys2.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(new_keys2.len(), seal_config.secret_shares as usize);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_when_already_unsealed() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_when_already_unsealed").await;

        // Get keys for testing
        let keys = core.generate_unseal_keys().await.unwrap();

        // Vault is already unsealed, so unseal_once should fail
        let result = core.unseal_once(&keys[0]).await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_unseal_once_forward_secrecy() {
        let (_bvault, core, _) = new_unseal_test_bastion_vault("test_unseal_once_forward_secrecy").await;

        // Get initial keys
        let keys1 = core.generate_unseal_keys().await.unwrap();

        // Seal and unseal_once to get new keys
        core.seal().await.unwrap();
        let mut keys2 = None;
        for key in keys1.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    keys2 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(keys2.is_some());
        let keys2 = keys2.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(keys2.len(), seal_config.secret_shares as usize);

        // Seal and unseal_once again
        core.seal().await.unwrap();

        let mut keys3 = None;
        for key in keys2.iter() {
            match core.unseal_once(key).await {
                Ok(keys) => {
                    keys3 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }
        assert!(keys3.is_some());
        let keys3 = keys3.unwrap();
        let seal_config = core.seal_config().await.unwrap();
        assert_eq!(keys3.len(), seal_config.secret_shares as usize);

        // All key sets should be different (forward secrecy)
        for i in 0..keys1.len() {
            assert_ne!(keys1[i], keys2[i]);
            assert_ne!(keys2[i], keys3[i]);
            assert_ne!(keys1[i], keys3[i]);
        }

        // Old keys should be deprecated and unusable
        core.seal().await.unwrap();
        for key in keys1.iter() {
            let result = core.unseal_once(key).await;
            assert!(result.is_err());
        }
        for key in keys2.iter() {
            let result = core.unseal_once(key).await;
            assert!(result.is_err());
        }
        for key in keys3.iter() {
            if let Err(RvError::ErrBarrierUnsealFailed) = core.unseal_once(key).await {
                break;
            }
        }

        let result = core.unseal_once(&keys3[0]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[1]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[2]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[3]).await;
        assert!(matches!(result, Err(RvError::ErrBarrierUnsealing)));
        let result = core.unseal_once(&keys3[4]).await;
        assert!(matches!(result, Ok(_)));
    }
}
