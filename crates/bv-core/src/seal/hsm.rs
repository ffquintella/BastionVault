//! HSM auto-unseal seal provider (spec § Capability 1; T454 phases 1–2).
//!
//! Per node: the KEK is a v2 blob under this node's device. Pool: it is a set
//! with one copy per member, unwrapped through the preferred reachable member.
//! Either way release is a signed, audited, replay-resistant unwrap, and a node
//! that cannot reach a device stays sealed (spec rule 6; never a fallback).

mod device_drain;
pub mod hooks;
mod pool_admin;
pub mod record;
mod recovery_ceremony;

pub use device_drain::{DrainMemberStatus, DrainReport};
pub use recovery_ceremony::{RecoveryMember, RecoverySubmission};

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use bv_metrics::hsm_metrics::{hsm_metrics, UnderReplicatedScope};
use rand::Rng;
use zeroize::Zeroizing;

use crate::{
    core::SealConfig,
    errors::RvError,
    hsm::{
        authz::{self, UnwrapRequest},
        authz_fingerprint_of,
        blob::{BvHsmBlob, Context, HsmId, Purpose, BV_HSM_BLOB_VERSION_V1},
        blobset::{unix_now_secs, BvHsmBlobSet},
        clock::{self, Clock},
        context,
        node_creds::{self, NodeCredentialStore},
        pool::{check_pool_storage_backend, HsmPool, PoolEventSink, PoolMember, PoolMemberSpec},
        recovery::{self, RecoverySplit, ShareSet},
        repair::RepairReport,
        validate_node_id, ConfigMemberOpener, HsmBackend, MemberOpener, MemberTarget, RecoveryMode, ResolvedHsmConfig,
        ResolvedPoolConfig,
    },
    seal::SealProvider,
    storage::{Backend as PhysicalBackend, BackendEntry},
};

use self::record::{HsmMember, HsmSealRecord, MemberState, RecoveryPublicKey, StoredSealRecord, Topology};

/// Physical-storage key for the HSM seal record. Non-secret (holds only
/// opaque wrapped blobs), so it lives in the pre-unseal physical layer.
const HSM_SEAL_RECORD_PATH: &str = "core/hsm-seal";
/// Pre-T454 cluster-wide unwrap counter. Read once per node, to start that
/// node's own counter above it; never written again, never deleted.
const HSM_AUTHZ_COUNTER_LEGACY_PATH: &str = "core/hsm-authz-counter";
/// Per-node unwrap counters: `core/hsm-authz-counter/<node_id>`.
const HSM_AUTHZ_COUNTER_PREFIX: &str = "core/hsm-authz-counter/";

/// How this provider reaches its device(s).
enum Devices {
    /// The per-node topology: this node's own device.
    PerNode(Arc<dyn HsmBackend>),
    /// The pool topology (T454 phase 2).
    Pool(PoolDevices),
}

/// How often a running node re-reads the seal record's membership and picks
/// up delivered credentials (spec § Configuration: at least every 30 s).
pub const MEMBERSHIP_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Who a pool was built for: (name, device, prefer, why unusable) per member,
/// and the client generation, so a new credential rebuilds the pool.
type Membership = (Vec<(String, HsmId, bool, Option<String>)>, u64);

/// How this node reaches each member, and the clients it has opened.
struct ClientCache {
    opener: Arc<dyn MemberOpener>,
    /// `credential_dir`, when the node authenticates with node credentials.
    credentials: Option<NodeCredentialStore>,
    /// Opened clients by device; dropped when a new credential arrives.
    clients: Mutex<BTreeMap<HsmId, Result<Arc<dyn HsmBackend>, String>>>,
    generation: AtomicU64,
}

/// This node's clients for the pool members, and the pool built over them.
struct PoolDevices {
    cache: ClientCache,
    clock: Arc<dyn Clock>,
    events: Arc<dyn PoolEventSink>,
    current: Mutex<(Membership, Arc<HsmPool>)>,
    probing: AtomicBool,
}

fn membership_of(specs: &[PoolMemberSpec], generation: u64) -> Membership {
    let mut members: Vec<_> = specs
        .iter()
        .map(|s| (s.name.clone(), s.hsm_id.clone(), s.prefer, s.device.as_ref().err().cloned()))
        .collect();
    members.sort();
    (members, generation)
}

/// A fixed set of pre-opened clients, by member name (tests, embedders).
struct FixedClients(BTreeMap<String, Result<Arc<dyn HsmBackend>, String>>);

impl MemberOpener for FixedClients {
    fn open_client(
        &self,
        target: &MemberTarget,
        _credential: Option<crate::hsm::admin::NodeCredential>,
    ) -> Result<Arc<dyn HsmBackend>, RvError> {
        match self.0.get(&target.name) {
            Some(Ok(client)) => Ok(client.clone()),
            Some(Err(e)) => Err(RvError::ErrHsmTransport(e.clone())),
            None => Err(RvError::ErrHsmTransport(format!(
                "this node's config has no `member \"{}\"` block; reaching a member through its recorded gateway \
                 needs the HSM link",
                target.name
            ))),
        }
    }

    fn open_admin(
        &self,
        target: &MemberTarget,
        _password: &str,
    ) -> Result<Box<dyn crate::hsm::admin::HsmAdminSession>, RvError> {
        Err(RvError::ErrHsm(format!("no admin access to HSM pool member {} from this node", target.name)))
    }
}

impl ClientCache {
    /// This node's client for `target`, opened once with the credential this
    /// node holds for the device, if any.
    fn client_for(&self, target: &MemberTarget) -> Result<Arc<dyn HsmBackend>, String> {
        let mut clients = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(client) = clients.get(&target.hsm_id) {
            return client.clone();
        }
        let credential = match &self.credentials {
            Some(store) => store.credential_for(&target.hsm_id),
            None => Ok(None),
        };
        let opened = credential.and_then(|c| self.opener.open_client(target, c)).map_err(|e| e.to_string());
        if let Err(e) = &opened {
            log::error!(target: "security", "HSM pool member {} ({}) cannot be opened: {e}", target.name, target.hsm_id);
        }
        clients.insert(target.hsm_id.clone(), opened.clone());
        opened
    }

    /// Reopen the clients for `ids` (a credential for them arrived).
    fn forget_clients(&self, ids: &[HsmId]) {
        if ids.is_empty() {
            return;
        }
        let mut clients = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        for id in ids {
            clients.remove(id);
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Specs for `members` (where to reach each, and the nodes whose
    /// revocation is pending on it), with this node's clients.
    fn specs_for(&self, pool_cfg: &ResolvedPoolConfig, members: Vec<(MemberTarget, Vec<String>)>) -> Vec<PoolMemberSpec> {
        let by_name = |name: &str| pool_cfg.members.iter().find(|m| m.name == name);
        members
            .into_iter()
            .map(|(target, pending)| {
                let device = if pending.is_empty() {
                    self.client_for(&target)
                } else {
                    Err(format!(
                        "node revocation pending on this member for {pending:?}; every node treats it as down until \
                         an operator applies the revocation with admin credentials"
                    ))
                };
                PoolMemberSpec {
                    prefer: by_name(&target.name).is_some_and(|m| m.prefer),
                    name: target.name,
                    hsm_id: target.hsm_id,
                    device,
                }
            })
            .collect()
    }
}

/// Where each of `members` is reached, and its pending revocations.
fn targets_of<'a>(members: impl Iterator<Item = (&'a HsmId, &'a HsmMember)>) -> Vec<(MemberTarget, Vec<String>)> {
    members
        .map(|(id, m)| {
            let target = MemberTarget { name: m.name.clone(), hsm_id: id.clone(), gateway: m.gateway.clone() };
            (target, m.pending_revocations.clone())
        })
        .collect()
}

fn build_pool(
    node_id: &str,
    pool_cfg: &ResolvedPoolConfig,
    specs: Vec<PoolMemberSpec>,
    generation: u64,
    clock: &Arc<dyn Clock>,
    events: &Arc<dyn PoolEventSink>,
) -> Result<(Membership, Arc<HsmPool>), RvError> {
    let membership = membership_of(&specs, generation);
    let pool = HsmPool::new(node_id, specs, pool_cfg.min_wrap_copies, clock.clone(), events.clone())?;
    Ok((membership, Arc::new(pool)))
}

impl PoolDevices {
    fn pool(&self) -> Arc<HsmPool> {
        self.current.lock().unwrap_or_else(|p| p.into_inner()).1.clone()
    }

    /// Rebuild the pre-init pool from the config's members (new credentials).
    fn rebuild_bootstrap(&self, config: &ResolvedHsmConfig) -> Result<(), RvError> {
        let pool_cfg = config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        let targets = pool_cfg
            .members
            .iter()
            .map(|m| {
                let hsm_id = m.hsm_id(&config.backend_type)?;
                Ok((MemberTarget { name: m.name.clone(), hsm_id, gateway: m.gateway.clone() }, Vec::new()))
            })
            .collect::<Result<Vec<_>, RvError>>()?;
        let specs = self.cache.specs_for(pool_cfg, targets);
        let built = build_pool(&config.node_id, pool_cfg, specs, self.cache.generation(), &self.clock, &self.events)?;
        *self.current.lock().unwrap_or_else(|p| p.into_inner()) = built;
        Ok(())
    }

    /// The pool the seal record describes. The record is authoritative: a
    /// config block that disagrees is ignored with a warning naming the field;
    /// only where this node reaches a device (`connector`, `state_path`) is local.
    fn pool_for_record(&self, config: &ResolvedHsmConfig, record: &HsmSealRecord) -> Result<Arc<HsmPool>, RvError> {
        let pool_cfg = config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        let specs = self.cache.specs_for(pool_cfg, targets_of(record.active_members()));
        let wanted = membership_of(&specs, self.cache.generation());
        let mut current = self.current.lock().unwrap_or_else(|p| p.into_inner());
        if current.0 == wanted {
            return Ok(current.1.clone());
        }
        warn_config_disagreements(pool_cfg, record);
        let built = build_pool(&config.node_id, pool_cfg, specs, wanted.1, &self.clock, &self.events)?;
        #[cfg(not(feature = "sync_handler"))]
        if self.probing.load(Ordering::SeqCst) {
            built.1.spawn_health_probe();
        }
        *current = built;
        Ok(current.1.clone())
    }
}

/// Log, once per membership change, every config `member` block that the
/// seal record overrides.
fn warn_config_disagreements(pool_cfg: &ResolvedPoolConfig, record: &HsmSealRecord) {
    for block in &pool_cfg.members {
        let Some((hsm_id, member)) = record.members.iter().find(|(_, m)| m.name == block.name) else {
            log::warn!(
                target: "security",
                "HSM config `member \"{}\"` is not in the seal record; it is ignored (the record is authoritative)",
                block.name
            );
            continue;
        };
        if member.serial != block.serial {
            log::warn!(
                target: "security",
                "HSM config `member \"{}\"` field `serial` ({}) disagrees with the seal record ({}); the record wins",
                block.name,
                block.serial,
                member.serial
            );
        }
        if !block.gateway.is_empty() && member.gateway != block.gateway {
            log::warn!(
                target: "security",
                "HSM config `member \"{}\"` field `gateway` disagrees with the seal record; the record wins",
                block.name
            );
        }
        if member.state != MemberState::Active {
            log::warn!(
                target: "security",
                "HSM pool member {} ({hsm_id}) is {:?} in the seal record; this node does not use it",
                block.name,
                member.state
            );
        }
    }
}

/// Auto-unseal provider backed by one [`HsmBackend`] or an [`HsmPool`].
pub struct HsmSealProvider {
    devices: Devices,
    physical: Arc<dyn PhysicalBackend>,
    config: ResolvedHsmConfig,
    /// The last repair run on this node (pool only), for `v2/sys/hsm/repair`.
    repair_state: Mutex<Option<RepairReport>>,
    /// Audit delivery and the repair tick (pool, from `open`).
    hooks: Option<Arc<hooks::ProviderHooks>>,
    /// The per-node device `migrate_from` names (pool, `migrate-to-pool`).
    migration_source: Option<Arc<dyn HsmBackend>>,
    /// Recovery shares submitted to `v2/sys/hsm/recover` so far (pool,
    /// phase 5). Memory only; zeroized on reset, on every ceremony attempt
    /// and on drop.
    recovery_shares: Mutex<ShareSet>,
    /// What this node's device-log drains last saw, per member (phase 6).
    device_audit_state: Mutex<device_drain::DrainState>,
}

impl HsmSealProvider {
    /// The per-node topology over this node's own device.
    pub fn new(backend: Arc<dyn HsmBackend>, physical: Arc<dyn PhysicalBackend>, config: ResolvedHsmConfig) -> Self {
        Self {
            devices: Devices::PerNode(backend),
            physical,
            config,
            repair_state: Mutex::new(None),
            hooks: None,
            migration_source: None,
            recovery_shares: Mutex::new(ShareSet::default()),
            device_audit_state: Mutex::new(BTreeMap::new()),
        }
    }

    /// The pool topology over pre-opened member clients (`opened`, by member
    /// name; an `Err` is a member this node could not open). Refuses storage
    /// without a cluster lock for `hsm-custody`.
    pub fn new_pool(
        opened: BTreeMap<String, Result<Arc<dyn HsmBackend>, String>>,
        physical: Arc<dyn PhysicalBackend>,
        config: ResolvedHsmConfig,
        clock: Arc<dyn Clock>,
        events: Arc<dyn PoolEventSink>,
    ) -> Result<Self, RvError> {
        let pool_cfg = config
            .pool
            .as_ref()
            .ok_or_else(|| RvError::ErrHsmConfigInvalid("new_pool needs topology = \"pool\"".into()))?;
        let names: Vec<&str> = pool_cfg.members.iter().map(|m| m.name.as_str()).collect();
        if opened.keys().map(String::as_str).ne(names.iter().copied()) {
            return Err(RvError::ErrHsmConfigInvalid(format!(
                "pool member clients {:?} do not match the config's members {names:?}",
                opened.keys().collect::<Vec<_>>()
            )));
        }
        Self::new_pool_with(Arc::new(FixedClients(opened)), None, physical, config, clock, events)
    }

    /// The pool topology reaching members through `opener`, authenticating
    /// with the node credentials in `credentials` when it has them.
    pub fn new_pool_with(
        opener: Arc<dyn MemberOpener>,
        credentials: Option<NodeCredentialStore>,
        physical: Arc<dyn PhysicalBackend>,
        config: ResolvedHsmConfig,
        clock: Arc<dyn Clock>,
        events: Arc<dyn PoolEventSink>,
    ) -> Result<Self, RvError> {
        let pool_cfg = config
            .pool
            .as_ref()
            .ok_or_else(|| RvError::ErrHsmConfigInvalid("new_pool needs topology = \"pool\"".into()))?;
        check_pool_storage_backend(physical.backend_kind())?;
        let cache =
            ClientCache { opener, credentials, clients: Mutex::new(BTreeMap::new()), generation: AtomicU64::new(0) };
        // Bootstrap membership: the config, until a seal record exists.
        let bootstrap = pool_cfg
            .members
            .iter()
            .map(|m| {
                let hsm_id = m.hsm_id(&config.backend_type)?;
                Ok((MemberTarget { name: m.name.clone(), hsm_id, gateway: m.gateway.clone() }, Vec::new()))
            })
            .collect::<Result<Vec<_>, RvError>>()?;
        let specs = cache.specs_for(pool_cfg, bootstrap);
        let current = build_pool(&config.node_id, pool_cfg, specs, 0, &clock, &events)?;
        let devices = PoolDevices { cache, clock, events, current: Mutex::new(current), probing: AtomicBool::new(false) };
        Ok(Self {
            devices: Devices::Pool(devices),
            physical,
            config,
            repair_state: Mutex::new(None),
            hooks: None,
            migration_source: None,
            recovery_shares: Mutex::new(ShareSet::default()),
            device_audit_state: Mutex::new(BTreeMap::new()),
        })
    }

    /// Open the configured topology: per node, the device; for a pool, the
    /// member opener and this node's credential store. A member that fails
    /// to open is down, not fatal; a build that cannot run a pool is.
    #[maybe_async::maybe_async]
    pub async fn open(config: &ResolvedHsmConfig, physical: Arc<dyn PhysicalBackend>) -> Result<Arc<Self>, RvError> {
        let Some(pool_cfg) = &config.pool else {
            let backend = crate::hsm::new_backend(config).await?;
            return Ok(Arc::new(Self::new(backend, physical, config.clone())));
        };
        check_pool_storage_backend(physical.backend_kind())?;
        let clock = clock::monotonic();
        let opener = Arc::new(ConfigMemberOpener::new(config, clock.clone())?);
        let credentials = if pool_cfg.credential_dir.is_empty() {
            None
        } else {
            let store = NodeCredentialStore::new(&pool_cfg.credential_dir, &config.node_id)?;
            store.ensure_transport_key()?;
            Some(store)
        };
        let hooks = hooks::ProviderHooks::new();
        let mut provider =
            Self::new_pool_with(opener, credentials, physical, config.clone(), clock, hooks.clone())?;
        provider.hooks = Some(hooks);
        if let Some(from) = &pool_cfg.migrate_from {
            // Explicit: a configured migration source that cannot open stops
            // the node rather than leaving `migrate-to-pool` silently absent.
            let per_node = ResolvedHsmConfig {
                connector: from.connector.clone(),
                state_path: from.state_path.clone(),
                password: from.password.clone(),
                objects: crate::hsm::HsmObjectIds { auth_key: from.auth_key_id, ..config.objects },
                pool: None,
                ..config.clone()
            };
            provider.migration_source = Some(crate::hsm::new_backend(&per_node).await?);
        }
        let provider = Arc::new(provider);
        if let Err(e) = provider.refresh_membership().await {
            log::error!(target: "security", "HSM pool membership refresh failed at startup: {e}");
        }
        #[cfg(not(feature = "sync_handler"))]
        {
            provider.start_health_probe();
            provider.start_membership_refresh();
        }
        Ok(provider)
    }

    /// Re-read the record's membership every [`MEMBERSHIP_REFRESH_INTERVAL`]
    /// and pick up delivered credentials, until the provider is dropped.
    #[cfg(not(feature = "sync_handler"))]
    pub fn start_membership_refresh(self: &Arc<Self>) {
        if !matches!(self.devices, Devices::Pool(_)) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            log::error!(target: "security", "no async runtime: HSM pool membership is not re-read every 30 s");
            return;
        };
        let provider = Arc::downgrade(self);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(MEMBERSHIP_REFRESH_INTERVAL).await;
                let Some(provider) = provider.upgrade() else { break };
                if let Err(e) = provider.refresh_membership().await {
                    log::error!(target: "security", "HSM pool membership refresh failed: {e}");
                }
            }
        });
    }

    /// Install delivered credentials (or advertise this node for enrollment
    /// while it has none), then rebuild the pool from the seal record.
    #[maybe_async::maybe_async]
    pub async fn refresh_membership(&self) -> Result<(), RvError> {
        let Devices::Pool(devices) = &self.devices else { return Ok(()) };
        if let Some(store) = &devices.cache.credentials {
            let installed = node_creds::pick_up(self.physical.as_ref(), store).await?;
            devices.cache.forget_clients(&installed);
            if store.members()?.is_empty() {
                node_creds::publish_pending(self.physical.as_ref(), &store.ensure_transport_key()?).await?;
            }
        }
        if let Some(stored) = self.load_record().await? {
            if stored.record.topology == Topology::Pool {
                devices.pool_for_record(&self.config, &stored.record)?;
            }
        }
        Ok(())
    }

    /// The per-node device `migrate-to-pool` reads the KEK from.
    pub fn with_migration_source(mut self, device: Arc<dyn HsmBackend>) -> Self {
        self.migration_source = Some(device);
        self
    }

    /// Probe the pool members every 10 s in the background (pool only).
    #[cfg(not(feature = "sync_handler"))]
    pub fn start_health_probe(&self) {
        if let Devices::Pool(devices) = &self.devices {
            if !devices.probing.swap(true, Ordering::SeqCst) {
                devices.pool().spawn_health_probe();
            }
        }
    }

    /// The per-node device; `None` in the pool topology.
    pub fn backend(&self) -> Option<Arc<dyn HsmBackend>> {
        match &self.devices {
            Devices::PerNode(backend) => Some(backend.clone()),
            Devices::Pool(_) => None,
        }
    }

    /// The pool as of the last record read (or the bootstrap config).
    pub fn pool(&self) -> Option<Arc<HsmPool>> {
        match &self.devices {
            Devices::PerNode(_) => None,
            Devices::Pool(devices) => Some(devices.pool()),
        }
    }

    /// One line for the startup log. No secrets.
    pub fn describe(&self) -> String {
        match &self.devices {
            Devices::PerNode(b) => format!("backend `{}` (serial {})", b.backend_type(), b.device_serial()),
            Devices::Pool(d) => {
                let members: Vec<String> =
                    d.pool().member_status().iter().map(|m| format!("{} {}", m.name, m.hsm_id)).collect();
                format!("pool of `{}` devices: {}", self.config.backend_type, members.join(", "))
            }
        }
    }

    #[maybe_async::maybe_async]
    async fn load_record(&self) -> Result<Option<StoredSealRecord>, RvError> {
        match self.physical.get(HSM_SEAL_RECORD_PATH).await? {
            Some(pe) => Ok(Some(HsmSealRecord::decode(&pe.value)?)),
            None => Ok(None),
        }
    }

    /// Write the record, always as v2 (a record loaded from v1 is converted
    /// here). Every writer of a pool record holds the `hsm-custody` lock.
    #[maybe_async::maybe_async]
    async fn store_record(&self, rec: &HsmSealRecord) -> Result<(), RvError> {
        let value = rec.encode()?;
        self.physical.put(&BackendEntry { key: HSM_SEAL_RECORD_PATH.to_string(), value }).await
    }

    /// Read, increment and persist this node's strictly-increasing unwrap
    /// counter, so a captured (blob, authorization) pair cannot be replayed
    /// across restarts. Per node, so concurrent unseals never share a key.
    #[maybe_async::maybe_async]
    async fn next_counter(&self) -> Result<u64, RvError> {
        validate_node_id(&self.config.node_id)?;
        let key = format!("{HSM_AUTHZ_COUNTER_PREFIX}{}", self.config.node_id);
        let current = match self.physical.get(&key).await? {
            Some(pe) => parse_counter(&key, &pe.value)?,
            // First use on this node: start above the legacy global counter,
            // so nothing authorized under it can be replayed.
            None => match self.physical.get(HSM_AUTHZ_COUNTER_LEGACY_PATH).await? {
                Some(pe) => parse_counter(HSM_AUTHZ_COUNTER_LEGACY_PATH, &pe.value)?,
                None => 0,
            },
        };
        let next =
            current.checked_add(1).ok_or_else(|| RvError::ErrHsm(format!("unwrap counter {key} is exhausted")))?;
        self.physical.put(&BackendEntry { key, value: next.to_string().into_bytes() }).await?;
        Ok(next)
    }

    fn barrier_context(&self, cluster_uuid: &str, epoch: u64) -> Context {
        Context::new(context::barrier_kek(cluster_uuid), Purpose::BarrierKek, epoch, &self.config.node_id)
    }

    /// Per-node + `shamir-ceremony` would initialize a vault with no recovery
    /// key while the config claims one, which is a silent failure. Refused.
    fn refuse_unavailable_recovery(&self) -> Result<(), RvError> {
        match self.config.recovery {
            RecoveryMode::None => Ok(()),
            RecoveryMode::ShamirCeremony => Err(RvError::ErrHsmConfigInvalid(
                "recovery = \"shamir-ceremony\" is not available for the per-node HSM topology: no recovery key \
                 would be generated and init would return no recovery shares. Set recovery = \"none\". See \
                 features/hsm-pool-ha.md § Recovery: Shamir ceremony (T454)"
                    .into(),
            )),
        }
    }

    /// Pool init needs an explicit recovery posture (spec § Bootstrap at
    /// init): `none`, or `shamir-ceremony` with its recovery key (phase 5).
    fn refuse_pool_recovery(&self) -> Result<(), RvError> {
        if !self.config.recovery_explicit {
            return Err(RvError::ErrHsmConfigInvalid(
                "topology = \"pool\" requires an explicit `recovery` at init (\"none\" or \"shamir-ceremony\"); \
                 pool init never picks a recovery posture for you"
                    .into(),
            ));
        }
        Ok(())
    }

    /// The recovery split pool init uses: the request's, the default 5 / 3
    /// with `shamir-ceremony`, and none at all with `recovery = "none"`
    /// (where explicit parameters are refused, never ignored).
    fn pool_recovery_split(&self, requested: Option<RecoverySplit>) -> Result<Option<RecoverySplit>, RvError> {
        match (self.config.recovery, requested) {
            (RecoveryMode::None, None) => Ok(None),
            (RecoveryMode::None, Some(_)) => Err(RvError::ErrHsmConfigInvalid(
                "recovery_shares and recovery_threshold need recovery = \"shamir-ceremony\" in the pool `hsm` block; \
                 this node's config says recovery = \"none\""
                    .into(),
            )),
            (RecoveryMode::ShamirCeremony, requested) => {
                let split = requested.unwrap_or_default();
                split.validate()?;
                Ok(Some(split))
            }
        }
    }

    /// Whether init on this provider makes a recovery key and returns its
    /// shares (a pool with `recovery = "shamir-ceremony"`): `v1/sys/init`,
    /// which has no field for them, refuses such an init.
    pub fn init_returns_recovery_shares(&self) -> bool {
        matches!(self.devices, Devices::Pool(_)) && self.config.recovery == RecoveryMode::ShamirCeremony
    }

    fn recovery_requested(&self) -> &'static str {
        match self.config.recovery {
            RecoveryMode::None => "none",
            RecoveryMode::ShamirCeremony => "shamir-ceremony",
        }
    }

    /// Pool init requires both members reachable (spec § Bootstrap at init).
    #[maybe_async::maybe_async]
    async fn check_pool_init(&self, devices: &PoolDevices) -> Result<(), RvError> {
        self.refuse_pool_recovery()?;
        let pool = devices.pool();
        let mut unreachable = Vec::new();
        for member in pool.members() {
            let reachable = match member.backend() {
                Ok(backend) => backend.probe().await.map(|_| ()),
                Err(e) => Err(e),
            };
            if let Err(e) = reachable {
                unreachable.push(format!("{} ({}): {e}", member.name(), member.hsm_id()));
            }
        }
        if !unreachable.is_empty() {
            return Err(RvError::ErrHsmPoolUnavailable(format!(
                "pool init needs every member reachable, so that no secret starts with one copy; unreachable: {}",
                unreachable.join("; ")
            )));
        }
        Ok(())
    }

    /// Pool init. With `shamir-ceremony` the recovery key is generated here
    /// and its shares returned, once; the seed is gone before this returns.
    #[maybe_async::maybe_async]
    async fn init_pool(
        &self,
        devices: &PoolDevices,
        kek: &[u8],
        requested: Option<RecoverySplit>,
    ) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        let split = self.pool_recovery_split(requested)?;
        let mut uuid_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut uuid_bytes);
        let (recovery_pub, shares) = match split {
            None => (None, Zeroizing::new(Vec::new())),
            Some(split) => {
                let generated = recovery::generate(split)?;
                (Some(RecoveryPublicKey::new(generated.public_key, split)), generated.shares)
            }
        };
        self.write_pool_record(devices, kek, &hex::encode(uuid_bytes), 0, None, recovery_pub.as_ref()).await?;
        Ok(shares)
    }

    /// Dual-wrap `kek` for the configured members and write the pool record.
    /// `replacing`: the exact per-node record bytes a migration replaces;
    /// `None` (init) refuses any existing record. `recovery`: the recovery
    /// key the KEK's recovery copy is sealed to, recorded with it.
    #[maybe_async::maybe_async]
    async fn write_pool_record(
        &self,
        devices: &PoolDevices,
        kek: &[u8],
        cluster_uuid: &str,
        epoch: u64,
        replacing: Option<&[u8]>,
        recovery: Option<&RecoveryPublicKey>,
    ) -> Result<(), RvError> {
        self.check_pool_init(devices).await?;
        let pool_cfg = self.config.pool.as_ref().ok_or_else(|| RvError::ErrHsm("not a pool provider".into()))?;
        let pool = devices.pool();
        let cluster_uuid = cluster_uuid.to_string();
        let ctx = self.barrier_context(&cluster_uuid, epoch);

        // Spec § Bootstrap, step 1: a node that authenticates with node
        // credentials (provisioned devices) initializes only members its
        // bootstrap attested, and the device must still hold the attested keys.
        let attested = crate::hsm::ceremony::read_bootstrap(self.physical.as_ref()).await?;
        let needs_attestation = match &devices.cache.credentials {
            Some(store) => !store.members()?.is_empty(),
            None => false,
        };
        let mut members = BTreeMap::new();
        for member in pool.members() {
            let backend = member.backend()?;
            let block = pool_cfg.members.iter().find(|m| m.name == member.name());
            // A YubiHSM 2 node key cannot read the domain-2 identity; then the
            // attested identity stands, and the authz key is still compared.
            let read_identity = backend.identity_public_key().ok();
            let authz_pub = backend.authz_public_key()?;
            let pinned = attested.as_ref().and_then(|a| a.members.get(member.hsm_id()));
            let identity_matches = |p: &crate::hsm::ceremony::BootstrapMember| {
                read_identity.as_ref().is_none_or(|read| *read == p.identity_pub)
            };
            let (identity_pub, seed_ecdh_pub, attestation_fps) = match pinned {
                Some(p) if identity_matches(p) && p.authz_pub == authz_pub => {
                    (p.identity_pub.clone(), p.seed_ecdh_pub.clone(), p.attestation_fps.clone())
                }
                Some(_) => {
                    log::error!(target: "security", "pool init refused: {} no longer holds its attested keys", member.name());
                    return Err(RvError::ErrHsmAttestationInvalid(format!(
                        "member {} reports keys other than the ones its bootstrap attested",
                        member.name()
                    )));
                }
                None if needs_attestation => {
                    return Err(RvError::ErrHsmAttestationInvalid(format!(
                        "member {} was not attested by `operator hsm bootstrap`; run it before init",
                        member.name()
                    )))
                }
                // A pre-phase-4 (unprovisioned mock) pool: no attestation,
                // and `bv-identity` is also the seed-ECDH contributor.
                None => {
                    let identity_pub = backend.identity_public_key()?;
                    (identity_pub.clone(), identity_pub, Vec::new())
                }
            };
            members.insert(
                member.hsm_id().clone(),
                HsmMember {
                    name: member.name().to_string(),
                    gateway: block.map(|b| b.gateway.clone()).unwrap_or_default(),
                    serial: backend.device_serial(),
                    identity_pub,
                    seed_ecdh_pub,
                    authz_pub,
                    authz_alg: backend.authz_alg(),
                    attestation_fps,
                    state: MemberState::Active,
                    pending_revocations: Vec::new(),
                },
            );
        }

        let outcome = pool.wrap_on_every_member(self.config.objects.wrap_barrier, &ctx, kek).await?;
        let mut copies = outcome.copies.into_values();
        let first = copies.next().ok_or_else(|| RvError::ErrHsm("pool wrap produced no copy".into()))?;
        let mut kek_set = BvHsmBlobSet::new(Purpose::BarrierKek, epoch, first, &self.config.node_id, unix_now_secs()?)?;
        for copy in copies {
            kek_set.insert_copy(copy)?;
        }
        if let Some(recovery) = recovery {
            let aad = recovery::kek_recovery_aad(&cluster_uuid, epoch);
            kek_set.recovery = Some(recovery::seal_copy(&recovery.public_key, &aad, kek)?);
        }
        let mut record = HsmSealRecord::new_pool(cluster_uuid, epoch, members, kek_set);
        record.recovery_pub = recovery.cloned();
        // Write-new: a pool record names its wrap keys from the start.
        record.wrap_keys.insert(epoch, record::WrapKeyIds::of(&self.config.objects));
        {
            // Membership writer: under `hsm-custody`, and never over a record.
            let _custody_lock = self.physical.lock(crate::hsm::custody_store::HSM_CUSTODY_LOCK).await?;
            let current = self.physical.get(HSM_SEAL_RECORD_PATH).await?.map(|e| e.value);
            match (replacing, current) {
                (None, None) => {}
                (None, Some(_)) => {
                    return Err(RvError::ErrHsm("an HSM seal record already exists; refusing to overwrite it".into()))
                }
                (Some(old), Some(cur)) if cur == old => {}
                (Some(_), _) => {
                    return Err(RvError::ErrHsm("the HSM seal record changed during migration; nothing was written".into()))
                }
            }
            self.store_record(&record).await?;
            // The attestation now lives in the record's member entries.
            if attested.is_some() {
                self.physical.delete(crate::hsm::ceremony::BOOTSTRAP_RECORD_PATH).await?;
            }
        }
        hsm_metrics().set_under_replicated(UnderReplicatedScope::SealRecord, 0);
        let copies_on = record.members.values().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ");
        match &record.recovery_pub {
            None => log::warn!(
                target: "security",
                "HSM pool seal initialized with recovery=none: losing both pool devices makes this vault \
                 UNRECOVERABLE (intended posture); KEK copies on {copies_on}"
            ),
            Some(r) => log::warn!(
                target: "security",
                "HSM pool seal initialized with recovery=shamir-ceremony (recovery key {}, {} of {} shares): any {} \
                 share holders together with a copy of storage can decrypt everything (the explicit break-glass \
                 path); KEK copies on {copies_on}",
                r.fingerprint,
                r.threshold,
                r.shares,
                r.threshold
            ),
        }
        Ok(())
    }

    #[maybe_async::maybe_async]
    async fn recover_per_node(
        &self,
        backend: &Arc<dyn HsmBackend>,
        record: &HsmSealRecord,
    ) -> Result<Zeroizing<Vec<u8>>, RvError> {
        if record.topology != Topology::PerNode {
            log::error!(
                target: "security",
                "HSM seal record topology is `pool`, but this node's `hsm` block is per-node; vault stays sealed"
            );
            return Err(RvError::ErrHsm(
                "the HSM seal record has topology `pool`, but this node is configured per-node; set \
                 topology = \"pool\" with the cluster's `member` blocks"
                    .into(),
            ));
        }
        if self.config.recovery == RecoveryMode::ShamirCeremony && record.recovery_pub.is_none() {
            log::error!(
                target: "security",
                "HSM seal config sets recovery = \"shamir-ceremony\", but this cluster has no recovery key: none was \
                 ever generated for the per-node topology. Losing this node's HSM loses the vault. See \
                 features/hsm-pool-ha.md § Recovery: Shamir ceremony (T454)"
            );
        }

        // Exactly one copy is chosen, deterministically: the v2 copy bound to
        // this device, else this node's legacy v1 blob. A failure on the chosen
        // copy is final; it is never retried against the other source.
        let node_id = &self.config.node_id;
        let hsm_id = backend.hsm_id()?;
        let (blob_bytes, source) = if let Some(copy) = record.kek.as_ref().and_then(|set| set.copy_for(&hsm_id)) {
            (copy.to_bytes()?, "v2")
        } else if let Some(legacy) = record.legacy_node_blobs.get(node_id) {
            if BvHsmBlob::from_bytes(legacy)?.version() != BV_HSM_BLOB_VERSION_V1 {
                return Err(RvError::ErrHsm(format!("legacy KEK blob for node {node_id} is not a v1 blob")));
            }
            (legacy.clone(), "legacy-v1")
        } else {
            return Err(RvError::ErrHsm(format!(
                "no HSM-wrapped KEK for node {node_id} on HSM {hsm_id}; this node must be enrolled"
            )));
        };

        // Signed unwrap authorization ("the signed part"): the release decision
        // is anchored in the HSM, replay-resistant, and audited.
        let counter = self.next_counter().await?;
        let ctx = self.barrier_context(&record.cluster_uuid, record.epoch);
        let request =
            UnwrapRequest::new(ctx.context.clone(), &blob_bytes, node_id, record.epoch, counter, Purpose::BarrierKek);
        let authorization = authz::sign_authorization(backend.as_ref(), self.config.objects.authz, request).await?;

        // Every key release is an attributable, HSM-signed audit event. The
        // audit broker is not up pre-unseal, so this goes to the security log.
        log::info!(
            target: "security",
            "hsm auto-unseal authorized (hsm_id={hsm_id}, kek_copy={source}): {}",
            authz::audit_record(&authorization)
        );

        backend.unwrap_data(self.config.objects.wrap_barrier, &ctx, &blob_bytes).await
    }

    /// Spec § Unseal flow (pool topology). Never consults a recovery copy, a
    /// cache or a software path: if no member releases the KEK, stay sealed.
    #[maybe_async::maybe_async]
    async fn recover_pool(&self, devices: &PoolDevices, record: &HsmSealRecord) -> Result<Zeroizing<Vec<u8>>, RvError> {
        if record.topology != Topology::Pool {
            log::error!(
                target: "security",
                "HSM seal record topology is `per-node`, but this node's `hsm` block sets topology = \"pool\"; \
                 vault stays sealed"
            );
            return Err(RvError::ErrHsm(
                "the HSM seal record has topology `per-node`, but this node is configured for a pool; to move it, \
                 add a `migrate_from` block, run `operator hsm bootstrap`, then `operator hsm migrate-to-pool`"
                    .into(),
            ));
        }
        let kek = record.kek.as_ref().ok_or_else(|| RvError::ErrHsm("pool seal record has no KEK set".into()))?;
        let pool = devices.pool_for_record(&self.config, record)?;
        let missing = kek.missing_copies(&pool.active_ids());
        hsm_metrics().set_under_replicated(UnderReplicatedScope::SealRecord, usize::from(!missing.is_empty()));
        pool.report_under_replicated("the barrier KEK", &missing);

        let ctx = self.barrier_context(&record.cluster_uuid, record.epoch);
        let mut attempt = pool.read(|id| kek.copy_for(id).is_some());
        while let Some(member) = attempt.next_member() {
            let (Some(copy), Some(pinned)) = (kek.copy_for(member.hsm_id()), record.members.get(member.hsm_id()))
            else {
                continue;
            };
            // A counter per attempt: every authorization is fresh. A storage
            // failure here is not a member failure, so it is returned as is.
            let counter = self.next_counter().await?;
            match self.unwrap_kek_on(member, pinned, record, copy, &ctx, counter).await {
                Ok(kek) => {
                    attempt.succeeded(member);
                    return Ok(kek);
                }
                Err(e) => attempt.failed(member, "unseal", e)?,
            }
        }
        Err(attempt.into_error("HSM auto-unseal; the vault stays sealed"))
    }

    /// Steps 3.1–3.5 of the pool unseal on one member.
    #[maybe_async::maybe_async]
    async fn unwrap_kek_on(
        &self,
        member: &PoolMember,
        pinned: &HsmMember,
        record: &HsmSealRecord,
        copy: &BvHsmBlob,
        ctx: &Context,
        counter: u64,
    ) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let backend = member.backend()?;
        let blob_bytes = copy.to_bytes()?;
        let node_id = &self.config.node_id;
        let request =
            UnwrapRequest::new(ctx.context.clone(), &blob_bytes, node_id, record.epoch, counter, Purpose::BarrierKek);
        let authorization =
            authz::sign_authorization(backend.as_ref(), self.config.objects.authz, request.clone()).await?;
        // The authorization must come from the `bv-authz` key the record pins
        // for this member, which must also be the key the copy was bound to.
        let pinned_fp = authz_fingerprint_of(&pinned.authz_pub);
        if authorization.authz_fp != pinned_fp || copy.aad.authz_fp() != pinned_fp {
            log::error!(
                target: "security",
                "hsm pool member {} ({}): the device's unwrap authorization key is not the one the seal record pins",
                member.name(),
                member.hsm_id()
            );
            return Err(RvError::ErrHsmAuthzInvalid);
        }
        authz::verify_authorization(&authorization, &pinned.authz_pub, &request)?;
        log::info!(
            target: "security",
            "hsm auto-unseal authorized (topology=pool, member={}, hsm_id={}): {}",
            member.name(),
            member.hsm_id(),
            authz::audit_record(&authorization)
        );
        let keys = record.wrap_key_ids(record.epoch, &self.config.objects)?;
        backend.unwrap_data(keys.barrier, ctx, &blob_bytes).await
    }

    #[maybe_async::maybe_async]
    async fn pool_status(
        &self,
        devices: &PoolDevices,
        stored: Option<&StoredSealRecord>,
    ) -> Result<serde_json::Value, RvError> {
        use serde_json::{json, Value};
        let pool_record = stored.map(|s| &s.record).filter(|r| r.topology == Topology::Pool);
        let pool = match pool_record {
            Some(record) => devices.pool_for_record(&self.config, record)?,
            None => devices.pool(),
        };
        let kek = pool_record.and_then(|r| r.kek.as_ref());
        let members: Vec<Value> = pool
            .member_status()
            .into_iter()
            .map(|m| {
                let id = HsmId::parse(&m.hsm_id).ok();
                let recorded = match (pool_record, &id) {
                    (Some(r), Some(id)) => r.members.get(id),
                    _ => None,
                };
                let state = match (pool_record, recorded) {
                    (Some(_), Some(rm)) => Some(json!(rm.state)),
                    (Some(_), None) => None,
                    (None, _) => Some(json!("bootstrap")),
                };
                json!({
                    "name": m.name,
                    "hsm_id": m.hsm_id,
                    "serial": m.serial,
                    "state": state,
                    "up": m.up,
                    "faulted": m.faulted,
                    "prefer": m.prefer,
                    "holds_kek_copy": id.as_ref().is_some_and(|id| kek.is_some_and(|k| k.copy_for(id).is_some())),
                    "last_error": m.last_error,
                    "latency_ms": m.latency_ms,
                    "pending_revocations": recorded.map(|rm| rm.pending_revocations.clone()).unwrap_or_default(),
                })
            })
            .collect();
        // Only the KEK set is cheap to count here; custody sets are counted by
        // `CustodyStore::replication_report`, which reads the barrier.
        let kek_under = kek.is_some_and(|k| k.is_under_replicated(&pool.active_ids()));
        // Every pending revocation, including those on members this node's
        // pool leaves out (a member with one is down for every node).
        let pending: Vec<Value> = pool_record
            .map(|r| {
                r.members
                    .values()
                    .flat_map(|m| m.pending_revocations.iter().map(move |node| json!({ "member": m.name, "node": node })))
                    .collect()
            })
            .unwrap_or_default();
        let mut out = json!({
            "topology": Topology::Pool.as_str(),
            "min_wrap_copies": pool.min_wrap_copies(),
            "members": members,
            "under_replicated_sets": usize::from(kek_under),
            "kek_under_replicated": kek_under,
            "pending_revocations": pending,
            "repair": self.repair_status(),
            "device_audit": self.device_audit_status(pool_record),
        });
        if let (Some(stored), Some(obj)) = (stored, out.as_object_mut()) {
            obj.insert("cluster_uuid".into(), json!(stored.record.cluster_uuid));
            obj.insert("epoch".into(), json!(stored.record.epoch));
            obj.insert("seal_record_version".into(), json!(stored.stored_version));
            obj.insert("seal_record_topology".into(), json!(stored.record.topology.as_str()));
            obj.insert("recovery_configured".into(), json!(stored.record.recovery_pub.is_some()));
            if let Some(r) = &stored.record.recovery_pub {
                // Public values only: the fingerprint, the split, and how many
                // shares a running ceremony holds (never the shares).
                obj.insert("recovery_fingerprint".into(), json!(r.fingerprint));
                obj.insert("recovery_threshold".into(), json!(r.threshold));
                obj.insert("recovery_shares".into(), json!(r.shares));
                obj.insert("kek_recovery_copy".into(), json!(kek.is_some_and(|k| k.recovery.is_some())));
                obj.insert("recovery_progress".into(), json!(self.recovery_progress()));
            }
        } else if let Some(obj) = out.as_object_mut() {
            for key in ["cluster_uuid", "epoch", "seal_record_version", "seal_record_topology"] {
                obj.insert(key.into(), Value::Null);
            }
            obj.insert("recovery_configured".into(), json!(false));
        }
        Ok(out)
    }
}

/// Counters are written as decimal by this module only. Anything else is
/// corruption or tampering, and is an error rather than a silent reset to 0.
fn parse_counter(key: &str, raw: &[u8]) -> Result<u64, RvError> {
    std::str::from_utf8(raw).ok().and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| {
        RvError::ErrHsm(format!("unwrap counter at {key} is not a decimal integer; refusing to reset it"))
    })
}

#[maybe_async::maybe_async]
impl SealProvider for HsmSealProvider {
    fn seal_type(&self) -> &str {
        "hsm"
    }

    fn requires_shares(&self) -> bool {
        false
    }

    fn as_hsm(&self) -> Option<&HsmSealProvider> {
        Some(self)
    }

    async fn check_init(&self, _seal_config: &SealConfig) -> Result<(), RvError> {
        match &self.devices {
            Devices::PerNode(_) => self.refuse_unavailable_recovery(),
            Devices::Pool(devices) => self.check_pool_init(devices).await,
        }
    }

    async fn check_init_recovery(&self, split: Option<RecoverySplit>) -> Result<(), RvError> {
        match &self.devices {
            Devices::PerNode(_) => match split {
                None => Ok(()),
                Some(_) => Err(RvError::ErrHsmConfigInvalid(
                    "recovery_shares and recovery_threshold are not available for the per-node HSM topology (no \
                     recovery key exists there; see features/hsm-pool-ha.md § Recovery)"
                        .into(),
                )),
            },
            Devices::Pool(_) => self.pool_recovery_split(split).map(|_| ()),
        }
    }

    async fn init_kek_with_recovery(
        &self,
        kek: &[u8],
        seal_config: &SealConfig,
        split: Option<RecoverySplit>,
    ) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        match &self.devices {
            Devices::Pool(devices) => self.init_pool(devices, kek, split).await,
            Devices::PerNode(_) => {
                self.check_init_recovery(split).await?;
                self.init_kek(kek, seal_config).await
            }
        }
    }

    /// Returns the recovery shares, once, for a pool with `shamir-ceremony`
    /// (default 5 / 3); nothing otherwise.
    async fn init_kek(&self, kek: &[u8], _seal_config: &SealConfig) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        let backend = match &self.devices {
            Devices::PerNode(backend) => backend,
            Devices::Pool(devices) => return self.init_pool(devices, kek, None).await,
        };
        // `Core::init` already ran `check_init`; repeat it for direct callers.
        self.refuse_unavailable_recovery()?;

        // Fresh cluster identity for the barrier context (independent of the
        // namespace root uuid, which is not derived until post_unseal).
        let mut uuid_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut uuid_bytes);
        let cluster_uuid = hex::encode(uuid_bytes);
        let epoch = 0u64;

        let ctx = self.barrier_context(&cluster_uuid, epoch);
        let wrapped = backend.wrap_data(self.config.objects.wrap_barrier, &ctx, kek).await?;
        let copy = BvHsmBlob::from_bytes(&wrapped)?;
        let kek_set = BvHsmBlobSet::new(Purpose::BarrierKek, epoch, copy, &self.config.node_id, unix_now_secs()?)?;
        self.store_record(&HsmSealRecord::new_per_node(cluster_uuid, epoch, kek_set)).await?;

        log::warn!(
            target: "security",
            "HSM seal initialized with recovery=none: losing every cluster HSM makes this vault UNRECOVERABLE (intended posture)"
        );

        // Auto-unseal: no operator shares are produced.
        Ok(Zeroizing::new(Vec::new()))
    }

    async fn recover_kek(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
        if let Devices::Pool(devices) = &self.devices {
            // Credentials delivered since the last refresh. A delivery that
            // does not install is logged and left in place; the node keeps
            // its current credentials and tries every member as usual.
            if let Some(store) = &devices.cache.credentials {
                match node_creds::pick_up(self.physical.as_ref(), store).await {
                    Ok(installed) => devices.cache.forget_clients(&installed),
                    Err(e) => log::error!(target: "security", "HSM pool credentials could not be installed: {e}"),
                }
            }
        }
        let stored = self.load_record().await?.ok_or(RvError::ErrCoreSealConfigNotFound)?;
        match &self.devices {
            Devices::PerNode(backend) => self.recover_per_node(backend, &stored.record).await,
            Devices::Pool(devices) => self.recover_pool(devices, &stored.record).await,
        }
    }

    async fn status(&self) -> Result<serde_json::Value, RvError> {
        use serde_json::{json, Value};

        let stored = self.load_record().await?;
        let node_id = &self.config.node_id;
        let mut out = json!({
            "type": "hsm",
            "auto_unseal": true,
            "backend": self.config.backend_type,
            "node_id": node_id,
            "recovery": self.recovery_requested(),
            "recovery_requested": self.recovery_requested(),
            "pqc_key_cache_ttl_secs": self.config.pqc_key_cache_ttl.as_secs(),
        });
        let backend = match &self.devices {
            Devices::PerNode(backend) => backend,
            Devices::Pool(devices) => {
                let extra = self.pool_status(devices, stored.as_ref()).await?;
                if let (Some(out), Some(extra)) = (out.as_object_mut(), extra.as_object()) {
                    out.extend(extra.clone());
                }
                return Ok(out);
            }
        };

        let hsm_id = backend.hsm_id().ok();
        let status = match &stored {
            Some(StoredSealRecord { record: r, stored_version }) => {
                let v2_copies = r.kek.as_ref().map(|k| k.copies.len()).unwrap_or(0);
                let has_v2_copy =
                    hsm_id.as_ref().is_some_and(|id| r.kek.as_ref().is_some_and(|k| k.copy_for(id).is_some()));
                json!({
                    "cluster_uuid": r.cluster_uuid,
                    "epoch": r.epoch,
                    // Per node, each v2 copy is one node's device.
                    "enrolled_nodes": r.legacy_node_blobs.len() + v2_copies,
                    "this_node_enrolled": has_v2_copy || r.legacy_node_blobs.contains_key(node_id),
                    "topology": r.topology.as_str(),
                    "recovery_configured": r.recovery_pub.is_some(),
                    "seal_record_version": stored_version,
                })
            }
            None => json!({
                "cluster_uuid": Value::Null,
                "epoch": Value::Null,
                "enrolled_nodes": 0,
                "this_node_enrolled": false,
                "topology": Topology::PerNode.as_str(),
                "recovery_configured": false,
                "seal_record_version": Value::Null,
            }),
        };
        if let Some(obj) = out.as_object_mut() {
            obj.insert("backend".into(), json!(backend.backend_type()));
            obj.insert("device_serial".into(), json!(backend.device_serial()));
            obj.insert("hsm_id".into(), json!(hsm_id.map(String::from)));
            if let Some(extra) = status.as_object() {
                obj.extend(extra.clone());
            }
        }
        Ok(out)
    }
}

#[cfg(all(test, feature = "hsm_mock", not(feature = "sync_handler")))]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use super::*;
    use crate::hsm::{mock::MockHsmBackend, HsmObjectIds};

    /// Throwaway mock-device keys and the records the pre-T454 code (commit
    /// f4139929) wrote with them: `init_kek` for node `fixture-node` with KEK
    /// `0, 1, …, 31`, then three `recover_kek` calls (legacy counter = 3).
    const FIXTURE_STATE: &[u8] = include_bytes!("testdata/hsm-seal-v1/mock-hsm-state.json");
    const FIXTURE_RECORD: &[u8] = include_bytes!("testdata/hsm-seal-v1/core-hsm-seal.json");
    const FIXTURE_COUNTER: &[u8] = include_bytes!("testdata/hsm-seal-v1/core-hsm-authz-counter");
    const FIXTURE_NODE: &str = "fixture-node";

    fn fixture_kek() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn rand_id() -> String {
        let mut b = vec![0u8; 6];
        rand::rng().fill_bytes(&mut b);
        hex::encode(b)
    }

    fn temp_file_backend() -> Arc<dyn PhysicalBackend> {
        let dir = std::env::temp_dir().join(format!("bv-seal-hsm-{}", rand_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut conf: HashMap<String, serde_json::Value> = HashMap::new();
        conf.insert("path".to_string(), serde_json::Value::String(dir.to_string_lossy().to_string()));
        crate::storage::new_backend("file", &conf).unwrap()
    }

    fn cfg(node: &str) -> ResolvedHsmConfig {
        ResolvedHsmConfig {
            backend_type: "mock".into(),
            connector: String::new(),
            objects: HsmObjectIds::default(),
            password: Zeroizing::new(String::new()),
            domains: vec![1],
            pqc_key_cache_ttl: Duration::from_secs(60),
            recovery: RecoveryMode::None,
            state_path: String::new(),
            node_id: node.into(),
            pool: None,
            recovery_explicit: false,
        }
    }

    fn seal_config() -> SealConfig {
        SealConfig { secret_shares: 1, secret_threshold: 1 }
    }

    async fn raw(physical: &Arc<dyn PhysicalBackend>, key: &str) -> Option<Vec<u8>> {
        physical.get(key).await.unwrap().map(|e| e.value)
    }

    async fn counter_of(physical: &Arc<dyn PhysicalBackend>, node: &str) -> Option<String> {
        raw(physical, &format!("{HSM_AUTHZ_COUNTER_PREFIX}{node}")).await.map(|v| String::from_utf8(v).unwrap())
    }

    /// The mock device the fixture was captured with, plus storage holding the
    /// fixture's two physical entries exactly as the old code wrote them.
    async fn fixture(
        mut config: ResolvedHsmConfig,
    ) -> (Arc<MockHsmBackend>, Arc<dyn PhysicalBackend>, ResolvedHsmConfig) {
        let state_path = std::env::temp_dir().join(format!("bv-seal-hsm-fixture-{}.json", rand_id()));
        std::fs::write(&state_path, FIXTURE_STATE).unwrap();
        config.state_path = state_path.to_string_lossy().to_string();
        let backend = Arc::new(MockHsmBackend::open(&config).await.unwrap());
        let physical = temp_file_backend();
        physical.put(&BackendEntry { key: HSM_SEAL_RECORD_PATH.into(), value: FIXTURE_RECORD.to_vec() }).await.unwrap();
        physical
            .put(&BackendEntry { key: HSM_AUTHZ_COUNTER_LEGACY_PATH.into(), value: FIXTURE_COUNTER.to_vec() })
            .await
            .unwrap();
        (backend, physical, config)
    }

    #[tokio::test]
    async fn init_then_recover_kek_round_trip() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n1"));

        let kek = vec![7u8; 32];
        let shares = provider.init_kek(&kek, &seal_config()).await.unwrap();
        assert!(shares.is_empty(), "HSM auto-unseal returns no operator shares");

        // New records are v2, per-node, with a one-copy v2 KEK set for this device.
        let stored = HsmSealRecord::decode(&raw(&physical, HSM_SEAL_RECORD_PATH).await.unwrap()).unwrap();
        assert_eq!(stored.stored_version, record::HSM_SEAL_RECORD_VERSION);
        assert_eq!(stored.record.topology, Topology::PerNode);
        assert!(stored.record.legacy_node_blobs.is_empty());
        let kek_set = stored.record.kek.as_ref().unwrap();
        assert_eq!(kek_set.copies.keys().cloned().collect::<Vec<_>>(), vec![backend.hsm_id().unwrap()]);

        // Recover twice: both succeed and the per-node counter advances.
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), kek.as_slice());
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), kek.as_slice());
        assert_eq!(counter_of(&physical, "n1").await.as_deref(), Some("2"));
        assert_eq!(raw(&physical, HSM_AUTHZ_COUNTER_LEGACY_PATH).await, None, "the legacy counter is never written");
    }

    #[tokio::test]
    async fn another_node_on_the_same_device_recovers_from_the_v2_copy() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n1"))
            .init_kek(&[9u8; 32], &seal_config())
            .await
            .unwrap();
        let provider_b = HsmSealProvider::new(backend, physical, cfg("n2"));
        assert_eq!(provider_b.recover_kek().await.unwrap().as_slice(), &[9u8; 32]);
    }

    #[tokio::test]
    async fn recover_fails_on_a_device_without_a_copy() {
        let physical = temp_file_backend();
        let device_a = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        HsmSealProvider::new(device_a, physical.clone(), cfg("n1")).init_kek(&[9u8; 32], &seal_config()).await.unwrap();

        let device_b = Arc::new(MockHsmBackend::open(&cfg("n2")).await.unwrap());
        let err = HsmSealProvider::new(device_b, physical.clone(), cfg("n2")).recover_kek().await.unwrap_err();
        assert!(err.to_string().contains("must be enrolled"), "{err}");
        assert_eq!(counter_of(&physical, "n2").await, None, "no authorization is issued without a copy");
    }

    #[tokio::test]
    async fn v1_fixture_unseals_and_first_write_produces_v2() {
        let (backend, physical, config) = fixture(cfg(FIXTURE_NODE)).await;
        let provider = HsmSealProvider::new(backend, physical.clone(), config);

        let status = provider.status().await.unwrap();
        assert_eq!(status["seal_record_version"], 1);
        assert_eq!(status["topology"], "per-node");
        assert_eq!(status["this_node_enrolled"], true);
        assert_eq!(status["enrolled_nodes"], 1);

        // The v1 record unseals under the new code, from its legacy v1 blob.
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), fixture_kek().as_slice());
        // This node's counter starts above the legacy global one (3), which stays put.
        assert_eq!(counter_of(&physical, FIXTURE_NODE).await.as_deref(), Some("4"));
        assert_eq!(raw(&physical, HSM_AUTHZ_COUNTER_LEGACY_PATH).await.unwrap(), FIXTURE_COUNTER);
        // Unsealing is not a write: the record is still v1 on disk.
        assert_eq!(raw(&physical, HSM_SEAL_RECORD_PATH).await.unwrap(), FIXTURE_RECORD);

        // The first write converts it; the legacy blob survives byte for byte.
        let loaded = provider.load_record().await.unwrap().unwrap();
        provider.store_record(&loaded.record).await.unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&raw(&physical, HSM_SEAL_RECORD_PATH).await.unwrap()).unwrap();
        assert_eq!(written["version"], 2);
        let v1: serde_json::Value = serde_json::from_slice(FIXTURE_RECORD).unwrap();
        assert_eq!(written["legacy_node_blobs"][FIXTURE_NODE], v1["kek_blobs"][FIXTURE_NODE]);

        // ...and the converted record keeps unsealing.
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), fixture_kek().as_slice());
        assert_eq!(counter_of(&physical, FIXTURE_NODE).await.as_deref(), Some("5"));
        assert_eq!(provider.status().await.unwrap()["seal_record_version"], 2);
    }

    #[tokio::test]
    async fn v1_fixture_still_binds_its_node() {
        // v1 blobs bind node_id: another node on the same device cannot use it.
        let (backend, physical, _) = fixture(cfg("someone-else")).await;
        let provider = HsmSealProvider::new(backend, physical, cfg("someone-else"));
        assert!(provider.recover_kek().await.is_err());
    }

    #[tokio::test]
    async fn per_node_shamir_ceremony_is_refused_at_init() {
        let mut config = cfg("n1");
        config.recovery = RecoveryMode::ShamirCeremony;
        let backend = Arc::new(MockHsmBackend::open(&config).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend, physical.clone(), config);

        let err = provider.check_init(&seal_config()).await.unwrap_err();
        assert!(matches!(&err, RvError::ErrHsmConfigInvalid(m) if m.contains("features/hsm-pool-ha.md")), "{err}");
        assert!(provider.init_kek(&[1u8; 32], &seal_config()).await.is_err());
        assert_eq!(raw(&physical, HSM_SEAL_RECORD_PATH).await, None, "nothing is written");

        let mut ok = cfg("n1");
        ok.recovery = RecoveryMode::None;
        let backend = Arc::new(MockHsmBackend::open(&ok).await.unwrap());
        HsmSealProvider::new(backend, physical, ok).check_init(&seal_config()).await.unwrap();
    }

    #[tokio::test]
    async fn initialized_per_node_cluster_with_shamir_ceremony_keeps_unsealing_and_says_so() {
        let mut config = cfg(FIXTURE_NODE);
        config.recovery = RecoveryMode::ShamirCeremony;
        let (backend, physical, config) = fixture(config).await;
        let provider = HsmSealProvider::new(backend, physical, config);

        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), fixture_kek().as_slice());
        let status = provider.status().await.unwrap();
        assert_eq!(status["recovery_requested"], "shamir-ceremony");
        assert_eq!(status["recovery"], "shamir-ceremony");
        assert_eq!(status["recovery_configured"], false, "a recovery that never existed is never reported");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn per_node_counters_do_not_race_under_concurrent_unseals() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n0")).await.unwrap());
        let physical = temp_file_backend();
        HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n0"))
            .init_kek(&[5u8; 32], &seal_config())
            .await
            .unwrap();
        // A legacy global counter left by the pre-T454 code.
        physical.put(&BackendEntry { key: HSM_AUTHZ_COUNTER_LEGACY_PATH.into(), value: b"10".to_vec() }).await.unwrap();

        const NODES: usize = 6;
        const UNSEALS: u64 = 4;
        let mut tasks = Vec::new();
        for n in 0..NODES {
            let provider = Arc::new(HsmSealProvider::new(backend.clone(), physical.clone(), cfg(&format!("n{n}"))));
            tasks.push(tokio::spawn(async move {
                for _ in 0..UNSEALS {
                    assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[5u8; 32]);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        for n in 0..NODES {
            let expected = (10 + UNSEALS).to_string();
            assert_eq!(counter_of(&physical, &format!("n{n}")).await.as_deref(), Some(expected.as_str()), "node n{n}");
        }
        assert_eq!(raw(&physical, HSM_AUTHZ_COUNTER_LEGACY_PATH).await.unwrap(), b"10");
    }

    #[tokio::test]
    async fn a_corrupt_counter_is_an_error_not_a_reset() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend, physical.clone(), cfg("n1"));
        provider.init_kek(&[3u8; 32], &seal_config()).await.unwrap();

        physical
            .put(&BackendEntry { key: format!("{HSM_AUTHZ_COUNTER_PREFIX}n1"), value: b"12x".to_vec() })
            .await
            .unwrap();
        assert!(provider.recover_kek().await.is_err());

        physical.delete(&format!("{HSM_AUTHZ_COUNTER_PREFIX}n1")).await.unwrap();
        physical.put(&BackendEntry { key: HSM_AUTHZ_COUNTER_LEGACY_PATH.into(), value: b"-1".to_vec() }).await.unwrap();
        assert!(provider.recover_kek().await.is_err(), "a corrupt legacy counter does not seed 0");
    }

    /// Phase 1 refused every pool record; now a per-node node refuses one
    /// explicitly (its config is wrong), and unknown versions stay sealed.
    #[tokio::test]
    async fn a_per_node_node_refuses_a_pool_record_and_unknown_versions_stay_sealed() {
        let backend = Arc::new(MockHsmBackend::open(&cfg("n1")).await.unwrap());
        let physical = temp_file_backend();
        let provider = HsmSealProvider::new(backend.clone(), physical.clone(), cfg("n1"));
        provider.init_kek(&[3u8; 32], &seal_config()).await.unwrap();

        let mut record = provider.load_record().await.unwrap().unwrap().record;
        record.topology = Topology::Pool;
        record.members.insert(
            backend.hsm_id().unwrap(),
            record::HsmMember {
                name: "hsm-a".into(),
                gateway: String::new(),
                serial: backend.device_serial(),
                identity_pub: backend.identity_public_key().unwrap(),
                seed_ecdh_pub: backend.identity_public_key().unwrap(),
                authz_pub: backend.authz_public_key().unwrap(),
                authz_alg: crate::hsm::AuthzAlg::Ed25519,
                attestation_fps: vec![],
                state: record::MemberState::Active,
                pending_revocations: vec![],
            },
        );
        provider.store_record(&record).await.unwrap();
        let err = provider.recover_kek().await.unwrap_err();
        assert!(err.to_string().contains("set topology = \"pool\""), "{err}");

        let mut future: serde_json::Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
        future["version"] = 3.into();
        physical
            .put(&BackendEntry { key: HSM_SEAL_RECORD_PATH.into(), value: serde_json::to_vec(&future).unwrap() })
            .await
            .unwrap();
        assert!(provider.recover_kek().await.is_err());
        assert!(provider.status().await.is_err());
    }

    // ── Pool topology (T454 phase 2) ─────────────────────────────────────

    use bv_metrics::hsm_metrics::SessionErrorKind;

    use crate::{
        hsm::{
            clock::ManualClock,
            custody_store::{CustodyScope, CustodyStore},
            derive::PqcKeyKind,
            mock::{MockHsmDevice, MOCK_MAX_SESSIONS, MOCK_SESSION_IDLE_TIMEOUT},
            pool::{PoolEvent, PoolEventKind, BREAKER_BACKOFF_MIN, BREAKER_THRESHOLD},
            ResolvedPoolMember,
        },
        storage::{barrier::SecurityBarrier, barrier_aes_gcm::AESGCMBarrier, test_support::new_test_backend, Storage},
    };

    #[derive(Default)]
    struct Recorder(Mutex<Vec<PoolEvent>>);

    impl PoolEventSink for Recorder {
        fn emit(&self, event: &PoolEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    impl Recorder {
        fn seen(&self, kind: PoolEventKind, member: &str) -> bool {
            self.0.lock().unwrap().iter().any(|e| e.kind == kind && e.member == member)
        }

        fn count(&self, kind: PoolEventKind) -> usize {
            self.0.lock().unwrap().iter().filter(|e| e.kind == kind).count()
        }
    }

    /// Two in-process mock devices, shared by every node of a test cluster,
    /// on one manual clock. Member names are per test, so metrics never mix.
    struct Cluster {
        a: Arc<MockHsmDevice>,
        b: Arc<MockHsmDevice>,
        clock: Arc<ManualClock>,
        physical: Arc<dyn PhysicalBackend>,
        events: Arc<Recorder>,
        name_a: String,
        name_b: String,
    }

    impl Cluster {
        fn new(tag: &str) -> Self {
            let clock = ManualClock::new();
            Self {
                a: MockHsmDevice::open("", Some(&format!("A-{tag}")), clock.clone()).unwrap(),
                b: MockHsmDevice::open("", Some(&format!("B-{tag}")), clock.clone()).unwrap(),
                clock,
                physical: temp_file_backend(),
                events: Arc::new(Recorder::default()),
                name_a: format!("{tag}-a"),
                name_b: format!("{tag}-b"),
            }
        }

        fn id_a(&self) -> HsmId {
            HsmId::from_parts("mock", &self.a.serial()).unwrap()
        }

        fn id_b(&self) -> HsmId {
            HsmId::from_parts("mock", &self.b.serial()).unwrap()
        }

        /// `prefer = true` on A makes every node try A first, deterministically.
        fn config(&self, node: &str, min_wrap_copies: usize) -> ResolvedHsmConfig {
            let member = |name: &str, device: &MockHsmDevice, prefer: bool| ResolvedPoolMember {
                name: name.into(),
                gateway: String::new(),
                connector: String::new(),
                serial: device.serial(),
                state_path: format!("/unused/{name}.json"),
                prefer,
            };
            ResolvedHsmConfig {
                pool: Some(ResolvedPoolConfig {
                    min_wrap_copies,
                    repair_rate: crate::hsm::repair::DEFAULT_REPAIR_RATE,
                    credential_dir: String::new(),
                    link: None,
                    migrate_from: None,
                    members: vec![member(&self.name_a, &self.a, true), member(&self.name_b, &self.b, false)],
                    device_audit: crate::hsm::device_audit::DeviceAuditMode::Drain,
                }),
                recovery_explicit: true,
                ..cfg(node)
            }
        }

        fn opened(&self, node: &str) -> BTreeMap<String, Result<Arc<dyn HsmBackend>, String>> {
            let client = |device: &Arc<MockHsmDevice>| -> Result<Arc<dyn HsmBackend>, String> {
                Ok(Arc::new(MockHsmBackend::connect(device.clone(), node, HsmObjectIds::default()).unwrap()))
            };
            BTreeMap::from([(self.name_a.clone(), client(&self.a)), (self.name_b.clone(), client(&self.b))])
        }

        fn provider_with(&self, config: ResolvedHsmConfig) -> HsmSealProvider {
            let opened = self.opened(&config.node_id);
            HsmSealProvider::new_pool(opened, self.physical.clone(), config, self.clock.clone(), self.events.clone())
                .unwrap()
        }

        fn provider(&self, node: &str) -> HsmSealProvider {
            self.provider_with(self.config(node, 1))
        }

        async fn init(&self, kek: &[u8]) -> HsmSealProvider {
            let provider = self.provider("n1");
            provider.check_init(&seal_config()).await.unwrap();
            provider.init_kek(kek, &seal_config()).await.unwrap();
            provider
        }
    }

    /// A custody store on a fresh barrier over `provider`'s pool.
    async fn custody_over(provider: &HsmSealProvider, name: &str) -> CustodyStore {
        let barrier = AESGCMBarrier::new(new_test_backend(name));
        let key = barrier.generate_key().unwrap();
        barrier.init(&key).await.unwrap();
        barrier.unseal(&key).await.unwrap();
        let storage: Arc<dyn Storage> = Arc::new(barrier);
        let pool = provider.pool().unwrap();
        let binding_pub = pool.members()[0].backend().unwrap().identity_public_key().unwrap();
        let scope = CustodyScope {
            cluster_uuid: "clu".into(),
            epoch: 0,
            ecdh_key: HsmObjectIds::default().identity,
            binding_pub,
            pqc_wrap_keys: Default::default(),
            recovery_pub: None,
        };
        CustodyStore::with_pool(storage, pool, provider.config.clone(), scope)
    }

    #[tokio::test]
    async fn pool_init_dual_wraps_the_kek_and_every_node_unseals() {
        let c = Cluster::new("init");
        c.init(&[7u8; 32]).await;

        let stored = HsmSealRecord::decode(&raw(&c.physical, HSM_SEAL_RECORD_PATH).await.unwrap()).unwrap();
        assert_eq!(stored.stored_version, record::HSM_SEAL_RECORD_VERSION);
        let r = &stored.record;
        assert_eq!(r.topology, Topology::Pool);
        assert!(r.legacy_node_blobs.is_empty() && r.recovery_pub.is_none());
        assert_eq!(r.members.keys().cloned().collect::<Vec<_>>(), vec![c.id_a(), c.id_b()]);
        assert!(r.members.values().all(|m| m.state == MemberState::Active));
        assert_eq!(r.members[&c.id_a()].name, c.name_a);
        let kek_set = r.kek.as_ref().unwrap();
        assert_eq!(kek_set.copies.keys().cloned().collect::<Vec<_>>(), vec![c.id_a(), c.id_b()], "one copy per member");

        for node in ["n1", "n2", "n3"] {
            assert_eq!(c.provider(node).recover_kek().await.unwrap().as_slice(), &[7u8; 32], "{node}");
        }
        assert_eq!(c.events.count(PoolEventKind::CryptoFailure), 0);
    }

    #[tokio::test]
    async fn pool_init_needs_explicit_recovery_and_both_members() {
        let c = Cluster::new("initgate");
        let mut implicit = c.config("n1", 1);
        implicit.recovery_explicit = false;
        let err = c.provider_with(implicit).check_init(&seal_config()).await.unwrap_err();
        assert!(err.to_string().contains("explicit `recovery`"), "{err}");

        // Explicit recovery parameters are refused, never ignored, without a
        // recovery key to split; and a bad split is refused before any write.
        let none = c.provider("n1");
        let split = Some(RecoverySplit { shares: 5, threshold: 3 });
        assert!(none.check_init_recovery(split).await.unwrap_err().to_string().contains("shamir-ceremony"));
        let mut shamir = c.config("n1", 1);
        shamir.recovery = RecoveryMode::ShamirCeremony;
        let provider = c.provider_with(shamir);
        provider.check_init(&seal_config()).await.unwrap();
        provider.check_init_recovery(split).await.unwrap();
        assert!(provider.check_init_recovery(Some(RecoverySplit { shares: 5, threshold: 1 })).await.is_err());
        assert_eq!(raw(&c.physical, HSM_SEAL_RECORD_PATH).await, None, "nothing is written by the checks");
        // Only this pool returns recovery shares, so only it is refused by the
        // frozen `v1/sys/init` (whose response has no field for them).
        assert!(provider.init_returns_recovery_shares());
        assert!(!none.init_returns_recovery_shares());

        c.b.set_offline(true);
        let provider = c.provider("n1");
        let err = provider.check_init(&seal_config()).await.unwrap_err();
        assert!(matches!(&err, RvError::ErrHsmPoolUnavailable(m) if m.contains(&c.name_b)), "{err}");
        assert!(provider.init_kek(&[1u8; 32], &seal_config()).await.is_err());
        assert_eq!(raw(&c.physical, HSM_SEAL_RECORD_PATH).await, None, "nothing is written");
    }

    #[tokio::test]
    async fn pool_init_never_overwrites_an_existing_record() {
        let c = Cluster::new("reinit");
        c.init(&[1u8; 32]).await;
        let before = raw(&c.physical, HSM_SEAL_RECORD_PATH).await;
        assert!(c.provider("n2").init_kek(&[2u8; 32], &seal_config()).await.is_err());
        assert_eq!(raw(&c.physical, HSM_SEAL_RECORD_PATH).await, before);
    }

    #[tokio::test]
    async fn unseal_fails_over_when_the_preferred_member_is_down() {
        let c = Cluster::new("failover");
        c.init(&[5u8; 32]).await;
        let b_sessions = c.b.open_sessions();
        c.a.set_offline(true);

        let provider = c.provider("n2");
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[5u8; 32]);
        assert_eq!(c.b.open_sessions(), b_sessions + 1, "served by B");
        let a = provider.pool().unwrap().member_status().into_iter().find(|m| m.name == c.name_a).unwrap();
        assert!(a.last_error.as_deref().unwrap_or_default().contains("unreachable"), "{a:?}");
        assert_eq!(hsm_metrics().session_errors(&c.name_a, SessionErrorKind::Transport), 1);
        assert_eq!(c.events.count(PoolEventKind::CryptoFailure), 0);
        // Every attempt took a fresh authorization counter.
        assert_eq!(counter_of(&c.physical, "n2").await.as_deref(), Some("2"));
    }

    #[tokio::test]
    async fn a_crypto_mismatch_on_the_preferred_member_never_fails_over() {
        let c = Cluster::new("crypto");
        let provider = c.init(&[6u8; 32]).await;
        let original = provider.load_record().await.unwrap().unwrap().record;
        let b_sessions = c.b.open_sessions();

        // A's copy is tampered with in storage: the device's AEAD tag fails.
        let mut tampered = original.clone();
        let copy = tampered.kek.as_mut().unwrap().copies.get_mut(&c.id_a()).unwrap();
        let last = copy.wrapped.len() - 1;
        copy.wrapped[last] ^= 0x01;
        provider.store_record(&tampered).await.unwrap();
        assert_eq!(c.provider("n2").recover_kek().await.unwrap_err(), RvError::ErrHsmContextMismatch);
        assert_eq!(c.b.open_sessions(), b_sessions, "B is never asked: tampering is not an outage");
        assert!(c.events.seen(PoolEventKind::CryptoFailure, &c.name_a));
        assert_eq!(hsm_metrics().session_errors(&c.name_a, SessionErrorKind::Crypto), 1);

        // The record pins A's authorization key; another key is refused alike.
        let mut repinned = original.clone();
        let b_authz = repinned.members[&c.id_b()].authz_pub.clone();
        repinned.members.get_mut(&c.id_a()).unwrap().authz_pub = b_authz;
        provider.store_record(&repinned).await.unwrap();
        assert_eq!(c.provider("n3").recover_kek().await.unwrap_err(), RvError::ErrHsmAuthzInvalid);
        assert_eq!(c.b.open_sessions(), b_sessions);
        assert_eq!(c.events.count(PoolEventKind::CryptoFailure), 2);
    }

    #[tokio::test]
    async fn with_both_members_down_the_node_stays_sealed_and_names_each() {
        let c = Cluster::new("bothdown");
        c.init(&[4u8; 32]).await;
        c.a.set_offline(true);
        c.b.set_offline(true);
        match c.provider("n2").recover_kek().await {
            Err(RvError::ErrHsmPoolUnavailable(msg)) => {
                assert!(msg.contains(&c.name_a) && msg.contains(&c.name_b), "{msg}");
                assert!(msg.contains("stays sealed"), "{msg}");
            }
            other => panic!("expected ErrHsmPoolUnavailable, got {:?}", other.map(|_| "a KEK")),
        }
    }

    #[tokio::test]
    async fn with_a_down_nodes_unseal_and_create_under_replicated_keys() {
        let c = Cluster::new("adown");
        c.init(&[8u8; 32]).await;
        c.a.set_offline(true);

        let provider = c.provider("n2");
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[8u8; 32]);
        let store = custody_over(&provider, "pool_adown").await;
        let (handle, _) = store.create(PqcKeyKind::MlKem768).await.unwrap();
        let report = store.replication_report().await.unwrap();
        assert_eq!(report.total_sets, 1);
        assert_eq!(report.under_replicated.len(), 1);
        assert_eq!(report.under_replicated[0].missing, vec![c.id_a()]);
        assert_eq!(c.events.count(PoolEventKind::SetUnderReplicated), 1);
        assert_eq!(hsm_metrics().under_replicated(), 1, "KEK fully replicated, one custody set short");
        store.with_private(&handle, |_| ()).await.unwrap();

        // min_wrap_copies = 2 refuses creation with one member down.
        let strict = c.provider_with(c.config("n3", 2));
        let store = custody_over(&strict, "pool_adown_strict").await;
        match store.create(PqcKeyKind::MlDsa65).await {
            Err(RvError::ErrHsmInsufficientCopies { have, need, unreachable }) => {
                assert_eq!((have, need), (1, 2));
                assert!(unreachable.len() == 1 && unreachable[0].contains(&c.name_a), "{unreachable:?}");
            }
            other => panic!("expected ErrHsmInsufficientCopies, got {:?}", other.map(|_| "a key")),
        }
        assert_eq!(store.replication_report().await.unwrap().total_sets, 0, "nothing is stored");
    }

    #[tokio::test]
    async fn session_exhaustion_backs_off_and_fails_over() {
        let c = Cluster::new("sessions");
        c.init(&[9u8; 32]).await;
        c.clock.advance(MOCK_SESSION_IDLE_TIMEOUT); // init's sessions idle out
        let others: Vec<MockHsmBackend> = (0..MOCK_MAX_SESSIONS)
            .map(|i| MockHsmBackend::connect(c.a.clone(), &format!("other-{i}"), HsmObjectIds::default()).unwrap())
            .collect();
        for other in &others {
            other.get_random(1).await.unwrap();
        }

        let provider = c.provider("n2");
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[9u8; 32], "B serves");
        assert_eq!(hsm_metrics().session_errors(&c.name_a, SessionErrorKind::SessionsFull), 1);
        let a = provider.pool().unwrap().member_status().into_iter().find(|m| m.name == c.name_a).unwrap();
        assert!(a.up, "SESSIONS_FULL is saturation, not an outage");

        // Inside the backoff A is not asked again.
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[9u8; 32]);
        assert_eq!(hsm_metrics().session_errors(&c.name_a, SessionErrorKind::SessionsFull), 1);

        // The other sessions idle out and the backoff (at most 100 ms) has passed.
        c.clock.advance(MOCK_SESSION_IDLE_TIMEOUT);
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[9u8; 32]);
        assert_eq!(c.a.open_sessions(), 1, "A, preferred, serves again");
        assert_eq!(c.b.open_sessions(), 0);
    }

    #[tokio::test]
    async fn the_breaker_opens_after_three_failures_and_closes_through_the_probe() {
        let c = Cluster::new("breaker");
        let provider = c.init(&[2u8; 32]).await;
        let pool = provider.pool().unwrap();
        let a_up = |pool: &HsmPool| pool.member_status().into_iter().find(|m| m.name == c.name_a).unwrap().up;
        let transport = || hsm_metrics().session_errors(&c.name_a, SessionErrorKind::Transport);

        c.a.set_offline(true);
        for _ in 0..BREAKER_THRESHOLD - 1 {
            pool.probe_all().await;
        }
        assert!(a_up(&pool), "two failures do not open the breaker");
        pool.probe_all().await;
        assert!(!a_up(&pool));
        assert!(c.events.seen(PoolEventKind::MemberDown, &c.name_a));
        assert_eq!(hsm_metrics().member_up(&c.name_a), Some(false));

        // While open, neither unseal nor the probe waits on A.
        let failures = transport();
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[2u8; 32]);
        pool.probe_all().await;
        assert_eq!(transport(), failures);

        // After 1 s one probe goes through; it fails and the backoff doubles.
        c.clock.advance(BREAKER_BACKOFF_MIN);
        pool.probe_all().await;
        assert_eq!(transport(), failures + 1);
        c.a.set_offline(false);
        c.clock.advance(BREAKER_BACKOFF_MIN);
        pool.probe_all().await;
        assert!(!a_up(&pool), "still inside the 2 s backoff");
        c.clock.advance(BREAKER_BACKOFF_MIN);
        pool.probe_all().await;
        assert!(a_up(&pool));
        assert!(c.events.seen(PoolEventKind::MemberUp, &c.name_a));
        assert_eq!(hsm_metrics().member_up(&c.name_a), Some(true));
    }

    #[tokio::test]
    async fn the_seal_record_not_the_config_decides_membership() {
        let c = Cluster::new("authority");
        c.init(&[1u8; 32]).await;

        // This node's config names another serial for B: ignored, the record wins.
        let mut stale = c.config("n2", 1);
        stale.pool.as_mut().unwrap().members[1].serial = "B-SOMETHING-ELSE".into();
        let provider = c.provider_with(stale);
        assert_eq!(provider.recover_kek().await.unwrap().as_slice(), &[1u8; 32]);
        let status = provider.status().await.unwrap();
        let members = status["members"].as_array().unwrap();
        assert!(members.iter().all(|m| m["up"] == true && m["state"] == "active"), "{status}");
        assert!(members.iter().any(|m| m["serial"] == c.b.serial().as_str()), "{status}");
    }

    #[tokio::test]
    async fn pool_and_per_node_records_never_cross() {
        let c = Cluster::new("cross");
        let per_node = HsmSealProvider::new(
            Arc::new(MockHsmBackend::connect(c.a.clone(), "n1", HsmObjectIds::default()).unwrap()),
            c.physical.clone(),
            cfg("n1"),
        );
        per_node.init_kek(&[3u8; 32], &seal_config()).await.unwrap();
        let err = c.provider("n1").recover_kek().await.unwrap_err();
        assert!(err.to_string().contains("migrate-to-pool"), "{err}");
    }

    #[tokio::test]
    async fn the_pool_topology_needs_storage_with_a_cluster_lock() {
        let c = Cluster::new("gate");
        let no_lock = crate::storage::new_backend("mock", &HashMap::new()).unwrap();
        let err =
            HsmSealProvider::new_pool(c.opened("n1"), no_lock, c.config("n1", 1), c.clock.clone(), c.events.clone())
                .err()
                .unwrap();
        assert!(matches!(&err, RvError::ErrHsmConfigInvalid(m) if m.contains("\"mock\"")), "{err}");
    }

    #[tokio::test]
    async fn pool_status_reports_members_and_never_secrets() {
        let c = Cluster::new("status");
        let provider = c.init(&[0xA5u8; 32]).await;
        c.b.set_offline(true);
        provider.pool().unwrap().probe_all().await;

        let status = provider.status().await.unwrap();
        assert_eq!(status["topology"], "pool");
        assert_eq!(status["min_wrap_copies"], 1);
        assert_eq!(status["under_replicated_sets"], 0);
        assert_eq!(status["seal_record_version"], 2);
        let members = status["members"].as_array().unwrap();
        assert_eq!(members.len(), 2);
        for m in members {
            for key in ["name", "hsm_id", "serial", "state", "up", "last_error", "holds_kek_copy"] {
                assert!(m.get(key).is_some(), "member status lacks {key}: {m}");
            }
        }
        let b = members.iter().find(|m| m["name"] == c.name_b.as_str()).unwrap();
        assert!(b["last_error"].as_str().unwrap().contains("unreachable"), "{b}");
        let text = status.to_string();
        for secret in ["165,165,165", "wrapped", "authz_pub", "identity_pub"] {
            assert!(!text.contains(secret), "status leaks {secret:?}: {text}");
        }
    }
}
