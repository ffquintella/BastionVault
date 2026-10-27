//! Software mock HSM backend (feature `hsm_mock`).
//!
//! Implements the full [`HsmBackend`] contract in software so dev and
//! homologation clusters (which have no USB passthrough) exercise the identical
//! code path minus the hardware. It provides **zero** hardware protection: it is
//! compile-time gated behind `hsm_mock`, refuses to start when the environment
//! is production (enforced in [`crate::hsm::new_backend`]), and its object
//! store is a plaintext file.
//!
//! The mock honors the same object model, capability separation (wrap keys
//! cannot sign; identity/authz keys cannot unwrap), context strings, and blob
//! wire format as the real device.

// A `MockHsmDevice` is the device and a `MockHsmBackend` one client of it (one
// session owner). Like the YubiHSM 2 it holds 16 sessions, expires one after
// 30 s idle, answers SESSIONS_FULL past that, and can be set offline. It keeps
// a 62-entry device log in memory (T454 phase 6), per process like its
// session table, so a restart or a second process starts a new log.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        admin::{
            node_slot_of, verify_layout, AuthKeyRole, HsmAdminSession, NodeCredential, ObjectInfo, ObjectKind,
            ADMIN_AUTH_KEY_ID, FACTORY_AUTH_KEY_ID, WRAP_KEY_CAPABILITIES,
        },
        blob::{open_blob, seal_blob, Context, HsmId},
        ceremony::AttestationBundle,
        clock::{self, Clock},
        device_audit::{
            AuditorCredential, DeviceLog, DeviceLogEntry, HsmAuditSession, AUDITOR_AUTH_KEY_ID, DEVICE_LOG_CAPACITY,
        },
        domain_separated, AttestedKey, HsmBackend, HsmObjectId, HsmObjectIds, ResolvedHsmConfig,
    },
};

/// YubiHSM 2 command codes the mock writes to its device log.
mod cmd {
    pub const PUT_AUTHENTICATION_KEY: u8 = 0x44;
    pub const GET_OBJECT_INFO: u8 = 0x4e;
    pub const SET_OPTION: u8 = 0x4f;
    pub const GET_PSEUDO_RANDOM: u8 = 0x51;
    pub const GET_PUBLIC_KEY: u8 = 0x54;
    pub const SIGN_ECDSA: u8 = 0x56;
    pub const DERIVE_ECDH: u8 = 0x57;
    pub const DELETE_OBJECT: u8 = 0x58;
    pub const GENERATE_WRAP_KEY: u8 = 0x5b;
    pub const SIGN_ATTESTATION_CERTIFICATE: u8 = 0x64;
    pub const WRAP_DATA: u8 = 0x68;
    pub const UNWRAP_DATA: u8 = 0x69;
    pub const SIGN_EDDSA: u8 = 0x6a;
}

/// No second key in a log entry.
const NO_KEY: u16 = 0xffff;

/// The device log: the last [`DEVICE_LOG_CAPACITY`] entries, each chaining
/// the digest of the one before, and the index the auditor acknowledged.
#[derive(Default)]
struct MockLog {
    entries: VecDeque<DeviceLogEntry>,
    last_index: u16,
    last_digest: [u8; 16],
    acked: u16,
    unlogged_boot: u16,
    unlogged_auth: u16,
}

impl MockLog {
    fn unacknowledged(&self) -> usize {
        usize::from(self.last_index.wrapping_sub(self.acked))
    }
}

const AES_NONCE_LEN: usize = 12;
/// Concurrent sessions per device (YubiHSM 2 limit).
pub const MOCK_MAX_SESSIONS: usize = 16;
/// A session idle this long is expired by the device (YubiHSM 2 behaviour).
pub const MOCK_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The kind of a provisioned mock object, mirroring the real device's object
/// types and their capability masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MockKind {
    /// AES-256 wrap key: `wrap-data` / `unwrap-data` only.
    Wrap,
    /// ECC P-256: `sign-ecdsa`, `derive-ecdh`, attestation.
    Identity,
    /// Ed25519: `sign-eddsa` only (unwrap authorizations).
    Authz,
    /// ECC P-256 `bv-seed-ecdh`: `derive-ecdh` only (T454 phase 4 layout).
    SeedEcdh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredObject {
    kind: MockKind,
    /// Wrap: 32-byte AES key. Identity: 32-byte P-256 scalar. Authz: 32-byte
    /// Ed25519 seed. Never leaves the process except re-wrapped (enrollment).
    #[serde(with = "serde_bytes")]
    material: Vec<u8>,
    /// Capabilities beyond the kind's own set. Only a test that simulates a
    /// mis-provisioned device writes this; layout verification must catch it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extra_capabilities: Vec<String>,
}

/// An authentication key (T454 phase 4). The id namespace is separate from
/// data objects, as on the device. `key` is the derived session key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MockAuthKey {
    label: String,
    role: AuthKeyRole,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MockState {
    serial: String,
    objects: BTreeMap<u16, StoredObject>,
    /// Empty on every pre-phase-4 device: those accept unauthenticated
    /// sessions, as before. A device with `bv-admin` is provisioned.
    #[serde(default)]
    auth_keys: BTreeMap<u16, MockAuthKey>,
    /// The forced-audit option (T454 phase 6). Absent, as in every earlier
    /// state file, means off; written only when on.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    forced_audit: bool,
}

impl MockState {
    fn provisioned(&self) -> bool {
        self.auth_keys.contains_key(&ADMIN_AUTH_KEY_ID)
    }

    fn factory(&self) -> bool {
        self.objects.is_empty()
            && self.auth_keys.len() == 1
            && self.auth_keys.get(&FACTORY_AUTH_KEY_ID).is_some_and(|k| k.role == AuthKeyRole::Factory)
    }
}

/// The mock's password-to-session-key derivation, standing in for the
/// device's PBKDF2. The mock protects nothing; this only keeps passwords out
/// of its state file.
fn mock_password_key(password: &str) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"bastionvault/mock-hsm/password/v1"), password.as_bytes());
    let mut out = vec![0u8; 32];
    hk.expand(b"auth-key", &mut out).expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn auth_failed(id: u16, serial: &str) -> RvError {
    RvError::ErrHsm(format!(
        "authentication with auth key {id:#06x} failed on mock HSM {serial}: the key does not exist or the credential \
         is wrong"
    ))
}

/// One simulated device: its object store, session table and link state.
pub struct MockHsmDevice {
    /// Path backing the object store; empty ⇒ ephemeral (tests).
    state_path: String,
    /// In-memory object store. Persisted to `state_path` on provisioning so dev
    /// clusters survive restarts. `RwLock` guards provisioning-time mutation.
    state: RwLock<MockState>,
    /// Session owner → last use. Per process: two processes opening the same
    /// `state_path` are two devices as far as the session limit goes.
    sessions: Mutex<BTreeMap<String, Duration>>,
    offline: AtomicBool,
    clock: Arc<dyn Clock>,
    log: Mutex<MockLog>,
}

impl MockHsmDevice {
    fn from_state(state_path: &str, state: MockState, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            state_path: state_path.to_string(),
            state: RwLock::new(state),
            sessions: Mutex::new(BTreeMap::new()),
            offline: AtomicBool::new(false),
            clock,
            log: Mutex::new(MockLog::default()),
        })
    }

    fn device_log(&self) -> std::sync::MutexGuard<'_, MockLog> {
        // Bookkeeping only; a panic elsewhere must not wedge the device.
        self.log.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn forced_audit(&self) -> bool {
        self.state.read().map(|s| s.forced_audit).unwrap_or(true)
    }

    /// Forced audit: a loggable command is refused while the log holds
    /// [`DEVICE_LOG_CAPACITY`] unacknowledged entries (`LOG_FULL`), so no
    /// command ever runs unlogged.
    fn admit(&self) -> Result<(), RvError> {
        self.reachable()?;
        if self.forced_audit() && self.device_log().unacknowledged() >= DEVICE_LOG_CAPACITY {
            return Err(RvError::ErrHsm(format!(
                "mock HSM {}: LOG_FULL (forced audit is on and the device log is full until the drain acknowledges it)",
                self.serial()
            )));
        }
        Ok(())
    }

    /// Append one entry, chained to the one before; the oldest is overwritten
    /// once the buffer is full (only possible with forced audit off).
    fn record(&self, command: u8, session_key: u16, target_key: u16, ok: bool) {
        let systick = u32::try_from(self.clock.now().as_millis() & u128::from(u32::MAX)).unwrap_or(0);
        let mut log = self.device_log();
        let mut entry = DeviceLogEntry {
            index: log.last_index.wrapping_add(1),
            command,
            length: 0,
            session_key,
            target_key,
            second_key: NO_KEY,
            result: if ok { 0x80 | command } else { 0x7f },
            systick,
            digest: [0; 16],
        };
        entry.digest = entry.chained_digest(&log.last_digest);
        log.last_index = entry.index;
        log.last_digest = entry.digest;
        if log.entries.len() == DEVICE_LOG_CAPACITY {
            log.entries.pop_front();
        }
        log.entries.push_back(entry);
    }

    /// Run `command` as the device does: admitted, executed, logged.
    fn logged<T>(
        &self,
        command: u8,
        session_key: u16,
        target_key: u16,
        run: impl FnOnce() -> Result<T, RvError>,
    ) -> Result<T, RvError> {
        self.admit()?;
        let out = run();
        // An unreachable device logs nothing; it never saw the command.
        if !matches!(out, Err(RvError::ErrHsmTransport(_))) {
            self.record(command, session_key, target_key, out.is_ok());
        }
        out
    }

    /// A session authenticated with `bv-auditor` (T454 phase 6).
    pub fn auditor_session(self: &Arc<Self>, credential: &AuditorCredential) -> Result<MockAuditSession, RvError> {
        self.authenticate_auditor(credential)?;
        self.session(AUDITOR_SESSION_OWNER)?;
        Ok(MockAuditSession { device: self.clone(), credential: credential.clone() })
    }

    fn authenticate_auditor(&self, credential: &AuditorCredential) -> Result<(), RvError> {
        self.reachable()?;
        let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        match state.auth_keys.get(&AUDITOR_AUTH_KEY_ID) {
            Some(k) if k.role == AuthKeyRole::Auditor && k.key.as_slice() == credential.key() => Ok(()),
            _ => Err(auth_failed(AUDITOR_AUTH_KEY_ID, &state.serial)),
        }
    }

    /// Whether the forced-audit option is on (tests, status).
    pub fn forced_audit_on(&self) -> bool {
        self.forced_audit()
    }

    /// Change entry `index` in place, as tampering with the log would.
    #[cfg(test)]
    pub(crate) fn tamper_log_entry(&self, index: u16) {
        let mut log = self.device_log();
        if let Some(e) = log.entries.iter_mut().find(|e| e.index == index) {
            e.target_key ^= 1;
        }
    }

    /// The newest entry's index (0 before any command).
    #[cfg(test)]
    pub(crate) fn newest_log_index(&self) -> u16 {
        self.device_log().last_index
    }

    /// A power cycle that lost the log: it restarts at index 1, and the
    /// device counts one boot it could not log.
    #[cfg(test)]
    pub(crate) fn restart_log(&self) {
        let mut log = self.device_log();
        let unlogged_boot = log.unlogged_boot.saturating_add(1);
        *log = MockLog { unlogged_boot, ..MockLog::default() };
    }
    /// Open the device at `state_path`. A new device takes `serial_if_new`
    /// (a random `MOCK-…` serial when `None`); an existing one keeps its own,
    /// so a wrong file is caught by the caller's serial check, not hidden.
    pub fn open(state_path: &str, serial_if_new: Option<&str>, clock: Arc<dyn Clock>) -> Result<Arc<Self>, RvError> {
        let mut state = load_state(state_path)?;
        if state.serial.is_empty() {
            state.serial = match serial_if_new {
                Some(serial) => serial.to_string(),
                None => format!("MOCK-{}", hex::encode(random_bytes(6))),
            };
            persist_state(state_path, &state)?;
        }
        Ok(Self::from_state(state_path, state, clock))
    }

    pub fn serial(&self) -> String {
        self.state.read().map(|s| s.serial.clone()).unwrap_or_default()
    }

    /// Simulate the device, its host or its link going down (or coming back).
    pub fn set_offline(&self, offline: bool) {
        self.offline.store(offline, Ordering::SeqCst);
    }

    /// Sessions currently held (idle ones past the timeout are not counted).
    pub fn open_sessions(&self) -> usize {
        let now = self.clock.now();
        self.sessions
            .lock()
            .map(|s| s.values().filter(|last| now.saturating_sub(**last) < MOCK_SESSION_IDLE_TIMEOUT).count())
            .unwrap_or(0)
    }

    fn reachable(&self) -> Result<(), RvError> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(RvError::ErrHsmTransport(format!("mock HSM {} is unreachable", self.serial())));
        }
        Ok(())
    }

    /// Use (or open) `owner`'s session, as every authenticated command does.
    fn session(&self, owner: &str) -> Result<(), RvError> {
        self.reachable()?;
        let now = self.clock.now();
        let mut sessions = self.sessions.lock().map_err(|_| RvError::ErrRwLockWritePoison)?;
        sessions.retain(|_, last| now.saturating_sub(*last) < MOCK_SESSION_IDLE_TIMEOUT);
        if !sessions.contains_key(owner) && sessions.len() >= MOCK_MAX_SESSIONS {
            return Err(RvError::ErrHsmSessionsFull);
        }
        sessions.insert(owner.to_string(), now);
        Ok(())
    }

    fn close_session(&self, owner: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(owner);
        }
    }

    /// Provision any missing object `objects` names. Keys come from host
    /// CSPRNG bytes (the codebase's idiom, avoiding the rand_core version
    /// split) and are persisted so restarts reuse them.
    fn ensure_objects(&self, objects: &HsmObjectIds) -> Result<(), RvError> {
        let mut state = self.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
        if ensure_all(&mut state, objects) {
            persist_state(&self.state_path, &state)?;
        }
        Ok(())
    }

    /// A device in factory state: the factory auth key 1 and nothing else,
    /// which is what `provision` expects. An existing state file is kept.
    pub fn open_factory(state_path: &str, serial: &str, clock: Arc<dyn Clock>) -> Result<Arc<Self>, RvError> {
        let mut state = load_state(state_path)?;
        if state.serial.is_empty() && state.objects.is_empty() && state.auth_keys.is_empty() {
            state.serial = serial.to_string();
            let key = mock_password_key(crate::hsm::admin::FACTORY_PASSWORD);
            state.auth_keys.insert(FACTORY_AUTH_KEY_ID, MockAuthKey { label: "factory".into(), role: AuthKeyRole::Factory, key });
            persist_state(state_path, &state)?;
        }
        Ok(Self::from_state(state_path, state, clock))
    }

    /// Whether `bv-admin` exists: such a device only takes authenticated sessions.
    pub fn is_provisioned(&self) -> bool {
        self.state.read().map(|s| s.provisioned()).unwrap_or(true)
    }

    /// Whether the device has authentication keys at all (factory state or
    /// provisioned). Only a pre-phase-4 device has none.
    fn takes_credentials(&self) -> bool {
        self.state.read().map(|s| !s.auth_keys.is_empty()).unwrap_or(true)
    }

    /// `bvault operator hsm provision` on this device (spec § Pool membership):
    /// from factory state, create `bv-admin`, generate the objects, delete the
    /// factory key. Any other state is refused unless `adopt` and the layout
    /// verifies. Returns the attestation bundle a `member add` takes.
    #[maybe_async::maybe_async]
    pub async fn provision(
        self: &Arc<Self>,
        factory_password: &str,
        admin_password: &str,
        objects: &HsmObjectIds,
        adopt: bool,
    ) -> Result<AttestationBundle, RvError> {
        self.reachable()?;
        if admin_password.is_empty() {
            return Err(RvError::ErrHsm("the bv-admin password must not be empty".into()));
        }
        {
            let mut state = self.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
            if state.factory() {
                if state.auth_keys[&FACTORY_AUTH_KEY_ID].key != mock_password_key(factory_password) {
                    return Err(auth_failed(FACTORY_AUTH_KEY_ID, &state.serial));
                }
                let key = mock_password_key(admin_password);
                state.auth_keys.insert(ADMIN_AUTH_KEY_ID, MockAuthKey { label: "bv-admin".into(), role: AuthKeyRole::Admin, key });
                ensure_all(&mut state, objects);
                ensure_object(&mut state, objects.seed_ecdh, MockKind::SeedEcdh);
                state.auth_keys.remove(&FACTORY_AUTH_KEY_ID);
                persist_state(&self.state_path, &state)?;
                log::info!(target: "security", "mock HSM {} provisioned; factory key 1 deleted", state.serial);
            } else if !adopt {
                return Err(RvError::ErrHsm(format!(
                    "mock HSM {} is not in factory state; refusing to provision it (adopt accepts a device whose \
                     layout verifies)",
                    state.serial
                )));
            }
        }
        let session = self.admin_session(admin_password, *objects)?;
        let checked = verify_layout(&session, objects).await;
        let bundle = checked.and_then(|_| {
            let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            let identity = mock_attestation(&state, objects.identity, objects.identity)?;
            let authz = mock_attestation(&state, objects.authz, objects.identity)?;
            let seed_ecdh = mock_attestation(&state, objects.seed_ecdh, objects.identity)?;
            Ok(AttestationBundle::new("mock", &state.serial, "mock", &identity, &authz).with_seed_ecdh(&seed_ecdh))
        });
        session.close().await?;
        bundle
    }

    /// A session authenticated with `bv-admin` (spec § ceremonies).
    pub fn admin_session(self: &Arc<Self>, password: &str, objects: HsmObjectIds) -> Result<MockAdminSession, RvError> {
        self.reachable()?;
        let accepted = {
            let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            let key = state.auth_keys.get(&ADMIN_AUTH_KEY_ID);
            key.is_some_and(|k| k.role == AuthKeyRole::Admin && k.key == mock_password_key(password))
        };
        if !accepted {
            log::warn!(target: "security", "mock HSM {}: bv-admin authentication failed", self.serial());
            return Err(auth_failed(ADMIN_AUTH_KEY_ID, &self.serial()));
        }
        self.session(ADMIN_SESSION_OWNER)?;
        Ok(MockAdminSession { device: self.clone(), objects })
    }

    /// Authenticate a node session, as the device does at session open.
    fn authenticate(&self, credential: &NodeCredential) -> Result<(), RvError> {
        self.reachable()?;
        let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        match state.auth_keys.get(&credential.auth_key_id()) {
            Some(k) if k.role == AuthKeyRole::Node && k.key.as_slice() == credential.key() => Ok(()),
            _ => Err(auth_failed(credential.auth_key_id(), &state.serial)),
        }
    }

    /// Simulate a mis-provisioned object (tests of layout verification).
    #[cfg(test)]
    pub(crate) fn add_capability(&self, id: u16, capability: &str) {
        let mut state = self.state.write().unwrap();
        state.objects.get_mut(&id).unwrap().extra_capabilities.push(capability.to_string());
    }
}

const ADMIN_SESSION_OWNER: &str = "bv-admin";
const AUDITOR_SESSION_OWNER: &str = "bv-auditor";

/// A `bv-admin` session on a mock device. Every command is logged under
/// auth key 2, as the device logs the key behind each command.
pub struct MockAdminSession {
    device: Arc<MockHsmDevice>,
    objects: HsmObjectIds,
}

impl MockAdminSession {
    fn logged<T>(&self, command: u8, target: u16, run: impl FnOnce() -> Result<T, RvError>) -> Result<T, RvError> {
        self.device.logged(command, ADMIN_AUTH_KEY_ID, target, || {
            self.device.session(ADMIN_SESSION_OWNER)?;
            run()
        })
    }
}

#[maybe_async::maybe_async]
impl HsmAdminSession for MockAdminSession {
    fn hsm_id(&self) -> Result<HsmId, RvError> {
        HsmId::from_parts("mock", &self.device.serial())
    }

    async fn object_info(&self, kind: ObjectKind, id: u16) -> Result<Option<ObjectInfo>, RvError> {
        self.logged(cmd::GET_OBJECT_INFO, id, || {
            let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            let info = |label: &str, base: &[&str], extra: &[String]| ObjectInfo {
                id,
                kind,
                label: label.to_string(),
                capabilities: base.iter().map(|c| c.to_string()).chain(extra.iter().cloned()).collect(),
                delegated: Vec::new(),
            };
            Ok(match kind {
                ObjectKind::AuthenticationKey => {
                    state.auth_keys.get(&id).map(|k| info(&k.label, k.role.capabilities(), &[]))
                }
                ObjectKind::WrapKey => state
                    .objects
                    .get(&id)
                    .filter(|o| o.kind == MockKind::Wrap)
                    .map(|o| info("bv-wrap", WRAP_KEY_CAPABILITIES, &o.extra_capabilities)),
                ObjectKind::AsymmetricKey => state.objects.get(&id).and_then(|o| match o.kind {
                    MockKind::Identity => {
                        Some(info("bv-identity", &["derive-ecdh", "sign-ecdsa"], &o.extra_capabilities))
                    }
                    MockKind::Authz => Some(info("bv-authz", &["sign-eddsa"], &o.extra_capabilities)),
                    MockKind::SeedEcdh => Some(info("bv-seed-ecdh", &["derive-ecdh"], &o.extra_capabilities)),
                    MockKind::Wrap => None,
                }),
            })
        })
    }

    async fn auth_key_ids(&self) -> Result<Vec<u16>, RvError> {
        self.device.session(ADMIN_SESSION_OWNER)?;
        let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        Ok(state.auth_keys.keys().copied().collect())
    }

    async fn put_node_auth_key(&self, label: &str, credential: &NodeCredential) -> Result<(), RvError> {
        let id = credential.auth_key_id();
        node_slot_of(id)?;
        self.logged(cmd::PUT_AUTHENTICATION_KEY, id, || {
            let mut state = self.device.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
            if state.auth_keys.contains_key(&id) {
                return Err(RvError::ErrHsm(format!("auth key {id:#06x} already exists on mock HSM {}", state.serial)));
            }
            let key = MockAuthKey { label: label.to_string(), role: AuthKeyRole::Node, key: credential.key().to_vec() };
            state.auth_keys.insert(id, key);
            persist_state(&self.device.state_path, &state)
        })
    }

    async fn generate_wrap_key(&self, id: HsmObjectId, _label: &str) -> Result<(), RvError> {
        self.logged(cmd::GENERATE_WRAP_KEY, id, || {
            let mut state = self.device.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
            if state.objects.contains_key(&id) {
                return Err(RvError::ErrHsm(format!("object {id} already exists on mock HSM {}", state.serial)));
            }
            ensure_object(&mut state, id, MockKind::Wrap);
            persist_state(&self.device.state_path, &state)
        })
    }

    async fn delete_wrap_key(&self, id: HsmObjectId) -> Result<bool, RvError> {
        self.logged(cmd::DELETE_OBJECT, id, || {
            let mut state = self.device.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
            match state.objects.get(&id).map(|o| o.kind) {
                None => Ok(false),
                Some(MockKind::Wrap) => {
                    state.objects.remove(&id);
                    persist_state(&self.device.state_path, &state)?;
                    Ok(true)
                }
                Some(_) => Err(RvError::ErrHsm(format!("object {id} is not a wrap key"))),
            }
        })
    }

    async fn delete_node_auth_key(&self, auth_key_id: u16) -> Result<bool, RvError> {
        node_slot_of(auth_key_id)?;
        self.logged(cmd::DELETE_OBJECT, auth_key_id, || {
            let mut state = self.device.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
            let existed = state.auth_keys.remove(&auth_key_id).is_some();
            if existed {
                persist_state(&self.device.state_path, &state)?;
            }
            Ok(existed)
        })
    }

    async fn public_key(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError> {
        self.logged(cmd::GET_PUBLIC_KEY, key, || {
            let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            match state.objects.get(&key).map(|o| o.kind) {
                Some(MockKind::Identity | MockKind::SeedEcdh) => identity_public(&state, key),
                Some(MockKind::Authz) => authz_public(&state, key),
                _ => Err(RvError::ErrHsm(format!("object {key} is not an asymmetric key"))),
            }
        })
    }

    async fn identity_sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        if key != self.objects.identity {
            return Err(RvError::ErrHsm(format!("an admin session signs only with bv-identity, not object {key}")));
        }
        self.logged(cmd::SIGN_ECDSA, key, || {
            let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            let obj =
                state.objects.get(&key).filter(|o| o.kind == MockKind::Identity).ok_or(RvError::ErrHsmUnavailable)?;
            ecdsa_sign(&obj.material, &domain_separated(ctx, msg))
        })
    }

    async fn verify_attestation(&self, attestation: &[u8]) -> Result<AttestedKey, RvError> {
        verify_mock_attestation(attestation)
    }

    async fn close(&self) -> Result<(), RvError> {
        self.device.close_session(ADMIN_SESSION_OWNER);
        Ok(())
    }

    /// Replace auth key 8 with `credential`, role `bv-auditor`.
    async fn put_auditor_auth_key(&self, credential: &AuditorCredential) -> Result<(), RvError> {
        self.logged(cmd::PUT_AUTHENTICATION_KEY, AUDITOR_AUTH_KEY_ID, || {
            let mut state = self.device.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
            let key =
                MockAuthKey { label: "bv-auditor".into(), role: AuthKeyRole::Auditor, key: credential.key().to_vec() };
            state.auth_keys.insert(AUDITOR_AUTH_KEY_ID, key);
            persist_state(&self.device.state_path, &state)
        })
    }

    async fn set_forced_audit(&self, on: bool) -> Result<(), RvError> {
        self.logged(cmd::SET_OPTION, NO_KEY, || {
            let mut state = self.device.state.write().map_err(|_| RvError::ErrRwLockWritePoison)?;
            if state.forced_audit != on {
                state.forced_audit = on;
                persist_state(&self.device.state_path, &state)?;
            }
            Ok(())
        })
    }
}

/// A `bv-auditor` session on a mock device. It authenticates on every
/// command, so replacing or deleting key 8 cuts it off at once. The mock does
/// not log the auditor's own two commands (to be confirmed on hardware).
pub struct MockAuditSession {
    device: Arc<MockHsmDevice>,
    credential: AuditorCredential,
}

impl MockAuditSession {
    fn open(&self) -> Result<(), RvError> {
        self.device.authenticate_auditor(&self.credential)?;
        self.device.session(AUDITOR_SESSION_OWNER)
    }
}

#[maybe_async::maybe_async]
impl HsmAuditSession for MockAuditSession {
    fn hsm_id(&self) -> Result<HsmId, RvError> {
        HsmId::from_parts("mock", &self.device.serial())
    }

    async fn get_log_entries(&self) -> Result<DeviceLog, RvError> {
        self.open()?;
        let log = self.device.device_log();
        Ok(DeviceLog {
            unlogged_boot: log.unlogged_boot,
            unlogged_auth: log.unlogged_auth,
            entries: log.entries.iter().copied().collect(),
        })
    }

    async fn set_log_index(&self, index: u16) -> Result<(), RvError> {
        self.open()?;
        let mut log = self.device.device_log();
        let ahead = index.wrapping_sub(log.last_index);
        if ahead != 0 && ahead < 0x8000 {
            return Err(RvError::ErrHsm(format!(
                "set-log-index {index} is past the newest entry {} on mock HSM {}",
                log.last_index,
                self.device.serial()
            )));
        }
        log.acked = index;
        Ok(())
    }

    async fn close(&self) -> Result<(), RvError> {
        self.device.close_session(AUDITOR_SESSION_OWNER);
        Ok(())
    }
}

/// Create every object `objects` names that is missing; true if any was.
fn ensure_all(state: &mut MockState, objects: &HsmObjectIds) -> bool {
    let mut changed = ensure_object(state, objects.wrap_barrier, MockKind::Wrap);
    changed |= ensure_object(state, objects.wrap_pqc, MockKind::Wrap);
    changed |= ensure_object(state, objects.identity, MockKind::Identity);
    changed |= ensure_object(state, objects.authz, MockKind::Authz);
    changed
}

fn ecdsa_sign(scalar: &[u8], msg: &[u8]) -> Result<Vec<u8>, RvError> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey as EcSigningKey};
    let sk = EcSigningKey::from_slice(scalar).map_err(|_| RvError::ErrHsm("bad identity key".into()))?;
    let sig: Signature = sk.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

/// One client of a [`MockHsmDevice`]: what a node's session to it looks like.
pub struct MockHsmBackend {
    device: Arc<MockHsmDevice>,
    /// Session owner on the device (the node id).
    owner: String,
    objects: HsmObjectIds,
    /// Cached public keys (derived at open; keys are immutable in steady state).
    authz_pub: Vec<u8>,
    identity_pub: Vec<u8>,
    /// This node's `bv-node` credential on a provisioned device; `None` on a
    /// pre-phase-4 device, which takes unauthenticated sessions.
    credential: Option<NodeCredential>,
}

impl MockHsmBackend {
    /// Open (and, on first use, provision) the mock device for `config`, as a
    /// client owned by `config.node_id`.
    #[maybe_async::maybe_async]
    pub async fn open(config: &ResolvedHsmConfig) -> Result<Self, RvError> {
        let device = MockHsmDevice::open(&config.state_path, None, clock::monotonic())?;
        Self::connect(device, &config.node_id, config.objects)
    }

    /// An unauthenticated client of a pre-phase-4 device, creating any missing
    /// object. A provisioned device refuses it: revocation must hold.
    pub fn connect(device: Arc<MockHsmDevice>, owner: &str, objects: HsmObjectIds) -> Result<Self, RvError> {
        if device.takes_credentials() {
            return Err(RvError::ErrHsm(format!(
                "mock HSM {} has authentication keys (factory state or provisioned): a node session needs this \
                 node's credential for it",
                device.serial()
            )));
        }
        device.ensure_objects(&objects)?;
        Self::build(device, owner, objects, None)
    }

    /// A client of a provisioned device, authenticated with `credential` on
    /// every command, so deleting the node's auth key cuts it off at once.
    pub fn connect_with_credential(
        device: Arc<MockHsmDevice>,
        owner: &str,
        objects: HsmObjectIds,
        credential: NodeCredential,
    ) -> Result<Self, RvError> {
        if !device.is_provisioned() {
            return Err(RvError::ErrHsm(format!(
                "mock HSM {} is not provisioned; node credentials exist only on provisioned devices",
                device.serial()
            )));
        }
        Self::build(device, owner, objects, Some(credential))
    }

    fn build(
        device: Arc<MockHsmDevice>,
        owner: &str,
        objects: HsmObjectIds,
        credential: Option<NodeCredential>,
    ) -> Result<Self, RvError> {
        let (authz_pub, identity_pub) = {
            let state = device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            (authz_public(&state, objects.authz)?, identity_public(&state, objects.identity)?)
        };
        Ok(Self { device, owner: owner.to_string(), objects, authz_pub, identity_pub, credential })
    }

    pub fn device(&self) -> Arc<MockHsmDevice> {
        self.device.clone()
    }

    /// What every authenticated command does first: authenticate (when the
    /// device takes credentials), then use or open this owner's session.
    fn open_session(&self) -> Result<(), RvError> {
        if let Some(credential) = &self.credential {
            self.device.authenticate(credential)?;
        }
        self.device.session(&self.owner)
    }

    /// The auth key the device logs for this client's commands.
    fn session_key(&self) -> u16 {
        self.credential.as_ref().map(NodeCredential::auth_key_id).unwrap_or(self.objects.auth_key)
    }

    /// Authenticate, use the session and run `command`, logged as the device does.
    fn command<T>(&self, command: u8, target: u16, run: impl FnOnce() -> Result<T, RvError>) -> Result<T, RvError> {
        self.device.logged(command, self.session_key(), target, || {
            self.open_session()?;
            run()
        })
    }

    fn wrap_material(&self, key: HsmObjectId) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
        if obj.kind != MockKind::Wrap {
            // Capability minimization: only wrap keys wrap/unwrap.
            return Err(RvError::ErrHsm("object is not a wrap key".into()));
        }
        Ok(Zeroizing::new(obj.material.clone()))
    }
}

#[maybe_async::maybe_async]
impl HsmBackend for MockHsmBackend {
    fn backend_type(&self) -> &str {
        "mock"
    }

    fn device_serial(&self) -> String {
        self.device.serial()
    }

    fn authz_public_key(&self) -> Result<Vec<u8>, RvError> {
        Ok(self.authz_pub.clone())
    }

    fn identity_public_key(&self) -> Result<Vec<u8>, RvError> {
        Ok(self.identity_pub.clone())
    }

    async fn wrap_data(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
        self.command(cmd::WRAP_DATA, key, || {
            let material = self.wrap_material(key)?;
            let device = self.device_binding()?;
            seal_blob("mock", key, ctx, &device, plaintext, |inner| aes256_gcm_seal(&material, inner))
        })
    }

    async fn unwrap_data(&self, key: HsmObjectId, ctx: &Context, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        self.command(cmd::UNWRAP_DATA, key, || {
            let material = self.wrap_material(key)?;
            let device = self.device_binding()?;
            open_blob(wrapped, ctx, &device, |w| aes256_gcm_open(&material, w))
        })
    }

    async fn sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        let kind = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?.objects.get(&key).map(|o| o.kind);
        let command = if kind == Some(MockKind::Authz) { cmd::SIGN_EDDSA } else { cmd::SIGN_ECDSA };
        self.command(command, key, || {
            let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
            let signed = domain_separated(ctx, msg);
            match obj.kind {
                MockKind::Authz => {
                    let seed: [u8; 32] = obj.material.as_slice().try_into().map_err(|_| RvError::ErrHsmBlobInvalid)?;
                    let sk = SigningKey::from_bytes(&seed);
                    Ok(sk.sign(&signed).to_bytes().to_vec())
                }
                MockKind::Identity => {
                    if self.credential.is_some() {
                        return Err(RvError::ErrHsm("bv-identity is in domain 2; a node session cannot use it".into()));
                    }
                    ecdsa_sign(&obj.material, &signed)
                }
                MockKind::Wrap | MockKind::SeedEcdh => Err(RvError::ErrHsm("object cannot sign".into())),
            }
        })
    }

    async fn attest(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError> {
        self.command(cmd::SIGN_ATTESTATION_CERTIFICATE, key, || {
            let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            mock_attestation(&state, key, self.objects.identity)
        })
    }

    async fn verify_attestation(&self, cert_chain: &[u8]) -> Result<AttestedKey, RvError> {
        verify_mock_attestation(cert_chain)
    }

    async fn derive_ecdh(&self, key: HsmObjectId, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        self.command(cmd::DERIVE_ECDH, key, || {
            let state = self.device.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
            let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
            // On a provisioned device `bv-identity` is domain 2 (admin only); the
            // node's ECDH key is `bv-seed-ecdh`. A pre-phase-4 device has no split.
            let allowed = match obj.kind {
                MockKind::SeedEcdh => true,
                MockKind::Identity => self.credential.is_none(),
                MockKind::Wrap | MockKind::Authz => false,
            };
            if !allowed {
                return Err(RvError::ErrHsm("object cannot derive ECDH from this session".into()));
            }
            let secret =
                p256::SecretKey::from_slice(&obj.material).map_err(|_| RvError::ErrHsm("bad identity key".into()))?;
            let peer =
                p256::PublicKey::from_sec1_bytes(peer_pub).map_err(|_| RvError::ErrHsm("bad ECDH peer key".into()))?;
            let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        })
    }

    async fn get_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, RvError> {
        self.command(cmd::GET_PSEUDO_RANDOM, NO_KEY, || Ok(Zeroizing::new(random_bytes(len))))
    }

    /// `device-info` holds no session, so it answers even at `SESSIONS_FULL`.
    async fn probe(&self) -> Result<String, RvError> {
        self.device.reachable()?;
        Ok(self.device.serial())
    }

    async fn close_session(&self) -> Result<(), RvError> {
        self.device.close_session(&self.owner);
        Ok(())
    }
}

/// The mock's attestation of `key`: a self-description signed by the device's
/// identity key (`signer`), the test-CA analogue of the Yubico chain.
fn mock_attestation(state: &MockState, key: HsmObjectId, signer: HsmObjectId) -> Result<Vec<u8>, RvError> {
    let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
    let (label, public_key) = match obj.kind {
        MockKind::Identity => ("bv-identity", identity_public(state, key)?),
        MockKind::SeedEcdh => ("bv-seed-ecdh", identity_public(state, key)?),
        MockKind::Authz => ("bv-authz", authz_public(state, key)?),
        MockKind::Wrap => return Err(RvError::ErrHsm("wrap key is not attestable".into())),
    };
    let body = serde_json::to_vec(&MockAttestation {
        label: label.to_string(),
        object_id: key,
        public_key,
        serial: state.serial.clone(),
        non_exportable: true,
    })
    .map_err(|e| RvError::ErrHsm(format!("attestation encode: {e}")))?;
    let signer_obj = state.objects.get(&signer).ok_or(RvError::ErrHsmUnavailable)?;
    let signature = ecdsa_sign(&signer_obj.material, &body)?;
    let bundle = MockAttestationBundle { body, signature, signer_pub: identity_public(state, signer)? };
    serde_json::to_vec(&bundle).map_err(|e| RvError::ErrHsm(format!("bundle encode: {e}")))
}

/// Verify a [`mock_attestation`]. It proves only self-consistency: the mock
/// has no root of trust, which is why it refuses to run in production.
fn verify_mock_attestation(cert_chain: &[u8]) -> Result<AttestedKey, RvError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let bundle: MockAttestationBundle = serde_json::from_slice(cert_chain)
        .map_err(|_| RvError::ErrHsmAttestationInvalid("malformed mock attestation bundle".into()))?;
    let vk = VerifyingKey::from_sec1_bytes(&bundle.signer_pub)
        .map_err(|_| RvError::ErrHsmAttestationInvalid("bad attestation signer key".into()))?;
    let sig = Signature::from_slice(&bundle.signature)
        .map_err(|_| RvError::ErrHsmAttestationInvalid("bad attestation signature".into()))?;
    vk.verify(&bundle.body, &sig)
        .map_err(|_| RvError::ErrHsmAttestationInvalid("attestation signature does not verify".into()))?;
    let att: MockAttestation = serde_json::from_slice(&bundle.body)
        .map_err(|_| RvError::ErrHsmAttestationInvalid("malformed attested-key body".into()))?;
    if !att.non_exportable {
        return Err(RvError::ErrHsmAttestationInvalid("attested key is exportable".into()));
    }
    Ok(AttestedKey {
        label: att.label,
        object_id: att.object_id,
        public_key: att.public_key,
        serial: att.serial,
        non_exportable: att.non_exportable,
    })
}

/// Serializable copy of [`AttestedKey`] for the mock bundle body.
#[derive(Serialize, Deserialize)]
struct MockAttestation {
    label: String,
    object_id: u16,
    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,
    serial: String,
    non_exportable: bool,
}

#[derive(Serialize, Deserialize)]
struct MockAttestationBundle {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signer_pub: Vec<u8>,
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    rand::rng().fill_bytes(&mut b);
    b
}

/// Generate a valid P-256 scalar from host entropy (retry on the negligibly
/// rare invalid draw).
fn random_p256_scalar() -> Vec<u8> {
    loop {
        let candidate = random_bytes(32);
        if p256::SecretKey::from_slice(&candidate).is_ok() {
            return candidate;
        }
    }
}

fn ensure_object(state: &mut MockState, id: u16, kind: MockKind) -> bool {
    if state.objects.contains_key(&id) {
        return false;
    }
    let material = match kind {
        MockKind::Wrap => random_bytes(32),
        MockKind::Identity | MockKind::SeedEcdh => random_p256_scalar(),
        MockKind::Authz => random_bytes(32),
    };
    state.objects.insert(id, StoredObject { kind, material, extra_capabilities: Vec::new() });
    true
}

fn authz_public(state: &MockState, id: u16) -> Result<Vec<u8>, RvError> {
    let obj = state.objects.get(&id).ok_or(RvError::ErrHsmUnavailable)?;
    let seed: [u8; 32] = obj.material.as_slice().try_into().map_err(|_| RvError::ErrHsmBlobInvalid)?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes().to_vec())
}

fn identity_public(state: &MockState, id: u16) -> Result<Vec<u8>, RvError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let obj = state.objects.get(&id).ok_or(RvError::ErrHsmUnavailable)?;
    let secret = p256::SecretKey::from_slice(&obj.material).map_err(|_| RvError::ErrHsm("bad identity key".into()))?;
    Ok(secret.public_key().to_encoded_point(false).as_bytes().to_vec())
}

fn load_state(path: &str) -> Result<MockState, RvError> {
    if path.is_empty() {
        // Ephemeral in-memory device (tests): no persistence across restarts.
        return Ok(MockState::default());
    }
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| RvError::ErrHsm(format!("mock HSM state at {path} is corrupt: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MockState::default()),
        Err(e) => Err(RvError::ErrHsm(format!("reading mock HSM state {path}: {e}"))),
    }
}

fn persist_state(path: &str, state: &MockState) -> Result<(), RvError> {
    if path.is_empty() {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| RvError::ErrHsm(format!("encoding mock HSM state: {e}")))?;
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| RvError::ErrHsm(format!("creating mock HSM state dir: {e}")))?;
        }
    }
    std::fs::write(path, bytes).map_err(|e| RvError::ErrHsm(format!("writing mock HSM state {path}: {e}")))
}

fn aes256_gcm_seal(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| RvError::ErrHsm("bad wrap key length".into()))?;
    let nonce_bytes = random_bytes(AES_NONCE_LEN);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut out = cipher.encrypt(nonce, plaintext).map_err(|_| RvError::ErrHsm("wrap encryption failed".into()))?;
    let mut result = nonce_bytes;
    result.append(&mut out);
    Ok(result)
}

fn aes256_gcm_open(key: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
    if wrapped.len() < AES_NONCE_LEN {
        return Err(RvError::ErrHsmBlobInvalid);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| RvError::ErrHsm("bad wrap key length".into()))?;
    let (nonce_bytes, ct) = wrapped.split_at(AES_NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher.decrypt(nonce, ct).map_err(|_| RvError::ErrHsmContextMismatch)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::{
        authz::{self, UnwrapRequest},
        context, HsmObjectIds, Purpose, RecoveryMode,
    };
    use std::time::Duration;

    fn test_config(node_id: &str) -> ResolvedHsmConfig {
        ResolvedHsmConfig {
            backend_type: "mock".into(),
            connector: String::new(),
            objects: HsmObjectIds::default(),
            password: Zeroizing::new(String::new()),
            domains: vec![1],
            pqc_key_cache_ttl: Duration::from_secs(60),
            recovery: RecoveryMode::None,
            state_path: String::new(), // ephemeral
            node_id: node_id.into(),
            pool: None,
            recovery_explicit: false,
            attestation_roots_file: None,
        }
    }

    fn device_with_clock() -> (Arc<MockHsmDevice>, Arc<crate::hsm::clock::ManualClock>) {
        let clock = crate::hsm::clock::ManualClock::new();
        (MockHsmDevice::open("", Some("MOCK-S"), clock.clone()).unwrap(), clock)
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn sixteen_sessions_then_sessions_full_until_one_expires() {
        let (device, clock) = device_with_clock();
        assert_eq!(device.serial(), "MOCK-S", "a new device takes the configured serial");
        let clients: Vec<MockHsmBackend> = (0..MOCK_MAX_SESSIONS)
            .map(|i| MockHsmBackend::connect(device.clone(), &format!("node-{i}"), HsmObjectIds::default()).unwrap())
            .collect();
        for c in &clients {
            c.get_random(1).await.unwrap();
        }
        assert_eq!(device.open_sessions(), MOCK_MAX_SESSIONS);
        // An existing owner keeps its slot; a 17th owner is refused.
        clients[0].get_random(1).await.unwrap();
        let late = MockHsmBackend::connect(device.clone(), "node-late", HsmObjectIds::default()).unwrap();
        assert_eq!(late.get_random(1).await.unwrap_err(), RvError::ErrHsmSessionsFull);
        // device-info holds no session and still answers.
        assert_eq!(late.probe().await.unwrap(), "MOCK-S");

        // Idle sessions expire after 30 s; client 0 was used last, at t=0 too.
        clock.advance(MOCK_SESSION_IDLE_TIMEOUT - Duration::from_millis(1));
        assert_eq!(late.get_random(1).await.unwrap_err(), RvError::ErrHsmSessionsFull);
        clock.advance(Duration::from_millis(1));
        late.get_random(1).await.unwrap();
        assert_eq!(device.open_sessions(), 1);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn close_session_frees_the_slot() {
        let (device, _) = device_with_clock();
        let a = MockHsmBackend::connect(device.clone(), "a", HsmObjectIds::default()).unwrap();
        a.get_random(1).await.unwrap();
        assert_eq!(device.open_sessions(), 1);
        a.close_session().await.unwrap();
        assert_eq!(device.open_sessions(), 0);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn an_offline_device_fails_every_command_as_a_transport_error() {
        let (device, _) = device_with_clock();
        let a = MockHsmBackend::connect(device.clone(), "a", HsmObjectIds::default()).unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "a");
        let blob = a.wrap_data(a.objects.wrap_barrier, &ctx, b"kek").await.unwrap();

        device.set_offline(true);
        assert!(matches!(a.probe().await.unwrap_err(), RvError::ErrHsmTransport(_)));
        assert!(matches!(a.unwrap_data(a.objects.wrap_barrier, &ctx, &blob).await, Err(RvError::ErrHsmTransport(_))));
        assert!(matches!(a.sign(a.objects.authz, "c", b"m").await, Err(RvError::ErrHsmTransport(_))));
        // Metadata cached at open stays readable, as on the real device.
        assert_eq!(a.device_serial(), "MOCK-S");

        device.set_offline(false);
        assert_eq!(a.unwrap_data(a.objects.wrap_barrier, &ctx, &blob).await.unwrap().as_slice(), b"kek");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn an_existing_device_keeps_its_serial() {
        let path = std::env::temp_dir().join(format!("bv-mock-hsm-serial-{}.json", hex::encode(random_bytes(6))));
        let path = path.to_string_lossy().to_string();
        let first = MockHsmDevice::open(&path, Some("MOCK-FIRST"), crate::hsm::clock::monotonic()).unwrap();
        MockHsmBackend::connect(first, "n", HsmObjectIds::default()).unwrap();
        let again = MockHsmDevice::open(&path, Some("MOCK-OTHER"), crate::hsm::clock::monotonic()).unwrap();
        assert_eq!(again.serial(), "MOCK-FIRST", "the configured serial never rewrites a device");
        let _ = std::fs::remove_file(&path);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn wrap_unwrap_round_trip() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let secret = b"the barrier KEK bytes............";
        let blob = hsm.wrap_data(hsm.objects.wrap_barrier, &ctx, secret).await.unwrap();
        // The blob must be opaque — the plaintext never appears in it.
        assert!(!blob.windows(secret.len()).any(|w| w == secret), "plaintext leaked into blob");
        let out = hsm.unwrap_data(hsm.objects.wrap_barrier, &ctx, &blob).await.unwrap();
        assert_eq!(out.as_slice(), secret);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn unwrap_rejects_wrong_context_purpose_epoch() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = hsm.wrap_data(hsm.objects.wrap_barrier, &ctx, b"kek").await.unwrap();

        let wrong_epoch = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 1, "n1");
        assert_eq!(
            hsm.unwrap_data(hsm.objects.wrap_barrier, &wrong_epoch, &blob).await.unwrap_err(),
            RvError::ErrHsmContextMismatch
        );
        let wrong_purpose = Context::new(context::barrier_kek("clu"), Purpose::PqcKemSeed, 0, "n1");
        assert_eq!(
            hsm.unwrap_data(hsm.objects.wrap_barrier, &wrong_purpose, &blob).await.unwrap_err(),
            RvError::ErrHsmContextMismatch
        );
        let wrong_ctx = Context::new(context::barrier_kek("other-cluster"), Purpose::BarrierKek, 0, "n1");
        assert_eq!(
            hsm.unwrap_data(hsm.objects.wrap_barrier, &wrong_ctx, &blob).await.unwrap_err(),
            RvError::ErrHsmContextMismatch
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn new_blobs_are_v2_and_open_for_any_node_on_the_same_device() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = hsm.wrap_data(hsm.objects.wrap_barrier, &ctx, b"kek").await.unwrap();
        let parsed = crate::hsm::BvHsmBlob::from_bytes(&blob).unwrap();
        assert_eq!(parsed.version(), crate::hsm::BV_HSM_BLOB_VERSION);
        assert_eq!(parsed.aad.hsm_id(), Some(&hsm.hsm_id().unwrap()));
        // Node n2 opens n1's copy through the same device: v2 binds the device.
        let as_n2 = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n2");
        assert_eq!(hsm.unwrap_data(hsm.objects.wrap_barrier, &as_n2, &blob).await.unwrap().as_slice(), b"kek");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn v2_blob_is_refused_by_another_device() {
        let a = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let b = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        assert_ne!(a.hsm_id().unwrap(), b.hsm_id().unwrap());
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = a.wrap_data(a.objects.wrap_barrier, &ctx, b"kek").await.unwrap();
        assert_eq!(
            b.unwrap_data(b.objects.wrap_barrier, &ctx, &blob).await.unwrap_err(),
            RvError::ErrHsmContextMismatch
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn key_separation_barrier_vs_pqc() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = hsm.wrap_data(hsm.objects.wrap_barrier, &ctx, b"kek").await.unwrap();
        // Unwrapping a barrier blob with the PQC wrap key must fail (distinct
        // keys → AES-GCM tag fails), and vice versa.
        assert!(hsm.unwrap_data(hsm.objects.wrap_pqc, &ctx, &blob).await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn wrap_key_cannot_sign_and_identity_cannot_unwrap() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        // A wrap key must not sign (capability minimization).
        assert!(hsm.sign(hsm.objects.wrap_barrier, "ctx", b"m").await.is_err());
        // An identity key must not unwrap.
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        assert!(hsm.wrap_data(hsm.objects.identity, &ctx, b"x").await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn signed_authorization_accepts_valid_rejects_tampered_and_replayed() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = context::barrier_kek("clu");
        let blob = b"opaque-wrapped-bytes";

        let req = UnwrapRequest::new(ctx.clone(), blob, "n1", 0, 1, Purpose::BarrierKek);
        let auth = authz::sign_authorization(&hsm, hsm.objects.authz, req.clone()).await.unwrap();
        // Valid authorization verifies against the local authz key.
        let vk = hsm.authz_public_key().unwrap();
        assert!(authz::verify_authorization(&auth, &vk, &req).is_ok());

        // Tampered request field (counter) → signature no longer matches.
        let mut tampered = auth.clone();
        tampered.request.counter = 999;
        assert_eq!(
            authz::verify_authorization(&tampered, &vk, &tampered.request).unwrap_err(),
            RvError::ErrHsmAuthzInvalid
        );

        // Mismatch between authorization and the expected request (replay of an
        // authz for a different counter against a fresh expected request).
        let expected_next = UnwrapRequest::new(ctx, blob, "n1", 0, 2, Purpose::BarrierKek);
        assert_eq!(
            authz::verify_authorization(&auth, &vk, &expected_next).unwrap_err(),
            RvError::ErrHsmAuthzInvalid
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn a_rewrap_authorization_never_stands_in_for_a_use_and_old_requests_still_read() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let vk = hsm.authz_public_key().unwrap();
        let use_req = UnwrapRequest::new(context::barrier_kek("clu"), b"blob", "n1", 0, 7, Purpose::BarrierKek);
        let rewrap_req = use_req.clone().rewrap();
        let rewrap = authz::sign_authorization(&hsm, hsm.objects.authz, rewrap_req.clone()).await.unwrap();
        authz::verify_authorization(&rewrap, &vk, &rewrap_req).unwrap();
        assert_eq!(authz::verify_authorization(&rewrap, &vk, &use_req).unwrap_err(), RvError::ErrHsmAuthzInvalid);
        let mut relabelled = rewrap.clone();
        relabelled.request.operation = authz::UnwrapOperation::Use;
        assert_eq!(authz::verify_authorization(&relabelled, &vk, &use_req).unwrap_err(), RvError::ErrHsmAuthzInvalid);

        // A request serialized before phase 4 has no `operation` and is a use;
        // a use still serializes without it, byte for byte as before.
        let old = r#"{"context":"c","blob_digest":"d","node_id":"n","epoch":0,"counter":1,"purpose":"barrier-kek"}"#;
        let parsed: UnwrapRequest = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.operation, authz::UnwrapOperation::Use);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), old);
        assert!(authz::audit_record(&rewrap)["operation"] == "rewrap");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn a_node_credential_opens_sessions_until_its_key_is_deleted() {
        let clock = crate::hsm::clock::ManualClock::new();
        let device = MockHsmDevice::open_factory("", "CRED", clock).unwrap();
        let objects = HsmObjectIds::default();
        device.provision(crate::hsm::admin::FACTORY_PASSWORD, "admin", &objects, false).await.unwrap();
        let admin = device.admin_session("admin", objects).unwrap();
        let cred = NodeCredential::generate(0x100).unwrap();
        admin.put_node_auth_key("bv-node-n1", &cred).await.unwrap();
        assert!(admin.put_node_auth_key("bv-node-n1", &cred).await.is_err(), "an id is used once");
        let bad_id = NodeCredential::from_parts(0x101, Zeroizing::new(cred.key().to_vec())).unwrap();

        let good = MockHsmBackend::connect_with_credential(device.clone(), "n1", objects, cred).unwrap();
        good.get_random(8).await.unwrap();
        let wrong = MockHsmBackend::connect_with_credential(device.clone(), "n2", objects, bad_id).unwrap();
        assert!(wrong.get_random(8).await.unwrap_err().to_string().contains("authentication"));
        assert_eq!(device.open_sessions(), 2, "the admin and n1; a failed authentication takes no slot");

        assert!(admin.delete_node_auth_key(0x100).await.unwrap());
        assert!(!admin.delete_node_auth_key(0x100).await.unwrap(), "already gone");
        assert!(admin.delete_node_auth_key(crate::hsm::admin::ADMIN_AUTH_KEY_ID).await.is_err(), "never bv-admin");
        assert!(good.get_random(8).await.unwrap_err().to_string().contains("authentication"), "revoked at once");
        assert!(admin.identity_sign(objects.authz, "c", b"m").await.is_err(), "admin signs only with bv-identity");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn attestation_round_trip() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let bundle = hsm.attest(hsm.objects.identity).await.unwrap();
        let attested = hsm.verify_attestation(&bundle).await.unwrap();
        assert!(attested.non_exportable);
        assert_eq!(attested.public_key, hsm.identity_public_key().unwrap());
        assert_eq!(attested.object_id, hsm.objects.identity);

        // A tampered bundle must fail verification.
        let mut bad = bundle.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(hsm.verify_attestation(&bad).await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn ecdh_is_symmetric_between_two_devices() {
        let a = MockHsmBackend::open(&test_config("a")).await.unwrap();
        let b = MockHsmBackend::open(&test_config("b")).await.unwrap();
        let sa = a.derive_ecdh(a.objects.identity, &b.identity_public_key().unwrap()).await.unwrap();
        let sb = b.derive_ecdh(b.objects.identity, &a.identity_public_key().unwrap()).await.unwrap();
        assert_eq!(sa.as_slice(), sb.as_slice());
        assert_eq!(sa.len(), 32);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn get_random_length_and_freshness() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let r1 = hsm.get_random(32).await.unwrap();
        let r2 = hsm.get_random(32).await.unwrap();
        assert_eq!(r1.len(), 32);
        assert_ne!(r1.as_slice(), r2.as_slice());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn state_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("bv-mock-hsm-{}.json", hex::encode(random_bytes(6))));
        let path = dir.to_string_lossy().to_string();
        let mut cfg = test_config("n1");
        cfg.state_path = path.clone();

        let hsm1 = MockHsmBackend::open(&cfg).await.unwrap();
        let pub1 = hsm1.authz_public_key().unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = hsm1.wrap_data(hsm1.objects.wrap_barrier, &ctx, b"kek").await.unwrap();
        drop(hsm1);

        // Reopen from the same file: same keys, and the earlier blob unwraps.
        let hsm2 = MockHsmBackend::open(&cfg).await.unwrap();
        assert_eq!(hsm2.authz_public_key().unwrap(), pub1);
        let out = hsm2.unwrap_data(hsm2.objects.wrap_barrier, &ctx, &blob).await.unwrap();
        assert_eq!(out.as_slice(), b"kek");
        let _ = std::fs::remove_file(&path);
    }

    async fn provisioned_with_auditor(serial: &str) -> (Arc<MockHsmDevice>, MockAdminSession, AuditorCredential) {
        let device = MockHsmDevice::open_factory("", serial, crate::hsm::clock::ManualClock::new()).unwrap();
        let objects = HsmObjectIds::default();
        device.provision(crate::hsm::admin::FACTORY_PASSWORD, "admin", &objects, false).await.unwrap();
        let admin = device.admin_session("admin", objects).unwrap();
        let credential = AuditorCredential::generate();
        admin.put_auditor_auth_key(&credential).await.unwrap();
        (device, admin, credential)
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn the_device_log_chains_every_command_and_names_its_key() {
        use crate::hsm::device_audit::verify_log;
        let (device, admin, credential) = provisioned_with_auditor("LOG1").await;
        let audit = device.auditor_session(&credential).unwrap();
        let wrong = AuditorCredential::generate();
        assert!(device.auditor_session(&wrong).is_err(), "bv-auditor authenticates");

        let node = crate::hsm::admin::NodeCredential::generate(0x100).unwrap();
        admin.put_node_auth_key("bv-node-n1", &node).await.unwrap();
        let client = MockHsmBackend::connect_with_credential(device.clone(), "n1", HsmObjectIds::default(), node).unwrap();
        client.get_random(8).await.unwrap();
        let log = audit.get_log_entries().await.unwrap();
        let (verified, last) = verify_log(None, &log).unwrap();
        assert!(verified.gaps.is_empty(), "{:?}", verified.gaps);
        let newest = log.entries.last().unwrap();
        assert_eq!((newest.command, newest.session_key), (cmd::GET_PSEUDO_RANDOM, 0x100), "logged under the node key");
        assert!(log.entries.iter().any(|e| e.command == cmd::PUT_AUTHENTICATION_KEY && e.session_key == 2));
        assert!(log.entries.iter().all(|e| e.session_key != AUDITOR_AUTH_KEY_ID), "the drain's own reads are not logged");
        assert_eq!(last.unwrap().0, newest.index);
        assert!(audit.set_log_index(newest.index.wrapping_add(1)).await.is_err(), "never past the newest entry");

        device.tamper_log_entry(newest.index);
        let (tampered, _) = verify_log(None, &audit.get_log_entries().await.unwrap()).unwrap();
        assert!(!tampered.gaps.is_empty(), "a changed entry breaks the chain");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn forced_audit_refuses_commands_until_the_log_is_acknowledged() {
        let (device, admin, credential) = provisioned_with_auditor("LOG2").await;
        let audit = device.auditor_session(&credential).unwrap();
        let node = crate::hsm::admin::NodeCredential::generate(0x100).unwrap();
        admin.put_node_auth_key("bv-node-n1", &node).await.unwrap();
        let client = MockHsmBackend::connect_with_credential(device.clone(), "n1", HsmObjectIds::default(), node).unwrap();

        // Off: the buffer wraps, holding the newest entries only.
        for _ in 0..(DEVICE_LOG_CAPACITY + 5) {
            client.get_random(1).await.unwrap();
        }
        assert_eq!(audit.get_log_entries().await.unwrap().entries.len(), DEVICE_LOG_CAPACITY);

        admin.set_forced_audit(true).await.unwrap();
        assert!(device.forced_audit_on());
        let err = client.get_random(1).await.unwrap_err();
        assert!(err.to_string().contains("LOG_FULL"), "{err}");
        let newest = audit.get_log_entries().await.unwrap().entries.last().unwrap().index;
        audit.set_log_index(newest).await.unwrap();
        client.get_random(1).await.unwrap();
    }

    #[test]
    fn a_state_file_without_the_audit_fields_still_loads() {
        let old = serde_json::json!({ "serial": "OLD", "objects": {} });
        let state: MockState = serde_json::from_value(old).unwrap();
        assert!(!state.forced_audit && state.auth_keys.is_empty());
        let written = serde_json::to_value(&state).unwrap();
        assert!(written.get("forced_audit").is_none(), "off is not written: old readers see the same file");
    }
}
