//! Audit broker — fan-out, hash-chain maintenance, fail policy.
//!
//! The broker owns every enabled [`AuditDevice`] and is called from
//! `Core::handle_request` after each operation. It stamps the
//! next `prev_hash` onto the entry, redacts sensitive fields via
//! the HMAC key configured on the broker, and forwards the entry
//! to every device. If any device fails, the broker returns an
//! error; [`Core`] treats that as fail-closed and rejects the
//! operation.
//!
//! The broker also persists device config at
//! `sys/audit-devices/<path>` in the barrier so enabled devices
//! survive seal/unseal.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::{
    entry::AuditEntry,
    file_device::FileAuditDevice,
    hash_chain::{digest, genesis},
    AuditDevice, DeviceEntry,
};
use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const AUDIT_DEVICES_SUB_PATH: &str = "audit-devices/";

/// Snapshot of fan-out targets for one entry: the devices on the entry's
/// own namespace chain, and the root mirror devices that also receive it.
type FanoutTargets = (Vec<Arc<dyn AuditDevice>>, Vec<Arc<dyn AuditDevice>>);

/// Persisted-config storage key for a device. Root devices keep their bare
/// path (backward compatible with pre-namespace deployments); tenant devices
/// are stored under a URL-safe-base64 namespace segment so two namespaces may
/// each enable a device with the same operator-facing path.
fn config_key(namespace: &str, path: &str) -> String {
    if namespace.is_empty() {
        path.to_string()
    } else {
        format!("{}/{}", URL_SAFE_NO_PAD.encode(namespace.as_bytes()), path)
    }
}

/// Persisted device configuration. Re-hydrated on unseal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditDeviceConfig {
    pub path: String,
    pub device_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
    /// Multi-tenancy: the namespace this device audits (`""` = root).
    /// A device only sees entries whose `namespace` matches — except a
    /// root device with `mirror = true`, which additionally receives every
    /// namespace's entries (the superuser SOC mirror). Legacy configs lack
    /// this field and deserialize as root.
    #[serde(default)]
    pub namespace: String,
    /// Root-only superuser mirror: when set on a root (`namespace == ""`)
    /// device, that device additionally receives every other namespace's
    /// audit stream. Ignored on non-root devices. Off by default.
    #[serde(default)]
    pub mirror: bool,
}

pub struct AuditBroker {
    /// Registered devices. Each carries the namespace it audits; routing in
    /// [`AuditBroker::log`] partitions by namespace.
    devices: Mutex<Vec<DeviceEntry>>,
    /// Per-namespace chain heads (hex-prefixed), keyed by namespace path
    /// (`""` = root). Each namespace's devices share one chain so a single
    /// device file is a contiguous, independently-verifiable hash chain. The
    /// superuser mirror reuses the root (`""`) chain, since mirror devices are
    /// root devices that also receive every namespace's entries.
    chains: Mutex<HashMap<String, String>>,
    /// HMAC key used for redaction. Derived from the barrier at
    /// broker construction and stable across the broker's lifetime.
    hmac_key: Vec<u8>,
    /// Persistence handle for the device-config sub-view.
    config_view: Arc<BarrierView>,
}

impl AuditBroker {
    /// Construct the broker, loading any persisted device configs
    /// and re-enabling them. Failures to re-enable a single device
    /// are logged and that device is skipped; the broker still
    /// comes up. New enable calls go through `enable_device`.
    pub async fn new(core: &Core, hmac_key: Vec<u8>) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let config_view = Arc::new(system_view.new_sub_view(AUDIT_DEVICES_SUB_PATH));

        let broker = Arc::new(Self {
            devices: Mutex::new(Vec::new()),
            chains: Mutex::new(HashMap::new()),
            hmac_key,
            config_view: config_view.clone(),
        });

        // Re-hydrate saved configs.
        if let Ok(keys) = config_view.get_keys().await {
            for k in keys {
                if let Ok(Some(raw)) = config_view.get(&k).await {
                    if let Ok(cfg) = serde_json::from_slice::<AuditDeviceConfig>(&raw.value) {
                        if let Err(e) = broker.instantiate_and_register(&cfg).await {
                            log::warn!(
                                "audit: failed to re-enable device {}: {e}. Skipping.",
                                cfg.path,
                            );
                        }
                    }
                }
            }
        }

        Ok(broker)
    }

    /// Route an entry to the devices that should see it, maintaining a
    /// per-namespace tamper-evident chain. Fail-closed on any device error.
    ///
    /// An entry tagged with namespace `N` is delivered to:
    ///   1. every device bound to `N` (on `N`'s chain), and
    ///   2. when `N` is non-root, every root device with `mirror = true`
    ///      (on the root chain — the mirror device sees root events and all
    ///      tenant events as one contiguous stream).
    pub async fn log(&self, entry: &mut AuditEntry) -> Result<(), RvError> {
        let ns = entry.namespace.clone();

        // Snapshot the two target device groups without holding the lock
        // across the async writes.
        let (own_devices, mirror_devices): FanoutTargets = {
            let g = self.devices.lock().unwrap();
            let own = g
                .iter()
                .filter(|d| d.namespace == ns)
                .map(|d| d.device.clone())
                .collect();
            // Mirror only carries *tenant* events into root; a root event is
            // already covered by `own` above (root mirror devices have
            // namespace == "" == ns), so skip the mirror pass at root.
            let mirror = if ns.is_empty() {
                Vec::new()
            } else {
                g.iter()
                    .filter(|d| d.mirror && d.namespace.is_empty())
                    .map(|d| d.device.clone())
                    .collect()
            };
            (own, mirror)
        };

        // The namespace's own devices, on the namespace chain.
        self.fan(&ns, entry, &own_devices).await?;

        // The superuser mirror, on the root chain. A separate clone carries
        // its own prev_hash so the root chain stays contiguous; the entry's
        // `namespace` field is preserved so the mirror attributes the event.
        if !mirror_devices.is_empty() {
            let mut mirrored = entry.clone();
            self.fan("", &mut mirrored, &mirror_devices).await?;
        }
        Ok(())
    }

    /// Stamp the next `prev_hash` from `chain_key`'s head, forward to every
    /// device in `devices`, and advance that chain only after all writes
    /// succeed. A no-op (and chain-preserving) when `devices` is empty.
    async fn fan(
        &self,
        chain_key: &str,
        entry: &mut AuditEntry,
        devices: &[Arc<dyn AuditDevice>],
    ) -> Result<(), RvError> {
        if devices.is_empty() {
            return Ok(());
        }
        {
            let chains = self.chains.lock().unwrap();
            entry.prev_hash = chains.get(chain_key).cloned().unwrap_or_else(genesis);
        }
        for dev in devices {
            dev.log_entry(entry).await?;
        }
        // Advance the chain head only after every device accepted the entry.
        let next = digest(entry)?;
        self.chains.lock().unwrap().insert(chain_key.to_string(), next);
        Ok(())
    }

    /// HMAC key the broker passes to `AuditEntry::from_request` for
    /// redaction. Exposed so the caller (Core) can build entries
    /// outside the broker but with consistent redaction.
    pub fn hmac_key(&self) -> &[u8] {
        &self.hmac_key
    }

    /// `true` when at least one audit device is enabled. Used by
    /// the log phase to decide whether to emit an entry at all.
    pub fn has_devices(&self) -> bool {
        !self.devices.lock().unwrap().is_empty()
    }

    /// Snapshot of the devices visible from `namespace`: that namespace's own
    /// devices, plus the root superuser mirror device(s) when enabled (every
    /// namespace is shown the mirror so tenants know their stream is shadowed).
    pub fn list(&self, namespace: &str) -> Vec<AuditDeviceConfig> {
        self.devices
            .lock()
            .unwrap()
            .iter()
            .filter(|d| d.namespace == namespace || (d.mirror && d.namespace.is_empty()))
            .map(|d| AuditDeviceConfig {
                path: d.path.clone(),
                device_type: d.device_type.clone(),
                description: d.description.clone(),
                options: HashMap::new(),
                namespace: d.namespace.clone(),
                mirror: d.mirror,
            })
            .collect()
    }

    /// Register a device and persist its config. The device is scoped to
    /// `cfg.namespace`; the `mirror` flag is honoured only for root devices.
    pub async fn enable_device(&self, mut cfg: AuditDeviceConfig) -> Result<(), RvError> {
        // `mirror` is meaningless outside the root namespace.
        if !cfg.namespace.is_empty() {
            cfg.mirror = false;
        }
        {
            let g = self.devices.lock().unwrap();
            if g.iter().any(|d| d.path == cfg.path && d.namespace == cfg.namespace) {
                return Err(bv_error_string!(format!(
                    "audit: device path {} already in use in namespace {:?}",
                    cfg.path, cfg.namespace
                )));
            }
        }
        self.instantiate_and_register(&cfg).await?;
        let key = config_key(&cfg.namespace, &cfg.path);
        let value = serde_json::to_vec(&cfg)?;
        self.config_view.put(&StorageEntry { key, value }).await?;
        Ok(())
    }

    /// Remove a device and its persisted config from `namespace`. Idempotent.
    pub async fn disable_device(&self, namespace: &str, path: &str) -> Result<(), RvError> {
        {
            let mut g = self.devices.lock().unwrap();
            g.retain(|d| !(d.path == path && d.namespace == namespace));
        }
        self.config_view.delete(&config_key(namespace, path)).await?;
        Ok(())
    }

    async fn instantiate_and_register(&self, cfg: &AuditDeviceConfig) -> Result<(), RvError> {
        let device: Arc<dyn AuditDevice> = match cfg.device_type.as_str() {
            "file" => FileAuditDevice::new(&cfg.options).await?,
            other => {
                return Err(bv_error_string!(format!(
                    "audit: unsupported device type `{other}`. Supported: file."
                )));
            }
        };
        let entry = DeviceEntry {
            path: cfg.path.clone(),
            device_type: cfg.device_type.clone(),
            description: cfg.description.clone(),
            device,
            namespace: cfg.namespace.clone(),
            mirror: cfg.mirror && cfg.namespace.is_empty(),
        };
        self.devices.lock().unwrap().push(entry);
        Ok(())
    }
}
