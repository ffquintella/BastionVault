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

/// Persisted device configuration. Re-hydrated on unseal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDeviceConfig {
    pub path: String,
    pub device_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
}

pub struct AuditBroker {
    /// Registered devices keyed by operator-facing path.
    devices: Mutex<Vec<DeviceEntry>>,
    /// Chain head (hex-prefixed). Single chain across all devices.
    last_hash: Mutex<String>,
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
            last_hash: Mutex::new(genesis()),
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

    /// Stamp `prev_hash`, redact sensitive fields, and forward to
    /// every device. Fail-closed on any device error. On success
    /// the broker's chain head advances.
    pub async fn log(&self, entry: &mut AuditEntry) -> Result<(), RvError> {
        {
            let prev = self.last_hash.lock().unwrap().clone();
            entry.prev_hash = prev;
        }

        // Snapshot the device list so we don't hold the lock across
        // the async writes.
        let devices: Vec<Arc<dyn AuditDevice>> = {
            let g = self.devices.lock().unwrap();
            g.iter().map(|d| d.device.clone()).collect()
        };

        for dev in &devices {
            dev.log_entry(entry).await?;
        }

        // Advance the chain head only after every device accepted
        // the entry. A failed write leaves the chain unchanged, so
        // a retry keyed off the same entry re-presents the same
        // `prev_hash`.
        let next = digest(entry)?;
        *self.last_hash.lock().unwrap() = next;
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

    /// Snapshot of the current device list for the `list` API.
    pub fn list(&self) -> Vec<AuditDeviceConfig> {
        self.devices
            .lock()
            .unwrap()
            .iter()
            .map(|d| AuditDeviceConfig {
                path: d.path.clone(),
                device_type: d.device_type.clone(),
                description: d.description.clone(),
                options: HashMap::new(),
            })
            .collect()
    }

    /// Register a device and persist its config.
    pub async fn enable_device(&self, cfg: AuditDeviceConfig) -> Result<(), RvError> {
        {
            let g = self.devices.lock().unwrap();
            if g.iter().any(|d| d.path == cfg.path) {
                return Err(bv_error_string!(format!(
                    "audit: device path {} already in use",
                    cfg.path
                )));
            }
        }
        self.instantiate_and_register(&cfg).await?;
        let key = cfg.path.clone();
        let value = serde_json::to_vec(&cfg)?;
        self.config_view.put(&StorageEntry { key, value }).await?;
        Ok(())
    }

    /// Remove a device and its persisted config. Idempotent.
    pub async fn disable_device(&self, path: &str) -> Result<(), RvError> {
        {
            let mut g = self.devices.lock().unwrap();
            g.retain(|d| d.path != path);
        }
        self.config_view.delete(path).await?;
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
        };
        self.devices.lock().unwrap().push(entry);
        Ok(())
    }
}
