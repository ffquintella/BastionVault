//! `pki/tidy`, `pki/tidy-status`, `pki/config/auto-tidy` — Phase 4.
//!
//! Tidy sweeps two things: expired entries from the cert store, and expired
//! entries from the CRL revoked-list (a cert that has expired no longer
//! needs to appear on a CRL because verifiers reject it on date alone).
//!
//! Both sweeps are gated by a per-call `safety_buffer` so an operator has a
//! window after expiry to do forensic inspection before records actually
//! disappear.
//!
//! Phase 4 ships:
//! - `POST /v1/pki/tidy` — synchronous on-demand sweep.
//! - `GET  /v1/pki/tidy-status` — last-run snapshot.
//! - `POST /v1/pki/config/auto-tidy` — store-only configuration for a
//!   periodic tidy. The actual scheduler is Phase 4.1; today the config
//!   round-trips through storage so an operator can persist their preference
//!   ahead of the scheduler landing.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Instant, SystemTime},
};

use humantime::parse_duration;
use serde_json::{json, Map, Value};

use super::{
    path_revoke::rebuild_crl,
    storage::{
        self, AutoTidyConfig, CertRecord, CrlState, TidyStatus, KEY_CONFIG_AUTO_TIDY, KEY_CRL_STATE,
        KEY_TIDY_STATUS,
    },
    PkiBackend, PkiBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl PkiBackend {
    pub fn tidy_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"tidy$",
            fields: {
                "tidy_cert_store": { field_type: FieldType::Bool, default: true,
                    description: "Sweep expired certs from the cert store." },
                "tidy_revoked_certs": { field_type: FieldType::Bool, default: true,
                    description: "Sweep expired entries from the CRL revoked list." },
                "safety_buffer": { field_type: FieldType::Str, default: "72h",
                    description: "Wait this long after expiry before deletion (e.g. 72h)." }
            },
            operations: [{op: Operation::Write, handler: r.run_tidy}],
            help: "Sweep expired certs and CRL entries on demand."
        })
    }

    pub fn tidy_status_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"tidy-status$",
            operations: [{op: Operation::Read, handler: r.read_tidy_status}],
            help: "Return the last tidy run's summary."
        })
    }

    pub fn config_auto_tidy_path(&self) -> Path {
        let rr = self.inner.clone();
        let rw = self.inner.clone();
        new_path!({
            pattern: r"config/auto-tidy$",
            fields: {
                "enabled": { field_type: FieldType::Bool, default: false,
                    description: "Whether the periodic tidy is enabled." },
                "interval": { field_type: FieldType::Str, default: "12h",
                    description: "Interval between tidy runs (e.g. 12h)." },
                "tidy_cert_store": { field_type: FieldType::Bool, default: true,
                    description: "Default tidy_cert_store for periodic runs." },
                "tidy_revoked_certs": { field_type: FieldType::Bool, default: true,
                    description: "Default tidy_revoked_certs for periodic runs." },
                "safety_buffer": { field_type: FieldType::Str, default: "72h",
                    description: "Default safety buffer for periodic runs." }
            },
            operations: [
                {op: Operation::Read, handler: rr.read_auto_tidy},
                {op: Operation::Write, handler: rw.write_auto_tidy}
            ],
            help: "Configure the periodic tidy job (config-only in Phase 4)."
        })
    }
}

#[maybe_async::maybe_async]
impl PkiBackendInner {
    pub async fn run_tidy(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let tidy_certs = req.get_data_or_default("tidy_cert_store")?.as_bool().unwrap_or(true);
        let tidy_revoked = req.get_data_or_default("tidy_revoked_certs")?.as_bool().unwrap_or(true);
        let buffer_str = req.get_data_or_default("safety_buffer")?.as_str().unwrap_or("72h").to_string();
        let safety_buffer =
            parse_duration(&buffer_str).map_err(|_| RvError::ErrRequestFieldInvalid)?.as_secs();

        let summary = run_tidy_inner(req, tidy_certs, tidy_revoked, safety_buffer, "manual").await?;

        let mut data: Map<String, Value> = Map::new();
        data.insert("certs_deleted".into(), json!(summary.certs_deleted));
        data.insert("revoked_entries_deleted".into(), json!(summary.revoked_entries_deleted));
        data.insert("duration_ms".into(), json!(summary.last_run_duration_ms));
        data.insert("safety_buffer_seconds".into(), json!(summary.safety_buffer_seconds));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn read_tidy_status(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let status: TidyStatus = storage::get_json(req, KEY_TIDY_STATUS).await?.unwrap_or_default();
        let data = serde_json::to_value(&status)?;
        Ok(Some(Response::data_response(data.as_object().cloned())))
    }

    pub async fn read_auto_tidy(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg: AutoTidyConfig = storage::get_json(req, KEY_CONFIG_AUTO_TIDY).await?.unwrap_or_default();
        let mut data: Map<String, Value> = Map::new();
        data.insert("enabled".into(), json!(cfg.enabled));
        data.insert("interval".into(), json!(format!("{}s", cfg.interval_seconds)));
        data.insert("tidy_cert_store".into(), json!(cfg.tidy_cert_store));
        data.insert("tidy_revoked_certs".into(), json!(cfg.tidy_revoked_certs));
        data.insert("safety_buffer".into(), json!(format!("{}s", cfg.safety_buffer_seconds)));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn write_auto_tidy(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let interval_str = req.get_data_or_default("interval")?.as_str().unwrap_or("12h").to_string();
        let interval = parse_duration(&interval_str).map_err(|_| RvError::ErrRequestFieldInvalid)?;
        let buffer_str = req.get_data_or_default("safety_buffer")?.as_str().unwrap_or("72h").to_string();
        let safety_buffer = parse_duration(&buffer_str).map_err(|_| RvError::ErrRequestFieldInvalid)?;

        let cfg = AutoTidyConfig {
            enabled: req.get_data_or_default("enabled")?.as_bool().unwrap_or(false),
            interval_seconds: interval.as_secs().max(60),
            tidy_cert_store: req.get_data_or_default("tidy_cert_store")?.as_bool().unwrap_or(true),
            tidy_revoked_certs: req.get_data_or_default("tidy_revoked_certs")?.as_bool().unwrap_or(true),
            safety_buffer_seconds: safety_buffer.as_secs(),
        };
        storage::put_json(req, KEY_CONFIG_AUTO_TIDY, &cfg).await?;
        Ok(None)
    }
}

/// Core sweep logic — split out so the (forthcoming) periodic scheduler can
/// invoke it with the same semantics as the on-demand handler. Returns the
/// status struct that's also persisted at `tidy/status`.
#[maybe_async::maybe_async]
pub async fn run_tidy_inner(
    req: &Request,
    tidy_cert_store: bool,
    tidy_revoked_certs: bool,
    safety_buffer_seconds: u64,
    source: &str,
) -> Result<TidyStatus, RvError> {
    let started = Instant::now();
    let now_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cutoff = now_unix.saturating_sub(safety_buffer_seconds) as i64;

    let mut certs_deleted: u64 = 0;
    let mut revoked_deleted: u64 = 0;
    let mut crl_state_changed = false;

    // ── Sweep cert store ────────────────────────────────────────────
    if tidy_cert_store {
        let keys = req.storage_list("certs/").await?;
        for key in keys {
            let storage_key = format!("certs/{key}");
            let Some(record) = storage::get_json::<CertRecord>(req, &storage_key).await? else {
                continue;
            };
            // not_after_unix == 0 means a pre-Phase-4 record: skip rather
            // than delete blindly. Operators can re-revoke / re-issue to
            // backfill the field if they want those records sweepable.
            if record.not_after_unix == 0 {
                continue;
            }
            if record.not_after_unix < cutoff {
                req.storage_delete(&storage_key).await?;
                certs_deleted += 1;
            }
        }
    }

    // ── Sweep CRL revoked-list ──────────────────────────────────────
    if tidy_revoked_certs {
        let mut state: CrlState = storage::get_json(req, KEY_CRL_STATE).await?.unwrap_or_default();
        let before = state.revoked.len();
        // We need each revoked entry's NotAfter to decide; pull the (still
        // present, possibly already swept) cert record for that serial. If
        // the cert record is gone (already swept above) we know it expired
        // past cutoff and the CRL entry is fair game for removal too.
        let mut keep: Vec<storage::RevokedSerial> = Vec::with_capacity(before);
        for entry in state.revoked.drain(..) {
            let storage_key = format!("certs/{}", entry.serial_hex);
            let cert = storage::get_json::<CertRecord>(req, &storage_key).await?;
            let expired_past_buffer = match cert {
                Some(c) if c.not_after_unix > 0 => c.not_after_unix < cutoff,
                Some(_) => false, // pre-Phase-4 record without not_after — be conservative
                None => true,     // cert already gone → its CRL entry is too
            };
            if expired_past_buffer {
                revoked_deleted += 1;
            } else {
                keep.push(entry);
            }
        }
        state.revoked = keep;
        if revoked_deleted > 0 {
            // Bump crl_number on any meaningful CRL state change so verifiers
            // that cache by number invalidate.
            state.crl_number = state.crl_number.saturating_add(1);
            storage::put_json(req, KEY_CRL_STATE, &state).await?;
            crl_state_changed = true;
        }
    }

    // Rebuild CRL if we changed the revoked-list. Best-effort: a CRL rebuild
    // failure must not lose the storage deletions we already committed.
    if crl_state_changed {
        if let Err(e) = rebuild_crl(req).await {
            log::warn!("pki/tidy: CRL rebuild failed after sweep: {e:?}");
        }
    }

    let status = TidyStatus {
        last_run_at_unix: now_unix,
        last_run_duration_ms: started.elapsed().as_millis() as u64,
        certs_deleted,
        revoked_entries_deleted: revoked_deleted,
        safety_buffer_seconds,
        source: source.to_string(),
    };
    storage::put_json(req, KEY_TIDY_STATUS, &status).await?;
    Ok(status)
}
