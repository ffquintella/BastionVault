//! Mount-level security configuration for the userpass backend:
//!
//!   * `config/lockout` — temporary account-lockout thresholds applied
//!     after repeated failed password attempts.
//!   * `config/mfa`     — global TOTP multi-factor switch and the default
//!     TOTP engine mount used when a user does not name its own.
//!
//! Both are stored barrier-encrypted under the userpass mount and read
//! back with serde defaults, so a mount that predates this feature (no
//! stored blob) transparently uses the documented defaults.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};

use super::{UserPassBackend, UserPassBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const LOCKOUT_CONFIG_KEY: &str = "lockout_config";
const MFA_CONFIG_KEY: &str = "mfa_config";

/// Default TOTP engine mount consulted for MFA when a user does not bind
/// its own `totp_mount`.
pub const DEFAULT_TOTP_MOUNT: &str = "totp/";

/// Temporary account-lockout policy.
///
/// Lockout is **enabled by default** with conservative thresholds so a
/// stock deployment resists password brute-forcing without operator
/// action. Operators can widen, tighten, or switch it off entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutConfig {
    /// Master switch. When false, failed attempts are neither counted nor
    /// acted upon and no account is ever locked by this mechanism.
    #[serde(default = "default_lockout_enabled")]
    pub enabled: bool,
    /// Number of consecutive failed password attempts that triggers a
    /// lockout. `0` is treated as "never lock" even when `enabled`.
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,
    /// How long (seconds) an account stays locked once the threshold is
    /// hit. Clamped to at least 1 second when enforcing.
    #[serde(default = "default_lockout_duration_secs")]
    pub lockout_duration_secs: u64,
}

fn default_lockout_enabled() -> bool {
    true
}
fn default_max_failed_attempts() -> u32 {
    5
}
fn default_lockout_duration_secs() -> u64 {
    900
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            enabled: default_lockout_enabled(),
            max_failed_attempts: default_max_failed_attempts(),
            lockout_duration_secs: default_lockout_duration_secs(),
        }
    }
}

impl LockoutConfig {
    /// Whether an account should be locked at `count` consecutive failures.
    pub fn should_lock(&self, count: u32) -> bool {
        self.enabled && self.max_failed_attempts > 0 && count >= self.max_failed_attempts
    }
}

/// Global TOTP multi-factor policy.
///
/// MFA is **opt-in**: it ships disabled so upgrading a deployment does
/// not suddenly demand a second factor from every user. Turning it on
/// makes each user's per-user `totp_mfa_enabled` flag take effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpMfaConfig {
    /// Master switch. When false, per-user `totp_mfa_enabled` is ignored
    /// and logins proceed password-only — the administrative "disable
    /// TOTP MFA" control.
    #[serde(default)]
    pub enabled: bool,
    /// TOTP engine mount used when a user does not name its own
    /// `totp_mount`. Defaults to `totp/`.
    #[serde(default = "default_totp_mount")]
    pub default_mount: String,
}

fn default_totp_mount() -> String {
    DEFAULT_TOTP_MOUNT.to_string()
}

impl Default for TotpMfaConfig {
    fn default() -> Self {
        Self { enabled: false, default_mount: default_totp_mount() }
    }
}

impl UserPassBackend {
    pub fn lockout_config_path(&self) -> Path {
        let read_ref = self.inner.clone();
        let write_ref = self.inner.clone();

        new_path!({
            pattern: r"config/lockout",
            fields: {
                "enabled": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "Master switch for temporary account lockout."
                },
                "max_failed_attempts": {
                    field_type: FieldType::Int,
                    required: false,
                    description: "Consecutive failed password attempts before an account is locked (0 = never)."
                },
                "lockout_duration_secs": {
                    field_type: FieldType::Int,
                    required: false,
                    description: "Seconds an account remains locked once the threshold is reached."
                }
            },
            operations: [
                {op: Operation::Read, handler: read_ref.read_lockout_config},
                {op: Operation::Write, handler: write_ref.write_lockout_config}
            ],
            help: r#"Configure temporary account lockout after repeated failed password attempts."#
        })
    }

    pub fn mfa_config_path(&self) -> Path {
        let read_ref = self.inner.clone();
        let write_ref = self.inner.clone();

        new_path!({
            pattern: r"config/mfa",
            fields: {
                "enabled": {
                    field_type: FieldType::Bool,
                    required: false,
                    description: "Master switch for TOTP multi-factor authentication."
                },
                "default_mount": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "TOTP engine mount used when a user does not bind its own (default totp/)."
                }
            },
            operations: [
                {op: Operation::Read, handler: read_ref.read_mfa_config},
                {op: Operation::Write, handler: write_ref.write_mfa_config}
            ],
            help: r#"Enable or disable TOTP multi-factor authentication for this userpass mount."#
        })
    }
}

#[maybe_async::maybe_async]
impl UserPassBackendInner {
    pub async fn get_lockout_config(&self, req: &Request) -> Result<LockoutConfig, RvError> {
        match req.storage_get(LOCKOUT_CONFIG_KEY).await? {
            Some(entry) => Ok(serde_json::from_slice(&entry.value)?),
            None => Ok(LockoutConfig::default()),
        }
    }

    pub async fn get_mfa_config(&self, req: &Request) -> Result<TotpMfaConfig, RvError> {
        match req.storage_get(MFA_CONFIG_KEY).await? {
            Some(entry) => Ok(serde_json::from_slice(&entry.value)?),
            None => Ok(TotpMfaConfig::default()),
        }
    }

    async fn read_lockout_config(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg = self.get_lockout_config(req).await?;
        Ok(Some(Response::data_response(serde_json::to_value(&cfg)?.as_object().cloned())))
    }

    async fn write_lockout_config(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut cfg = self.get_lockout_config(req).await?;
        if let Ok(v) = req.get_data("enabled") {
            cfg.enabled = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("max_failed_attempts") {
            let n = v.as_int().ok_or(RvError::ErrRequestFieldInvalid)?;
            if n < 0 {
                return Err(RvError::ErrResponse("max_failed_attempts must be >= 0".to_string()));
            }
            cfg.max_failed_attempts = n as u32;
        }
        if let Ok(v) = req.get_data("lockout_duration_secs") {
            let n = v.as_int().ok_or(RvError::ErrRequestFieldInvalid)?;
            if n < 0 {
                return Err(RvError::ErrResponse("lockout_duration_secs must be >= 0".to_string()));
            }
            cfg.lockout_duration_secs = n as u64;
        }
        req.storage_put(&StorageEntry::new(LOCKOUT_CONFIG_KEY, &cfg)?).await?;
        Ok(None)
    }

    async fn read_mfa_config(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cfg = self.get_mfa_config(req).await?;
        Ok(Some(Response::data_response(serde_json::to_value(&cfg)?.as_object().cloned())))
    }

    async fn write_mfa_config(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut cfg = self.get_mfa_config(req).await?;
        if let Ok(v) = req.get_data("enabled") {
            cfg.enabled = v.as_bool_ex().ok_or(RvError::ErrRequestFieldInvalid)?;
        }
        if let Ok(v) = req.get_data("default_mount") {
            let mount = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.trim().to_string();
            if !mount.is_empty() {
                // Normalize to a trailing-slash mount path so callers may
                // pass either "totp" or "totp/".
                cfg.default_mount = if mount.ends_with('/') { mount } else { format!("{mount}/") };
            }
        }
        req.storage_put(&StorageEntry::new(MFA_CONFIG_KEY, &cfg)?).await?;
        Ok(None)
    }
}
