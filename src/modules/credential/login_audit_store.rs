//! Login (authentication) audit trail.
//!
//! Captures every authentication attempt — success or failure — from
//! the credential backends (userpass, approle, fido2) in a
//! system-view-backed append log, so logins surface on the admin
//! Audit page alongside policy / identity-group / asset-group /
//! share / user / file events.
//!
//! Unlike the user-lifecycle store (`UserAuditStore`), which records
//! *administrative* changes to principals, this store records the
//! *authentication events themselves*: who tried to log in, on which
//! mount, from where, and whether it succeeded.
//!
//! Storage:
//!   sys/login-audit/<20-digit-nanos> -> LoginAuditEntry JSON
//!
//! Mirrors `FileAuditStore`: flat, timestamp-keyed, immutable entries,
//! cheap prefix-walk to list, constructed lazily from the system view
//! (no post_unseal wiring needed), so any login handler can append
//! without holding a long-lived reference.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    logical::Response,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const LOGIN_AUDIT_SUB_PATH: &str = "login-audit/";

/// One row in the login-audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginAuditEntry {
    pub ts: String,
    /// Principal that attempted the login: username for userpass/fido2,
    /// role name for approle. May be `"(unknown)"` when the attempt
    /// failed before the principal could be identified (e.g. an
    /// invalid approle role_id, which is an opaque secret we must not
    /// log).
    pub username: String,
    /// Auth mount the attempt targeted: `"userpass/"`, `"approle/"`,
    /// or `"fido2/"`.
    pub mount: String,
    /// `true` when a token was issued, `false` for any rejected attempt.
    pub success: bool,
    /// Peer address of the caller when available (best-effort; empty
    /// when the connection info is absent).
    #[serde(default)]
    pub remote_addr: String,
    /// Free-form detail. On failure this is the (deliberately generic)
    /// reason surfaced to the client; on success it is a short summary
    /// such as the granted policies.
    #[serde(default)]
    pub details: String,
}

pub struct LoginAuditStore {
    view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl LoginAuditStore {
    pub fn from_core(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view = Arc::new(system_view.new_sub_view(LOGIN_AUDIT_SUB_PATH));
        Ok(Arc::new(Self { view }))
    }

    /// Append an entry. `ts` is stamped here if empty. Key is monotonic
    /// nanoseconds so `get_keys` + sort yields chronological order.
    pub async fn append(&self, mut entry: LoginAuditEntry) -> Result<(), RvError> {
        if entry.ts.is_empty() {
            entry.ts = Utc::now().to_rfc3339();
        }
        let key = hist_seq();
        let value = serde_json::to_vec(&entry)?;
        self.view.put(&StorageEntry { key, value }).await
    }

    /// Full log, newest first.
    pub async fn list_all(&self) -> Result<Vec<LoginAuditEntry>, RvError> {
        let mut keys = self.view.get_keys().await?;
        keys.sort();
        keys.reverse();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(raw) = self.view.get(&k).await? {
                if let Ok(e) = serde_json::from_slice::<LoginAuditEntry>(&raw.value) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }
}

/// Best-effort append of a login event. Never fails the login: a
/// sealed barrier or storage error is logged at WARN and swallowed, so
/// authentication is never blocked by the audit side-channel.
#[maybe_async::maybe_async]
pub async fn record_login(
    core: &Core,
    mount: &str,
    username: &str,
    success: bool,
    remote_addr: &str,
    details: &str,
) {
    let store = match LoginAuditStore::from_core(core) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(target: "security", "login audit skipped (store unavailable): {e}");
            return;
        }
    };
    let entry = LoginAuditEntry {
        ts: String::new(),
        username: username.to_string(),
        mount: mount.to_string(),
        success,
        remote_addr: remote_addr.to_string(),
        details: details.to_string(),
    };
    if let Err(e) = store.append(entry).await {
        log::warn!(target: "security", "login audit append failed: {e}");
    }
}

/// Classify a login handler's result into `(success, details)` for
/// the audit trail. A response that carries an `auth` block is a token
/// issuance (success); otherwise the attempt was rejected and we record
/// the (deliberately generic) reason — the `error` field of an
/// error-response, or the error string of a hard failure.
pub fn login_outcome(result: &Result<Option<Response>, RvError>) -> (bool, String) {
    match result {
        Ok(Some(resp)) if resp.auth.is_some() => {
            let pols = resp.auth.as_ref().unwrap().policies.join(",");
            let details = if pols.is_empty() { String::new() } else { format!("policies={pols}") };
            (true, details)
        }
        Ok(Some(resp)) => {
            let reason = resp
                .data
                .as_ref()
                .and_then(|d| d.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("login rejected")
                .to_string();
            (false, reason)
        }
        Ok(None) => (false, "no response".to_string()),
        Err(e) => (false, e.to_string()),
    }
}

/// 20-digit zero-padded nanoseconds since UNIX epoch. Matches
/// `FileAuditStore::hist_seq` / `UserAuditStore::hist_seq` so
/// append-only logs sort chronologically.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}
