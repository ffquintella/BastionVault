//! Tokens and auth mounts, as an engine sees them.
//!
//! Two separate concerns, deliberately two traits:
//!
//! * [`TokenService`] answers "who does this bearer token belong to, and
//!   revoke it". Its consumers are the FerroGate machine-binding path and the
//!   sys-level audit emitter — neither of which has any business holding a
//!   `TokenStore`, which owns the salt, the token cache and the expiration
//!   manager.
//! * [`AuthMountRegistry`] is how a credential backend installs itself under
//!   `auth/<type>/`, and how a reader walks the mounts of a given type. Twelve
//!   of the fifteen `get_module::<AuthModule>` sites in the engines were the
//!   two-line `add_auth_backend` / `delete_auth_backend` pair.

use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{core::LogicalBackendNewFunc, errors::RvError, storage::barrier_view::BarrierView};

/// Ceiling on any lease or token TTL: 30 days.
///
/// Lives here rather than in the expiration manager because auth backends
/// clamp their own configured TTLs against it — the AppRole `secret_id_ttl`
/// validator is the reason — and a backend that had to import the expiration
/// manager for one `Duration` pulled the whole lease subsystem in with it.
pub const MAX_LEASE_DURATION_SECS: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Lease/token TTL used when none is configured: 24 hours.
pub const DEFAULT_LEASE_DURATION_SECS: Duration = Duration::from_secs(24 * 60 * 60);

/// What a caller's token says about them.
///
/// The readable half of `modules::auth::token_store::TokenEntry`. The stored
/// entry also carries the parent link, use counter, TTLs and creation time —
/// lifecycle state owned by the token store, which is why it is not here.
#[derive(Debug, Clone, Default)]
pub struct TokenInfo {
    pub display_name: String,
    pub policies: Vec<String>,
    pub meta: HashMap<String, String>,
    /// Auth mount path the token was issued from, e.g. `"auth/userpass/"`.
    pub path: String,
}

impl TokenInfo {
    /// Whether the token carries the `root` policy.
    ///
    /// Its own method because both callers got this subtly differently and one
    /// of them gates a bootstrap path.
    pub fn is_root(&self) -> bool {
        self.policies.iter().any(|p| p == "root")
    }

    /// A `meta` value, or empty.
    pub fn meta_or_empty(&self, key: &str) -> String {
        self.meta.get(key).cloned().unwrap_or_default()
    }
}

/// Token lookup and revocation.
#[maybe_async::maybe_async]
pub trait TokenService: Send + Sync {
    /// Resolve a bearer token. `Ok(None)` = not a valid token. Never returns
    /// the raw stored entry, and never logs the token.
    async fn lookup(&self, token: &str) -> Result<Option<TokenInfo>, RvError>;

    /// Revoke a token and its lease tree.
    async fn revoke(&self, token: &str) -> Result<(), RvError>;
}

/// Registration and inspection of `auth/` mounts.
#[maybe_async::maybe_async]
pub trait AuthMountRegistry: Send + Sync {
    /// Register a credential backend factory under an auth mount type.
    fn add_auth_backend(
        &self,
        logical_type: &str,
        backend: Arc<LogicalBackendNewFunc>,
    ) -> Result<(), RvError>;

    fn delete_auth_backend(&self, logical_type: &str) -> Result<(), RvError>;

    /// A barrier view over the storage of every auth mount of `logical_type`.
    ///
    /// For readers that need to sweep the principals of a credential backend
    /// they do not own — the notification service reading contact addresses
    /// off `userpass` user records is the only one today. Returns an empty
    /// vector, not an error, when no such mount exists.
    fn auth_mount_views(&self, logical_type: &str) -> Result<Vec<BarrierView>, RvError>;
}
