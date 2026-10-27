//! Secret leases, as an engine sees them (T62, `features/dynamic-secrets.md`).
//!
//! Deliberately narrow: a mount ending early a lease **it issued**, and a
//! quota pre-check before it creates a credential. Registration, renewal and
//! the operator surface stay in the kernel: through this trait an engine
//! cannot list, renew or force-clear leases, nor revoke a token's lease or
//! another mount's.

use bv_errors::RvError;

/// What became of an early revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRevocation {
    /// The issuing backend revoked the credential and the lease record is gone.
    Revoked,
    /// The issuing backend's revoke failed. The record is kept as
    /// `revoke_failed` and retried with backoff; `attempts` revokes of it have
    /// failed so far. Operators see it in `LIST v2/sys/leases/revoke-failed`.
    Deferred { attempts: u32 },
}

/// Early revocation of a secret lease by the mount that issued it.
#[maybe_async::maybe_async]
pub trait OwnedLeaseRevoker: Send + Sync {
    /// Revoke `lease_id` now for the mount at router path `owner_mount` (e.g.
    /// `"database/"`), which the host supplies from what it knows of the
    /// caller, never from request data: the ownership check trusts it.
    /// [`RvError::ErrPermissionDenied`] unless the lease is a secret lease
    /// whose path routes to exactly `owner_mount` (not a parent mount);
    /// [`RvError::ErrLeaseNotFound`] for an unknown id; `409` when a revoke or
    /// renew of the same lease is already running.
    async fn revoke_owned_lease(&self, owner_mount: &str, lease_id: &str) -> Result<LeaseRevocation, RvError>;

    /// Refuse, with the quota error registration would give, when the
    /// namespace `namespace_path` (`Request::namespace_path`; empty for root)
    /// is already at its `max_leases`. A pre-check for a backend about to
    /// create a credential in an external system: registration still enforces.
    async fn check_lease_quota(&self, namespace_path: &str) -> Result<(), RvError>;
}
