//! Asset-group membership, as an engine sees it.
//!
//! The resource-group module keeps a reverse index from resource name to the
//! asset groups that contain it. Two engines depend on it and neither owns it:
//! the resource engine has to keep the index honest when a resource is renamed
//! or deleted, and the login-class resolver needs a resource's group
//! memberships to pick a tier.

use bv_errors::RvError;

/// The reverse index over asset-group membership.
///
/// Every method is best-effort at the call site: a deployment with no
/// resource-group module has no `resource_groups()` service, and both consumers
/// already degrade cleanly (no memberships, no index to fix up).
#[maybe_async::maybe_async]
pub trait ResourceGroupIndex: Send + Sync {
    /// Drop every membership record naming `resource`.
    ///
    /// Called after the resource is deleted. A failure leaves a dangling
    /// membership, which the `resource-group/reindex` endpoint repairs — so
    /// callers log and continue rather than failing the delete.
    async fn prune_resource(&self, resource: &str) -> Result<(), RvError>;

    /// Re-key every membership record from `old` to `new`.
    async fn rename_resource(&self, old: &str, new: &str) -> Result<(), RvError>;

    /// The asset groups `resource` belongs to.
    async fn groups_for_resource(&self, resource: &str) -> Result<Vec<String>, RvError>;
}
