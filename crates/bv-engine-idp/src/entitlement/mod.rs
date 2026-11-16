//! Pillar 2 of features/identity-provider.md: environments (bound for life
//! to one namespace, mapping role names to that namespace's ACL policies),
//! entitlements (identity -> environment -> roles, optionally time-boxed)
//! and the fail-closed issue gate ([`gate::IssueGate`]) that every
//! downstream provider calls before it issues anything.

pub mod gate;
pub mod model;
pub mod store;

use std::sync::Arc;

/// Late-bound handle to the store, set once the barrier is unsealed.
pub type EntitlementStoreSlot = arc_swap::ArcSwap<Option<Arc<store::EntitlementStore>>>;

/// Audit-event and log-event names, fixed here so the spelling stays
/// consistent. Payloads carry ids, logins, role and policy names only.
pub mod events {
    /// The gate allowed an issuance (audit event).
    pub const ISSUE: &str = "idp.issue";
    /// The gate refused an issuance (audit event).
    pub const ISSUE_DENIED: &str = "idp.issue-denied";
    pub const ENVIRONMENT_CREATE: &str = "idp.environment.create";
    pub const ENVIRONMENT_UPDATE: &str = "idp.environment.update";
    pub const ENVIRONMENT_RETIRE: &str = "idp.environment.retire";
    pub const ENTITLEMENT_GRANT: &str = "idp.entitlement.grant";
    pub const ENTITLEMENT_REVOKE: &str = "idp.entitlement.revoke";
}
