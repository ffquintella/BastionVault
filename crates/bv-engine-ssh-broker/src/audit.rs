//! Audit-event taxonomy for the SSH login-broker policy module.
//!
//! These fix the **names** of the config-change events so the spelling
//! stays consistent across the codebase; the payloads are produced by
//! the handler performing the write. Session-side fields
//! (`login_class`, `ssh_engine_mode`, `cert_serial`, `login_class_chain`)
//! are stamped on the existing `session.open` event by the connect path,
//! not here.

/// Deployment-wide `login_class` default / lock changed.
pub const POLICY_GLOBAL_UPDATE: &str = "ssh_broker.policy.global.update";

/// Per-resource-type `login_class` policy changed.
pub const POLICY_TYPE_UPDATE: &str = "ssh_broker.policy.type.update";

/// Per-asset-group `login_class` policy changed.
pub const POLICY_ASSET_GROUP_UPDATE: &str = "ssh_broker.policy.asset_group.update";

/// Per-resource `login_class` policy override changed.
pub const POLICY_RESOURCE_UPDATE: &str = "ssh_broker.policy.resource.update";
