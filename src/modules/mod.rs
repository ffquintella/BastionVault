//! `bastion_vault::modules` contains a set of real BastionVault modules. Each sub module needs to
//! implement the `bastion_vault::modules::Module` trait and then the module could be added to
//! module manager.
//!
//! It's important for the developers who want to implement a new BastionVault module themselves to
//! get the `trait Module` implemented correctly.
//!
//! The trait itself now lives in [`bv_kernel_api::module`] and is re-exported
//! here — an engine crate cannot implement a trait defined in the crate above
//! it, and every engine implements this one. See
//! roadmaps/workspace-decomposition.md § Phase 3.

pub use bv_kernel_api::Module;

/// The PKI secret engine, now the Tier 3 `bv-engine-pki` crate. Re-exported
/// here so `bastion_vault::modules::pki::*` paths are unchanged.
pub use bv_engine_pki as pki;

/// The Rustion PQC bastion fleet engine, now the Tier 3 `bv-engine-rustion` crate.
pub use bv_engine_rustion as rustion;

/// The infrastructure-resource engine (assets, connection profiles, connect-MFA), now the Tier 3 `bv-engine-resource` crate.
pub use bv_engine_resource as resource;

/// The encrypted file-resource engine, now the Tier 3 `bv-engine-files` crate.
pub use bv_engine_files as files;

/// In-app notifications, targeting and channel delivery, now the Tier 3 `bv-engine-notifications` crate.
pub use bv_engine_notifications as notifications;

/// The two key/value engines, now the Tier 3 `bv-engine-kv` crate. One crate,
/// two modules, because they are one concept and 1,323 lines between them.
pub use bv_engine_kv::{v1 as kv, v2 as kv_v2};

/// The SSH secret engine (OTP creds, CA signing), now the Tier 3 `bv-engine-ssh` crate.
pub use bv_engine_ssh as ssh;

/// The TOTP second-factor engine, now the Tier 3 `bv-engine-totp` crate.
pub use bv_engine_totp as totp;

/// The SSH login-class broker policy engine, now the Tier 3 `bv-engine-ssh-broker` crate.
pub use bv_engine_ssh_broker as ssh_broker;

/// The LDAP directory engine, now the Tier 3 `bv-engine-ldap` crate.
pub use bv_engine_ldap as ldap;

/// Certificate lifecycle tracking and renewal, now the Tier 3 `bv-engine-cert-lifecycle` crate.
pub use bv_engine_cert_lifecycle as cert_lifecycle;

/// The Transit encryption-as-a-service engine, now the Tier 3 `bv-engine-transit` crate.
pub use bv_engine_transit as transit;

pub mod auth;
pub mod credential;
pub mod crypto;
pub mod identity;
pub mod namespace;
pub mod policy;
pub mod resource_group;
pub mod system;
