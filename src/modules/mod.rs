//! `bastion_vault::modules` — the namespace a server's mount list is written
//! against.
//!
//! Two halves now. The six kernel modules moved into the Tier 2b `bv-kernel`
//! crate in Phase 4.5 and are re-exported by name below; the twelve engine
//! crates from Phase 3 are re-exported alongside them, as they have been since
//! that phase. Every `bastion_vault::modules::*` path is unchanged.
//!
//! The kernel modules are listed explicitly rather than glob-imported:
//! `bv_kernel::modules` carries its own, smaller `credential` — the two
//! backends the kernel tier reads — and a glob would collide with the full
//! eight-backend list this file owns. Naming them is also the honest record of
//! what the kernel tier actually is.
//!
//! See roadmaps/workspace-decomposition.md §§ Phase 3, Phase 4.5.

/// The trait every module implements, from the Tier 1 kernel contract.
pub use bv_kernel_api::Module;

// ── Tier 2b: the kernel tier (`bv-kernel`) ───────────────────────────
pub use bv_kernel::modules::{auth, crypto, identity, namespace, policy, resource_group, system};

// ── Tier 3: the engines (Phase 3) ────────────────────────────────────
/// The PKI secret engine, the Tier 3 `bv-engine-pki` crate.
pub use bv_engine_pki as pki;

/// The Rustion PQC bastion fleet engine, the Tier 3 `bv-engine-rustion` crate.
pub use bv_engine_rustion as rustion;

/// The infrastructure-resource engine (assets, connection profiles,
/// connect-MFA), the Tier 3 `bv-engine-resource` crate.
pub use bv_engine_resource as resource;

/// The encrypted file-resource engine, the Tier 3 `bv-engine-files` crate.
pub use bv_engine_files as files;

/// In-app notifications, targeting and channel delivery, the Tier 3
/// `bv-engine-notifications` crate.
pub use bv_engine_notifications as notifications;

/// The two key/value engines, the Tier 3 `bv-engine-kv` crate. One crate,
/// two modules, because they are one concept and 1,323 lines between them.
pub use bv_engine_kv::{v1 as kv, v2 as kv_v2};

/// The SSH secret engine (OTP creds, CA signing), the Tier 3 `bv-engine-ssh`
/// crate.
pub use bv_engine_ssh as ssh;

/// The TOTP second-factor engine, the Tier 3 `bv-engine-totp` crate.
pub use bv_engine_totp as totp;

/// The SSH login-class broker policy engine, the Tier 3
/// `bv-engine-ssh-broker` crate.
pub use bv_engine_ssh_broker as ssh_broker;

/// The LDAP directory engine, the Tier 3 `bv-engine-ldap` crate.
pub use bv_engine_ldap as ldap;

/// Certificate lifecycle tracking and renewal, the Tier 3
/// `bv-engine-cert-lifecycle` crate.
pub use bv_engine_cert_lifecycle as cert_lifecycle;

/// The Transit encryption-as-a-service engine, the Tier 3
/// `bv-engine-transit` crate.
pub use bv_engine_transit as transit;

pub mod credential;
