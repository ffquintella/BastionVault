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

pub mod auth;
pub mod cert_lifecycle;
pub mod credential;
pub mod crypto;
pub mod files;
pub mod identity;
pub mod kv;
pub mod kv_v2;
pub mod ldap;
pub mod namespace;
pub mod notifications;
pub mod pki;
pub mod policy;
pub mod resource;
pub mod resource_group;
pub mod rustion;
pub mod ssh;
pub mod ssh_broker;
pub mod system;
pub mod totp;
pub mod transit;
