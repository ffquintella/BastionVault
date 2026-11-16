//! Pillar 1 of features/identity-provider.md: the canonical workforce
//! identity and its immutable, never-reused POSIX `(login, uid, gid)`.

pub mod allocator;
pub mod idset;
pub mod model;
pub mod store;

/// Log-event names for the identity lifecycle, fixed here so the spelling
/// stays consistent. Payloads carry ids and logins only, never credentials.
pub mod events {
    pub const IDENTITY_ALLOCATE: &str = "idp.identity.allocate";
    pub const IDENTITY_IMPORT: &str = "idp.identity.import";
    pub const IDENTITY_UPDATE: &str = "idp.identity.update";
    pub const IDENTITY_DISABLE: &str = "idp.identity.disable";
    pub const IDENTITY_REINSTATE: &str = "idp.identity.reinstate";
    pub const IDENTITY_REMOVE: &str = "idp.identity.remove";
    pub const CONFIG_UPDATE: &str = "idp.config.update";
}
