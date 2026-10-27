//! SDK for BastionVault dynamic-secret engine plugins
//! (`plugin_type = "secret/dynamic"`, plugin ABI 1.5, features/dynamic-secrets.md).
//!
//! Implement [`DynamicCredentialBackend`], then hand it to
//! [`process::run_main`] (process runtime) or [`dynamic_module!`] (WASM).
//! The host generates usernames and passwords and renders statements; the
//! plugin runs them on its target and never generates, logs or returns one.

pub mod audit;
pub mod backend;
pub mod connection;
pub mod ctx;
pub mod dispatch;
pub mod error;
pub mod host;
pub mod lease;
pub mod pool;
pub mod role;
pub mod secret;

#[cfg(feature = "process")]
pub mod process;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests;

/// The base plugin SDK, re-exported: dynamic plugins keep its conventions.
pub use bastion_plugin_sdk as base;
pub use bastion_plugin_sdk::{register, Host, HostError, LogLevel, Plugin, Request, Response};

pub use async_trait::async_trait;
pub use audit::{AuditEvent, EventKind};
pub use backend::{
    DynamicCredentialBackend, GenerateRequest, Generated, RenewRequest, Renewed, RevokeRequest, RotateRootRequest,
};
pub use connection::{Connection, ConnectionSchema};
pub use ctx::DynamicCtx;
pub use error::{status, DynamicError};
pub use lease::LeaseTerms;
pub use pool::{PoolGrant, TlsPolicy};
pub use role::RoleRecipe;
pub use secret::SecretString;

/// The plugin ABI this SDK speaks (`abi_version` in `plugin.toml`).
pub const ABI_VERSION: &str = "1.5";
/// The manifest `plugin_type` of every dynamic plugin.
pub const PLUGIN_TYPE: &str = "secret/dynamic";

/// Export a [`DynamicCredentialBackend`] as a WASM plugin: the base SDK's
/// `bv_alloc` / `bv_run` ABI glue around [`wasm::run`]. Build with
/// `--features wasm` for `wasm32-unknown-unknown`. The backend must not
/// await real I/O: WASM reaches the target only through host calls.
#[macro_export]
macro_rules! dynamic_module {
    ($backend:ty, $ctor:expr) => {
        #[doc(hidden)]
        pub struct __BvDynamicModule;

        impl $crate::base::Plugin for __BvDynamicModule {
            fn handle(req: $crate::base::Request<'_>, _host: &$crate::base::Host) -> $crate::base::Response {
                let backend: $backend = $ctor;
                $crate::wasm::run(&backend, req.input())
            }
        }

        #[no_mangle]
        pub extern "C" fn bv_alloc(len: i32) -> i32 {
            $crate::base::abi::alloc(len)
        }

        #[no_mangle]
        pub extern "C" fn bv_run(ptr: i32, len: i32) -> i32 {
            $crate::base::abi::run::<__BvDynamicModule>(ptr, len)
        }
    };
}
