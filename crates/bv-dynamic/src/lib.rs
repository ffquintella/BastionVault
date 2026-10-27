//! Host-side building blocks of the dynamic-secrets framework
//! (`features/dynamic-secrets.md`, T62).
//!
//! Pure logic only: the plugin host in the facade (`src/plugins/dynamic/`)
//! wires these to the plugin runtimes, the lease manager and storage.

pub mod audit;
pub mod cache;
pub mod credential;
pub mod error;
pub mod pool;
pub mod records;
pub mod template;

pub use error::DynamicError;
