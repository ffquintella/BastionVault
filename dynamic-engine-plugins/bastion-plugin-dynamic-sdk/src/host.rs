//! The host calls a dynamic plugin makes, independent of the runtime.
//!
//! Implemented over stdio JSON-RPC by the process runtime
//! ([`crate::process`]), over the `bv.*` imports on wasm32
//! ([`crate::wasm`]), and in memory by [`crate::testing::MockHost`].

use async_trait::async_trait;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::DynamicError;

/// The three ABI 1.5 dynamic-secret host calls. The name is both the
/// process JSON-RPC method and the `bv.*` WASM import, and the manifest
/// capability that gates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicMethod {
    LeaseRegister,
    AuditEmit,
    PoolCheckout,
}

impl DynamicMethod {
    pub fn name(self) -> &'static str {
        match self {
            Self::LeaseRegister => "dynamic_lease_register",
            Self::AuditEmit => "dynamic_audit_emit",
            Self::PoolCheckout => "dynamic_pool_checkout",
        }
    }
}

/// What a plugin may ask its host for. Storage keys are relative to the
/// plugin's namespace (`storage_prefix = ""` in the manifest).
#[async_trait(?Send)]
pub trait HostCalls {
    /// One dynamic host call; the reply is the host's JSON result.
    async fn dynamic_call(&mut self, method: DynamicMethod, params: Value) -> Result<Value, DynamicError>;
    /// `Ok(None)` when the key does not exist.
    async fn storage_get(&mut self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DynamicError>;
    async fn storage_put(&mut self, key: &str, value: &[u8]) -> Result<(), DynamicError>;
    async fn storage_delete(&mut self, key: &str) -> Result<(), DynamicError>;
    /// Immediate children of `prefix`; sub-directories end with `/`.
    async fn storage_list(&mut self, prefix: &str) -> Result<Vec<String>, DynamicError>;
}
