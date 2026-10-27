//! [`DynamicCredentialBackend`]: what an engine implements.
//!
//! The host generates the credential and renders the role's statements; a
//! backend only runs them on its target. It never generates, logs or returns
//! a credential: the SDK registers the lease and answers the host.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::{
    connection::{Connection, ConnectionSchema},
    ctx::DynamicCtx,
    lease::LeaseTerms,
    role::RoleRecipe,
    secret::SecretString,
    DynamicError,
};

/// `dynamic.generate`: create `username` on the target.
#[derive(Debug)]
pub struct GenerateRequest {
    pub role: String,
    pub connection: Connection,
    /// The role's creation statements, rendered by the host. They hold the
    /// password, so they are secrets too.
    pub statements: Vec<SecretString>,
    /// Host-generated `v-<display>-<role>-<unix>-<8 hex>`.
    pub username: String,
    /// Host-generated; 24 bytes from the host's OS RNG, URL-safe base64.
    pub password: SecretString,
    /// RFC 3339 UTC (`2026-10-26T18:32:11Z`): when the lease ends.
    pub expiration: String,
    pub ttl_secs: u64,
}

/// What `generate` hands back: the lease the SDK registers (exactly once)
/// and extra response fields. `username`/`password` are the host's to add.
#[derive(Debug)]
pub struct Generated {
    pub lease: LeaseTerms,
    pub data: Map<String, Value>,
}

impl Generated {
    pub fn new(lease: LeaseTerms) -> Self {
        Self { lease, data: Map::new() }
    }
}

/// `dynamic.renew`: extend `username` to `expiration`.
#[derive(Debug)]
pub struct RenewRequest {
    pub role: String,
    pub connection: Connection,
    pub username: String,
    /// The role's renew statements, rendered by the host (no password).
    pub statements: Vec<String>,
    pub expiration: String,
    pub ttl_secs: u64,
    /// The `internal` blob registered with the lease (or the last renewal's).
    pub internal: Value,
}

/// A renewal may replace the lease's `internal` blob.
#[derive(Debug, Default)]
pub struct Renewed {
    pub internal: Option<Value>,
}

/// `dynamic.revoke`: remove `username` from the target. Must succeed when
/// the identity is already gone: the host retries failed revokes.
#[derive(Debug)]
pub struct RevokeRequest {
    pub role: String,
    pub connection: Connection,
    pub username: String,
    /// The role's revocation statements, rendered at generation (no password).
    pub statements: Vec<String>,
    pub internal: Value,
}

/// `dynamic.rotate_root`: replace the connection's root credential with the
/// host-generated `new_secret`, then persist it (`DynamicCtx::save_connection`).
#[derive(Debug)]
pub struct RotateRootRequest {
    pub connection: Connection,
    pub new_secret: SecretString,
}

#[async_trait(?Send)]
pub trait DynamicCredentialBackend {
    /// The manifest's `engine_type` (`database`, `aws`, …).
    fn engine_type(&self) -> &'static str;

    /// The fields `config/<name>` accepts.
    fn connection_schema(&self) -> ConnectionSchema;

    /// Engine checks on a connection about to be stored.
    fn validate_connection(&self, _connection: &Connection) -> Result<(), DynamicError> {
        Ok(())
    }

    /// Engine checks on a role about to be stored.
    fn validate_role(&self, _role: &RoleRecipe) -> Result<(), DynamicError> {
        Ok(())
    }

    async fn generate(&self, ctx: &mut DynamicCtx<'_>, req: GenerateRequest) -> Result<Generated, DynamicError>;

    async fn renew(&self, ctx: &mut DynamicCtx<'_>, req: RenewRequest) -> Result<Renewed, DynamicError>;

    async fn revoke(&self, ctx: &mut DynamicCtx<'_>, req: RevokeRequest) -> Result<(), DynamicError>;

    async fn rotate_root(&self, _ctx: &mut DynamicCtx<'_>, _req: RotateRootRequest) -> Result<(), DynamicError> {
        Err(DynamicError::Unsupported("rotate_root"))
    }
}
