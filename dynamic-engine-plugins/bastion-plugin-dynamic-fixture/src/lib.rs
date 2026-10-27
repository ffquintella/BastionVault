//! A fake dynamic engine: its "target" is the plugin's own storage
//! (`state/<username>` while the identity lives). Exists to run the SDK
//! through the testkit's process and WASM harnesses, i.e. the host's wire
//! protocol, without a database.

use bastion_plugin_dynamic_sdk::{
    AuditEvent, ConnectionSchema, DynamicCredentialBackend, DynamicCtx, DynamicError, EventKind, GenerateRequest,
    Generated, LeaseTerms, RenewRequest, Renewed, RevokeRequest, RotateRootRequest,
};
use serde_json::json;

/// A role with this name fails on the target after "creating" the identity,
/// with the password in the target's error text.
pub const FAILING_ROLE: &str = "failing";

pub struct FakeEngine;

#[async_trait::async_trait(?Send)]
impl DynamicCredentialBackend for FakeEngine {
    fn engine_type(&self) -> &'static str {
        "database"
    }

    fn connection_schema(&self) -> ConnectionSchema {
        ConnectionSchema { settings: &["url"], secrets: &["password"], required: &["url", "password"] }
    }

    async fn generate(&self, ctx: &mut DynamicCtx<'_>, req: GenerateRequest) -> Result<Generated, DynamicError> {
        ctx.pool_checkout(&req.connection.name).await?;
        ctx.state_put(&req.username, b"live").await?;
        if req.role == FAILING_ROLE {
            return Err(DynamicError::target(format!("lost connection after creating with {}", req.password.expose())));
        }
        ctx.emit(&AuditEvent::new(EventKind::Generate).identity_type("fake_user")?).await?;
        Ok(Generated::new(LeaseTerms::new(req.ttl_secs).with_internal(json!({ "v": 1 }))))
    }

    async fn renew(&self, ctx: &mut DynamicCtx<'_>, req: RenewRequest) -> Result<Renewed, DynamicError> {
        if ctx.state_get(&req.username).await?.is_none() {
            return Err(DynamicError::target(format!("identity {} does not exist", req.username)));
        }
        Ok(Renewed { internal: Some(json!({ "v": 1, "until": req.expiration })) })
    }

    async fn revoke(&self, ctx: &mut DynamicCtx<'_>, req: RevokeRequest) -> Result<(), DynamicError> {
        ctx.state_delete(&req.username).await?;
        ctx.emit(&AuditEvent::new(EventKind::Revoke).identity_type("fake_user")?).await
    }

    async fn rotate_root(&self, ctx: &mut DynamicCtx<'_>, req: RotateRootRequest) -> Result<(), DynamicError> {
        let mut conn = req.connection;
        conn.set_secret("password", req.new_secret);
        ctx.save_connection(&conn).await
    }
}

#[cfg(target_arch = "wasm32")]
bastion_plugin_dynamic_sdk::dynamic_module!(FakeEngine, FakeEngine);
