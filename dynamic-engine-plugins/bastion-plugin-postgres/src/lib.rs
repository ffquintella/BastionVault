//! PostgreSQL dynamic credentials for BastionVault (`secret/dynamic`,
//! `engine_type = "database"`), on `bastion-plugin-dynamic-sdk`. The host
//! makes the username and password and renders the role's statements; this
//! engine runs them over a TLS-verified connection and drops the role again.

pub mod sql;
pub mod target;
pub mod tls;

use async_trait::async_trait;
use bastion_plugin_dynamic_sdk::{
    AuditEvent, Connection, ConnectionSchema, DynamicCredentialBackend, DynamicCtx, DynamicError, EventKind,
    GenerateRequest, Generated, LeaseTerms, RenewRequest, Renewed, RevokeRequest, RoleRecipe, RotateRootRequest,
    SecretString,
};
use serde_json::json;

use crate::{
    sql::{alter_password, default_renew, default_revocation, quote_ident},
    target::{Connector, PgConnector, Session, Target},
};

/// `config/<name>`: where the server is and the root role that mints users.
pub const SCHEMA: ConnectionSchema = ConnectionSchema {
    settings: &["connection_url", "username", "connect_timeout_secs"],
    secrets: &["password"],
    required: &["connection_url", "username", "password"],
};

/// `target_identity_type` of this engine's audit events.
pub const IDENTITY_TYPE: &str = "postgres_role";

pub struct PostgresBackend<C = PgConnector> {
    connector: C,
}

impl<C: Connector> PostgresBackend<C> {
    pub fn new(connector: C) -> Self {
        Self { connector }
    }

    /// Check out a pool slot for the connection and dial it with the slot's
    /// TLS policy.
    async fn open(
        &self,
        ctx: &mut DynamicCtx<'_>,
        conn: &Connection,
    ) -> Result<(Target, Box<dyn Session>), DynamicError> {
        let target = Target::from_connection(conn)?;
        let grant = ctx.pool_checkout(&conn.name).await?;
        if !grant.tls.verify {
            ctx.warn(&format!(
                "connection `{}`: TLS certificate verification disabled by insecure_skip_tls_verify (development only)",
                conn.name
            ));
        }
        let session = self.connector.connect(&target, &grant.tls).await?;
        Ok((target, session))
    }
}

/// Plugin events are a supplement to the host's own; a refused one is noted
/// in the host log and does not undo work already done on the target.
async fn emit(ctx: &mut DynamicCtx<'_>, event: Result<AuditEvent, DynamicError>) {
    let outcome = match event {
        Ok(e) => ctx.emit(&e).await,
        Err(e) => Err(e),
    };
    if let Err(e) = outcome {
        ctx.warn(&format!("audit event not emitted ({})", e.kind()));
    }
}

fn event(kind: EventKind) -> Result<AuditEvent, DynamicError> {
    AuditEvent::new(kind).identity_type(IDENTITY_TYPE)
}

#[async_trait(?Send)]
impl<C: Connector> DynamicCredentialBackend for PostgresBackend<C> {
    fn engine_type(&self) -> &'static str {
        "database"
    }

    fn connection_schema(&self) -> ConnectionSchema {
        SCHEMA
    }

    fn validate_connection(&self, connection: &Connection) -> Result<(), DynamicError> {
        Target::from_connection(connection).map(|_| ())
    }

    fn validate_role(&self, role: &RoleRecipe) -> Result<(), DynamicError> {
        if role.creation_statements.is_empty() {
            return Err(DynamicError::invalid(
                "a postgres role needs creation_statements, e.g. CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD \
                 '{{password}}' VALID UNTIL '{{expiration}}'",
            ));
        }
        Ok(())
    }

    async fn generate(&self, ctx: &mut DynamicCtx<'_>, req: GenerateRequest) -> Result<Generated, DynamicError> {
        if req.statements.is_empty() {
            return Err(DynamicError::invalid("the role has no creation_statements"));
        }
        quote_ident(&req.username)?;
        let (_, mut session) = self.open(ctx, &req.connection).await?;
        let statements: Vec<&str> = req.statements.iter().map(SecretString::expose).collect();
        session.execute_in_transaction(&statements).await?;
        let count = req.statements.len().to_string();
        emit(ctx, event(EventKind::Generate).and_then(|e| e.detail("statements", &count))).await;
        Ok(Generated::new(LeaseTerms::new(req.ttl_secs).with_internal(json!({ "v": 1 }))))
    }

    async fn renew(&self, ctx: &mut DynamicCtx<'_>, req: RenewRequest) -> Result<Renewed, DynamicError> {
        quote_ident(&req.username)?;
        let statements = if req.statements.is_empty() {
            vec![default_renew(&req.username, &req.expiration)?]
        } else {
            req.statements
        };
        let (_, mut session) = self.open(ctx, &req.connection).await?;
        let refs: Vec<&str> = statements.iter().map(String::as_str).collect();
        session.execute_in_transaction(&refs).await?;
        emit(ctx, event(EventKind::Renew)).await;
        Ok(Renewed::default())
    }

    async fn revoke(&self, ctx: &mut DynamicCtx<'_>, req: RevokeRequest) -> Result<(), DynamicError> {
        quote_ident(&req.username)?;
        let (_, mut session) = self.open(ctx, &req.connection).await?;
        // Revoking an identity that is already gone succeeds: the host retries
        // failed revokes, and the target may have been cleaned by hand.
        if !session.role_exists(&req.username).await? {
            emit(ctx, event(EventKind::Revoke).and_then(|e| e.detail("already_absent", "true"))).await;
            return Ok(());
        }
        let statements = if req.statements.is_empty() { default_revocation(&req.username)? } else { req.statements };
        let refs: Vec<&str> = statements.iter().map(String::as_str).collect();
        session.execute_in_transaction(&refs).await?;
        emit(ctx, event(EventKind::Revoke)).await;
        Ok(())
    }

    async fn rotate_root(&self, ctx: &mut DynamicCtx<'_>, req: RotateRootRequest) -> Result<(), DynamicError> {
        let (target, mut session) = self.open(ctx, &req.connection).await?;
        let alter = SecretString::new(alter_password(&target.username, req.new_secret.expose())?);
        session.execute_in_transaction(&[alter.expose()]).await?;
        let mut conn = req.connection;
        conn.set_secret("password", req.new_secret.clone());
        if let Err(stored) = ctx.save_connection(&conn).await {
            // The server already has the new password; put the old one back
            // so the stored credential keeps working.
            let revert = SecretString::new(alter_password(&target.username, target.password.expose())?);
            return Err(match session.execute_in_transaction(&[revert.expose()]).await {
                Ok(()) => DynamicError::Unavailable(format!(
                    "the new root credential could not be stored ({stored}); the previous one was restored"
                )),
                Err(e) => DynamicError::target(format!(
                    "the new root credential could not be stored ({stored}) and restoring the previous one failed \
                     ({e}); reset the password of the root role of `{}` by hand",
                    conn.name
                )),
            });
        }
        emit(ctx, event(EventKind::RotateRoot)).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
