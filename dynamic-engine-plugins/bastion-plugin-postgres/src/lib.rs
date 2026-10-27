//! PostgreSQL dynamic credentials for BastionVault (`secret/dynamic`,
//! `engine_type = "database"`), on `bastion-plugin-dynamic-sdk`. The host
//! makes the username and password and renders the role's statements. When
//! the host has a `postgres` connector it also runs them, on its own pooled,
//! TLS-enforced connection; on an older host this engine dials itself.

pub mod sql;
pub mod target;
pub mod tls;

use async_trait::async_trait;
use bastion_plugin_dynamic_sdk::{
    AuditEvent, Connection, ConnectionSchema, DynamicCredentialBackend, DynamicCtx, DynamicError, EventKind,
    GenerateRequest, Generated, HostConnector, LeaseTerms, PoolGrant, RenewRequest, Renewed, RevokeRequest, RoleRecipe,
    RotateRootRequest, SecretString,
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
/// The host connector kind this engine's connections are dialled with.
pub const CONNECTOR_KIND: &str = "postgres";

/// How one call reaches the database.
enum Route {
    /// The host runs the statements it rendered for this call, on its own
    /// connection under the operator's TLS policy. Its failure is final.
    Host(PoolGrant, HostConnector),
    /// An older host: this engine dials with the grant's TLS policy.
    Dial(Box<dyn Session>),
}

/// The stored connection as the host connector receives it (already checked
/// by [`Target::from_connection`]).
fn host_connector(conn: &Connection, target: &Target) -> HostConnector {
    HostConnector {
        kind: CONNECTOR_KIND,
        url: conn.setting_str("connection_url").unwrap_or_default().to_string(),
        username: target.username.clone(),
        password: target.password.clone(),
        connect_timeout_secs: conn.setting("connect_timeout_secs").and_then(|v| v.as_u64()),
    }
}

pub struct PostgresBackend<C = PgConnector> {
    connector: C,
}

impl<C: Connector> PostgresBackend<C> {
    pub fn new(connector: C) -> Self {
        Self { connector }
    }

    /// Dial with the grant's TLS policy (a host without a `postgres`
    /// connector, or a connection whose endpoint it has not pinned).
    async fn dial(
        &self,
        ctx: &mut DynamicCtx<'_>,
        conn: &Connection,
        target: &Target,
        grant: &PoolGrant,
    ) -> Result<Box<dyn Session>, DynamicError> {
        if !grant.tls.verify {
            ctx.warn(&format!(
                "connection `{}`: TLS certificate verification disabled by insecure_skip_tls_verify (development only)",
                conn.name
            ));
        }
        self.connector.connect(target, &grant.tls).await
    }

    /// The host when its grant lists the `postgres` connector, else a dial.
    /// A host that executes is always used: dialling instead would bypass
    /// the TLS enforcement the host does for the operator.
    async fn route(&self, ctx: &mut DynamicCtx<'_>, conn: &Connection) -> Result<Route, DynamicError> {
        let target = Target::from_connection(conn)?;
        let grant = ctx.pool_checkout(&conn.name).await?;
        if grant.executes(CONNECTOR_KIND) {
            return Ok(Route::Host(grant, host_connector(conn, &target)));
        }
        Ok(Route::Dial(self.dial(ctx, conn, &target, &grant).await?))
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
        match self.route(ctx, &req.connection).await? {
            // The host runs the creation statements it rendered: these ones.
            Route::Host(grant, connector) => {
                ctx.host_execute(&grant, &connector).await?;
            }
            Route::Dial(mut session) => {
                let statements: Vec<&str> = req.statements.iter().map(SecretString::expose).collect();
                session.execute_in_transaction(&statements).await?;
            }
        }
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
        match self.route(ctx, &req.connection).await? {
            // The host renders the same default itself when the role has none.
            Route::Host(grant, connector) => {
                ctx.host_execute(&grant, &connector).await?;
            }
            Route::Dial(mut session) => {
                let refs: Vec<&str> = statements.iter().map(String::as_str).collect();
                session.execute_in_transaction(&refs).await?;
            }
        }
        emit(ctx, event(EventKind::Renew)).await;
        Ok(Renewed::default())
    }

    async fn revoke(&self, ctx: &mut DynamicCtx<'_>, req: RevokeRequest) -> Result<(), DynamicError> {
        quote_ident(&req.username)?;
        let mut session = match self.route(ctx, &req.connection).await? {
            // The host checks the role exists (and runs nothing when it is
            // gone), then the revocation statements or its own default.
            Route::Host(grant, connector) => {
                let done = ctx.host_execute(&grant, &connector).await?;
                let revoked = event(EventKind::Revoke);
                let revoked = if done.identity_absent {
                    revoked.and_then(|e| e.detail("already_absent", "true"))
                } else {
                    revoked
                };
                emit(ctx, revoked).await;
                return Ok(());
            }
            Route::Dial(session) => session,
        };
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
        let mut session = match self.route(ctx, &req.connection).await? {
            // The host sets the new secret over its old-secret connection and
            // proves it with a fresh login; this engine only stores it. If
            // storing fails the call fails, and the host puts the previous
            // secret back on the target itself.
            Route::Host(grant, connector) => {
                ctx.host_execute(&grant, &connector).await?;
                let mut conn = req.connection;
                conn.set_secret("password", req.new_secret.clone());
                // Anything after the store must not fail the call: from here
                // the host assumes the new secret is stored.
                ctx.save_connection(&conn).await.map_err(|stored| {
                    DynamicError::RootNotStored(format!("{stored}; the host restores the previous one"))
                })?;
                emit(ctx, event(EventKind::RotateRoot)).await;
                return Ok(());
            }
            Route::Dial(session) => session,
        };
        // An older host, or a connection it has not pinned: dial, as before.
        let target = Target::from_connection(&req.connection)?;
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
