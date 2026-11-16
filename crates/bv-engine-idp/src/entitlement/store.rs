//! The environment and entitlement store (Pillar 2).
//!
//! Lives on the root system view under `idp/authz/`, next to the POSIX store
//! and shared by every `idp` mount. Writes run under a process-local mutex
//! plus the storage backend's lock, as the POSIX store's do, so the
//! one-environment-per-namespace check cannot race a concurrent create.

use std::{any::Any, collections::BTreeMap, sync::Arc};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    errors::RvError,
    posix::{
        model::{decode_versioned, validate_entity_id, IdentityState, PosixError, RECORD_VERSION},
        store::PosixStore,
    },
    storage::{Storage, StorageEntry},
};

use super::{
    events,
    model::{
        normalize_role_list, normalize_role_map, validate_description, validate_environment_name, Entitlement,
        EntitlementSource, Environment, EnvironmentState,
    },
};

/// Name of the storage-backend lock that serializes every write here.
pub const STORAGE_LOCK_NAME: &str = "bv-idp/authz";
pub const ENVIRONMENT_PREFIX: &str = "environments/";
pub const ENTITLEMENT_PREFIX: &str = "entitlements/";

/// The in-process half of the write lock (see `posix::store`).
static LOCAL_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Both halves of the write lock; field order is drop order.
struct WriteLock {
    _cluster: Box<dyn Any + Send>,
    _local: tokio::sync::MutexGuard<'static, ()>,
}

/// A namespace already resolved by the caller: canonical path and uuid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundNamespace {
    pub path: String,
    pub uuid: String,
}

/// Create-or-update of an environment. `namespace` is required to create
/// one and, on an update, must restate the bound namespace.
#[derive(Debug, Clone, Default)]
pub struct EnvironmentWrite {
    pub name: String,
    pub namespace: Option<BoundNamespace>,
    /// Replaces the whole role map when given.
    pub roles: Option<BTreeMap<String, Vec<String>>>,
    pub description: Option<String>,
}

/// One grant. A write replaces the whole entitlement.
#[derive(Debug, Clone)]
pub struct EntitlementWrite {
    pub entity_id: String,
    pub environment: String,
    pub roles: Vec<String>,
    pub not_after: Option<DateTime<Utc>>,
    pub source: EntitlementSource,
    pub granted_by: String,
}

fn environment_key(name: &str) -> String {
    format!("{ENVIRONMENT_PREFIX}{name}")
}

fn entitlement_dir(entity_id: &str) -> String {
    format!("{ENTITLEMENT_PREFIX}{entity_id}/")
}

fn entitlement_key(entity_id: &str, environment: &str) -> String {
    format!("{ENTITLEMENT_PREFIX}{entity_id}/{environment}")
}

pub struct EntitlementStore {
    storage: Arc<dyn Storage>,
}

#[maybe_async::maybe_async]
impl EntitlementStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    async fn write_lock(&self) -> Result<WriteLock, RvError> {
        let local = LOCAL_WRITE_LOCK.lock().await;
        let cluster = self.storage.lock(STORAGE_LOCK_NAME).await?;
        Ok(WriteLock { _cluster: cluster, _local: local })
    }

    async fn get_record<T: DeserializeOwned>(&self, what: &str, key: &str) -> Result<Option<T>, RvError> {
        match self.storage.get(key).await? {
            None => Ok(None),
            Some(entry) => Ok(Some(decode_versioned(what, &entry.value)?)),
        }
    }

    async fn put_record<T: Serialize + Sync>(&self, key: &str, value: &T) -> Result<(), RvError> {
        self.storage.put(&StorageEntry::new(key, value)?).await
    }

    // ─── Reads ──────────────────────────────────────────────────

    /// An environment, checked against the key it was read from.
    pub async fn get_environment(&self, name: &str) -> Result<Option<Environment>, RvError> {
        validate_environment_name(name)?;
        let env: Option<Environment> = self.get_record("environment", &environment_key(name)).await?;
        if let Some(e) = &env {
            if e.name != name {
                return Err(PosixError::Corrupt(format!("environment record under `{name}` names another one")).into());
            }
        }
        Ok(env)
    }

    pub async fn list_environments(&self) -> Result<Vec<Environment>, RvError> {
        let mut out = Vec::new();
        for name in self.storage.list(ENVIRONMENT_PREFIX).await? {
            if name.ends_with('/') {
                continue;
            }
            if let Some(env) = self.get_environment(&name).await? {
                out.push(env);
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// An entitlement, checked against the key it was read from.
    pub async fn get_entitlement(&self, entity_id: &str, environment: &str) -> Result<Option<Entitlement>, RvError> {
        validate_entity_id(entity_id)?;
        validate_environment_name(environment)?;
        let ent: Option<Entitlement> = self.get_record("entitlement", &entitlement_key(entity_id, environment)).await?;
        if let Some(e) = &ent {
            if e.entity_id != entity_id || e.environment != environment {
                return Err(PosixError::Corrupt(format!(
                    "entitlement record under `{entity_id}/{environment}` names another grant"
                ))
                .into());
            }
            if e.roles.is_empty() {
                return Err(PosixError::Corrupt(format!("entitlement `{entity_id}/{environment}` has no roles")).into());
            }
        }
        Ok(ent)
    }

    pub async fn list_entitlements(&self, entity_id: &str) -> Result<Vec<Entitlement>, RvError> {
        validate_entity_id(entity_id)?;
        let mut out = Vec::new();
        for env in self.storage.list(&entitlement_dir(entity_id)).await? {
            if env.ends_with('/') {
                continue;
            }
            if let Some(ent) = self.get_entitlement(entity_id, &env).await? {
                out.push(ent);
            }
        }
        out.sort_by(|a, b| a.environment.cmp(&b.environment));
        Ok(out)
    }

    // ─── Writes ─────────────────────────────────────────────────

    /// Create an environment or update its roles and description. The bound
    /// namespace never changes, and at most one active environment is bound
    /// to a namespace.
    pub async fn put_environment(&self, w: EnvironmentWrite) -> Result<(Environment, bool), RvError> {
        validate_environment_name(&w.name)?;
        if let Some(d) = &w.description {
            validate_description(d)?;
        }
        let roles = w.roles.map(normalize_role_map).transpose()?;
        let _lock = self.write_lock().await?;
        let now = Utc::now();
        match self.get_environment(&w.name).await? {
            Some(mut env) => {
                if env.state == EnvironmentState::Retired {
                    return Err(PosixError::Conflict(format!("environment `{}` is retired", w.name)).into());
                }
                if w.namespace.as_ref().is_some_and(|ns| ns.path != env.namespace) {
                    return Err(PosixError::Invalid("an environment's namespace is immutable".into()).into());
                }
                if let Some(roles) = roles {
                    env.roles = roles;
                }
                if let Some(d) = w.description {
                    env.description = d;
                }
                env.updated_at = now;
                self.put_record(&environment_key(&env.name), &env).await?;
                log::info!(
                    target: "idp",
                    "{}: environment={} roles={:?}",
                    events::ENVIRONMENT_UPDATE,
                    env.name,
                    env.roles.keys().collect::<Vec<_>>()
                );
                Ok((env, false))
            }
            None => {
                let ns = w
                    .namespace
                    .ok_or_else(|| PosixError::Invalid("namespace is required to create an environment".into()))?;
                for other in self.list_environments().await? {
                    if other.state == EnvironmentState::Active && other.namespace_uuid == ns.uuid {
                        return Err(PosixError::Conflict(format!(
                            "namespace `{}` is already bound to environment `{}`",
                            ns.path, other.name
                        ))
                        .into());
                    }
                }
                let env = Environment {
                    version: RECORD_VERSION,
                    name: w.name,
                    namespace: ns.path,
                    namespace_uuid: ns.uuid,
                    roles: roles.unwrap_or_default(),
                    description: w.description.unwrap_or_default(),
                    state: EnvironmentState::Active,
                    created_at: now,
                    updated_at: now,
                    retired_at: None,
                };
                self.put_record(&environment_key(&env.name), &env).await?;
                log::info!(
                    target: "idp",
                    "{}: environment={} namespace={:?}",
                    events::ENVIRONMENT_CREATE,
                    env.name,
                    env.namespace
                );
                Ok((env, true))
            }
        }
    }

    /// Retire an environment: terminal, and its name is never reused.
    pub async fn retire_environment(&self, name: &str) -> Result<Environment, RvError> {
        validate_environment_name(name)?;
        let _lock = self.write_lock().await?;
        let mut env = self
            .get_environment(name)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no environment `{name}`")))?;
        if env.state == EnvironmentState::Retired {
            return Ok(env);
        }
        let now = Utc::now();
        env.state = EnvironmentState::Retired;
        env.retired_at = Some(now);
        env.updated_at = now;
        self.put_record(&environment_key(name), &env).await?;
        log::info!(target: "idp", "{}: environment={}", events::ENVIRONMENT_RETIRE, env.name);
        Ok(env)
    }

    /// Grant (or re-grant) an entitlement. The identity must exist and not be
    /// removed, the environment must be active and define every role, and a
    /// `not_after` must lie in the future.
    pub async fn put_entitlement(
        &self,
        posix: &PosixStore,
        w: EntitlementWrite,
        now: DateTime<Utc>,
    ) -> Result<(Entitlement, bool), RvError> {
        validate_entity_id(&w.entity_id)?;
        validate_environment_name(&w.environment)?;
        let roles = normalize_role_list(w.roles)?;
        if w.not_after.is_some_and(|t| t <= now) {
            return Err(PosixError::Invalid("not_after must be in the future".into()).into());
        }
        let _lock = self.write_lock().await?;
        let identity = posix
            .get_identity(&w.entity_id)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no workforce identity for entity `{}`", w.entity_id)))?;
        if identity.state == IdentityState::Removed {
            return Err(PosixError::Conflict("identity is removed; it cannot be entitled".into()).into());
        }
        let env = self
            .get_environment(&w.environment)
            .await?
            .ok_or_else(|| PosixError::NotFound(format!("no environment `{}`", w.environment)))?;
        if env.state == EnvironmentState::Retired {
            return Err(PosixError::Conflict(format!("environment `{}` is retired", env.name)).into());
        }
        if let Some(undefined) = roles.iter().find(|r| !env.roles.contains_key(*r)) {
            return Err(PosixError::Invalid(format!(
                "role `{undefined}` is not defined on environment `{}`",
                env.name
            ))
            .into());
        }
        let key = entitlement_key(&w.entity_id, &w.environment);
        let created = self.storage.get(&key).await?.is_none();
        let ent = Entitlement {
            version: RECORD_VERSION,
            entity_id: w.entity_id,
            environment: w.environment,
            roles,
            not_after: w.not_after,
            source: w.source,
            granted_by: w.granted_by,
            granted_at: now,
        };
        self.put_record(&key, &ent).await?;
        log::info!(
            target: "idp",
            "{}: entity_id={} login={} environment={} roles={:?} not_after={:?} granted_by={}",
            events::ENTITLEMENT_GRANT,
            ent.entity_id,
            identity.login,
            ent.environment,
            ent.roles,
            ent.not_after.map(|t| t.to_rfc3339()),
            ent.granted_by
        );
        Ok((ent, created))
    }

    /// Revoke an entitlement. The next gate evaluation is denied.
    pub async fn delete_entitlement(&self, entity_id: &str, environment: &str) -> Result<Entitlement, RvError> {
        validate_entity_id(entity_id)?;
        validate_environment_name(environment)?;
        let _lock = self.write_lock().await?;
        // Decoded first, so a malformed record is reported rather than
        // silently discarded.
        let ent = self.get_entitlement(entity_id, environment).await?.ok_or_else(|| {
            PosixError::NotFound(format!("no entitlement for `{entity_id}` in environment `{environment}`"))
        })?;
        self.storage.delete(&entitlement_key(entity_id, environment)).await?;
        log::info!(
            target: "idp",
            "{}: entity_id={} environment={}",
            events::ENTITLEMENT_REVOKE,
            entity_id,
            environment
        );
        Ok(ent)
    }
}

#[cfg(test)]
mod tests;
