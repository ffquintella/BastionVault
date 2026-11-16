//! Phase 2 handlers: `v2/idp/environments/...` and `v2/idp/entitlements/...`.
//! Each runs the same guard as the identity routes before anything else.

use std::sync::Arc;

use chrono::Utc;
use serde_json::{Map, Value};

use super::{entity_id, field, str_field, IdpBackendInner};
use crate::{
    entitlement::{
        gate::{CtxNamespaceLookup, NamespaceLookup},
        model::{parse_role_map, parse_string_list, parse_timestamp, EntitlementSource},
        store::{BoundNamespace, EntitlementStore, EntitlementWrite, EnvironmentWrite},
    },
    errors::RvError,
    kernel_api::{identity::caller_audit_actor, namespace::normalize_path},
    logical::{Backend, Request, Response},
    posix::{model::PosixError, store::PosixStore},
};

fn environment_name(req: &Request) -> Result<String, RvError> {
    str_field(req, "environment")?
        .ok_or_else(|| PosixError::Invalid("environment is missing from the path".into()).into())
}

#[maybe_async::maybe_async]
impl IdpBackendInner {
    /// The identity guard, then both stores.
    async fn guard_authz(&self, req: &Request) -> Result<(Arc<PosixStore>, Arc<EntitlementStore>), RvError> {
        let posix = self.guard(req).await?;
        let authz = self.authz.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)?;
        Ok((posix, authz))
    }

    pub async fn handle_environment_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (_, authz) = self.guard_authz(req).await?;
        let envs = authz.list_environments().await?;
        let keys: Vec<String> = envs.iter().map(|e| e.name.clone()).collect();
        let mut info = Map::new();
        for e in &envs {
            let mut m = Map::new();
            m.insert("namespace".into(), Value::from(e.namespace.clone()));
            m.insert("state".into(), Value::from(e.state.as_str()));
            m.insert("roles".into(), Value::from(e.roles.keys().cloned().collect::<Vec<_>>()));
            info.insert(e.name.clone(), Value::Object(m));
        }
        let mut resp = Response::list_response(&keys);
        resp.data.get_or_insert_with(Map::new).insert("key_info".into(), Value::Object(info));
        Ok(Some(resp))
    }

    pub async fn handle_environment_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (_, authz) = self.guard_authz(req).await?;
        let name = environment_name(req)?;
        match authz.get_environment(&name).await? {
            Some(env) => Ok(Some(Response::data_response(Some(env.to_map())))),
            None => Err(PosixError::NotFound(format!("no environment `{name}`")).into()),
        }
    }

    /// Create or update. A given `namespace` is resolved here and pinned by
    /// uuid; an unknown namespace is refused, never created.
    pub async fn handle_environment_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (_, authz) = self.guard_authz(req).await?;
        let name = environment_name(req)?;
        let namespace = match str_field(req, "namespace")? {
            None => None,
            Some(raw) => {
                let path = normalize_path(&raw)
                    .map_err(|_| PosixError::Invalid(format!("namespace `{raw}` is not a valid namespace path")))?;
                let lookup = CtxNamespaceLookup { ctx: self.core.clone() };
                let ns = lookup
                    .resolve(&path)
                    .await?
                    .ok_or_else(|| PosixError::NotFound(format!("no namespace `{path}`")))?;
                if ns.uuid.is_empty() {
                    return Err(PosixError::Conflict(format!("namespace `{path}` has no uuid to pin")).into());
                }
                Some(BoundNamespace { path: ns.path, uuid: ns.uuid })
            }
        };
        let write = EnvironmentWrite {
            name,
            namespace,
            roles: field(req, "roles")?.map(|v| parse_role_map(&v)).transpose()?,
            description: str_field(req, "description")?,
        };
        let (env, created) = authz.put_environment(write).await?;
        let mut data = env.to_map();
        data.insert("created".into(), Value::from(created));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_environment_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (_, authz) = self.guard_authz(req).await?;
        let name = environment_name(req)?;
        let env = authz.retire_environment(&name).await?;
        Ok(Some(Response::data_response(Some(env.to_map()))))
    }

    /// `GET entitlements/<entity_id>`: every grant, keyed by environment.
    pub async fn handle_entitlement_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (posix, authz) = self.guard_authz(req).await?;
        let id = entity_id(req)?;
        if posix.get_identity(&id).await?.is_none() {
            return Err(PosixError::NotFound(format!("no workforce identity for entity `{id}`")).into());
        }
        let mut grants = Map::new();
        for ent in authz.list_entitlements(&id).await? {
            grants.insert(ent.environment.clone(), Value::Object(ent.to_map()));
        }
        let mut data = Map::new();
        data.insert("entity_id".into(), Value::from(id));
        data.insert("entitlements".into(), Value::Object(grants));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_entitlement_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (_, authz) = self.guard_authz(req).await?;
        let (id, env) = (entity_id(req)?, environment_name(req)?);
        match authz.get_entitlement(&id, &env).await? {
            Some(ent) => Ok(Some(Response::data_response(Some(ent.to_map())))),
            None => Err(PosixError::NotFound(format!("no entitlement for `{id}` in environment `{env}`")).into()),
        }
    }

    /// Grant. The approver is the caller, stamped here; a client cannot name
    /// someone else as `granted_by`.
    pub async fn handle_entitlement_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (posix, authz) = self.guard_authz(req).await?;
        let (id, env) = (entity_id(req)?, environment_name(req)?);
        let roles = match field(req, "roles")? {
            Some(v) => parse_string_list("roles", &v)?,
            None => return Err(PosixError::Invalid("roles is required".into()).into()),
        };
        let not_after = match str_field(req, "not_after")? {
            Some(s) if !s.trim().is_empty() => Some(parse_timestamp("not_after", &s)?),
            _ => None,
        };
        let source = match str_field(req, "source")? {
            Some(s) => EntitlementSource::parse_writable(&s)?,
            None => EntitlementSource::Manual,
        };
        let write = EntitlementWrite {
            entity_id: id,
            environment: env,
            roles,
            not_after,
            source,
            granted_by: caller_audit_actor(req),
        };
        let (ent, created) = authz.put_entitlement(&posix, write, Utc::now()).await?;
        let mut data = ent.to_map();
        data.insert("created".into(), Value::from(created));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_entitlement_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (_, authz) = self.guard_authz(req).await?;
        let (id, env) = (entity_id(req)?, environment_name(req)?);
        let ent = authz.delete_entitlement(&id, &env).await?;
        let mut data = ent.to_map();
        data.insert("revoked".into(), Value::from(true));
        Ok(Some(Response::data_response(Some(data))))
    }
}
