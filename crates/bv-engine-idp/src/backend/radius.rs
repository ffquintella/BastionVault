//! Phase 4 handlers: `v2/idp/radius/config`, `v2/idp/radius/clients/...`,
//! `v2/idp/radius/profiles/...` and the self-service
//! `v2/idp/radius/passcode/:environment`. Each runs the identity guard
//! first. No response carries a TLS key, a shared secret or a stored
//! passcode; the minted passcode is returned once.

use std::{collections::BTreeMap, sync::Arc};

use bv_errors::bv_error_response_status;
use chrono::Utc;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{field, ssh::duration_field, str_field, IdpBackendInner};
use crate::{
    entitlement::{gate::IssueRequest, model::parse_string_list, store::EntitlementStore},
    errors::RvError,
    kernel_api::namespace::caller_namespace,
    logical::{Backend, Request, Response, ENTITY_ID_META},
    posix::model::PosixError,
    provider::{
        radius::{
            store::{ClientWrite, ConfigUpdate, ProfileWrite, RadiusStore, Transport, MIN_PASSCODE_TTL_SECS},
            vendor::{parse_attribute, VendorAttribute},
            PASSCODE_PROVIDER,
        },
        Authorizer,
    },
    IssuanceStores,
};

fn bool_field(req: &Request, key: &str) -> Result<Option<bool>, RvError> {
    match field(req, key)? {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(b)),
        Some(_) => Err(PosixError::Invalid(format!("{key} must be a boolean")).into()),
    }
}

fn u32_field(req: &Request, key: &str) -> Result<Option<u32>, RvError> {
    match field(req, key)? {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| PosixError::Invalid(format!("{key} must be a non-negative integer")).into()),
    }
}

fn path_name(req: &Request, key: &str) -> Result<String, RvError> {
    str_field(req, key)?.ok_or_else(|| PosixError::Invalid(format!("{key} is missing from the path")).into())
}

/// `{"role": [attribute, ...], ...}`.
fn parse_profile_roles(v: &Value) -> Result<BTreeMap<String, Vec<VendorAttribute>>, PosixError> {
    let Value::Object(roles) = v else {
        return Err(PosixError::Invalid("roles must be an object of role name -> array of attributes".into()));
    };
    let mut out = BTreeMap::new();
    for (role, attrs) in roles {
        let Value::Array(items) = attrs else {
            return Err(PosixError::Invalid(format!("roles.{role} must be an array of attributes")));
        };
        out.insert(role.clone(), items.iter().map(parse_attribute).collect::<Result<Vec<_>, _>>()?);
    }
    Ok(out)
}

/// The calling token's entity: passcodes are self-service only.
fn caller_entity(req: &Request) -> Result<String, RvError> {
    req.auth.as_ref().and_then(|a| a.metadata.get(ENTITY_ID_META)).filter(|id| !id.is_empty()).cloned().ok_or_else(
        || {
            bv_error_response_status!(
                403,
                "RADIUS passcodes are self-service and the calling token is not bound to an entity"
            )
        },
    )
}

#[maybe_async::maybe_async]
impl IdpBackendInner {
    async fn guard_radius(&self, req: &Request) -> Result<(Arc<IssuanceStores>, Arc<EntitlementStore>), RvError> {
        self.guard(req).await?;
        let stores = self.issuance.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)?;
        let authz = self.authz.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)?;
        Ok((stores, authz))
    }

    async fn radius_config_response(&self, radius: &RadiusStore) -> Result<Option<Response>, RvError> {
        let mut data = match radius.config().await? {
            Some(cfg) => cfg.to_map(),
            None => Map::from_iter([("enabled".to_string(), Value::Bool(false))]),
        };
        data.insert("listening".into(), self.radius.status().to_value());
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_radius_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        self.radius_config_response(&stores.radius).await
    }

    pub async fn handle_radius_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let update = ConfigUpdate {
            enabled: bool_field(req, "enabled")?,
            radsec_listen: str_field(req, "radsec_listen")?,
            udp_enabled: bool_field(req, "udp_enabled")?,
            udp_listen: str_field(req, "udp_listen")?,
            allow_unspecified_bind: bool_field(req, "allow_unspecified_bind")?,
            tls_cert_pem: str_field(req, "tls_cert_pem")?,
            tls_key_pem: str_field(req, "tls_key_pem")?.map(Zeroizing::new),
            client_ca_pem: str_field(req, "client_ca_pem")?,
            rate_limit_per_minute: u32_field(req, "rate_limit_per_minute")?,
            passcode_default_ttl_secs: duration_field(req, "passcode_default_ttl")?,
            passcode_max_ttl_secs: duration_field(req, "passcode_max_ttl")?,
        };
        stores.radius.put_config(update, Utc::now()).await?;
        self.radius.reconcile_soon();
        let mut resp = self.radius_config_response(&stores.radius).await?;
        if let Some(r) = resp.as_mut() {
            r.add_warning("the listeners are reconciled asynchronously; read this path again for `listening`");
        }
        Ok(resp)
    }

    pub async fn handle_radius_client_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let clients = stores.radius.list_clients().await?;
        let keys: Vec<String> = clients.iter().map(|c| c.name.clone()).collect();
        let mut info = Map::new();
        for c in &clients {
            let mut m = Map::new();
            m.insert("transport".into(), c.transport.as_str().into());
            m.insert("environment".into(), c.environment.clone().into());
            m.insert("profile".into(), c.profile.clone().into());
            info.insert(c.name.clone(), Value::Object(m));
        }
        let mut resp = Response::list_response(&keys);
        resp.data.get_or_insert_with(Map::new).insert("key_info".into(), Value::Object(info));
        Ok(Some(resp))
    }

    pub async fn handle_radius_client_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let name = path_name(req, "name")?;
        match stores.radius.get_client(&name).await? {
            Some(c) => Ok(Some(Response::data_response(Some(c.to_map())))),
            None => Err(PosixError::NotFound(format!("no radius client `{name}`")).into()),
        }
    }

    pub async fn handle_radius_client_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, authz) = self.guard_radius(req).await?;
        let write = ClientWrite {
            name: path_name(req, "name")?,
            transport: str_field(req, "transport")?.map(|t| Transport::parse(&t)).transpose()?,
            environment: str_field(req, "environment")?,
            profile: str_field(req, "profile")?,
            address: str_field(req, "address")?,
            secret: str_field(req, "secret")?.map(Zeroizing::new),
            cert_sha256: str_field(req, "cert_sha256")?,
            description: str_field(req, "description")?,
        };
        let (client, created) = stores.radius.put_client(&authz, write, Utc::now()).await?;
        self.radius.reconcile_soon();
        let mut data = client.to_map();
        data.insert("created".into(), created.into());
        let mut resp = Response::data_response(Some(data));
        if client.transport == Transport::Udp {
            resp.add_warning("classic UDP RADIUS relies on an MD5-based shared secret; use it on a trusted segment");
        }
        Ok(Some(resp))
    }

    pub async fn handle_radius_client_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let name = path_name(req, "name")?;
        let removed = stores.radius.delete_client(&name).await?;
        self.radius.reconcile_soon();
        match removed {
            Some(c) => Ok(Some(Response::data_response(Some(c.to_map())))),
            None => Err(PosixError::NotFound(format!("no radius client `{name}`")).into()),
        }
    }

    pub async fn handle_radius_profile_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let profiles = stores.radius.list_profiles().await?;
        let keys: Vec<String> = profiles.iter().map(|p| p.name.clone()).collect();
        let mut info = Map::new();
        for p in &profiles {
            let mut m = Map::new();
            m.insert("environment".into(), p.environment.clone().into());
            m.insert("roles".into(), Value::from(p.roles.keys().cloned().collect::<Vec<_>>()));
            info.insert(p.name.clone(), Value::Object(m));
        }
        let mut resp = Response::list_response(&keys);
        resp.data.get_or_insert_with(Map::new).insert("key_info".into(), Value::Object(info));
        Ok(Some(resp))
    }

    pub async fn handle_radius_profile_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let name = path_name(req, "name")?;
        match stores.radius.get_profile(&name).await? {
            Some(p) => Ok(Some(Response::data_response(Some(p.to_map())))),
            None => Err(PosixError::NotFound(format!("no radius profile `{name}`")).into()),
        }
    }

    pub async fn handle_radius_profile_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, authz) = self.guard_radius(req).await?;
        let write = ProfileWrite {
            name: path_name(req, "name")?,
            environment: str_field(req, "environment")?,
            roles: field(req, "roles")?.map(|v| parse_profile_roles(&v)).transpose()?,
            description: str_field(req, "description")?,
        };
        let (profile, created) = stores.radius.put_profile(&authz, write, Utc::now()).await?;
        let mut data = profile.to_map();
        data.insert("created".into(), created.into());
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_radius_profile_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let name = path_name(req, "name")?;
        match stores.radius.delete_profile(&name).await? {
            Some(p) => Ok(Some(Response::data_response(Some(p.to_map())))),
            None => Err(PosixError::NotFound(format!("no radius profile `{name}`")).into()),
        }
    }

    /// Self-service: the caller's own entity, gated like any issue. The
    /// passcode is returned once and stored only as a hash.
    pub async fn handle_radius_passcode(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_radius(req).await?;
        let entity_id = caller_entity(req)?;
        let environment = path_name(req, "environment")?;
        let roles = field(req, "roles")?.map(|v| parse_string_list("roles", &v)).transpose()?;
        let requested_ttl = duration_field(req, "ttl")?;
        let cfg = stores.radius.config().await?.filter(|c| c.enabled).ok_or_else(|| {
            bv_error_response_status!(400, "the RADIUS provider is not enabled; write v2/idp/radius/config first")
        })?;
        let ttl = requested_ttl.unwrap_or(cfg.passcode_default_ttl_secs);
        if !(MIN_PASSCODE_TTL_SECS..=cfg.passcode_max_ttl_secs).contains(&ttl) {
            return Err(bv_error_response_status!(
                400,
                &format!("ttl must lie within [{MIN_PASSCODE_TTL_SECS}, {}] seconds", cfg.passcode_max_ttl_secs)
            ));
        }
        let ask = IssueRequest {
            entity_id: entity_id.clone(),
            environment: environment.clone(),
            roles: roles.clone(),
            caller_namespace: caller_namespace(self.core.as_ref(), req).await?,
            provider: PASSCODE_PROVIDER.to_string(),
        };
        let gate = self.issue_gate();
        let grant = Authorizer::check(&gate, &ask, Some(&*req)).await?;
        let (passcode, rec) = stores
            .radius
            .mint_passcode(&grant.entity_id, &grant.login, &grant.environment, roles, ttl, Utc::now())
            .await?;
        log::info!(
            target: "security",
            "idp.radius.passcode: entity_id={} login={} environment={} expires_at={}",
            rec.entity_id,
            rec.login,
            rec.environment,
            rec.expires_at.to_rfc3339()
        );
        let mut data = Map::new();
        data.insert("passcode".into(), passcode.as_str().into());
        data.insert("login".into(), rec.login.clone().into());
        data.insert("environment".into(), rec.environment.clone().into());
        data.insert("roles".into(), Value::from(grant.roles));
        data.insert("expires_at".into(), rec.expires_at.to_rfc3339().into());
        data.insert("ttl".into(), ttl.into());
        Ok(Some(Response::data_response(Some(data))))
    }
}
