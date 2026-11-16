//! Phase 5 SAML handlers: `v2/idp/saml/config`, `keys`, `keys/rotate`,
//! `sps/...` (admin), `sso` and `initiate/:name` (self-service), and the
//! unauthenticated `metadata`. Each runs the identity guard first. The
//! signed response is returned once, for the caller to POST to `acs_url`.

use chrono::Utc;
use serde_json::{Map, Value};

use super::{field, radius::bool_field, ssh::duration_field, str_field, IdpBackendInner};
use crate::{
    entitlement::model::parse_string_list,
    errors::RvError,
    kernel_api::namespace::caller_namespace,
    logical::{Backend, Request, Response},
    posix::model::PosixError,
    provider::{
        federation::{caller_entity, keys::DEFAULT_OVERLAP_SECS},
        saml_idp::{
            self,
            request::Binding,
            store::{SamlConfigUpdate, SpWrite},
            xml, Caller, Refusal, SamlDeps, SamlIssued, SsoInput,
        },
    },
};

fn path_name(req: &Request, key: &str) -> Result<String, RvError> {
    str_field(req, key)?.ok_or_else(|| PosixError::Invalid(format!("{key} is missing from the path")).into())
}

fn list_field(req: &Request, key: &str) -> Result<Option<Vec<String>>, RvError> {
    Ok(field(req, key)?.map(|v| parse_string_list(key, &v)).transpose()?)
}

fn issued_response(issued: SamlIssued) -> Response {
    let mut data = Map::new();
    data.insert("saml_response".into(), issued.saml_response.as_str().into());
    data.insert("acs_url".into(), issued.acs_url.into());
    data.insert("binding".into(), xml::BINDING_POST.into());
    data.insert("relay_state".into(), issued.relay_state.into());
    data.insert("service_provider".into(), issued.service_provider.into());
    data.insert("response_id".into(), issued.response_id.into());
    data.insert("assertion_id".into(), issued.assertion_id.into());
    data.insert("not_on_or_after".into(), issued.not_on_or_after.to_rfc3339().into());
    Response::data_response(Some(data))
}

#[maybe_async::maybe_async]
impl IdpBackendInner {
    pub async fn handle_saml_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let data = match stores.saml.config().await? {
            Some(cfg) => cfg.to_map(),
            None => Map::from_iter([("enabled".to_string(), Value::Bool(false))]),
        };
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_saml_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let update = SamlConfigUpdate {
            enabled: bool_field(req, "enabled")?,
            entity_id: str_field(req, "entity_id")?,
            sso_url: str_field(req, "sso_url")?,
            assertion_ttl_secs: duration_field(req, "assertion_ttl")?,
            request_max_age_secs: duration_field(req, "request_max_age")?,
        };
        let cfg = stores.saml.put_config(update, Utc::now()).await?;
        Ok(Some(Response::data_response(Some(cfg.to_map()))))
    }

    pub async fn handle_saml_keys_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let now = Utc::now();
        let keys: Vec<Value> = match stores.saml.keys.load().await? {
            Some(ring) => ring.keys.iter().map(|k| Value::Object(k.to_map(now))).collect(),
            None => Vec::new(),
        };
        Ok(Some(Response::data_response(Some(Map::from_iter([("keys".to_string(), Value::Array(keys))])))))
    }

    pub async fn handle_saml_keys_rotate(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let overlap = duration_field(req, "overlap")?.unwrap_or(DEFAULT_OVERLAP_SECS);
        let now = Utc::now();
        let ring = stores.saml.keys.rotate(overlap, now).await?;
        let keys: Vec<Value> = ring.keys.iter().map(|k| Value::Object(k.to_map(now))).collect();
        Ok(Some(Response::data_response(Some(Map::from_iter([("keys".to_string(), Value::Array(keys))])))))
    }

    pub async fn handle_saml_sp_list(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let sps = stores.saml.list_sps().await?;
        let keys: Vec<String> = sps.iter().map(|s| s.name.clone()).collect();
        let mut info = Map::new();
        for s in &sps {
            let mut m = Map::new();
            m.insert("entity_id".into(), s.entity_id.clone().into());
            m.insert("environment".into(), s.environment.clone().into());
            info.insert(s.name.clone(), Value::Object(m));
        }
        let mut resp = Response::list_response(&keys);
        resp.data.get_or_insert_with(Map::new).insert("key_info".into(), Value::Object(info));
        Ok(Some(resp))
    }

    pub async fn handle_saml_sp_read(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let name = path_name(req, "name")?;
        match stores.saml.get_sp(&name).await? {
            Some(sp) => Ok(Some(Response::data_response(Some(sp.to_map())))),
            None => Err(PosixError::NotFound(format!("no saml service provider `{name}`")).into()),
        }
    }

    pub async fn handle_saml_sp_write(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let authz = self.authz.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)?;
        let write = SpWrite {
            name: path_name(req, "name")?,
            entity_id: str_field(req, "entity_id")?,
            acs_urls: list_field(req, "acs_urls")?,
            environment: str_field(req, "environment")?,
            allow_idp_initiated: bool_field(req, "allow_idp_initiated")?,
            description: str_field(req, "description")?,
        };
        let (sp, created) = stores.saml.put_sp(&authz, write, Utc::now()).await?;
        let mut data = sp.to_map();
        data.insert("created".into(), created.into());
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_saml_sp_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let name = path_name(req, "name")?;
        match stores.saml.delete_sp(&name).await? {
            Some(sp) => Ok(Some(Response::data_response(Some(sp.to_map())))),
            None => Err(PosixError::NotFound(format!("no saml service provider `{name}`")).into()),
        }
    }

    /// Self-service: answer an SP's AuthnRequest for the caller's identity.
    pub async fn handle_saml_sso(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let entity_id = caller_entity(req, "SAML single sign-on")?;
        let binding = match str_field(req, "binding")? {
            None => Binding::Redirect,
            Some(b) => {
                Binding::parse(&b).ok_or_else(|| PosixError::Invalid("binding must be `redirect` or `post`".into()))?
            }
        };
        let input = SsoInput {
            saml_request: str_field(req, "saml_request")?
                .ok_or_else(|| PosixError::Invalid("saml_request is required".into()))?,
            binding,
            relay_state: str_field(req, "relay_state")?,
            roles: list_field(req, "roles")?,
        };
        let caller_ns = caller_namespace(self.core.as_ref(), req).await?;
        let cfg = stores.saml.config().await?;
        let gate = self.issue_gate();
        let audit = self.federation_audit();
        let deps = SamlDeps { authorizer: &gate, store: &stores.saml, audit: &audit };
        let caller = Caller { entity_id: &entity_id, namespace: &caller_ns, http: Some(&*req) };
        let issued = saml_idp::sso(&deps, cfg.as_ref(), &input, &caller, Utc::now()).await.map_err(RvError::from)?;
        Ok(Some(issued_response(issued)))
    }

    /// Self-service: an IdP-initiated response for a registered SP.
    pub async fn handle_saml_initiate(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let entity_id = caller_entity(req, "SAML single sign-on")?;
        let sp = path_name(req, "name")?;
        let relay_state = str_field(req, "relay_state")?;
        let roles = list_field(req, "roles")?;
        let caller_ns = caller_namespace(self.core.as_ref(), req).await?;
        let cfg = stores.saml.config().await?;
        let gate = self.issue_gate();
        let audit = self.federation_audit();
        let deps = SamlDeps { authorizer: &gate, store: &stores.saml, audit: &audit };
        let caller = Caller { entity_id: &entity_id, namespace: &caller_ns, http: Some(&*req) };
        let issued = saml_idp::initiate(&deps, cfg.as_ref(), &sp, relay_state, roles, &caller, Utc::now())
            .await
            .map_err(RvError::from)?;
        Ok(Some(issued_response(issued)))
    }

    /// Unauthenticated: the IdP metadata, as XML in `data.metadata`.
    pub async fn handle_saml_metadata(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let cfg =
            stores.saml.config().await?.filter(|c| c.enabled).ok_or_else(|| RvError::from(Refusal::NotEnabled))?;
        let now = Utc::now();
        let ring = stores.saml.keys.ensure(now).await?;
        let mut data = Map::new();
        data.insert("metadata".into(), xml::metadata(&cfg.entity_id, &cfg.sso_url, &ring, now)?.into());
        data.insert("entity_id".into(), cfg.entity_id.clone().into());
        data.insert("sso_url".into(), cfg.sso_url.clone().into());
        data.insert("certificate".into(), ring.current()?.cert_pem.clone().into());
        Ok(Some(Response::data_response(Some(data))))
    }
}
