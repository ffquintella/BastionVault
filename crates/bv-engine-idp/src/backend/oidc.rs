//! Phase 5 OIDC handlers: `v2/idp/oidc/config`, `keys`, `keys/rotate`,
//! `clients/...` (admin), `authorize` (self-service), and the relying
//! party's unauthenticated `token`, `jwks` and
//! `.well-known/openid-configuration`. Each runs the identity guard first.
//! No response carries a stored secret; a minted client secret, a code and
//! a token are each returned once.

use std::sync::Arc;

use chrono::Utc;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{field, radius::bool_field, ssh::duration_field, str_field, IdpBackendInner};
use crate::{
    entitlement::model::parse_string_list,
    errors::RvError,
    kernel_api::namespace::caller_namespace,
    logical::{Backend, Request, Response},
    posix::model::PosixError,
    provider::{
        federation::{caller_entity, keys::DEFAULT_OVERLAP_SECS, BrokerFederationAudit},
        oidc_op::{
            self,
            store::{ClientWrite, OidcConfigUpdate},
            AuthorizeRequest, OidcDeps, Refusal, TokenRequest,
        },
    },
    IssuanceStores,
};

fn path_name(req: &Request, key: &str) -> Result<String, RvError> {
    str_field(req, key)?.ok_or_else(|| PosixError::Invalid(format!("{key} is missing from the path")).into())
}

fn list_field(req: &Request, key: &str) -> Result<Option<Vec<String>>, RvError> {
    Ok(field(req, key)?.map(|v| parse_string_list(key, &v)).transpose()?)
}

fn secret_field(req: &Request, key: &str) -> Result<Zeroizing<String>, RvError> {
    Ok(Zeroizing::new(str_field(req, key)?.unwrap_or_default()))
}

#[maybe_async::maybe_async]
impl IdpBackendInner {
    pub(super) async fn guard_federation(&self, req: &Request) -> Result<Arc<IssuanceStores>, RvError> {
        self.guard(req).await?;
        self.issuance.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)
    }

    pub(super) fn federation_audit(&self) -> BrokerFederationAudit {
        BrokerFederationAudit { ctx: self.core.clone() }
    }

    pub async fn handle_oidc_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let data = match stores.oidc.config().await? {
            Some(cfg) => cfg.to_map(),
            None => Map::from_iter([("enabled".to_string(), Value::Bool(false))]),
        };
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_oidc_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let update = OidcConfigUpdate {
            enabled: bool_field(req, "enabled")?,
            issuer: str_field(req, "issuer")?,
            authorization_endpoint: str_field(req, "authorization_endpoint")?,
            id_token_ttl_secs: duration_field(req, "id_token_ttl")?,
            code_ttl_secs: duration_field(req, "code_ttl")?,
        };
        let cfg = stores.oidc.put_config(update, Utc::now()).await?;
        Ok(Some(Response::data_response(Some(cfg.to_map()))))
    }

    pub async fn handle_oidc_keys_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let now = Utc::now();
        let keys: Vec<Value> = match stores.oidc.keys.load().await? {
            Some(ring) => ring.keys.iter().map(|k| Value::Object(k.to_map(now))).collect(),
            None => Vec::new(),
        };
        Ok(Some(Response::data_response(Some(Map::from_iter([("keys".to_string(), Value::Array(keys))])))))
    }

    pub async fn handle_oidc_keys_rotate(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let overlap = duration_field(req, "overlap")?.unwrap_or(DEFAULT_OVERLAP_SECS);
        let now = Utc::now();
        let ring = stores.oidc.keys.rotate(overlap, now).await?;
        let keys: Vec<Value> = ring.keys.iter().map(|k| Value::Object(k.to_map(now))).collect();
        Ok(Some(Response::data_response(Some(Map::from_iter([("keys".to_string(), Value::Array(keys))])))))
    }

    pub async fn handle_oidc_client_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let clients = stores.oidc.list_clients().await?;
        let keys: Vec<String> = clients.iter().map(|c| c.client_id.clone()).collect();
        let mut info = Map::new();
        for c in &clients {
            let mut m = Map::new();
            m.insert("environment".into(), c.environment.clone().into());
            m.insert("redirect_uris".into(), Value::from(c.redirect_uris.clone()));
            info.insert(c.client_id.clone(), Value::Object(m));
        }
        let mut resp = Response::list_response(&keys);
        resp.data.get_or_insert_with(Map::new).insert("key_info".into(), Value::Object(info));
        Ok(Some(resp))
    }

    pub async fn handle_oidc_client_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let name = path_name(req, "name")?;
        match stores.oidc.get_client(&name).await? {
            Some(c) => Ok(Some(Response::data_response(Some(c.to_map())))),
            None => Err(PosixError::NotFound(format!("no oidc client `{name}`")).into()),
        }
    }

    pub async fn handle_oidc_client_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let authz = self.authz.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)?;
        let write = ClientWrite {
            client_id: path_name(req, "name")?,
            environment: str_field(req, "environment")?,
            redirect_uris: list_field(req, "redirect_uris")?,
            initiate_login_uri: str_field(req, "initiate_login_uri")?,
            description: str_field(req, "description")?,
            rotate_secret: bool_field(req, "rotate_secret")?.unwrap_or(false),
        };
        let (client, created, secret) = stores.oidc.put_client(&authz, write, Utc::now()).await?;
        let mut data = client.to_map();
        data.insert("created".into(), created.into());
        let mut resp = Response::data_response(Some(data));
        if let Some(secret) = secret {
            resp.data.get_or_insert_with(Map::new).insert("client_secret".into(), secret.as_str().into());
            resp.add_warning("client_secret is shown once; store it in the relying party now");
        }
        Ok(Some(resp))
    }

    pub async fn handle_oidc_client_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let name = path_name(req, "name")?;
        match stores.oidc.delete_client(&name).await? {
            Some(c) => Ok(Some(Response::data_response(Some(c.to_map())))),
            None => Err(PosixError::NotFound(format!("no oidc client `{name}`")).into()),
        }
    }

    /// Self-service: a code for the caller's own identity, for one client.
    /// The browser-facing page relays `redirect_to`; nothing redirects here.
    pub async fn handle_oidc_authorize(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let entity_id = caller_entity(req, "OIDC authorization")?;
        let ask = AuthorizeRequest {
            client_id: str_field(req, "client_id")?.unwrap_or_default(),
            redirect_uri: str_field(req, "redirect_uri")?.unwrap_or_default(),
            response_type: str_field(req, "response_type")?.unwrap_or_default(),
            scope: str_field(req, "scope")?.unwrap_or_default(),
            state: str_field(req, "state")?,
            nonce: str_field(req, "nonce")?,
            code_challenge: str_field(req, "code_challenge")?,
            code_challenge_method: str_field(req, "code_challenge_method")?,
            roles: list_field(req, "roles")?,
        };
        let caller_ns = caller_namespace(self.core.as_ref(), req).await?;
        let cfg = stores.oidc.config().await?;
        let gate = self.issue_gate();
        let audit = self.federation_audit();
        let deps = OidcDeps { authorizer: &gate, store: &stores.oidc, audit: &audit };
        let ok = oidc_op::authorize(&deps, cfg.as_ref(), &ask, &entity_id, &caller_ns, Some(&*req), Utc::now())
            .await
            .map_err(RvError::from)?;
        let mut data = Map::new();
        data.insert("code".into(), ok.code.as_str().into());
        data.insert("redirect_to".into(), ok.redirect_to.as_str().into());
        data.insert("state".into(), ok.state.into());
        data.insert("client_id".into(), ok.client_id.into());
        data.insert("environment".into(), ok.environment.into());
        data.insert("roles".into(), Value::from(ok.roles));
        data.insert("expires_at".into(), ok.expires_at.to_rfc3339().into());
        Ok(Some(Response::data_response(Some(data))))
    }

    /// The relying party's token request (unauthenticated: the client
    /// secret and the PKCE verifier are the proof).
    pub async fn handle_oidc_token(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let ask = TokenRequest {
            grant_type: str_field(req, "grant_type")?.unwrap_or_default(),
            code: secret_field(req, "code")?,
            redirect_uri: str_field(req, "redirect_uri")?.unwrap_or_default(),
            client_id: str_field(req, "client_id")?.unwrap_or_default(),
            client_secret: secret_field(req, "client_secret")?,
            code_verifier: secret_field(req, "code_verifier")?,
        };
        let cfg = stores.oidc.config().await?;
        let gate = self.issue_gate();
        let audit = self.federation_audit();
        let deps = OidcDeps { authorizer: &gate, store: &stores.oidc, audit: &audit };
        let issued = oidc_op::token(&deps, cfg.as_ref(), &ask, Some(&*req), Utc::now()).await.map_err(RvError::from)?;
        let mut data = Map::new();
        data.insert("access_token".into(), issued.access_token.as_str().into());
        data.insert("token_type".into(), "Bearer".into());
        data.insert("expires_in".into(), issued.expires_in.into());
        data.insert("id_token".into(), issued.id_token.as_str().into());
        data.insert("scope".into(), issued.scope.into());
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_oidc_jwks(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        stores.oidc.config().await?.filter(|c| c.enabled).ok_or_else(|| RvError::from(Refusal::NotEnabled))?;
        let now = Utc::now();
        let ring = stores.oidc.keys.ensure(now).await?;
        Ok(Some(Response::data_response(Some(oidc_op::jwks(&ring, now)?))))
    }

    pub async fn handle_oidc_discovery(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let stores = self.guard_federation(req).await?;
        let cfg =
            stores.oidc.config().await?.filter(|c| c.enabled).ok_or_else(|| RvError::from(Refusal::NotEnabled))?;
        Ok(Some(Response::data_response(Some(oidc_op::discovery(&cfg)))))
    }
}
