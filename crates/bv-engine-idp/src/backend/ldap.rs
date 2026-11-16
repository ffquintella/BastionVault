//! Phase 6 handlers: `v2/idp/ldap/config`, `v2/idp/ldap/clients/...` and
//! the self-service `v2/idp/ldap/passcode/:environment`. Each runs the
//! identity guard first. No response carries the TLS key or a stored
//! passcode; the minted passcode is returned once.

use std::sync::Arc;

use bv_errors::bv_error_response_status;
use chrono::Utc;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{field, radius::bool_field, ssh::duration_field, str_field, IdpBackendInner};
use crate::{
    entitlement::{gate::IssueRequest, store::EntitlementStore},
    errors::RvError,
    kernel_api::namespace::caller_namespace,
    logical::{Backend, Request, Response},
    posix::model::PosixError,
    provider::{
        federation::caller_entity,
        ldap_dir::{
            store::{ClientWrite, ConfigUpdate, LdapStore, Transport},
            PASSCODE_PROVIDER,
        },
        radius::store::MIN_PASSCODE_TTL_SECS,
        Authorizer,
    },
    IssuanceStores,
};

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

#[maybe_async::maybe_async]
impl IdpBackendInner {
    async fn guard_ldap(&self, req: &Request) -> Result<(Arc<IssuanceStores>, Arc<EntitlementStore>), RvError> {
        self.guard(req).await?;
        let stores = self.issuance.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)?;
        let authz = self.authz.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)?;
        Ok((stores, authz))
    }

    async fn ldap_config_response(&self, ldap: &LdapStore) -> Result<Option<Response>, RvError> {
        let mut data = match ldap.config().await? {
            Some(cfg) => cfg.to_map(),
            None => Map::from_iter([("enabled".to_string(), Value::Bool(false))]),
        };
        data.insert("listening".into(), self.ldap.status().to_value());
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_ldap_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_ldap(req).await?;
        self.ldap_config_response(&stores.ldap).await
    }

    pub async fn handle_ldap_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_ldap(req).await?;
        let time_limit = duration_field(req, "time_limit")?
            .map(|t| u32::try_from(t).map_err(|_| PosixError::Invalid("time_limit is too large".into())))
            .transpose()?;
        let update = ConfigUpdate {
            enabled: bool_field(req, "enabled")?,
            ldaps_listen: str_field(req, "ldaps_listen")?,
            ldap_listen: str_field(req, "ldap_listen")?,
            plaintext_enabled: bool_field(req, "plaintext_enabled")?,
            allow_unspecified_bind: bool_field(req, "allow_unspecified_bind")?,
            tls_cert_pem: str_field(req, "tls_cert_pem")?,
            tls_key_pem: str_field(req, "tls_key_pem")?.map(Zeroizing::new),
            client_ca_pem: str_field(req, "client_ca_pem")?,
            base_dn: str_field(req, "base_dn")?,
            home_directory_base: str_field(req, "home_directory_base")?,
            login_shell: str_field(req, "login_shell")?,
            size_limit: u32_field(req, "size_limit")?,
            time_limit_secs: time_limit,
            rate_limit_per_minute: u32_field(req, "rate_limit_per_minute")?,
            passcode_default_ttl_secs: duration_field(req, "passcode_default_ttl")?,
            passcode_max_ttl_secs: duration_field(req, "passcode_max_ttl")?,
        };
        let cfg = stores.ldap.put_config(update, Utc::now()).await?;
        self.ldap.reconcile_soon();
        let mut resp = self.ldap_config_response(&stores.ldap).await?;
        if let Some(r) = resp.as_mut() {
            r.add_warning("the listeners are reconciled asynchronously; read this path again for `listening`");
            if cfg.plaintext_enabled {
                r.add_warning(
                    "cleartext LDAP is enabled: directory data and bind passcodes cross the network unencrypted; \
                     use it on a trusted segment only",
                );
            }
        }
        Ok(resp)
    }

    pub async fn handle_ldap_client_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_ldap(req).await?;
        let clients = stores.ldap.list_clients().await?;
        let keys: Vec<String> = clients.iter().map(|c| c.name.clone()).collect();
        let mut info = Map::new();
        for c in &clients {
            let mut m = Map::new();
            m.insert("transport".into(), c.transport.as_str().into());
            m.insert("environment".into(), c.environment.clone().into());
            info.insert(c.name.clone(), Value::Object(m));
        }
        let mut resp = Response::list_response(&keys);
        resp.data.get_or_insert_with(Map::new).insert("key_info".into(), Value::Object(info));
        Ok(Some(resp))
    }

    pub async fn handle_ldap_client_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_ldap(req).await?;
        let name = path_name(req, "name")?;
        match stores.ldap.get_client(&name).await? {
            Some(c) => Ok(Some(Response::data_response(Some(c.to_map())))),
            None => Err(PosixError::NotFound(format!("no ldap client `{name}`")).into()),
        }
    }

    pub async fn handle_ldap_client_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, authz) = self.guard_ldap(req).await?;
        let write = ClientWrite {
            name: path_name(req, "name")?,
            transport: str_field(req, "transport")?.map(|t| Transport::parse(&t)).transpose()?,
            environment: str_field(req, "environment")?,
            cert_sha256: str_field(req, "cert_sha256")?,
            address: str_field(req, "address")?,
            description: str_field(req, "description")?,
        };
        let (client, created) = stores.ldap.put_client(&authz, write, Utc::now()).await?;
        self.ldap.reconcile_soon();
        let mut data = client.to_map();
        data.insert("created".into(), created.into());
        let mut resp = Response::data_response(Some(data));
        if client.transport == Transport::Plain {
            resp.add_warning(
                "a plain client is recognised by its source address over cleartext LDAP; trusted segments only",
            );
        }
        Ok(Some(resp))
    }

    pub async fn handle_ldap_client_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_ldap(req).await?;
        let name = path_name(req, "name")?;
        let removed = stores.ldap.delete_client(&name).await?;
        self.ldap.reconcile_soon();
        match removed {
            Some(c) => Ok(Some(Response::data_response(Some(c.to_map())))),
            None => Err(PosixError::NotFound(format!("no ldap client `{name}`")).into()),
        }
    }

    /// Self-service: the caller's own entity, gated like any issue. The
    /// passcode is returned once and stored only as a hash.
    pub async fn handle_ldap_passcode(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let (stores, _) = self.guard_ldap(req).await?;
        let entity_id = caller_entity(req, "LDAP passcodes")?;
        let environment = path_name(req, "environment")?;
        let requested_ttl = duration_field(req, "ttl")?;
        let cfg = stores.ldap.config().await?.filter(|c| c.enabled).ok_or_else(|| {
            bv_error_response_status!(400, "the LDAP directory is not enabled; write v2/idp/ldap/config first")
        })?;
        let ttl = requested_ttl.unwrap_or(cfg.passcode_default_ttl_secs);
        if !(MIN_PASSCODE_TTL_SECS..=cfg.passcode_max_ttl_secs).contains(&ttl) {
            return Err(bv_error_response_status!(
                400,
                &format!("ttl must lie within [{MIN_PASSCODE_TTL_SECS}, {}] seconds", cfg.passcode_max_ttl_secs)
            ));
        }
        let layout = cfg.layout()?;
        let ask = IssueRequest {
            entity_id,
            environment,
            roles: None,
            caller_namespace: caller_namespace(self.core.as_ref(), req).await?,
            provider: PASSCODE_PROVIDER.to_string(),
        };
        let gate = self.issue_gate();
        let grant = Authorizer::check(&gate, &ask, Some(&*req)).await?;
        let (passcode, rec) =
            stores.ldap.mint_passcode(&grant.entity_id, &grant.login, &grant.environment, ttl, Utc::now()).await?;
        log::info!(
            target: "security",
            "idp.ldap.passcode: entity_id={} login={} environment={} expires_at={}",
            rec.entity_id,
            rec.login,
            rec.environment,
            rec.expires_at.to_rfc3339()
        );
        let mut data = Map::new();
        data.insert("passcode".into(), passcode.as_str().into());
        data.insert("login".into(), rec.login.clone().into());
        data.insert("bind_dn".into(), layout.person_dn(&rec.login).to_string().into());
        data.insert("environment".into(), rec.environment.clone().into());
        data.insert("expires_at".into(), rec.expires_at.to_rfc3339().into());
        data.insert("ttl".into(), ttl.into());
        Ok(Some(Response::data_response(Some(data))))
    }
}
