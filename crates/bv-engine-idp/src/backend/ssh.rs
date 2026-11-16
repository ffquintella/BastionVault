//! Phase 3 handlers: `v2/idp/ssh/config`, `v2/idp/ssh/sign/:environment`,
//! `v2/idp/ssh/krl`, `v2/idp/deny-feed` and `v2/idp/deny-feed/key`, plus
//! the revocation every lifecycle change propagates.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bv_errors::bv_error_response_status;
use chrono::Utc;
use serde_json::{Map, Value};

use super::{field, str_field, IdpBackendInner};
use crate::{
    entitlement::model::parse_string_list,
    errors::RvError,
    kernel_api::namespace::caller_namespace,
    logical::{Backend, Request, Response, ENTITY_ID_META},
    posix::{
        model::{IdentityState, PosixError},
        store::PosixStore,
    },
    provider::ssh::{self, store::SshConfigUpdate, RouterSigner, SignRequest},
    revoke::{self, krl::build_krl},
    IssuanceStores,
};

const KRL_COMMENT: &str = "BastionVault identity provider";

/// Seconds, as an integer, a string of digits, or a duration like `30m`.
pub(super) fn duration_field(req: &Request, key: &str) -> Result<Option<u64>, RvError> {
    let invalid = || PosixError::Invalid(format!("{key} must be a duration such as 600, \"600s\" or \"30m\""));
    match field(req, key)? {
        None => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| invalid().into()),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) if s.trim().bytes().all(|b| b.is_ascii_digit()) => {
            s.trim().parse::<u64>().map(Some).map_err(|_| invalid().into())
        }
        Some(Value::String(s)) => {
            humantime::parse_duration(s.trim()).map(|d| Some(d.as_secs())).map_err(|_| invalid().into())
        }
        Some(_) => Err(invalid().into()),
    }
}

/// The calling token's entity. Set only by auth backends (a reserved token
/// metadata key), so a caller can sign for itself and for no one else.
fn caller_entity(req: &Request) -> Result<String, RvError> {
    req.auth.as_ref().and_then(|a| a.metadata.get(ENTITY_ID_META)).filter(|id| !id.is_empty()).cloned().ok_or_else(
        || {
            bv_error_response_status!(
                403,
                "SSH identity certificates are self-service and the calling token is not bound to an entity"
            )
        },
    )
}

#[maybe_async::maybe_async]
impl IdpBackendInner {
    fn issuance(&self) -> Result<Arc<IssuanceStores>, RvError> {
        self.issuance.load().as_ref().clone().ok_or(RvError::ErrBarrierSealed)
    }

    pub async fn handle_ssh_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.guard(req).await?;
        let data = match self.issuance()?.ssh.config().await? {
            Some(cfg) => cfg.to_map(),
            None => Map::from_iter([("enabled".to_string(), Value::Bool(false))]),
        };
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_ssh_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.guard(req).await?;
        let update = SshConfigUpdate {
            mount: str_field(req, "mount")?,
            role: str_field(req, "role")?,
            default_ttl_secs: duration_field(req, "default_ttl")?,
            max_ttl_secs: duration_field(req, "max_ttl")?,
        };
        let cfg = self.issuance()?.ssh.put_config(update, Utc::now()).await?;
        Ok(Some(Response::data_response(Some(cfg.to_map()))))
    }

    /// Self-service sign. The environment's namespace is reached only after
    /// the gate allows; see [`ssh::issue`] for the order of the checks.
    pub async fn handle_ssh_sign(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        self.guard(req).await?;
        let stores = self.issuance()?;
        let entity_id = caller_entity(req)?;
        let environment = str_field(req, "environment")?
            .ok_or_else(|| PosixError::Invalid("environment is missing from the path".into()))?;
        let public_key =
            str_field(req, "public_key")?.ok_or_else(|| PosixError::Invalid("public_key is required".into()))?;
        let ttl_secs = duration_field(req, "ttl")?;
        let roles = field(req, "roles")?.map(|v| parse_string_list("roles", &v)).transpose()?;
        let cfg = stores.ssh.config().await?.ok_or_else(|| {
            bv_error_response_status!(400, "the SSH provider is not configured; write v2/idp/ssh/config first")
        })?;
        // The namespace the request is served in. The guard admits root
        // only, so the gate's namespace rule passes and reach is decided by
        // the entitlement and the root ACL on this path.
        let caller_ns = caller_namespace(self.core.as_ref(), req).await?;
        let sign = SignRequest { entity_id, environment, public_key, ttl_secs, roles, caller_namespace: caller_ns };
        let gate = self.issue_gate();
        let signer = RouterSigner { ctx: self.core.clone() };
        let issued = ssh::issue(&gate, &signer, &stores.ssh, &cfg, &sign, Some(&*req)).await?;
        Ok(Some(Response::data_response(Some(issued.to_map()))))
    }

    pub async fn handle_ssh_krl(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let posix = self.guard(req).await?;
        let stores = self.issuance()?;
        let now = Utc::now();
        let (view, version) = revoke::refresh(&posix, &stores.ssh, &stores.feed, now).await?;
        let generated_at = u64::try_from(now.timestamp()).unwrap_or(0);
        let krl = build_krl(version, generated_at, KRL_COMMENT, &view.certificates)?;
        let mut data = Map::new();
        data.insert("krl".into(), B64.encode(&krl).into());
        data.insert("krl_version".into(), version.into());
        data.insert("generated_at".into(), generated_at.into());
        data.insert("revoked_serials".into(), Value::from(view.serials()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_deny_feed(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let posix = self.guard(req).await?;
        let stores = self.issuance()?;
        let now = Utc::now();
        let (view, version) = revoke::refresh(&posix, &stores.ssh, &stores.feed, now).await?;
        let signer = stores.feed.signer(now).await?;
        let signed = signer.sign(&view.into_feed(version, now.timestamp()))?;
        Ok(Some(Response::data_response(Some(signed.to_map(&signer.public_key())))))
    }

    pub async fn handle_deny_feed_key(&self, _b: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        self.guard(req).await?;
        let signer = self.issuance()?.feed.signer(Utc::now()).await?;
        Ok(Some(Response::data_response(Some(signer.public_key().to_map()))))
    }

    /// A lifecycle change plus its propagation. Leaving `active` marks every
    /// outstanding certificate revoked (idempotent, so repeating the same
    /// state retries it); reinstating first marks whatever was issued before
    /// the disable, so a reinstated identity never revives an old
    /// certificate. Then the feed version moves.
    pub(super) async fn transition_and_propagate(
        &self,
        posix: &PosixStore,
        entity_id: &str,
        to: IdentityState,
        reason: Option<String>,
    ) -> Result<Response, RvError> {
        let stores = self.issuance()?;
        let now = Utc::now();
        if to == IdentityState::Active {
            if let Some(current) = posix.get_identity(entity_id).await? {
                if current.state == IdentityState::Disabled {
                    stores.ssh.revoke_entity(entity_id, "issued before the identity was disabled", now).await?;
                }
            }
        }
        let rec = posix.transition(entity_id, to, reason).await?;
        let mut revoked = 0;
        if rec.state != IdentityState::Active {
            let why = format!("identity {}", rec.state.as_str());
            revoked = stores.ssh.revoke_entity(entity_id, &why, now).await.map_err(|e| {
                log::error!(target: "idp", "idp.ssh.revoke: entity_id={entity_id} marking failed: {e}");
                bv_error_response_status!(
                    500,
                    &format!(
                        "the identity is {} but marking its certificates revoked failed ({e}); the KRL and deny \
                         feed list them while it is not active; repeat the same state change to retry",
                        rec.state.as_str()
                    )
                )
            })?;
        }
        let mut data = rec.to_map();
        data.insert("revoked_certificates".into(), revoked.into());
        let mut resp = Response::data_response(None);
        match revoke::refresh(posix, &stores.ssh, &stores.feed, now).await {
            Ok((_, version)) => {
                data.insert("deny_feed_version".into(), version.into());
            }
            Err(e) => {
                log::warn!(target: "idp", "idp.deny-feed: version not advanced after a state change: {e}");
                resp.add_warning("the deny feed version was not advanced; the next fetch of the feed or KRL will");
            }
        }
        resp.data = Some(data);
        Ok(resp)
    }
}
