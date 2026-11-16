//! The SSH provider (features/identity-provider.md §3a): an identity-bound
//! user certificate for one environment. The issue gate runs first; the
//! certificate is then signed by the SSH engine mounted in the environment's
//! namespace, router-direct (as `bv_kernel_api::ssh_credentials` does), read
//! back and checked field by field, and recorded for the KRL before it is
//! returned. Nothing here signs: there is one SSH signer, the SSH engine.

pub mod store;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, sync::Arc};

use bv_errors::bv_error_response_status;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use ssh_key::{certificate::CertType, Certificate, PublicKey};

use crate::{
    entitlement::gate::{IssueDenied, IssueGate, IssueGrant, IssueRequest},
    errors::RvError,
    kernel_api::{namespace::scoped_mount, VaultCtx},
    logical::{Operation, Request},
};

use store::{format_serial, CertRecord, SshProviderConfig, SshStore, MIN_TTL_SECS};

/// The provider name the gate records.
pub const PROVIDER: &str = "ssh";
pub const EXT_UID: &str = "uid@bastionvault";
pub const EXT_GID: &str = "gid@bastionvault";
pub const EXT_ENV: &str = "env@bastionvault";
pub const EXT_ROLES: &str = "roles@bastionvault";
/// Allowed drift between this process's clock and the engine's when the
/// validity window is checked.
const VALIDITY_SLACK_SECS: u64 = 5;
const MAX_PUBLIC_KEY_LEN: usize = 16 * 1024;

/// `bv:<entity_id>:<login>:uid=<uid>:env=<environment>`. Every part is
/// already restricted to `[A-Za-z0-9_-]`, so the colons are unambiguous.
pub fn identity_key_id(grant: &IssueGrant) -> String {
    format!("bv:{}:{}:uid={}:env={}", grant.entity_id, grant.login, grant.uid, grant.environment)
}

/// The extensions a certificate must carry, exactly.
pub fn identity_extensions(grant: &IssueGrant) -> BTreeMap<String, String> {
    BTreeMap::from([
        (EXT_UID.to_string(), grant.uid.to_string()),
        (EXT_GID.to_string(), grant.primary_gid.to_string()),
        (EXT_ENV.to_string(), grant.environment.clone()),
        (EXT_ROLES.to_string(), grant.roles.join(",")),
    ])
}

/// A sign request. `entity_id` is the calling token's entity, never a
/// field of the request body.
#[derive(Debug, Clone)]
pub struct SignRequest {
    pub entity_id: String,
    pub environment: String,
    pub public_key: String,
    pub ttl_secs: Option<u64>,
    pub roles: Option<Vec<String>>,
    pub caller_namespace: String,
}

/// What a caller gets back. The private key is the caller's own; it never
/// reaches the vault.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub signed_key: String,
    pub serial: u64,
    pub key_id: String,
    pub login: String,
    pub uid: u32,
    pub primary_gid: u32,
    pub environment: String,
    pub namespace: String,
    pub roles: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
}

impl IssuedCert {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("signed_key".into(), self.signed_key.clone().into());
        m.insert("serial_number".into(), format_serial(self.serial).into());
        m.insert("key_id".into(), self.key_id.clone().into());
        m.insert("principals".into(), Value::from(vec![self.login.clone()]));
        m.insert("login".into(), self.login.clone().into());
        m.insert("uid".into(), self.uid.into());
        m.insert("gid".into(), self.primary_gid.into());
        m.insert("environment".into(), self.environment.clone().into());
        m.insert("namespace".into(), self.namespace.clone().into());
        m.insert("roles".into(), Value::from(self.roles.clone()));
        m.insert("valid_after".into(), self.valid_after.into());
        m.insert("valid_before".into(), self.valid_before.into());
        m
    }
}

/// The decision a sign waits on. Implemented by [`IssueGate`] only; the
/// seam exists for the test that proves the sign tests depend on the gate.
// Same macro-generated `double_must_use` as the gate's traits.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub(crate) trait Authorizer: Send + Sync {
    async fn check(&self, req: &IssueRequest, http: Option<&Request>) -> Result<IssueGrant, IssueDenied>;
}

#[maybe_async::maybe_async]
impl Authorizer for IssueGate {
    async fn check(&self, req: &IssueRequest, http: Option<&Request>) -> Result<IssueGrant, IssueDenied> {
        self.authorize(req, http).await
    }
}

/// Where the SSH engine that signs lives.
#[derive(Debug, Clone)]
pub struct SignTarget<'a> {
    pub namespace: &'a str,
    pub namespace_uuid: &'a str,
    pub mount: &'a str,
    pub role: &'a str,
}

/// Asks an SSH engine to sign; returns its `signed_key`.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub trait SshSigner: Send + Sync {
    async fn sign(&self, target: &SignTarget<'_>, body: Map<String, Value>) -> Result<String, RvError>;
}

/// The SSH engine mounted in the environment's namespace, called through
/// the router without the caller's ACL: the gate has already decided.
pub struct RouterSigner {
    pub ctx: Arc<dyn VaultCtx>,
}

#[maybe_async::maybe_async]
impl SshSigner for RouterSigner {
    async fn sign(&self, target: &SignTarget<'_>, body: Map<String, Value>) -> Result<String, RvError> {
        let mount = scoped_mount(self.ctx.as_ref(), target.namespace, target.namespace_uuid, target.mount).await?;
        let path = format!("{mount}/sign/{}", target.role);
        let mut sub = Request::new_write_request(&path, Some(body));
        sub.operation = Operation::Write;
        let resp = self
            .ctx
            .router()
            .handle_request(&mut sub)
            .await?
            .ok_or_else(|| bv_error_response_status!(502, &format!("ssh engine `{path}` returned no response")))?;
        resp.data
            .as_ref()
            .and_then(|d| d.get("signed_key"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| bv_error_response_status!(502, &format!("ssh engine `{path}` returned no `signed_key`")))
    }
}

fn unix_secs(t: DateTime<Utc>) -> u64 {
    u64::try_from(t.timestamp()).unwrap_or(0)
}

/// An OpenSSH public key, one line, without its comment. A certificate or
/// anything else is refused.
pub fn parse_client_key(raw: &str) -> Result<PublicKey, RvError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_PUBLIC_KEY_LEN || raw.contains(['\n', '\r']) {
        return Err(bv_error_response_status!(400, "public_key must be one OpenSSH public-key line"));
    }
    let mut key = PublicKey::from_openssh(raw)
        .map_err(|_| bv_error_response_status!(400, "public_key is not an OpenSSH public key this provider signs"))?;
    key.set_comment("");
    Ok(key)
}

/// The requested lifetime, or the default. Above the configured maximum is
/// refused, not clamped.
pub fn effective_ttl(cfg: &SshProviderConfig, requested: Option<u64>) -> Result<u64, RvError> {
    let ttl = requested.unwrap_or(cfg.default_ttl_secs);
    if ttl < MIN_TTL_SECS {
        return Err(bv_error_response_status!(400, &format!("ttl must be at least {MIN_TTL_SECS} seconds")));
    }
    if ttl > cfg.max_ttl_secs {
        return Err(bv_error_response_status!(
            400,
            &format!("ttl {ttl}s exceeds the SSH provider's max_ttl of {}s", cfg.max_ttl_secs)
        ));
    }
    Ok(ttl)
}

fn mismatch(serial: Option<u64>, what: &str) -> RvError {
    log::warn!(
        target: "security",
        "idp.ssh.issue: the SSH engine's certificate was discarded (serial={}): {what}",
        serial.map(format_serial).unwrap_or_default()
    );
    bv_error_response_status!(
        502,
        &format!("the SSH engine's certificate does not match the identity request ({what}); nothing was issued")
    )
}

/// Read the certificate back and check every field the identity depends on.
/// The engine's role may add extensions or critical options (they only
/// restrict); anything else that differs discards the certificate.
pub(crate) fn verify_issued(
    signed_key: &str,
    client_key: &PublicKey,
    grant: &IssueGrant,
    ttl: u64,
    started: u64,
) -> Result<Certificate, RvError> {
    let cert =
        Certificate::from_openssh(signed_key.trim()).map_err(|_| mismatch(None, "not an OpenSSH certificate"))?;
    let serial = Some(cert.serial());
    if cert.serial() == 0 {
        return Err(mismatch(serial, "serial 0 cannot be listed in a KRL"));
    }
    if cert.cert_type() != CertType::User {
        return Err(mismatch(serial, "not a user certificate"));
    }
    if cert.public_key() != client_key.key_data() {
        return Err(mismatch(serial, "certifies a different public key"));
    }
    if cert.valid_principals() != [grant.login.clone()] {
        return Err(mismatch(serial, "valid principals are not exactly the login"));
    }
    if cert.key_id() != identity_key_id(grant) {
        return Err(mismatch(serial, "key id is not the identity key id"));
    }
    for (name, value) in identity_extensions(grant) {
        if cert.extensions().get(&name) != Some(&value) {
            return Err(mismatch(serial, &format!("extension {name} is missing or altered")));
        }
    }
    let latest = started.saturating_add(ttl).saturating_add(VALIDITY_SLACK_SECS);
    if cert.valid_before() <= started || cert.valid_before() > latest {
        return Err(mismatch(serial, "validity ends outside the requested lifetime"));
    }
    if cert.valid_after() >= cert.valid_before() || cert.valid_after() > started.saturating_add(VALIDITY_SLACK_SECS) {
        return Err(mismatch(serial, "validity window is malformed"));
    }
    Ok(cert)
}

/// Issue one identity certificate. Order matters: every input the caller
/// controls is checked first, then the gate, then the signature, then the
/// read-back, then the record; only then is the certificate returned.
#[maybe_async::maybe_async]
pub(crate) async fn issue(
    authorizer: &dyn Authorizer,
    signer: &dyn SshSigner,
    store: &SshStore,
    cfg: &SshProviderConfig,
    req: &SignRequest,
    http: Option<&Request>,
) -> Result<IssuedCert, RvError> {
    let client_key = parse_client_key(&req.public_key)?;
    let ttl = effective_ttl(cfg, req.ttl_secs)?;
    let ask = IssueRequest {
        entity_id: req.entity_id.clone(),
        environment: req.environment.clone(),
        roles: req.roles.clone(),
        caller_namespace: req.caller_namespace.clone(),
        provider: PROVIDER.to_string(),
    };
    let grant = authorizer.check(&ask, http).await?;

    let key_id = identity_key_id(&grant);
    let extensions: Map<String, Value> =
        identity_extensions(&grant).into_iter().map(|(k, v)| (k, Value::String(v))).collect();
    let public_key = client_key
        .to_openssh()
        .map_err(|e| bv_error_response_status!(400, &format!("public_key cannot be re-encoded: {e}")))?;
    let mut body = Map::new();
    body.insert("public_key".into(), public_key.into());
    body.insert("valid_principals".into(), grant.login.clone().into());
    body.insert("cert_type".into(), "user".into());
    body.insert("key_id".into(), key_id.clone().into());
    body.insert("ttl".into(), format!("{ttl}s").into());
    body.insert("extensions".into(), Value::Object(extensions));

    let started = unix_secs(Utc::now());
    let target = SignTarget {
        namespace: &grant.namespace,
        namespace_uuid: &grant.namespace_uuid,
        mount: &cfg.mount,
        role: &cfg.role,
    };
    let signed_key = signer.sign(&target, body).await.map_err(|e| {
        log::error!(
            target: "idp",
            "idp.ssh.issue: ssh engine {}/{} in namespace {:?} refused to sign for entity_id={}: {e}",
            cfg.mount,
            cfg.role,
            grant.namespace,
            grant.entity_id
        );
        bv_error_response_status!(502, &format!("the SSH engine refused to sign: {e}"))
    })?;
    let cert = verify_issued(&signed_key, &client_key, &grant, ttl, started)?;

    let ca_public_key = PublicKey::new(cert.signature_key().clone(), "")
        .to_openssh()
        .map_err(|_| mismatch(Some(cert.serial()), "signing CA key cannot be encoded"))?;
    let record = CertRecord {
        version: crate::posix::model::RECORD_VERSION,
        serial: format_serial(cert.serial()),
        entity_id: grant.entity_id.clone(),
        login: grant.login.clone(),
        uid: grant.uid,
        environment: grant.environment.clone(),
        namespace: grant.namespace.clone(),
        key_id: key_id.clone(),
        ca_public_key,
        valid_after: cert.valid_after(),
        valid_before: cert.valid_before(),
        issued_at: Utc::now(),
        revoked_at: None,
        revoke_reason: None,
    };
    // Unrecorded means unrevocable by serial: such a certificate is not issued.
    store.record_issued(&record, started).await.map_err(|e| {
        log::error!(target: "idp", "idp.ssh.issue: cannot record serial {}, not issuing: {e}", record.serial);
        e
    })?;
    log::info!(
        target: "security",
        "idp.ssh.issue: entity_id={} login={} uid={} environment={} serial={} valid_before={}",
        grant.entity_id,
        grant.login,
        grant.uid,
        grant.environment,
        record.serial,
        record.valid_before
    );
    Ok(IssuedCert {
        signed_key,
        serial: cert.serial(),
        key_id,
        login: grant.login,
        uid: grant.uid,
        primary_gid: grant.primary_gid,
        environment: grant.environment,
        namespace: grant.namespace,
        roles: grant.roles,
        valid_after: cert.valid_after(),
        valid_before: cert.valid_before(),
    })
}
