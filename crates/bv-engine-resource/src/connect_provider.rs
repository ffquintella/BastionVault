//! Credential providers at Connect — the resource engine's half
//! (`features/self-accounts.md` §5, §6, §9; T103 Phase 3).
//!
//! A connection profile whose `credential_source` is
//! `{"kind": "provider", "provider": "<plugin>"}` takes its credential from a
//! plugin the administrator approved as a credential provider. This module
//! owns what the resource engine does with such a profile:
//!
//! * `v2/connect/providers` — the approved, active providers a profile can
//!   name (for the profile editor), declarations only;
//! * `v2/connect/provider/candidates` — the accounts the operator may pick,
//!   **metadata only**;
//! * the release on `v2/connect/authorize` (direct SSH / RDP). The release on
//!   `v2/connect/web/launch` lives with the rest of the launch in
//!   `connect_web`, and uses [`ResourceBackendInner::provider_launch`] and
//!   [`ResourceBackendInner::release_provider`] from here.
//!
//! ## What the provider is told, and by whom
//!
//! The resource *type*, its *OS* and the *target* are computed here from the
//! **stored** resource record and profile, never from the request: the
//! request body carries `resource`, `profile_id` and, on a release,
//! `provider_account_id` — nothing else is read. A resource edited to point at
//! another host therefore reaches the provider with that other host, and an
//! account bound to the real one does not match (spec §5).
//!
//! ## Failing closed
//!
//! An ungranted, quarantined or stale provider, a profile naming a different
//! provider, an unsupported protocol, a missing account id, a caller without
//! an identity entity and a release that fails the host's shape check all
//! refuse. Nothing falls back to another credential source.
//!
//! ## Audit
//!
//! `target: "audit"` lines `connect.provider.release` (per release attempt) and
//! `connect.provider.candidates` (per listing), written by the shared
//! [`ProviderAudit`]: names, ids and enum values only.

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::connect_mfa::find_profile;
pub(crate) use crate::kernel_api::provider::ProviderAudit;
use crate::kernel_api::{
    engines::{profile_gate_flag, PluginHost},
    provider::{
        host_target, profile_provider, provider_resource, reason, refusal, refusal_reason, require_not_brokered_for,
        CallerIdentity,
        CredentialProviderDecl, ProviderConnectContext, ProviderNeeds, ProviderQuery, ProviderReleaseRequest,
        ProviderResource, ProviderTarget, ReleasedCredential, ReleasedSecret,
    },
};
use crate::{
    errors::RvError,
    logical::{Backend, Request, Response},
};

/// Longest `provider_account_id` accepted. Self-account ids are far shorter;
/// the bound only keeps an absurd value out of the audit line.
const MAX_ACCOUNT_ID_LEN: usize = 128;

// ── Request fields ─────────────────────────────────────────────────

/// The request's `provider_account_id`. `Ok(None)` when absent or empty; a
/// wrong-typed or malformed value is refused rather than ignored.
pub(crate) fn account_id_field(req: &Request) -> Result<Option<String>, RvError> {
    let invalid = || refusal(400, reason::INVALID_REQUEST, "`provider_account_id` must be an account id string");
    match req.get_data("provider_account_id") {
        Ok(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            if s.len() > MAX_ACCOUNT_ID_LEN || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(invalid());
            }
            Ok(Some(s.to_string()))
        }
        Ok(_) | Err(RvError::ErrRequestFieldInvalid) => Err(invalid()),
        Err(_) => Ok(None),
    }
}

/// The stored profile's protocol, as the provider vocabulary names it.
pub(crate) fn profile_protocol(profile: &Value) -> Result<&'static str, RvError> {
    match profile.get("protocol").and_then(Value::as_str) {
        Some("ssh") => Ok("ssh"),
        Some("rdp") => Ok("rdp"),
        Some("web") => Ok("web"),
        _ => Err(refusal(
            422,
            reason::INVALID_PROFILE,
            "the profile's `protocol` must be ssh, rdp or web to use a credential provider",
        )),
    }
}

/// The provider a stored profile names; refuses a profile that names none.
fn stored_provider(profile: &Value) -> Result<String, RvError> {
    match profile_provider(profile) {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(refusal(
            400,
            reason::INVALID_PROFILE,
            "this connection profile does not take its credential from a credential provider",
        )),
        Err(m) => Err(refusal(422, reason::INVALID_PROFILE, m)),
    }
}

// ── Audit ──────────────────────────────────────────────────────────

/// A refusal with the reason the audit line records. Most reasons are read
/// back from the error's prefix; the few that are not (the connect grant, an
/// MFA ticket refusal, a web profile check) are named where they happen.
pub(crate) struct Denied {
    pub reason: &'static str,
    pub err: RvError,
}

/// The audit reason of an error with no explicit one: its prefix, else
/// `invalid_request` for a 400 / 404 / 422 from the shared front half
/// (`resource is required`, an unknown resource), else `error`.
pub(crate) fn audit_reason(err: &RvError) -> &'static str {
    match refusal_reason(err) {
        reason::ERROR => match err {
            RvError::ErrResponseStatus(400 | 404 | 422, _) => reason::INVALID_REQUEST,
            _ => reason::ERROR,
        },
        r => r,
    }
}

impl From<RvError> for Denied {
    fn from(err: RvError) -> Self {
        Self { reason: audit_reason(&err), err }
    }
}

impl Denied {
    pub fn new(reason: &'static str, err: RvError) -> Self {
        Self { reason, err }
    }
}

// ── The provider listing ───────────────────────────────────────────

/// The `providers` response of `GET resources/v2/connect/providers`: one entry
/// per declaration, sorted by name so the editor's list is stable.
fn providers_listing(mut decls: Vec<CredentialProviderDecl>) -> Map<String, Value> {
    decls.sort_by(|a, b| a.plugin.cmp(&b.plugin));
    let providers = decls
        .into_iter()
        .map(|d| {
            let mut m = Map::new();
            m.insert("name".into(), Value::String(d.plugin));
            m.insert("display_name".into(), Value::String(d.display_name));
            m.insert("protocols".into(), Value::Array(d.protocols.into_iter().map(Value::String).collect()));
            m.insert("secret_kinds".into(), Value::Array(d.secret_kinds.into_iter().map(Value::String).collect()));
            Value::Object(m)
        })
        .collect();
    let mut data = Map::new();
    data.insert("providers".into(), Value::Array(providers));
    data
}

// ── The response's `credential` ────────────────────────────────────

/// The `credential` object of an `authorize` response: the released username,
/// the domain when there is one, and the secret. A TOTP seed is never put in
/// it (the direct path asks for none, and the bridge refuses an unrequested
/// one). The strings are copies the response map owns; the
/// `ReleasedCredential` they came from is zeroized when it drops.
fn credential_object(cred: &ReleasedCredential) -> Map<String, Value> {
    let mut secret = Map::new();
    secret.insert("kind".into(), Value::String(cred.secret.kind().into()));
    match &cred.secret {
        ReleasedSecret::Password { password, .. } => {
            secret.insert("password".into(), Value::String(password.to_string()));
        }
        ReleasedSecret::SshKey { private_key } => {
            secret.insert("private_key".into(), Value::String(private_key.to_string()));
        }
    }
    let mut out = Map::new();
    out.insert("username".into(), Value::String(cred.username.clone()));
    if let Some(d) = &cred.domain {
        out.insert("domain".into(), Value::String(d.clone()));
    }
    out.insert("secret".into(), Value::Object(secret));
    out
}

/// What `handle_connect_authorize` hands the `provider` arm: the canonical
/// resource name, the stored profile and record it already loaded under the
/// connect grant, the provider the profile names, and the request's account.
pub(crate) struct AuthorizeTarget<'a> {
    pub resource: String,
    pub profile_id: String,
    pub profile: &'a Value,
    pub meta: &'a Map<String, Value>,
    pub provider: String,
    pub account_id: Option<String>,
}

// ── Prepared calls ─────────────────────────────────────────────────

/// Everything a provider call needs, checked before the provider runs: the
/// attested caller (with an entity), a live provider that declares the
/// protocol, and the query the stored metadata produced.
pub(crate) struct ProviderLaunch {
    pub host: Arc<dyn PluginHost>,
    pub provider: String,
    pub caller: CallerIdentity,
    pub protocol: &'static str,
    pub resource: ProviderResource,
    pub target: ProviderTarget,
}

#[maybe_async::maybe_async]
impl super::ResourceBackendInner {
    /// The checks every provider call makes before reaching the provider.
    /// The bridge repeats the grant and protocol checks (a grant revoked in
    /// between still refuses); doing them here first means a refusal costs
    /// the operator no MFA ticket.
    pub(crate) async fn provider_launch(
        &self,
        req: &Request,
        provider: &str,
        protocol: &'static str,
        resource: ProviderResource,
        target: ProviderTarget,
    ) -> Result<ProviderLaunch, RvError> {
        let caller = CallerIdentity::from_request(req);
        if caller.entity_id.is_empty() {
            return Err(refusal(
                403,
                reason::NO_ENTITY,
                "a credential provider releases per-user accounts and needs an identity-backed login; \
                 this token has no identity entity",
            ));
        }
        let not_approved =
            || refusal(403, reason::NOT_GRANTED, format!("credential provider `{provider}` is not approved on this server"));
        let host = self.core.plugin_host().ok_or_else(not_approved)?;
        let decl = host.credential_providers().await.into_iter().find(|d| d.plugin == provider).ok_or_else(not_approved)?;
        if !decl.protocols.iter().any(|p| p == protocol) {
            return Err(refusal(
                400,
                reason::UNSUPPORTED_PROTOCOL,
                format!("credential provider `{provider}` does not support protocol `{protocol}`"),
            ));
        }
        Ok(ProviderLaunch { host, provider: provider.to_string(), caller, protocol, resource, target })
    }

    /// Ask the provider for one account's credential. `mfa_verified` must be
    /// true only when a connect MFA ticket was redeemed for this very launch.
    pub(crate) async fn release_provider(
        &self,
        launch: &ProviderLaunch,
        account_id: &str,
        needs: ProviderNeeds,
        mfa_verified: bool,
        transport: &str,
    ) -> Result<ReleasedCredential, RvError> {
        let req = ProviderReleaseRequest {
            account_id: account_id.to_string(),
            protocol: launch.protocol.to_string(),
            resource: launch.resource.clone(),
            target: launch.target.clone(),
            needs,
            connect: ProviderConnectContext { mfa_verified, transport: transport.to_string() },
        };
        launch.host.provider_release(&launch.provider, &launch.caller, &req).await
    }

    /// The query the stored record produces for `protocol`. SSH / RDP: the
    /// host target. Web: every origin the profile's recipe may fill, exactly
    /// as `connect/web/launch` checks them.
    fn provider_query_parts(
        &self,
        profile: &Value,
        meta: &Map<String, Value>,
        protocol: &'static str,
    ) -> Result<(ProviderResource, ProviderTarget), Denied> {
        let invalid = |m: String| Denied::new(reason::INVALID_PROFILE, refusal(422, reason::INVALID_PROFILE, m));
        let resource = provider_resource(meta).map_err(invalid)?;
        let target = if protocol == "web" {
            let parsed = crate::connect_web::profile::parse_launch_profile(profile)
                .map_err(|r| Denied::new(reason::INVALID_PROFILE, r.into_rv()))?;
            ProviderTarget::Origins { origins: parsed.origins }
        } else {
            host_target(profile, meta, protocol).map_err(invalid)?
        };
        Ok((resource, target))
    }

    // ── providers ──────────────────────────────────────────────────

    /// `GET resources/v2/connect/providers`: the providers a connection
    /// profile can name, for the profile editor (Phase 4). The list is the
    /// host's own: approved, active and not quarantined
    /// ([`PluginHost::credential_providers`]). Nothing per-user is read, so
    /// the ACL check on the path is the whole gate; no account data, config
    /// or grant record is returned. A server with no plugin runtime has no
    /// providers.
    pub async fn handle_connect_providers(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let decls = match self.core.plugin_host() {
            Some(host) => host.credential_providers().await,
            None => Vec::new(),
        };
        Ok(Some(Response::data_response(Some(providers_listing(decls)))))
    }

    // ── candidates ─────────────────────────────────────────────────

    /// `POST resources/v2/connect/provider/candidates`.
    pub async fn handle_connect_provider_candidates(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut audit = ProviderAudit::new("candidates", "-", req);
        match self.provider_candidates(req, &mut audit).await {
            Ok((data, n)) => {
                audit.listed(n);
                Ok(Some(Response::data_response(Some(data))))
            }
            Err(d) => {
                audit.denied(d.reason);
                Err(d.err)
            }
        }
    }

    async fn provider_candidates(
        &self,
        req: &mut Request,
        audit: &mut ProviderAudit,
    ) -> Result<(Map<String, Value>, usize), Denied> {
        // The connect grant, then the stored record — the same front half as
        // `connect/authorize`. Only `resource` and `profile_id` are read off
        // the body. The names as requested go on a refusal's audit line; a
        // granted call replaces them with the canonical ones.
        let named = |k: &str| req.get_data(k).ok().and_then(|v| v.as_str().map(|s| s.trim().to_string()));
        audit.resource = named("resource").unwrap_or_default();
        audit.profile_id = named("profile_id").unwrap_or_default();
        let (resource, profile_id, meta) = self.connect_target_record(req).await?;
        audit.resource = resource.clone();
        audit.profile_id = profile_id.clone();
        let meta = meta.ok_or_else(|| {
            refusal(404, reason::INVALID_REQUEST, format!("resource `{resource}` not found"))
        })?;
        let profile = find_profile(&meta, &profile_id).ok_or_else(|| {
            refusal(404, reason::INVALID_REQUEST, format!("profile `{profile_id}` not found on resource `{resource}`"))
        })?;
        let provider = stored_provider(&profile)?;
        audit.provider = provider.clone();
        let protocol = profile_protocol(&profile)?;
        audit.protocol = protocol.into();
        // A brokered resource's SSH logins are minted by the SSH engine: no
        // provider account is offered for them (the release refuses too).
        require_not_brokered_for(self.core.as_ref(), &resource, &meta, protocol).await?;

        let (resource_desc, target) = self.provider_query_parts(&profile, &meta, protocol)?;
        let launch = self.provider_launch(req, &provider, protocol, resource_desc, target).await?;
        let query =
            ProviderQuery { protocol: protocol.into(), resource: launch.resource.clone(), target: launch.target.clone() };
        let candidates = launch.host.provider_candidates(&provider, &launch.caller, &query).await?;
        let display_name = launch
            .host
            .credential_providers()
            .await
            .into_iter()
            .find(|d| d.plugin == provider)
            .map(|d| d.display_name)
            .unwrap_or_else(|| provider.clone());

        let n = candidates.len();
        let mut data = Map::new();
        data.insert("resource".into(), Value::String(resource));
        data.insert("profile_id".into(), Value::String(profile_id));
        data.insert("provider".into(), Value::String(provider));
        data.insert("display_name".into(), Value::String(display_name));
        data.insert("protocol".into(), Value::String(protocol.into()));
        data.insert("resource_type".into(), Value::String(query.resource.resource_type.clone()));
        data.insert("os_type".into(), query.resource.os_type.clone().map(Value::String).unwrap_or(Value::Null));
        data.insert("target".into(), serde_json::to_value(&query.target).map_err(RvError::from)?);
        data.insert("candidates".into(), serde_json::to_value(&candidates).map_err(RvError::from)?);
        Ok((data, n))
    }

    // ── authorize ──────────────────────────────────────────────────

    /// The `provider` arm of `POST resources/v2/connect/authorize` (direct SSH /
    /// RDP). Called by `handle_connect_authorize` once it has checked the
    /// connect grant and found the profile.
    ///
    /// Order: every check that can fail without the provider (account id,
    /// entity, grant, protocol, target, transport policy, the SSH login
    /// class) runs **before** the
    /// MFA ticket is redeemed, so a fixable refusal costs no ticket. Then the
    /// ticket is redeemed (burnt whatever happens next), then the provider
    /// releases. A failed release leaves nothing behind: the response carries
    /// a credential only when the release succeeded.
    pub(crate) async fn authorize_provider(
        &self,
        req: &mut Request,
        target: AuthorizeTarget<'_>,
    ) -> Result<Option<Response>, RvError> {
        let mut audit = ProviderAudit::new("release", "direct", req);
        audit.resource = target.resource.clone();
        audit.profile_id = target.profile_id.clone();
        audit.provider = target.provider.clone();
        audit.account_id = target.account_id.clone().unwrap_or_default();
        match self.authorize_provider_inner(req, target, &mut audit).await {
            Ok((data, login)) => {
                audit.released(&login);
                Ok(Some(Response::data_response(Some(data))))
            }
            Err(d) => {
                audit.denied(d.reason);
                Err(d.err)
            }
        }
    }

    async fn authorize_provider_inner(
        &self,
        req: &mut Request,
        target: AuthorizeTarget<'_>,
        audit: &mut ProviderAudit,
    ) -> Result<(Map<String, Value>, String), Denied> {
        let AuthorizeTarget { resource, profile_id, profile, meta, provider, account_id } = target;
        let protocol = profile_protocol(profile)?;
        audit.protocol = protocol.into();
        if protocol == "web" {
            return Err(refusal(
                400,
                reason::INVALID_PROFILE,
                "a web profile's provider credential is released by `resources/v2/connect/web/launch`, not by \
                 `connect/authorize`",
            )
            .into());
        }
        let account_id = account_id.ok_or_else(|| {
            refusal(
                400,
                reason::INVALID_REQUEST,
                "`provider_account_id` is required for a provider profile: the account the operator picked from \
                 `resources/v2/connect/provider/candidates`",
            )
        })?;

        let (resource_desc, target) = self.provider_query_parts(profile, meta, protocol)?;
        let launch = self.provider_launch(req, &provider, protocol, resource_desc, target).await?;

        // A provider credential reaches this machine only when the resource's
        // transport policy allows a direct session. Under `rustion-required`
        // (or a lock violation) it is released only through
        // `rustion/v2/session/open`, which seals it for the bastion.
        if let Err(r) = self.effective_transport(req, &resource, meta).await {
            let err = if r.code == "transport_policy" {
                refusal(
                    403,
                    reason::TRANSPORT_POLICY,
                    "this resource's Rustion transport policy does not allow a direct session (rustion-required, or \
                     a policy lock violation; see `rustion/policy/effective`). A provider credential for it is \
                     released only through `rustion/v2/session/open`, never to this machine",
                )
            } else {
                refusal(r.status, reason::TRANSPORT_POLICY, r.message)
            };
            return Err(Denied::new(reason::TRANSPORT_POLICY, err));
        }

        // A provider account is a static credential: it never logs in over SSH
        // to a brokered resource, whose every SSH login the SSH engine mints.
        // Refused before the ticket is redeemed.
        require_not_brokered_for(self.core.as_ref(), &resource, meta, protocol).await?;

        // Connect-time MFA. `mfa_verified` is attested to the provider only
        // when a ticket was redeemed for this call.
        let gated = profile_gate_flag(profile);
        let method = if gated {
            let record = self
                .redeem_connect_ticket(req, &resource, &profile_id)
                .await
                .map_err(|e| Denied::new(reason::MFA_REQUIRED, e))?;
            Some(record.method)
        } else {
            None
        };

        let cred = self
            .release_provider(&launch, &account_id, ProviderNeeds { password: true, totp: false }, gated, "direct")
            .await?;
        let login = cred.username.clone();

        let mut data = Map::new();
        data.insert("resource".into(), Value::String(resource));
        data.insert("profile_id".into(), Value::String(profile_id));
        data.insert("authorized".into(), Value::Bool(true));
        data.insert("mfa_required".into(), Value::Bool(gated));
        if let Some(m) = method {
            data.insert("method".into(), Value::String(m));
        }
        data.insert("credential_source".into(), Value::String("provider".into()));
        data.insert("provider".into(), Value::String(provider));
        data.insert("provider_account_id".into(), Value::String(account_id));
        // The one target the credential was released for. The host dials this
        // and nothing else: no fallback to another host candidate.
        data.insert("target".into(), serde_json::to_value(&launch.target).map_err(RvError::from)?);
        data.insert("credential".into(), Value::Object(credential_object(&cred)));
        Ok((data, login))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use zeroize::Zeroizing;

    fn released(secret: ReleasedSecret) -> ReleasedCredential {
        ReleasedCredential { username: "felipe.adm".into(), domain: Some("CORP".into()), secret }
    }

    #[test]
    fn the_credential_object_carries_the_secret_and_never_a_totp_seed() {
        let c = released(ReleasedSecret::Password {
            password: Zeroizing::new("hunter2-S3CRET".into()),
            totp_seed: Some(Zeroizing::new("GEZDGNBV".into())),
        });
        let o = Value::Object(credential_object(&c));
        assert_eq!(o["username"], "felipe.adm");
        assert_eq!(o["domain"], "CORP");
        assert_eq!(o["secret"]["kind"], "password");
        assert_eq!(o["secret"]["password"], "hunter2-S3CRET");
        assert!(!o.to_string().contains("GEZDGNBV"), "a TOTP seed never reaches the response");

        let k = released(ReleasedSecret::SshKey { private_key: Zeroizing::new("-----BEGIN OPENSSH".into()) });
        let o = Value::Object(credential_object(&k));
        assert_eq!(o["secret"]["kind"], "ssh-key");
        assert_eq!(o["secret"]["private_key"], "-----BEGIN OPENSSH");
        assert!(o["secret"].get("password").is_none());
    }

    #[test]
    fn the_provider_listing_carries_names_and_declarations_only_sorted_by_name() {
        let decl = |plugin: &str, protocols: &[&str]| CredentialProviderDecl {
            plugin: plugin.into(),
            display_name: format!("{plugin} display"),
            protocols: protocols.iter().map(|s| s.to_string()).collect(),
            secret_kinds: vec!["password".into()],
        };
        let data =
            Value::Object(providers_listing(vec![decl("zeta", &["web"]), decl("self-accounts", &["ssh", "rdp"])]));
        assert_eq!(
            data,
            json!({ "providers": [
                { "name": "self-accounts", "display_name": "self-accounts display",
                  "protocols": ["ssh", "rdp"], "secret_kinds": ["password"] },
                { "name": "zeta", "display_name": "zeta display", "protocols": ["web"], "secret_kinds": ["password"] },
            ] })
        );
        assert_eq!(Value::Object(providers_listing(Vec::new())), json!({ "providers": [] }));
    }

    #[test]
    fn denied_reasons_come_from_the_prefix_or_the_status() {
        assert_eq!(Denied::from(refusal(404, reason::NO_MATCH, "x")).reason, reason::NO_MATCH);
        assert_eq!(Denied::from(RvError::ErrPermissionDenied).reason, reason::CONNECT_DENIED);
        assert_eq!(
            Denied::from(RvError::ErrResponseStatus(400, "`resource` is required".into())).reason,
            reason::INVALID_REQUEST
        );
        assert_eq!(Denied::from(RvError::ErrRequestInvalid).reason, reason::ERROR);
    }

    #[test]
    fn a_profile_must_name_a_provider_and_a_known_protocol() {
        assert!(stored_provider(&json!({ "credential_source": { "kind": "secret", "secret_id": "x" } })).is_err());
        assert!(stored_provider(&json!({ "credential_source": { "kind": "provider" } })).is_err());
        assert_eq!(
            stored_provider(&json!({ "credential_source": { "kind": "provider", "provider": "self-accounts" } }))
                .unwrap(),
            "self-accounts"
        );
        assert_eq!(profile_protocol(&json!({ "protocol": "rdp" })).unwrap(), "rdp");
        for bad in [json!({}), json!({ "protocol": "telnet" }), json!({ "protocol": ["ssh"] })] {
            assert!(profile_protocol(&bad).is_err(), "{bad}");
        }
    }
}
