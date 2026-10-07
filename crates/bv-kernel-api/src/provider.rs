//! Credential providers: plugins a connection profile can name as its
//! credential source.
//!
//! Spec: [features/self-accounts.md](../../../features/self-accounts.md) §4.
//! Nothing here mentions any particular provider. The Connect paths in the
//! resource and Rustion engines ask [`PluginHost`](super::engines::PluginHost)
//! for the candidate list and for the credential of the one picked; the plugin
//! runtime turns those into the `provider.candidates` / `provider.release`
//! envelope ops, which only this bridge can produce.
//!
//! The types are narrowed the way [`PluginChannel`](super::engines::PluginChannel)
//! is: an engine sees what it needs to render and route, not the manifest.

use bv_errors::RvError;
use bv_logical::Request;

use super::engines::LoginClassVerdict;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Longest value the host accepts from a provider for any single text field
/// other than a secret (`username`, `domain`, labels).
pub const MAX_TEXT_LEN: usize = 256;
/// Longest password the host accepts from a provider.
pub const MAX_PASSWORD_LEN: usize = 1024;
/// Longest private key the host accepts from a provider.
pub const MAX_PRIVATE_KEY_LEN: usize = 16 * 1024;

/// The request's caller, attested by the host from the token. Never carries
/// the token, its accessor or its policies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerIdentity {
    pub entity_id: String,
    pub display_name: String,
    /// Auth mount the principal logged in through, e.g. `userpass/`.
    pub principal_mount: String,
    pub principal_name: String,
    pub namespace: String,
}

impl CallerIdentity {
    /// Build the caller from the request's authenticated token (spec §4.2).
    /// Nothing in the request body is consulted, and the token, its accessor
    /// and its policies are never copied.
    ///
    /// The one rule for "who is asking": the plugin runtime uses it for the
    /// envelope's `caller` block and the Connect engines for provider calls,
    /// so the two cannot disagree about whose records a release touches.
    pub fn from_request(req: &Request) -> Self {
        let Some(auth) = req.auth.as_ref() else {
            return Self::default();
        };
        let meta = |k: &str| auth.metadata.get(k).cloned().unwrap_or_default();
        let principal_name = {
            let u = meta("username");
            if u.is_empty() {
                meta("role_name")
            } else {
                u
            }
        };
        Self {
            entity_id: meta("entity_id"),
            display_name: auth.display_name.clone(),
            principal_mount: meta("mount_path"),
            principal_name,
            namespace: req.namespace_path.clone().unwrap_or_default(),
        }
    }

    /// `<mount><name>` (`userpass/felipe`), as audit lines show the principal.
    pub fn principal(&self) -> String {
        format!("{}{}", self.principal_mount, self.principal_name)
    }
}

// ── refusal reasons ─────────────────────────────────────────────────────

/// Stable reason codes for a refused provider call (spec §9).
///
/// Every refusal the host bridge or a Connect engine produces on a provider
/// path is an `ErrResponseStatus` whose message starts with `<reason>: `. The
/// audit line's `reason`, the metric's `outcome` and the operator-facing
/// error therefore name the same thing, and a client can match on the prefix
/// the way it already does for `mfa_required:`.
pub mod reason {
    /// The caller's token has no identity entity.
    pub const NO_ENTITY: &str = "no_entity";
    /// The provider is not registered, not active, quarantined, or its grant
    /// is missing or stale.
    pub const NOT_GRANTED: &str = "not_granted";
    /// The provider does not declare the profile's protocol.
    pub const UNSUPPORTED_PROTOCOL: &str = "unsupported_protocol";
    /// No account of the caller matches this resource, protocol and target
    /// (also a forged or stale account id).
    pub const NO_MATCH: &str = "no_match";
    /// Connect-time MFA is required and was not proved for this launch.
    pub const MFA_REQUIRED: &str = "mfa_required";
    /// The provider refused the request as malformed or unsatisfiable.
    pub const BAD_REQUEST: &str = "bad_request";
    /// The provider's output failed the host's shape check.
    pub const BAD_PROVIDER_OUTPUT: &str = "bad_provider_output";
    /// The provider failed internally, or the invocation itself failed.
    pub const PROVIDER_ERROR: &str = "provider_error";
    /// The stored profile cannot be read as a provider launch.
    pub const INVALID_PROFILE: &str = "invalid_profile";
    /// The request body is missing or malformed.
    pub const INVALID_REQUEST: &str = "invalid_request";
    /// The caller has no `connect` grant on the resource.
    pub const CONNECT_DENIED: &str = "connect_denied";
    /// The resource's transport policy forbids releasing to this route.
    pub const TRANSPORT_POLICY: &str = "transport_policy";
    /// The resource's SSH login class is `brokered`: every SSH login to it is
    /// minted per connect by the SSH engine, so no provider account is
    /// released for SSH. The same code the desktop host has always used for
    /// this rule on the direct path.
    pub const BROKERED_REQUIRES_SSH_ENGINE: &str = "brokered_requires_ssh_engine";
    /// Anything else.
    pub const ERROR: &str = "error";

    pub(super) const PREFIXED: [&str; 13] = [
        NO_ENTITY,
        NOT_GRANTED,
        UNSUPPORTED_PROTOCOL,
        NO_MATCH,
        MFA_REQUIRED,
        BAD_REQUEST,
        BAD_PROVIDER_OUTPUT,
        PROVIDER_ERROR,
        INVALID_PROFILE,
        INVALID_REQUEST,
        CONNECT_DENIED,
        TRANSPORT_POLICY,
        BROKERED_REQUIRES_SSH_ENGINE,
    ];
}

/// A provider-path refusal: `status`, and a message prefixed with `reason`.
pub fn refusal(status: u16, reason: &'static str, message: impl std::fmt::Display) -> RvError {
    RvError::ErrResponseStatus(status, format!("{reason}: {message}"))
}

/// The reason code of a provider-path error, read back from its prefix. A
/// missing connect grant (`ErrPermissionDenied`) is `connect_denied`; any
/// error that carries no known prefix is `error`.
pub fn refusal_reason(e: &RvError) -> &'static str {
    match e {
        RvError::ErrResponseStatus(_, m) => reason::PREFIXED
            .iter()
            .find(|r| m.strip_prefix(**r).is_some_and(|rest| rest.starts_with(':')))
            .copied()
            .unwrap_or(reason::ERROR),
        RvError::ErrPermissionDenied => reason::CONNECT_DENIED,
        _ => reason::ERROR,
    }
}

// ── the SSH login class ─────────────────────────────────────────────────

/// A provider account is a static credential, so it may not log in over SSH
/// to a resource whose login class is `brokered` (every SSH login to such a
/// resource is minted per connect by the SSH engine). Every Connect route
/// that lists or releases provider accounts applies this one rule, before
/// any MFA ticket is redeemed. RDP and web are not governed by the SSH login
/// class and pass.
pub fn require_not_brokered(protocol: &str, verdict: &LoginClassVerdict) -> Result<(), RvError> {
    if protocol == "ssh" && verdict.brokered {
        return Err(refusal(
            403,
            reason::BROKERED_REQUIRES_SSH_ENGINE,
            format!(
                "this resource is brokered (login class via tier `{}`): every SSH login to it is minted per \
                 connect by the SSH engine, so a credential provider's account is never released for SSH. Use \
                 an `ssh-engine` or `default-account` connection profile",
                verdict.source
            ),
        ));
    }
    Ok(())
}

/// [`require_not_brokered`] for one resource, its login class resolved from
/// the stored record (`type`) and its asset groups, exactly as the resource
/// engine's attach-time guard resolves it. Only SSH is resolved. Fails closed:
/// an error resolving the class or the groups refuses rather than releases.
/// A server without the ssh-broker module has no brokered resources.
#[maybe_async::maybe_async]
pub async fn require_not_brokered_for(
    ctx: &dyn super::ctx::VaultCtx,
    resource: &str,
    meta: &Map<String, Value>,
    protocol: &str,
) -> Result<(), RvError> {
    if protocol != "ssh" {
        return Ok(());
    }
    let Some(policy) = ctx.login_class() else {
        return Ok(());
    };
    let resource_type = meta.get("type").and_then(Value::as_str).unwrap_or_default();
    let groups = match ctx.resource_groups() {
        Some(index) => index.groups_for_resource(resource).await?,
        None => Vec::new(),
    };
    let verdict = policy.resolve_for(resource_type, &groups, resource).await?;
    require_not_brokered(protocol, &verdict)
}

// ── what a provider is told, from stored metadata ───────────────────────

/// The desktop host's default port for a protocol (`profile_port` in the
/// Tauri host): `ssh` 22, `rdp` 3389.
pub fn default_port(protocol: &str) -> Option<u16> {
    match protocol {
        "ssh" => Some(22),
        "rdp" => Some(3389),
        _ => None,
    }
}

/// A string field of stored metadata: absent, `null` or empty is `None`; any
/// other non-string is an error rather than a silent skip.
fn opt_text<'a>(obj: Option<&'a Map<String, Value>>, key: &str, what: &str) -> Result<Option<&'a str>, String> {
    match obj.and_then(|o| o.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim())),
        Some(_) => Err(format!("{what} `{key}` must be a string")),
    }
}

/// A host field as the desktop host reads it: absent, `null` or `""` is "not
/// set" and the next candidate applies; anything else is taken verbatim, so
/// surrounding whitespace is refused by [`dial_host`] rather than trimmed into
/// a host the desktop would not dial.
fn opt_host<'a>(obj: Option<&'a Map<String, Value>>, key: &str, what: &str) -> Result<Option<&'a str>, String> {
    match obj.and_then(|o| o.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(format!("{what} `{key}` must be a string")),
    }
}

/// The resource descriptor a provider matches on (§4.4): the stored `type`
/// and `os_type`, never the name. `os_type` is lower-cased so that a record
/// saved as `Windows` matches an account tagged `windows`.
pub fn provider_resource(meta: &Map<String, Value>) -> Result<ProviderResource, String> {
    let resource_type = opt_text(Some(meta), "type", "resource")?
        .ok_or_else(|| "the resource has no `type`, so no account can be matched to it".to_string())?
        .to_string();
    let os_type = opt_text(Some(meta), "os_type", "resource")?.map(|s| s.to_ascii_lowercase());
    Ok(ProviderResource { resource_type, os_type })
}

/// The SSH / RDP dial target (§5), computed from the **stored** profile and
/// resource record only — a request never supplies it.
///
/// The host is the first of the desktop host's candidates
/// (`profile_host_candidates`): the profile's `target_host` override, else the
/// resource's `ip_address`, else its `hostname`. Only that one host is bound:
/// a client that releases a provider credential must dial exactly this target
/// and never fall back to another candidate. The port is the profile's
/// `target_port`, else the protocol default.
///
/// Fails closed on anything it cannot read unambiguously: a wrong-typed
/// field, a host with whitespace, a path or userinfo, a port outside
/// 1..=65535.
pub fn host_target(profile: &Value, meta: &Map<String, Value>, protocol: &str) -> Result<ProviderTarget, String> {
    let default = default_port(protocol).ok_or_else(|| format!("protocol `{protocol}` has no host target"))?;
    let p = profile.as_object();
    let host = match opt_host(p, "target_host", "profile")? {
        Some(h) => h,
        None => match opt_host(Some(meta), "ip_address", "resource")? {
            Some(ip) => ip,
            None => opt_host(Some(meta), "hostname", "resource")?.ok_or_else(|| {
                "the resource has no hostname or ip_address and the profile no target_host".to_string()
            })?,
        },
    };
    let host = dial_host(host)?;
    let port = match p.and_then(|o| o.get("target_port")) {
        None | Some(Value::Null) => default,
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n != 0)
            .ok_or_else(|| "profile `target_port` must be an integer in 1..=65535".to_string())?,
        Some(_) => return Err("profile `target_port` must be an integer in 1..=65535".into()),
    };
    Ok(ProviderTarget::Host { host, port })
}

/// One dial host, normalised the way `connect_web::recipe::origin_key`
/// normalises an origin's host, so the value a provider matches is exactly
/// one spelling of exactly one host: ASCII only (punycode for IDNs),
/// lower-cased, no trailing dot (a different name to a resolver's search
/// list), no wildcard, percent-encoding, brackets, userinfo, path or
/// whitespace, and a `:` only when the whole value is an IPv6 address (so
/// never a `host:port`). The IPv6 spelling is kept as written, lower-cased,
/// because the client that dials compares it with its own copy.
fn dial_host(raw: &str) -> Result<String, String> {
    let bad = |why: &str| Err(format!("the dial target {why}"));
    if raw.len() > 253 {
        return bad("is longer than 253 characters");
    }
    if !raw.is_ascii() {
        return bad("has a non-ASCII host; write it in its punycode (`xn--…`) form");
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control())
        || raw.contains(['*', '%', '[', ']', '@', '/', '\\', '?', '#'])
    {
        return bad("must be a literal host name or address (no wildcard, brackets, percent-encoding or path)");
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains(':') {
        return match lower.parse::<std::net::Ipv6Addr>() {
            Ok(_) => Ok(lower),
            Err(_) => bad("may contain `:` only as an IPv6 address; the port is `target_port`"),
        };
    }
    if lower.ends_with('.') {
        return bad("has a trailing dot");
    }
    if !lower.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return bad("has characters outside [a-z0-9._-]");
    }
    Ok(lower)
}

/// The provider a stored profile names, when its `credential_source.kind` is
/// `provider`. `Ok(None)` for every other kind. Strict: a `provider` source
/// whose `provider` is missing, not a string, empty, over-long or carries
/// control characters is an error, never "no provider".
pub fn profile_provider(profile: &Value) -> Result<Option<String>, String> {
    let Some(cs) = profile.get("credential_source") else {
        return Ok(None);
    };
    let Some(cs) = cs.as_object() else {
        return Ok(None);
    };
    if cs.get("kind").and_then(Value::as_str) != Some("provider") {
        return Ok(None);
    }
    provider_name(cs).map(Some)
}

/// `credential_source.provider` of a source whose kind is `provider`, read
/// strictly. Shared by [`profile_provider`] and the web profile parser.
pub fn provider_name(credential_source: &Map<String, Value>) -> Result<String, String> {
    match credential_source.get("provider") {
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control) => Ok(s.clone()),
        _ => Err("credential_source.provider must name a credential provider".into()),
    }
}

/// One server audit line for a provider call (spec §9):
/// `connect.provider.release` per release attempt, `connect.provider.candidates`
/// per candidate listing. Every field is a name, an id or an enum value;
/// there is no field a secret could be put in. Operator-controlled values are
/// `{:?}`-quoted so none can forge a field or break the line.
pub struct ProviderAuditLine<'a> {
    /// `release` or `candidates`.
    pub op: &'a str,
    /// `success` or `denied`.
    pub outcome: &'a str,
    /// A [`reason`] code; `-` on success.
    pub reason: &'a str,
    pub principal: &'a str,
    pub entity_id: &'a str,
    pub resource: &'a str,
    pub profile_id: &'a str,
    pub protocol: &'a str,
    /// `direct`, `rustion`, `web`, or `-` for a candidate listing.
    pub transport: &'a str,
    pub provider: &'a str,
    pub account_id: &'a str,
    /// The released login name, on a successful release only.
    pub login_name: &'a str,
    /// Number of candidates returned, on a successful listing only.
    pub candidates: Option<usize>,
}

/// What one `connect.provider.*` audit line says, filled in as a Connect
/// handler learns it, and written with `target: "audit"`. Shared by the
/// resource and Rustion engines so the two write the same line.
pub struct ProviderAudit {
    op: &'static str,
    transport: &'static str,
    principal: String,
    entity_id: String,
    pub resource: String,
    pub profile_id: String,
    pub protocol: String,
    pub provider: String,
    pub account_id: String,
}

impl ProviderAudit {
    /// `op` is `release` or `candidates`; `transport` is `direct`,
    /// `rustion`, `web`, or `-`. The principal and entity are attested from
    /// the request's token.
    pub fn new(op: &'static str, transport: &'static str, req: &Request) -> Self {
        let caller = CallerIdentity::from_request(req);
        Self {
            op,
            transport,
            principal: caller.principal(),
            entity_id: caller.entity_id,
            resource: String::new(),
            profile_id: String::new(),
            protocol: String::new(),
            provider: String::new(),
            account_id: String::new(),
        }
    }

    fn line(&self, outcome: &str, reason: &str, login_name: &str, candidates: Option<usize>) -> String {
        ProviderAuditLine {
            op: self.op,
            outcome,
            reason,
            principal: &self.principal,
            entity_id: &self.entity_id,
            resource: &self.resource,
            profile_id: &self.profile_id,
            protocol: &self.protocol,
            transport: self.transport,
            provider: &self.provider,
            account_id: &self.account_id,
            login_name,
            candidates,
        }
        .render()
    }

    /// A refusal, with a [`reason`] code.
    pub fn denied(&self, reason: &str) {
        log::info!(target: "audit", "{}", self.line("denied", reason, "", None));
    }

    /// A successful release of `login_name` (not a secret: target-side
    /// attribution is the point of naming it).
    pub fn released(&self, login_name: &str) {
        log::info!(target: "audit", "{}", self.line("success", "-", login_name, None));
    }

    /// A successful candidate listing of `n` accounts.
    pub fn listed(&self, n: usize) {
        log::info!(target: "audit", "{}", self.line("success", "-", "", Some(n)));
    }
}

impl ProviderAuditLine<'_> {
    pub fn render(&self) -> String {
        let mut line = format!(
            "connect.provider.{} outcome={} reason={} principal={:?} entity_id={:?} resource={:?} profile_id={:?} \
             protocol={:?} transport={} provider={:?} account_id={:?} login_name={:?}",
            self.op,
            self.outcome,
            self.reason,
            self.principal,
            self.entity_id,
            self.resource,
            self.profile_id,
            self.protocol,
            self.transport,
            self.provider,
            self.account_id,
            self.login_name,
        );
        if let Some(n) = self.candidates {
            line.push_str(&format!(" candidates={n}"));
        }
        line
    }
}

/// A granted, active credential provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialProviderDecl {
    pub plugin: String,
    pub display_name: String,
    pub protocols: Vec<String>,
    pub secret_kinds: Vec<String>,
}

/// What kind of resource the connection is for. The resource *name* is
/// deliberately absent (data minimisation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
}

/// The target being dialled, computed by the host from stored metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderTarget {
    /// SSH / RDP.
    Host { host: String, port: u16 },
    /// Web `form`: every origin the recipe may fill (start URL plus
    /// `allowed_origins`).
    Origins { origins: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderQuery {
    /// `ssh`, `rdp` or `web`.
    pub protocol: String,
    pub resource: ProviderResource,
    pub target: ProviderTarget,
}

/// One account the operator may pick. Metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCandidate {
    pub id: String,
    pub label: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub secret_kind: String,
    #[serde(default)]
    pub has_totp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// The provider has no record of releasing this account for this target
    /// (spec §5, Phase 5). A hint for the picker, never a protection: the
    /// target binding is. `false` when a provider does not report it.
    #[serde(default)]
    pub first_use_on_target: bool,
    /// When this account was last released for this same target, so the
    /// picker can preselect it. A time, never the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_on_target: Option<String>,
}

/// What the connect recipe will fill. A provider returns only what is asked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderNeeds {
    pub password: bool,
    pub totp: bool,
}

/// Facts about this launch the host attests to the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConnectContext {
    /// A connect-time MFA ticket was redeemed for this launch.
    pub mfa_verified: bool,
    /// `direct`, `rustion` or `web`.
    pub transport: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReleaseRequest {
    pub account_id: String,
    pub protocol: String,
    pub resource: ProviderResource,
    pub target: ProviderTarget,
    pub needs: ProviderNeeds,
    pub connect: ProviderConnectContext,
}

/// The secret half of a released credential. Held in `Zeroizing` buffers and
/// without a `Debug` that prints them.
pub enum ReleasedSecret {
    Password {
        password: Zeroizing<String>,
        totp_seed: Option<Zeroizing<String>>,
    },
    SshKey {
        private_key: Zeroizing<String>,
    },
}

impl ReleasedSecret {
    /// `password` or `ssh-key`, the manifest's `secret_kinds` vocabulary.
    pub fn kind(&self) -> &'static str {
        match self {
            ReleasedSecret::Password { .. } => "password",
            ReleasedSecret::SshKey { .. } => "ssh-key",
        }
    }
}

impl std::fmt::Debug for ReleasedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReleasedSecret::{}(<redacted>)", self.kind())
    }
}

/// A credential released by a provider, already validated by the host.
#[derive(Debug)]
pub struct ReleasedCredential {
    pub username: String,
    pub domain: Option<String>,
    pub secret: ReleasedSecret,
}

/// Why the host refused what a provider returned. The text is operator-facing
/// and never contains secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderOutputError(pub String);

impl std::fmt::Display for ProviderOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl ReleasedCredential {
    /// The shape check the host runs on whatever a provider returned
    /// (spec §4.4): the secret kind is one the provider declared and is
    /// compatible with the protocol, the username is non-empty, and every
    /// field is within the size limits. Fails closed.
    pub fn validate(
        &self,
        protocol: &str,
        declared_kinds: &[String],
    ) -> Result<(), ProviderOutputError> {
        let bad = |m: &str| Err(ProviderOutputError(m.to_string()));
        let kind = self.secret.kind();
        if !declared_kinds.iter().any(|k| k == kind) {
            return bad("provider returned a secret kind it did not declare");
        }
        // password: ssh | rdp | web.  ssh-key: ssh only.
        let compatible = match (kind, protocol) {
            ("password", "ssh" | "rdp" | "web") => true,
            ("ssh-key", "ssh") => true,
            _ => false,
        };
        if !compatible {
            return bad("provider returned a secret kind that is incompatible with the protocol");
        }
        if self.username.trim().is_empty() {
            return bad("provider returned an empty username");
        }
        if self.username.len() > MAX_TEXT_LEN
            || self.domain.as_ref().is_some_and(|d| d.len() > MAX_TEXT_LEN)
        {
            return bad("provider returned an oversize username or domain");
        }
        match &self.secret {
            ReleasedSecret::Password { password, totp_seed } => {
                if password.is_empty() {
                    return bad("provider returned an empty password");
                }
                if password.len() > MAX_PASSWORD_LEN
                    || totp_seed.as_ref().is_some_and(|t| t.len() > MAX_PASSWORD_LEN)
                {
                    return bad("provider returned an oversize secret");
                }
            }
            ReleasedSecret::SshKey { private_key } => {
                if private_key.is_empty() {
                    return bad("provider returned an empty private key");
                }
                if private_key.len() > MAX_PRIVATE_KEY_LEN {
                    return bad("provider returned an oversize secret");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(user: &str, password: &str) -> ReleasedCredential {
        ReleasedCredential {
            username: user.into(),
            domain: None,
            secret: ReleasedSecret::Password {
                password: Zeroizing::new(password.into()),
                totp_seed: None,
            },
        }
    }

    fn kinds() -> Vec<String> {
        vec!["password".into(), "ssh-key".into()]
    }

    #[test]
    fn accepts_a_well_formed_password() {
        assert!(pw("felipe", "hunter2").validate("rdp", &kinds()).is_ok());
    }

    #[test]
    fn refuses_undeclared_kind() {
        let only_key = vec!["ssh-key".to_string()];
        assert!(pw("felipe", "x").validate("ssh", &only_key).is_err());
    }

    #[test]
    fn refuses_key_over_rdp_and_web() {
        let c = ReleasedCredential {
            username: "u".into(),
            domain: None,
            secret: ReleasedSecret::SshKey { private_key: Zeroizing::new("k".into()) },
        };
        assert!(c.validate("ssh", &kinds()).is_ok());
        assert!(c.validate("rdp", &kinds()).is_err());
        assert!(c.validate("web", &kinds()).is_err());
    }

    #[test]
    fn refuses_empty_and_oversize_fields() {
        assert!(pw("", "x").validate("ssh", &kinds()).is_err());
        assert!(pw("  ", "x").validate("ssh", &kinds()).is_err());
        assert!(pw("u", "").validate("ssh", &kinds()).is_err());
        assert!(pw(&"u".repeat(MAX_TEXT_LEN + 1), "x").validate("ssh", &kinds()).is_err());
        assert!(pw("u", &"p".repeat(MAX_PASSWORD_LEN + 1)).validate("ssh", &kinds()).is_err());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let c = pw("felipe", "s3cret-value");
        assert!(!format!("{c:?}").contains("s3cret-value"));
    }

    // ── caller, reasons, targets ─────────────────────────────────────

    #[test]
    fn caller_comes_from_the_token_never_the_body() {
        let mut req = Request::default();
        let mut body = Map::new();
        body.insert("entity_id".into(), Value::String("attacker".into()));
        req.body = Some(body);
        assert_eq!(CallerIdentity::from_request(&req), CallerIdentity::default());

        let mut auth = bv_logical::Auth::default();
        auth.metadata.insert("entity_id".into(), "ent-1".into());
        auth.metadata.insert("mount_path".into(), "userpass/".into());
        auth.metadata.insert("username".into(), "felipe".into());
        req.auth = Some(auth);
        req.namespace_path = Some("tenant-a".into());
        let c = CallerIdentity::from_request(&req);
        assert_eq!(c.entity_id, "ent-1");
        assert_eq!(c.principal(), "userpass/felipe");
        assert_eq!(c.namespace, "tenant-a");

        // An AppRole token names its role.
        let mut auth = bv_logical::Auth::default();
        auth.metadata.insert("role_name".into(), "ci".into());
        auth.metadata.insert("mount_path".into(), "approle/".into());
        req.auth = Some(auth);
        assert_eq!(CallerIdentity::from_request(&req).principal(), "approle/ci");
    }

    #[test]
    fn a_brokered_resource_refuses_provider_accounts_for_ssh_only() {
        let brokered = LoginClassVerdict { brokered: true, source: "type".into() };
        let e = require_not_brokered("ssh", &brokered).unwrap_err();
        assert_eq!(refusal_reason(&e), reason::BROKERED_REQUIRES_SSH_ENGINE);
        assert!(matches!(&e, RvError::ErrResponseStatus(403, m) if m.contains("tier `type`")), "{e}");
        // RDP and web are not governed by the SSH login class.
        for protocol in ["rdp", "web"] {
            assert!(require_not_brokered(protocol, &brokered).is_ok(), "{protocol}");
        }
        // A shared-credential resource takes provider accounts on every protocol.
        for protocol in ["ssh", "rdp", "web"] {
            assert!(require_not_brokered(protocol, &LoginClassVerdict::default()).is_ok(), "{protocol}");
        }
    }

    #[test]
    fn reasons_round_trip_through_the_message_prefix() {
        for r in reason::PREFIXED {
            assert_eq!(refusal_reason(&refusal(400, r, "x")), r);
        }
        // A prefix must be a whole word followed by `:`.
        assert_eq!(refusal_reason(&RvError::ErrResponseStatus(404, "no_matching: x".into())), reason::ERROR);
        assert_eq!(refusal_reason(&RvError::ErrResponseStatus(404, "plain text".into())), reason::ERROR);
        assert_eq!(refusal_reason(&RvError::ErrPermissionDenied), reason::CONNECT_DENIED);
        assert_eq!(refusal_reason(&RvError::ErrRequestInvalid), reason::ERROR);
    }

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn the_host_target_follows_the_desktop_hosts_order() {
        let meta = obj(serde_json::json!({ "type": "server", "hostname": "dc01.corp", "ip_address": "10.0.0.5" }));
        let t = |p: Value, proto: &str| host_target(&p, &meta, proto);
        // target_host override, else ip_address, else hostname.
        assert_eq!(
            t(serde_json::json!({ "target_host": "jump.corp", "target_port": 2222 }), "ssh").unwrap(),
            ProviderTarget::Host { host: "jump.corp".into(), port: 2222 }
        );
        assert_eq!(t(serde_json::json!({}), "rdp").unwrap(), ProviderTarget::Host { host: "10.0.0.5".into(), port: 3389 });
        assert_eq!(
            t(serde_json::json!({ "target_host": "" }), "ssh").unwrap(),
            ProviderTarget::Host { host: "10.0.0.5".into(), port: 22 }
        );
        let only_name = obj(serde_json::json!({ "type": "server", "hostname": "dc01.corp" }));
        assert_eq!(
            host_target(&serde_json::json!({}), &only_name, "ssh").unwrap(),
            ProviderTarget::Host { host: "dc01.corp".into(), port: 22 }
        );
        // One spelling per host: lower-cased; an IPv6 address is accepted
        // bare (its `:` is not a port).
        assert_eq!(
            t(serde_json::json!({ "target_host": "DC01.Corp.Example.COM" }), "ssh").unwrap(),
            ProviderTarget::Host { host: "dc01.corp.example.com".into(), port: 22 }
        );
        assert_eq!(
            t(serde_json::json!({ "target_host": "FD00::1" }), "rdp").unwrap(),
            ProviderTarget::Host { host: "fd00::1".into(), port: 3389 }
        );
        assert_eq!(
            t(serde_json::json!({ "target_host": "xn--bcher-kva.example" }), "ssh").unwrap(),
            ProviderTarget::Host { host: "xn--bcher-kva.example".into(), port: 22 }
        );
    }

    #[test]
    fn the_host_target_fails_closed() {
        let meta = obj(serde_json::json!({ "type": "server", "hostname": "dc01.corp" }));
        for bad in [
            serde_json::json!({ "target_host": 5 }),
            serde_json::json!({ "target_host": "a b" }),
            serde_json::json!({ "target_host": "evil/x" }),
            serde_json::json!({ "target_host": "user@host" }),
            // origin_key's rules: ASCII only, no trailing dot, no wildcard,
            // percent-encoding or brackets, `:` only as a whole IPv6 address.
            serde_json::json!({ "target_host": "bücher.example" }),
            serde_json::json!({ "target_host": "dc01.corp." }),
            serde_json::json!({ "target_host": "*.corp" }),
            serde_json::json!({ "target_host": "dc*1.corp" }),
            serde_json::json!({ "target_host": "exa%6dple.com" }),
            serde_json::json!({ "target_host": "[::1]" }),
            serde_json::json!({ "target_host": "fd00::1]" }),
            serde_json::json!({ "target_host": "dc01.corp:22" }),
            serde_json::json!({ "target_host": "10.0.0.5:3389" }),
            serde_json::json!({ "target_host": "fd00::zz" }),
            serde_json::json!({ "target_host": "dc01.corp\t" }),
            serde_json::json!({ "target_host": " dc01.corp" }),
            serde_json::json!({ "target_host": " " }),
            serde_json::json!({ "target_host": "dc01!corp" }),
            serde_json::json!({ "target_port": 0 }),
            serde_json::json!({ "target_port": 70000 }),
            serde_json::json!({ "target_port": "22" }),
            serde_json::json!({ "target_port": -1 }),
        ] {
            assert!(host_target(&bad, &meta, "ssh").is_err(), "{bad}");
        }
        assert!(host_target(&serde_json::json!({}), &obj(serde_json::json!({ "type": "server" })), "ssh").is_err());
        assert!(host_target(&serde_json::json!({}), &meta, "web").is_err(), "web has origins, not a host");
        let wrong_type = obj(serde_json::json!({ "type": "server", "hostname": ["x"] }));
        assert!(host_target(&serde_json::json!({}), &wrong_type, "ssh").is_err());
    }

    #[test]
    fn the_resource_descriptor_is_type_and_os_only() {
        let r = provider_resource(&obj(serde_json::json!({
            "name": "dc01", "type": "server", "os_type": "Windows", "hostname": "dc01.corp"
        })))
        .unwrap();
        assert_eq!(r, ProviderResource { resource_type: "server".into(), os_type: Some("windows".into()) });
        assert!(provider_resource(&obj(serde_json::json!({ "name": "x" }))).is_err());
        assert!(provider_resource(&obj(serde_json::json!({ "type": 1 }))).is_err());
        let no_os = provider_resource(&obj(serde_json::json!({ "type": "server", "os_type": "" }))).unwrap();
        assert_eq!(no_os.os_type, None);
    }

    #[test]
    fn a_provider_source_is_read_strictly() {
        let p = |cs: Value| profile_provider(&serde_json::json!({ "credential_source": cs }));
        assert_eq!(p(serde_json::json!({ "kind": "provider", "provider": "self-accounts" })).unwrap().as_deref(), Some("self-accounts"));
        assert_eq!(p(serde_json::json!({ "kind": "secret", "secret_id": "x" })).unwrap(), None);
        assert_eq!(profile_provider(&serde_json::json!({})).unwrap(), None);
        for bad in [
            serde_json::json!({ "kind": "provider" }),
            serde_json::json!({ "kind": "provider", "provider": "" }),
            serde_json::json!({ "kind": "provider", "provider": 7 }),
            serde_json::json!({ "kind": "provider", "provider": ["self-accounts"] }),
            serde_json::json!({ "kind": "provider", "provider": "a\nb" }),
        ] {
            assert!(p(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_audit_line_quotes_operator_values() {
        let line = ProviderAuditLine {
            op: "release",
            outcome: "denied",
            reason: reason::NO_MATCH,
            principal: "userpass/felipe",
            entity_id: "ent-1",
            resource: "dc01 outcome=success\nconnect.provider.release",
            profile_id: "p",
            protocol: "rdp",
            transport: "direct",
            provider: "self-accounts",
            account_id: "sa_1",
            login_name: "",
            candidates: None,
        }
        .render();
        assert!(line.starts_with("connect.provider.release outcome=denied reason=no_match "));
        assert!(!line.contains('\n'));
        assert_eq!(line.matches("outcome=").count(), 2, "the forged field stays inside the quoted value: {line}");
        assert!(line.contains(r#"resource="dc01 outcome=success\nconnect.provider.release""#));
    }

    /// Phase 5 added two candidate fields. A provider that predates them
    /// still parses, and claims neither a first use nor a last use here: the
    /// picker shows no badge rather than a wrong one.
    #[test]
    fn candidates_from_an_older_provider_parse_without_the_target_fields() {
        let old: ProviderCandidate = serde_json::from_value(serde_json::json!({
            "id": "sa_1", "label": "L", "username": "u", "secret_kind": "password"
        }))
        .unwrap();
        assert!(!old.first_use_on_target);
        assert_eq!(old.last_used_on_target, None);

        let new: ProviderCandidate = serde_json::from_value(serde_json::json!({
            "id": "sa_1", "label": "L", "username": "u", "secret_kind": "password",
            "first_use_on_target": true, "last_used_on_target": "2026-10-07T12:00:00Z"
        }))
        .unwrap();
        assert!(new.first_use_on_target);
        let v = serde_json::to_value(&new).unwrap();
        assert_eq!(v["first_use_on_target"], true);
        assert_eq!(v["last_used_on_target"], "2026-10-07T12:00:00Z");
        // An absent time is omitted, not sent as null.
        assert!(serde_json::to_value(&old).unwrap().get("last_used_on_target").is_none());
    }
}
