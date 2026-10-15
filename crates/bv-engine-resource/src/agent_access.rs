//! The resource-side opt-ins for MCP brokered sessions
//! (`features/mcp-brokered-sessions.md` §11-12): `agent_sessions_max` on a
//! resource type and `agent_access` on a connection profile.
//!
//! **Deny unless opted in, at both levels.** An agent session reaches a
//! profile only when the resource's type says `connect.agent_sessions_max =
//! "allow"` in the saved type configuration *and* the profile says
//! `agent_access = "allow"`. Absent means deny at both levels, so every type
//! and profile written before this feature reads as "no agent sessions"; no
//! stored record needs migrating. The type tier exists so a whole class of
//! resources (production databases' hosts, say) can be put out of every
//! agent's reach whatever individual profile owners set, in the manner of
//! `web_exposure_max` (`connect_web/exposure.rs`).
//!
//! Every value is parsed strictly: a value this server does not recognise
//! refuses, rather than reading as either default.
//!
//! Two callers:
//!
//! * **writes** — [`validate_profiles_on_write`] runs on `resources/<name>`
//!   and refuses a profile that turns `agent_access` on without the type's
//!   consent or without the protocol's static requirements (a host-key pin
//!   for SSH, https for web, a server-resolvable credential source).
//!   [`validate_type_config`] refuses a malformed `agent_sessions_max` on
//!   `config/types`;
//! * **calls** — [`check_agent_enabled`] is the session handler's §3 step 5.5
//!   check, which re-reads both tiers and the static requirements at every
//!   call. A profile edited before the type was turned back to `deny` is
//!   refused there, not at write time.

use std::fmt;

use base64::Engine as _;
use serde_json::{Map, Value};

/// Key inside a type's `connect` block.
pub const AGENT_SESSIONS_MAX_KEY: &str = "agent_sessions_max";
/// Key on a connection profile.
pub const AGENT_ACCESS_KEY: &str = "agent_access";

/// One tier's opinion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGate {
    Deny,
    Allow,
}

/// Which setting was malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTier {
    Type,
    Profile,
}

impl AgentTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Type => "resource type's `connect.agent_sessions_max`",
            Self::Profile => "connection profile's `agent_access`",
        }
    }
}

/// Why an agent may not use a profile, or may not be allowed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAccessRefusal {
    /// A tier carries a value outside `"allow" | "deny"`.
    InvalidPolicy { tier: AgentTier },
    /// The type has not opted in. `type_saved` says whether the resource's
    /// type is in the saved type configuration at all.
    TypeNotOptedIn { type_saved: bool },
    /// The profile has not opted in.
    ProfileNotOptedIn,
    /// The profile's protocol has no brokered agent session.
    UnsupportedProtocol { protocol: String },
    /// SSH: a credential source the vault cannot use on an agent's behalf
    /// (§5.2). RDP: likewise.
    CredentialSourceUnsupported { protocol: &'static str, kind: String },
    /// SSH: no `host_key_pin` (§5.2).
    HostKeyUnpinned,
    /// SSH: a `host_key_pin` that is not an OpenSSH `SHA256:<base64>`
    /// fingerprint.
    HostKeyPinMalformed,
    /// Web: a login mode other than `open` or `http-auth` (§6.2).
    WebLoginModeUnsupported { mode: String },
    /// Web: not https, or `allow_insecure_http`.
    WebNotHttps,
}

impl AgentAccessRefusal {
    /// The stable code, used as the error prefix and in the
    /// `connect.agent.refused` audit line.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy { .. } => "agent_policy_invalid",
            Self::TypeNotOptedIn { .. } | Self::ProfileNotOptedIn | Self::UnsupportedProtocol { .. } => {
                "mcp_session_profile_not_agent_enabled"
            }
            Self::CredentialSourceUnsupported { .. } => "mcp_session_login_class_unsupported",
            Self::HostKeyUnpinned | Self::HostKeyPinMalformed => "mcp_session_host_key_unpinned",
            Self::WebLoginModeUnsupported { .. } => "mcp_web_login_mode_unsupported",
            Self::WebNotHttps => "mcp_web_origin_refused",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidPolicy { .. } => 422,
            _ => 403,
        }
    }
}

impl fmt::Display for AgentAccessRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy { tier } => {
                write!(f, "the {} must be \"allow\" or \"deny\"; fix it rather than relying on a default", tier.as_str())
            }
            Self::TypeNotOptedIn { type_saved: false } => write!(
                f,
                "agent sessions are off by default: this resource's type is not in the saved resource type \
                 configuration. Save the type with `connect.agent_sessions_max = \"allow\"` to opt it in"
            ),
            Self::TypeNotOptedIn { type_saved: true } => write!(
                f,
                "agent sessions are off by default: this resource's type does not set \
                 `connect.agent_sessions_max = \"allow\"`"
            ),
            Self::ProfileNotOptedIn => {
                write!(f, "this connection profile does not set `agent_access = \"allow\"`")
            }
            Self::UnsupportedProtocol { protocol } => {
                write!(f, "a {protocol:?} profile cannot be used for agent sessions")
            }
            Self::CredentialSourceUnsupported { protocol, kind } => write!(
                f,
                "a {protocol} agent session cannot use a {kind:?} credential source: the vault must resolve and use the \
                 credential itself, so only an SSH-engine certificate (CA mode) or a stored `secret` qualifies for SSH, \
                 and a stored `secret` for RDP"
            ),
            Self::HostKeyUnpinned => write!(
                f,
                "an SSH profile used for agent sessions must carry `host_key_pin`: the host key is checked before any \
                 credential is sent"
            ),
            Self::HostKeyPinMalformed => {
                write!(f, "`host_key_pin` must be an OpenSSH fingerprint, `SHA256:<base64>`")
            }
            Self::WebLoginModeUnsupported { mode } => write!(
                f,
                "web login mode {mode:?} cannot be used for agent sessions; only `open` and `http-auth` can"
            ),
            Self::WebNotHttps => {
                write!(f, "a web profile used for agent sessions must start at an https URL and not allow insecure http")
            }
        }
    }
}

fn parse_gate(v: Option<&Value>, tier: AgentTier) -> Result<AgentGate, AgentAccessRefusal> {
    match v {
        None | Some(Value::Null) => Ok(AgentGate::Deny),
        Some(Value::String(s)) if s == "deny" => Ok(AgentGate::Deny),
        Some(Value::String(s)) if s == "allow" => Ok(AgentGate::Allow),
        Some(_) => Err(AgentAccessRefusal::InvalidPolicy { tier }),
    }
}

/// The type tier. `type_def` is the resource's entry in the *saved*
/// `config/types` (see `type_config::effective_type_config`); `None` when
/// the configuration was never saved, the resource has no type, or its type
/// is not in it — all three deny.
pub fn type_gate(type_def: Option<&Value>) -> Result<AgentGate, AgentAccessRefusal> {
    match type_def {
        None | Some(Value::Null) => Ok(AgentGate::Deny),
        Some(Value::Object(def)) => match def.get("connect") {
            None | Some(Value::Null) => Ok(AgentGate::Deny),
            Some(Value::Object(c)) => parse_gate(c.get(AGENT_SESSIONS_MAX_KEY), AgentTier::Type),
            Some(_) => Err(AgentAccessRefusal::InvalidPolicy { tier: AgentTier::Type }),
        },
        Some(_) => Err(AgentAccessRefusal::InvalidPolicy { tier: AgentTier::Type }),
    }
}

fn require_type_allows(type_def: Option<&Value>) -> Result<(), AgentAccessRefusal> {
    match type_gate(type_def)? {
        AgentGate::Allow => Ok(()),
        AgentGate::Deny => {
            Err(AgentAccessRefusal::TypeNotOptedIn { type_saved: matches!(type_def, Some(Value::Object(_))) })
        }
    }
}

/// The profile tier, strictly.
pub fn profile_gate(profile: &Value) -> Result<AgentGate, AgentAccessRefusal> {
    parse_gate(profile.get(AGENT_ACCESS_KEY), AgentTier::Profile)
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
}

/// An OpenSSH `SHA256:<base64>` host-key fingerprint: 32 bytes, unpadded.
fn valid_ssh_fingerprint(pin: &str) -> bool {
    let Some(b64) = pin.strip_prefix("SHA256:") else {
        return false;
    };
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64).is_ok_and(|digest| digest.len() == 32)
}

/// The protocol's static requirements (§12 "Connection profile"): what can
/// be decided from the profile alone, before anything is dialed.
pub fn check_profile_static_requirements(profile: &Value) -> Result<(), AgentAccessRefusal> {
    let protocol = str_at(profile, &["protocol"]).unwrap_or_default();
    let credential_kind = str_at(profile, &["credential_source", "kind"]).unwrap_or_default();
    match protocol {
        "ssh" => {
            let mode = str_at(profile, &["credential_source", "mode"]).unwrap_or_default();
            let supported = (credential_kind == "ssh-engine" && mode == "ca") || credential_kind == "secret";
            if !supported {
                let kind = if credential_kind == "ssh-engine" {
                    format!("ssh-engine (mode {mode:?})")
                } else {
                    credential_kind.to_string()
                };
                return Err(AgentAccessRefusal::CredentialSourceUnsupported { protocol: "ssh", kind });
            }
            match str_at(profile, &["host_key_pin"]).map(str::trim) {
                None | Some("") => Err(AgentAccessRefusal::HostKeyUnpinned),
                Some(pin) if !valid_ssh_fingerprint(pin) => Err(AgentAccessRefusal::HostKeyPinMalformed),
                Some(_) => Ok(()),
            }
        }
        "web" => {
            let mode = str_at(profile, &["web", "login_mode"]).unwrap_or_default();
            if mode != "open" && mode != "http-auth" {
                return Err(AgentAccessRefusal::WebLoginModeUnsupported { mode: mode.to_string() });
            }
            let insecure = !matches!(
                profile.get("web").and_then(|w| w.get("allow_insecure_http")),
                None | Some(Value::Bool(false)) | Some(Value::Null)
            );
            let https = str_at(profile, &["web", "start_url"])
                .is_some_and(|u| u.get(..8).is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://")));
            if insecure || !https {
                return Err(AgentAccessRefusal::WebNotHttps);
            }
            // `http-auth` releases a username and password; only a stored
            // secret is resolved under the server's authority (§6.2). LDAP,
            // default-account and provider sources resolve *as the caller*,
            // and an MCP token has no caller identity to resolve them as.
            if mode == "http-auth" && credential_kind != "secret" {
                return Err(AgentAccessRefusal::CredentialSourceUnsupported {
                    protocol: "web",
                    kind: credential_kind.to_string(),
                });
            }
            Ok(())
        }
        "rdp" => {
            if credential_kind != "secret" {
                return Err(AgentAccessRefusal::CredentialSourceUnsupported {
                    protocol: "rdp",
                    kind: credential_kind.to_string(),
                });
            }
            Ok(())
        }
        other => Err(AgentAccessRefusal::UnsupportedProtocol { protocol: other.to_string() }),
    }
}

/// The session handler's opt-in check (§3 step 5.5): the type allows, the
/// profile allows, and the profile still meets its protocol's static
/// requirements.
pub fn check_agent_enabled(type_def: Option<&Value>, profile: &Value) -> Result<(), AgentAccessRefusal> {
    require_type_allows(type_def)?;
    if profile_gate(profile)? != AgentGate::Allow {
        return Err(AgentAccessRefusal::ProfileNotOptedIn);
    }
    check_profile_static_requirements(profile)
}

fn profiles(record: &Map<String, Value>) -> &[Value] {
    match record.get("connection_profiles") {
        Some(Value::Array(arr)) => arr,
        _ => &[],
    }
}

/// The profiles of `body` a write has to vet: those carrying `agent_access`
/// that are new or differ from the stored profile with the same `id`.
/// Unchanged profiles are not re-vetted, so an unrelated edit to a resource
/// — the desktop app's `recent_sessions` stamp, a note — is not refused
/// because the type was later turned back to `deny`; the call-time check
/// covers those.
fn changed_agent_profiles<'a>(previous: Option<&Map<String, Value>>, body: &'a Map<String, Value>) -> Vec<&'a Value> {
    let before = previous.map(profiles).unwrap_or_default();
    profiles(body)
        .iter()
        .filter(|p| p.get(AGENT_ACCESS_KEY).is_some())
        .filter(|p| {
            let id = p.get("id").and_then(Value::as_str);
            let prior = id.and_then(|id| before.iter().find(|q| q.get("id").and_then(Value::as_str) == Some(id)));
            prior != Some(*p)
        })
        .collect()
}

/// Does this write need the type configuration? Only when a changed profile
/// turns `agent_access` on — so ordinary writes cost no extra read.
pub fn write_needs_type_check(previous: Option<&Map<String, Value>>, body: &Map<String, Value>) -> bool {
    changed_agent_profiles(previous, body).iter().any(|p| profile_gate(p) != Ok(AgentGate::Deny))
}

/// Vet a resource write (§12): every new or changed profile carrying
/// `agent_access` must carry a valid value, and one set to `"allow"` needs
/// the type's consent and the protocol's static requirements. `type_def` is
/// the resource's entry in the effective saved type configuration.
pub fn validate_profiles_on_write(
    previous: Option<&Map<String, Value>>,
    body: &Map<String, Value>,
    type_def: Option<&Value>,
) -> Result<(), AgentAccessRefusal> {
    for profile in changed_agent_profiles(previous, body) {
        if profile_gate(profile)? == AgentGate::Allow {
            require_type_allows(type_def)?;
            check_profile_static_requirements(profile)?;
        }
    }
    Ok(())
}

/// Vet a `config/types` write: an `agent_sessions_max` that is present must
/// be `"allow"` or `"deny"`.
pub fn validate_type_config(types: &Map<String, Value>) -> Result<(), AgentAccessRefusal> {
    for def in types.values() {
        if let Some(Value::Object(connect)) = def.get("connect") {
            parse_gate(connect.get(AGENT_SESSIONS_MAX_KEY), AgentTier::Type)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PIN: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn allow_type() -> Value {
        json!({ "id": "server", "connect": { "agent_sessions_max": "allow" } })
    }

    fn ssh_cert_profile() -> Value {
        json!({
            "id": "p1", "name": "agent", "protocol": "ssh", "agent_access": "allow",
            "credential_source": { "kind": "ssh-engine", "ssh_mount": "ssh", "ssh_role": "agent", "mode": "ca" },
            "host_key_pin": PIN,
        })
    }

    #[test]
    fn absent_means_deny_at_both_tiers() {
        // Every type and profile written before this feature.
        assert_eq!(type_gate(None), Ok(AgentGate::Deny));
        assert_eq!(type_gate(Some(&json!({ "id": "server" }))), Ok(AgentGate::Deny));
        assert_eq!(type_gate(Some(&json!({ "connect": { "web_exposure_max": "dom" } }))), Ok(AgentGate::Deny));
        assert_eq!(profile_gate(&json!({ "id": "p", "protocol": "ssh" })), Ok(AgentGate::Deny));
        let mut old_profile = ssh_cert_profile();
        old_profile.as_object_mut().unwrap().remove(AGENT_ACCESS_KEY);
        assert_eq!(check_agent_enabled(Some(&allow_type()), &old_profile), Err(AgentAccessRefusal::ProfileNotOptedIn));
    }

    #[test]
    fn values_are_parsed_strictly() {
        for bad in [json!("Allow"), json!(true), json!(1), json!("yes")] {
            assert_eq!(
                type_gate(Some(&json!({ "connect": { "agent_sessions_max": bad } }))),
                Err(AgentAccessRefusal::InvalidPolicy { tier: AgentTier::Type })
            );
            assert_eq!(
                profile_gate(&json!({ "agent_access": bad })),
                Err(AgentAccessRefusal::InvalidPolicy { tier: AgentTier::Profile })
            );
        }
        assert_eq!(
            type_gate(Some(&json!({ "connect": "allow" }))),
            Err(AgentAccessRefusal::InvalidPolicy { tier: AgentTier::Type })
        );
        assert_eq!(type_gate(Some(&json!({ "connect": { "agent_sessions_max": "deny" } }))), Ok(AgentGate::Deny));
    }

    #[test]
    fn call_time_check_needs_both_tiers() {
        let p = ssh_cert_profile();
        assert_eq!(check_agent_enabled(Some(&allow_type()), &p), Ok(()));
        assert_eq!(check_agent_enabled(None, &p), Err(AgentAccessRefusal::TypeNotOptedIn { type_saved: false }));
        let deny = json!({ "connect": { "agent_sessions_max": "deny" } });
        let err = check_agent_enabled(Some(&deny), &p).unwrap_err();
        assert_eq!(err, AgentAccessRefusal::TypeNotOptedIn { type_saved: true });
        assert_eq!(err.code(), "mcp_session_profile_not_agent_enabled");
        let mut off = p.clone();
        off["agent_access"] = json!("deny");
        assert_eq!(check_agent_enabled(Some(&allow_type()), &off), Err(AgentAccessRefusal::ProfileNotOptedIn));
    }

    #[test]
    fn ssh_needs_a_supported_credential_source_and_a_pin() {
        let mut secret = ssh_cert_profile();
        secret["credential_source"] = json!({ "kind": "secret", "secret_id": "root-pw" });
        assert_eq!(check_profile_static_requirements(&secret), Ok(()));

        for (source, kind) in [
            (json!({ "kind": "ssh-engine", "mode": "otp" }), "ssh-engine (mode \"otp\")"),
            (json!({ "kind": "ssh-engine", "mode": "pqc" }), "ssh-engine (mode \"pqc\")"),
            (json!({ "kind": "ldap", "ldap_mount": "ldap" }), "ldap"),
            (json!({ "kind": "default-account" }), "default-account"),
            (json!({ "kind": "provider", "provider": "self-accounts" }), "provider"),
            (json!({ "kind": "pki", "pki_mount": "pki", "pki_role": "r" }), "pki"),
            (json!({ "kind": "fido2" }), "fido2"),
        ] {
            let mut p = ssh_cert_profile();
            p["credential_source"] = source;
            let err = check_profile_static_requirements(&p).unwrap_err();
            assert_eq!(err, AgentAccessRefusal::CredentialSourceUnsupported { protocol: "ssh", kind: kind.into() });
            assert_eq!(err.code(), "mcp_session_login_class_unsupported");
        }

        let mut unpinned = ssh_cert_profile();
        unpinned.as_object_mut().unwrap().remove("host_key_pin");
        assert_eq!(check_profile_static_requirements(&unpinned), Err(AgentAccessRefusal::HostKeyUnpinned));
        unpinned["host_key_pin"] = json!("  ");
        assert_eq!(check_profile_static_requirements(&unpinned), Err(AgentAccessRefusal::HostKeyUnpinned));
        for bad in ["MD5:aa:bb", "SHA256:not base64!", "SHA256:AAAA", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"] {
            unpinned["host_key_pin"] = json!(bad);
            assert_eq!(
                check_profile_static_requirements(&unpinned),
                Err(AgentAccessRefusal::HostKeyPinMalformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn web_needs_open_or_http_auth_over_https() {
        let web = |mode: &str, url: &str, kind: &str| {
            json!({ "id": "w", "protocol": "web", "agent_access": "allow",
                    "credential_source": { "kind": kind },
                    "web": { "login_mode": mode, "start_url": url } })
        };
        assert_eq!(check_profile_static_requirements(&web("open", "https://grafana.internal/", "none")), Ok(()));
        assert_eq!(check_profile_static_requirements(&web("http-auth", "HTTPS://idrac/", "secret")), Ok(()));
        for mode in ["form", "sso", ""] {
            assert_eq!(
                check_profile_static_requirements(&web(mode, "https://x/", "secret")),
                Err(AgentAccessRefusal::WebLoginModeUnsupported { mode: mode.into() })
            );
        }
        assert_eq!(
            check_profile_static_requirements(&web("open", "http://grafana.internal/", "none")),
            Err(AgentAccessRefusal::WebNotHttps)
        );
        let mut insecure = web("open", "https://grafana.internal/", "none");
        insecure["web"]["allow_insecure_http"] = json!(true);
        assert_eq!(check_profile_static_requirements(&insecure), Err(AgentAccessRefusal::WebNotHttps));
        assert_eq!(
            check_profile_static_requirements(&web("http-auth", "https://x/", "ldap")),
            Err(AgentAccessRefusal::CredentialSourceUnsupported { protocol: "web", kind: "ldap".into() })
        );
    }

    #[test]
    fn rdp_needs_a_stored_secret_and_other_protocols_are_refused() {
        let rdp = |kind: &str| json!({ "protocol": "rdp", "credential_source": { "kind": kind } });
        assert_eq!(check_profile_static_requirements(&rdp("secret")), Ok(()));
        assert!(check_profile_static_requirements(&rdp("provider")).is_err());
        assert_eq!(
            check_profile_static_requirements(&json!({ "protocol": "vnc" })),
            Err(AgentAccessRefusal::UnsupportedProtocol { protocol: "vnc".into() })
        );
    }

    #[test]
    fn a_write_turning_agent_access_on_needs_the_type_and_the_static_requirements() {
        let body = obj(json!({ "type": "server", "connection_profiles": [ssh_cert_profile()] }));
        assert!(write_needs_type_check(None, &body));
        assert_eq!(validate_profiles_on_write(None, &body, Some(&allow_type())), Ok(()));
        assert_eq!(
            validate_profiles_on_write(None, &body, None),
            Err(AgentAccessRefusal::TypeNotOptedIn { type_saved: false })
        );
        let mut unpinned = ssh_cert_profile();
        unpinned.as_object_mut().unwrap().remove("host_key_pin");
        let body = obj(json!({ "type": "server", "connection_profiles": [unpinned] }));
        assert_eq!(
            validate_profiles_on_write(None, &body, Some(&allow_type())),
            Err(AgentAccessRefusal::HostKeyUnpinned)
        );
        let mut bad = ssh_cert_profile();
        bad["agent_access"] = json!("ALLOW");
        let body = obj(json!({ "connection_profiles": [bad] }));
        assert_eq!(
            validate_profiles_on_write(None, &body, Some(&allow_type())),
            Err(AgentAccessRefusal::InvalidPolicy { tier: AgentTier::Profile })
        );
    }

    #[test]
    fn unchanged_or_denying_profiles_are_not_vetted_on_write() {
        let stored = obj(json!({ "type": "server", "connection_profiles": [ssh_cert_profile()] }));
        // The type was later turned back to deny, and the desktop app stamps
        // `recent_sessions`: the unchanged profile is not re-vetted.
        let mut stamped = stored.clone();
        stamped.insert("recent_sessions".into(), json!([{ "ts": "2026-10-14T00:00:00Z" }]));
        assert!(!write_needs_type_check(Some(&stored), &stamped));
        assert_eq!(validate_profiles_on_write(Some(&stored), &stamped, None), Ok(()));
        // ... but editing that profile is.
        let mut edited = stored.clone();
        edited["connection_profiles"][0]["name"] = json!("renamed");
        assert!(write_needs_type_check(Some(&stored), &edited));
        assert!(validate_profiles_on_write(Some(&stored), &edited, None).is_err());
        // Turning it off never needs the type.
        let mut off = stored.clone();
        off["connection_profiles"][0]["agent_access"] = json!("deny");
        assert!(!write_needs_type_check(Some(&stored), &off));
        assert_eq!(validate_profiles_on_write(Some(&stored), &off, None), Ok(()));
        // Profiles without the key are someone else's business.
        let legacy = obj(json!({ "connection_profiles": [{ "id": "x", "protocol": "ssh" }], "notes": "n" }));
        assert!(!write_needs_type_check(None, &legacy));
        assert_eq!(validate_profiles_on_write(None, &legacy, None), Ok(()));
        // A non-array `connection_profiles` is opaque metadata, as before.
        let opaque = obj(json!({ "connection_profiles": "not-an-array" }));
        assert_eq!(validate_profiles_on_write(None, &opaque, None), Ok(()));
    }

    #[test]
    fn type_config_writes_refuse_a_malformed_agent_sessions_max() {
        let ok = obj(json!({
            "server": { "connect": { "agent_sessions_max": "allow" } },
            "db": { "connect": { "agent_sessions_max": "deny", "web_exposure_max": "none" } },
            "legacy": { "fields": [] },
        }));
        assert_eq!(validate_type_config(&ok), Ok(()));
        let bad = obj(json!({ "server": { "connect": { "agent_sessions_max": "everyone" } } }));
        let err = validate_type_config(&bad).unwrap_err();
        assert_eq!((err.code(), err.status()), ("agent_policy_invalid", 422));
    }
}
