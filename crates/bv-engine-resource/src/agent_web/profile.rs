//! A stored web connection profile, read as an agent fetch
//! (`features/mcp-brokered-sessions.md` §6.2-6.3).
//!
//! Strict, like the human launch's reader (`connect_web::profile`), whose
//! origin and credential-source parsers this reuses so the two read a
//! profile the same way: a value this server does not recognise refuses the
//! call rather than falling back. The opt-ins and the static requirements
//! (`open`/`http-auth`, https, a stored secret for `http-auth`) have been
//! checked by `agent_access` before this runs; this reads what the fetch
//! needs and refuses again what it cannot use.

use bv_utils::tls_pin::PinSet;
use serde_json::{Map, Value};

use crate::{
    agent_session::SessionRefusal,
    connect_web::profile::{bare_origin, credential_source, url_origin, SecretFieldMap, WebCredentialSource},
};

/// An https origin the fetch may talk to, normalized
/// (`connect_web::recipe::origin_key`): lower-case host, default port
/// dropped from the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebOrigin {
    /// `https://host[:port]`, the form the profile's lists are compared in.
    pub key: String,
    /// The host as it goes in a URL: a name, an IPv4 literal, or a
    /// bracketed IPv6 literal.
    pub host: String,
    pub port: u16,
}

impl WebOrigin {
    /// Read back an origin key `origin_key` produced.
    pub fn from_key(key: &str) -> Result<Self, String> {
        let authority = key.strip_prefix("https://").ok_or_else(|| format!("{key:?} is not an https origin"))?;
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let close = rest.find(']').ok_or_else(|| format!("{key:?} has an unterminated IPv6 literal"))?;
            let host = format!("[{}]", &rest[..close]);
            match &rest[close + 1..] {
                "" => (host, None),
                p => (host, Some(p.strip_prefix(':').ok_or_else(|| format!("{key:?} has junk after its host"))?)),
            }
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            None => 443,
            Some(p) => p.parse::<u16>().map_err(|_| format!("{key:?} has a malformed port"))?,
        };
        if host.is_empty() {
            return Err(format!("{key:?} has no host"));
        }
        Ok(Self { key: key.to_string(), host, port })
    }

    /// The host as the destination policy and the resolver take it: an IPv6
    /// literal without its brackets.
    pub fn dial_host(&self) -> String {
        self.host.trim_start_matches('[').trim_end_matches(']').to_string()
    }
}

/// How the fetch logs in (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WebLogin {
    /// No credential, ever.
    Open,
    /// HTTP Basic, answered only to the target's own challenge, with a
    /// stored secret read under the server's authority.
    HttpAuth { secret_id: String, fields: SecretFieldMap },
}

impl WebLogin {
    /// `open` or `http-auth`, for results, events and transcripts.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::HttpAuth { .. } => "http-auth",
        }
    }
}

/// What a fetch needs from the profile.
#[derive(Debug, Clone)]
pub(crate) struct AgentWebProfile {
    /// The origin of `web.start_url`: every call's path is fetched from it.
    pub start: WebOrigin,
    /// Origin keys a redirect may go to: the start origin first, then
    /// `web.allowed_origins`.
    pub allowed: Vec<String>,
    pub login: WebLogin,
    /// `web.tls_pin_sha256`: consulted only for a certificate the platform
    /// roots reject.
    pub pins: PinSet,
}

fn malformed(message: impl Into<String>) -> SessionRefusal {
    SessionRefusal::new("mcp_session_profile_not_agent_enabled", 422, message)
}

fn origin_refused(message: impl Into<String>) -> SessionRefusal {
    SessionRefusal::new("mcp_web_origin_refused", 403, message)
}

impl AgentWebProfile {
    pub fn parse(profile: &Value) -> Result<Self, SessionRefusal> {
        let p = profile.as_object().ok_or_else(|| malformed("the profile is not a JSON object"))?;
        let web = p.get("web").and_then(Value::as_object).ok_or_else(|| malformed("the profile has no `web` block"))?;

        // A bastion route is never bypassed (§3 step 5.7). `kind: rustion`
        // is refused by the shared transport check; Rustion browser
        // isolation is a web transport of its own.
        match web.get("transport").filter(|v| !v.is_null()) {
            None => {}
            Some(Value::String(t)) if t == "local" => {}
            Some(Value::String(t)) if t == "rustion-isolated" => {
                return Err(SessionRefusal::new(
                    "mcp_session_requires_bastion",
                    403,
                    "this profile's transport is Rustion browser isolation; an agent fetch is never run direct \
                     instead",
                ))
            }
            Some(_) => return Err(malformed("web.transport must be `local`")),
        }
        if !matches!(web.get("allow_insecure_http"), None | Some(Value::Null) | Some(Value::Bool(false))) {
            return Err(origin_refused("an agent fetch is https only; this profile allows insecure http"));
        }

        let login = match web.get("login_mode").and_then(Value::as_str) {
            Some("open") => WebLogin::Open,
            Some("http-auth") => match credential_source(p, "http-auth") {
                Ok(WebCredentialSource::Secret { secret_id, fields, .. }) => WebLogin::HttpAuth { secret_id, fields },
                Ok(other) => {
                    return Err(SessionRefusal::new(
                        "mcp_session_login_class_unsupported",
                        403,
                        format!(
                            "an agent fetch can use only a stored `secret` for http-auth, not a {:?} source",
                            other.kind()
                        ),
                    ))
                }
                Err(r) => return Err(SessionRefusal::new("mcp_session_login_class_unsupported", 403, r.message)),
            },
            Some(mode) => {
                return Err(SessionRefusal::new(
                    "mcp_web_login_mode_unsupported",
                    403,
                    format!(
                        "web login mode {mode:?} cannot be used by an agent: only `open` and `http-auth` can (form \
                         and sso need a browser, which waits on proxy mode or Rustion browser isolation)"
                    ),
                ))
            }
            None => return Err(malformed("web.login_mode is missing")),
        };

        let start_url =
            web.get("start_url").and_then(Value::as_str).ok_or_else(|| malformed("web.start_url is required"))?;
        let start_key = url_origin(start_url, false).map_err(|r| origin_refused(format!("web.start_url {r}")))?;
        let start = WebOrigin::from_key(&start_key).map_err(origin_refused)?;
        let mut allowed = vec![start_key];
        match web.get("allowed_origins") {
            None | Some(Value::Null) => {}
            Some(Value::Array(list)) => {
                for (i, o) in list.iter().enumerate() {
                    let raw =
                        o.as_str().ok_or_else(|| malformed(format!("web.allowed_origins[{i}] must be a string")))?;
                    let key =
                        bare_origin(raw, false).map_err(|r| origin_refused(format!("web.allowed_origins[{i}] {r}")))?;
                    if !allowed.contains(&key) {
                        allowed.push(key);
                    }
                }
            }
            Some(_) => return Err(malformed("web.allowed_origins must be an array")),
        }

        let pins = match web.get("tls_pin_sha256") {
            None | Some(Value::Null) => PinSet::default(),
            Some(Value::Array(list)) => PinSet::from_json(list).map_err(malformed)?,
            Some(_) => return Err(malformed("web.tls_pin_sha256 must be an array of pins")),
        };

        Ok(Self { start, allowed, login, pins })
    }
}

/// The secret's username and password, out of its stored fields, by the
/// profile's field map. Both are required for http-auth.
pub(crate) fn basic_credential(
    data: &Map<String, Value>,
    fields: &SecretFieldMap,
    secret_id: &str,
) -> Result<(zeroize::Zeroizing<String>, zeroize::Zeroizing<String>), SessionRefusal> {
    let take = crate::connect_web::take_field;
    let missing = |field: &str| {
        SessionRefusal::new(
            "mcp_session_failed",
            422,
            format!("the profile's stored secret `{secret_id}` has no `{field}` field for http-auth"),
        )
    };
    let username = take(data, &fields.username).ok_or_else(|| missing(&fields.username))?;
    let password = take(data, &fields.password).ok_or_else(|| missing(&fields.password))?;
    if username.contains(':') {
        return Err(SessionRefusal::new(
            "mcp_session_failed",
            422,
            format!("the username in secret `{secret_id}` contains `:`, which HTTP Basic cannot carry"),
        ));
    }
    Ok((username, password))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn web(block: Value) -> Value {
        json!({ "id": "p_web", "protocol": "web", "agent_access": "allow",
                "credential_source": { "kind": "secret", "secret_id": "login" }, "web": block })
    }

    #[test]
    fn an_open_profile_reads_its_origins_and_pins() {
        let pin = format!("sha256:{}", "ab".repeat(32));
        let p = AgentWebProfile::parse(&web(json!({
            "login_mode": "open",
            "start_url": "https://Grafana.Internal:8443/login?next=/",
            "allowed_origins": ["https://sso.internal", "https://grafana.internal:8443/"],
            "tls_pin_sha256": [pin],
        })))
        .unwrap();
        assert_eq!(
            p.start,
            WebOrigin { key: "https://grafana.internal:8443".into(), host: "grafana.internal".into(), port: 8443 }
        );
        assert_eq!(p.allowed, vec!["https://grafana.internal:8443".to_string(), "https://sso.internal".to_string()]);
        assert_eq!(p.login, WebLogin::Open);
        assert_eq!(p.pins.len(), 1);
    }

    #[test]
    fn http_auth_needs_a_stored_secret() {
        let p =
            AgentWebProfile::parse(&web(json!({ "login_mode": "http-auth", "start_url": "https://idrac/" }))).unwrap();
        assert!(matches!(p.login, WebLogin::HttpAuth { ref secret_id, .. } if secret_id == "login"));
        assert_eq!(p.login.kind(), "http-auth");
        let mut ldap = web(json!({ "login_mode": "http-auth", "start_url": "https://idrac/" }));
        ldap["credential_source"] =
            json!({ "kind": "ldap", "ldap_mount": "ldap/", "bind_mode": "static_role", "static_role": "svc" });
        assert_eq!(AgentWebProfile::parse(&ldap).unwrap_err().code, "mcp_session_login_class_unsupported");
    }

    /// `form` and `sso` need a browser: refused with the spec's code.
    #[test]
    fn form_and_sso_are_refused() {
        for mode in ["form", "sso"] {
            let err =
                AgentWebProfile::parse(&web(json!({ "login_mode": mode, "start_url": "https://x/" }))).unwrap_err();
            assert_eq!(err.code, "mcp_web_login_mode_unsupported", "{mode}");
        }
    }

    #[test]
    fn insecure_isolated_and_malformed_profiles_are_refused() {
        let cases = [
            (json!({ "login_mode": "open", "start_url": "http://grafana/" }), "mcp_web_origin_refused"),
            (
                json!({ "login_mode": "open", "start_url": "https://g/", "allow_insecure_http": true }),
                "mcp_web_origin_refused",
            ),
            (
                json!({ "login_mode": "open", "start_url": "https://g/", "allowed_origins": ["http://g2"] }),
                "mcp_web_origin_refused",
            ),
            (json!({ "login_mode": "open", "start_url": "https://user@g/" }), "mcp_web_origin_refused"),
            (
                json!({ "login_mode": "open", "start_url": "https://g/", "transport": "rustion-isolated" }),
                "mcp_session_requires_bastion",
            ),
            (
                json!({ "login_mode": "open", "start_url": "https://g/", "tls_pin_sha256": ["nope"] }),
                "mcp_session_profile_not_agent_enabled",
            ),
            (json!({ "start_url": "https://g/" }), "mcp_session_profile_not_agent_enabled"),
        ];
        for (block, code) in cases {
            assert_eq!(AgentWebProfile::parse(&web(block.clone())).unwrap_err().code, code, "{block}");
        }
    }

    #[test]
    fn origin_keys_read_back_with_their_port() {
        let v6 = WebOrigin::from_key("https://[fd00::9]:8443").unwrap();
        assert_eq!((v6.host.as_str(), v6.port, v6.dial_host()), ("[fd00::9]", 8443, "fd00::9".to_string()));
        assert_eq!(WebOrigin::from_key("https://10.0.0.5").unwrap().port, 443);
        assert!(WebOrigin::from_key("http://x").is_err());
    }

    #[test]
    fn the_basic_credential_follows_the_field_map() {
        let data = json!({ "user": "ops", "pass": "hunter2" }).as_object().cloned().unwrap();
        let fields = SecretFieldMap {
            username: "user".into(),
            password: "pass".into(),
            totp_seed: "t".into(),
            ..SecretFieldMap::default()
        };
        let (u, p) = basic_credential(&data, &fields, "login").unwrap();
        assert_eq!((u.as_str(), p.as_str()), ("ops", "hunter2"));
        assert_eq!(
            basic_credential(&data, &SecretFieldMap::default(), "login").unwrap_err().code,
            "mcp_session_failed"
        );
        let colon = json!({ "username": "a:b", "password": "x" }).as_object().cloned().unwrap();
        assert!(basic_credential(&colon, &SecretFieldMap::default(), "login").is_err());
    }
}
