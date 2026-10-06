//! Reading a stored connection profile as a web launch: `form` mode (Phase 2)
//! or `http-auth` mode (Phase 3).
//!
//! Profiles are GUI-owned JSON on the resource record. This module reads only
//! the parts the launch decision depends on, and reads those strictly: a value
//! it does not recognise refuses the launch rather than falling back to a
//! default. Keys it does not read (window size, clipboard, download policy) are
//! the host's business and are left alone.

use serde_json::{Map, Value};

use super::exposure::WebExposure;
use super::recipe::{self, RecipeNeeds, WebLoginRecipe};
use super::totp::TotpParams;
use super::WebRefusal;

/// Key names inside a `secret` source's resource secret (§1). Each can be
/// remapped with `credential_source.fields`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFieldMap {
    pub username: String,
    pub password: String,
    pub totp_seed: String,
}

impl Default for SecretFieldMap {
    fn default() -> Self {
        Self { username: "username".into(), password: "password".into(), totp_seed: "totp_seed".into() }
    }
}

/// The credential sources a `form` or `http-auth` launch can resolve (§1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebCredentialSource {
    /// A secret on this resource. Resolved under the server's authority: the
    /// `connect` grant on this resource is the authorization.
    Secret { secret_id: String, fields: SecretFieldMap, totp: TotpParams },
    /// An LDAP static role, read *as the caller*.
    LdapStaticRole { mount: String, role: String },
    /// An LDAP library set, checked out *as the caller* and checked back in on
    /// `close`.
    LdapLibrarySet { mount: String, set: String },
    /// The caller's own default account: a username only.
    DefaultAccount,
}

impl WebCredentialSource {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Secret { .. } => "secret",
            Self::LdapStaticRole { .. } | Self::LdapLibrarySet { .. } => "ldap",
            Self::DefaultAccount => "default-account",
        }
    }
}

/// The login mode a launch serves, with what that mode carries.
#[derive(Debug, Clone)]
pub enum LaunchLogin {
    /// `form` (§2, §5): a recipe fills the credential into the page's DOM.
    /// Boxed: a parsed recipe is far larger than the `HttpAuth` variant.
    Form { recipe: Box<WebLoginRecipe>, recipe_hash: String },
    /// `http-auth` (§7): the desktop host answers HTTP Basic / Digest / NTLM
    /// challenges natively. No recipe, no TOTP: the credential is a username
    /// and a password, handed to the webview's challenge handler only.
    HttpAuth,
}

/// A profile that passed every static check `v2/connect/web/launch` makes.
#[derive(Debug, Clone)]
pub struct WebLaunchProfile {
    pub require_mfa: bool,
    pub allow_insecure_http: bool,
    /// `web.start_url` as stored; its origin is `origins[0]`.
    pub start_url: String,
    /// Normalised origin keys: the start URL's origin first, then
    /// `allowed_origins`. For `form` the fill scope; for `http-auth` the only
    /// origins whose challenges the host may answer.
    pub origins: Vec<String>,
    pub login: LaunchLogin,
    /// What the launch releases. For `http-auth`: username and password,
    /// never TOTP, no steps.
    pub needs: RecipeNeeds,
    pub source: WebCredentialSource,
}

impl WebLaunchProfile {
    /// `web.login_mode` as the record, the audit line and the bundle carry it.
    pub fn login_mode(&self) -> &'static str {
        match self.login {
            LaunchLogin::Form { .. } => "form",
            LaunchLogin::HttpAuth => "http-auth",
        }
    }

    /// The recipe hash a `form` launch is bound to; `None` for `http-auth`,
    /// which has no recipe.
    pub fn recipe_hash(&self) -> Option<&str> {
        match &self.login {
            LaunchLogin::Form { recipe_hash, .. } => Some(recipe_hash),
            LaunchLogin::HttpAuth => None,
        }
    }

    /// The exposure the login mode needs (§6): `form` is `dom`, `http-auth`
    /// is `handler`.
    pub fn required_exposure(&self) -> WebExposure {
        match self.login {
            LaunchLogin::Form { .. } => WebExposure::Dom,
            LaunchLogin::HttpAuth => WebExposure::Handler,
        }
    }

    /// The exposure the launch is recorded and reported at. §6: "a credential
    /// sent over plaintext HTTP is not `handler` or `proxy` exposure in any
    /// meaningful sense", so a profile that allows plain http is `dom`
    /// whatever its mode — which is also why the policy check refuses
    /// `allow_insecure_http` below a `dom` cap.
    pub fn launched_exposure(&self) -> WebExposure {
        if self.allow_insecure_http {
            WebExposure::Dom
        } else {
            self.required_exposure()
        }
    }
}

/// What an `http-auth` launch releases: a username and a password, nothing
/// else. There is no recipe step, so no step index is valid in `result`.
fn http_auth_needs() -> RecipeNeeds {
    RecipeNeeds { heuristic: false, username: true, password: true, totp: false, totp_steps: Vec::new(), step_count: 0 }
}

fn refuse(status: u16, code: &'static str, message: impl Into<String>) -> WebRefusal {
    WebRefusal::new(status, code, message)
}

fn invalid(message: impl Into<String>) -> WebRefusal {
    refuse(422, "invalid_profile", message)
}

/// The LDAP engine's own path-segment rule for role and set names
/// (`\w[\w-]*\w`), so a name that could never route is refused here with a
/// clear message rather than 404ing inside a sub-request.
fn ldap_name(v: Option<&Value>, field: &str) -> Result<String, WebRefusal> {
    let s = v.and_then(Value::as_str).map(str::trim).unwrap_or_default();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let ok = s.len() >= 2
        && s.len() <= 128
        && s.chars().all(|c| word(c) || c == '-')
        && s.chars().next().is_some_and(word)
        && s.chars().last().is_some_and(word);
    if !ok {
        return Err(invalid(format!("credential_source.{field} must be an LDAP role/set name (\\w[\\w-]*\\w)")));
    }
    Ok(s.to_string())
}

fn mount_path(v: Option<&Value>) -> Result<String, WebRefusal> {
    let raw = v.and_then(Value::as_str).map(str::trim).unwrap_or_default();
    let m = raw.trim_end_matches('/');
    let ok = !m.is_empty()
        && !m.starts_with('/')
        && m.len() <= 256
        && m.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && m.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.'));
    if !ok {
        return Err(invalid("credential_source.ldap_mount must be a mount path such as `openldap/`"));
    }
    Ok(format!("{m}/"))
}

/// A key inside this resource's secret store: one path segment.
fn secret_key(v: Option<&Value>, field: &str) -> Result<String, WebRefusal> {
    let s = v.and_then(Value::as_str).unwrap_or_default();
    if s.is_empty() || s.len() > 256 || s.contains('/') || s == "." || s == ".." || s.chars().any(char::is_control) {
        return Err(invalid(format!("credential_source.{field} must be a single secret key name")));
    }
    Ok(s.to_string())
}

fn secret_fields(v: Option<&Value>) -> Result<SecretFieldMap, WebRefusal> {
    let mut map = SecretFieldMap::default();
    let Some(v) = v else { return Ok(map) };
    let obj = v.as_object().ok_or_else(|| invalid("credential_source.fields must be an object"))?;
    for (k, val) in obj {
        let name = secret_key(Some(val), &format!("fields.{k}"))?;
        match k.as_str() {
            "username" => map.username = name,
            "password" => map.password = name,
            "totp_seed" => map.totp_seed = name,
            other => {
                return Err(invalid(format!("credential_source.fields.{other} is not a field this server understands")))
            }
        }
    }
    Ok(map)
}

fn credential_source(profile: &Map<String, Value>, mode: &str) -> Result<WebCredentialSource, WebRefusal> {
    let cs = profile
        .get("credential_source")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(format!("a {mode} profile needs a credential_source")))?;
    match cs.get("kind").and_then(Value::as_str).unwrap_or_default() {
        "secret" => Ok(WebCredentialSource::Secret {
            secret_id: secret_key(cs.get("secret_id"), "secret_id")?,
            fields: secret_fields(cs.get("fields"))?,
            totp: TotpParams::parse(cs.get("totp")).map_err(invalid)?,
        }),
        "ldap" => {
            let mount = mount_path(cs.get("ldap_mount"))?;
            match cs.get("bind_mode").and_then(Value::as_str).unwrap_or_default() {
                "static_role" => Ok(WebCredentialSource::LdapStaticRole {
                    mount,
                    role: ldap_name(cs.get("static_role"), "static_role")?,
                }),
                "library_set" => Ok(WebCredentialSource::LdapLibrarySet {
                    mount,
                    set: ldap_name(cs.get("library_set"), "library_set")?,
                }),
                "operator" => Err(refuse(
                    400,
                    "credential_source_unsupported",
                    "ldap bind_mode `operator` means the operator types their own credential, so \
                     there is nothing for the server to release; use `open` mode or a \
                     `default-account` source",
                )),
                _ => Err(invalid("credential_source.bind_mode must be static_role or library_set")),
            }
        }
        "default-account" => Ok(WebCredentialSource::DefaultAccount),
        "none" => Err(refuse(
            400,
            "credential_source_unsupported",
            if mode == "http-auth" {
                "credential_source `none` releases nothing; an http-auth profile needs a secret or ldap source"
            } else {
                "credential_source `none` releases nothing; a form-mode profile needs secret, ldap or default-account"
            },
        )),
        "ssh-engine" | "pki" | "fido2" => Err(refuse(
            400,
            "credential_source_unsupported",
            "ssh-engine, pki and fido2 sources are not valid on a web profile",
        )),
        _ => Err(invalid("credential_source.kind is missing or unknown")),
    }
}

/// The origin key of a full URL (the profile's `start_url`).
fn url_origin(raw: &str, allow_insecure_http: bool) -> Result<String, String> {
    let (scheme, authority, _) = recipe::split_url(raw)?;
    recipe::origin_key(scheme, authority, allow_insecure_http)
}

/// The origin key of a configured `allowed_origins` entry: a bare
/// `scheme://host[:port]`, at most one trailing `/`.
fn bare_origin(raw: &str, allow_insecure_http: bool) -> Result<String, String> {
    let (scheme, authority, rest) = recipe::split_url(raw.trim())?;
    if !(rest.is_empty() || rest == "/") {
        return Err("is not a bare origin (no path, query or fragment)".into());
    }
    recipe::origin_key(scheme, authority, allow_insecure_http)
}

/// Every static check of the launch, in the order an operator would fix them.
/// Nothing here reads a secret or burns a ticket.
pub fn parse_launch_profile(profile: &Value) -> Result<WebLaunchProfile, WebRefusal> {
    let p = profile.as_object().ok_or_else(|| invalid("the profile is not a JSON object"))?;

    match p.get("protocol").and_then(Value::as_str) {
        Some("web") => {}
        _ => {
            return Err(refuse(
                400,
                "wrong_protocol",
                "only a `web` profile can be launched through connect/web/launch",
            ))
        }
    }
    match p.get("kind").and_then(Value::as_str) {
        None | Some("direct") => {}
        Some(_) => {
            return Err(refuse(400, "transport_unavailable", "a web profile with kind `rustion` is not available"))
        }
    }

    let web = p.get("web").and_then(Value::as_object).ok_or_else(|| invalid("the profile has no `web` block"))?;
    let http_auth = match web.get("login_mode").and_then(Value::as_str) {
        Some("form") => false,
        Some("http-auth") => true,
        Some("open") => {
            return Err(refuse(
                400,
                "wrong_login_mode",
                "`open` mode releases no credential; it is authorised by connect/authorize, not launched here",
            ))
        }
        Some("sso") => {
            return Err(refuse(
                400,
                "wrong_login_mode",
                "the `sso` login mode is not available yet; only `form` and `http-auth` launch here",
            ))
        }
        _ => return Err(refuse(400, "wrong_login_mode", "web.login_mode is missing or unknown")),
    };
    let mode = if http_auth { "http-auth" } else { "form" };
    match web.get("transport").filter(|v| !v.is_null()) {
        None => {}
        Some(Value::String(t)) if t == "local" => {}
        Some(Value::String(t)) if t == "rustion-isolated" => {
            return Err(refuse(
                400,
                "transport_unavailable",
                "transport `rustion-isolated` (Rustion browser isolation) is not available; it is never run locally instead",
            ))
        }
        Some(_) => return Err(invalid("web.transport must be `local`")),
    }
    let allow_insecure_http = match web.get("allow_insecure_http") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(invalid("web.allow_insecure_http must be a boolean")),
    };

    let start_url = web.get("start_url").and_then(Value::as_str).ok_or_else(|| invalid("web.start_url is required"))?;
    let mut origins =
        vec![url_origin(start_url, allow_insecure_http).map_err(|r| invalid(format!("web.start_url {r}")))?];
    match web.get("allowed_origins") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for (i, o) in list.iter().enumerate() {
                let raw = o.as_str().ok_or_else(|| invalid(format!("web.allowed_origins[{i}] must be a string")))?;
                let key = bare_origin(raw, allow_insecure_http)
                    .map_err(|r| invalid(format!("web.allowed_origins[{i}] {r}")))?;
                if !origins.contains(&key) {
                    origins.push(key);
                }
            }
        }
        Some(_) => return Err(invalid("web.allowed_origins must be an array")),
    }

    let (login, needs) = if http_auth {
        // No recipe: the host answers challenges, it never fills a page. A
        // recipe left on the profile would make the stored record ambiguous
        // about what was checked, so it is refused rather than ignored.
        if web.get("recipe").is_some_and(|v| !v.is_null()) {
            return Err(invalid(
                "web.recipe applies to the form login mode only; an http-auth profile carries no recipe",
            ));
        }
        (LaunchLogin::HttpAuth, http_auth_needs())
    } else {
        let recipe_value =
            web.get("recipe").ok_or_else(|| refuse(422, "invalid_recipe", "a form-mode profile needs a recipe"))?;
        let (recipe, recipe_hash) =
            recipe::parse_and_hash(recipe_value).map_err(|e| refuse(422, "invalid_recipe", e.to_string()))?;
        recipe
            .check_origins(&origins, allow_insecure_http)
            .map_err(|e| refuse(422, "invalid_recipe", e.to_string()))?;
        let needs = recipe.needs();
        (LaunchLogin::Form { recipe: Box::new(recipe), recipe_hash }, needs)
    };

    let source = credential_source(p, mode)?;
    if http_auth && matches!(source, WebCredentialSource::DefaultAccount) {
        return Err(refuse(
            422,
            "credential_unavailable",
            "a default-account source supplies a username only, and an HTTP authentication challenge needs a \
             username and a password; use a secret or ldap source, or `open` mode and let the operator type it",
        ));
    }
    // What a source can supply is known without reading it; a recipe that
    // fills something the source can never provide is refused before any
    // ticket is burnt or credential read.
    if !needs.heuristic {
        match &source {
            WebCredentialSource::DefaultAccount if needs.password => {
                return Err(refuse(
                    422,
                    "credential_unavailable",
                    "a default-account source supplies a username only; remove the recipe's password fill and let the operator type it",
                ))
            }
            WebCredentialSource::DefaultAccount | WebCredentialSource::LdapStaticRole { .. }
            | WebCredentialSource::LdapLibrarySet { .. }
                if needs.totp =>
            {
                return Err(refuse(
                    422,
                    "totp_not_configured",
                    "the recipe fills `totp`, but only a `secret` source carrying a TOTP seed can supply one",
                ))
            }
            _ => {}
        }
    }

    Ok(WebLaunchProfile {
        require_mfa: crate::kernel_api::engines::profile_gate_flag(profile),
        allow_insecure_http,
        start_url: start_url.to_string(),
        origins,
        login,
        needs,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn form_profile() -> Value {
        json!({
            "id": "p_web",
            "name": "Admin console",
            "protocol": "web",
            "credential_source": { "kind": "secret", "secret_id": "admin" },
            "web": {
                "start_url": "https://fw01.example.com/login",
                "allowed_origins": ["https://sso.example.com/"],
                "login_mode": "form",
                "recipe": {
                    "version": 1,
                    "steps": [
                        { "when_url": "https://fw01.example.com/login*",
                          "actions": [
                            { "fill": "#user", "value": "username" },
                            { "fill": "#pass", "value": "password" },
                            { "submit": "form" }
                          ] },
                        { "when_url": "https://fw01.example.com/2fa*",
                          "actions": [ { "fill": "#otp", "value": "totp" }, { "submit": "form" } ] }
                    ],
                    "success_when": { "url": "https://fw01.example.com/ng/*" }
                }
            }
        })
    }

    fn code(v: &Value) -> &'static str {
        parse_launch_profile(v).unwrap_err().code
    }

    #[test]
    fn a_valid_form_profile_parses() {
        let p = parse_launch_profile(&form_profile()).unwrap();
        assert_eq!(p.origins, vec!["https://fw01.example.com".to_string(), "https://sso.example.com".to_string()]);
        assert!(p.needs.username && p.needs.password && p.needs.totp);
        assert_eq!(p.source.kind(), "secret");
        assert!(!p.require_mfa);
        assert!(p.recipe_hash().unwrap().starts_with("sha256:"));
        assert_eq!(p.login_mode(), "form");
        assert_eq!((p.required_exposure(), p.launched_exposure()), (WebExposure::Dom, WebExposure::Dom));
    }

    #[test]
    fn wrong_protocol_mode_and_transport_are_refused() {
        let mut v = form_profile();
        v["protocol"] = json!("ssh");
        assert_eq!(code(&v), "wrong_protocol");
        let mut v = form_profile();
        v.as_object_mut().unwrap().remove("protocol");
        assert_eq!(code(&v), "wrong_protocol");

        for mode in ["open", "sso", "FORM", "http_auth", "basic"] {
            let mut v = form_profile();
            v["web"]["login_mode"] = json!(mode);
            assert_eq!(code(&v), "wrong_login_mode", "{mode}");
        }
        let mut v = form_profile();
        v["web"]["transport"] = json!("rustion-isolated");
        assert_eq!(code(&v), "transport_unavailable");
        let mut v = form_profile();
        v["kind"] = json!("rustion");
        assert_eq!(code(&v), "transport_unavailable");
        let mut v = form_profile();
        v["web"]["transport"] = json!("local");
        assert!(parse_launch_profile(&v).is_ok());
    }

    #[test]
    fn credential_sources_are_checked_against_the_recipe() {
        let with_source = |cs: Value| {
            let mut v = form_profile();
            v["credential_source"] = cs;
            v
        };
        assert_eq!(code(&with_source(json!({ "kind": "none" }))), "credential_source_unsupported");
        assert_eq!(
            code(&with_source(json!({ "kind": "ssh-engine", "ssh_mount": "ssh", "ssh_role": "r" }))),
            "credential_source_unsupported"
        );
        assert_eq!(code(&with_source(json!({ "kind": "pki" }))), "credential_source_unsupported");
        assert_eq!(code(&with_source(json!({ "kind": "fido2" }))), "credential_source_unsupported");
        assert_eq!(
            code(&with_source(json!({ "kind": "ldap", "ldap_mount": "openldap/", "bind_mode": "operator" }))),
            "credential_source_unsupported"
        );
        assert_eq!(code(&with_source(json!({ "kind": "magic" }))), "invalid_profile");
        // The recipe fills a password a default account can never supply.
        assert_eq!(code(&with_source(json!({ "kind": "default-account" }))), "credential_unavailable");
        // … and a TOTP an LDAP source can never supply.
        assert_eq!(
            code(&with_source(
                json!({ "kind": "ldap", "ldap_mount": "openldap", "bind_mode": "library_set", "library_set": "web-admins" })
            )),
            "totp_not_configured"
        );
        // Path-escaping names are refused before any request is built from them.
        assert_eq!(code(&with_source(json!({ "kind": "secret", "secret_id": "../other/admin" }))), "invalid_profile");
        assert_eq!(
            code(&with_source(
                json!({ "kind": "ldap", "ldap_mount": "../sys", "bind_mode": "library_set", "library_set": "x1" })
            )),
            "invalid_profile"
        );
        assert_eq!(
            code(&with_source(
                json!({ "kind": "ldap", "ldap_mount": "openldap", "bind_mode": "static_role", "static_role": "a/b" })
            )),
            "invalid_profile"
        );
        assert_eq!(
            code(&with_source(json!({ "kind": "secret", "secret_id": "a", "fields": { "otp": "x" } }))),
            "invalid_profile"
        );
        assert_eq!(
            code(&with_source(json!({ "kind": "secret", "secret_id": "a", "totp": { "digits": 7 } }))),
            "invalid_profile"
        );
    }

    #[test]
    fn source_mapping_and_ldap_shapes_parse() {
        let mut v = form_profile();
        v["credential_source"] = json!({
            "kind": "secret", "secret_id": "admin",
            "fields": { "username": "user", "totp_seed": "otp" },
            "totp": { "digits": 8 }
        });
        let p = parse_launch_profile(&v).unwrap();
        let WebCredentialSource::Secret { fields, totp, .. } = p.source else { panic!() };
        assert_eq!(fields.username, "user");
        assert_eq!(fields.password, "password");
        assert_eq!(fields.totp_seed, "otp");
        assert_eq!(totp.digits, 8);

        // A recipe without a totp fill can use an LDAP library set.
        let mut v = form_profile();
        v["web"]["recipe"]["steps"].as_array_mut().unwrap().truncate(1);
        v["credential_source"] = json!({ "kind": "ldap", "ldap_mount": "openldap", "bind_mode": "library_set", "library_set": "web-admins" });
        let p = parse_launch_profile(&v).unwrap();
        assert_eq!(
            p.source,
            WebCredentialSource::LdapLibrarySet { mount: "openldap/".into(), set: "web-admins".into() }
        );
    }

    #[test]
    fn origins_and_recipe_are_validated() {
        let mut v = form_profile();
        v["web"]["start_url"] = json!("http://fw01.example.com/login");
        assert_eq!(code(&v), "invalid_profile");
        let mut v = form_profile();
        v["web"]["allowed_origins"] = json!(["https://sso.example.com/path"]);
        assert_eq!(code(&v), "invalid_profile");
        let mut v = form_profile();
        v["web"]["allow_insecure_http"] = json!("yes");
        assert_eq!(code(&v), "invalid_profile");
        // A step on an origin outside the set.
        let mut v = form_profile();
        v["web"]["recipe"]["steps"][1]["when_url"] = json!("https://evil.example/2fa*");
        assert_eq!(code(&v), "invalid_recipe");
        let mut v = form_profile();
        v["web"]["recipe"]["steps"][1]["when_url"] = json!("https://sso.example.com/2fa*");
        assert!(parse_launch_profile(&v).is_ok(), "an allowed origin is accepted");
        let mut v = form_profile();
        v["web"].as_object_mut().unwrap().remove("recipe");
        assert_eq!(code(&v), "invalid_recipe");
        let mut v = form_profile();
        v["web"]["recipe"]["version"] = json!(9);
        assert_eq!(code(&v), "invalid_recipe");
    }

    #[test]
    fn the_mfa_gate_is_read_off_the_stored_profile() {
        let mut v = form_profile();
        v["require_mfa"] = json!(true);
        assert!(parse_launch_profile(&v).unwrap().require_mfa);
    }
    fn http_auth_profile() -> Value {
        json!({
            "id": "p_basic",
            "name": "Appliance (Basic)",
            "protocol": "web",
            "credential_source": { "kind": "secret", "secret_id": "admin" },
            "web": {
                "start_url": "https://idrac01.example.com/",
                "allowed_origins": ["https://idrac01.example.com:8443"],
                "login_mode": "http-auth"
            }
        })
    }

    #[test]
    fn an_http_auth_profile_parses_without_a_recipe() {
        let p = parse_launch_profile(&http_auth_profile()).unwrap();
        assert!(matches!(p.login, LaunchLogin::HttpAuth));
        assert_eq!(p.login_mode(), "http-auth");
        assert_eq!(p.recipe_hash(), None);
        assert_eq!(
            p.origins,
            vec!["https://idrac01.example.com".to_string(), "https://idrac01.example.com:8443".to_string()]
        );
        // Username and password, never TOTP, and no recipe step.
        assert!(p.needs.username && p.needs.password && !p.needs.totp && !p.needs.heuristic);
        assert!(p.needs.totp_steps.is_empty());
        assert_eq!(p.needs.step_count, 0);
        assert_eq!((p.required_exposure(), p.launched_exposure()), (WebExposure::Handler, WebExposure::Handler));

        // An LDAP static role or library set supplies both parts.
        for cs in [
            json!({ "kind": "ldap", "ldap_mount": "openldap", "bind_mode": "static_role", "static_role": "idrac" }),
            json!({ "kind": "ldap", "ldap_mount": "openldap", "bind_mode": "library_set", "library_set": "bmc-admins" }),
        ] {
            let mut v = http_auth_profile();
            v["credential_source"] = cs;
            assert_eq!(parse_launch_profile(&v).unwrap().source.kind(), "ldap");
        }

        // TOTP settings on the source are read (so a malformed one still
        // refuses) but release nothing.
        let mut v = http_auth_profile();
        v["credential_source"]["totp"] = json!({ "digits": 8 });
        assert!(!parse_launch_profile(&v).unwrap().needs.totp);
        v["credential_source"]["totp"] = json!({ "digits": 7 });
        assert_eq!(code(&v), "invalid_profile");
    }

    #[test]
    fn plain_http_makes_an_http_auth_launch_dom_level() {
        let mut v = http_auth_profile();
        v["web"]["start_url"] = json!("http://idrac01.example.com/");
        // Refused unless the profile opts in …
        assert_eq!(code(&v), "invalid_profile");
        // … and when it does, the launch is `dom`, not `handler` (§6).
        v["web"]["allow_insecure_http"] = json!(true);
        let p = parse_launch_profile(&v).unwrap();
        assert_eq!((p.required_exposure(), p.launched_exposure()), (WebExposure::Handler, WebExposure::Dom));
    }

    #[test]
    fn malformed_http_auth_profiles_are_refused() {
        // A recipe on an http-auth profile is refused, not ignored.
        let mut v = http_auth_profile();
        v["web"]["recipe"] = form_profile()["web"]["recipe"].clone();
        assert_eq!(code(&v), "invalid_profile");
        let mut v = http_auth_profile();
        v["web"]["recipe"] = Value::Null;
        assert!(parse_launch_profile(&v).is_ok(), "a null recipe is no recipe");

        // A default account supplies a username only.
        let mut v = http_auth_profile();
        v["credential_source"] = json!({ "kind": "default-account" });
        assert_eq!(code(&v), "credential_unavailable");
        for (cs, want) in [
            (json!({ "kind": "none" }), "credential_source_unsupported"),
            (json!({ "kind": "fido2" }), "credential_source_unsupported"),
            (
                json!({ "kind": "ldap", "ldap_mount": "openldap", "bind_mode": "operator" }),
                "credential_source_unsupported",
            ),
            (json!({ "kind": "secret", "secret_id": "../x" }), "invalid_profile"),
            (json!({ "kind": "secret", "secret_id": "a", "fields": { "otp": "x" } }), "invalid_profile"),
        ] {
            let mut v = http_auth_profile();
            v["credential_source"] = cs.clone();
            assert_eq!(code(&v), want, "{cs}");
        }
        let mut v = http_auth_profile();
        v.as_object_mut().unwrap().remove("credential_source");
        assert_eq!(code(&v), "invalid_profile");

        // The shared checks still apply.
        for (path, bad) in [
            ("start_url", json!("https://admin:pw@idrac01.example.com/")),
            ("allowed_origins", json!(["https://idrac01.example.com/path"])),
            ("allowed_origins", json!("https://idrac01.example.com")),
            ("allow_insecure_http", json!("yes")),
            ("transport", json!(5)),
        ] {
            let mut v = http_auth_profile();
            v["web"][path] = bad.clone();
            assert_eq!(code(&v), "invalid_profile", "{path} = {bad}");
        }
        let mut v = http_auth_profile();
        v["web"]["transport"] = json!("rustion-isolated");
        assert_eq!(code(&v), "transport_unavailable");
        let mut v = http_auth_profile();
        v["web"]["login_mode"] = json!(["http-auth"]);
        assert_eq!(code(&v), "wrong_login_mode");
    }
}
