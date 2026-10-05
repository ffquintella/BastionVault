//! The login recipe of `features/web-application-connect.md` §2 — the
//! versioned, declarative format a `form`-mode `web` profile carries.
//!
//! The server parses it for two reasons, both security decisions:
//!
//!   1. **Exposure and heuristics.** `"steps": "auto"` is heuristic mode, which
//!      policy must allow (§6), and the values a recipe fills decide which
//!      parts of the credential the launch releases at all.
//!   2. **Binding.** The launch is bound to the recipe's hash, so the recipe
//!      the host runs is the recipe the server checked.
//!
//! Parsing is strict and fails closed: an unknown version, an unknown key at
//! any level, a non-enum value, or an out-of-range size is a refusal, never a
//! default. The format is also the contract Phase 8 shares with Rustion, so
//! every rule here is one a second implementation can reproduce.
//!
//! This module is `pub` so the desktop host can reuse the same parser and the
//! same [`recipe_hash`] rather than re-deriving either.

use std::fmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The only recipe version this server understands.
pub const RECIPE_VERSION: u64 = 1;
pub const MAX_STEPS: usize = 16;
pub const MAX_ACTIONS_PER_STEP: usize = 32;
pub const MAX_SELECTOR_LEN: usize = 512;
pub const MAX_URL_PATTERN_LEN: usize = 2048;
pub const MAX_LITERAL_LEN: usize = 256;
/// Upper bound on `timeout_secs`. Equal to the launch's login window
/// ([`super::launch_store::LOGIN_WINDOW_SECS`]), so a recipe can never be
/// still waiting for a TOTP refresh after the server stopped issuing them.
pub const MAX_TIMEOUT_SECS: u64 = 60;
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// The `web_application.vendor` enum (§1). `vendor` on a recipe names the
/// preset its steps came from; it is informational and never changes what the
/// steps do.
pub const VENDORS: &[&str] =
    &["generic", "fortigate", "vcenter", "idrac", "ilo", "pfsense", "grafana", "jenkins", "other"];

const TOP_LEVEL_KEYS: &[&str] =
    &["version", "vendor", "steps", "success_when", "failure_when", "timeout_secs", "pause_for_operator"];

/// What a `fill` action writes into a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillValue {
    Username,
    Password,
    Totp,
    /// `literal:<text>` — a fixed, non-secret value (a realm, a tenant id).
    Literal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipeAction {
    Fill {
        selector: String,
        value: FillValue,
    },
    Click {
        selector: String,
    },
    Submit {
        selector: String,
    },
    /// Wait (up to `timeout_secs`) for `selector` to appear.
    Wait {
        selector: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeStep {
    /// Glob over the host-observed top-frame URL. Only `*` is special, and
    /// never inside the origin, which is matched exactly.
    pub when_url: String,
    pub actions: Vec<RecipeAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipeSteps {
    Explicit(Vec<RecipeStep>),
    /// `"steps": "auto"` — the host finds fields by `autocomplete`. Allowed
    /// only where policy sets `allow_heuristic_fill` (§6).
    Heuristic,
}

/// `success_when` / `failure_when`: a URL glob, a selector, or both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecipeCondition {
    pub url: Option<String>,
    pub selector: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    Captcha,
    PushMfa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebLoginRecipe {
    pub version: u64,
    pub vendor: Option<String>,
    pub steps: RecipeSteps,
    pub success_when: RecipeCondition,
    pub failure_when: Option<RecipeCondition>,
    pub timeout_secs: u64,
    pub pause_for_operator: Vec<PauseReason>,
}

/// Which parts of a credential a recipe consumes. The launch releases nothing
/// the recipe does not fill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeNeeds {
    /// Heuristic mode: each value is wanted *if the source has it* rather
    /// than required.
    pub heuristic: bool,
    pub username: bool,
    pub password: bool,
    pub totp: bool,
    /// Step indexes that fill `totp` — each may ask `v2/connect/web/totp` for
    /// one fresh code. Heuristic mode has a single implicit step, `0`.
    pub totp_steps: Vec<u32>,
    /// Number of steps (`1` for heuristic mode).
    pub step_count: u32,
}

/// Why a recipe was refused. `at` is a JSON-path-like location
/// (`steps[1].actions[0].value`), never the offending value itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeError {
    pub at: String,
    pub reason: String,
}

impl fmt::Display for RecipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.at.is_empty() {
            write!(f, "recipe: {}", self.reason)
        } else {
            write!(f, "recipe `{}`: {}", self.at, self.reason)
        }
    }
}

fn err(at: impl Into<String>, reason: impl Into<String>) -> RecipeError {
    RecipeError { at: at.into(), reason: reason.into() }
}

fn join(at: &str, key: &str) -> String {
    if at.is_empty() {
        key.to_string()
    } else {
        format!("{at}.{key}")
    }
}

fn reject_unknown(obj: &Map<String, Value>, at: &str, allowed: &[&str]) -> Result<(), RecipeError> {
    // Report the first unknown key in sorted order so the error is stable
    // whatever map ordering serde_json was built with.
    let mut unknown: Vec<&String> = obj.keys().filter(|k| !allowed.contains(&k.as_str())).collect();
    unknown.sort();
    match unknown.first() {
        Some(k) => Err(err(join(at, k), "is not a recipe field this server understands")),
        None => Ok(()),
    }
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn selector(v: Option<&Value>, at: &str) -> Result<String, RecipeError> {
    let s = v.and_then(Value::as_str).ok_or_else(|| err(at, "must be a CSS selector string"))?;
    if s.trim().is_empty() {
        return Err(err(at, "must not be empty"));
    }
    if s.len() > MAX_SELECTOR_LEN {
        return Err(err(at, format!("is longer than {MAX_SELECTOR_LEN} bytes")));
    }
    if has_control(s) {
        return Err(err(at, "must not contain control characters"));
    }
    Ok(s.to_string())
}

fn fill_value(v: Option<&Value>, at: &str) -> Result<FillValue, RecipeError> {
    let s = v
        .and_then(Value::as_str)
        .ok_or_else(|| err(at, "is required: one of `username`, `password`, `totp` or `literal:<text>`"))?;
    match s {
        "username" => Ok(FillValue::Username),
        "password" => Ok(FillValue::Password),
        "totp" => Ok(FillValue::Totp),
        _ => {
            let Some(text) = s.strip_prefix("literal:") else {
                return Err(err(at, "must be one of `username`, `password`, `totp` or `literal:<text>`"));
            };
            if text.is_empty() || text.len() > MAX_LITERAL_LEN || has_control(text) {
                return Err(err(
                    at,
                    format!("a literal must be 1..={MAX_LITERAL_LEN} bytes with no control characters"),
                ));
            }
            Ok(FillValue::Literal(text.to_string()))
        }
    }
}

/// Split `scheme://authority[/…]` without interpreting it. Refuses the shapes
/// a WHATWG parser would read differently from a naive one (backslashes,
/// whitespace, control characters), so this conservative reading can only
/// ever be *stricter* than the host's — never looser.
pub(crate) fn split_url(raw: &str) -> Result<(&str, &str, &str), String> {
    if raw.is_empty() {
        return Err("is empty".into());
    }
    if raw.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
        return Err("must not contain whitespace, control characters or backslashes".into());
    }
    let (scheme, rest) = raw.split_once("://").ok_or_else(|| "must be an absolute https:// URL".to_string())?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Ok((scheme, &rest[..end], &rest[end..]))
}

/// Normalise `(scheme, authority)` into the exact origin key
/// `scheme://host[:port]` — lower-case host, default port dropped.
///
/// Deliberately narrower than the URL standard: a non-ASCII host, a
/// percent-encoded host, userinfo, a wildcard, a trailing dot or any character
/// outside `[a-z0-9._-]` (bracketed IPv6 aside) is refused outright. The host
/// re-checks every origin with a full WHATWG parser at fill time, so a refusal
/// here costs an operator an edit, while an over-permissive reading here would
/// be a parser differential on an anti-phishing check.
pub(crate) fn origin_key(scheme: &str, authority: &str, allow_insecure_http: bool) -> Result<String, String> {
    let default_port = match scheme {
        "https" => 443,
        "http" if allow_insecure_http => 80,
        "http" => return Err("plain http is refused unless the profile sets allow_insecure_http".into()),
        _ => return Err("scheme must be `https` (or `http` with allow_insecure_http)".into()),
    };
    if authority.is_empty() {
        return Err("has no host".into());
    }
    if !authority.is_ascii() {
        return Err("has a non-ASCII host; write it in its punycode (`xn--…`) form".into());
    }
    if authority.contains(['@', '*', '%']) {
        return Err("origin must be a literal host (no userinfo, wildcard or percent-encoding)".into());
    }
    let lower = authority.to_ascii_lowercase();
    let (host, port) = if let Some(rest) = lower.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| "has an unterminated IPv6 literal".to_string())?;
        let inner = &rest[..close];
        if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.') {
            return Err("has a malformed IPv6 literal".into());
        }
        let after = &rest[close + 1..];
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or_else(|| "has junk after the IPv6 literal".to_string())?),
        };
        (format!("[{inner}]"), port)
    } else {
        let (host, port) = match lower.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (lower.clone(), None),
        };
        if host.is_empty() {
            return Err("has no host".into());
        }
        if host.ends_with('.') {
            return Err("host has a trailing dot; browsers treat it as a different origin".into());
        }
        if !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
            return Err("host has characters outside [a-z0-9._-]".into());
        }
        (host, port)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
                return Err("has a malformed port".into());
            }
            let n: u16 = p.parse().map_err(|_| "port is out of range".to_string())?;
            (n != default_port).then_some(n)
        }
    };
    Ok(match port {
        Some(n) => format!("{scheme}://{host}:{n}"),
        None => format!("{scheme}://{host}"),
    })
}

fn url_pattern(v: Option<&Value>, at: &str) -> Result<String, RecipeError> {
    let s = v.and_then(Value::as_str).ok_or_else(|| err(at, "must be a URL pattern string"))?;
    if s.len() > MAX_URL_PATTERN_LEN {
        return Err(err(at, format!("is longer than {MAX_URL_PATTERN_LEN} bytes")));
    }
    let (scheme, authority, _) = split_url(s).map_err(|r| err(at, r))?;
    if scheme != "https" && scheme != "http" {
        return Err(err(at, "must start with https:// (or http:// with allow_insecure_http)"));
    }
    if authority.is_empty() || authority.contains(['*', '@']) {
        return Err(err(at, "its origin must be literal: `*` may appear only after the host, and userinfo is refused"));
    }
    Ok(s.to_string())
}

fn condition(v: &Value, at: &str) -> Result<RecipeCondition, RecipeError> {
    let obj = v.as_object().ok_or_else(|| err(at, "must be an object with `url` and/or `selector`"))?;
    reject_unknown(obj, at, &["url", "selector"])?;
    let url = match obj.get("url") {
        None => None,
        some => Some(url_pattern(some, &join(at, "url"))?),
    };
    let selector = match obj.get("selector") {
        None => None,
        some => Some(selector(some, &join(at, "selector"))?),
    };
    if url.is_none() && selector.is_none() {
        return Err(err(at, "needs a `url`, a `selector`, or both"));
    }
    Ok(RecipeCondition { url, selector })
}

fn action(v: &Value, at: &str) -> Result<RecipeAction, RecipeError> {
    let obj = v.as_object().ok_or_else(|| err(at, "must be an object"))?;
    let verbs: Vec<&str> = ["fill", "click", "submit", "wait"].into_iter().filter(|k| obj.contains_key(*k)).collect();
    let [verb] = verbs.as_slice() else {
        return Err(err(at, "must carry exactly one of `fill`, `click`, `submit` or `wait`"));
    };
    match *verb {
        "fill" => {
            reject_unknown(obj, at, &["fill", "value"])?;
            Ok(RecipeAction::Fill {
                selector: selector(obj.get("fill"), &join(at, "fill"))?,
                value: fill_value(obj.get("value"), &join(at, "value"))?,
            })
        }
        other => {
            reject_unknown(obj, at, &[other])?;
            let s = selector(obj.get(other), &join(at, other))?;
            Ok(match other {
                "click" => RecipeAction::Click { selector: s },
                "submit" => RecipeAction::Submit { selector: s },
                _ => RecipeAction::Wait { selector: s },
            })
        }
    }
}

fn step(v: &Value, at: &str) -> Result<RecipeStep, RecipeError> {
    let obj = v.as_object().ok_or_else(|| err(at, "must be an object"))?;
    reject_unknown(obj, at, &["when_url", "actions"])?;
    let when_url = url_pattern(obj.get("when_url"), &join(at, "when_url"))?;
    let actions_at = join(at, "actions");
    let list = obj
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| err(&actions_at, "is required and must be an array"))?;
    if list.is_empty() || list.len() > MAX_ACTIONS_PER_STEP {
        return Err(err(&actions_at, format!("must hold 1..={MAX_ACTIONS_PER_STEP} actions")));
    }
    let actions = list
        .iter()
        .enumerate()
        .map(|(i, a)| action(a, &format!("{actions_at}[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RecipeStep { when_url, actions })
}

impl WebLoginRecipe {
    /// Strictly parse a recipe value as stored on the profile.
    pub fn parse(value: &Value) -> Result<Self, RecipeError> {
        let obj = value.as_object().ok_or_else(|| err("", "must be a JSON object"))?;

        // The version is read before anything else, so a later format never
        // half-parses as this one.
        let version = obj
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| err("version", "is required and must be an integer"))?;
        if version != RECIPE_VERSION {
            return Err(err(
                "version",
                format!(
                    "recipe version {version} is not supported; this server understands version {RECIPE_VERSION} only"
                ),
            ));
        }
        reject_unknown(obj, "", TOP_LEVEL_KEYS)?;

        let vendor = match obj.get("vendor") {
            None => None,
            Some(Value::String(v)) if VENDORS.contains(&v.as_str()) => Some(v.clone()),
            Some(_) => return Err(err("vendor", format!("must be one of {}", VENDORS.join(", ")))),
        };

        let steps = match obj.get("steps") {
            Some(Value::String(s)) if s == "auto" => RecipeSteps::Heuristic,
            Some(Value::Array(list)) => {
                if list.is_empty() || list.len() > MAX_STEPS {
                    return Err(err("steps", format!("must hold 1..={MAX_STEPS} steps")));
                }
                RecipeSteps::Explicit(
                    list.iter()
                        .enumerate()
                        .map(|(i, s)| step(s, &format!("steps[{i}]")))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            _ => return Err(err("steps", "is required: an array of steps, or the string \"auto\"")),
        };

        let success_when =
            condition(obj.get("success_when").ok_or_else(|| err("success_when", "is required"))?, "success_when")?;
        let failure_when = match obj.get("failure_when") {
            None => None,
            Some(v) => Some(condition(v, "failure_when")?),
        };

        let timeout_secs = match obj.get("timeout_secs") {
            None => DEFAULT_TIMEOUT_SECS,
            Some(v) => match v.as_u64() {
                Some(n) if (1..=MAX_TIMEOUT_SECS).contains(&n) => n,
                _ => return Err(err("timeout_secs", format!("must be an integer in 1..={MAX_TIMEOUT_SECS}"))),
            },
        };

        let pause_for_operator = match obj.get("pause_for_operator") {
            None => Vec::new(),
            Some(Value::Array(list)) => list
                .iter()
                .enumerate()
                .map(|(i, v)| match v.as_str() {
                    Some("captcha") => Ok(PauseReason::Captcha),
                    Some("push_mfa") => Ok(PauseReason::PushMfa),
                    _ => Err(err(format!("pause_for_operator[{i}]"), "must be `captcha` or `push_mfa`")),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(err("pause_for_operator", "must be an array")),
        };

        Ok(Self { version, vendor, steps, success_when, failure_when, timeout_secs, pause_for_operator })
    }

    /// Which credential parts the recipe fills.
    pub fn needs(&self) -> RecipeNeeds {
        match &self.steps {
            RecipeSteps::Heuristic => RecipeNeeds {
                heuristic: true,
                username: true,
                password: true,
                totp: true,
                totp_steps: vec![0],
                step_count: 1,
            },
            RecipeSteps::Explicit(steps) => {
                let mut needs = RecipeNeeds {
                    heuristic: false,
                    username: false,
                    password: false,
                    totp: false,
                    totp_steps: Vec::new(),
                    step_count: steps.len() as u32,
                };
                for (i, s) in steps.iter().enumerate() {
                    let mut step_fills_totp = false;
                    for a in &s.actions {
                        if let RecipeAction::Fill { value, .. } = a {
                            match value {
                                FillValue::Username => needs.username = true,
                                FillValue::Password => needs.password = true,
                                FillValue::Totp => step_fills_totp = true,
                                FillValue::Literal(_) => {}
                            }
                        }
                    }
                    if step_fills_totp {
                        needs.totp = true;
                        needs.totp_steps.push(i as u32);
                    }
                }
                needs
            }
        }
    }

    /// §2: every URL the recipe matches on must be on an origin of the
    /// profile's set, over https unless the profile allows plain http.
    /// `origins` holds keys produced by [`origin_key`].
    pub fn check_origins(&self, origins: &[String], allow_insecure_http: bool) -> Result<(), RecipeError> {
        let mut urls: Vec<(String, &str)> = Vec::new();
        if let RecipeSteps::Explicit(steps) = &self.steps {
            for (i, s) in steps.iter().enumerate() {
                urls.push((format!("steps[{i}].when_url"), s.when_url.as_str()));
            }
        }
        if let Some(u) = &self.success_when.url {
            urls.push(("success_when.url".into(), u.as_str()));
        }
        if let Some(u) = self.failure_when.as_ref().and_then(|c| c.url.as_ref()) {
            urls.push(("failure_when.url".into(), u.as_str()));
        }
        for (at, url) in urls {
            let (scheme, authority, _) = split_url(url).map_err(|r| err(&at, r))?;
            let key = origin_key(scheme, authority, allow_insecure_http).map_err(|r| err(&at, r))?;
            if !origins.contains(&key) {
                return Err(err(&at, "its origin is not the start URL's origin or one of allowed_origins"));
            }
        }
        Ok(())
    }
}

/// `sha256:<hex>` of the recipe's canonical JSON.
///
/// Canonical form is RFC 8785 (JCS) for the value space a valid recipe can
/// hold: object keys sorted by UTF-16 code units, no insignificant
/// whitespace, strings escaped as `serde_json` escapes them (which matches JCS
/// for every code point), integers in plain decimal. A non-integer number is
/// refused — no valid recipe carries one — so the float-formatting half of JCS
/// never arises. Hash the value *as stored*, after [`WebLoginRecipe::parse`]
/// accepted it.
pub fn recipe_hash(value: &Value) -> Result<String, RecipeError> {
    let mut out = String::new();
    canonical_json(value, &mut out)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(out.as_bytes()))))
}

/// Parse and hash in one step, the order every caller needs.
pub fn parse_and_hash(value: &Value) -> Result<(WebLoginRecipe, String), RecipeError> {
    let recipe = WebLoginRecipe::parse(value)?;
    Ok((recipe, recipe_hash(value)?))
}

fn canonical_json(v: &Value, out: &mut String) -> Result<(), RecipeError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                return Err(err("", "non-integer numbers have no canonical form here"));
            }
        }
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).map_err(|e| err("", format!("string encoding failed: {e}")))?)
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).map_err(|e| err("", format!("key encoding failed: {e}")))?);
                out.push(':');
                canonical_json(&map[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fortigate() -> Value {
        json!({
            "version": 1,
            "vendor": "fortigate",
            "steps": [
                { "when_url": "https://fw01.example.com/login*",
                  "actions": [
                    { "fill": "input[name=username]", "value": "username" },
                    { "fill": "input[name=secretkey]", "value": "password" },
                    { "click": "button#login_button" }
                  ] },
                { "when_url": "https://fw01.example.com/login/2fa*",
                  "actions": [
                    { "fill": "input[autocomplete=one-time-code]", "value": "totp" },
                    { "submit": "form" }
                  ] }
            ],
            "success_when": { "url": "https://fw01.example.com/ng/*" },
            "failure_when": { "selector": ".error-message, .login-error" },
            "timeout_secs": 30,
            "pause_for_operator": ["captcha"]
        })
    }

    #[test]
    fn spec_example_parses_and_reports_its_needs() {
        let r = WebLoginRecipe::parse(&fortigate()).unwrap();
        assert_eq!(r.version, 1);
        assert_eq!(r.timeout_secs, 30);
        assert_eq!(r.pause_for_operator, vec![PauseReason::Captcha]);
        let n = r.needs();
        assert!(!n.heuristic && n.username && n.password && n.totp);
        assert_eq!(n.totp_steps, vec![1]);
        assert_eq!(n.step_count, 2);
    }

    #[test]
    fn heuristic_mode_is_recognised() {
        let r = WebLoginRecipe::parse(&json!({
            "version": 1, "steps": "auto", "success_when": { "selector": "#dashboard" }
        }))
        .unwrap();
        assert_eq!(r.steps, RecipeSteps::Heuristic);
        assert_eq!(r.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert!(r.needs().heuristic);
        assert_eq!(r.needs().totp_steps, vec![0]);
    }

    #[test]
    fn unknown_versions_and_fields_are_refused() {
        let mut v = fortigate();
        v["version"] = json!(2);
        assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, "version");

        let mut v = fortigate();
        v["version"] = json!(1.0);
        assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, "version");

        let mut v = fortigate();
        v.as_object_mut().unwrap().remove("version");
        assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, "version");

        let mut v = fortigate();
        v["script"] = json!("alert(1)");
        assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, "script");

        let mut v = fortigate();
        v["steps"][0]["frame_origin"] = json!("https://x");
        assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, "steps[0].frame_origin");

        let mut v = fortigate();
        v["steps"][0]["actions"][0]["eval"] = json!("x");
        assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, "steps[0].actions[0].eval");

        let mut v = fortigate();
        v["success_when"]["title"] = json!("x");
        assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, "success_when.title");
    }

    #[test]
    fn malformed_values_are_refused() {
        let cases: Vec<(Value, &str)> = vec![
            (json!("not an object"), ""),
            (json!({"version": 1, "steps": "manual", "success_when": {"selector": "x"}}), "steps"),
            (json!({"version": 1, "steps": [], "success_when": {"selector": "x"}}), "steps"),
            (json!({"version": 1, "steps": "auto"}), "success_when"),
            (json!({"version": 1, "steps": "auto", "success_when": {}}), "success_when"),
            (json!({"version": 1, "steps": "auto", "success_when": {"selector": "x"}, "vendor": "acme"}), "vendor"),
            (
                json!({"version": 1, "steps": "auto", "success_when": {"selector": "x"}, "timeout_secs": 0}),
                "timeout_secs",
            ),
            (
                json!({"version": 1, "steps": "auto", "success_when": {"selector": "x"}, "timeout_secs": 61}),
                "timeout_secs",
            ),
            (
                json!({"version": 1, "steps": "auto", "success_when": {"selector": "x"}, "timeout_secs": "30"}),
                "timeout_secs",
            ),
            (
                json!({"version": 1, "steps": "auto", "success_when": {"selector": "x"}, "pause_for_operator": ["sms"]}),
                "pause_for_operator[0]",
            ),
        ];
        for (v, at) in cases {
            assert_eq!(WebLoginRecipe::parse(&v).unwrap_err().at, at, "{v}");
        }
    }

    #[test]
    fn actions_must_be_one_known_verb_with_enum_values() {
        let with_action = |a: Value| {
            let mut v = fortigate();
            v["steps"][0]["actions"] = json!([a]);
            WebLoginRecipe::parse(&v)
        };
        // Two verbs at once, and none at all.
        assert!(with_action(json!({"fill": "a", "click": "b", "value": "username"})).is_err());
        assert!(with_action(json!({"value": "username"})).is_err());
        // `value` is an enum: free text, a secret name and an empty literal are refused.
        assert!(with_action(json!({"fill": "a", "value": "hunter2"})).is_err());
        assert!(with_action(json!({"fill": "a", "value": "totp_seed"})).is_err());
        assert!(with_action(json!({"fill": "a", "value": "literal:"})).is_err());
        assert!(with_action(json!({"fill": "a"})).is_err());
        // `value` belongs to fill only.
        assert!(with_action(json!({"click": "a", "value": "username"})).is_err());
        // Selectors are bounded data.
        assert!(with_action(json!({"click": ""})).is_err());
        assert!(with_action(json!({"click": "a\nb"})).is_err());
        assert!(with_action(json!({"click": "a".repeat(MAX_SELECTOR_LEN + 1)})).is_err());
        assert!(with_action(json!({"click": 7})).is_err());
        // Literals are accepted and carried verbatim.
        let r = with_action(json!({"fill": "#realm", "value": "literal:CORP"})).unwrap();
        let RecipeSteps::Explicit(steps) = r.steps else { panic!() };
        assert_eq!(
            steps[0].actions[0],
            RecipeAction::Fill { selector: "#realm".into(), value: FillValue::Literal("CORP".into()) }
        );
    }

    #[test]
    fn when_url_origin_must_be_literal() {
        let with_url = |u: &str| {
            let mut v = fortigate();
            v["steps"][0]["when_url"] = json!(u);
            WebLoginRecipe::parse(&v)
        };
        assert!(with_url("https://*.example.com/login").is_err());
        assert!(with_url("https://user@fw01.example.com/login").is_err());
        assert!(with_url("https:\\\\evil.example/").is_err());
        assert!(with_url("javascript:alert(1)").is_err());
        assert!(with_url("ftp://fw01.example.com/").is_err());
        assert!(with_url("https://fw01.example.com /x").is_err());
        assert!(with_url("https://fw01.example.com/login?next=*").is_ok());
    }

    #[test]
    fn origin_key_normalises_and_refuses_ambiguity() {
        assert_eq!(origin_key("https", "FW01.Example.com:443", false).unwrap(), "https://fw01.example.com");
        assert_eq!(origin_key("https", "fw01.example.com:0443", false).unwrap(), "https://fw01.example.com");
        assert_eq!(origin_key("https", "fw01.example.com:8443", false).unwrap(), "https://fw01.example.com:8443");
        assert_eq!(origin_key("https", "[::1]:8443", false).unwrap(), "https://[::1]:8443");
        assert_eq!(origin_key("http", "app:80", true).unwrap(), "http://app");
        for bad in [
            "fw01.example.com.",
            "bücher.example",
            "exa%6dple.com",
            "a@b",
            "*.x",
            "h:",
            "h:99999",
            "h:12a",
            "[::1",
            "[]",
            "a b",
        ] {
            assert!(origin_key("https", bad, false).is_err(), "{bad}");
        }
        assert!(origin_key("http", "app", false).is_err(), "http needs allow_insecure_http");
        assert!(origin_key("ftp", "app", true).is_err());
    }

    #[test]
    fn check_origins_enforces_the_profile_set_and_scheme() {
        let r = WebLoginRecipe::parse(&fortigate()).unwrap();
        let set = vec!["https://fw01.example.com".to_string()];
        assert!(r.check_origins(&set, false).is_ok());
        let other = vec!["https://fw02.example.com".to_string()];
        assert_eq!(r.check_origins(&other, false).unwrap_err().at, "steps[0].when_url");

        let mut v = fortigate();
        v["success_when"]["url"] = json!("http://fw01.example.com/ng/*");
        let r = WebLoginRecipe::parse(&v).unwrap();
        // Plain http on a recipe URL is refused without allow_insecure_http …
        assert_eq!(r.check_origins(&set, false).unwrap_err().at, "success_when.url");
        // … and with it, the http origin must itself be in the set.
        assert!(r.check_origins(&set, true).is_err());
        let both = vec!["https://fw01.example.com".to_string(), "http://fw01.example.com".to_string()];
        assert!(r.check_origins(&both, true).is_ok());
    }

    #[test]
    fn recipe_hash_is_canonical_over_key_order_and_whitespace() {
        let a = fortigate();
        let b: Value = serde_json::from_str(
            r#"{ "timeout_secs":30, "pause_for_operator":["captcha"], "failure_when":{"selector":".error-message, .login-error"},
                 "success_when":{"url":"https://fw01.example.com/ng/*"}, "vendor":"fortigate",
                 "steps":[{"actions":[{"value":"username","fill":"input[name=username]"},
                                      {"value":"password","fill":"input[name=secretkey]"},
                                      {"click":"button#login_button"}],
                           "when_url":"https://fw01.example.com/login*"},
                          {"actions":[{"value":"totp","fill":"input[autocomplete=one-time-code]"},{"submit":"form"}],
                           "when_url":"https://fw01.example.com/login/2fa*"}],
                 "version":1 }"#,
        )
        .unwrap();
        let ha = recipe_hash(&a).unwrap();
        assert!(ha.starts_with("sha256:") && ha.len() == 7 + 64);
        assert_eq!(ha, recipe_hash(&b).unwrap());

        // Any semantic change moves the hash.
        let mut c = fortigate();
        c["steps"][0]["actions"][1]["fill"] = json!("input[name=other]");
        assert_ne!(ha, recipe_hash(&c).unwrap());
    }

    #[test]
    fn canonical_form_matches_jcs_for_the_recipe_value_space() {
        let mut out = String::new();
        canonical_json(&json!({"b": [1, "x\u{1}\"\\"], "a": {"d": true, "c": null}, "é": 0}), &mut out).unwrap();
        assert_eq!(out, r#"{"a":{"c":null,"d":true},"b":[1,"x\u0001\"\\"],"é":0}"#);
        // Floats have no canonical form here.
        assert!(canonical_json(&json!({"x": 1.5}), &mut String::new()).is_err());
    }
}
