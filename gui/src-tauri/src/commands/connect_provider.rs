//! Credential providers at Connect — the desktop host's half
//! (`features/self-accounts.md` §6, T103 Phase 4).
//!
//! A connection profile whose `credential_source` is
//! `{"kind": "provider", "provider": "<plugin>"}` takes its credential from
//! one of the connecting operator's own accounts in an approved
//! credential-provider plugin. This module is what the host does with one:
//!
//! * [`connect_credential_providers`] — the providers a profile can name, for
//!   the profile editor (`GET resources/v2/connect/providers`).
//! * [`connect_provider_candidates`] — the accounts the operator may pick for
//!   one profile (`POST resources/v2/connect/provider/candidates`). Metadata
//!   only, and every string is checked here before it reaches the webview:
//!   a candidate whose text could not be shown as plain text is hidden, not
//!   repaired.
//! * [`authorize_provider_direct`] — the release on the direct SSH / RDP path
//!   (`POST resources/v2/connect/authorize` with `provider_account_id`). The
//!   credential moves into `Zeroizing` buffers here, is handed to the session
//!   that dials, and never crosses to JS. No command in this module returns
//!   secret material.
//! * [`DialPlan`] / [`dial_in_order`] — which hosts a direct open may dial. A
//!   provider credential is released for **one** target (the `target` the
//!   `authorize` response carries), so a provider launch dials exactly that
//!   target and never falls back to another host candidate, not even on a
//!   network-layer error: a resource whose IP matches the account's binding
//!   and whose hostname is hostile would otherwise receive the credential.
//!
//! The rustion route (`rustion/v2/session/open`) and the web route
//! (`resources/v2/connect/web/launch`) only carry `provider_account_id` from
//! here; the server releases there, and seals (rustion) or hands the fill
//! values to the web launcher (web).

use std::future::Future;

use bastion_vault::kernel_api::provider::{MAX_PASSWORD_LEN, MAX_PRIVATE_KEY_LEN, MAX_TEXT_LEN};
use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;
use zeroize::Zeroizing;

use crate::commands::make_request;
use crate::error::{CmdResult, CommandError};
use crate::session::ssh::SshCredential;
use crate::state::AppState;

const RESOURCE_MOUNT: &str = "resources/";

/// Longest `provider_account_id` the server accepts.
const MAX_ACCOUNT_ID_LEN: usize = 128;
/// Longest provider (plugin) name a profile may carry, as the server reads it.
const MAX_PROVIDER_NAME_LEN: usize = 128;
/// The manifest's bound on `credential_provider.display_name`.
const MAX_DISPLAY_NAME_CHARS: usize = 64;
/// Most candidates the picker is handed; the rest are counted as hidden. The
/// plugin's own per-user cap is 25 by default.
const MAX_CANDIDATES: usize = 256;
/// Longest origin a web target may list.
const MAX_ORIGIN_LEN: usize = 2048;

// ── Text the webview may show ──────────────────────────────────────

/// Code points that are not shown as themselves, by category (Unicode 16.0):
/// every `Cf` format character (bidirectional marks, overrides and isolates,
/// zero-width spaces and joiners, the soft hyphen, the BOM, interlinear
/// annotation marks, tags), the `Zl` / `Zp` line and paragraph separators,
/// and every other `Default_Ignorable_Code_Point` (variation selectors, the
/// combining grapheme joiner, the Hangul and Khmer fillers, the reserved
/// ignorable ranges). Sorted, inclusive. `Cc` controls are `char::is_control`.
const INVISIBLE_RANGES: &[(char, char)] = &[
    ('\u{00AD}', '\u{00AD}'),   // Cf soft hyphen
    ('\u{034F}', '\u{034F}'),   // combining grapheme joiner
    ('\u{0600}', '\u{0605}'),   // Cf Arabic number signs
    ('\u{061C}', '\u{061C}'),   // Cf Arabic letter mark
    ('\u{06DD}', '\u{06DD}'),   // Cf
    ('\u{070F}', '\u{070F}'),   // Cf
    ('\u{0890}', '\u{0891}'),   // Cf
    ('\u{08E2}', '\u{08E2}'),   // Cf
    ('\u{115F}', '\u{1160}'),   // Hangul choseong / jungseong fillers
    ('\u{17B4}', '\u{17B5}'),   // Khmer inherent vowels
    ('\u{180B}', '\u{180F}'),   // Mongolian variation selectors, Cf vowel separator
    ('\u{200B}', '\u{200F}'),   // Cf zero-width space / joiners, LRM, RLM
    ('\u{2028}', '\u{2029}'),   // Zl, Zp
    ('\u{202A}', '\u{202E}'),   // Cf bidi embeddings and overrides
    ('\u{2060}', '\u{206F}'),   // Cf word joiner, invisible operators, isolates, deprecated formats
    ('\u{3164}', '\u{3164}'),   // Hangul filler
    ('\u{FE00}', '\u{FE0F}'),   // variation selectors
    ('\u{FEFF}', '\u{FEFF}'),   // Cf BOM / zero-width no-break space
    ('\u{FFA0}', '\u{FFA0}'),   // halfwidth Hangul filler
    ('\u{FFF0}', '\u{FFFB}'),   // reserved ignorables, Cf interlinear annotation
    ('\u{110BD}', '\u{110BD}'), // Cf
    ('\u{110CD}', '\u{110CD}'), // Cf
    ('\u{13430}', '\u{1343F}'), // Cf Egyptian hieroglyph format controls
    ('\u{1BCA0}', '\u{1BCA3}'), // Cf shorthand format controls
    ('\u{1D173}', '\u{1D17A}'), // Cf musical symbol format controls
    ('\u{E0000}', '\u{E0FFF}'), // Cf tags, variation selectors supplement, reserved ignorables
];

/// Whether `c` changes how surrounding text is *displayed* without being
/// visible itself. A label carrying one could render as another account's
/// name (or move a host name in a session label), so it is refused outright.
fn is_display_control(c: char) -> bool {
    c.is_control() || INVISIBLE_RANGES.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// A metadata string the picker may render as plain text: no control or
/// invisible formatting characters, not blank, at most `max_chars`
/// characters. `None` when it fails any of these — never a repaired copy.
pub(crate) fn display_text(raw: &str, max_chars: usize) -> Option<String> {
    if raw.trim().is_empty() || raw.chars().count() > max_chars || raw.chars().any(is_display_control) {
        return None;
    }
    Some(raw.to_string())
}

/// A credential-provider (plugin) name as a profile may name it: ASCII
/// letters, digits, `.`, `_`, `-`, starting with a letter or digit.
pub(crate) fn is_provider_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_PROVIDER_NAME_LEN
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !s.contains("..")
}

fn is_account_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ACCOUNT_ID_LEN && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// One dial host, read the way the server's `host_target` normalises it:
/// ASCII, no whitespace, wildcard, brackets, percent-encoding, userinfo or
/// path, a `:` only as an IPv6 address, no trailing dot, lower-cased.
pub(crate) fn checked_dial_host(raw: &str) -> Result<String, String> {
    let bad = |why: &str| Err(format!("the dial target {why}"));
    if raw.is_empty() || raw.len() > 253 {
        return bad("is empty or longer than 253 characters");
    }
    if !raw.is_ascii() {
        return bad("is not ASCII");
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control())
        || raw.contains(['*', '%', '[', ']', '@', '/', '\\', '?', '#'])
    {
        return bad("is not a literal host name or address");
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains(':') {
        return match lower.parse::<std::net::Ipv6Addr>() {
            Ok(_) => Ok(lower),
            Err(_) => bad("carries a `:` but is not an IPv6 address"),
        };
    }
    if lower.ends_with('.') || !lower.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return bad("has characters outside [a-z0-9._-] or a trailing dot");
    }
    Ok(lower)
}

/// A web fill origin exactly as `scheme://host[:port]`, canonical.
fn checked_origin(raw: &str) -> Option<String> {
    if raw.len() > MAX_ORIGIN_LEN || !raw.is_ascii() || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let url = tauri::Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    (origin == raw).then_some(origin)
}

fn str_field<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Value::as_str)
}

// ── The profile editor's provider list ─────────────────────────────

/// One provider the profile editor may offer. Unknown protocols and secret
/// kinds are dropped, so the editor never offers a provider for a protocol
/// this build cannot launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialProviderInfo {
    pub name: String,
    pub display_name: String,
    pub protocols: Vec<String>,
    pub secret_kinds: Vec<String>,
}

/// Parse the `providers` listing. An entry with an unusable name is dropped;
/// one whose display name cannot be shown as text falls back to its name.
pub(crate) fn parse_providers(data: &Map<String, Value>) -> Vec<CredentialProviderInfo> {
    let Some(list) = data.get("providers").and_then(Value::as_array) else {
        return Vec::new();
    };
    let strings = |v: Option<&Value>, known: &[&str]| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in v.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            if known.contains(&s) && !out.iter().any(|o| o == s) {
                out.push(s.to_string());
            }
        }
        out
    };
    let mut out: Vec<CredentialProviderInfo> = Vec::new();
    for entry in list.iter().filter_map(Value::as_object) {
        let Some(name) = str_field(entry, "name").filter(|n| is_provider_name(n)) else {
            continue;
        };
        if out.iter().any(|p| p.name == name) {
            continue;
        }
        let display_name = str_field(entry, "display_name")
            .and_then(|d| display_text(d, MAX_DISPLAY_NAME_CHARS))
            .unwrap_or_else(|| name.to_string());
        out.push(CredentialProviderInfo {
            name: name.to_string(),
            display_name,
            protocols: strings(entry.get("protocols"), &["ssh", "rdp", "web"]),
            secret_kinds: strings(entry.get("secret_kinds"), &["password", "ssh-key"]),
        });
    }
    out
}

/// The approved, active credential providers a connection profile can name.
/// Read through the caller's own token, so the server's ACL applies in both
/// the embedded and the remote mode.
#[tauri::command]
pub async fn connect_credential_providers(state: State<'_, AppState>) -> CmdResult<Vec<CredentialProviderInfo>> {
    let resp = make_request(&state, Operation::Read, format!("{RESOURCE_MOUNT}v2/connect/providers"), None).await?;
    Ok(parse_providers(&resp.and_then(|r| r.data).unwrap_or_default()))
}

// ── The picker's candidate list ────────────────────────────────────

/// What the operator is connecting to, as the server computed it from the
/// stored record. Shown in the picker's header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProviderTargetView {
    Host { host: String, port: u16 },
    Origins { origins: Vec<String> },
}

/// One account the operator may pick. Every string has passed
/// [`display_text`] (or is an id / enum value checked here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderCandidateView {
    pub id: String,
    pub label: String,
    pub username: String,
    pub domain: Option<String>,
    /// `password` or `ssh-key`.
    pub secret_kind: String,
    pub has_totp: bool,
    /// RFC 3339, UTC; `None` when never used or unreadable.
    pub last_used_at: Option<String>,
    /// The provider has never released this account for this target
    /// (Phase 5). The picker shows a caution; `false` when not reported.
    pub first_use_on_target: bool,
    /// RFC 3339, UTC: the last release for this same target, which the
    /// picker preselects. `None` when never, unreported or unreadable.
    pub last_used_on_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderCandidatesView {
    pub provider: String,
    pub display_name: String,
    /// `ssh`, `rdp` or `web`.
    pub protocol: String,
    pub resource_type: String,
    pub os_type: Option<String>,
    pub target: ProviderTargetView,
    pub candidates: Vec<ProviderCandidateView>,
    /// Candidates withheld because a field could not be shown safely (or
    /// past [`MAX_CANDIDATES`]). The picker says so rather than hiding it.
    pub hidden: usize,
}

fn parse_target(v: Option<&Value>) -> Result<ProviderTargetView, String> {
    let m = v.and_then(Value::as_object).ok_or("the response carries no target")?;
    if let Some(origins) = m.get("origins") {
        let list = origins.as_array().ok_or("the target's origins are not a list")?;
        let parsed: Option<Vec<String>> = list.iter().map(|o| o.as_str().and_then(checked_origin)).collect();
        let parsed = parsed.filter(|p| !p.is_empty()).ok_or("the target lists an origin that is not one")?;
        return Ok(ProviderTargetView::Origins { origins: parsed });
    }
    let host = checked_dial_host(str_field(m, "host").ok_or("the target has no host")?)?;
    let port = m
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .ok_or("the target has no valid port")?;
    Ok(ProviderTargetView::Host { host, port })
}

fn parse_candidate(v: &Value, protocol: &str) -> Option<ProviderCandidateView> {
    let m = v.as_object()?;
    let id = str_field(m, "id").filter(|s| is_account_id(s))?.to_string();
    let username = display_text(str_field(m, "username")?, MAX_TEXT_LEN)?;
    // A missing label shows the login name; a label that is present but
    // cannot be shown hides the candidate.
    let label = match m.get("label") {
        None | Some(Value::Null) => username.clone(),
        Some(Value::String(s)) if s.trim().is_empty() => username.clone(),
        Some(Value::String(s)) => display_text(s, MAX_TEXT_LEN)?,
        Some(_) => return None,
    };
    let domain = match m.get("domain") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(display_text(s, MAX_TEXT_LEN)?),
        Some(_) => return None,
    };
    let secret_kind = match str_field(m, "secret_kind")? {
        "password" => "password",
        "ssh-key" if protocol == "ssh" => "ssh-key",
        _ => return None,
    };
    let has_totp = match m.get("has_totp") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    let utc = |key: &str| {
        str_field(m, key)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&chrono::Utc).to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    };
    let first_use_on_target = match m.get("first_use_on_target") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    Some(ProviderCandidateView {
        id,
        label,
        username,
        domain,
        secret_kind: secret_kind.to_string(),
        has_totp,
        last_used_at: utc("last_used_at"),
        first_use_on_target,
        last_used_on_target: utc("last_used_on_target"),
    })
}

/// Parse and check a `provider/candidates` response for `profile_id`.
pub(crate) fn parse_candidates(profile_id: &str, data: &Map<String, Value>) -> Result<ProviderCandidatesView, String> {
    if str_field(data, "profile_id") != Some(profile_id) {
        return Err("the server answered for a different connection profile".into());
    }
    let provider =
        str_field(data, "provider").filter(|p| is_provider_name(p)).ok_or("the response names no usable provider")?;
    let display_name = str_field(data, "display_name")
        .and_then(|d| display_text(d, MAX_DISPLAY_NAME_CHARS))
        .unwrap_or_else(|| provider.to_string());
    let protocol = match str_field(data, "protocol") {
        Some(p @ ("ssh" | "rdp" | "web")) => p,
        _ => return Err("the response names no known protocol".into()),
    };
    let target = parse_target(data.get("target"))?;
    match (&target, protocol) {
        (ProviderTargetView::Origins { .. }, "web") | (ProviderTargetView::Host { .. }, "ssh" | "rdp") => {}
        _ => return Err("the response's target does not fit its protocol".into()),
    }
    let resource_type =
        str_field(data, "resource_type").and_then(|s| display_text(s, MAX_TEXT_LEN)).unwrap_or_default();
    let os_type = str_field(data, "os_type").and_then(|s| display_text(s, MAX_TEXT_LEN));

    let raw = data.get("candidates").and_then(Value::as_array).ok_or("the response carries no candidate list")?;
    let mut candidates: Vec<ProviderCandidateView> = Vec::new();
    let mut hidden = 0usize;
    for v in raw {
        match parse_candidate(v, protocol) {
            Some(c) if candidates.len() < MAX_CANDIDATES && !candidates.iter().any(|x| x.id == c.id) => {
                candidates.push(c)
            }
            _ => hidden += 1,
        }
    }
    Ok(ProviderCandidatesView {
        provider: provider.to_string(),
        display_name,
        protocol: protocol.to_string(),
        resource_type,
        os_type,
        target,
        candidates,
        hidden,
    })
}

/// The accounts the operator may pick for `profile_id` on `resource_name`,
/// metadata only. The server computes the resource type, OS and target from
/// the stored record and requires the `connect` grant; this host only checks
/// that what comes back is safe to render.
#[tauri::command]
pub async fn connect_provider_candidates(
    state: State<'_, AppState>,
    resource_name: String,
    profile_id: String,
) -> CmdResult<ProviderCandidatesView> {
    let mut body = Map::new();
    body.insert("resource".into(), Value::String(resource_name));
    body.insert("profile_id".into(), Value::String(profile_id.clone()));
    let resp =
        make_request(&state, Operation::Write, format!("{RESOURCE_MOUNT}v2/connect/provider/candidates"), Some(body))
            .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    parse_candidates(&profile_id, &data).map_err(|e| CommandError::from(format!("the account list is malformed ({e})")))
}

// ── The open request's account ─────────────────────────────────────

/// The provider a profile names and the account the operator picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderPick {
    pub provider: String,
    pub account_id: String,
}

/// The account a session open must carry for `profile`: required (and
/// checked) when the profile's source is `provider`, refused for any other
/// source. Runs before anything is read, resolved or dialled, so a missing
/// pick costs no MFA ticket.
pub(crate) fn provider_pick_for_open(
    profile: &Value,
    requested: Option<&str>,
) -> Result<Option<ProviderPick>, CommandError> {
    let cs = profile.get("credential_source").and_then(Value::as_object);
    let is_provider = cs.and_then(|c| c.get("kind")).and_then(Value::as_str) == Some("provider");
    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    if !is_provider {
        return match requested {
            Some(_) => Err(CommandError::from(
                "`provider_account_id` applies only to a profile whose credential source is a credential provider"
                    .to_string(),
            )),
            None => Ok(None),
        };
    }
    let provider = cs.and_then(|c| str_field(c, "provider")).filter(|p| is_provider_name(p)).ok_or_else(|| {
        CommandError::from("this profile's credential source names no usable credential provider".to_string())
    })?;
    let account_id = requested.ok_or_else(|| {
        CommandError::from(
            "this profile takes its credential from a credential provider: pick one of your accounts first \
             (`provider_account_id` is required)"
                .to_string(),
        )
    })?;
    if !is_account_id(account_id) {
        return Err(CommandError::from("`provider_account_id` is not an account id".to_string()));
    }
    Ok(Some(ProviderPick { provider: provider.to_string(), account_id: account_id.to_string() }))
}

// ── The direct-path release ────────────────────────────────────────

/// The one target a provider credential was released for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedTarget {
    pub host: String,
    pub port: u16,
}

/// The secret half of a released credential. No `Debug` that prints it.
pub(crate) enum ReleasedProviderSecret {
    Password(Zeroizing<String>),
    SshKey(Zeroizing<String>),
}

impl ReleasedProviderSecret {
    fn kind(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::SshKey(_) => "ssh-key",
        }
    }
}

impl std::fmt::Debug for ReleasedProviderSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReleasedProviderSecret({}, <redacted>)", self.kind())
    }
}

/// A provider release on the direct path: the account's login, the pinned
/// target, and the secret until the session takes it.
#[derive(Debug)]
pub(crate) struct ProviderRelease {
    pub provider: String,
    pub account_id: String,
    pub target: PinnedTarget,
    /// The released login name, authoritative over the profile's `username`.
    pub username: String,
    pub domain: Option<String>,
    secret: Option<ReleasedProviderSecret>,
}

impl ProviderRelease {
    /// Move the secret into an SSH credential. SSH has no domain; the
    /// released username is used as is.
    pub fn take_ssh_credential(&mut self) -> Result<SshCredential, CommandError> {
        match self.secret.take() {
            Some(ReleasedProviderSecret::Password(p)) => Ok(SshCredential::Password(p)),
            Some(ReleasedProviderSecret::SshKey(pem)) => Ok(SshCredential::PrivateKey { pem, passphrase: None }),
            None => Err(CommandError::from("the released credential was already used".to_string())),
        }
    }

    /// Move the secret into an RDP password. A key cannot authenticate RDP,
    /// and is refused rather than ignored.
    pub fn take_rdp_password(&mut self) -> Result<Zeroizing<String>, CommandError> {
        match self.secret.take() {
            Some(ReleasedProviderSecret::Password(p)) => Ok(p),
            Some(ReleasedProviderSecret::SshKey(_)) => {
                Err(CommandError::from("the credential provider released an SSH key for an RDP session".to_string()))
            }
            None => Err(CommandError::from("the released credential was already used".to_string())),
        }
    }

    /// The fields the host's `session.open` audit line adds for a provider
    /// launch: names and ids only, each `{:?}`-quoted so no value can forge
    /// a field. The login name is not a secret (target-side attribution is
    /// the point of naming it, spec §9).
    pub fn audit_fields(&self) -> String {
        format!(
            " credential_source=provider provider={:?} account_id={:?} login_name={:?}",
            self.provider, self.account_id, self.username
        )
    }
}

/// Overwrite every string left in a response before it is dropped.
fn scrub(v: &mut Value) {
    use zeroize::Zeroize;
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::Object(m) => m.values_mut().for_each(scrub),
        _ => {}
    }
}

fn take_secret_string(m: &mut Map<String, Value>, key: &str, max: usize) -> Result<Zeroizing<String>, String> {
    match m.remove(key) {
        Some(Value::String(s)) => {
            let s = Zeroizing::new(s);
            if s.is_empty() || s.len() > max {
                return Err(format!("the released `{key}` is empty or too long"));
            }
            Ok(s)
        }
        Some(mut other) => {
            scrub(&mut other);
            Err(format!("the released `{key}` is not a string"))
        }
        None => Err(format!("the release carries no `{key}`")),
    }
}

/// Parse a provider `authorize` response for `pick` on `protocol` (`ssh` or
/// `rdp`). Takes the response by value so the secret moves into `Zeroizing`
/// buffers instead of being copied; every string left over is scrubbed,
/// whatever the outcome.
pub(crate) fn parse_provider_authorize(
    mut data: Map<String, Value>,
    profile_id: &str,
    pick: &ProviderPick,
    protocol: &str,
) -> Result<ProviderRelease, String> {
    let result = (|| {
        if data.get("authorized").and_then(Value::as_bool) != Some(true) {
            return Err("the server did not authorize this connection".to_string());
        }
        if str_field(&data, "profile_id") != Some(profile_id) {
            return Err("the server answered for a different connection profile".into());
        }
        if str_field(&data, "credential_source") != Some("provider")
            || str_field(&data, "provider") != Some(pick.provider.as_str())
            || str_field(&data, "provider_account_id") != Some(pick.account_id.as_str())
        {
            return Err("the server released a different credential than the one picked".into());
        }
        let target = match parse_target(data.get("target"))? {
            ProviderTargetView::Host { host, port } => PinnedTarget { host, port },
            ProviderTargetView::Origins { .. } => return Err("a direct session needs a host target".into()),
        };
        let mut credential = match data.remove("credential") {
            Some(Value::Object(m)) => m,
            Some(mut other) => {
                scrub(&mut other);
                return Err("the release's `credential` is not an object".into());
            }
            None => return Err("the response carries no credential".into()),
        };
        let inner = (|| {
            // The login and domain end up in the session's label and window
            // title (`ssh <user>@<host>:<port>`), so they are held to the
            // picker's plain-text rule: a bidi override or an invisible
            // character in them could make the label name another host.
            let username = str_field(&credential, "username")
                .filter(|u| u.len() <= MAX_TEXT_LEN)
                .and_then(|u| display_text(u, MAX_TEXT_LEN))
                .ok_or("the released username is empty, too long, or carries control or invisible characters")?;
            let domain = match credential.get("domain") {
                None | Some(Value::Null) => None,
                Some(Value::String(d)) if d.is_empty() => None,
                Some(Value::String(d)) if d.len() <= MAX_TEXT_LEN => Some(display_text(d, MAX_TEXT_LEN).ok_or(
                    "the released domain is too long, or carries control or invisible characters".to_string(),
                )?),
                Some(_) => return Err("the released domain is malformed".to_string()),
            };
            let mut secret = match credential.remove("secret") {
                Some(Value::Object(m)) => m,
                Some(mut other) => {
                    scrub(&mut other);
                    return Err("the released secret is not an object".into());
                }
                None => return Err("the release carries no secret".into()),
            };
            let parsed = match str_field(&secret, "kind") {
                Some("password") => {
                    take_secret_string(&mut secret, "password", MAX_PASSWORD_LEN).map(ReleasedProviderSecret::Password)
                }
                Some("ssh-key") if protocol == "ssh" => {
                    take_secret_string(&mut secret, "private_key", MAX_PRIVATE_KEY_LEN)
                        .map(ReleasedProviderSecret::SshKey)
                }
                Some("ssh-key") => Err(format!("a key cannot authenticate a `{protocol}` session")),
                _ => Err("the released secret has an unknown kind".into()),
            };
            scrub_map(&mut secret);
            Ok((username, domain, parsed?))
        })();
        scrub_map(&mut credential);
        let (username, domain, secret) = inner?;
        Ok(ProviderRelease {
            provider: pick.provider.clone(),
            account_id: pick.account_id.clone(),
            target,
            username,
            domain,
            secret: Some(secret),
        })
    })();
    scrub_map(&mut data);
    result
}

fn scrub_map(m: &mut Map<String, Value>) {
    m.values_mut().for_each(scrub);
}

/// `POST resources/v2/connect/authorize` for a provider profile on the direct
/// path: redeems the MFA ticket (when the profile is gated) and releases the
/// picked account in one call. The returned [`ProviderRelease`] holds the
/// secret in `Zeroizing` buffers and the one target it was released for.
pub(crate) async fn authorize_provider_direct(
    state: &State<'_, AppState>,
    resource_name: &str,
    profile_id: &str,
    connect_ticket: Option<&str>,
    pick: &ProviderPick,
    protocol: &str,
) -> CmdResult<ProviderRelease> {
    let mut body = Map::new();
    body.insert("resource".into(), Value::String(resource_name.to_string()));
    body.insert("profile_id".into(), Value::String(profile_id.to_string()));
    body.insert("provider_account_id".into(), Value::String(pick.account_id.clone()));
    if let Some(t) = connect_ticket.map(str::trim).filter(|t| !t.is_empty()) {
        body.insert("connect_ticket".into(), Value::String(t.to_string()));
    }
    let resp =
        make_request(state, Operation::Write, format!("{RESOURCE_MOUNT}v2/connect/authorize"), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    parse_provider_authorize(data, profile_id, pick, protocol)
        .map_err(|e| CommandError::from(format!("refusing the released credential: {e}; nothing was dialled")))
}

// ── Which hosts a direct open may dial ─────────────────────────────

/// The hosts a direct SSH / RDP open may try, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DialPlan {
    /// The resource's host candidates (`target_host`, then `ip_address`,
    /// then `hostname`); a network-layer failure moves to the next one.
    Candidates(Vec<String>),
    /// Exactly one target, with its port. A provider credential is released
    /// for this target only, so nothing else is ever dialled.
    Pinned(PinnedTarget),
}

impl DialPlan {
    pub fn hosts(&self) -> Vec<String> {
        match self {
            DialPlan::Candidates(h) => h.clone(),
            DialPlan::Pinned(t) => vec![t.host.clone()],
        }
    }

    /// The port to dial: the pinned one, else the profile's.
    pub fn port(&self, profile_port: u16) -> u16 {
        match self {
            DialPlan::Candidates(_) => profile_port,
            DialPlan::Pinned(t) => t.port,
        }
    }
}

/// One failed dial: its message, and whether it failed before the target
/// was reached (DNS / TCP / TLS / timeout) so another candidate may be tried.
pub(crate) struct DialFailure {
    pub message: String,
    pub network_layer: bool,
}

/// Dial `hosts` in order. Only a network-layer failure moves to the next
/// host — an authentication refusal stops, so a credential is never tried on
/// one host after another — and the last host's failure is final. With one
/// host (a [`DialPlan::Pinned`] plan) nothing else is ever dialled.
pub(crate) async fn dial_in_order<T, F, Fut>(
    proto: &str,
    hosts: &[String],
    port: u16,
    mut dial: F,
) -> Result<(String, T), CommandError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<T, DialFailure>>,
{
    let mut last_err: Option<String> = None;
    for (idx, host) in hosts.iter().enumerate() {
        let is_last = idx + 1 == hosts.len();
        match dial(host.clone()).await {
            Ok(v) => return Ok((host.clone(), v)),
            Err(f) if !is_last && f.network_layer => {
                log::warn!(
                    "resource-connect/{proto}: candidate {host}:{port} failed at network layer ({}); trying next",
                    f.message
                );
                last_err = Some(f.message);
            }
            Err(f) => return Err(CommandError::from(f.message)),
        }
    }
    Err(CommandError::from(last_err.unwrap_or_else(|| format!("{proto}: no host candidates succeeded"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "S3lf-acct-pw-6f1d";

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn pick() -> ProviderPick {
        ProviderPick { provider: "self-accounts".into(), account_id: "sa_5k2q".into() }
    }

    fn authorize_response(secret: Value) -> Map<String, Value> {
        obj(json!({
            "resource": "dc01", "profile_id": "p_rdp", "authorized": true, "mfa_required": true,
            "credential_source": "provider", "provider": "self-accounts", "provider_account_id": "sa_5k2q",
            "target": { "host": "dc01.corp.example.com", "port": 3389 },
            "credential": { "username": "felipe.adm", "domain": "CORP", "secret": secret },
        }))
    }

    // ── target pinning ─────────────────────────────────────────────

    /// A network-layer failure on the pinned target never moves on to
    /// another host: the plan has exactly one, whatever the resource's other
    /// candidates are.
    #[tokio::test]
    async fn a_network_error_never_dials_a_different_host_for_a_pinned_plan() {
        let pinned = DialPlan::Pinned(PinnedTarget { host: "10.20.0.5".into(), port: 3389 });
        assert_eq!(pinned.hosts(), vec!["10.20.0.5".to_string()]);
        assert_eq!(pinned.port(22), 3389, "the pinned port wins over the profile's");

        let mut dialled: Vec<String> = Vec::new();
        let r: Result<(String, ()), CommandError> = dial_in_order("rdp", &pinned.hosts(), 3389, |h| {
            dialled.push(h);
            async { Err(DialFailure { message: "tcp connect: connection refused".into(), network_layer: true }) }
        })
        .await;
        assert_eq!(dialled, vec!["10.20.0.5".to_string()], "exactly the pinned target, once");
        assert_eq!(r.unwrap_err().message, "tcp connect: connection refused");
    }

    /// The unpinned plan keeps today's behaviour: a network-layer failure
    /// tries the next candidate, an authentication failure stops.
    #[tokio::test]
    async fn the_candidate_plan_falls_back_only_on_network_errors() {
        let plan = DialPlan::Candidates(vec!["10.0.0.5".into(), "db.internal".into()]);
        let mut dialled: Vec<String> = Vec::new();
        let r = dial_in_order("ssh", &plan.hosts(), 22, |h| {
            dialled.push(h.clone());
            async move {
                if h == "10.0.0.5" {
                    Err(DialFailure { message: "dns lookup failed".into(), network_layer: true })
                } else {
                    Ok(7u8)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(r, ("db.internal".to_string(), 7));
        assert_eq!(dialled, vec!["10.0.0.5".to_string(), "db.internal".to_string()]);

        let mut dialled: Vec<String> = Vec::new();
        let r: Result<(String, ()), _> = dial_in_order("ssh", &plan.hosts(), 22, |h| {
            dialled.push(h);
            async { Err(DialFailure { message: "ssh: authentication rejected".into(), network_layer: false }) }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(dialled.len(), 1, "an auth refusal is not retried on another host");
    }

    // ── the release ────────────────────────────────────────────────

    #[test]
    fn the_release_pins_the_server_target_and_moves_the_secret_out() {
        let mut r = parse_provider_authorize(
            authorize_response(json!({ "kind": "password", "password": SECRET })),
            "p_rdp",
            &pick(),
            "rdp",
        )
        .unwrap();
        assert_eq!(r.target, PinnedTarget { host: "dc01.corp.example.com".into(), port: 3389 });
        assert_eq!((r.username.as_str(), r.domain.as_deref()), ("felipe.adm", Some("CORP")));
        assert_eq!(r.take_rdp_password().unwrap().as_str(), SECRET);
        assert!(r.take_rdp_password().is_err(), "the secret is taken once");
    }

    #[test]
    fn the_release_types_print_no_secret() {
        let r = parse_provider_authorize(
            authorize_response(json!({ "kind": "password", "password": SECRET })),
            "p_rdp",
            &pick(),
            "rdp",
        )
        .unwrap();
        let printed = format!("{r:?}");
        assert!(!printed.contains(SECRET), "{printed}");
        assert!(printed.contains("<redacted>"));
        let fields = r.audit_fields();
        assert!(!fields.contains(SECRET));
        assert_eq!(
            fields,
            r#" credential_source=provider provider="self-accounts" account_id="sa_5k2q" login_name="felipe.adm""#
        );
        let key = ReleasedProviderSecret::SshKey(Zeroizing::new("-----BEGIN OPENSSH PRIVATE KEY-----".into()));
        assert!(!format!("{key:?}").contains("BEGIN"));
    }

    #[test]
    fn a_release_that_does_not_match_the_pick_or_protocol_is_refused() {
        let pw = || json!({ "kind": "password", "password": SECRET });
        // A different account, provider or source than the one picked.
        for (k, v) in [
            ("provider_account_id", json!("sa_other")),
            ("provider", json!("evil")),
            ("credential_source", json!("secret")),
        ] {
            let mut d = authorize_response(pw());
            d.insert(k.into(), v);
            assert!(parse_provider_authorize(d, "p_rdp", &pick(), "rdp").is_err(), "{k}");
        }
        // A key for RDP.
        let d = authorize_response(json!({ "kind": "ssh-key", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----" }));
        assert!(parse_provider_authorize(d, "p_rdp", &pick(), "rdp").unwrap_err().contains("key cannot authenticate"));
        // A key for SSH is fine.
        let d = authorize_response(json!({ "kind": "ssh-key", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----" }));
        let mut r = parse_provider_authorize(d, "p_rdp", &pick(), "ssh").unwrap();
        assert!(matches!(r.take_ssh_credential().unwrap(), SshCredential::PrivateKey { passphrase: None, .. }));
        // No target, a web target, a hostile host.
        for target in [
            Value::Null,
            json!({ "origins": ["https://a.example"] }),
            json!({ "host": "a b", "port": 22 }),
            json!({ "host": "x", "port": 0 }),
        ] {
            let mut d = authorize_response(pw());
            d.insert("target".into(), target.clone());
            assert!(parse_provider_authorize(d, "p_rdp", &pick(), "rdp").is_err(), "{target}");
        }
        // Not authorized, an empty or oversize password, an unknown kind.
        let mut d = authorize_response(pw());
        d.insert("authorized".into(), json!(false));
        assert!(parse_provider_authorize(d, "p_rdp", &pick(), "rdp").is_err());
        for secret in [
            json!({ "kind": "password", "password": "" }),
            json!({ "kind": "password", "password": "x".repeat(MAX_PASSWORD_LEN + 1) }),
            json!({ "kind": "totp" }),
            json!("hunter2"),
        ] {
            assert!(
                parse_provider_authorize(authorize_response(secret.clone()), "p_rdp", &pick(), "rdp").is_err(),
                "{secret}"
            );
        }
        // A refusal message never carries the secret.
        let mut d = authorize_response(pw());
        d.insert("provider".into(), json!("evil"));
        assert!(!parse_provider_authorize(d, "p_rdp", &pick(), "rdp").unwrap_err().contains(SECRET));
    }

    // ── the open request's account ─────────────────────────────────

    #[test]
    fn a_provider_profile_refuses_a_missing_or_malformed_account_id() {
        let profile = json!({ "id": "p", "protocol": "ssh", "credential_source": { "kind": "provider", "provider": "self-accounts" } });
        for missing in [None, Some(""), Some("   ")] {
            let e = provider_pick_for_open(&profile, missing).unwrap_err();
            assert!(e.message.contains("provider_account_id"), "{}", e.message);
        }
        assert!(provider_pick_for_open(&profile, Some("sa x")).is_err());
        assert!(provider_pick_for_open(&profile, Some(&"a".repeat(MAX_ACCOUNT_ID_LEN + 1))).is_err());
        assert_eq!(
            provider_pick_for_open(&profile, Some(" sa_5k2q ")).unwrap(),
            Some(ProviderPick { provider: "self-accounts".into(), account_id: "sa_5k2q".into() })
        );
        // A provider source with no usable name.
        for cs in [json!({ "kind": "provider" }), json!({ "kind": "provider", "provider": "../x" })] {
            let p = json!({ "credential_source": cs });
            assert!(provider_pick_for_open(&p, Some("sa_5k2q")).is_err(), "{p}");
        }
        // Any other source: no pick, and an account id is refused.
        let secret = json!({ "credential_source": { "kind": "secret", "secret_id": "s" } });
        assert_eq!(provider_pick_for_open(&secret, None).unwrap(), None);
        assert!(provider_pick_for_open(&secret, Some("sa_5k2q")).is_err());
    }

    // ── what reaches the webview ───────────────────────────────────

    fn candidates_response(candidates: Value) -> Map<String, Value> {
        obj(json!({
            "resource": "dc01", "profile_id": "p_rdp", "provider": "self-accounts", "display_name": "Self-account",
            "protocol": "rdp", "resource_type": "server", "os_type": "windows",
            "target": { "host": "dc01.corp.example.com", "port": 3389 },
            "candidates": candidates,
        }))
    }

    #[test]
    fn candidates_are_metadata_checked_for_plain_text_display() {
        let v = parse_candidates(
            "p_rdp",
            &candidates_response(json!([
                { "id": "sa_1", "label": "Domain admin", "username": "felipe.adm", "domain": "CORP",
                  "secret_kind": "password", "has_totp": false, "last_used_at": "2026-10-01T09:12:00-03:00" },
                // Hostile display strings: a bidi override, a control
                // character, markup is fine as *text* (React escapes it).
                { "id": "sa_2", "label": "adm\u{202E}nimda", "username": "x", "secret_kind": "password" },
                { "id": "sa_3", "label": "line\nbreak", "username": "x", "secret_kind": "password" },
                { "id": "sa_4", "label": "<img src=x onerror=alert(1)>", "username": "<b>u</b>", "secret_kind": "password" },
                // A key cannot authenticate RDP; an unknown kind; a bad id; a duplicate.
                { "id": "sa_5", "label": "key", "username": "k", "secret_kind": "ssh-key" },
                { "id": "sa_6", "label": "?", "username": "k", "secret_kind": "certificate" },
                { "id": "sa 7", "label": "space", "username": "k", "secret_kind": "password" },
                { "id": "sa_1", "label": "dup", "username": "k", "secret_kind": "password" },
                { "id": "sa_8", "label": "x".repeat(MAX_TEXT_LEN + 1), "username": "k", "secret_kind": "password" },
            ])),
        )
        .unwrap();
        assert_eq!(v.display_name, "Self-account");
        assert_eq!(v.target, ProviderTargetView::Host { host: "dc01.corp.example.com".into(), port: 3389 });
        let ids: Vec<&str> = v.candidates.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["sa_1", "sa_4"]);
        assert_eq!(v.hidden, 7);
        assert_eq!(v.candidates[0].last_used_at.as_deref(), Some("2026-10-01T12:12:00Z"));
        assert_eq!(v.candidates[1].label, "<img src=x onerror=alert(1)>", "kept verbatim; rendered as text");

        // The serialised view carries no field a secret could be in.
        let json = serde_json::to_value(&v).unwrap();
        for c in json["candidates"].as_array().unwrap() {
            let keys: Vec<&String> = c.as_object().unwrap().keys().collect();
            for k in keys {
                assert!(
                    [
                        "id",
                        "label",
                        "username",
                        "domain",
                        "secret_kind",
                        "has_totp",
                        "last_used_at",
                        "first_use_on_target",
                        "last_used_on_target"
                    ]
                    .contains(&k.as_str()),
                    "{k}"
                );
            }
        }
        assert_eq!(json["target"], json!({ "kind": "host", "host": "dc01.corp.example.com", "port": 3389 }));
    }

    #[test]
    fn the_target_history_fields_are_typed_and_normalised() {
        let v = parse_candidates(
            "p_rdp",
            &candidates_response(json!([
                { "id": "sa_1", "label": "A", "username": "a", "secret_kind": "password",
                  "first_use_on_target": true },
                { "id": "sa_2", "label": "B", "username": "b", "secret_kind": "password",
                  "first_use_on_target": false, "last_used_on_target": "2026-10-01T09:12:00-03:00" },
                // An older provider reports neither: no badge, no preselection.
                { "id": "sa_3", "label": "C", "username": "c", "secret_kind": "password" },
                // A time that is not one is dropped, not shown.
                { "id": "sa_4", "label": "D", "username": "d", "secret_kind": "password",
                  "last_used_on_target": "dc01.corp.example.com" },
                // A flag of the wrong type hides the candidate, like `has_totp`.
                { "id": "sa_5", "label": "E", "username": "e", "secret_kind": "password",
                  "first_use_on_target": "yes" },
            ])),
        )
        .unwrap();
        let by_id = |id: &str| v.candidates.iter().find(|c| c.id == id).unwrap();
        assert!(by_id("sa_1").first_use_on_target);
        assert_eq!(by_id("sa_1").last_used_on_target, None);
        assert!(!by_id("sa_2").first_use_on_target);
        assert_eq!(by_id("sa_2").last_used_on_target.as_deref(), Some("2026-10-01T12:12:00Z"));
        assert!(!by_id("sa_3").first_use_on_target);
        assert_eq!(by_id("sa_4").last_used_on_target, None);
        assert!(v.candidates.iter().all(|c| c.id != "sa_5"));
        assert_eq!(v.hidden, 1);
    }

    #[test]
    fn a_candidates_response_for_another_profile_or_without_a_target_is_refused() {
        assert!(parse_candidates("p_other", &candidates_response(json!([]))).is_err());
        let mut d = candidates_response(json!([]));
        d.remove("target");
        assert!(parse_candidates("p_rdp", &d).is_err());
        let mut d = candidates_response(json!([]));
        d.insert("target".into(), json!({ "origins": ["https://fw01.example.com"] }));
        assert!(parse_candidates("p_rdp", &d).is_err(), "a web target on an rdp profile");
        let mut d = candidates_response(json!([]));
        d.insert("protocol".into(), json!("web"));
        d.insert("target".into(), json!({ "origins": ["https://fw01.example.com", "https://FW01.example.com/x"] }));
        assert!(parse_candidates("p_rdp", &d).is_err(), "a non-canonical origin");
    }

    #[test]
    fn the_provider_listing_drops_unusable_names_and_unknown_kinds() {
        let v = parse_providers(&obj(json!({ "providers": [
            { "name": "self-accounts", "display_name": "Self-account", "protocols": ["ssh", "rdp", "web", "telnet"],
              "secret_kinds": ["password", "ssh-key", "x509"] },
            { "name": "../evil", "display_name": "Evil", "protocols": ["ssh"], "secret_kinds": ["password"] },
            { "name": "vault-bridge", "display_name": "bad\u{202E}name", "protocols": ["web"], "secret_kinds": ["password"] },
            { "name": "self-accounts", "display_name": "Duplicate", "protocols": ["ssh"], "secret_kinds": ["password"] },
        ] })));
        assert_eq!(
            v,
            vec![
                CredentialProviderInfo {
                    name: "self-accounts".into(),
                    display_name: "Self-account".into(),
                    protocols: vec!["ssh".into(), "rdp".into(), "web".into()],
                    secret_kinds: vec!["password".into(), "ssh-key".into()],
                },
                CredentialProviderInfo {
                    name: "vault-bridge".into(),
                    display_name: "vault-bridge".into(),
                    protocols: vec!["web".into()],
                    secret_kinds: vec!["password".into()],
                },
            ]
        );
        assert!(parse_providers(&Map::new()).is_empty());
    }

    /// Every code point that is not shown as itself — by category, not by a
    /// hand-picked list — is refused wherever the host shows provider text.
    #[test]
    fn invisible_and_format_characters_are_refused_by_category() {
        let refused: &[(&str, &[u32])] = &[
            ("Cc", &[0x00, 0x09, 0x1B, 0x7F, 0x85, 0x9F]),
            (
                "Cf",
                &[
                    0x00AD, 0x0600, 0x0605, 0x061C, 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2, 0x180E, 0x200B, 0x200C,
                    0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060, 0x2061, 0x2062, 0x2063,
                    0x2064, 0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, 0xFEFF,
                    0xFFF9, 0xFFFA, 0xFFFB, 0x110BD, 0x110CD, 0x13430, 0x1343F, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A,
                    0xE0001, 0xE0020, 0xE0041, 0xE007F,
                ],
            ),
            ("Zl, Zp", &[0x2028, 0x2029]),
            ("variation selectors", &[0x180B, 0x180C, 0x180D, 0x180F, 0xFE00, 0xFE0E, 0xFE0F, 0xE0100, 0xE01EF]),
            (
                "fillers and other default-ignorables",
                &[0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0, 0xFFF0, 0xE0000, 0xE0002, 0xE0080, 0xE0FFF],
            ),
        ];
        for (category, points) in refused {
            for &p in *points {
                let c = char::from_u32(p).unwrap();
                let s = format!("adm{c}in");
                assert!(display_text(&s, MAX_TEXT_LEN).is_none(), "{category}: U+{p:04X} must be refused");
            }
        }
        // Visible text, non-ASCII included, is shown as it is.
        for ok in ["José Müller", "管理者", "администратор", "CORP\\felipe.adm", "a b", "admin 🔑", "<b>x</b>"]
        {
            assert_eq!(display_text(ok, MAX_TEXT_LEN).as_deref(), Some(ok), "{ok}");
        }
        // The table is sorted and its ranges well-formed (the lookup scans it).
        assert!(INVISIBLE_RANGES.windows(2).all(|w| w[0].1 < w[1].0));
        assert!(INVISIBLE_RANGES.iter().all(|&(lo, hi)| lo <= hi));
    }

    /// The released login goes into the session's label and window title, so
    /// a bidi override or an invisible character in it — or in the domain —
    /// refuses the release, and the refusal carries no secret.
    #[test]
    fn a_release_whose_login_could_spoof_the_label_is_refused() {
        let with = |username: &str, domain: Value| {
            let mut d = authorize_response(json!({ "kind": "password", "password": SECRET }));
            let cred = d.get_mut("credential").unwrap().as_object_mut().unwrap();
            cred.insert("username".into(), json!(username));
            cred.insert("domain".into(), domain);
            parse_provider_authorize(d, "p_rdp", &pick(), "rdp")
        };
        for (user, domain) in [
            ("felipe\u{202E}moc.live", json!(null)),
            ("felipe\u{200B}adm", json!(null)),
            ("felipe\u{2028}", json!(null)),
            ("felipe", json!("CO\u{2066}RP")),
            ("felipe", json!("CORP\u{00AD}")),
            ("felipe", json!(7)),
        ] {
            let e = with(user, domain.clone()).unwrap_err();
            assert!(!e.contains(SECRET), "{e}");
            assert!(e.contains("released"), "{user:?} {domain}: {e}");
        }
        assert!(with("felipe.adm", json!("CORP")).is_ok());
        assert!(with("José", json!(null)).is_ok());
    }

    #[test]
    fn dial_hosts_are_read_like_the_server_reads_them() {
        assert_eq!(checked_dial_host("DC01.Corp.Example.com").unwrap(), "dc01.corp.example.com");
        assert_eq!(checked_dial_host("fe80::1").unwrap(), "fe80::1");
        for bad in ["", "a b", "host:22", "*.corp", "[::1]", "user@host", "host.", "h\u{e9}st", "a/b"] {
            assert!(checked_dial_host(bad).is_err(), "{bad}");
        }
    }
}
