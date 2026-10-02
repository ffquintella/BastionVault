//! Web Application Connect — the ephemeral, IPC-less web session window
//! (features/web-application-connect.md §4, T96 Phase 1).
//!
//! This module holds the parts of a web session that need no Tauri
//! runtime, so they can be unit-tested: parsing a `web` connection
//! profile, the exact-origin allow-list the window's navigation /
//! new-window handlers consult, and the per-session registry entry plus
//! its teardown. The command that builds the window lives in
//! `commands/connect_web.rs`.
//!
//! Phase 1 ships `login_mode: "open"` only: the window opens on the
//! application and releases no credential. Every other login mode, the
//! `rustion-isolated` transport and TLS pinning are refused explicitly
//! rather than ignored, so a profile written for a later phase can never
//! run with its protections silently missing.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::Value;
use tauri::Url;

/// Default window size when the profile doesn't set one.
pub const DEFAULT_WINDOW_WIDTH: u32 = 1280;
pub const DEFAULT_WINDOW_HEIGHT: u32 = 860;
/// Accepted window-size range, both axes. Outside it the profile is
/// refused rather than clamped, so a typo surfaces in the editor.
pub const MIN_WINDOW_DIMENSION: u32 = 400;
pub const MAX_WINDOW_DIMENSION: u32 = 10_000;

/// Prefix of every web session window label. No capability file may match
/// it — see `capability_isolation_tests` in `commands/connect_web.rs`.
pub const WINDOW_LABEL_PREFIX: &str = "web-";

/// Directory (under the app cache dir) holding the per-session webview data
/// directories. Each session gets `<cache>/web-sessions/<token>`, removed
/// when the session ends.
pub const DATA_DIR_NAME: &str = "web-sessions";

/// One exact web origin: `(scheme, host, port)`, with the port always
/// explicit (default ports filled in) so `https://a` and `https://a:443`
/// compare equal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl WebOrigin {
    /// The origin of an `http`/`https` URL. `None` for any other scheme,
    /// for a URL without a host, and for a URL carrying userinfo — a
    /// `https://allowed.example@evil.example/` shape is a phishing tool,
    /// not something an allow-listed application needs.
    pub fn of_url(url: &Url) -> Option<Self> {
        let scheme = url.scheme();
        if scheme != "https" && scheme != "http" {
            return None;
        }
        if !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let port = url.port_or_known_default()?;
        Some(Self { scheme: scheme.to_string(), host, port })
    }

    /// Parse an operator-configured origin (`scheme://host[:port]`, an
    /// optional single trailing `/`). Anything more — a path, query,
    /// fragment, userinfo — is refused rather than truncated, because an
    /// operator who wrote `https://app.example/admin` expects a path
    /// restriction the allow-list does not implement.
    pub fn parse_config(raw: &str, allow_insecure_http: bool) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("an allowed origin is empty".to_string());
        }
        let url = Url::parse(trimmed).map_err(|e| format!("`{trimmed}` is not a valid origin: {e}"))?;
        let path_ok = url.path() == "/" || url.path().is_empty();
        if !path_ok || url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "`{trimmed}` is not a bare origin: give scheme://host[:port] only (no path, query or fragment)"
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(format!("`{trimmed}` carries userinfo (`user@host`); origins may not"));
        }
        let origin = Self::validated(&url, allow_insecure_http).map_err(|e| format!("`{trimmed}`: {e}"))?;
        Ok(origin)
    }

    /// Shared scheme/host rules for a configured origin or start URL.
    fn validated(url: &Url, allow_insecure_http: bool) -> Result<Self, String> {
        match url.scheme() {
            "https" => {}
            "http" if allow_insecure_http => {}
            "http" => return Err("plain http is refused unless the profile sets allow_insecure_http".to_string()),
            other => return Err(format!("scheme `{other}` is not allowed (https only)")),
        }
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        if host.is_empty() {
            return Err("missing host".to_string());
        }
        if host.ends_with('.') {
            return Err(format!(
                "host `{host}` has a trailing dot; browsers treat it as a different origin — remove the dot"
            ));
        }
        // `localhost` and `*.localhost` are where Tauri serves the vault UI
        // and its own custom protocols (`http://tauri.localhost`,
        // `http://ipc.localhost` on Windows; the dev server on
        // `http://localhost:1420`). Tauri classifies those as *local*
        // origins and grants them IPC, so a web session pointed there would
        // be a remote page with the vault's command surface. Refused
        // outright.
        if host == "localhost" || host.ends_with(".localhost") {
            return Err(format!("host `{host}` is reserved for the vault's own UI; web sessions may not open it"));
        }
        Self::of_url(url).ok_or_else(|| "not an http(s) origin".to_string())
    }

    fn default_port(&self) -> u16 {
        if self.scheme == "http" {
            80
        } else {
            443
        }
    }
}

impl fmt::Display for WebOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == self.default_port() {
            write!(f, "{}://{}", self.scheme, self.host)
        } else {
            write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

/// What the window does with a navigation, new-window or download request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationVerdict {
    Allow,
    /// Refused. `origin` is safe to log and show: an origin for http(s), or
    /// only the scheme (`data:`, `mailto:` …) — never a path or query,
    /// which can carry tokens.
    Block {
        origin: String,
    },
}

/// The profile's origin set: the start URL's origin plus
/// `allowed_origins`, compared exactly.
#[derive(Debug, Clone)]
pub struct OriginSet {
    origins: Vec<WebOrigin>,
}

impl OriginSet {
    pub fn new(origins: Vec<WebOrigin>) -> Self {
        let mut deduped: Vec<WebOrigin> = Vec::with_capacity(origins.len());
        for o in origins {
            if !deduped.contains(&o) {
                deduped.push(o);
            }
        }
        Self { origins: deduped }
    }

    pub fn contains(&self, origin: &WebOrigin) -> bool {
        self.origins.contains(origin)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.origins.len()
    }

    /// Decide a top-level (or, on macOS, any-frame) navigation.
    ///
    /// * `http`/`https`: allowed only on an exact origin match.
    /// * `about:blank` / `about:srcdoc`: allowed — no network fetch, and the
    ///   document inherits its creator's origin. Pages create these for
    ///   iframes constantly; refusing them breaks ordinary applications
    ///   without protecting anything.
    /// * `blob:<origin>/<uuid>`: allowed when the embedded origin is in the
    ///   set (a blob URL can only be minted by that origin).
    /// * Everything else (`data:`, `file:`, `javascript:`, `mailto:`,
    ///   custom schemes that would launch an external handler): refused.
    pub fn check(&self, url: &Url) -> NavigationVerdict {
        match url.scheme() {
            "http" | "https" => match WebOrigin::of_url(url) {
                Some(o) if self.contains(&o) => NavigationVerdict::Allow,
                Some(o) => NavigationVerdict::Block { origin: o.to_string() },
                // userinfo or no host — log the scheme only.
                None => NavigationVerdict::Block { origin: format!("{}:", url.scheme()) },
            },
            "about" if matches!(url.path(), "blank" | "srcdoc") => NavigationVerdict::Allow,
            "blob" => match Url::parse(url.path()).ok().as_ref().and_then(WebOrigin::of_url) {
                Some(o) if self.contains(&o) => NavigationVerdict::Allow,
                Some(o) => NavigationVerdict::Block { origin: format!("blob:{o}") },
                None => NavigationVerdict::Block { origin: "blob:".to_string() },
            },
            other => NavigationVerdict::Block { origin: format!("{other}:") },
        }
    }

    /// New-window requests (`window.open`, `target=_blank`). Stricter than
    /// [`check`](Self::check): only an http(s) URL in the set qualifies,
    /// and only when the profile allows popups at all.
    pub fn check_popup(&self, url: &Url, allow_popups: bool) -> NavigationVerdict {
        match WebOrigin::of_url(url) {
            Some(o) if allow_popups && self.contains(&o) => NavigationVerdict::Allow,
            Some(o) => NavigationVerdict::Block { origin: o.to_string() },
            None => NavigationVerdict::Block { origin: format!("{}:", url.scheme()) },
        }
    }
}

/// Comma-separated origins, for the `session.open` audit line.
impl fmt::Display for OriginSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, o) in self.origins.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{o}")?;
        }
        Ok(())
    }
}

/// Text shown in the window title for the page the host observed loading.
/// The title is the operator's only origin indicator (there is no address
/// bar), so it is built from the host-observed URL — never from
/// `document.title`, which the page controls.
pub fn display_origin(url: &Url) -> String {
    match WebOrigin::of_url(url) {
        Some(o) => o.to_string(),
        None => format!("{}:", url.scheme()),
    }
}

/// `profile.web.clipboard`. Only `bidirectional` grants the page
/// programmatic clipboard access, and only on Linux / Windows — WKWebView
/// cannot gate it (spec §4, Security Considerations 8). The operator's own
/// keyboard copy/paste is native editing and is never blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebClipboard {
    Bidirectional,
    HostToSession,
    SessionToHost,
    Off,
}

impl WebClipboard {
    pub fn grants_page_clipboard_access(self) -> bool {
        matches!(self, Self::Bidirectional)
    }
}

/// A validated `web` connection profile, ready to build a window from.
#[derive(Debug, Clone)]
pub struct WebSessionConfig {
    pub start_url: Url,
    pub origins: OriginSet,
    pub allow_downloads: bool,
    pub allow_popups: bool,
    pub clipboard: WebClipboard,
    pub width: u32,
    pub height: u32,
}

fn opt_bool(obj: &serde_json::Map<String, Value>, key: &str, default: bool) -> Result<bool, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("web.{key} must be true or false")),
    }
}

fn opt_dimension(obj: Option<&serde_json::Map<String, Value>>, key: &str, default: u32) -> Result<u32, String> {
    let Some(v) = obj.and_then(|o| o.get(key)) else {
        return Ok(default);
    };
    if v.is_null() {
        return Ok(default);
    }
    let n = v
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("web.window.{key} must be a whole number of pixels"))?;
    if !(MIN_WINDOW_DIMENSION..=MAX_WINDOW_DIMENSION).contains(&n) {
        return Err(format!(
            "web.window.{key} must be between {MIN_WINDOW_DIMENSION} and {MAX_WINDOW_DIMENSION} pixels"
        ));
    }
    Ok(n)
}

/// Parse and validate the `web` half of a connection profile for an
/// `open`-mode launch. Every field that belongs to a later phase is
/// refused when set, never ignored.
pub fn parse_web_profile(profile: &Value) -> Result<WebSessionConfig, String> {
    // The profile's own transport. Rustion-brokered web sessions are the
    // Phase 8 browser-isolation design; nothing routes them today.
    match profile.get("kind").and_then(|v| v.as_str()) {
        None | Some("direct") => {}
        Some("rustion") => {
            return Err("web sessions cannot be brokered through a Rustion bastion yet; set the profile's \
                 transport to direct"
                .to_string())
        }
        Some(other) => return Err(format!("unknown profile transport `{other}`")),
    }

    // `open` releases no credential, so the only acceptable source is the
    // explicit `none` (or none at all). A profile carrying a real source
    // would make the operator believe a login is performed.
    if let Some(cs) = profile.get("credential_source") {
        let kind = cs.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "none" {
            return Err(format!(
                "credential source `{kind}` does not apply to the `open` login mode, which releases no \
                 credential; set the source to none"
            ));
        }
    }

    let web = profile
        .get("web")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "web profile has no `web` settings block".to_string())?;

    match web.get("login_mode").and_then(|v| v.as_str()) {
        Some("open") => {}
        Some(mode @ ("form" | "http-auth" | "sso")) => {
            return Err(format!("login mode `{mode}` is not available yet; this release supports `open` only"))
        }
        Some(other) => return Err(format!("unknown login mode `{other}`")),
        None => return Err("web profile has no login_mode".to_string()),
    }

    match web.get("transport").and_then(|v| v.as_str()) {
        None | Some("local") => {}
        Some("rustion-isolated") => return Err("the rustion-isolated web transport is not available yet".to_string()),
        Some(other) => return Err(format!("unknown web transport `{other}`")),
    }
    if web.get("recipe").is_some_and(|v| !v.is_null()) {
        return Err("a login recipe only applies to the `form` login mode".to_string());
    }
    if web.get("sso").is_some_and(|v| !v.is_null()) {
        return Err("sso settings only apply to the `sso` login mode".to_string());
    }
    // A pin the window cannot honour must not look like it is honoured.
    if web.get("tls_pin_sha256").and_then(|v| v.as_array()).is_some_and(|a| !a.is_empty()) {
        return Err("TLS certificate pinning for web sessions is not available yet; remove tls_pin_sha256 \
             (the session fails closed on an untrusted certificate)"
            .to_string());
    }

    let allow_insecure_http = opt_bool(web, "allow_insecure_http", false)?;
    let allow_downloads = opt_bool(web, "allow_downloads", false)?;
    let allow_popups = opt_bool(web, "allow_popups_same_origin_set", true)?;

    let start_raw = web
        .get("start_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "web profile has no start_url".to_string())?;
    let start_url = Url::parse(start_raw).map_err(|e| format!("start_url is not a valid URL: {e}"))?;
    if !start_url.username().is_empty() || start_url.password().is_some() {
        return Err("start_url carries userinfo (`user@host`); put credentials in a credential source, \
             never in the URL"
            .to_string());
    }
    let start_origin = WebOrigin::validated(&start_url, allow_insecure_http).map_err(|e| format!("start_url: {e}"))?;

    let mut origins = vec![start_origin];
    match web.get("allowed_origins") {
        None | Some(Value::Null) => {}
        Some(Value::Array(arr)) => {
            for item in arr {
                let s = item.as_str().ok_or_else(|| "allowed_origins must be a list of strings".to_string())?;
                origins.push(WebOrigin::parse_config(s, allow_insecure_http)?);
            }
        }
        Some(_) => return Err("allowed_origins must be a list of strings".to_string()),
    }

    let clipboard = match web.get("clipboard").filter(|v| !v.is_null()) {
        None => WebClipboard::Off,
        Some(v) => match v.as_str() {
            Some("bidirectional") => WebClipboard::Bidirectional,
            Some("host-to-session") => WebClipboard::HostToSession,
            Some("session-to-host") => WebClipboard::SessionToHost,
            Some("off") => WebClipboard::Off,
            _ => return Err("web.clipboard must be bidirectional, host-to-session, session-to-host or off".into()),
        },
    };

    let window = match web.get("window") {
        None | Some(Value::Null) => None,
        Some(Value::Object(m)) => Some(m),
        Some(_) => return Err("web.window must be an object".to_string()),
    };
    let width = opt_dimension(window, "width", DEFAULT_WINDOW_WIDTH)?;
    let height = opt_dimension(window, "height", DEFAULT_WINDOW_HEIGHT)?;

    Ok(WebSessionConfig {
        start_url,
        origins: OriginSet::new(origins),
        allow_downloads,
        allow_popups,
        clipboard,
        width,
        height,
    })
}

/// File name of a download destination, for the audit line. The directory
/// is the operator's and stays out of the log.
pub fn download_file_name(path: &std::path::Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "(unnamed)".to_string())
}

/// Registry entry for one live web session in `AppState::connect_sessions`.
pub struct WebSessionState {
    pub resource_name: String,
    pub profile_id: String,
    pub window_label: String,
    /// Per-session webview data directory, `None` on macOS where the
    /// incognito (non-persistent) WKWebsiteDataStore is already per-window
    /// and WKWebView ignores `data_directory`.
    pub data_dir: Option<PathBuf>,
    pub opened_at: Instant,
}

/// Finish a web session that has just been removed from the registry:
/// write the host-side close audit line and remove the data directory.
///
/// Every path that drops a web session's registry entry calls this —
/// window destruction, `session_close`, and the generic SSH/RDP drop paths
/// should a web token ever reach them — so the cleanup can't be skipped by
/// taking a different door out.
pub fn finish_session(token: &str, session: WebSessionState, reason: &str) {
    let duration_ms = session.opened_at.elapsed().as_millis();
    log::info!(
        target: "audit",
        "session.close: protocol=web resource={} profile={} token={} duration_ms={} reason={}",
        session.resource_name,
        session.profile_id,
        token,
        duration_ms,
        reason,
    );
    if let Some(dir) = session.data_dir {
        remove_data_dir_eventually(dir);
    }
}

/// Remove a session's data directory. On Windows the WebView2 browser
/// process can hold the user-data folder for a moment after the window is
/// destroyed, so this retries off-thread before giving up with a warning.
/// Anything still left behind is swept on the next web-session open (see
/// [`sweep_stale_data_dirs`]).
pub fn remove_data_dir_eventually(dir: PathBuf) {
    std::thread::spawn(move || {
        const ATTEMPTS: u32 = 20;
        for attempt in 1..=ATTEMPTS {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(e) if attempt == ATTEMPTS => {
                    log::warn!(
                        "connect.web: could not remove session data dir {} after {ATTEMPTS} attempts: {e}; \
                         it will be swept on the next web session",
                        dir.display()
                    );
                    return;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    });
}

/// Remove data directories under `root` that belong to no live session —
/// leftovers from a crash or a removal that lost the race with WebView2.
pub fn sweep_stale_data_dirs(root: &std::path::Path, live_tokens: &[String]) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if live_tokens.iter().any(|t| t == &name) {
            continue;
        }
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            remove_data_dir_eventually(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn origin(s: &str) -> WebOrigin {
        WebOrigin::parse_config(s, false).unwrap()
    }

    fn open_profile(web: Value) -> Value {
        json!({
            "id": "p_web",
            "name": "Console",
            "protocol": "web",
            "credential_source": { "kind": "none" },
            "web": web,
        })
    }

    // ── Origin parsing and matching ────────────────────────────────

    #[test]
    fn default_ports_normalise() {
        assert_eq!(origin("https://app.example.com"), origin("https://app.example.com:443"));
        assert_eq!(origin("https://app.example.com:443").to_string(), "https://app.example.com");
        assert_eq!(origin("https://app.example.com:8443").to_string(), "https://app.example.com:8443");
        assert_ne!(origin("https://app.example.com"), origin("https://app.example.com:8443"));
    }

    #[test]
    fn host_is_case_insensitive_and_idn_is_punycoded() {
        assert_eq!(origin("https://APP.Example.COM"), origin("https://app.example.com"));
        let set = OriginSet::new(vec![origin("https://bücher.example")]);
        assert_eq!(set.check(&url("https://xn--bcher-kva.example/x")), NavigationVerdict::Allow);
    }

    #[test]
    fn trailing_slash_is_tolerated_but_a_path_is_not() {
        assert!(WebOrigin::parse_config("https://app.example.com/", false).is_ok());
        let err = WebOrigin::parse_config("https://app.example.com/admin", false).unwrap_err();
        assert!(err.contains("bare origin"), "{err}");
        assert!(WebOrigin::parse_config("https://app.example.com/?a=1", false).is_err());
        assert!(WebOrigin::parse_config("https://app.example.com/#f", false).is_err());
    }

    #[test]
    fn userinfo_is_refused_in_config_and_blocked_in_navigation() {
        let err = WebOrigin::parse_config("https://a@b.example", false).unwrap_err();
        assert!(err.contains("userinfo"), "{err}");
        let set = OriginSet::new(vec![origin("https://b.example")]);
        // The classic confusion: the *host* here is evil.example.
        assert_eq!(
            set.check(&url("https://b.example@evil.example/")),
            NavigationVerdict::Block { origin: "https:".into() }
        );
        assert_eq!(set.check(&url("https://user:pw@b.example/")), NavigationVerdict::Block { origin: "https:".into() });
    }

    #[test]
    fn http_needs_the_explicit_opt_in() {
        let err = WebOrigin::parse_config("http://app.example.com", false).unwrap_err();
        assert!(err.contains("allow_insecure_http"), "{err}");
        assert!(WebOrigin::parse_config("http://app.example.com", true).is_ok());
        // http and https on the same host are different origins.
        let set = OriginSet::new(vec![origin("https://app.example.com")]);
        assert_eq!(
            set.check(&url("http://app.example.com/")),
            NavigationVerdict::Block { origin: "http://app.example.com".into() }
        );
    }

    #[test]
    fn trailing_dot_hosts_are_refused_and_never_match() {
        assert!(WebOrigin::parse_config("https://app.example.com.", false).is_err());
        let set = OriginSet::new(vec![origin("https://app.example.com")]);
        assert!(matches!(set.check(&url("https://app.example.com./")), NavigationVerdict::Block { .. }));
    }

    #[test]
    fn vault_local_hosts_are_refused() {
        for raw in ["https://localhost", "http://localhost:1420", "http://tauri.localhost", "https://ipc.localhost"] {
            let err = WebOrigin::parse_config(raw, true).unwrap_err();
            assert!(err.contains("reserved"), "{raw}: {err}");
        }
    }

    #[test]
    fn non_web_schemes_are_refused_in_config() {
        for raw in ["ftp://files.example", "file:///etc/passwd", "tauri://localhost", "javascript:alert(1)"] {
            assert!(WebOrigin::parse_config(raw, true).is_err(), "{raw}");
        }
    }

    #[test]
    fn navigation_policy_by_scheme() {
        let set = OriginSet::new(vec![origin("https://app.example.com"), origin("https://sso.example.com")]);
        assert_eq!(set.check(&url("https://app.example.com/ng/x?y=1")), NavigationVerdict::Allow);
        assert_eq!(set.check(&url("https://sso.example.com/login")), NavigationVerdict::Allow);
        assert_eq!(set.check(&url("about:blank")), NavigationVerdict::Allow);
        assert_eq!(set.check(&url("about:srcdoc")), NavigationVerdict::Allow);
        assert_eq!(set.check(&url("blob:https://app.example.com/0b8e")), NavigationVerdict::Allow);
        // The blocked origin is logged without path or query.
        assert_eq!(
            set.check(&url("https://evil.example/steal?token=abc")),
            NavigationVerdict::Block { origin: "https://evil.example".into() }
        );
        assert_eq!(
            set.check(&url("blob:https://evil.example/0b8e")),
            NavigationVerdict::Block { origin: "blob:https://evil.example".into() }
        );
        assert_eq!(set.check(&url("data:text/html,hi")), NavigationVerdict::Block { origin: "data:".into() });
        assert_eq!(set.check(&url("mailto:a@b.example")), NavigationVerdict::Block { origin: "mailto:".into() });
        assert_eq!(set.check(&url("file:///etc/passwd")), NavigationVerdict::Block { origin: "file:".into() });
        assert_eq!(set.check(&url("about:config")), NavigationVerdict::Block { origin: "about:".into() });
    }

    #[test]
    fn subdomains_and_ports_are_distinct_origins() {
        let set = OriginSet::new(vec![origin("https://example.com")]);
        assert!(matches!(set.check(&url("https://www.example.com/")), NavigationVerdict::Block { .. }));
        assert!(matches!(set.check(&url("https://example.com:8443/")), NavigationVerdict::Block { .. }));
        assert!(matches!(set.check(&url("https://example.com.evil.example/")), NavigationVerdict::Block { .. }));
    }

    #[test]
    fn popups_need_the_flag_and_an_in_set_http_origin() {
        let set = OriginSet::new(vec![origin("https://app.example.com")]);
        assert_eq!(set.check_popup(&url("https://app.example.com/p"), true), NavigationVerdict::Allow);
        assert!(matches!(set.check_popup(&url("https://app.example.com/p"), false), NavigationVerdict::Block { .. }));
        assert!(matches!(set.check_popup(&url("https://evil.example/"), true), NavigationVerdict::Block { .. }));
        // about:blank popups are fine as frames, not as windows.
        assert!(matches!(set.check_popup(&url("about:blank"), true), NavigationVerdict::Block { .. }));
    }

    // ── Profile parsing ─────────────────────────────────────────────

    #[test]
    fn open_profile_parses_with_defaults() {
        let cfg = parse_web_profile(&open_profile(json!({
            "start_url": "https://fw01.example.com/login",
            "allowed_origins": ["https://sso.example.com", "https://FW01.example.com:443"],
            "login_mode": "open",
        })))
        .unwrap();
        assert_eq!(cfg.start_url.as_str(), "https://fw01.example.com/login");
        // start_url's origin is implicit; the duplicate collapses.
        assert_eq!(cfg.origins.len(), 2);
        assert!(!cfg.allow_downloads);
        assert!(cfg.allow_popups);
        assert_eq!(cfg.clipboard, WebClipboard::Off);
        assert!(!cfg.clipboard.grants_page_clipboard_access());
        assert_eq!((cfg.width, cfg.height), (DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT));
    }

    #[test]
    fn options_are_honoured() {
        let cfg = parse_web_profile(&open_profile(json!({
            "start_url": "http://legacy.example.com:8080/",
            "login_mode": "open",
            "allow_insecure_http": true,
            "allow_downloads": true,
            "allow_popups_same_origin_set": false,
            "clipboard": "bidirectional",
            "window": { "width": 1600, "height": 900 },
        })))
        .unwrap();
        assert!(cfg.allow_downloads);
        assert!(!cfg.allow_popups);
        assert!(cfg.clipboard.grants_page_clipboard_access());
        assert_eq!((cfg.width, cfg.height), (1600, 900));
        assert!(cfg.origins.contains(&WebOrigin::parse_config("http://legacy.example.com:8080", true).unwrap()));
    }

    #[test]
    fn later_phase_login_modes_are_refused_not_ignored() {
        for mode in ["form", "http-auth", "sso"] {
            let err = parse_web_profile(&open_profile(json!({
                "start_url": "https://a.example", "login_mode": mode,
            })))
            .unwrap_err();
            assert!(err.contains("not available yet"), "{mode}: {err}");
        }
        let err = parse_web_profile(&open_profile(json!({ "start_url": "https://a.example", "login_mode": "magic" })))
            .unwrap_err();
        assert!(err.contains("unknown login mode"), "{err}");
        let err = parse_web_profile(&open_profile(json!({ "start_url": "https://a.example" }))).unwrap_err();
        assert!(err.contains("no login_mode"), "{err}");
    }

    #[test]
    fn later_phase_fields_are_refused_not_ignored() {
        let base = |extra: Value| {
            let mut web = json!({ "start_url": "https://a.example", "login_mode": "open" });
            for (k, v) in extra.as_object().unwrap() {
                web[k] = v.clone();
            }
            parse_web_profile(&open_profile(web))
        };
        assert!(base(json!({ "transport": "rustion-isolated" })).unwrap_err().contains("not available"));
        assert!(base(json!({ "transport": "teleport" })).unwrap_err().contains("unknown web transport"));
        assert!(base(json!({ "recipe": { "version": 1 } })).unwrap_err().contains("form"));
        assert!(base(json!({ "tls_pin_sha256": ["abc"] })).unwrap_err().contains("pinning"));
        assert!(base(json!({ "tls_pin_sha256": [] })).is_ok());
        assert!(base(json!({ "clipboard": "sideways" })).is_err());
        assert!(base(json!({ "window": { "width": 10 } })).unwrap_err().contains("between"));
        assert!(base(json!({ "window": { "width": "wide" } })).is_err());
        assert!(base(json!({ "allow_downloads": "yes" })).is_err());
        assert!(base(json!({ "allowed_origins": "https://b.example" })).is_err());
        assert!(base(json!({ "allowed_origins": ["https://b.example/path"] })).is_err());
    }

    #[test]
    fn open_mode_refuses_real_credential_sources_and_rustion() {
        for kind in ["secret", "ldap", "default-account", "ssh-engine", "pki", "fido2"] {
            let mut p = open_profile(json!({ "start_url": "https://a.example", "login_mode": "open" }));
            p["credential_source"] = json!({ "kind": kind });
            let err = parse_web_profile(&p).unwrap_err();
            assert!(err.contains("does not apply"), "{kind}: {err}");
        }
        let mut p = open_profile(json!({ "start_url": "https://a.example", "login_mode": "open" }));
        p["kind"] = json!("rustion");
        assert!(parse_web_profile(&p).unwrap_err().contains("Rustion"));
    }

    #[test]
    fn start_url_rules() {
        let parse = |u: &str| parse_web_profile(&open_profile(json!({ "start_url": u, "login_mode": "open" })));
        assert!(parse("http://a.example").unwrap_err().contains("allow_insecure_http"));
        assert!(parse("https://user:pw@a.example/").unwrap_err().contains("userinfo"));
        assert!(parse("https://localhost:8443/").unwrap_err().contains("reserved"));
        assert!(parse("file:///tmp/x.html").is_err());
        assert!(parse("not a url").is_err());
        assert!(parse("   ").unwrap_err().contains("no start_url"));
        // Paths and queries are fine on the start URL; only the origin is
        // added to the allow-list.
        assert!(parse("https://a.example/ng/login?next=%2F").is_ok());
    }

    #[test]
    fn missing_web_block_is_refused() {
        let p = json!({ "id": "p", "name": "x", "protocol": "web", "credential_source": { "kind": "none" } });
        assert!(parse_web_profile(&p).unwrap_err().contains("no `web` settings"));
    }

    #[test]
    fn download_file_name_drops_the_directory() {
        assert_eq!(download_file_name(std::path::Path::new("/Users/op/Downloads/report.csv")), "report.csv");
    }

    #[test]
    fn sweep_removes_only_dead_sessions() {
        let root = std::env::temp_dir().join(format!("bv-web-sweep-{}", std::process::id()));
        let live = root.join("sess_live");
        let dead = root.join("sess_dead");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&dead).unwrap();
        sweep_stale_data_dirs(&root, &["sess_live".to_string()]);
        // Removal runs off-thread; give it a moment.
        for _ in 0..50 {
            if !dead.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(live.exists());
        assert!(!dead.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
