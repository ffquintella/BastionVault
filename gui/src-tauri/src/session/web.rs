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

/// Directory (under the app cache dir) holding the per-process instance
/// directories. Each running process owns `<cache>/web-sessions/<instance>/`
/// (see [`WebInstance`]) and each of its sessions gets
/// `<instance>/<token>`, removed when the session ends.
pub const DATA_DIR_NAME: &str = "web-sessions";

/// Held-open, exclusively locked file in every instance directory. Its lock
/// is the "this process is alive" signal the stale sweep reads.
const INSTANCE_LOCK_FILE: &str = ".lock";

/// An instance directory with no `.lock` file is either a leftover from the
/// pre-instance layout or an instance caught between `mkdir` and taking its
/// lock. Only one older than this is swept.
const UNLOCKED_INSTANCE_GRACE: Duration = Duration::from_secs(10 * 60);

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

/// `Ok(None)` when the key is absent or null, `Ok(Some)` for a string, and an
/// error for any other type. A security-relevant field of the wrong type must
/// never be read as "not set": that is how a typo turns a refusal into an
/// open.
fn opt_str<'a>(v: Option<&'a Value>, what: &str) -> Result<Option<&'a str>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(format!("{what} must be a string")),
    }
}

/// Parse and validate the `web` half of a connection profile for an
/// `open`-mode launch. Every field that belongs to a later phase is
/// refused when set, never ignored. Every field the checks below read is
/// type-checked: absent / null means unset, any other wrong type is an error.
pub fn parse_web_profile(profile: &Value) -> Result<WebSessionConfig, String> {
    // The profile's own transport. Rustion-brokered web sessions are the
    // Phase 8 browser-isolation design; nothing routes them today.
    match opt_str(profile.get("kind"), "the profile's transport (`kind`)")? {
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
    match profile.get("credential_source") {
        None | Some(Value::Null) => {}
        Some(Value::Object(cs)) => {
            let kind = opt_str(cs.get("kind"), "credential_source.kind")?.unwrap_or("");
            if kind != "none" {
                return Err(format!(
                    "credential source `{kind}` does not apply to the `open` login mode, which releases no \
                     credential; set the source to none"
                ));
            }
        }
        Some(_) => return Err("credential_source must be an object".to_string()),
    }

    let web = match profile.get("web") {
        Some(Value::Object(m)) => m,
        None | Some(Value::Null) => return Err("web profile has no `web` settings block".to_string()),
        Some(_) => return Err("the profile's `web` settings must be an object".to_string()),
    };

    match opt_str(web.get("login_mode"), "web.login_mode")? {
        Some("open") => {}
        Some(mode @ ("form" | "http-auth" | "sso")) => {
            return Err(format!("login mode `{mode}` is not available yet; this release supports `open` only"))
        }
        Some(other) => return Err(format!("unknown login mode `{other}`")),
        None => return Err("web profile has no login_mode".to_string()),
    }

    match opt_str(web.get("transport"), "web.transport")? {
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
    // A pin the window cannot honour must not look like it is honoured. A
    // non-list value is not "no pin" — it is a pin we cannot read.
    match web.get("tls_pin_sha256") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) if a.is_empty() => {}
        Some(Value::Array(_)) => {
            return Err("TLS certificate pinning for web sessions is not available yet; remove tls_pin_sha256 \
                 (the session fails closed on an untrusted certificate)"
                .to_string())
        }
        Some(_) => return Err("web.tls_pin_sha256 must be a list".to_string()),
    }

    let allow_insecure_http = opt_bool(web, "allow_insecure_http", false)?;
    let allow_downloads = opt_bool(web, "allow_downloads", false)?;
    let allow_popups = opt_bool(web, "allow_popups_same_origin_set", true)?;

    let start_raw = opt_str(web.get("start_url"), "web.start_url")?
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

/// What the download handler does with a `DownloadEvent::Requested`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadDecision {
    Allow,
    /// `reason` is the audit token (`disabled` or `origin`); `origin` is
    /// safe to log (see [`NavigationVerdict::Block`]).
    Deny {
        reason: &'static str,
        origin: String,
    },
}

/// Downloads are denied unless the profile allows them, and an allowed
/// download must also come from an origin in the profile's set — the same
/// verdict navigation gets, so `allow_downloads` cannot be used to pull a
/// file from an origin the window itself may not visit.
pub fn download_decision(allow_downloads: bool, origins: &OriginSet, url: &Url) -> DownloadDecision {
    if !allow_downloads {
        return DownloadDecision::Deny { reason: "disabled", origin: display_origin(url) };
    }
    match origins.check(url) {
        NavigationVerdict::Allow => DownloadDecision::Allow,
        NavigationVerdict::Block { origin } => DownloadDecision::Deny { reason: "origin", origin },
    }
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
/// Anything still left behind is swept, once this process or its instance is
/// gone, by [`sweep_stale_instances`].
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
                         it will be swept by a later process",
                        dir.display()
                    );
                    return;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    });
}

/// This process's instance directory under the web-sessions root. Holds a
/// `.lock` file, opened and exclusively locked for as long as the value
/// lives (the process lifetime, via [`session_data_dir`]), so any other
/// process can tell a live owner from a dead one by trying to take the same
/// lock. The OS releases the lock when the process exits or crashes.
pub struct WebInstance {
    dir: PathBuf,
    /// Never read: it is held open for the lock.
    _lock: std::fs::File,
}

impl WebInstance {
    /// Create `<root>/<new id>/` (mode 0700 on unix) and lock its `.lock`.
    pub fn create(root: &std::path::Path) -> Result<Self, String> {
        let id = crate::session::ssh::new_token();
        let dir = root.join(&id);
        create_private_dir(&dir)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(INSTANCE_LOCK_FILE))
            .map_err(|e| format!("create web instance lock in {}: {e}", dir.display()))?;
        lock.try_lock().map_err(|e| format!("lock web instance dir {}: {e}", dir.display()))?;
        Ok(Self { dir, _lock: lock })
    }

    #[cfg(test)]
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Directory name, which is also the instance id.
    pub fn id(&self) -> String {
        self.dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }

    /// Create and return `<instance>/<token>` for one session.
    pub fn session_dir(&self, token: &str) -> Result<PathBuf, String> {
        let dir = self.dir.join(token);
        create_private_dir(&dir)?;
        Ok(dir)
    }
}

fn create_private_dir(dir: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create web session data dir {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("restrict web session data dir {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// The one instance of this process. A mutex rather than a `OnceLock` so a
/// failed creation (full disk, bad permissions) is retried on the next open
/// instead of being cached for the process lifetime.
static INSTANCE: std::sync::Mutex<Option<std::sync::Arc<WebInstance>>> = std::sync::Mutex::new(None);

/// Create this session's webview data directory under the process's
/// instance directory (created and locked on first use), after sweeping
/// instance directories left behind by dead processes. Never touches a
/// live process's directories, this process's included.
pub fn session_data_dir(root: &std::path::Path, token: &str) -> Result<PathBuf, String> {
    let instance = {
        let mut guard = INSTANCE.lock().unwrap_or_else(|p| p.into_inner());
        match guard.as_ref() {
            Some(i) => std::sync::Arc::clone(i),
            None => {
                std::fs::create_dir_all(root)
                    .map_err(|e| format!("create web sessions root {}: {e}", root.display()))?;
                let i = std::sync::Arc::new(WebInstance::create(root)?);
                *guard = Some(std::sync::Arc::clone(&i));
                i
            }
        }
    };
    sweep_stale_instances(root, &instance.id(), UNLOCKED_INSTANCE_GRACE);
    instance.session_dir(token)
}

/// Remove instance directories under `root` whose owning process is gone —
/// leftovers from a crash, or a removal that lost the race with WebView2.
///
/// An instance is dead when its `.lock` can be locked here (the owner's
/// lock dies with it). `own_id` and any directory whose lock is held are
/// left alone, so two running copies of the app never delete each other's
/// live sessions. A directory with no `.lock` at all (the layout before
/// instance directories, or an instance mid-creation) is removed only once
/// it is older than `unlocked_grace`.
pub fn sweep_stale_instances(root: &std::path::Path, own_id: &str, unlocked_grace: Duration) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy() == own_id {
            continue;
        }
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        match std::fs::OpenOptions::new().read(true).write(true).open(path.join(INSTANCE_LOCK_FILE)) {
            Ok(lock) => match lock.try_lock() {
                Ok(()) => {
                    // The lock is held only until the handle closes, and
                    // Windows cannot delete a directory containing an open
                    // file, so release it before removing. The owner is
                    // dead and no other process creates this id.
                    drop(lock);
                    remove_data_dir_eventually(path);
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(e)) => {
                    log::warn!("connect.web: could not probe web instance lock in {}: {e}", path.display());
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let age = entry.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
                if age.is_some_and(|a| a >= unlocked_grace) {
                    remove_data_dir_eventually(path);
                }
            }
            Err(e) => {
                log::warn!("connect.web: could not open web instance lock in {}: {e}", path.display());
            }
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

    fn wait_until_gone(p: &std::path::Path) {
        // Removal runs off-thread; give it a moment.
        for _ in 0..100 {
            if !p.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn scratch_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "bv-web-{tag}-{}-{}",
            std::process::id(),
            crate::session::ssh::new_token()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn sweep_spares_locked_instances_and_removes_unlocked_ones() {
        let root = scratch_root("sweep");
        let own = WebInstance::create(&root).unwrap();
        let own_session = own.session_dir("sess_own").unwrap();
        let foreign_live = WebInstance::create(&root).unwrap();
        let foreign_live_session = foreign_live.session_dir("sess_theirs").unwrap();
        let foreign_dead = WebInstance::create(&root).unwrap();
        let dead_dir = foreign_dead.dir().to_path_buf();
        let dead_session = foreign_dead.session_dir("sess_old").unwrap();
        // The owner of this one exits: its lock is released.
        drop(foreign_dead);

        sweep_stale_instances(&root, &own.id(), UNLOCKED_INSTANCE_GRACE);
        wait_until_gone(&dead_dir);

        assert!(!dead_dir.exists(), "an unlocked foreign instance is removed");
        assert!(!dead_session.exists());
        assert!(foreign_live_session.exists(), "a locked foreign instance survives");
        assert!(own_session.exists(), "the sweeping instance's own dirs are untouched");

        // Once the other owner exits, the next sweep removes it too.
        let live_dir = foreign_live.dir().to_path_buf();
        drop(foreign_live);
        sweep_stale_instances(&root, &own.id(), UNLOCKED_INSTANCE_GRACE);
        wait_until_gone(&live_dir);
        assert!(!live_dir.exists());
        assert!(own_session.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sweep_never_touches_its_own_instance_even_when_unlocked() {
        let root = scratch_root("own");
        let own = WebInstance::create(&root).unwrap();
        let session = own.session_dir("sess_a").unwrap();
        // A zero grace would remove any lock-less dir; the own id is skipped first.
        sweep_stale_instances(&root, &own.id(), Duration::ZERO);
        std::thread::sleep(Duration::from_millis(100));
        assert!(session.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lock_less_dirs_are_swept_only_after_the_grace_period() {
        let root = scratch_root("legacy");
        let own = WebInstance::create(&root).unwrap();
        // A pre-instance-layout leftover: `<root>/<token>` with no `.lock`.
        let legacy = root.join("sess_legacy");
        std::fs::create_dir_all(&legacy).unwrap();
        // A plain file in the root is never touched.
        let stray = root.join("notes.txt");
        std::fs::write(&stray, b"x").unwrap();

        sweep_stale_instances(&root, &own.id(), UNLOCKED_INSTANCE_GRACE);
        std::thread::sleep(Duration::from_millis(100));
        assert!(legacy.exists(), "a fresh lock-less dir may be an instance mid-creation");

        sweep_stale_instances(&root, &own.id(), Duration::ZERO);
        wait_until_gone(&legacy);
        assert!(!legacy.exists());
        assert!(stray.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_lock_on_a_live_instance_is_refused() {
        let root = scratch_root("lock");
        let inst = WebInstance::create(&root).unwrap();
        let other = std::fs::OpenOptions::new().read(true).write(true).open(inst.dir().join(".lock")).unwrap();
        assert!(matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Download policy ─────────────────────────────────────────────

    #[test]
    fn downloads_need_the_flag_and_an_in_set_origin() {
        let set = OriginSet::new(vec![origin("https://app.example.com")]);
        let ok = url("https://app.example.com/export.csv");
        let foreign = url("https://evil.example/payload.exe?token=abc");
        assert_eq!(download_decision(true, &set, &ok), DownloadDecision::Allow);
        assert_eq!(
            download_decision(false, &set, &ok),
            DownloadDecision::Deny { reason: "disabled", origin: "https://app.example.com".into() }
        );
        // Allowed downloads still get the navigation verdict; the origin is logged without path or query.
        assert_eq!(
            download_decision(true, &set, &foreign),
            DownloadDecision::Deny { reason: "origin", origin: "https://evil.example".into() }
        );
        assert!(matches!(
            download_decision(true, &set, &url("data:text/html,hi")),
            DownloadDecision::Deny { reason: "origin", .. }
        ));
        assert_eq!(download_decision(true, &set, &url("blob:https://app.example.com/0b8e")), DownloadDecision::Allow);
        assert!(matches!(
            download_decision(true, &set, &url("blob:https://evil.example/0b8e")),
            DownloadDecision::Deny { reason: "origin", .. }
        ));
    }

    // ── Wrong JSON types fail closed ────────────────────────────────

    fn web_with(extra: Value) -> Result<WebSessionConfig, String> {
        let mut web = json!({ "start_url": "https://a.example", "login_mode": "open" });
        for (k, v) in extra.as_object().unwrap() {
            web[k] = v.clone();
        }
        parse_web_profile(&open_profile(web))
    }

    #[test]
    fn wrong_typed_profile_kind_is_an_error_not_direct() {
        for bad in [json!(5), json!(true), json!(["rustion"]), json!({ "k": "rustion" })] {
            let mut p = open_profile(json!({ "start_url": "https://a.example", "login_mode": "open" }));
            p["kind"] = bad.clone();
            let err = parse_web_profile(&p).unwrap_err();
            assert!(err.contains("must be a string"), "{bad}: {err}");
        }
        let mut p = open_profile(json!({ "start_url": "https://a.example", "login_mode": "open" }));
        p["kind"] = Value::Null;
        assert!(parse_web_profile(&p).is_ok());
        p["kind"] = json!("direct");
        assert!(parse_web_profile(&p).is_ok());
    }

    #[test]
    fn wrong_typed_web_transport_is_an_error_not_local() {
        for bad in [json!(5), json!(false), json!(["rustion-isolated"]), json!({})] {
            let err = web_with(json!({ "transport": bad.clone() })).unwrap_err();
            assert!(err.contains("web.transport must be a string"), "{bad}: {err}");
        }
        assert!(web_with(json!({ "transport": null })).is_ok());
        assert!(web_with(json!({ "transport": "local" })).is_ok());
    }

    #[test]
    fn wrong_typed_tls_pin_is_an_error_not_no_pin() {
        for bad in [json!("sha256:abc"), json!(5), json!(true), json!({ "pin": "abc" })] {
            let err = web_with(json!({ "tls_pin_sha256": bad.clone() })).unwrap_err();
            assert!(err.contains("tls_pin_sha256 must be a list"), "{bad}: {err}");
        }
        assert!(web_with(json!({ "tls_pin_sha256": null })).is_ok());
        assert!(web_with(json!({ "tls_pin_sha256": [] })).is_ok());
        assert!(web_with(json!({ "tls_pin_sha256": ["x"] })).unwrap_err().contains("pinning"));
    }

    #[test]
    fn wrong_typed_login_mode_and_start_url_are_errors() {
        for bad in [json!(1), json!(true), json!(["open"])] {
            let err = web_with(json!({ "login_mode": bad.clone() })).unwrap_err();
            assert!(err.contains("web.login_mode must be a string"), "{bad}: {err}");
            let err = web_with(json!({ "start_url": bad.clone() })).unwrap_err();
            assert!(err.contains("web.start_url must be a string"), "{bad}: {err}");
        }
    }

    #[test]
    fn wrong_typed_credential_source_is_an_error_not_none() {
        for bad in [json!("none"), json!(5), json!(["none"]), json!(true)] {
            let mut p = open_profile(json!({ "start_url": "https://a.example", "login_mode": "open" }));
            p["credential_source"] = bad.clone();
            let err = parse_web_profile(&p).unwrap_err();
            assert!(err.contains("credential_source must be an object"), "{bad}: {err}");
        }
        for bad in [json!(5), json!(null), json!(["none"])] {
            let mut p = open_profile(json!({ "start_url": "https://a.example", "login_mode": "open" }));
            p["credential_source"] = json!({ "kind": bad.clone() });
            assert!(parse_web_profile(&p).is_err(), "{bad}");
        }
        // Absent / null source is the same as `none`: nothing is released either way.
        let mut p = open_profile(json!({ "start_url": "https://a.example", "login_mode": "open" }));
        p["credential_source"] = Value::Null;
        assert!(parse_web_profile(&p).is_ok());
        p.as_object_mut().unwrap().remove("credential_source");
        assert!(parse_web_profile(&p).is_ok());
    }

    #[test]
    fn a_non_object_web_block_is_refused() {
        for bad in [json!("open"), json!(5), json!([])] {
            let mut p = open_profile(json!({}));
            p["web"] = bad.clone();
            assert!(parse_web_profile(&p).unwrap_err().contains("must be an object"), "{bad}");
        }
    }

    #[test]
    fn wrong_typed_boolean_options_clipboard_and_origins_are_errors() {
        for key in ["allow_insecure_http", "allow_downloads", "allow_popups_same_origin_set"] {
            for bad in [json!("true"), json!(1), json!([])] {
                let err = web_with(json!({ key: bad.clone() })).unwrap_err();
                assert!(err.contains(key), "{key} {bad}: {err}");
            }
        }
        for bad in [json!(true), json!(5), json!(["off"])] {
            assert!(web_with(json!({ "clipboard": bad.clone() })).is_err(), "{bad}");
        }
        for bad in [json!("https://b.example"), json!(5), json!({}), json!([5])] {
            assert!(web_with(json!({ "allowed_origins": bad.clone() })).is_err(), "{bad}");
        }
    }
}
