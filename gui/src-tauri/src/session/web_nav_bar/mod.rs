//! Cross-platform orchestrator for the web session nav bar
//! (back / forward / reload / download).
//!
//! The bar is a 36 px native sibling of the webview — not a DOM node, so a
//! hostile page cannot cover or remove it (docs/specs/2026-10-20-web-session-nav-controls-design.md
//! §7.1, §7.2). This module owns the pieces every platform needs:
//! - [`NavAction`], [`NavState`] and the [`NavBar`] trait each per-platform
//!   shim implements.
//! - [`NavBarAudit`], the per-session audit sink the shim calls on nav /
//!   download events (`connect.web.nav` / `download` / `download_refused`).
//! - [`DownloadLimiter`], the per-window `2 concurrent / 2 GiB soft cap`
//!   rate limiter the shim's download delegate consults.
//! - [`sanitize_filename`] and [`next_free_path`] (re-exported from
//!   [`filename`]), the pure-Rust path helpers.
//! - [`mark_operator_reload`] / [`take_operator_reload`], the one-shot
//!   flag the Reload button sets so the fill engine's step-picker skips
//!   the next match on the URL the operator reloaded (G5; wired in
//!   Task 6).
//!
//! Per-platform attachment lives in `macos.rs`, `windows.rs`, `linux.rs`
//! — added by Tasks 2–4, which also declare them in this file behind
//! `#[cfg(target_os = "…")]`. Until then the orchestrator and its unit
//! tests compile on every host without a platform shim.
//!
//! Dead-code allow: Tasks 2–7 of
//! docs/plans/2026-10-20-web-session-nav-controls.md consume every item
//! defined here (the per-platform shims call `NavBar`, `NavBarAudit`,
//! `DownloadLimiter`, `sanitize_filename` and `next_free_path`; the
//! composition root in `commands/connect_web.rs` constructs them). Allow
//! dead_code at the module boundary so the first commit stays
//! warning-free; later tasks drop the attribute once their callers land.
#![allow(dead_code)]

pub mod filename;

// Per-platform shim modules are declared by Tasks 2–4 of
// docs/plans/2026-10-20-web-session-nav-controls.md:
//   #[cfg(target_os = "macos")]   pub mod macos;    // Task 2
//   #[cfg(target_os = "windows")] pub mod windows;  // Task 3
//   #[cfg(target_os = "linux")]   pub mod linux;    // Task 4
// They all consume the trait, state and audit types defined below.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

#[allow(unused_imports)] // consumed by the per-platform shims (Tasks 2–4).
pub use filename::{next_free_path, sanitize_filename, CollisionExhausted, NextPathError};

use super::web;

/// Per-download soft cap. Above this the shim's download delegate
/// cancels the transfer and the bar flashes a short-lived error state
/// (spec §7.6).
pub const DOWNLOAD_SOFT_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Per-window maximum of in-flight downloads (spec §7.6). The third
/// concurrent click is a no-op with a tooltip.
pub const MAX_CONCURRENT_DOWNLOADS: u8 = 2;

/// A button on the bar. Each per-platform shim decodes a click into one
/// of these and dispatches to the webview's history / reload / download
/// primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavAction {
    Back,
    Forward,
    Reload,
    Download,
}

impl NavAction {
    /// The stable `action=` token for the audit line (spec §8.3).
    /// [`NavBarAudit::nav`] logs only back / forward / reload; a download
    /// click is audited by `download_ok` / `download_refused`.
    pub fn audit_token(self) -> &'static str {
        match self {
            Self::Back => "back",
            Self::Forward => "forward",
            Self::Reload => "reload",
            Self::Download => "download",
        }
    }
}

/// What the shim observed about the current main-frame response plus the
/// profile's `allow_downloads` flag. Rebuilt on every webview state
/// change (page load, `canGoBack` / `canGoForward` KVO, download
/// response headers) and handed to [`NavBar::set_state`] so the shim can
/// re-render button enablement without re-reading the webview.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NavState {
    /// Mirror of `WKWebView.canGoBack` / `CoreWebView2.CanGoBack` /
    /// `webkit_web_view_can_go_back` for the top frame.
    pub can_go_back: bool,
    /// Mirror of `canGoForward`.
    pub can_go_forward: bool,
    /// True between a navigation start event and its final load/error
    /// event. The download button is disabled while loading because the
    /// response headers that decide "is this downloadable" are not yet
    /// known (spec §7.3 "except mid-reload", plus the Review focus
    /// pin: "download during an in-flight navigation").
    pub is_loading: bool,
    /// `Content-Type` of the current main-frame response, as received
    /// ([`is_downloadable_mime`] strips parameters). `None` before the
    /// first response, and for a response that carried no Content-Type;
    /// such a response is downloadable only through
    /// `content_disposition_attachment`.
    pub current_mime: Option<String>,
    /// `true` iff the current main-frame response carried
    /// `Content-Disposition: attachment`. Enables the download button
    /// even for `text/html` (spec §7.5 last paragraph).
    pub content_disposition_attachment: bool,
    /// Profile-level permission. `false` → the button is rendered
    /// disabled with the "Downloads disabled for this profile." tooltip
    /// (spec §7.4). Operators cannot override it in-window.
    pub allow_downloads: bool,
}

impl NavState {
    /// Whether the download button should be clickable right now.
    ///
    /// Follows spec §7.3 / §7.4 / §7.5 exactly:
    /// - `allow_downloads` must be true (profile gate, §7.4);
    /// - the main frame must not be loading (its response headers are not
    ///   known yet);
    /// - the response carried `Content-Disposition: attachment`, or its
    ///   mime is in the downloadable set ([`is_downloadable_mime`]). An
    ///   attachment needs no Content-Type (§7.3: mime **or** attachment).
    pub fn download_enabled(&self) -> bool {
        if !self.allow_downloads || self.is_loading {
            return false;
        }
        self.content_disposition_attachment || self.current_mime.as_deref().is_some_and(is_downloadable_mime)
    }
}

/// The downloadable MIME set from spec §7.5. Parameters (`; charset=…`)
/// are stripped before matching; the comparison is ASCII case-insensitive
/// (RFC 7231: media types are case-insensitive).
///
/// `text/*`, `application/xhtml+xml` and `application/*+xml` / `+json`
/// are excluded; an HTML response is downloadable only through
/// `Content-Disposition: attachment` ([`NavState::download_enabled`]).
pub fn is_downloadable_mime(mime: &str) -> bool {
    let base = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    // image/svg+xml is scriptable and is explicitly excluded, even though
    // it matches the image/* prefix.
    if base == "image/svg+xml" {
        return false;
    }
    matches!(
        base.as_str(),
        "application/pdf"
            | "application/zip"
            | "application/x-tar"
            | "application/x-7z-compressed"
            | "application/x-rar-compressed"
            | "application/gzip"
            | "application/octet-stream"
    ) || base.starts_with("application/x-")
        || base.starts_with("image/")
        || base.starts_with("video/")
        || base.starts_with("audio/")
        || base.starts_with("application/vnd.ms-")
        || base.starts_with("application/vnd.openxmlformats-officedocument.")
        || base.starts_with("application/vnd.oasis.opendocument.")
}

/// The platform-specific bar handle. Each per-platform shim returns a
/// `Box<dyn NavBar>` from its `attach` function; the window's teardown
/// calls [`NavBar::detach`] to unparent the native views on the main
/// thread.
pub trait NavBar: Send {
    /// Re-render button enablement from `state`. Called from the host's
    /// main thread.
    fn set_state(&self, state: &NavState);
    /// Remove the bar from the window and release native resources.
    /// Takes `Box<Self>` so the trait object is consumed.
    fn detach(self: Box<Self>);
}

/// Which download path the shim took. The spec audits this so a
/// reviewer can tell MOTW-stamped downloads apart from the re-request
/// fallback on macOS 10.15 / WebKitGTK (spec §7.6 last paragraph).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadPath {
    /// `WKDownload` on macOS 11.3+, `CoreWebView2.DownloadStarting` on
    /// Windows, `WebKitDownload` on Linux. The native path; MOTW /
    /// quarantine is set on macOS and Windows by the OS.
    Webview,
    /// Fallback: `URLSession` on macOS 10.15–11.2, WebKitGTK's
    /// `webkit_web_view_download_uri` (re-requests). No MOTW; the audit
    /// line names it so a reviewer can see which path was taken.
    Refetch,
}

/// Per-session audit sink for the bar's events. Lines use the
/// `connect.web.*` shape (`target: "audit"`, `resource=` and `token=`
/// first). Never log cookies, credentials, the launch id or a URL.
pub struct NavBarAudit {
    pub app: tauri::AppHandle,
    pub resource: String,
    pub token: String,
}

/// Refusal reason tokens for [`NavBarAudit::download_refused`]. Every token
/// matches `[a-z0-9_]{1,32}` so the line stays one parseable `key=value`
/// field, and none is derived from page-controlled or OS-supplied text.
pub mod reason {
    /// The download URL's origin is outside the window's navigation allowlist.
    pub const OUTSIDE_ALLOWLIST: &str = "outside_allowlist";
    /// The profile has `allow_downloads = false`.
    pub const DOWNLOADS_DISABLED: &str = "downloads_disabled";
    /// The transfer passed [`super::DOWNLOAD_SOFT_CAP_BYTES`] and was cancelled.
    pub const SIZE_EXCEEDED: &str = "size_exceeded";
    /// A third concurrent download was refused ([`super::MAX_CONCURRENT_DOWNLOADS`]).
    pub const TOO_MANY_DOWNLOADS: &str = "too_many_downloads";
    /// [`super::NextPathError::Exhausted`].
    pub const COLLISION_EXHAUSTED: &str = "collision_exhausted";
    /// [`super::NextPathError::Io`].
    pub const SAVE_IO_ERROR: &str = "save_io_error";
    /// [`super::NextPathError::InvalidName`].
    pub const INVALID_FILENAME: &str = "invalid_filename";
}

/// Map a [`NextPathError`] to its fixed audit reason token. The
/// `io::Error` text is deliberately dropped: it can carry the destination
/// path, which the audit trail must not record.
pub fn refusal_reason(err: &NextPathError) -> &'static str {
    match err {
        NextPathError::Exhausted(_) => reason::COLLISION_EXHAUSTED,
        NextPathError::Io(_) => reason::SAVE_IO_ERROR,
        NextPathError::InvalidName => reason::INVALID_FILENAME,
    }
}

impl DownloadPath {
    /// The stable `path=` token for the download audit line.
    pub fn audit_token(self) -> &'static str {
        match self {
            Self::Webview => "webview",
            Self::Refetch => "refetch",
        }
    }
}

/// The `mime=` field comes from a response header the page's server
/// controls. Keep it to media-type characters (type/subtype, parameters
/// stripped) and fold anything else to `invalid`, so it can neither carry
/// whitespace that forges another `key=value` field nor grow the line.
fn audit_mime(mime: &str) -> String {
    let base = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let ok = !base.is_empty()
        && base.len() <= 127
        && base.matches('/').count() == 1
        && base.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'.' | b'-' | b'_'));
    if ok {
        base
    } else {
        "invalid".to_string()
    }
}

/// The `filename=` field, self-contained: control characters are dropped
/// (a name with a newline cannot start a second audit line) and the rest is
/// logged quoted and escaped (`{:?}`), so spaces, `=` and `"` in the name
/// cannot pass for further `key=value` fields.
fn audit_filename(filename: &str) -> String {
    let printable: String = filename.chars().filter(|c| !c.is_control()).collect();
    format!("{printable:?}")
}

// The line builders are pure so the shapes are testable without a
// `tauri::AppHandle` or a global logger; the `NavBarAudit` methods go
// through the `emit_*` wrappers, which only log the built line.
fn nav_line(resource: &str, token: &str, action: NavAction) -> String {
    debug_assert!(action != NavAction::Download, "a download click is audited by download_ok / download_refused");
    format!("connect.web.nav: resource={resource} token={token} action={}", action.audit_token())
}

fn download_line(resource: &str, token: &str, filename: &str, mime: &str, bytes: u64, path: DownloadPath) -> String {
    format!(
        "connect.web.download: resource={resource} token={token} filename={} mime={} bytes={bytes} path={}",
        audit_filename(filename),
        audit_mime(mime),
        path.audit_token(),
    )
}

fn refused_line(resource: &str, token: &str, reason: &'static str) -> String {
    format!("connect.web.download_refused: resource={resource} token={token} reason={reason}")
}

fn emit_nav(resource: &str, token: &str, action: NavAction) {
    log::info!(target: "audit", "{}", nav_line(resource, token, action));
}

fn emit_download_ok(resource: &str, token: &str, filename: &str, mime: &str, bytes: u64, path: DownloadPath) {
    log::info!(target: "audit", "{}", download_line(resource, token, filename, mime, bytes, path));
}

fn emit_download_refused(resource: &str, token: &str, reason: &'static str) {
    log::info!(target: "audit", "{}", refused_line(resource, token, reason));
}

impl NavBarAudit {
    /// Emit `connect.web.nav: resource=… token=… action=back|forward|reload`.
    /// Download clicks go through [`Self::download_ok`] /
    /// [`Self::download_refused`] instead.
    pub fn nav(&self, action: NavAction) {
        emit_nav(&self.resource, &self.token, action);
    }

    /// Emit `connect.web.download: resource=… token=… filename="<basename>"
    /// mime=<type> bytes=<n> path=webview|refetch`. `filename` should be
    /// sanitised by [`sanitize_filename`]; the line builder also drops
    /// control characters and quotes/escapes the name. The URL (path and
    /// query included) is never part of the line.
    pub fn download_ok(&self, filename: &str, mime: &str, bytes: u64, path: DownloadPath) {
        emit_download_ok(&self.resource, &self.token, filename, mime, bytes, path);
    }

    /// Emit `connect.web.download_refused: resource=… token=… reason=…`.
    /// `reason` is one of the [`reason`] constants, or the result of
    /// [`refusal_reason`].
    pub fn download_refused(&self, reason: &'static str) {
        emit_download_refused(&self.resource, &self.token, reason);
    }
}

/// Per-window rate limiter: `2 concurrent downloads / 2 GiB soft cap`
/// (spec §7.6). The shim's download delegate calls [`Self::try_acquire`]
/// before accepting a download and [`DownloadSlot::record`] on every
/// chunk. The slot drops when the download completes or is cancelled,
/// releasing the concurrency count.
///
/// The limiter is kept behind `Arc` so a slot can outlive the stack
/// frame that created it (async callbacks on the webview thread) while
/// still releasing the counter on drop.
#[derive(Debug)]
pub struct DownloadLimiter {
    concurrent: AtomicU8,
}

impl Default for DownloadLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl DownloadLimiter {
    pub fn new() -> Self {
        Self { concurrent: AtomicU8::new(0) }
    }

    /// Reserve one of the `MAX_CONCURRENT_DOWNLOADS` slots. `None` when
    /// the cap is reached — the shim renders a one-shot tooltip and
    /// drops the click.
    pub fn try_acquire(self: &Arc<Self>) -> Option<DownloadSlot> {
        let mut cur = self.concurrent.load(Ordering::SeqCst);
        loop {
            if cur >= MAX_CONCURRENT_DOWNLOADS {
                return None;
            }
            match self.concurrent.compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(DownloadSlot { limiter: Arc::clone(self), bytes: AtomicU64::new(0) }),
                Err(v) => cur = v,
            }
        }
    }

    /// Number of slots currently in use. Diagnostic / test only.
    pub fn in_flight(&self) -> u8 {
        self.concurrent.load(Ordering::SeqCst)
    }
}

/// A reservation on the concurrency counter plus a byte accumulator for
/// one in-flight download. Dropped by the shim when the download
/// finishes or is cancelled.
#[derive(Debug)]
pub struct DownloadSlot {
    limiter: Arc<DownloadLimiter>,
    bytes: AtomicU64,
}

/// Returned by [`DownloadSlot::record`] when the running byte total
/// would exceed [`DOWNLOAD_SOFT_CAP_BYTES`]. The shim cancels the
/// transfer and reports `reason=size_exceeded` to the audit sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeExceeded;

impl std::fmt::Display for SizeExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "download exceeds the {}-byte soft cap", DOWNLOAD_SOFT_CAP_BYTES)
    }
}

impl std::error::Error for SizeExceeded {}

impl DownloadSlot {
    /// Add `n` bytes to the running total. `Err(SizeExceeded)` when the
    /// running total passes [`DOWNLOAD_SOFT_CAP_BYTES`]. The error is
    /// sticky: the total never decreases, so every later call fails too.
    pub fn record(&self, n: u64) -> Result<(), SizeExceeded> {
        // The stored total saturates at u64::MAX instead of wrapping, so a
        // huge chunk (a hostile length, a delegate bug) can never bring the
        // counter back under the cap for the chunks that follow. `update`
        // is the infallible successor of the deprecated `fetch_update`; it
        // returns the previous value.
        let previous = self.bytes.update(Ordering::SeqCst, Ordering::SeqCst, |c| c.saturating_add(n));
        let total = previous.saturating_add(n);
        if total > DOWNLOAD_SOFT_CAP_BYTES {
            Err(SizeExceeded)
        } else {
            Ok(())
        }
    }

    /// Running byte total. Diagnostic / test only.
    pub fn bytes_recorded(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }
}

impl Drop for DownloadSlot {
    fn drop(&mut self) {
        // Release the concurrency slot. Each slot exists only after one
        // successful increment in `try_acquire`, so this decrement cannot
        // underflow. A slot leaked through `mem::forget` never decrements:
        // the window keeps one fewer slot for the rest of its life.
        self.limiter.concurrent.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Mark the operator's reload intent on `shared` (G5). The fill engine
/// skips the first load whose generation is newer than the page's now,
/// i.e. the reload's own load, so an operator who reloaded the login page
/// does not have the engine re-run a step on it. The page still loaded
/// when this is called keeps being polled normally: nothing is skipped
/// until the reload actually starts. One-shot per mark; marking again
/// before the reload starts re-targets the same load.
pub fn mark_operator_reload(shared: &web::WebShared) {
    shared.operator_reload.store(shared.load_gen() + 1, Ordering::SeqCst);
}

/// Consume the operator-reload mark on `shared` if `load_gen` (the engine's
/// current page snapshot) is the marked load or a later one. Returns `true`
/// exactly once per mark, and `false` while the page is still the one that
/// was loaded when Reload was clicked.
pub fn take_operator_reload(shared: &web::WebShared, load_gen: u64) -> bool {
    let threshold = shared.operator_reload.load(Ordering::SeqCst);
    threshold != 0
        && load_gen >= threshold
        && shared.operator_reload.compare_exchange(threshold, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_enabled_requires_allow_and_downloadable_mime() {
        // allow_downloads false blocks everything, downloadable mime or not.
        let s =
            NavState { allow_downloads: false, current_mime: Some("application/pdf".into()), ..NavState::default() };
        assert!(!s.download_enabled(), "allow_downloads=false blocks a pdf");

        // allow_downloads true + downloadable mime → enabled.
        let s = NavState { allow_downloads: true, current_mime: Some("application/pdf".into()), ..NavState::default() };
        assert!(s.download_enabled(), "pdf with allow_downloads is enabled");

        // allow_downloads true + non-downloadable mime → disabled.
        let s = NavState { allow_downloads: true, current_mime: Some("text/plain".into()), ..NavState::default() };
        assert!(!s.download_enabled(), "text/plain stays disabled");

        // No response yet (current_mime None) stays disabled even with the
        // profile allowing downloads.
        let s = NavState { allow_downloads: true, ..NavState::default() };
        assert!(!s.download_enabled(), "no response yet means no download");
    }

    #[test]
    fn download_enabled_honours_attachment_disposition_for_html() {
        let s = NavState {
            allow_downloads: true,
            current_mime: Some("text/html; charset=utf-8".into()),
            content_disposition_attachment: true,
            ..NavState::default()
        };
        assert!(s.download_enabled(), "text/html + Content-Disposition: attachment is downloadable (spec §7.5)");
    }

    #[test]
    fn download_disabled_for_text_html_without_attachment() {
        let s = NavState {
            allow_downloads: true,
            current_mime: Some("text/html".into()),
            content_disposition_attachment: false,
            ..NavState::default()
        };
        assert!(!s.download_enabled(), "text/html without attachment stays non-downloadable (spec §7.5)");
    }

    #[test]
    fn download_enabled_for_attachment_without_content_type() {
        // A response with `Content-Disposition: attachment` and no
        // Content-Type is still a download (spec §7.3: mime OR attachment).
        let s = NavState { allow_downloads: true, content_disposition_attachment: true, ..NavState::default() };
        assert!(s.download_enabled(), "attachment with no mime is downloadable");
        // The profile and loading gates still apply.
        let s = NavState { allow_downloads: false, content_disposition_attachment: true, ..NavState::default() };
        assert!(!s.download_enabled(), "allow_downloads=false blocks an attachment");
        let s = NavState {
            allow_downloads: true,
            is_loading: true,
            content_disposition_attachment: true,
            ..NavState::default()
        };
        assert!(!s.download_enabled(), "loading blocks an attachment");
    }

    #[test]
    fn test_download_button_disabled_while_loading() {
        let s = NavState {
            is_loading: true,
            allow_downloads: true,
            current_mime: Some("application/pdf".into()),
            ..NavState::default()
        };
        assert!(!s.download_enabled());
    }

    #[test]
    fn image_svg_is_not_downloadable() {
        // SVG is scriptable; even though it matches image/* it is pinned
        // out of the downloadable set (spec §7.5).
        assert!(!is_downloadable_mime("image/svg+xml"));
        assert!(is_downloadable_mime("image/png"));
        assert!(is_downloadable_mime("image/jpeg"));
    }

    #[test]
    fn limiter_rejects_third_concurrent_download() {
        let l = Arc::new(DownloadLimiter::new());
        let s1 = l.try_acquire();
        let s2 = l.try_acquire();
        let s3 = l.try_acquire();
        assert!(s1.is_some(), "first slot acquires");
        assert!(s2.is_some(), "second slot acquires");
        assert!(s3.is_none(), "third slot is refused");
        assert_eq!(l.in_flight(), 2);
        drop(s1);
        assert_eq!(l.in_flight(), 1);
        // After one drops, the next acquire succeeds again.
        let s4 = l.try_acquire();
        assert!(s4.is_some(), "slot opens up after a drop");
    }

    #[test]
    fn limiter_cancels_download_past_2_gib() {
        let l = Arc::new(DownloadLimiter::new());
        let slot = l.try_acquire().expect("acquire");
        // One gibibyte at a time.
        let gib: u64 = 1 << 30;
        assert!(slot.record(gib).is_ok(), "1 GiB fits");
        assert!(slot.record(gib).is_ok(), "2 GiB fits (soft cap is at, not below)");
        assert_eq!(slot.bytes_recorded(), 2 * gib);
        assert_eq!(slot.record(1), Err(SizeExceeded), "one byte past 2 GiB cancels");
        // Subsequent record calls stay in the error state (do not
        // silently accept bytes after the cap trips).
        assert_eq!(slot.record(1), Err(SizeExceeded));
    }

    #[test]
    fn limiter_size_error_is_sticky_on_counter_overflow() {
        // A total that would overflow u64 saturates instead of wrapping, so
        // a small chunk after it can never read as back under the cap.
        let l = Arc::new(DownloadLimiter::new());
        let slot = l.try_acquire().expect("acquire");
        assert_eq!(slot.record(u64::MAX), Err(SizeExceeded));
        assert_eq!(slot.record(2), Err(SizeExceeded));
        assert_eq!(slot.record(1), Err(SizeExceeded), "no wrap back under the cap");
        assert_eq!(slot.bytes_recorded(), u64::MAX);
    }

    #[test]
    fn operator_reload_mark_lands_once_on_the_reloads_own_load() {
        let shared = web::WebShared::new("test", "https://test.example");
        let url = tauri::Url::parse("https://test.example/login").unwrap();
        shared.page_load(&url, false);
        shared.page_load(&url, true);
        let gen = shared.load_gen();
        // Unset: nothing to take.
        assert!(!take_operator_reload(&shared, gen));
        // Marked, but the page is still the one loaded at mark time.
        mark_operator_reload(&shared);
        assert!(!take_operator_reload(&shared, gen), "no skip before the reload starts");
        // The reload starts: a new generation takes the mark, once.
        shared.page_load(&url, false);
        assert!(take_operator_reload(&shared, shared.load_gen()), "first new load takes the mark");
        assert!(!take_operator_reload(&shared, shared.load_gen()), "the mark is consumed");
        // Stacked marks before the reload still land once.
        mark_operator_reload(&shared);
        mark_operator_reload(&shared);
        shared.page_load(&url, false);
        assert!(take_operator_reload(&shared, shared.load_gen()));
        assert!(!take_operator_reload(&shared, shared.load_gen()));
    }
}

/// Audit-line tests. They assert on the pure line builders, so there is no
/// `tauri::AppHandle` and no process-global `log` logger (which would
/// collide with the one `session/rdp.rs` installs in the same test binary).
#[cfg(test)]
mod audit {
    use super::*;

    fn is_reason_token(t: &str) -> bool {
        (1..=32).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }

    #[test]
    fn nav_audit_line_matches_connect_web_shape() {
        assert_eq!(
            nav_line("res-nav", "tok-nav", NavAction::Reload),
            "connect.web.nav: resource=res-nav token=tok-nav action=reload"
        );
        assert!(nav_line("r", "t", NavAction::Back).ends_with("action=back"));
        assert!(nav_line("r", "t", NavAction::Forward).ends_with("action=forward"));
    }

    #[test]
    fn download_ok_audit_omits_url_path_and_query() {
        // The builder has no URL parameter, so a URL cannot reach the line.
        // `https://x/path?q=1` is what the shim saw; only the basename,
        // mime, byte count and path kind are passed on.
        let line = download_line(
            "res-dl",
            "tok-dl",
            "report.pdf",
            "application/pdf; charset=binary",
            4096,
            DownloadPath::Webview,
        );
        assert_eq!(
            line,
            "connect.web.download: resource=res-dl token=tok-dl filename=\"report.pdf\" mime=application/pdf \
             bytes=4096 path=webview"
        );
        assert!(!line.contains("https://") && !line.contains("q=1") && !line.contains("/path"), "{line}");

        let refetch = download_line("r", "t", "a.bin", "application/octet-stream", 1, DownloadPath::Refetch);
        assert!(refetch.ends_with("path=refetch"));
    }

    #[test]
    fn download_ok_audit_neutralises_hostile_mime() {
        let line = download_line("r", "t", "a.bin", "x/y bytes=0\nconnect.web.nav: forged", 1, DownloadPath::Webview);
        assert!(line.contains("mime=invalid "), "{line}");
        assert!(!line.contains('\n'), "{line}");
    }

    #[test]
    fn download_ok_audit_quotes_filename_so_it_cannot_forge_fields() {
        let line = download_line("r", "t", "a mime=x bytes=0", "application/pdf", 7, DownloadPath::Webview);
        assert_eq!(
            line,
            "connect.web.download: resource=r token=t filename=\"a mime=x bytes=0\" mime=application/pdf bytes=7 \
             path=webview"
        );
        // An embedded quote is escaped, so it cannot close the field early.
        let quoted = download_line("r", "t", "a\" mime=x", "application/pdf", 7, DownloadPath::Webview);
        assert!(quoted.contains("filename=\"a\\\" mime=x\" mime=application/pdf"), "{quoted}");
    }

    #[test]
    fn download_ok_audit_drops_control_characters_from_filename() {
        // The builder does not trust the caller to have sanitised the name.
        let line =
            download_line("r", "t", "a\nconnect.web.nav: forged\r\tb.pdf", "application/pdf", 1, DownloadPath::Webview);
        assert!(!line.chars().any(|c| c.is_control()), "{line:?}");
        assert!(line.contains("filename=\"aconnect.web.nav: forgedb.pdf\""), "{line}");
    }

    #[test]
    fn download_refused_audit_names_reason() {
        assert_eq!(
            refused_line("res-ref", "tok-ref", reason::OUTSIDE_ALLOWLIST),
            "connect.web.download_refused: resource=res-ref token=tok-ref reason=outside_allowlist"
        );
    }

    #[test]
    fn refusal_reason_maps_next_path_errors_without_io_text() {
        assert_eq!(refusal_reason(&NextPathError::Exhausted(CollisionExhausted)), "collision_exhausted");
        assert_eq!(refusal_reason(&NextPathError::InvalidName), "invalid_filename");
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "/Users/op/Downloads/secret.pdf");
        let token = refusal_reason(&NextPathError::Io(io));
        assert_eq!(token, "save_io_error");
        assert!(!token.contains("Users"));
    }

    #[test]
    fn every_reason_constant_is_a_valid_token() {
        let all = [
            reason::OUTSIDE_ALLOWLIST,
            reason::DOWNLOADS_DISABLED,
            reason::SIZE_EXCEEDED,
            reason::TOO_MANY_DOWNLOADS,
            reason::COLLISION_EXHAUSTED,
            reason::SAVE_IO_ERROR,
            reason::INVALID_FILENAME,
        ];
        for r in all {
            assert!(is_reason_token(r), "{r}");
        }
        assert_eq!(reason::DOWNLOADS_DISABLED, "downloads_disabled");
        assert_eq!(reason::SIZE_EXCEEDED, "size_exceeded");
        assert_eq!(reason::TOO_MANY_DOWNLOADS, "too_many_downloads");
    }
}
