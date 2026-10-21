//! The UI-free half of the macOS shim: layout arithmetic, the main-frame
//! response tracker, the download policy and response checks, file naming,
//! the download job (placeholder plus private staging file) and the
//! per-download state machine.
//!
//! Nothing here touches AppKit or WebKit, so all of it is unit-tested. The
//! FFI half (`super`) only reads facts out of Objective-C objects, hands them
//! to these functions and applies what they decide.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use tauri::Url;

use crate::session::web::{download_decision, DownloadDecision, OriginSet};
use crate::session::web_nav_bar::{
    is_downloadable_mime, next_free_path, reason, refusal_reason, sanitize_filename, DownloadSlot, NavAction, NavState,
    BAR_HEIGHT, DOWNLOAD_SOFT_CAP_BYTES,
};

// ── Layout ─────────────────────────────────────────────────────────

/// Width of one bar button (spec §7.1: four buttons, 44 × 36 each).
pub(crate) const BUTTON_WIDTH: f64 = 44.0;

/// A rectangle in a view's own coordinate space, in points.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Frame {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// A finite, non-negative length; anything else reads as 0.
fn length(v: f64) -> f64 {
    if v.is_finite() {
        v.max(0.0)
    } else {
        0.0
    }
}

/// Split `container` (the bounds of the webview's superview) into the
/// webview's frame and the bar's: the bar takes the bottom `BAR_HEIGHT`
/// (all of the container when it is shorter), the webview everything above
/// it, so no page content sits under the bar (spec §7.1, A5). AppKit's
/// default coordinates put y = 0 at the bottom edge; a flipped container
/// puts it at the top. Returns `(webview, bar)`.
pub(crate) fn split_frames(container: Frame, flipped: bool) -> (Frame, Frame) {
    let x = if container.x.is_finite() { container.x } else { 0.0 };
    let y = if container.y.is_finite() { container.y } else { 0.0 };
    let width = length(container.width);
    let height = length(container.height);
    let bar_height = BAR_HEIGHT.min(height);
    let web_height = height - bar_height;
    if flipped {
        (Frame { x, y, width, height: web_height }, Frame { x, y: y + web_height, width, height: bar_height })
    } else {
        (Frame { x, y: y + bar_height, width, height: web_height }, Frame { x, y, width, height: bar_height })
    }
}

/// Whether the bar's flexible autoresizing margin is its top edge in the
/// container's coordinates (`ViewMaxYMargin`), which keeps it pinned to the
/// bottom as the window resizes. A flipped container measures y downwards,
/// so there it is `ViewMinYMargin`.
pub(crate) fn bar_flexible_margin_is_max_y(flipped: bool) -> bool {
    !flipped
}

/// The frame of button `index` (0 = back … 3 = download) inside the bar.
pub(crate) fn button_frame(index: usize) -> Frame {
    Frame { x: index as f64 * BUTTON_WIDTH, y: 0.0, width: BUTTON_WIDTH, height: BAR_HEIGHT }
}

/// `(SF Symbol, fallback title, label)` of a button. The fallback title is
/// used where SF Symbols are unavailable (macOS 10.15); the label is the
/// tooltip and the accessibility description.
pub(crate) fn button_face(action: NavAction) -> (&'static str, &'static str, &'static str) {
    match action {
        NavAction::Back => ("chevron.left", "\u{2039}", "Back"),
        NavAction::Forward => ("chevron.right", "\u{203a}", "Forward"),
        NavAction::Reload => ("arrow.clockwise", "\u{21bb}", "Reload"),
        NavAction::Download => ("square.and.arrow.down", "\u{2193}", "Download"),
    }
}

// ── OS capabilities ────────────────────────────────────────────────

/// How the download button fetches the shown document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadRoute {
    /// `WKWebView.startDownload(using:)` (macOS 11.3+): the webview's own
    /// network session, cookies, proxy and quarantine handling.
    WebKit,
    /// `URLSession` with a copy of the webview's cookies (macOS 10.15–11.2).
    Refetch,
}

/// The route for macOS `major.minor` (from `NSProcessInfo`). A binary in
/// SDK-compatibility mode sees Big Sur and later as 10.16 and takes the
/// refetch route, which works there too.
pub(crate) fn download_route(major: isize, minor: isize) -> DownloadRoute {
    if (major, minor) >= (11, 3) {
        DownloadRoute::WebKit
    } else {
        DownloadRoute::Refetch
    }
}

/// `+[NSImage imageWithSystemSymbolName:accessibilityDescription:]` is
/// macOS 11+.
pub(crate) fn has_sf_symbols(major: isize) -> bool {
    major >= 11
}

// ── Destination ────────────────────────────────────────────────────

/// The operator's Downloads folder: `dirs::download_dir()`, else
/// `$HOME/Downloads` (spec §7.6). `None` when neither is known; the
/// download is then refused rather than written somewhere else.
pub(crate) fn downloads_dir(platform: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    platform.or_else(|| home.map(|h| h.join("Downloads")))
}

// ── Main-frame response tracking ───────────────────────────────────

/// Main-frame responses remembered for back / forward restores, which show
/// a page again without a new response.
pub(crate) const RESPONSES_KEPT: usize = 32;

/// What the bar keeps about a displayed main-frame response: its URL (to
/// match it to the shown document) and the two headers the download
/// button's state depends on. Nothing else, and never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MainFrameResponse {
    pub url: Url,
    pub mime: Option<String>,
    pub attachment: bool,
}

/// The displayed main-frame responses, most recent first.
#[derive(Debug, Default)]
pub(crate) struct ResponseTracker {
    seen: VecDeque<MainFrameResponse>,
}

impl ResponseTracker {
    /// A main-frame response the webview is about to display.
    pub fn record(&mut self, response: MainFrameResponse) {
        self.seen.retain(|r| !same_document(&r.url, &response.url));
        self.seen.push_front(response);
        self.seen.truncate(RESPONSES_KEPT);
    }

    /// The response of the document the webview shows, if one was seen.
    pub fn for_document(&self, shown: Option<&Url>) -> Option<&MainFrameResponse> {
        let shown = shown?;
        self.seen.iter().find(|r| same_document(&r.url, shown))
    }
}

/// Two URLs name the same document when they differ at most in the
/// fragment (a response URL never carries one, the shown URL may).
pub(crate) fn same_document(a: &Url, b: &Url) -> bool {
    let (mut a, mut b) = (a.clone(), b.clone());
    a.set_fragment(None);
    b.set_fragment(None);
    a == b
}

/// Whether a `Content-Disposition` value has the `attachment` type.
pub(crate) fn is_attachment(content_disposition: &str) -> bool {
    content_disposition.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("attachment")
}

/// The bar's state from what the webview reports.
pub(crate) fn nav_state(
    can_go_back: bool,
    can_go_forward: bool,
    is_loading: bool,
    response: Option<&MainFrameResponse>,
    allow_downloads: bool,
) -> NavState {
    NavState {
        can_go_back,
        can_go_forward,
        is_loading,
        current_mime: response.and_then(|r| r.mime.clone()),
        content_disposition_attachment: response.is_some_and(|r| r.attachment),
        allow_downloads,
    }
}

// ── Policy ─────────────────────────────────────────────────────────

/// The download policy for `url`: exactly `web::download_decision` — the
/// decision `RemotePolicy::on_download` applies to the webview's own
/// downloads (spec A6) — and, on top of it, http(s) only, since nothing else
/// can be fetched again. `Err` is the audit reason.
pub(crate) fn url_policy(allow_downloads: bool, origins: &OriginSet, url: &Url) -> Result<(), &'static str> {
    match download_decision(allow_downloads, origins, url) {
        DownloadDecision::Deny { reason: "disabled", .. } => Err(reason::DOWNLOADS_DISABLED),
        DownloadDecision::Deny { .. } => Err(reason::OUTSIDE_ALLOWLIST),
        DownloadDecision::Allow if matches!(url.scheme(), "http" | "https") => Ok(()),
        // `about:blank` / an in-set `blob:` URL: allowed to load, but there
        // is nothing a request could fetch again.
        DownloadDecision::Allow => Err(reason::UNAVAILABLE),
    }
}

/// What a download response reported, read out of `NSURLResponse`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ResponseFacts {
    /// The response URL, after redirects.
    pub url: Option<Url>,
    /// HTTP status; `None` for a non-HTTP response.
    pub status: Option<i64>,
    pub mime: Option<String>,
    pub content_disposition: Option<String>,
    /// `expectedContentLength`, when the server announced one.
    pub expected_length: Option<u64>,
    /// The webview's / Foundation's suggested name (it already applies
    /// `Content-Disposition` and the URL).
    pub suggested_filename: Option<String>,
}

/// Whether the response to a re-request is the document the bar offered to
/// save: its (final) URL passes [`url_policy`], the status is 2xx, it is in
/// the downloadable set or an attachment, and it does not announce more
/// than the soft cap.
pub(crate) fn check_response(
    facts: &ResponseFacts,
    allow_downloads: bool,
    origins: &OriginSet,
) -> Result<(), &'static str> {
    let url = facts.url.as_ref().ok_or(reason::UNAVAILABLE)?;
    url_policy(allow_downloads, origins, url)?;
    if !facts.status.is_some_and(|s| (200..300).contains(&s)) {
        return Err(reason::UNAVAILABLE);
    }
    let attachment = facts.content_disposition.as_deref().is_some_and(is_attachment);
    if !attachment && !facts.mime.as_deref().is_some_and(is_downloadable_mime) {
        return Err(reason::UNAVAILABLE);
    }
    if facts.expected_length.is_some_and(|n| n > DOWNLOAD_SOFT_CAP_BYTES) {
        return Err(reason::SIZE_EXCEEDED);
    }
    Ok(())
}

// ── Naming ─────────────────────────────────────────────────────────

/// The file name, sanitised (spec §7.6): the webview's suggestion, else the
/// last URL path segment (percent-decoded), else
/// `download-YYYYMMDD-HHMMSS.bin`.
pub(crate) fn choose_filename(suggested: Option<&str>, url: Option<&Url>, now: chrono::NaiveDateTime) -> String {
    let usable = |raw: &str| Some(sanitize_filename(raw)).filter(|n| !n.is_empty());
    let from_url = || {
        let segment = url?.path_segments()?.rfind(|s| !s.is_empty())?;
        let decoded = urlencoding::decode(segment).map(|d| d.into_owned()).unwrap_or_else(|_| segment.to_string());
        usable(&decoded)
    };
    suggested.and_then(usable).or_else(from_url).unwrap_or_else(|| now.format("download-%Y%m%d-%H%M%S.bin").to_string())
}

// ── Operator-facing text ───────────────────────────────────────────

/// Tooltip of a disabled download button on a profile without downloads
/// (spec §7.4, verbatim).
pub(crate) const DOWNLOADS_DISABLED_TOOLTIP: &str = "Downloads disabled for this profile.";

/// The download button's tooltip for `state`.
pub(crate) fn download_tooltip(state: &NavState) -> &'static str {
    if !state.allow_downloads {
        DOWNLOADS_DISABLED_TOOLTIP
    } else if state.is_loading {
        "Download (available once the page has loaded)"
    } else if state.download_enabled() {
        "Download this file to the Downloads folder"
    } else {
        "This page is not a downloadable file"
    }
}

/// The short-lived message shown for a refused download.
pub(crate) fn refusal_message(refusal: &str) -> &'static str {
    match refusal {
        reason::TOO_MANY_DOWNLOADS => "Two downloads are already in progress in this window.",
        reason::SIZE_EXCEEDED => "Download cancelled: the file is larger than 2 GiB.",
        reason::COLLISION_EXHAUSTED => "Could not save: the Downloads folder is full of files with this name.",
        reason::SAVE_IO_ERROR | reason::INVALID_FILENAME => "Could not save the file to the Downloads folder.",
        reason::OUTSIDE_ALLOWLIST => "Download refused: the file is outside this session's allowed origins.",
        reason::DOWNLOADS_DISABLED => DOWNLOADS_DISABLED_TOOLTIP,
        reason::UNAVAILABLE => {
            "This file cannot be fetched again from here (it may need a form submission or a one-time link)."
        }
        _ => "The download failed.",
    }
}

// ── Download job ───────────────────────────────────────────────────

/// Where a download lands, and where it is written until it is complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Destination {
    /// The operator's Downloads folder.
    pub downloads_dir: PathBuf,
    /// A private directory per download is created here (the user's temp
    /// directory).
    pub staging_root: PathBuf,
}

/// A download saved under its reserved name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Saved {
    /// The reserved basename (with any ` (n)` suffix). Never a path.
    pub filename: String,
    pub mime: String,
    pub bytes: u64,
}

/// One download between "the response passed" and "the file is in place".
///
/// The final name is reserved in the Downloads folder with
/// [`next_free_path`]'s zero-byte placeholder, while the bytes go to a file
/// in a private (0700) staging directory: WebKit refuses to write over an
/// existing file, and a half-written file never appears under the final
/// name. [`Self::finish`] moves the staging file over the placeholder.
/// Dropping an unfinished job removes the staging directory and the
/// placeholder — every abort path cleans up — but never a placeholder that
/// something else has since filled.
pub(crate) struct DownloadJob {
    slot: DownloadSlot,
    placeholder: PathBuf,
    staging_dir: PathBuf,
    staging_file: PathBuf,
    writer: Option<File>,
    filename: String,
    mime: String,
    /// Bytes counted against the slot so far.
    counted: u64,
    /// The placeholder now holds our bytes (a cross-volume copy started).
    placeholder_ours: bool,
    finished: bool,
}

/// A zero-byte regular file, i.e. still the placeholder `next_free_path`
/// created (a symlink is not followed).
fn is_untouched_placeholder(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() == 0)
}

impl DownloadJob {
    pub fn reserve(slot: DownloadSlot, dest: &Destination, filename: &str, mime: &str) -> Result<Self, &'static str> {
        let placeholder = next_free_path(&dest.downloads_dir, filename).map_err(|e| refusal_reason(&e))?;
        // `next_free_path` joined a `&str` name, so the reserved name is UTF-8.
        let Some(reserved) = placeholder.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            let _ = fs::remove_file(&placeholder);
            return Err(reason::SAVE_IO_ERROR);
        };
        let staging_dir = dest.staging_root.join(format!("bv-nav-download-{}", uuid::Uuid::new_v4().simple()));
        // `create`, not `create_all`: the directory is new and ours alone.
        if let Err(e) = fs::DirBuilder::new().mode(0o700).create(&staging_dir) {
            log::warn!("connect.web.nav_bar: could not create a download staging directory ({:?})", e.kind());
            if is_untouched_placeholder(&placeholder) {
                let _ = fs::remove_file(&placeholder);
            }
            return Err(reason::SAVE_IO_ERROR);
        }
        let staging_file = staging_dir.join(&reserved);
        Ok(Self {
            slot,
            placeholder,
            staging_dir,
            staging_file,
            writer: None,
            filename: reserved,
            mime: mime.to_string(),
            counted: 0,
            placeholder_ours: false,
            finished: false,
        })
    }

    /// The reserved file in the Downloads folder.
    pub fn placeholder(&self) -> &Path {
        &self.placeholder
    }

    /// Where the bytes are written until [`Self::finish`].
    pub fn staging_file(&self) -> &Path {
        &self.staging_file
    }

    /// Create the staging file for [`Self::write_chunk`] (the refetch
    /// route; WebKit creates its own).
    pub fn open_writer(&mut self) -> Result<(), &'static str> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.staging_file)
            .map_err(|_| reason::SAVE_IO_ERROR)?;
        self.writer = Some(file);
        Ok(())
    }

    /// Count `bytes` against the soft cap, then append them.
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        let n = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.counted = self.counted.saturating_add(n);
        self.slot.record(n).map_err(|_| reason::SIZE_EXCEEDED)?;
        let writer = self.writer.as_mut().ok_or(reason::SAVE_IO_ERROR)?;
        writer.write_all(bytes).map_err(|_| reason::SAVE_IO_ERROR)
    }

    /// Count a running byte total (WebKit reports totals, not chunks).
    pub fn record_total(&mut self, total: u64) -> Result<(), &'static str> {
        let delta = total.saturating_sub(self.counted);
        self.counted = self.counted.max(total);
        self.slot.record(delta).map_err(|_| reason::SIZE_EXCEEDED)
    }

    /// Move the complete staging file into the reserved name.
    pub fn finish(mut self) -> Result<Saved, &'static str> {
        drop(self.writer.take());
        let meta = fs::symlink_metadata(&self.staging_file).map_err(|_| reason::TRANSFER_FAILED)?;
        if !meta.is_file() {
            return Err(reason::TRANSFER_FAILED);
        }
        self.record_total(meta.len())?;
        if !is_untouched_placeholder(&self.placeholder) {
            // Something replaced or filled the reserved name meanwhile: it is
            // not ours to overwrite.
            return Err(reason::SAVE_IO_ERROR);
        }
        if fs::rename(&self.staging_file, &self.placeholder).is_err() {
            // Downloads on another volume than the temp directory (EXDEV):
            // copy into the reserved name instead.
            self.placeholder_ours = true;
            if let Err(e) = fs::copy(&self.staging_file, &self.placeholder) {
                log::warn!("connect.web.nav_bar: could not move a finished download into place ({:?})", e.kind());
                return Err(reason::SAVE_IO_ERROR);
            }
        }
        self.finished = true;
        Ok(Saved {
            filename: std::mem::take(&mut self.filename),
            mime: std::mem::take(&mut self.mime),
            bytes: meta.len(),
        })
    }
}

impl Drop for DownloadJob {
    fn drop(&mut self) {
        drop(self.writer.take());
        if let Err(e) = fs::remove_dir_all(&self.staging_dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("connect.web.nav_bar: could not remove a download staging directory ({:?})", e.kind());
            }
        }
        if !self.finished && (self.placeholder_ours || is_untouched_placeholder(&self.placeholder)) {
            if let Err(e) = fs::remove_file(&self.placeholder) {
                log::warn!(
                    "connect.web.nav_bar: could not remove an unfinished download's placeholder ({:?})",
                    e.kind()
                );
            }
        }
        // `slot` drops after this, releasing the concurrency count.
    }
}

// ── Per-download state machine ─────────────────────────────────────

/// How a download ended. Each download settles exactly once; the FFI half
/// turns it into one audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Settled {
    Saved(Saved),
    Refused(&'static str),
}

enum TransferState {
    /// Clicked: holds a concurrency slot, no response yet.
    Requested(DownloadSlot),
    /// The response passed; bytes are arriving.
    Active(DownloadJob),
    /// Settled (or never started); every later event is ignored.
    Closed,
}

/// One download from the click to its single [`Settled`] outcome. Every
/// method returns `Some` only on the event that settles it; afterwards the
/// transfer is closed and the FFI half cancels the native transfer.
pub(crate) struct Transfer {
    state: TransferState,
    dest: Destination,
}

impl Transfer {
    pub fn new(slot: DownloadSlot, dest: Destination) -> Self {
        Self { state: TransferState::Requested(slot), dest }
    }

    pub fn is_open(&self) -> bool {
        !matches!(self.state, TransferState::Closed)
    }

    /// The staging file while the transfer is active.
    pub fn staging_file(&self) -> Option<&Path> {
        match &self.state {
            TransferState::Active(job) => Some(job.staging_file()),
            _ => None,
        }
    }

    /// Close the transfer with `reason`, dropping (and so cleaning up) what
    /// it held. `None` when it was already closed.
    fn refuse(&mut self, refusal: &'static str) -> Option<Settled> {
        match std::mem::replace(&mut self.state, TransferState::Closed) {
            TransferState::Closed => None,
            _ => Some(Settled::Refused(refusal)),
        }
    }

    /// The response arrived: check it ([`check_response`]), name the file
    /// and reserve it.
    pub fn begin(
        &mut self,
        facts: &ResponseFacts,
        allow_downloads: bool,
        origins: &OriginSet,
        now: chrono::NaiveDateTime,
    ) -> Option<Settled> {
        if !matches!(self.state, TransferState::Requested(_)) {
            return None;
        }
        if let Err(r) = check_response(facts, allow_downloads, origins) {
            return self.refuse(r);
        }
        let TransferState::Requested(slot) = std::mem::replace(&mut self.state, TransferState::Closed) else {
            return None;
        };
        let name = choose_filename(facts.suggested_filename.as_deref(), facts.url.as_ref(), now);
        // RFC 9110 §8.3: a recipient may treat a response without a type as
        // `application/octet-stream`.
        let mime = facts.mime.as_deref().unwrap_or("application/octet-stream");
        match DownloadJob::reserve(slot, &self.dest, &name, mime) {
            Ok(job) => {
                self.state = TransferState::Active(job);
                None
            }
            Err(r) => Some(Settled::Refused(r)),
        }
    }

    /// A redirect to `to` (refused unless it passes [`url_policy`]).
    pub fn redirect(&mut self, to: Option<&Url>, allow_downloads: bool, origins: &OriginSet) -> Option<Settled> {
        if !self.is_open() {
            return None;
        }
        match to.map(|u| url_policy(allow_downloads, origins, u)) {
            Some(Ok(())) => None,
            Some(Err(r)) => self.refuse(r),
            None => self.refuse(reason::UNAVAILABLE),
        }
    }

    /// Run `step` on the active job; an error settles the transfer.
    fn on_job(&mut self, step: impl FnOnce(&mut DownloadJob) -> Result<(), &'static str>) -> Option<Settled> {
        let TransferState::Active(job) = &mut self.state else { return None };
        match step(job) {
            Ok(()) => None,
            Err(r) => self.refuse(r),
        }
    }

    pub fn open_writer(&mut self) -> Option<Settled> {
        self.on_job(DownloadJob::open_writer)
    }

    pub fn write_chunk(&mut self, bytes: &[u8]) -> Option<Settled> {
        self.on_job(|job| job.write_chunk(bytes))
    }

    pub fn record_total(&mut self, total: u64) -> Option<Settled> {
        self.on_job(|job| job.record_total(total))
    }

    /// The native transfer completed.
    pub fn finish(&mut self) -> Option<Settled> {
        match std::mem::replace(&mut self.state, TransferState::Closed) {
            TransferState::Closed => None,
            // Completed without ever passing the response check.
            TransferState::Requested(_) => Some(Settled::Refused(reason::TRANSFER_FAILED)),
            TransferState::Active(job) => Some(match job.finish() {
                Ok(saved) => Settled::Saved(saved),
                Err(r) => Settled::Refused(r),
            }),
        }
    }

    /// The native transfer failed, was refused or is being torn down.
    pub fn fail(&mut self, refusal: &'static str) -> Option<Settled> {
        self.refuse(refusal)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::session::web::WebOrigin;
    use crate::session::web_nav_bar::{reason, DownloadLimiter, DOWNLOAD_SOFT_CAP_BYTES};

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn origins() -> OriginSet {
        let o = WebOrigin::of_url(&url("https://fw.example.com/")).unwrap();
        OriginSet::new(vec![o])
    }

    fn noon() -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 21).unwrap().and_hms_opt(9, 30, 5).unwrap()
    }

    fn slot(limiter: &Arc<DownloadLimiter>) -> DownloadSlot {
        limiter.try_acquire().expect("slot")
    }

    fn tempdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "bv-nav-macos-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn dest(tag: &str) -> Destination {
        let root = tempdir(tag);
        let downloads_dir = root.join("Downloads");
        let staging_root = root.join("tmp");
        std::fs::create_dir_all(&downloads_dir).unwrap();
        std::fs::create_dir_all(&staging_root).unwrap();
        Destination { downloads_dir, staging_root }
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn pdf_facts() -> ResponseFacts {
        ResponseFacts {
            url: Some(url("https://fw.example.com/reports/q3.pdf?token=secret")),
            status: Some(200),
            mime: Some("application/pdf".into()),
            content_disposition: None,
            expected_length: Some(4),
            suggested_filename: Some("q3.pdf".into()),
        }
    }

    // ── layout ──

    #[test]
    fn the_bar_takes_the_bottom_strip_and_the_webview_the_rest() {
        let c = Frame { x: 0.0, y: 0.0, width: 800.0, height: 600.0 };
        let (web, bar) = split_frames(c, false);
        assert_eq!(bar, Frame { x: 0.0, y: 0.0, width: 800.0, height: 36.0 });
        assert_eq!(web, Frame { x: 0.0, y: 36.0, width: 800.0, height: 564.0 });
        assert!(bar_flexible_margin_is_max_y(false));

        // Flipped: y grows downwards, so the bottom strip starts at h - 36.
        let (web, bar) = split_frames(c, true);
        assert_eq!(bar, Frame { x: 0.0, y: 564.0, width: 800.0, height: 36.0 });
        assert_eq!(web, Frame { x: 0.0, y: 0.0, width: 800.0, height: 564.0 });
        assert!(!bar_flexible_margin_is_max_y(true));
    }

    #[test]
    fn a_container_shorter_than_the_bar_never_yields_a_negative_frame() {
        let (web, bar) = split_frames(Frame { x: 0.0, y: 0.0, width: 300.0, height: 20.0 }, false);
        assert_eq!(bar.height, 20.0);
        assert_eq!(web.height, 0.0);
        let (web, bar) = split_frames(Frame { x: 0.0, y: 0.0, width: f64::NAN, height: -5.0 }, false);
        assert_eq!((web.width, web.height, bar.width, bar.height), (0.0, 0.0, 0.0, 0.0));
    }

    #[test]
    fn buttons_are_44_by_36_left_aligned() {
        assert_eq!(button_frame(0), Frame { x: 0.0, y: 0.0, width: 44.0, height: 36.0 });
        assert_eq!(button_frame(3), Frame { x: 132.0, y: 0.0, width: 44.0, height: 36.0 });
        assert_eq!(button_face(NavAction::Back).0, "chevron.left");
        assert_eq!(button_face(NavAction::Download).2, "Download");
    }

    // ── OS capabilities, destination ──

    #[test]
    fn webkit_downloads_from_11_3_refetch_before() {
        for (major, minor) in [(10, 15), (10, 16), (11, 0), (11, 2)] {
            assert_eq!(download_route(major, minor), DownloadRoute::Refetch, "{major}.{minor}");
        }
        for (major, minor) in [(11, 3), (11, 7), (12, 0), (26, 0)] {
            assert_eq!(download_route(major, minor), DownloadRoute::WebKit, "{major}.{minor}");
        }
        assert!(!has_sf_symbols(10));
        assert!(has_sf_symbols(11));
    }

    #[test]
    fn destination_is_the_downloads_dir_then_home_downloads() {
        let platform = PathBuf::from("/Users/op/Downloads");
        assert_eq!(downloads_dir(Some(platform.clone()), Some("/home/x".into())), Some(platform));
        assert_eq!(downloads_dir(None, Some("/Users/op".into())), Some(PathBuf::from("/Users/op/Downloads")));
        assert_eq!(downloads_dir(None, None), None);
    }

    // ── response tracking and state ──

    #[test]
    fn the_shown_documents_response_decides_the_state_fragment_ignored() {
        let mut t = ResponseTracker::default();
        t.record(MainFrameResponse {
            url: url("https://fw.example.com/a.pdf"),
            mime: Some("application/pdf".into()),
            attachment: false,
        });
        let shown = url("https://fw.example.com/a.pdf#page=2");
        assert_eq!(t.for_document(Some(&shown)).unwrap().mime.as_deref(), Some("application/pdf"));
        assert!(t.for_document(Some(&url("https://fw.example.com/b"))).is_none());
        assert!(t.for_document(None).is_none());
        assert!(same_document(&url("https://x.test/p?q=1#a"), &url("https://x.test/p?q=1")));
        assert!(!same_document(&url("https://x.test/p?q=1"), &url("https://x.test/p?q=2")));
    }

    #[test]
    fn a_back_navigation_finds_the_earlier_response_and_the_latest_wins() {
        let mut t = ResponseTracker::default();
        let a = url("https://fw.example.com/a.pdf");
        t.record(MainFrameResponse { url: a.clone(), mime: Some("application/pdf".into()), attachment: false });
        t.record(MainFrameResponse {
            url: url("https://fw.example.com/b"),
            mime: Some("text/html".into()),
            attachment: false,
        });
        // Back to `a` from the page cache: no new response, the old one is used.
        assert_eq!(t.for_document(Some(&a)).unwrap().mime.as_deref(), Some("application/pdf"));
        // A reload of `a` answered differently replaces it.
        t.record(MainFrameResponse { url: a.clone(), mime: Some("text/html".into()), attachment: false });
        assert_eq!(t.for_document(Some(&a)).unwrap().mime.as_deref(), Some("text/html"));
    }

    #[test]
    fn the_tracker_is_bounded() {
        let mut t = ResponseTracker::default();
        for i in 0..(RESPONSES_KEPT + 10) {
            t.record(MainFrameResponse {
                url: url(&format!("https://fw.example.com/{i}")),
                mime: None,
                attachment: false,
            });
        }
        assert!(t.for_document(Some(&url("https://fw.example.com/0"))).is_none(), "oldest dropped");
        assert!(t.for_document(Some(&url(&format!("https://fw.example.com/{}", RESPONSES_KEPT + 9)))).is_some());
    }

    #[test]
    fn attachment_is_the_disposition_type_only() {
        assert!(is_attachment("attachment"));
        assert!(is_attachment("Attachment; filename=\"a.pdf\""));
        assert!(is_attachment("  attachment ;filename*=UTF-8''a.pdf"));
        assert!(!is_attachment("inline; filename=attachment.pdf"));
        assert!(!is_attachment("attachments"));
        assert!(!is_attachment(""));
    }

    #[test]
    fn state_maps_the_webview_flags_and_the_response() {
        let pdf = MainFrameResponse {
            url: url("https://fw.example.com/a.pdf"),
            mime: Some("application/pdf".into()),
            attachment: false,
        };
        let s = nav_state(true, false, false, Some(&pdf), true);
        assert!(s.can_go_back && !s.can_go_forward && !s.is_loading);
        assert!(s.download_enabled());
        assert!(!nav_state(true, false, false, Some(&pdf), false).download_enabled(), "profile forbids");
        assert!(!nav_state(true, false, true, Some(&pdf), true).download_enabled(), "loading");
        assert!(!nav_state(false, false, false, None, true).download_enabled(), "no response seen");
    }

    #[test]
    fn mime_pdf_is_downloadable() {
        let pdf = MainFrameResponse {
            url: url("https://fw.example.com/a.pdf"),
            mime: Some("application/pdf".into()),
            attachment: false,
        };
        assert!(nav_state(false, false, false, Some(&pdf), true).download_enabled());
        assert_eq!(check_response(&pdf_facts(), true, &origins()), Ok(()));
    }

    #[test]
    fn mime_text_html_is_not_downloadable_without_attachment() {
        let html = MainFrameResponse {
            url: url("https://fw.example.com/"),
            mime: Some("text/html".into()),
            attachment: false,
        };
        assert!(!nav_state(false, false, false, Some(&html), true).download_enabled());
        let facts = ResponseFacts { mime: Some("text/html".into()), ..pdf_facts() };
        assert_eq!(check_response(&facts, true, &origins()), Err(reason::UNAVAILABLE));
        // The server's attachment disposition makes it a download.
        let html = MainFrameResponse { attachment: true, ..html };
        assert!(nav_state(false, false, false, Some(&html), true).download_enabled());
        let facts = ResponseFacts { content_disposition: Some("attachment; filename=r.html".into()), ..facts };
        assert_eq!(check_response(&facts, true, &origins()), Ok(()));
    }

    #[test]
    fn mime_image_svg_xml_is_not_downloadable() {
        let svg = MainFrameResponse {
            url: url("https://fw.example.com/i.svg"),
            mime: Some("image/svg+xml".into()),
            attachment: false,
        };
        assert!(!nav_state(false, false, false, Some(&svg), true).download_enabled());
        let facts = ResponseFacts { mime: Some("image/svg+xml".into()), ..pdf_facts() };
        assert_eq!(check_response(&facts, true, &origins()), Err(reason::UNAVAILABLE));
    }

    // ── policy ──

    #[test]
    fn url_policy_is_the_webviews_download_decision_plus_http_only() {
        let o = origins();
        assert_eq!(url_policy(true, &o, &url("https://fw.example.com/a.pdf")), Ok(()));
        assert_eq!(url_policy(false, &o, &url("https://fw.example.com/a.pdf")), Err(reason::DOWNLOADS_DISABLED));
        assert_eq!(url_policy(true, &o, &url("https://evil.example.net/a.pdf")), Err(reason::OUTSIDE_ALLOWLIST));
        assert_eq!(
            url_policy(true, &o, &url("http://fw.example.com/a.pdf")),
            Err(reason::OUTSIDE_ALLOWLIST),
            "scheme is part of the origin"
        );
        assert_eq!(url_policy(true, &o, &url("data:application/pdf,x")), Err(reason::OUTSIDE_ALLOWLIST));
        // `download_decision` allows these (no network fetch); nothing to re-fetch.
        assert_eq!(url_policy(true, &o, &url("about:blank")), Err(reason::UNAVAILABLE));
        assert_eq!(url_policy(true, &o, &url("blob:https://fw.example.com/1b2c")), Err(reason::UNAVAILABLE));
    }

    #[test]
    fn a_re_request_that_does_not_return_the_document_is_unavailable() {
        let o = origins();
        for status in [None, Some(302), Some(401), Some(404), Some(405), Some(500)] {
            let facts = ResponseFacts { status, ..pdf_facts() };
            assert_eq!(check_response(&facts, true, &o), Err(reason::UNAVAILABLE), "{status:?}");
        }
        let facts = ResponseFacts { url: None, ..pdf_facts() };
        assert_eq!(check_response(&facts, true, &o), Err(reason::UNAVAILABLE));
        // Redirected off the allow-list: refused as such.
        let facts = ResponseFacts { url: Some(url("https://cdn.example.net/q3.pdf")), ..pdf_facts() };
        assert_eq!(check_response(&facts, true, &o), Err(reason::OUTSIDE_ALLOWLIST));
        let facts = ResponseFacts { expected_length: Some(DOWNLOAD_SOFT_CAP_BYTES + 1), ..pdf_facts() };
        assert_eq!(check_response(&facts, true, &o), Err(reason::SIZE_EXCEEDED));
        let facts = ResponseFacts { expected_length: Some(DOWNLOAD_SOFT_CAP_BYTES), ..pdf_facts() };
        assert_eq!(check_response(&facts, true, &o), Ok(()));
        assert_eq!(check_response(&pdf_facts(), false, &o), Err(reason::DOWNLOADS_DISABLED));
    }

    // ── naming, text ──

    #[test]
    fn the_file_name_is_the_suggestion_then_the_url_then_a_timestamp() {
        let u = url("https://fw.example.com/exports/Q3%20report.pdf?sig=abc");
        assert_eq!(choose_filename(Some("report.pdf"), Some(&u), noon()), "report.pdf");
        assert_eq!(choose_filename(Some("../../etc/passwd"), Some(&u), noon()), "etcpasswd");
        assert_eq!(choose_filename(Some("..."), Some(&u), noon()), "Q3 report.pdf");
        assert_eq!(choose_filename(None, Some(&u), noon()), "Q3 report.pdf");
        assert_eq!(
            choose_filename(None, Some(&url("https://fw.example.com/")), noon()),
            "download-20261021-093005.bin"
        );
        assert_eq!(choose_filename(None, None, noon()), "download-20261021-093005.bin");
        // A decoded segment is sanitised too.
        assert_eq!(choose_filename(None, Some(&url("https://fw.example.com/a%2F..%2Fb.pdf")), noon()), "a..b.pdf");
    }

    #[test]
    fn tooltips_and_messages() {
        let off = NavState { allow_downloads: false, ..NavState::default() };
        assert_eq!(download_tooltip(&off), "Downloads disabled for this profile.");
        let pdf =
            NavState { allow_downloads: true, current_mime: Some("application/pdf".into()), ..NavState::default() };
        assert_ne!(download_tooltip(&pdf), DOWNLOADS_DISABLED_TOOLTIP);
        for r in [
            reason::OUTSIDE_ALLOWLIST,
            reason::DOWNLOADS_DISABLED,
            reason::SIZE_EXCEEDED,
            reason::TOO_MANY_DOWNLOADS,
            reason::COLLISION_EXHAUSTED,
            reason::SAVE_IO_ERROR,
            reason::INVALID_FILENAME,
            reason::UNAVAILABLE,
            reason::TRANSFER_FAILED,
        ] {
            assert!(!refusal_message(r).is_empty(), "{r}");
        }
        assert_ne!(refusal_message(reason::TOO_MANY_DOWNLOADS), refusal_message(reason::TRANSFER_FAILED));
    }

    // ── download job ──

    #[test]
    fn a_finished_job_moves_the_bytes_into_the_reserved_name() {
        let d = dest("finish");
        let limiter = Arc::new(DownloadLimiter::new());
        let mut job = DownloadJob::reserve(slot(&limiter), &d, "q3.pdf", "application/pdf").unwrap();
        assert_eq!(job.placeholder(), d.downloads_dir.join("q3.pdf"));
        assert_eq!(std::fs::metadata(job.placeholder()).unwrap().len(), 0, "zero-byte placeholder");
        assert!(!job.staging_file().starts_with(&d.downloads_dir), "bytes are staged outside Downloads");
        job.open_writer().unwrap();
        job.write_chunk(b"%PDF").unwrap();
        job.write_chunk(b"-1.7").unwrap();
        let saved = job.finish().unwrap();
        assert_eq!(saved, Saved { filename: "q3.pdf".into(), mime: "application/pdf".into(), bytes: 8 });
        assert_eq!(std::fs::read(d.downloads_dir.join("q3.pdf")).unwrap(), b"%PDF-1.7");
        assert!(entries(&d.staging_root).is_empty(), "staging removed");
        assert_eq!(limiter.in_flight(), 0, "slot released");
    }

    #[test]
    fn the_staging_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = dest("mode");
        let limiter = Arc::new(DownloadLimiter::new());
        let job = DownloadJob::reserve(slot(&limiter), &d, "a.bin", "application/octet-stream").unwrap();
        let dir = job.staging_file().parent().unwrap();
        assert_eq!(std::fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_name_collision_reserves_the_next_free_name() {
        let d = dest("collide");
        std::fs::write(d.downloads_dir.join("a.pdf"), b"theirs").unwrap();
        let limiter = Arc::new(DownloadLimiter::new());
        let mut job = DownloadJob::reserve(slot(&limiter), &d, "a.pdf", "application/pdf").unwrap();
        job.open_writer().unwrap();
        job.write_chunk(b"ours").unwrap();
        let saved = job.finish().unwrap();
        assert_eq!(saved.filename, "a (1).pdf");
        assert_eq!(std::fs::read(d.downloads_dir.join("a.pdf")).unwrap(), b"theirs", "never overwritten");
        assert_eq!(std::fs::read(d.downloads_dir.join("a (1).pdf")).unwrap(), b"ours");
    }

    #[test]
    fn an_abandoned_job_leaves_nothing_behind() {
        let d = dest("abort");
        let limiter = Arc::new(DownloadLimiter::new());
        let mut job = DownloadJob::reserve(slot(&limiter), &d, "a.pdf", "application/pdf").unwrap();
        job.open_writer().unwrap();
        job.write_chunk(b"partial").unwrap();
        drop(job);
        assert!(entries(&d.downloads_dir).is_empty(), "placeholder removed");
        assert!(entries(&d.staging_root).is_empty(), "staging removed");
        assert_eq!(limiter.in_flight(), 0);
    }

    #[test]
    fn cleanup_never_deletes_a_placeholder_something_else_filled() {
        let d = dest("filled");
        let limiter = Arc::new(DownloadLimiter::new());
        let mut job = DownloadJob::reserve(slot(&limiter), &d, "a.pdf", "application/pdf").unwrap();
        std::fs::write(job.placeholder(), b"someone else's").unwrap();
        job.open_writer().unwrap();
        job.write_chunk(b"ours").unwrap();
        assert_eq!(job.finish().unwrap_err(), reason::SAVE_IO_ERROR, "not moved over a filled name");
        assert_eq!(std::fs::read(d.downloads_dir.join("a.pdf")).unwrap(), b"someone else's");
        assert!(entries(&d.staging_root).is_empty());
    }

    #[test]
    fn the_soft_cap_is_enforced_per_chunk_and_per_total() {
        let d = dest("cap");
        let limiter = Arc::new(DownloadLimiter::new());
        let mut job = DownloadJob::reserve(slot(&limiter), &d, "a.bin", "application/octet-stream").unwrap();
        job.open_writer().unwrap();
        job.record_total(DOWNLOAD_SOFT_CAP_BYTES - 2).unwrap();
        job.write_chunk(b"ab").unwrap();
        assert_eq!(job.write_chunk(b"c"), Err(reason::SIZE_EXCEEDED));
        drop(job);
        assert!(entries(&d.downloads_dir).is_empty());

        let mut job = DownloadJob::reserve(slot(&limiter), &d, "b.bin", "application/octet-stream").unwrap();
        assert_eq!(job.record_total(DOWNLOAD_SOFT_CAP_BYTES + 1), Err(reason::SIZE_EXCEEDED));
    }

    #[test]
    fn a_file_over_the_cap_is_refused_at_finish() {
        // WebKit may finish between two progress reports: the final size is
        // checked too. A sparse file costs no disk.
        let d = dest("final");
        let limiter = Arc::new(DownloadLimiter::new());
        let job = DownloadJob::reserve(slot(&limiter), &d, "big.bin", "application/octet-stream").unwrap();
        let f = std::fs::File::create(job.staging_file()).unwrap();
        f.set_len(DOWNLOAD_SOFT_CAP_BYTES + 1).unwrap();
        drop(f);
        assert_eq!(job.finish().unwrap_err(), reason::SIZE_EXCEEDED);
        assert!(entries(&d.downloads_dir).is_empty());
        assert!(entries(&d.staging_root).is_empty());
    }

    #[test]
    fn a_missing_downloads_folder_is_a_save_error() {
        let d = dest("missing");
        std::fs::remove_dir(&d.downloads_dir).unwrap();
        let limiter = Arc::new(DownloadLimiter::new());
        let err = DownloadJob::reserve(slot(&limiter), &d, "a.pdf", "application/pdf").err();
        assert_eq!(err, Some(reason::SAVE_IO_ERROR));
        assert!(entries(&d.staging_root).is_empty());
        assert_eq!(limiter.in_flight(), 0);
    }

    // ── state machine ──

    #[test]
    fn a_transfer_settles_exactly_once() {
        let d = dest("once");
        let limiter = Arc::new(DownloadLimiter::new());
        let o = origins();
        let mut t = Transfer::new(slot(&limiter), d.clone());
        assert!(t.is_open());
        assert_eq!(t.begin(&pdf_facts(), true, &o, noon()), None);
        let staging = t.staging_file().unwrap().to_path_buf();
        assert_eq!(t.open_writer(), None);
        assert_eq!(t.write_chunk(b"%PDF"), None);
        match t.finish() {
            Some(Settled::Saved(s)) => assert_eq!((s.filename.as_str(), s.bytes), ("q3.pdf", 4)),
            other => panic!("{other:?}"),
        }
        assert!(!t.is_open());
        assert!(!staging.exists());
        // Late native events are ignored.
        assert_eq!(t.fail(reason::TRANSFER_FAILED), None);
        assert_eq!(t.finish(), None);
        assert_eq!(t.write_chunk(b"x"), None);
        assert_eq!(limiter.in_flight(), 0);
    }

    #[test]
    fn a_refused_response_releases_the_slot_and_reserves_nothing() {
        let d = dest("refused");
        let limiter = Arc::new(DownloadLimiter::new());
        let mut t = Transfer::new(slot(&limiter), d.clone());
        let html = ResponseFacts { mime: Some("text/html".into()), ..pdf_facts() };
        assert_eq!(t.begin(&html, true, &origins(), noon()), Some(Settled::Refused(reason::UNAVAILABLE)));
        assert!(!t.is_open());
        assert_eq!(t.fail(reason::TRANSFER_FAILED), None, "the cancellation that follows is not a second outcome");
        assert!(entries(&d.downloads_dir).is_empty());
        assert_eq!(limiter.in_flight(), 0);
    }

    #[test]
    fn a_redirect_off_the_allow_list_is_refused_before_any_byte() {
        let d = dest("redirect");
        let limiter = Arc::new(DownloadLimiter::new());
        let o = origins();
        let mut t = Transfer::new(slot(&limiter), d.clone());
        assert_eq!(t.redirect(Some(&url("https://fw.example.com/next.pdf")), true, &o), None);
        assert!(t.is_open());
        assert_eq!(
            t.redirect(Some(&url("https://evil.example.net/x.pdf")), true, &o),
            Some(Settled::Refused(reason::OUTSIDE_ALLOWLIST))
        );
        assert!(!t.is_open());
        let mut t = Transfer::new(slot(&limiter), d);
        assert_eq!(t.redirect(None, true, &o), Some(Settled::Refused(reason::UNAVAILABLE)));
        assert_eq!(limiter.in_flight(), 0);
    }

    #[test]
    fn a_failure_mid_transfer_cleans_up() {
        let d = dest("midfail");
        let limiter = Arc::new(DownloadLimiter::new());
        let mut t = Transfer::new(slot(&limiter), d.clone());
        assert_eq!(t.begin(&pdf_facts(), true, &origins(), noon()), None);
        assert_eq!(t.open_writer(), None);
        assert_eq!(t.write_chunk(b"%P"), None);
        assert_eq!(t.fail(reason::TRANSFER_FAILED), Some(Settled::Refused(reason::TRANSFER_FAILED)));
        assert!(entries(&d.downloads_dir).is_empty());
        assert!(entries(&d.staging_root).is_empty());
        // Teardown before any response: the slot is released, nothing on disk.
        let mut t = Transfer::new(slot(&limiter), d.clone());
        assert_eq!(t.fail(reason::TRANSFER_FAILED), Some(Settled::Refused(reason::TRANSFER_FAILED)));
        assert_eq!(limiter.in_flight(), 0);
    }

    #[test]
    fn the_cap_settles_the_transfer() {
        let d = dest("capsettle");
        let limiter = Arc::new(DownloadLimiter::new());
        let mut t = Transfer::new(slot(&limiter), d.clone());
        assert_eq!(t.begin(&pdf_facts(), true, &origins(), noon()), None);
        assert_eq!(t.record_total(DOWNLOAD_SOFT_CAP_BYTES), None);
        assert_eq!(t.record_total(DOWNLOAD_SOFT_CAP_BYTES + 1), Some(Settled::Refused(reason::SIZE_EXCEEDED)));
        assert!(!t.is_open());
        assert!(entries(&d.downloads_dir).is_empty());
    }
}
