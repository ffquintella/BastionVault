//! The UI-free half of the Windows (WebView2) shim: the bar's geometry at a
//! given DPI, the buttons' command ids and glyphs, the main-frame navigation
//! tracking the download button's state depends on, the refetch gate (when
//! the bar may request the shown document itself), the request's `Cookie`
//! header, the `Content-Disposition` file name, the destination and the
//! Mark-of-the-Web stream.
//!
//! Not `cfg`-gated, unlike `windows.rs`, so all of it is unit-tested on every
//! host. The Win32 / WebView2 half only reads values out of COM objects and
//! window messages, hands them to these functions and applies what they
//! decide. The platform-neutral pieces it shares with the GTK shim (the
//! button views, the button order, the main-frame response record) are
//! reused from `linux_model` as they are.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tauri::Url;
use zeroize::Zeroizing;

use super::linux_model::ACTIONS;
use super::transfer::{self, Destination};
use super::{reason, NavAction};

// ── Layout ─────────────────────────────────────────────────────────

/// The bar's height in device-independent pixels ([`super::BAR_HEIGHT`]).
pub(crate) const BAR_HEIGHT_DIP: i32 = 36;

/// Width of one bar button (spec §7.1: four buttons, 44 × 36 each).
pub(crate) const BUTTON_WIDTH_DIP: i32 = 44;

/// Gap between the last button and the status text, and at the right edge.
const LABEL_GAP_DIP: i32 = 8;

/// The DPI at which one device-independent pixel is one physical pixel.
pub(crate) const BASE_DPI: u32 = 96;

/// `dip` device-independent pixels at `dpi`, in physical pixels, rounded
/// half up as `MulDiv` does for a positive value. A DPI of 0 (what
/// `GetDpiForWindow` returns for a window it cannot read) counts as 96.
pub(crate) fn scale(dip: i32, dpi: u32) -> i32 {
    let dpi = if dpi == 0 { BASE_DPI } else { dpi };
    let base = i64::from(BASE_DPI);
    // In i64, so no DPI a monitor can report overflows the product.
    let physical = (i64::from(dip) * i64::from(dpi) + base / 2) / base;
    i32::try_from(physical).unwrap_or(i32::MAX)
}

/// A rectangle in physical pixels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Where everything goes for one client-area size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    /// The webview, in the window's client coordinates: everything above
    /// the bar.
    pub webview: Rect,
    /// The bar, in the window's client coordinates: the bottom strip.
    pub bar: Rect,
    /// The four buttons in [`ACTIONS`] order, in the bar's coordinates.
    pub buttons: [Rect; 4],
    /// The status text (a refused download's message), in the bar's
    /// coordinates.
    pub label: Rect,
}

/// The layout of a window whose client area is `client_width` ×
/// `client_height` physical pixels at `dpi`. The bar keeps its full height
/// as long as the window has it, and the webview gets the rest (never a
/// negative height).
pub(crate) fn layout(client_width: i32, client_height: i32, dpi: u32) -> Layout {
    let width = client_width.max(0);
    let height = client_height.max(0);
    let bar_height = scale(BAR_HEIGHT_DIP, dpi).min(height);
    let button_width = scale(BUTTON_WIDTH_DIP, dpi);
    let gap = scale(LABEL_GAP_DIP, dpi);
    let mut x = 0;
    let buttons = ACTIONS.map(|_| {
        let button = Rect { x, y: 0, width: button_width, height: bar_height };
        x = x.saturating_add(button_width);
        button
    });
    let label_x = x.saturating_add(gap);
    Layout {
        webview: Rect { x: 0, y: 0, width, height: height - bar_height },
        bar: Rect { x: 0, y: height - bar_height, width, height: bar_height },
        buttons,
        label: Rect { x: label_x, y: 0, width: (width - label_x - gap).max(0), height: bar_height },
    }
}

// ── Buttons ────────────────────────────────────────────────────────

/// `WM_COMMAND` id of the first button; the others follow in [`ACTIONS`]
/// order. Above the range dialog managers reserve (`IDOK` … `IDCONTINUE`).
pub(crate) const FIRST_COMMAND: u16 = 0x8001;

/// The `WM_COMMAND` id of `action`'s button.
pub(crate) fn command_id(action: NavAction) -> u16 {
    let index = ACTIONS.iter().position(|a| *a == action).unwrap_or(0);
    // Four buttons: the index always fits.
    FIRST_COMMAND + u16::try_from(index).unwrap_or(0)
}

/// The action whose button sent `WM_COMMAND` id `id`.
pub(crate) fn action_for_command(id: u16) -> Option<NavAction> {
    ACTIONS.get(usize::from(id.checked_sub(FIRST_COMMAND)?)).copied()
}

/// The icon font: Segoe MDL2 Assets ships with every Windows 10 and 11.
pub(crate) const ICON_FONT: &str = "Segoe MDL2 Assets";
/// The icon glyphs' height in device-independent pixels.
pub(crate) const ICON_SIZE_DIP: i32 = 16;
/// The status text's font and height.
pub(crate) const TEXT_FONT: &str = "Segoe UI";
pub(crate) const TEXT_SIZE_DIP: i32 = 12;

/// The Segoe MDL2 Assets glyph of `action`'s button (Back, Forward,
/// Refresh, Download).
pub(crate) fn button_glyph(action: NavAction) -> char {
    match action {
        NavAction::Back => '\u{E72B}',
        NavAction::Forward => '\u{E72A}',
        NavAction::Reload => '\u{E72C}',
        NavAction::Download => '\u{E896}',
    }
}

/// How long a refused download's message stays on the bar.
pub(crate) const FLASH_FOR_MS: u32 = 3000;

/// The bar's status text: a refused download's message while it flashes,
/// nothing otherwise.
pub(crate) fn status_text(flash: Option<&'static str>) -> &'static str {
    flash.map_or("", transfer::refusal_message)
}

// ── Main-frame navigation ──────────────────────────────────────────

/// URIs of one navigation remembered (the start and its redirects).
pub(crate) const NAV_URIS_KEPT: usize = 20;

/// What the bar knows about the webview's top-level navigations from
/// `NavigationStarting` / `NavigationCompleted`: whether one is in flight,
/// and which URIs the latest one requested, so that the main frame's
/// response can be told apart from a subresource's in
/// `WebResourceResponseReceived`, which reports both.
#[derive(Debug, Default)]
pub(crate) struct MainFrameNav {
    current: Option<u64>,
    loading: bool,
    uris: Vec<Url>,
}

impl MainFrameNav {
    /// The document the webview shows (or is loading) when the bar attaches:
    /// wry starts the start URL's navigation before the bar's handlers
    /// exist, and that document's response may still arrive. Ignored once a
    /// navigation has been seen.
    pub fn seed(&mut self, shown: Option<Url>) {
        if self.current.is_none() && self.uris.is_empty() {
            self.uris.extend(shown);
        }
    }

    /// `NavigationStarting` for navigation `id` (WebView2 keeps one id
    /// across a navigation's redirects). A navigation another handler
    /// already cancelled is not one.
    pub fn started(&mut self, id: u64, uri: Option<Url>, cancelled: bool) {
        if cancelled {
            return;
        }
        if self.current != Some(id) {
            self.current = Some(id);
            self.uris.clear();
        }
        self.loading = true;
        if let Some(uri) = uri {
            if self.uris.len() < NAV_URIS_KEPT {
                self.uris.push(uri);
            }
        }
    }

    /// `NavigationCompleted` for navigation `id` (also raised for a failed
    /// or cancelled one). A superseded navigation's completion is ignored.
    pub fn completed(&mut self, id: u64) {
        if self.current == Some(id) {
            self.loading = false;
        }
    }

    /// Whether a top-level navigation is in flight.
    pub fn is_loading(&self) -> bool {
        self.loading
    }

    /// Whether a response for `request` answers the latest top-level
    /// navigation (its start or a redirect), fragment ignored. A response
    /// that arrives after the navigation completed still counts, until the
    /// next navigation starts.
    pub fn is_main_frame(&self, request: &Url) -> bool {
        self.uris.iter().any(|u| transfer::same_document(u, request))
    }
}

// ── Refetch gate ───────────────────────────────────────────────────

/// What the window's TLS pin gate says about the shown origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionTls {
    /// The profile pins keys (`TlsPinGate::has_pins`).
    pub has_pins: bool,
    /// The operator accepted a certificate the platform rejected for this
    /// origin, this session (`TlsPinGate::accepted_on_pin`).
    pub accepted_untrusted: bool,
}

/// Whether the bar may request the shown document itself. The request is
/// verified by the platform's trust store only and goes straight to the
/// origin, so it is refused, before anything is requested, whenever the
/// webview's own loads are trusted or routed differently: a profile with
/// pins, a certificate the operator accepted, a window without a TLS gate
/// (`None`: the profile is unknown), or a proxy-mode session. Never a
/// downgrade: what the webview needed an override for, the bar does not
/// fetch.
pub(crate) fn refetch_gate(tls: Option<SessionTls>, proxy_mode: bool) -> Result<(), &'static str> {
    match tls {
        Some(SessionTls { has_pins: false, accepted_untrusted: false }) if !proxy_mode => Ok(()),
        _ => Err(reason::REFETCH_BLOCKED),
    }
}

/// The current user's WinINET proxy settings, which WebView2 follows
/// (`WinHttpGetIEProxyConfigForCurrentUser`): whether each kind of proxy
/// configuration is present. Nothing else is kept (no proxy name, no URL).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SystemProxy {
    /// A fixed proxy server list (`lpszProxy`).
    pub static_proxy: bool,
    /// A proxy auto-config script (`lpszAutoConfigUrl`).
    pub pac_url: bool,
    /// Proxy auto-detection, WPAD (`fAutoDetect`).
    pub auto_detect: bool,
}

/// Whether the bar's request, which goes straight to the origin, takes the
/// route the webview's loads take. WebView2 routes through the user's
/// system proxy, so any proxy configuration refuses the request
/// (`refetch_blocked`) before anything is sent: with the session's cookies
/// it would otherwise bypass a corporate proxy (egress policy, DLP), or fail
/// where direct egress is blocked. `None` (the settings could not be read)
/// refuses too.
///
/// Known limitation: auto-detection (WPAD) is on by default on many
/// Windows installations, and telling "WPAD finds no proxy" apart from "WPAD
/// finds one" would need the discovery itself (DHCP / DNS lookups, seconds
/// of delay). It is refused instead, so on such machines the bar's download
/// is not available and the page's own download link is the way.
pub(crate) fn system_proxy_gate(proxy: Option<SystemProxy>) -> Result<(), &'static str> {
    match proxy {
        Some(SystemProxy { static_proxy: false, pac_url: false, auto_detect: false }) => Ok(()),
        _ => Err(reason::REFETCH_BLOCKED),
    }
}

// ── Request ────────────────────────────────────────────────────────

/// Most cookies read from the webview for one request (Chromium keeps at
/// most 180 per domain).
pub(crate) const MAX_COOKIES: u32 = 180;

/// The `Cookie` header for `cookies` (name, value, `Secure`), as the
/// webview's cookie manager returned them for the request's URL (it has
/// already matched domain, path, `Secure` and expiry). On a plain-http
/// request a `Secure` cookie is left out again, whatever the manager
/// returned. A pair that could not be sent as one cookie (an empty name, a
/// control character, `;`, or `=` in the name) is left out. `None` when
/// nothing is left. The buffer is sized up front, so no unzeroized copy is
/// left behind by a reallocation.
pub(crate) fn cookie_header<'a>(
    request_is_https: bool,
    cookies: impl IntoIterator<Item = (&'a str, &'a str, bool)>,
) -> Option<Zeroizing<String>> {
    let sendable = |part: &str, is_name: bool| {
        !(is_name && part.is_empty()) && part.chars().all(|c| !c.is_control() && c != ';' && !(is_name && c == '='))
    };
    let pairs: Vec<(&str, &str)> = cookies
        .into_iter()
        .filter(|(_, _, secure)| request_is_https || !secure)
        .filter(|(name, value, _)| sendable(name, true) && sendable(value, false))
        .map(|(name, value, _)| (name, value))
        .collect();
    if pairs.is_empty() {
        return None;
    }
    // `name=value` per pair, `; ` between them.
    let length = pairs.iter().map(|(n, v)| n.len() + 1 + v.len()).sum::<usize>() + 2 * (pairs.len() - 1);
    let mut header = Zeroizing::new(String::with_capacity(length));
    for (i, (name, value)) in pairs.into_iter().enumerate() {
        if i > 0 {
            header.push_str("; ");
        }
        header.push_str(name);
        header.push('=');
        header.push_str(value);
    }
    Some(header)
}

/// A secret the webview returned as UTF-16 (a cookie value), decoded into
/// one zeroizing buffer reserved for the worst case (3 UTF-8 bytes per
/// UTF-16 unit: a BMP character takes at most 3, a surrogate pair 4 for its
/// 2 units), so no reallocation leaves an unzeroized copy. A lone surrogate
/// becomes U+FFFD.
pub(crate) fn utf16_secret(units: &[u16]) -> Zeroizing<String> {
    let mut secret = Zeroizing::new(String::with_capacity(units.len().saturating_mul(3)));
    for c in char::decode_utf16(units.iter().copied()) {
        secret.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    secret
}

/// The file name a `Content-Disposition` value suggests (RFC 6266):
/// `filename*` (RFC 8187, UTF-8 or ISO-8859-1) before `filename`, quoted or
/// not. Raw: the caller sanitises it (`transfer::choose_filename`).
pub(crate) fn disposition_filename(value: &str) -> Option<String> {
    let mut plain = None;
    let mut extended = None;
    // The first part is the disposition type.
    for param in disposition_params(value).into_iter().skip(1) {
        let Some((name, raw)) = param.split_once('=') else { continue };
        match name.trim().to_ascii_lowercase().as_str() {
            "filename*" if extended.is_none() => extended = decode_ext_value(raw.trim()),
            "filename" if plain.is_none() => plain = Some(unquote(raw.trim())),
            _ => {}
        }
    }
    extended.filter(|n: &String| !n.is_empty()).or(plain.filter(|n| !n.is_empty()))
}

/// `value` split at the `;` that are not inside a quoted string.
fn disposition_params(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in value.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                parts.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// A token as it is, or a quoted string without its quotes and escapes.
fn unquote(raw: &str) -> String {
    let Some(inner) = raw.strip_prefix('"') else { return raw.to_string() };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// An RFC 8187 `ext-value`: `charset'language'percent-encoded`.
fn decode_ext_value(raw: &str) -> Option<String> {
    let (charset, rest) = raw.split_once('\'')?;
    let (_language, encoded) = rest.split_once('\'')?;
    let bytes = urlencoding::decode_binary(encoded.as_bytes());
    match charset.to_ascii_lowercase().as_str() {
        "utf-8" => String::from_utf8(bytes.into_owned()).ok(),
        "iso-8859-1" => Some(bytes.iter().map(|&b| char::from(b)).collect()),
        _ => None,
    }
}

// ── Destination, Mark of the Web ───────────────────────────────────

/// The folder under the app's own data folder that holds the download
/// staging directories.
pub(crate) const STAGING_DIR: &str = "nav-download-staging";

/// Where the bar's downloads go: the Downloads folder
/// (`FOLDERID_Downloads`, else `%USERPROFILE%\Downloads`; spec §7.6), with
/// the private staging directories in [`STAGING_DIR`] under `app_root`
/// (`embedded::app_root()`, i.e. `%LOCALAPPDATA%\.bastion_vault_gui`),
/// created when missing, else in the temp directory. That folder is the
/// user's own, whatever `%TMP%` points at, is normally on the Downloads
/// folder's volume, and is where a crash's leftovers can be found. `None`
/// when no Downloads folder is known.
pub(crate) fn destination(
    downloads: Option<PathBuf>,
    home: Option<PathBuf>,
    app_root: Option<PathBuf>,
    temp: PathBuf,
) -> Option<Destination> {
    let downloads_dir = transfer::downloads_dir(downloads, home)?;
    let staging = app_root.map(|root| root.join(STAGING_DIR)).filter(|dir| match std::fs::create_dir_all(dir) {
        Ok(()) => std::fs::metadata(dir).is_ok_and(|m| m.is_dir()),
        Err(e) => {
            log::warn!("connect.web.nav_bar: no download staging folder in the app's data folder ({:?})", e.kind());
            false
        }
    });
    Some(Destination { downloads_dir, staging_root: staging.unwrap_or(temp) })
}

/// The Mark of the Web written on a downloaded file: zone 3 (Internet), the
/// most cautious zone the OS applies to downloads. No URL is recorded: the
/// shown URL's path and query can carry tokens.
pub(crate) const ZONE_IDENTIFIER: &str = "[ZoneTransfer]\r\nZoneId=3\r\n";

/// The `Zone.Identifier` alternate data stream of `file`.
pub(crate) fn zone_identifier_path(file: &Path) -> PathBuf {
    let mut stream = OsString::from(file.as_os_str());
    stream.push(":Zone.Identifier");
    PathBuf::from(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::web_nav_bar::{linux_model, NavState, BAR_HEIGHT};

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn tempdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "bv-nav-windows-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // ── layout ──

    #[test]
    fn dips_scale_with_the_dpi() {
        assert_eq!(f64::from(BAR_HEIGHT_DIP), BAR_HEIGHT);
        assert_eq!(scale(36, 96), 36);
        assert_eq!(scale(36, 120), 45, "125 %");
        assert_eq!(scale(36, 144), 54, "150 %");
        assert_eq!(scale(44, 168), 77, "175 %");
        assert_eq!(scale(36, 192), 72, "200 %");
        assert_eq!(scale(1, 144), 2, "1.5 rounds half up");
        assert_eq!(scale(36, 0), 36, "an unreadable DPI counts as 96");
    }

    #[test]
    fn the_bar_owns_the_bottom_strip_and_the_webview_the_rest() {
        let l = layout(1280, 800, 96);
        assert_eq!(l.webview, Rect { x: 0, y: 0, width: 1280, height: 764 });
        assert_eq!(l.bar, Rect { x: 0, y: 764, width: 1280, height: 36 });
        assert_eq!(l.buttons[0], Rect { x: 0, y: 0, width: 44, height: 36 });
        assert_eq!(l.buttons[3], Rect { x: 132, y: 0, width: 44, height: 36 });
        assert_eq!(l.label, Rect { x: 184, y: 0, width: 1280 - 184 - 8, height: 36 });
        // The webview and the bar tile the client area exactly.
        assert_eq!(l.webview.height + l.bar.height, 800);
    }

    #[test]
    fn the_layout_follows_a_dpi_change_maximise_and_restore() {
        // 150 %: the same window, maximised on a 1920 × 1032 client area.
        let l = layout(1920, 1032, 144);
        assert_eq!(l.bar, Rect { x: 0, y: 1032 - 54, width: 1920, height: 54 });
        assert_eq!(l.webview.height, 1032 - 54);
        assert_eq!(l.buttons[1], Rect { x: 66, y: 0, width: 66, height: 54 });
        // Restored to a smaller size at 100 %: recomputed from scratch.
        let l = layout(800, 600, 96);
        assert_eq!(l.bar.y, 564);
        assert_eq!(l.webview.height, 564);
    }

    #[test]
    fn a_tiny_or_empty_client_area_never_goes_negative() {
        let l = layout(100, 20, 96);
        assert_eq!(l.bar, Rect { x: 0, y: 0, width: 100, height: 20 });
        assert_eq!(l.webview.height, 0);
        assert_eq!(l.label.width, 0, "no room for the status text");
        let l = layout(0, 0, 96);
        assert_eq!((l.webview.height, l.bar.height, l.bar.width), (0, 0, 0));
        let l = layout(-5, -5, 96);
        assert_eq!((l.webview.width, l.webview.height, l.bar.height), (0, 0, 0));
    }

    // ── buttons ──

    #[test]
    fn command_ids_map_to_the_four_actions_and_nothing_else() {
        assert_eq!(command_id(NavAction::Back), 0x8001);
        assert_eq!(command_id(NavAction::Download), 0x8004);
        for action in ACTIONS {
            assert_eq!(action_for_command(command_id(action)), Some(action));
        }
        assert_eq!(action_for_command(0x8000), None);
        assert_eq!(action_for_command(0x8005), None);
        assert_eq!(action_for_command(1), None, "IDOK is not a bar button");
        assert_eq!(action_for_command(0), None);
    }

    #[test]
    fn the_glyphs_are_segoe_mdl2_back_forward_refresh_download() {
        let glyphs: Vec<u32> = ACTIONS.iter().map(|a| u32::from(button_glyph(*a))).collect();
        assert_eq!(glyphs, [0xE72B, 0xE72A, 0xE72C, 0xE896]);
        assert_eq!(ICON_FONT, "Segoe MDL2 Assets");
    }

    #[test]
    fn the_status_text_is_the_flashed_refusal_only() {
        assert_eq!(status_text(None), "");
        assert_eq!(
            status_text(Some(reason::TOO_MANY_DOWNLOADS)),
            transfer::refusal_message(reason::TOO_MANY_DOWNLOADS)
        );
        assert_eq!(status_text(Some(reason::REFETCH_BLOCKED)), transfer::refusal_message(reason::REFETCH_BLOCKED));
        // The button views come from the shared mapping, unchanged.
        let off =
            NavState { allow_downloads: false, current_mime: Some("application/pdf".into()), ..NavState::default() };
        let [.., download] = linux_model::button_views(&off, None);
        assert!(!download.sensitive);
        assert_eq!(download.tooltip, "Downloads disabled for this profile.");
    }

    // ── navigation tracking ──

    #[test]
    fn a_navigation_is_loading_from_start_to_its_own_completion() {
        let mut n = MainFrameNav::default();
        assert!(!n.is_loading());
        n.started(7, Some(url("https://fw.example.com/a.pdf")), false);
        assert!(n.is_loading());
        // A superseded navigation's completion does not end the new one.
        n.started(8, Some(url("https://fw.example.com/b")), false);
        n.completed(7);
        assert!(n.is_loading());
        n.completed(8);
        assert!(!n.is_loading());
    }

    #[test]
    fn a_cancelled_navigation_is_not_tracked() {
        let mut n = MainFrameNav::default();
        n.started(1, Some(url("https://fw.example.com/")), false);
        n.completed(1);
        n.started(2, Some(url("https://evil.example.net/")), true);
        assert!(!n.is_loading());
        assert!(!n.is_main_frame(&url("https://evil.example.net/")));
        assert!(n.is_main_frame(&url("https://fw.example.com/")), "the previous navigation stays");
    }

    #[test]
    fn only_the_latest_navigations_uris_are_the_main_frame() {
        let mut n = MainFrameNav::default();
        n.started(3, Some(url("https://fw.example.com/export")), false);
        // A redirect keeps the id and adds its URI.
        n.started(3, Some(url("https://fw.example.com/files/r.pdf")), false);
        assert!(n.is_main_frame(&url("https://fw.example.com/export")));
        assert!(n.is_main_frame(&url("https://fw.example.com/files/r.pdf")));
        assert!(!n.is_main_frame(&url("https://fw.example.com/app.js")), "a subresource");
        // A response that arrives after completion still counts.
        n.completed(3);
        assert!(n.is_main_frame(&url("https://fw.example.com/files/r.pdf")));
        // The next navigation forgets the old URIs.
        n.started(4, Some(url("https://fw.example.com/next")), false);
        assert!(!n.is_main_frame(&url("https://fw.example.com/files/r.pdf")));
        // Fragment-insensitive, query-sensitive.
        n.started(5, Some(url("https://fw.example.com/doc?id=1#p2")), false);
        assert!(n.is_main_frame(&url("https://fw.example.com/doc?id=1")));
        assert!(!n.is_main_frame(&url("https://fw.example.com/doc?id=2")));
    }

    #[test]
    fn the_document_shown_at_attach_time_counts_until_a_navigation_is_seen() {
        // The start URL's navigation can begin before the bar's handlers
        // exist; its response may still arrive.
        let mut n = MainFrameNav::default();
        n.seed(Some(url("https://fw.example.com/start.pdf")));
        assert!(n.is_main_frame(&url("https://fw.example.com/start.pdf")));
        assert!(!n.is_loading(), "nothing is known to be loading");
        n.started(1, Some(url("https://fw.example.com/next")), false);
        assert!(!n.is_main_frame(&url("https://fw.example.com/start.pdf")), "replaced by the first navigation");
        // Once a navigation was seen, a seed changes nothing.
        n.seed(Some(url("https://fw.example.com/other")));
        assert!(!n.is_main_frame(&url("https://fw.example.com/other")));
        let mut n = MainFrameNav::default();
        n.seed(None);
        assert!(!n.is_main_frame(&url("https://fw.example.com/")));
    }

    #[test]
    fn a_redirect_loop_does_not_grow_the_uri_list() {
        let mut n = MainFrameNav::default();
        for i in 0..(NAV_URIS_KEPT + 50) {
            n.started(9, Some(url(&format!("https://fw.example.com/r{i}"))), false);
        }
        assert!(n.is_main_frame(&url("https://fw.example.com/r0")));
        assert!(!n.is_main_frame(&url(&format!("https://fw.example.com/r{}", NAV_URIS_KEPT + 49))));
        assert!(n.is_loading());
    }

    // ── refetch gate ──

    #[test]
    fn the_refetch_is_refused_whenever_the_webview_was_trusted_or_routed_differently() {
        let plain = SessionTls { has_pins: false, accepted_untrusted: false };
        assert_eq!(refetch_gate(Some(plain), false), Ok(()));
        let pinned = SessionTls { has_pins: true, ..plain };
        assert_eq!(refetch_gate(Some(pinned), false), Err(reason::REFETCH_BLOCKED));
        let accepted = SessionTls { accepted_untrusted: true, ..plain };
        assert_eq!(refetch_gate(Some(accepted), false), Err(reason::REFETCH_BLOCKED));
        assert_eq!(refetch_gate(None, false), Err(reason::REFETCH_BLOCKED), "no gate: the profile is unknown");
        assert_eq!(refetch_gate(Some(plain), true), Err(reason::REFETCH_BLOCKED), "proxy mode");
    }

    // ── system proxy ──

    #[test]
    fn the_refetch_is_allowed_only_without_any_system_proxy() {
        assert_eq!(system_proxy_gate(Some(SystemProxy::default())), Ok(()), "no proxy, no PAC, no auto-detect");
        let static_proxy = SystemProxy { static_proxy: true, ..SystemProxy::default() };
        assert_eq!(system_proxy_gate(Some(static_proxy)), Err(reason::REFETCH_BLOCKED));
        let pac = SystemProxy { pac_url: true, ..SystemProxy::default() };
        assert_eq!(system_proxy_gate(Some(pac)), Err(reason::REFETCH_BLOCKED));
        let wpad = SystemProxy { auto_detect: true, ..SystemProxy::default() };
        assert_eq!(system_proxy_gate(Some(wpad)), Err(reason::REFETCH_BLOCKED));
        assert_eq!(system_proxy_gate(None), Err(reason::REFETCH_BLOCKED), "unreadable settings: fail closed");
        // The refusal is the "cannot fetch it from here" state, not a failure.
        assert_ne!(transfer::refusal_message(reason::REFETCH_BLOCKED), transfer::refusal_message("other"));
    }

    // ── cookies ──

    #[test]
    fn the_cookie_header_joins_the_webviews_cookies() {
        let h = cookie_header(true, [("SID", "abc", true), ("theme", "dark", false)]).unwrap();
        assert_eq!(h.as_str(), "SID=abc; theme=dark");
        assert_eq!(h.capacity(), h.len(), "sized up front, never reallocated");
        let h = cookie_header(true, [("empty", "", false)]).unwrap();
        assert_eq!(h.as_str(), "empty=");
        assert!(cookie_header(true, std::iter::empty()).is_none());
    }

    #[test]
    fn a_secure_cookie_never_goes_over_plain_http() {
        let cookies = [("SID", "s3cr3t", true), ("theme", "dark", false)];
        assert_eq!(cookie_header(false, cookies).unwrap().as_str(), "theme=dark");
        assert_eq!(cookie_header(true, cookies).unwrap().as_str(), "SID=s3cr3t; theme=dark");
        assert!(cookie_header(false, [("SID", "s3cr3t", true)]).is_none());
    }

    #[test]
    fn a_cookie_that_could_split_or_forge_the_header_is_left_out() {
        let h = cookie_header(
            true,
            [
                ("ok", "1", false),
                ("", "anonymous", false),
                ("a=b", "x", false),
                ("semi", "a; injected=1", false),
                ("crlf", "a\r\nX-Evil: 1", false),
                ("nul", "a\0b", false),
                ("tab\t", "x", false),
                ("last", "2", false),
            ],
        )
        .unwrap();
        assert_eq!(h.as_str(), "ok=1; last=2");
        assert!(cookie_header(true, [("bad", "\n", false)]).is_none());
    }

    #[test]
    fn a_utf16_secret_is_decoded_into_one_presized_buffer() {
        let units: Vec<u16> = "s3cr3t-é-😀".encode_utf16().collect();
        let s = utf16_secret(&units);
        assert_eq!(s.as_str(), "s3cr3t-é-😀");
        assert_eq!(s.capacity(), units.len() * 3, "the worst case was reserved: no reallocation");
        // A lone surrogate becomes U+FFFD, as `from_utf16_lossy` would make it.
        let s = utf16_secret(&[0x61, 0xD800, 0x62]);
        assert_eq!(s.as_str(), "a\u{FFFD}b");
        assert_eq!(utf16_secret(&[]).as_str(), "");
    }

    // ── content disposition ──

    #[test]
    fn the_disposition_names_the_file() {
        assert_eq!(disposition_filename("attachment; filename=report.pdf").as_deref(), Some("report.pdf"));
        assert_eq!(disposition_filename("attachment; filename=\"Q3 report.pdf\"").as_deref(), Some("Q3 report.pdf"));
        assert_eq!(disposition_filename("inline; FILENAME = \"a.pdf\" ").as_deref(), Some("a.pdf"));
        assert_eq!(disposition_filename("attachment; filename=\"a;b.pdf\"; size=3").as_deref(), Some("a;b.pdf"));
        assert_eq!(disposition_filename(r#"attachment; filename="say \"hi\".txt""#).as_deref(), Some("say \"hi\".txt"));
        assert_eq!(disposition_filename("attachment"), None);
        assert_eq!(disposition_filename("attachment; filename="), None);
        assert_eq!(disposition_filename("attachment; name=x.pdf"), None);
    }

    #[test]
    fn the_extended_filename_wins_and_is_decoded() {
        assert_eq!(
            disposition_filename("attachment; filename=\"fallback.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf")
                .as_deref(),
            Some("résumé.pdf")
        );
        assert_eq!(disposition_filename("attachment; filename*=utf-8'en'a%20b.pdf").as_deref(), Some("a b.pdf"));
        assert_eq!(disposition_filename("attachment; filename*=ISO-8859-1''caf%E9.txt").as_deref(), Some("café.txt"));
        // Undecodable or of an unknown charset: the plain name is used.
        assert_eq!(
            disposition_filename("attachment; filename*=UTF-8''%FF%FE.pdf; filename=plain.pdf").as_deref(),
            Some("plain.pdf")
        );
        assert_eq!(
            disposition_filename("attachment; filename*=KOI8-R''x.pdf; filename=plain.pdf").as_deref(),
            Some("plain.pdf")
        );
        assert_eq!(disposition_filename("attachment; filename*=no-quotes.pdf"), None);
    }

    #[test]
    fn a_path_in_the_disposition_is_sanitised_by_the_shared_naming() {
        // Raw here (a quoted-string's `\x` is `x`, RFC 9110 §5.6.4);
        // `choose_filename` strips separators and leading dots.
        let raw = disposition_filename("attachment; filename=\"..\\..\\Windows\\evil.exe\"").unwrap();
        assert_eq!(raw, "....Windowsevil.exe");
        assert_eq!(transfer::choose_filename(Some(&raw), None, chrono::NaiveDateTime::default()), "Windowsevil.exe");
        let token = disposition_filename("attachment; filename=..\\..\\evil.exe").unwrap();
        assert_eq!(token, "..\\..\\evil.exe", "a token keeps its backslashes");
        assert_eq!(transfer::choose_filename(Some(&token), None, chrono::NaiveDateTime::default()), "evil.exe");
        let stream = disposition_filename("attachment; filename=\"a.pdf:Zone.Identifier\"").unwrap();
        assert_eq!(
            transfer::choose_filename(Some(&stream), None, chrono::NaiveDateTime::default()),
            "a.pdf_Zone.Identifier",
            "no alternate data stream through the name"
        );
    }

    // ── destination, MOTW ──

    #[test]
    fn the_destination_is_downloads_with_staging_in_the_apps_own_folder() {
        let root = tempdir("dest");
        // `%LOCALAPPDATA%\.bastion_vault_gui`, which may not exist yet.
        let app = root.join("AppData").join("Local").join(".bastion_vault_gui");
        let temp = root.join("Temp");
        let d = destination(Some(root.join("Downloads")), Some(root.clone()), Some(app.clone()), temp.clone()).unwrap();
        let staging = app.join(STAGING_DIR);
        assert_eq!(d, Destination { downloads_dir: root.join("Downloads"), staging_root: staging.clone() });
        assert!(std::fs::metadata(&staging).unwrap().is_dir(), "created, so orphans gather in one place");
        // Already there: reused.
        let d = destination(None, Some(root.clone()), Some(app.clone()), temp.clone()).unwrap();
        assert_eq!((d.downloads_dir, d.staging_root), (root.join("Downloads"), staging));
        // No app folder, or one that cannot hold a directory: the temp directory.
        let d = destination(None, Some(root.clone()), None, temp.clone()).unwrap();
        assert_eq!(d.staging_root, temp);
        let blocked = root.join("blocked");
        std::fs::write(&blocked, b"a file, not a folder").unwrap();
        let d = destination(None, Some(root.clone()), Some(blocked), temp.clone()).unwrap();
        assert_eq!(d.staging_root, temp);
        assert_eq!(destination(None, None, Some(app), root.join("t")), None);
        assert!(!root.join("Downloads").exists(), "the Downloads folder is never created");
    }

    #[test]
    fn the_mark_of_the_web_is_the_files_zone_identifier_stream() {
        assert_eq!(
            zone_identifier_path(Path::new("C:\\Users\\op\\Downloads\\q3 (1).pdf")),
            PathBuf::from("C:\\Users\\op\\Downloads\\q3 (1).pdf:Zone.Identifier")
        );
        assert_eq!(ZONE_IDENTIFIER, "[ZoneTransfer]\r\nZoneId=3\r\n");
        assert!(!ZONE_IDENTIFIER.contains("Url"), "no URL is written to disk");
    }

    // ── isolation ──

    /// The bar is native Win32, never DOM (spec §7.2, §8.1): neither half of
    /// the Windows shim, its re-request, nor the shared download model may
    /// inject a script into the page, run one, expose a host object to it,
    /// drive it over the DevTools protocol, or open a page-to-host message
    /// channel. The names are assembled from pieces so this file does not
    /// contain them itself.
    #[test]
    fn test_bar_is_not_a_dom_node() {
        let forbidden = [
            concat!("AddScriptToExecute", "OnDocumentCreated"),
            concat!("Execute", "Script"),
            concat!("PostWeb", "Message"),
            concat!("WebMessage", "Received"),
            concat!("java", "script:"),
            concat!("NavigateTo", "String"),
            concat!("add_", "script"),
            concat!("run_", "javascript"),
            concat!("AddHostObject", "ToScript"),
            concat!("CallDevTools", "ProtocolMethod"),
        ];
        let sources = [
            ("windows.rs", include_str!("windows.rs")),
            ("windows_model.rs", include_str!("windows_model.rs")),
            ("windows_refetch.rs", include_str!("windows_refetch.rs")),
            ("transfer.rs", include_str!("transfer.rs")),
        ];
        for (name, src) in sources {
            for f in forbidden {
                assert!(!src.contains(f), "{name} uses {f}: the bar must stay a native view (spec §7.2, §8.1)");
            }
        }
    }
}
