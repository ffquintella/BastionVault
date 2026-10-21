//! The UI-free half of the Linux (GTK 3 / WebKitGTK) shim: what each button
//! shows, the Downloads folder with the Linux last-resort create of
//! `$HOME/Downloads`, the staging root, the claim rule for the bar's own
//! WebKitDownload and the translation of WebKitGTK's response fields into the
//! shared `transfer` types.
//!
//! Not `cfg`-gated, unlike `linux.rs`, so all of it is unit-tested on every
//! host (the GTK half cannot run on the macOS hosts this was written on).
//! The GTK half only reads values out of GTK / WebKitGTK objects, hands them
//! to these functions and applies what they decide.

use std::path::{Path, PathBuf};

use tauri::Url;

use super::transfer::{self, MainFrameResponse, ResponseFacts};
use super::{reason, NavAction, NavState};

// ── Layout ─────────────────────────────────────────────────────────

/// The bar's height in GTK logical pixels ([`super::BAR_HEIGHT`]).
pub(crate) const BAR_HEIGHT_PX: i32 = 36;

/// Width of one bar button (spec §7.1: four buttons, 44 × 36 each).
pub(crate) const BUTTON_WIDTH_PX: i32 = 44;

/// Button order in the bar, left to right.
pub(crate) const ACTIONS: [NavAction; 4] =
    [NavAction::Back, NavAction::Forward, NavAction::Reload, NavAction::Download];

/// `(Adwaita icon name, label)` of a button. The label is the tooltip.
pub(crate) fn button_face(action: NavAction) -> (&'static str, &'static str) {
    match action {
        NavAction::Back => ("go-previous-symbolic", "Back"),
        NavAction::Forward => ("go-next-symbolic", "Forward"),
        NavAction::Reload => ("view-refresh-symbolic", "Reload"),
        NavAction::Download => ("document-save-symbolic", "Download"),
    }
}

/// How one button is drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ButtonView {
    pub sensitive: bool,
    pub tooltip: &'static str,
    /// The short-lived error state (spec §7.6): drawn as a destructive
    /// action.
    pub alert: bool,
}

/// The four buttons for `state`, in [`ACTIONS`] order. While `flash` (a
/// refusal reason) lasts, the download button shows its message instead of
/// its tooltip.
pub(crate) fn button_views(state: &NavState, flash: Option<&'static str>) -> [ButtonView; 4] {
    let plain = |action, sensitive| ButtonView { sensitive, tooltip: button_face(action).1, alert: false };
    let download = ButtonView {
        sensitive: state.download_enabled(),
        tooltip: flash.map_or_else(|| transfer::download_tooltip(state), transfer::refusal_message),
        alert: flash.is_some(),
    };
    [
        plain(NavAction::Back, state.can_go_back),
        plain(NavAction::Forward, state.can_go_forward),
        plain(NavAction::Reload, !state.is_loading),
        download,
    ]
}

// ── Destination ────────────────────────────────────────────────────

/// The Downloads folder (spec §7.6): `platform` (`dirs::download_dir()`,
/// i.e. `XDG_DOWNLOAD_DIR`) as it is; when that is unset, `$HOME/Downloads`,
/// created if it is missing (the Linux last resort). Only that one directory
/// is created, never `$HOME` itself. `None` when no folder is known or the
/// fallback is not a directory; the download is then refused.
pub(crate) fn ensure_downloads_dir(platform: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    if platform.is_some() {
        return platform;
    }
    let fallback = transfer::downloads_dir(None, home)?;
    // `create_dir`, not `create_dir_all`: a missing `$HOME` is not ours to make.
    if let Err(e) = std::fs::create_dir(&fallback) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            log::warn!("connect.web.nav_bar: could not create the Downloads folder ({:?})", e.kind());
            return None;
        }
    }
    // Follows a symlink: `~/Downloads` pointing at another disk is common.
    std::fs::metadata(&fallback).is_ok_and(|m| m.is_dir()).then_some(fallback)
}

/// Where the per-download private staging directories go: the user's cache
/// directory (`$XDG_CACHE_HOME`, else `~/.cache`) when it exists, else the
/// temp directory. `/tmp` is often a tmpfs, so staging there would hold a
/// download in memory and turn the final move into a copy on the GTK main
/// thread; the cache directory is normally on the same filesystem as the
/// Downloads folder.
pub(crate) fn staging_root(cache: Option<PathBuf>, temp: PathBuf) -> PathBuf {
    cache.filter(|c| std::fs::metadata(c).is_ok_and(|m| m.is_dir())).unwrap_or(temp)
}

/// The value for `webkit_download_set_destination`: a `file://` URI, which
/// every WebKitGTK 4.1 release accepts (older ones take only a URI; 2.40 and
/// later also take a path). `None` for a relative path.
pub(crate) fn destination_uri(path: &Path) -> Option<String> {
    Url::from_file_path(path).ok().map(String::from)
}

// ── Responses ──────────────────────────────────────────────────────

/// A WebKitGTK response as the shared checks want it. WebKitGTK reports
/// status 0 for a non-HTTP response and content length 0 when the server
/// sent none (or a wrong one).
pub(crate) fn response_facts(
    uri: Option<&str>,
    status: u32,
    mime: Option<&str>,
    content_disposition: Option<&str>,
    content_length: u64,
    suggested_filename: Option<&str>,
) -> ResponseFacts {
    ResponseFacts {
        url: uri.and_then(|u| Url::parse(u).ok()),
        status: (status != 0).then(|| i64::from(status)),
        mime: non_empty(mime),
        content_disposition: non_empty(content_disposition),
        expected_length: (content_length > 0).then_some(content_length),
        suggested_filename: non_empty(suggested_filename),
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.is_empty()).map(str::to_string)
}

/// The main resource's response of a committed load, for the tracker.
pub(crate) fn main_frame_response(
    uri: Option<&str>,
    mime: Option<&str>,
    content_disposition: Option<&str>,
) -> Option<MainFrameResponse> {
    Some(MainFrameResponse {
        url: Url::parse(uri?).ok()?,
        mime: non_empty(mime),
        attachment: content_disposition.is_some_and(transfer::is_attachment),
    })
}

// ── Claiming the bar's download ────────────────────────────────────

/// Whether the bar owns the WebKitDownload `webkit_web_view_download_uri`
/// returned. wry attaches `RemotePolicy::on_download` to every download in
/// the context's `download-started`, which WebKitGTK emits on a later turn of
/// the main loop; the bar's handlers, connected as soon as the call returns,
/// therefore run first and keep wry's off this download. Had WebKitGTK
/// announced the download while the call was still running, wry's handlers
/// would come first: the bar then refuses (and cancels) the download rather
/// than share it, so one download never gets two owners.
pub(crate) fn claim(announced_during_call: bool) -> Result<(), &'static str> {
    if announced_during_call {
        Err(reason::TRANSFER_FAILED)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::web_nav_bar::{transfer, BAR_HEIGHT};

    fn tempdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "bv-nav-linux-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn pdf_state() -> NavState {
        NavState { allow_downloads: true, current_mime: Some("application/pdf".into()), ..NavState::default() }
    }

    // ── layout ──

    #[test]
    fn the_bar_is_36_px_with_four_44_px_adwaita_buttons() {
        assert_eq!(f64::from(BAR_HEIGHT_PX), BAR_HEIGHT);
        assert_eq!(BUTTON_WIDTH_PX, 44);
        assert_eq!(ACTIONS, [NavAction::Back, NavAction::Forward, NavAction::Reload, NavAction::Download]);
        let icons: Vec<&str> = ACTIONS.iter().map(|a| button_face(*a).0).collect();
        assert_eq!(
            icons,
            ["go-previous-symbolic", "go-next-symbolic", "view-refresh-symbolic", "document-save-symbolic"]
        );
        assert_eq!(button_face(NavAction::Download).1, "Download");
    }

    #[test]
    fn buttons_follow_the_nav_state() {
        let s = NavState { can_go_back: true, ..pdf_state() };
        let [back, forward, reload, download] = button_views(&s, None);
        assert_eq!(back, ButtonView { sensitive: true, tooltip: "Back", alert: false });
        assert_eq!(forward, ButtonView { sensitive: false, tooltip: "Forward", alert: false });
        assert_eq!(reload, ButtonView { sensitive: true, tooltip: "Reload", alert: false });
        assert!(download.sensitive && !download.alert);
        assert_eq!(download.tooltip, transfer::download_tooltip(&s));

        // Mid-load: no reload, no download.
        let loading = NavState { is_loading: true, ..s.clone() };
        let [_, _, reload, download] = button_views(&loading, None);
        assert!(!reload.sensitive && !download.sensitive);
    }

    #[test]
    fn a_profile_without_downloads_keeps_the_button_disabled_with_the_spec_tooltip() {
        let s = NavState { allow_downloads: false, ..pdf_state() };
        let [.., download] = button_views(&s, None);
        assert!(!download.sensitive);
        assert_eq!(download.tooltip, "Downloads disabled for this profile.");
    }

    #[test]
    fn html_without_attachment_is_not_downloadable() {
        let s = NavState { current_mime: Some("text/html".into()), ..pdf_state() };
        assert!(!button_views(&s, None)[3].sensitive);
        let s = NavState { content_disposition_attachment: true, ..s };
        assert!(button_views(&s, None)[3].sensitive);
    }

    #[test]
    fn a_flash_shows_the_refusal_on_the_download_button_only() {
        let s = pdf_state();
        let views = button_views(&s, Some(reason::TOO_MANY_DOWNLOADS));
        assert!(views[3].alert);
        assert_eq!(views[3].tooltip, transfer::refusal_message(reason::TOO_MANY_DOWNLOADS));
        assert!(views[..3].iter().all(|v| !v.alert));
        // The flash never enables a button the state disables.
        let off = NavState { allow_downloads: false, ..s };
        assert!(!button_views(&off, Some(reason::DOWNLOADS_DISABLED))[3].sensitive);
    }

    // ── destination ──

    #[test]
    fn the_xdg_download_dir_is_used_as_it_is_and_never_created() {
        let root = tempdir("xdg");
        let xdg = root.join("Téléchargements");
        assert_eq!(ensure_downloads_dir(Some(xdg.clone()), Some(root.clone())), Some(xdg.clone()));
        assert!(!xdg.exists(), "an XDG folder that is missing is not created");
        assert!(!root.join("Downloads").exists(), "no fallback when XDG names a folder");
    }

    #[test]
    fn without_xdg_home_downloads_is_created_once() {
        let home = tempdir("home");
        let expected = home.join("Downloads");
        assert_eq!(ensure_downloads_dir(None, Some(home.clone())), Some(expected.clone()));
        assert!(std::fs::metadata(&expected).unwrap().is_dir());
        std::fs::write(expected.join("keep.txt"), b"x").unwrap();
        // Already there: reused as it is.
        assert_eq!(ensure_downloads_dir(None, Some(home.clone())), Some(expected.clone()));
        assert!(expected.join("keep.txt").exists());
    }

    #[test]
    fn the_fallback_never_creates_home_and_refuses_a_file() {
        let root = tempdir("nohome");
        let missing_home = root.join("gone");
        assert_eq!(ensure_downloads_dir(None, Some(missing_home.clone())), None);
        assert!(!missing_home.exists(), "$HOME is never created");
        let home = tempdir("filehome");
        std::fs::write(home.join("Downloads"), b"not a directory").unwrap();
        assert_eq!(ensure_downloads_dir(None, Some(home)), None);
        assert_eq!(ensure_downloads_dir(None, None), None);
    }

    #[test]
    fn staging_goes_to_the_cache_dir_when_it_exists() {
        let cache = tempdir("cache");
        let temp = PathBuf::from("/tmp");
        assert_eq!(staging_root(Some(cache.clone()), temp.clone()), cache.clone());
        assert_eq!(staging_root(Some(cache.join("missing")), temp.clone()), temp.clone());
        assert_eq!(staging_root(None, temp.clone()), temp);
    }

    #[test]
    fn the_destination_is_a_percent_encoded_file_uri() {
        let p = Path::new("/home/op/.cache/bv-nav-download-1/r e#p%.html");
        let uri = destination_uri(p).unwrap();
        // The form GLib's g_filename_to_uri gives (and WebKitGTK decodes).
        assert_eq!(uri, "file:///home/op/.cache/bv-nav-download-1/r%20e%23p%25.html");
        assert_eq!(Url::parse(&uri).unwrap().to_file_path().unwrap(), p);
        assert_eq!(destination_uri(Path::new("relative/a.pdf")), None);
    }

    // ── responses ──

    #[test]
    fn webkitgtk_response_fields_map_to_the_shared_facts() {
        let f = response_facts(
            Some("https://fw.example.com/r/q3.pdf?sig=1"),
            200,
            Some("application/pdf"),
            Some("attachment; filename=q3.pdf"),
            4096,
            Some("q3.pdf"),
        );
        assert_eq!(f.url.as_ref().map(Url::as_str), Some("https://fw.example.com/r/q3.pdf?sig=1"));
        assert_eq!(f.status, Some(200));
        assert_eq!(f.mime.as_deref(), Some("application/pdf"));
        assert_eq!(f.content_disposition.as_deref(), Some("attachment; filename=q3.pdf"));
        assert_eq!(f.expected_length, Some(4096));
        assert_eq!(f.suggested_filename.as_deref(), Some("q3.pdf"));

        // Status 0 (not HTTP), length 0 (unknown), empty strings and an
        // unparsable URI carry nothing.
        let f = response_facts(Some("not a url"), 0, Some(""), None, 0, Some(""));
        assert_eq!(f, ResponseFacts::default());
    }

    #[test]
    fn a_main_frame_response_records_mime_and_attachment() {
        let r = main_frame_response(Some("https://fw.example.com/a.pdf"), Some("application/pdf"), None).unwrap();
        assert_eq!(r.url.as_str(), "https://fw.example.com/a.pdf");
        assert_eq!(r.mime.as_deref(), Some("application/pdf"));
        assert!(!r.attachment);
        let r = main_frame_response(Some("https://fw.example.com/r"), Some("text/html"), Some("attachment")).unwrap();
        assert!(r.attachment);
        let r = main_frame_response(Some("https://fw.example.com/r"), Some(""), Some("inline")).unwrap();
        assert_eq!((r.mime, r.attachment), (None, false));
        assert_eq!(main_frame_response(None, Some("text/html"), None), None);
        assert_eq!(main_frame_response(Some("::"), Some("text/html"), None), None);
    }

    // ── claim ──

    #[test]
    fn a_download_announced_before_the_bar_claimed_it_is_refused_not_shared() {
        assert_eq!(claim(false), Ok(()));
        assert_eq!(claim(true), Err(reason::TRANSFER_FAILED));
    }

    // ── isolation ──

    /// The bar is native GTK, never DOM (spec §7.2, §8.1): neither half of
    /// the Linux shim, nor the shared download model, may inject a script
    /// into the page, run one, or open a page-to-host message channel. The
    /// names are assembled from pieces so this file does not contain them
    /// itself.
    #[test]
    fn test_bar_is_not_a_dom_node() {
        let forbidden = [
            concat!("UserContent", "Manager"),
            concat!("user_", "content"),
            concat!("User", "Script"),
            concat!("add_", "script"),
            concat!("run_", "javascript"),
            concat!("evaluate_", "javascript"),
            concat!("call_async_", "javascript"),
            concat!("register_script_", "message_handler"),
            concat!("script_", "message"),
        ];
        let sources = [
            ("linux.rs", include_str!("linux.rs")),
            ("linux_model.rs", include_str!("linux_model.rs")),
            ("transfer.rs", include_str!("transfer.rs")),
        ];
        for (name, src) in sources {
            for f in forbidden {
                assert!(!src.contains(f), "{name} uses {f}: the bar must stay a native view (spec §7.2, §8.1)");
            }
        }
    }
}
