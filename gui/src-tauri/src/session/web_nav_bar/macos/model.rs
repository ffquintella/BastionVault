//! The UI-free, macOS-only half of the shim: AppKit layout arithmetic (NSView
//! coordinates, SF Symbols) and the OS-version capability checks. The
//! platform-neutral decisions (the main-frame response tracker, the download
//! policy and response checks, file naming, the download job and the
//! per-download state machine) are in `web_nav_bar::transfer`.
//!
//! Nothing here touches AppKit or WebKit, so all of it is unit-tested. The
//! FFI half (`super`) only reads facts out of Objective-C objects, hands them
//! to these functions and applies what they decide.

use crate::session::web_nav_bar::{NavAction, BAR_HEIGHT};

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

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── OS capabilities ──

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
}
