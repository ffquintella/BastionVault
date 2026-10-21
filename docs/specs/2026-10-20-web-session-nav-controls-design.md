# Web session navigation controls (back / forward / reload / download)

Status: implemented (T459, S105), pending live verification on macOS, Windows and Linux. Sections marked *As built* below were corrected after implementation; see "As built / deviations" at the end and the *Session navigation bar* section of [features/web-application-connect.md](../../features/web-application-connect.md).
Author: Felipe Quintella + Claude.
Related: [features/web-application-connect.md](../../features/web-application-connect.md).

## 1. Intent

A web Connect session window today has no chrome: once the operator navigates
away from the fill engine's landing page (clicks a link, opens a PDF), there
is no way to go back, no way to reload, and no way to save the file they are
looking at. The only exit is closing the window, which ends the session.

Add four controls to every web session window, on every platform the GUI
ships on (macOS, Windows, Linux): **back**, **forward**, **reload**,
**download**.

## 2. Why now

Concrete trigger: operator opened [km.esi.fgv.br](https://km.esi.fgv.br), the
form fill signed them in, they clicked a wiki link that resolved to a PDF
rendered inline by WKWebView, and now the window is a dead end — the PDF, no
history, no download, no close-without-signout.

## 3. Goals

- **G1.** The operator can go back and forward in the main-frame history of a
  session window.
- **G2.** The operator can reload the current main-frame URL.
- **G3.** When the main-frame response is a downloadable MIME type (§7.5) or
  carries `Content-Disposition: attachment`, **and** the profile's
  `allow_downloads` flag is true, the operator can save it to the OS Downloads
  directory with the server's suggested filename, with no save dialog.
- **G4.** The controls are visible and interactable regardless of what the
  webview is currently rendering, including the inline PDF viewer, where DOM
  injection does not reach.
- **G5.** The controls work regardless of fill state — before, during, and
  after sign-in. Reloading mid-fill does not re-trigger the fill engine
  (§7.6).
- **G6.** macOS, Windows, Linux — one visible, functional bar per session
  window.

## 4. Non-goals

- Not Phase 5 session chrome (Disconnect, Re-run login, lock state,
  countdown). Those stay under `web_session_chrome`. §7.7 is how the two
  coexist.
- Not "save page as" for HTML responses. HTML pages served by the session
  commonly include a session cookie in a form or a token in a URL — writing
  arbitrary HTML to disk is a credential-leak surface we are not opening.
- Not a file-chooser dialog. Always `~/Downloads` (or the OS equivalent).
- Not autohide. The bar is always visible.
- Not keyboard shortcuts in this iteration (follow-up in §11).
- Not loosening the profile's `allow_downloads` default (false). A profile
  that forbids downloads keeps forbidding them; the bar's download button is
  disabled.
- Not touching `TlsPinGate`, the HTTP-auth handlers, the navigation
  allow-list, or the fill engine's own state. The bar's actions pass through
  the webview and reuse every existing gate.

## 5. Anti-goals (would make this a failure even if it worked)

- **A1.** Breaking the fill engine. The bar's native code must not touch any
  form input, must not race the fill routine, and must not consume navigation
  events the fill observes.
- **A2.** Exposing a credential, a TOTP, a token, a cookie, a `launch_id`, or
  the operator's user name through the bar's wire, UI, or audit payload. The
  bar sees only navigation primitives.
- **A3.** Giving a hostile page the ability to issue vault commands or
  simulate bar clicks. The bar is **not** DOM. It is a native sibling view
  outside the webview's reach (§7.1); nothing the page scripts can do
  reaches the bar's event path.
- **A4.** Overriding the profile's `allow_downloads` flag. A profile with
  downloads forbidden must stay that way — operator and auditors expect it.
- **A5.** Letting the bar overlap or hide page content in a way that is not
  obvious. Page content under the bar must stay reachable (§7.1).
- **A6.** Bypassing the `RemotePolicy::on_download` handler
  (gui/src-tauri/src/commands/connect_web.rs:1596). The bar reuses the same
  audit and policy code the webview's own download path uses today.

## 6. Platforms

The bar is a **native sibling view** on all three platforms, attached by
reaching the raw window handle wry already gives us. This does **not**
require Tauri's `unstable` feature: `unstable` is required for Tauri's
multi-*webview* layout; a native non-webview sibling is reachable through
`tao`'s `raw_window_handle()` and the platform's own window API.

| Platform | Webview | How the bar attaches | History / reload | Download trigger |
|---|---|---|---|---|
| macOS 10.15+ | WKWebView | *As built:* a 36 pt `NSVisualEffectView` added as a **sibling** of the webview at the bottom of the window's content view (the webview's superview); the webview is shrunk by 36 pt once and autoresizing keeps the strip on every resize. The content view is not replaced and no `NSStackView` or SwiftUI is used: that would re-parent wry's `WryWebViewParent`. | `WKWebView.goBack`, `goForward`, `reload`; KVO on `canGoBack`, `canGoForward`, `loading`, `URL`; a forwarding navigation delegate reads the main-frame response type | *As built:* macOS 11.3+: `WKWebView.startDownload(using:)` with the bar's own `WKDownloadDelegate` (`path=webview`); the policy runs on the click, on every redirect and on the final URL. macOS 10.15–11.2: refetch through an ephemeral `URLSession` seeded with the webview's cookies from `WKHTTPCookieStore.getAllCookies` (`path=refetch`). Both routes request the URL again, so a POST result or a one-time link cannot be saved and is reported `unavailable` (§7.5). |
| Windows 10+ | WebView2 (via wry) | *As built:* a 36 dip child `HWND` that is a sibling of wry's `WRY_WEBVIEW` container, plus a `SetWindowSubclass` on the session window that, after wry's own `WM_SIZE` handling, shrinks the container and `controller.SetBounds` to the client area minus the bar, and again on `WM_DPICHANGED`. | `ICoreWebView2` `GoBack`, `GoForward`, `Reload`; `CanGoBack`/`CanGoForward` from the navigation and history events | *As built:* WebView2 has no API to save the current response, so the bar re-requests the shown URL itself (`path=refetch`): hyper over `rustls-platform-verifier` (platform TLS only, HTTP/1.1, no redirect followed, `Accept-Encoding: identity`, the webview's cookies for that URL). The policy runs on the click and again before connecting. Refused with `refetch_blocked` before any request when the session has TLS pins, an operator-accepted untrusted certificate, no TLS gate, proxy mode, a WebView2 browser-argument proxy or host-remapping switch, or any system proxy, PAC or auto-detect setting (WPAD-only proxies are not detectable). The `Zone.Identifier` stream is written on the staging file before the move; staging is `%LOCALAPPDATA%\.bastion_vault_gui\nav-download-staging`. Not used: `NavigateWithWebResourceRequest`, WinHttp requests. |
| Linux (GTK) | WebKitGTK | *As built:* a horizontal `GtkBox` (not a `GtkActionBar`, which Adwaita pads past 36 px) packed with `pack_end` into the vertical `GtkBox` wry already packed the webview into; nothing of wry's is moved. | `webkit_web_view_go_back/_forward/_reload`, `can_go_back/_forward` | *As built:* `webkit_web_view_download_uri` for the shown URL (WebKitGTK **re-requests**; same POST/one-time-token caveat), audited `path=refetch`. wry's context-wide `download-started` handler would also act on it, so the bar **claims** the `WebKitDownload` it started: its own `decide-destination` returns `TRUE` (wry's never runs), and `failed` / `finished` stop emission. Downloads WebKitGTK escalates by itself stay with wry. *Residual:* WebKitGTK has no redirect hook, so a 3xx to an origin outside the allow-list is requested (ephemeral per-window cookies of that origin only) and refused at `decide-destination`: no body is saved, audited `outside_allowlist`. The refuse-and-cancel path is unverified on WebKitGTK older than 2.40 (wry's floor is 2.38). |

The macOS 10.15–11.2 fallback and the WebKitGTK re-request path both lose
POST bodies and one-time tokens. A download the webview itself started
(`WKDownloadDelegate` on 11.3+, WebView2's `DownloadStarting`, WebKitGTK's
own `download-started`) uses the in-flight response and does not lose them;
the bar's button only takes that fast path when the current main-frame
navigation response is one the webview already escalated to a download —
otherwise it falls back to the re-request path and surfaces a status if it
fails.

*As built:* the in-flight-response fast path was not built. The bar's button
always requests the shown URL again (macOS 11.3+ through `startDownload`,
Linux through `download_uri`, Windows and macOS 10.15–11.2 through the bar's
own request), so a POST result or a one-time link is refused as `unavailable`
on every platform. Downloads the webview escalates by itself keep their
existing handling and audit lines.

Platform floor comes from `gui/src-tauri/tauri.conf.json:63` (macOS 10.15,
Windows 10, GTK 3.24).

## 7. Shape

### 7.1. Where the bar lives

A thin bar at the **bottom** of the session webview, as a native sibling of
the webview inside the window's content area:

- 36 px tall, full width, pinned to the bottom edge, resizes with the window.
  *As built:* the page keeps the profile's size: the default window is the
  profile height + 36 px (the chrome build: + 40 px toolbar + 36 px bar), and
  the chrome window has a minimum height of 76 px so the bars never overlap.
- The webview is laid out above it; the bar is not an overlay, it owns its
  own 36 px of real estate so page content underneath is **not** covered.
- Platform-native rendering: SF Symbols on macOS, Fluent icons on Windows,
  Adwaita icons on Linux — matches the OS the operator is already looking at.
  (Builder may pick an inline SVG set used identically on all three if
  consistency is preferred over platform-native feel.)
- Four buttons left-aligned, 44 × 36 px each: back, forward, reload, download.

### 7.2. Why a native sibling and not DOM injection

The motivating case is a PDF rendered inline by the webview. WKWebView
renders PDFs in `PDFKit`, which does not run user scripts; the equivalent
holds for WebKitGTK (`WebKitPDFPlugin`) and for WebView2's internal PDF
viewer. A DOM-injected bar would disappear exactly on the case that
motivated the feature. Native sibling views have no such hole.

Native siblings also sidestep the WebView2 isolated-world gap (WebView2 has
no page-isolated world), so the design does not have to accept a weaker
hostile-page guarantee on Windows than on macOS and Linux.

### 7.3. States

| Control | Enabled when |
|---|---|
| Back | `canGoBack` is true |
| Forward | `canGoForward` is true |
| Reload | always, except mid-reload |
| Download | the current main-frame response's content-type is in the downloadable set (§7.5) **or** it carried `Content-Disposition: attachment` **and** the profile's `allow_downloads` is true |

### 7.4. `allow_downloads`

The web profile already carries `allow_downloads` (default `false`;
gui/src-tauri/src/session/web.rs:528). The bar **honours it**. When the
profile forbids downloads the download button is rendered disabled with a
tooltip "Downloads disabled for this profile." The operator cannot override
it in-window — profiles are the control plane.

A profile that allows downloads still only enables the button for the
downloadable set (§7.5); HTML stays non-downloadable regardless.

### 7.5. Downloadable MIME set

Anything the browser cannot render inline as text, plus anything the server
flagged as attachment. In practice:

- `application/pdf`
- `application/zip`, `application/x-tar`, `application/gzip`,
  `application/x-7z-compressed`, `application/x-rar-compressed`
- `application/octet-stream` and `application/x-*`
- `image/*` except `image/svg+xml`
- `video/*`, `audio/*`
- `application/vnd.ms-*`,
  `application/vnd.openxmlformats-officedocument.*`,
  `application/vnd.oasis.opendocument.*`
- Any response with `Content-Disposition: attachment`

A page served as `text/html`, `text/plain`, `text/xml`,
`application/xhtml+xml` or `application/*+json/+xml` is **not** downloadable
from the bar even if browseable. (The server can still trigger a download
for any of these by sending `Content-Disposition: attachment`; the bar
honours that one case for HTML.)

Builder may extend the `application/vnd.*` list as long as `text/html` and
friends stay excluded.

### 7.6. Download mechanics and destination

Destination: `dirs::download_dir()` (already a dependency,
gui/src-tauri/Cargo.toml:55) with the OS fallback `$HOME/Downloads` and, on
Linux, a last-resort create of `$HOME/Downloads` when `XDG_DOWNLOAD_DIR` is
unset.

Filename:

1. The webview's suggested name (WKDownload / WebView2 `DownloadStarting` /
   WebKitDownload) when the download started through the webview itself.
2. Otherwise the `Content-Disposition` filename.
3. Otherwise the last URL path segment, URL-decoded.
4. Otherwise `download-YYYYMMDD-HHMMSS.bin`.

Sanitize (every source): strip path separators (`/`, `\`), zero bytes,
control characters (`\x00`–`\x1f`, `\x7f`); strip leading dots; **strip
trailing dots and spaces** (Windows); refuse Windows reserved stems
(`CON`, `PRN`, `AUX`, `NUL`, `COM0–9`, `LPT0–9`) by prefixing `_`; refuse
NTFS stream names (`:`) by replacing with `_`.

Collision handling: open with `O_CREAT|O_EXCL` (or `CREATE_NEW`) and, on
`EEXIST`, retry with ` (1)`, ` (2)`, … before the extension, up to 999.
After 999 the download reports "could not save, directory full of this
name" to the audit and the bar flashes a short-lived error state (no modal).

Rate limiting: at most 2 concurrent downloads per window; the third click
is a no-op with a tooltip. Soft cap at 2 GiB per download; above that the
operator is told via a short-lived error state and the download is
cancelled. Both limits are per window, per lifetime.

Mark-of-the-web: *As built:* `WKDownload` (macOS 11.3+) sets the quarantine
attribute as part of its own path. The Windows bar never goes through
WebView2's `DownloadStarting` (it re-requests), so the shim writes the
`Zone.Identifier` stream (zone 3) itself on the staging file, before the move
into Downloads. The macOS 10.15–11.2 refetch and the Linux download (which has
no MOTW mechanism) carry only what the OS applies. The audit line names which
path was taken (`path=webview` is written by the macOS bar only; the Linux and
Windows bars write `path=refetch`) so a reviewer can tell.

### 7.7. Phase 5 coexistence

The bottom bar ships in **every** build — default and `web_session_chrome`
— until Phase 5 absorbs back/forward/reload/download into its top toolbar.
The top toolbar and the bottom bar are **not** two homes for the same
controls at the same time: Phase 5 today has Disconnect / Re-run login /
lock state / countdown and no navigation, so the bottom bar fills the gap
in the `web_session_chrome` build as well.

When Phase 5 later grows its own back/forward/reload/download — a separate
change, not this one — that change removes the bottom bar from the
`web_session_chrome` build in the same commit (compile-time `cfg`, no
runtime switch). Until that happens, both are visible in the
`web_session_chrome` build; they do not duplicate each other.

### 7.8. Fill engine interaction

- Reload (G2) issues `webview.reload()`. The fill engine's URL-pattern-based
  step gate observes a reload as a new navigation and would, in principle,
  re-run a step whose `when_url` matches. The bar sets a one-shot flag on
  the session (`reloaded_by_operator`) that the fill engine's step-picker
  reads: when true for this URL, the next match is skipped and the flag is
  cleared. The fill engine still re-arms for subsequent URLs. (Verified by a
  test; §13 touches on this.)
- Back / forward (G1) do not touch the fill engine's state; the engine
  already ignores main-frame history traversals during its deadline window.
- The bar is attached in the session window's constructor, so controls are
  visible before the fill engine's first injected script runs (G5).

### 7.9. Proxy mode (Phase 6 / T106)

Nav and download work in proxy mode too. The webview's history, reload and
`startDownload` all go through the loopback CONNECT proxy the session set
up; the bar does not know and does not need to know whether the current
session is proxied. Downloads route through the proxy and still land in
`~/Downloads` via `RemotePolicy::on_download`.

## 8. Security

### 8.1. Isolation

The bar is a native sibling view with no DOM presence; a hostile page has no
API that reaches it. There is no bar-side script, no page-to-bar message
channel, no bar-to-page push.

### 8.2. What the bar does not see

- `document.cookie`
- any form field value
- the fill engine's state (except the one-shot `reloaded_by_operator` flag
  it sets, which carries no page data)
- the resource id, credential, token, launch id, actor identity (the bar's
  code reads only `canGoBack`, `canGoForward`, current main-frame URL mime,
  and `allow_downloads`)

### 8.3. Audit

Reuses the existing `connect.web.*` audit shape
(gui/src-tauri/src/commands/connect_web.rs:1603–1640). One line per bar
action:

- `connect.web.nav: resource=<id> token=<hash> action=back|forward|reload`
- `connect.web.download: resource=<id> token=<hash> filename=<basename> \
  mime=<type> bytes=<n> path=webview|refetch`
- *As built:* the `token` is the session's clear `sess_...` token, as in the
  existing `connect.web.*` lines; `filename` is logged quoted and escaped
  (`filename="x.pdf"`) with control characters dropped; and a refusal is
  `connect.web.download_refused: resource=<id> token=<tok> reason=<token>` with
  a fixed token (`outside_allowlist`, `downloads_disabled`, `size_exceeded`,
  `too_many_downloads`, `collision_exhausted`, `save_io_error`,
  `invalid_filename`, `unavailable`, `transfer_failed`, `refetch_blocked`).

URL path and query are never logged (existing discipline). `filename` is
the sanitized basename only, not a full path.

### 8.4. TLS pin / allow-list / proxy

All nav primitives go through the standard navigation path, so `TlsPinGate`,
the HTTP-auth handlers and the origin allow-list run exactly as a user click
does. Downloads reuse `RemotePolicy::on_download` (A6) — the same policy
and audit sink the webview's own download path uses — so a URL outside the
session's allow-list is refused before bytes are requested, and a pin
mismatch surfaces as it does today.

*As built:* the bar calls `web::download_decision` (the decision
`RemotePolicy::on_download` applies) itself, with the window's own origin set
and `allow_downloads`, on the click and again on the final URL. Where the bar
has to make the request itself (Windows, macOS 10.15–11.2) it cannot reuse the
webview's TLS exceptions: on Windows it fails closed (`refetch_blocked`) rather
than request around pins, an accepted certificate or a proxy the webview
follows. Linux has a redirect residual (§6). All three shims share one
download implementation, `session/web_nav_bar/transfer.rs`.

### 8.5. `unsafe` justifications

Each per-platform window-handle shim contains `unsafe` for the one FFI call
that reaches the native window object (`NSWindow*`, `HWND`, `GtkWindow*`).
Those lines carry a one-line SAFETY comment naming the invariant: the
handle is valid for the lifetime of the `tao::Window` the shim borrows.
`gui/src-tauri` has precedent for this pattern
(gui/src-tauri/src/commands/connect_web_tls_pin.rs:244–247, etc.).

## 9. Audit, metrics, telemetry

Only §8.3. No new metrics families.

## 10. Open to the builder

- Exact icon set: SF Symbols on mac, Fluent on Windows, Adwaita on Linux —
  **or** an inline SVG set used identically on all three. Builder's call;
  recommended inline SVG for pixel parity.
- Button hover / active / focus-visible treatment matching each OS.
- The exact `application/vnd.*` extension to §7.5, as long as the text/html
  exclusion holds.
- Whether to show a 3 px progress sliver under the download button during
  an in-flight download (recommended: yes).
- The "operator was told via a short-lived error state" affordance (toast,
  button flash, status glyph): builder's call.

## 11. Follow-ups (not in this change)

- Keyboard shortcuts (`Cmd/Ctrl + [`, `Cmd/Ctrl + ]`, `Cmd/Ctrl + R`,
  `Cmd/Ctrl + S` for download) via a native accelerator table per window.
- Phase 5 chrome absorbing nav/download into its top toolbar, with the
  same commit removing the bottom bar from `web_session_chrome` builds
  (§7.7).
- "Copy current URL" and "Open in Downloads folder" actions.
- A download cancel button for an in-flight long download.

## 12. Tracking (per AGENTS.md §8)

- Add a task row under `S105 Web Application Connect` in `ROADMAP.md`:
  `T<next> Give web session windows a native back/forward/reload/download
  bottom bar (macOS, Windows, Linux) honouring the profile's
  allow_downloads flag (S105)`.
- Add a `features/web-application-connect.md` row referencing this design
  under its own section "Session navigation bar (default build)" — or under
  Phase 5 if the Phase 5 maintainer prefers the two to merge. (The feature
  file's maintainer settles this during `writing-plans`.)
- Changelog entry under `[Unreleased]` → `### Added` when the task lands.

## 13. Size

Project (one design doc, three platform-specific shims, a cross-cutting
Rust orchestrator, audit lines, G5 and G6 tests). Hand off to
`writing-plans`.

## 14. Decisions I made on your behalf (builder-check settled)

- `dirs::download_dir()` for destination, OS fallbacks named in §7.6.
- Collision via `O_CREAT|O_EXCL` / `CREATE_NEW`, capped at 999.
- Windows reserved names and trailing dots/spaces in sanitising.
- Reuse `RemotePolicy::on_download` rather than a new download delegate;
  mandated by A6 and §8.3.
- Audit shape mirrors existing `connect.web.*` lines (filename=, mime=,
  bytes=), not the `url_hash=/dest=` the first draft used.
- Phase 5 coexistence: the bottom bar ships in every build (default and
  `web_session_chrome`) until a future Phase 5 change adds its own
  nav/download; that change removes the bottom bar from the
  `web_session_chrome` build in the same commit. No runtime switch, no
  double-chrome.
- Rate limits (2 concurrent, 2 GiB soft cap) are mine — set them where
  review wants, but they live in the design because an un-rate-limited
  download channel is a disk-fill vector.
- `reloaded_by_operator` one-shot flag to keep reload from re-triggering
  the fill engine (G5); the fill engine's step-picker is the natural reader.
- `unsafe` scope and SAFETY comment pattern mirrors the existing TLS pin
  shim.

## 15. As built / deviations

What differs from the design above (details and the manual verification
checklist are in the *Session navigation bar* section of
[features/web-application-connect.md](../../features/web-application-connect.md)):

- The platform-neutral download path was extracted into one shared module
  (`session/web_nav_bar/transfer.rs`, the plan's Task 2b) instead of three
  copies; the per-platform shims hold only layout and glue.
- Section 6 is corrected: no `NSStackView` / SwiftUI on macOS, no `GtkActionBar`
  on Linux, no `NavigateWithWebResourceRequest` / WinHttp request on Windows
  (the bar's own hyper request, with the `refetch_blocked` gate).
- The Windows refetch follows no redirect, uses platform TLS only, refuses
  non-identity `Content-Encoding` and writes `Zone.Identifier` before the move;
  it is often blocked in practice because auto-detect proxy settings are on by
  default on many machines.
- The Linux bar claims its own `WebKitDownload` and always audits `path=refetch`;
  the redirect residual (§6) is recorded, not closed.
- macOS refetch on 10.15–11.2 and `startDownload(using:)` on 11.3+ both request
  the URL again, so neither can save a POST result or a one-time link.
- The default window is 36 px taller than before so the page keeps the
  profile's size (§7.1).
- Audit: clear `sess_...` token, quoted `filename`, and a `download_refused`
  line with fixed reason tokens (§8.3).
- Not done: progress indicator, cancel button, reading WebView2 policy browser
  arguments. Nothing has run live; Windows msvc and Linux x86_64 were not
  compiled (gnu and arm64 were).
