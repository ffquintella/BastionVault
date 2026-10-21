# Web session navigation controls implementation plan

> Executed with deviations: Task 2b was added (the platform-neutral download path moved into a shared `transfer` module) and Windows and Linux got their own per-platform shims; the list is in the execution ledger. As built, see "Session navigation bar (T459)" in [features/web-application-connect.md](../../features/web-application-connect.md).

> For agents: use `subagent-driven-development` (recommended) or
> `executing-plans` to implement this plan task by task. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** Give every web Connect session window a native 36 px bottom bar
with back / forward / reload / download, on macOS, Windows and Linux,
honouring the profile's `allow_downloads` flag.

**Architecture:** A new `gui/src-tauri/src/session/web_nav_bar.rs` holds the
cross-platform orchestrator (state, action enum, trait object the platform
shim implements). Three per-platform modules under
`gui/src-tauri/src/session/web_nav_bar/` (`macos.rs`, `windows.rs`,
`linux.rs`) attach the bar as a native sibling of the webview by reaching
the raw window handle `tao` already exposes. Downloads reuse the existing
`RemotePolicy::on_download` sink (gui/src-tauri/src/commands/connect_web.rs:1596).
The bar is wired into `build_window` for both the default and
`web_session_chrome` builds (gui/src-tauri/src/commands/connect_web.rs:1724
and :1755).

**Tech stack:** Rust, Tauri 2, wry 0.55.1, tao, objc2 + security-framework
on macOS, windows-sys / webview2-com on Windows, gtk + webkit2gtk on Linux.
`raw-window-handle` is already in the dependency graph via tao.

**Spec:** [docs/specs/2026-10-20-web-session-nav-controls-design.md](../specs/2026-10-20-web-session-nav-controls-design.md).

## Global constraints

- Platform floor: macOS 10.15, Windows 10, GTK 3.24
  (gui/src-tauri/tauri.conf.json:63). WKDownload needs macOS 11.3; the macOS
  shim detects at runtime and falls back to the URLSession path on
  10.15–11.2.
- Do not touch `TlsPinGate`, HTTP-auth handlers, the navigation allow-list,
  or the fill engine's own state. Reuse `RemotePolicy::on_download`.
- Do not enable Tauri's `unstable` feature. Platform shims use raw window
  handles; the bar is not a webview.
- Downloads land in `dirs::download_dir()` with `$HOME/Downloads` fallback;
  Linux falls back to `$HOME/Downloads` when `XDG_DOWNLOAD_DIR` is unset
  and creates it on first use.
- Filename sanitising: strip path separators (`/`, `\`), zero bytes,
  control chars (`\x00–\x1f`, `\x7f`), leading dots, trailing dots and
  spaces; `_`-prefix Windows reserved stems (CON, PRN, AUX, NUL, COM0–9,
  LPT0–9); `_`-replace `:` (NTFS streams).
- Collision policy: `O_CREAT|O_EXCL` (or `CREATE_NEW`); append ` (n)`
  before extension for `n` in 1..=999; report "directory full of this name"
  past that.
- Rate limits (per window, per lifetime): max 2 concurrent downloads;
  2 GiB soft cap per download.
- Downloadable MIME set: `application/pdf`, `application/zip`,
  `application/x-{tar,7z-compressed,rar-compressed}`, `application/gzip`,
  `application/octet-stream`, `application/x-*`, `image/*` **except**
  `image/svg+xml`, `video/*`, `audio/*`, `application/vnd.ms-*`,
  `application/vnd.openxmlformats-officedocument.*`,
  `application/vnd.oasis.opendocument.*`, plus anything with
  `Content-Disposition: attachment`. HTML/text excluded even when
  browseable.
- `allow_downloads` false → download button rendered disabled with tooltip
  "Downloads disabled for this profile." No in-window override.
- Phase 5 coexistence: bar ships in both default and `web_session_chrome`
  builds. A later Phase 5 change removes it from the chrome build in the
  same commit that adds its own nav controls.
- Audit shape matches `connect.web.*` existing lines
  (gui/src-tauri/src/commands/connect_web.rs:1603–1640): `filename=` not
  `dest=`, no URL path/query.
- Proxy mode (Phase 6 / T106) requires no bar-side work: the bar talks to
  the webview, the webview is proxied transparently, so history / reload /
  download URLs flow through the same loopback CONNECT and still hit
  `RemotePolicy::on_download`. Task 7's wiring applies to both proxied and
  non-proxied sessions unchanged.
- Per AGENTS.md §7: every `unsafe` block names its invariant on one line.
- Per AGENTS.md §8: add a `T<next>` row under `S105` in `ROADMAP.md` and a
  `### Added` CHANGELOG entry under `[Unreleased]` ending with the task id
  group, in the same commit as the work's final task.

## Review focus

- **Download during an in-flight navigation.** Clicking download while the
  main frame is still loading today would race `RemotePolicy::on_download`.
  Expected: ignored with a one-shot "loading, retry" state. Pinned by
  `test_download_button_disabled_while_loading` in **Task 1**.
- **Reload during active fill.** G5. Expected: `webview.reload()` fires, but
  the next matched step is skipped (operator-initiated reload). Pinned by
  `test_reload_sets_operator_flag_and_fill_skips_next_step` in **Task 6**.
- **Hostile page tries to remove or cover the bar.** Native sibling has no
  DOM presence; a page script cannot reach the bar area. Pinned by
  `test_bar_is_not_a_dom_node` (shim-level: assert no `WKUserScript` /
  WebView2 `AddScriptToExecuteOnDocumentCreatedAsync` /
  `UserContentManager::add_script` is registered by the bar module) in
  **Tasks 2, 3, 4**.
- **Download URL outside the session's allow-list.** Expected: refused by
  `RemotePolicy::on_download` before bytes are requested; audit line names
  the refusal. Pinned by `test_download_outside_allowlist_refused` in
  **Task 7**.
- **Filename collision in `~/Downloads` past 999 copies.** Expected: no
  overwrite; audit says `collision_exhausted`; bar flashes error.
  Pinned by `test_collision_exhausted_at_999` in **Task 1**.

---

### Task 1: cross-platform orchestrator and shared types

**Tier:** complex (architect) — the trait, the state machine, the audit
lines and the test harness that every platform shim will build against.

**Files:**
- Create: `gui/src-tauri/src/session/web_nav_bar.rs`
- Create: `gui/src-tauri/src/session/web_nav_bar/mod.rs` (declares the
  three platform submodules behind `#[cfg(target_os = "…")]`)
- Create: `gui/src-tauri/src/session/web_nav_bar/filename.rs` (sanitiser
  and collision helpers, pure Rust, testable without a webview)
- Modify: `gui/src-tauri/src/session/mod.rs` (add `pub mod web_nav_bar;`)
- Test: in-crate `#[cfg(test)]` at the bottom of `web_nav_bar.rs` and
  `filename.rs`

**Interfaces produced:**

```rust
pub enum NavAction { Back, Forward, Reload, Download }

pub struct NavState {
    pub can_go_back: bool,
    pub can_go_forward: bool,
    pub is_loading: bool,
    pub current_mime: Option<String>,
    pub content_disposition_attachment: bool,
    pub allow_downloads: bool,
}

impl NavState {
    pub fn download_enabled(&self) -> bool { /* §7.3, §7.4, §7.5 */ }
}

pub trait NavBar: Send {
    fn set_state(&self, state: &NavState);
    fn detach(self: Box<Self>);
}

pub struct NavBarAudit {
    pub app: tauri::AppHandle,
    pub resource: String,
    pub token: String,
}
impl NavBarAudit {
    pub fn nav(&self, action: NavAction);
    pub fn download_ok(&self, filename: &str, mime: &str, bytes: u64, path: DownloadPath);
    pub fn download_refused(&self, reason: &'static str);
}
pub enum DownloadPath { Webview, Refetch }

pub struct DownloadLimiter { /* 2 concurrent, 2 GiB soft cap */ }

pub fn sanitize_filename(raw: &str) -> String; // filename.rs
pub fn next_free_path(dir: &Path, name: &str) -> Result<PathBuf, CollisionExhausted>;
pub struct CollisionExhausted;

/// The one-shot flag set by Reload so the fill engine's step-picker
/// skips the next matching step on this URL.
pub fn mark_operator_reload(shared: &web::WebShared);
pub fn take_operator_reload(shared: &web::WebShared) -> bool;
```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn download_enabled_requires_allow_and_downloadable_mime() { /* §7.3 */ }
#[test] fn download_enabled_honours_attachment_disposition_for_html() { /* §7.5 */ }
#[test] fn download_disabled_for_text_html_without_attachment() { /* §7.5 */ }
#[test] fn sanitize_strips_separators_and_controls() { /* §Global */ }
#[test] fn sanitize_prefixes_windows_reserved_stems() { /* CON, LPT1 → _CON, _LPT1 */ }
#[test] fn sanitize_strips_trailing_dots_and_spaces() { /* "x.pdf. " → "x.pdf" */ }
#[test] fn next_free_path_returns_input_on_empty_dir() { /* new tempdir */ }
#[test] fn next_free_path_appends_n_before_extension() { /* "a.pdf" exists → "a (1).pdf" */ }
#[test] fn test_collision_exhausted_at_999() { /* 1000 copies → Err(CollisionExhausted) */ }
#[test] fn limiter_rejects_third_concurrent_download() {}
#[test] fn limiter_cancels_download_past_2_gib() {}
#[test] fn operator_reload_flag_is_one_shot() { /* mark → take=true → take=false */ }
#[test] fn test_download_button_disabled_while_loading() {
    let s = NavState { is_loading: true, allow_downloads: true,
        current_mime: Some("application/pdf".into()), ..default() };
    assert!(!s.download_enabled());
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement the signatures above**

The state transitions follow §7.3/§7.4/§7.5 exactly. `next_free_path`
uses `OpenOptions::new().write(true).create_new(true).open(...)` to try
each candidate, closing on success without writing bytes (the caller
re-opens for writing). `DownloadLimiter` is an `AtomicU8` counter plus a
per-download byte accumulator; the 2 GiB cap is checked incrementally in
the shim's download delegate (shim calls `limiter.record(n)` on every
chunk; `Err(SizeExceeded)` cancels).

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar`
Expected: PASS, all 13 tests.

- [ ] **Step 5: Commit**

```bash
git add gui/src-tauri/src/session/web_nav_bar.rs \
        gui/src-tauri/src/session/web_nav_bar/ \
        gui/src-tauri/src/session/mod.rs
git commit -m "feat(gui): web session nav bar orchestrator and filename rules"
```

---

### Task 2: macOS platform shim

**Tier:** complex (architect) — unsafe FFI into AppKit and WebKit; §7.6
URLSession fallback for macOS 10.15–11.2.

**Files:**
- Create: `gui/src-tauri/src/session/web_nav_bar/macos.rs`
- Modify: `gui/src-tauri/src/session/web_nav_bar/mod.rs` (declare
  `#[cfg(target_os = "macos")] pub mod macos;`)
- Test: `#[cfg(test)]` at the bottom (unit tests for mime classifier only;
  the UI path needs a running NSApp)

**Interfaces consumed:** `NavAction`, `NavState`, `NavBar`, `NavBarAudit`,
`DownloadLimiter`, `sanitize_filename`, `next_free_path`,
`mark_operator_reload` from Task 1. `RemotePolicy::on_download` from
`gui/src-tauri/src/commands/connect_web.rs:1596`.

**Interfaces produced:**

```rust
pub fn attach(
    ns_window: *mut objc2_app_kit::NSWindow,
    webview: &wry::WebView,
    allow_downloads: bool,
    origins: Arc<OriginSet>,
    audit: NavBarAudit,
    on_download: Box<dyn Fn(DownloadRequest) -> DownloadVerdict + Send + Sync>,
    shared: Arc<WebShared>,
) -> Box<dyn NavBar>;
```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn mime_pdf_is_downloadable() {}
#[test] fn mime_text_html_is_not_downloadable_without_attachment() {}
#[test] fn mime_image_svg_xml_is_not_downloadable() {}
#[test] fn test_bar_is_not_a_dom_node() {
    // compile-time assertion: this module imports no WKUserScript APIs
    // (grep in build.rs or a static-asserts crate check).
    assert!(!module_source().contains("WKUserScript"));
    assert!(!module_source().contains("addUserScript"));
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::macos`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement `attach` in `macos.rs`**

Pattern mirrors
`gui/src-tauri/src/commands/connect_web_tls_pin.rs:244–247` for safe `objc2`
usage. Steps:

1. Fetch the window's existing `contentView` (SAFETY: `ns_window` is
   valid for the Tauri `WebviewWindow`'s lifetime, which outlives the
   bar).
2. Build an `NSStackView` (orientation vertical, distribution fill), set
   it as the new `contentView`, add the former content (webview) and a
   36 px `NSView` bar below.
3. The bar is an `NSStackView` horizontal of four `NSButton`s with SF
   Symbols (`chevron.left`, `chevron.right`, `arrow.clockwise`,
   `square.and.arrow.down`). Each button's action calls a tiny ObjC
   target that routes to the Rust `NavAction` handler.
4. KVO on `canGoBack`, `canGoForward`, `loading`, and on the main
   frame's `URL` + `MIMEType` (read from the current
   `WKNavigationResponse` in the navigation delegate; coordinate with
   the existing navigation delegate in `web.rs`).
5. Download:
   - macOS 11.3+ (runtime check via `NSProcessInfo.operatingSystemVersion`):
     `WKWebView.startDownload(using:)` + a `WKDownloadDelegate` whose
     `download(_:decideDestinationUsing:suggestedFilename:)` calls
     `on_download`, `sanitize_filename`, `next_free_path`,
     `limiter.record` on each chunk via `download(_:didWriteData:…)`.
   - macOS 10.15–11.2 (fallback): read cookies via
     `WKHTTPCookieStore.getAllCookies`, make an `URLSession` with those
     cookies, `downloadTask(with: URLRequest(url:))`, feed through the
     same `on_download` + sanitize + limiter path. Audit records
     `path=refetch`.
6. Reload button calls `mark_operator_reload(&shared)` then
   `webview.reload()`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::macos`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add gui/src-tauri/src/session/web_nav_bar/macos.rs \
        gui/src-tauri/src/session/web_nav_bar/mod.rs
git commit -m "feat(gui): web session nav bar — macOS shim"
```

---

### Task 3: Windows platform shim

**Tier:** complex (architect) — HWND reparenting and WebView2 download
plumbing.

**Files:**
- Create: `gui/src-tauri/src/session/web_nav_bar/windows.rs`
- Modify: `gui/src-tauri/src/session/web_nav_bar/mod.rs` (declare
  `#[cfg(target_os = "windows")] pub mod windows;`)
- Test: `#[cfg(test)]` at the bottom (mime classifier reuse + the
  no-DOM-script static check).

**Interfaces consumed:** same as Task 2.

**Interfaces produced:**

```rust
pub fn attach(
    hwnd: windows::Win32::Foundation::HWND,
    webview: &wry::WebView,
    allow_downloads: bool,
    origins: Arc<OriginSet>,
    audit: NavBarAudit,
    on_download: Box<dyn Fn(DownloadRequest) -> DownloadVerdict + Send + Sync>,
    shared: Arc<WebShared>,
) -> Box<dyn NavBar>;
```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn test_bar_is_not_a_dom_node() {
    assert!(!module_source().contains("AddScriptToExecuteOnDocumentCreated"));
    assert!(!module_source().contains("web_resource_request_filter"));
}
```

(mime tests are the same set as Task 2, imported from the shared module.)

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::windows`
Expected: FAIL.

- [ ] **Step 3: Implement `attach` in `windows.rs`**

Steps:

1. Create a child `HWND` for the bar with `WS_CHILD | WS_VISIBLE`,
   36 px tall, pinned to the bottom. Hook the parent's `WM_SIZE` to
   resize the webview above it and the bar below. (SAFETY: `hwnd` is
   valid for the Tauri window's lifetime; the subclass is removed on
   `detach`.)
2. Place four `BUTTON`-class Win32 controls with Fluent / Segoe MDL2
   glyphs; command IDs 0x8001..0x8004 for the four actions.
3. State: subscribe to `CoreWebView2.HistoryChanged` for
   `CanGoBack/CanGoForward`, to `NavigationCompleted` for `is_loading`,
   and track the latest main-frame response's `Content-Type` and
   `Content-Disposition` from `WebResourceResponseReceived`.
4. Download:
   - For a download the webview itself detected: hook
     `CoreWebView2.DownloadStarting`, set the destination via
     `args.ResultFilePath = next_free_path(...)`, feed progress to the
     limiter. Audit `path=webview`.
   - For a bar-click download (webview did not auto-detect): issue
     a GET through `winhttp` using the webview's cookies
     (`CoreWebView2CookieManager.GetCookies`), stream through the
     limiter, sanitize + collision-check filename, write to disk,
     refuse via `RemotePolicy::on_download` first. Audit
     `path=refetch`.
5. Reload: `mark_operator_reload(&shared)` then `webview.reload()`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::windows`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add gui/src-tauri/src/session/web_nav_bar/windows.rs \
        gui/src-tauri/src/session/web_nav_bar/mod.rs
git commit -m "feat(gui): web session nav bar — Windows shim"
```

---

### Task 4: Linux platform shim

**Tier:** complex (architect) — GTK box reparenting and WebKitGTK download
delegate.

**Files:**
- Create: `gui/src-tauri/src/session/web_nav_bar/linux.rs`
- Modify: `gui/src-tauri/src/session/web_nav_bar/mod.rs` (declare
  `#[cfg(target_os = "linux")] pub mod linux;`)
- Test: `#[cfg(test)]` at the bottom (mime + no-user-script check).

**Interfaces consumed:** same as Task 2.

**Interfaces produced:**

```rust
pub fn attach(
    gtk_window: *mut gtk::ffi::GtkWindow,
    webview: &wry::WebView,
    allow_downloads: bool,
    origins: Arc<OriginSet>,
    audit: NavBarAudit,
    on_download: Box<dyn Fn(DownloadRequest) -> DownloadVerdict + Send + Sync>,
    shared: Arc<WebShared>,
) -> Box<dyn NavBar>;
```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn test_bar_is_not_a_dom_node() {
    assert!(!module_source().contains("UserContentManager"));
    assert!(!module_source().contains("add_script"));
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::linux`
Expected: FAIL.

- [ ] **Step 3: Implement `attach` in `linux.rs`**

Steps:

1. The `GtkWindow`'s existing child is the webview packed into a
   `GtkBox`. Replace with a vertical `GtkBox` holding the webview
   (expand) and a `GtkActionBar` at the bottom (fixed 36 px). (SAFETY:
   `gtk_window` is valid for the Tauri window's lifetime.)
2. Four `GtkButton`s with Adwaita icon names
   (`go-previous-symbolic`, `go-next-symbolic`, `view-refresh-symbolic`,
   `document-save-symbolic`), connected to signal handlers that fire
   the `NavAction`.
3. State: `connect_notify_estimated_load_progress`,
   `connect_notify_uri`, main-frame response via
   `connect_resource_load_started` + `response_received` to capture
   `Content-Type` and `Content-Disposition`.
4. Download:
   - `webkit_web_view_download_uri` is a re-request path (audit
     `path=refetch`), filtered through `on_download` first; the resulting
     `WebKitDownload` gets `connect_decide_destination` →
     `set_destination(file:// next_free_path)` and
     `connect_received_data` → `limiter.record`.
   - For a download the webview escalates on its own (`download-started`
     signal before the response completes), take that `WebKitDownload`
     over and audit `path=webview`.
5. XDG fallback: at `attach` time, call `dirs::download_dir()`; if
   `None`, `std::fs::create_dir_all("$HOME/Downloads")` and use that.
6. Reload: `mark_operator_reload(&shared)` then
   `webkit_web_view_reload(view)`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::linux`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add gui/src-tauri/src/session/web_nav_bar/linux.rs \
        gui/src-tauri/src/session/web_nav_bar/mod.rs
git commit -m "feat(gui): web session nav bar — Linux shim"
```

---

### Task 5: audit lines

**Tier:** routine (builder) — two log formats, one module, pattern copied
from existing `connect.web.*` emitters.

**Files:**
- Modify: `gui/src-tauri/src/session/web_nav_bar.rs` (implement
  `NavBarAudit::nav` and `::download_ok` / `::download_refused`)
- Test: in-crate `#[cfg(test)]` capturing `log` records with a test logger

**Interfaces consumed:** `NavBarAudit`, `NavAction`, `DownloadPath` from
Task 1.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn nav_audit_line_matches_connect_web_shape() {
    // expected: "connect.web.nav: resource=R token=T action=reload"
}
#[test] fn download_ok_audit_omits_url_path_and_query() {
    // input URL "https://x/path?q=1"; assert the line contains neither "path" nor "q=1".
}
#[test] fn download_refused_audit_names_reason() {
    // expected: "connect.web.download_refused: resource=R token=T reason=outside_allowlist"
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::audit`
Expected: FAIL.

- [ ] **Step 3: Implement the three audit emitters**

Follow the pattern at
`gui/src-tauri/src/session/web_tls_pin.rs:242–258`: `log::warn!(target: "audit", "connect.web.nav: resource={} token={} action={}", resource, token, action)`.
Enum `NavAction::as_str()` returns `"back" | "forward" | "reload"`.
Download does not include URL path or query — only `filename=<basename>`,
`mime=<type>`, `bytes=<n>`, `path=webview|refetch`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo nextest run -p bastion-vault-gui --lib web_nav_bar::audit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add gui/src-tauri/src/session/web_nav_bar.rs
git commit -m "feat(gui): audit lines for web session nav bar actions"
```

---

### Task 6: fill-engine reload interaction (G5)

**Tier:** routine (builder) — one flag on `WebShared`, one read in the
step-picker.

**Files:**
- Modify: `gui/src-tauri/src/session/web.rs` (add
  `operator_reload: AtomicBool` to `WebShared`; implement
  `web_nav_bar::mark_operator_reload` and `::take_operator_reload`)
- Modify: `gui/src-tauri/src/session/web_engine.rs:737` (step-picker reads
  and clears the flag before matching)
- Test: new `#[cfg(test)]` in `web_engine.rs`

**Interfaces consumed:** `WebShared` from `web.rs`; the step iterator in
`web_engine.rs:737`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn test_reload_sets_operator_flag_and_fill_skips_next_step() {
    let shared = Arc::new(WebShared::new_for_test());
    let plan = test_plan_with_two_steps();
    let mut report = plan.empty_report();
    // Before the flag: first step is picked.
    assert_eq!(pick_next_step(&shared, &plan, &mut report, &url("/doku.php?id=start&do=login")), Some(0));
    // After operator reload: next matching step is skipped.
    web_nav_bar::mark_operator_reload(&shared);
    assert_eq!(pick_next_step(&shared, &plan, &mut report, &url("/doku.php?id=start&do=login")), None);
    // Flag is one-shot: a later navigation matches again.
    assert_eq!(pick_next_step(&shared, &plan, &mut report, &url("/doku.php?id=start&do=login")), Some(0));
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `cargo nextest run -p bastion-vault-gui --lib test_reload_sets_operator_flag`
Expected: FAIL.

- [ ] **Step 3: Implement**

Add `pub(crate) operator_reload: AtomicBool` to `WebShared` (initialized
false). `mark_operator_reload` does
`shared.operator_reload.store(true, SeqCst)`. `take_operator_reload` does
`shared.operator_reload.swap(false, SeqCst)`. In `web_engine.rs:737` the
step-picker calls `take_operator_reload(shared)` first — if true, skip
the current URL's match once and return `None`.

- [ ] **Step 4: Run the test and confirm it passes**

Run: `cargo nextest run -p bastion-vault-gui --lib test_reload_sets_operator_flag`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add gui/src-tauri/src/session/web.rs gui/src-tauri/src/session/web_engine.rs
git commit -m "feat(gui): operator reload bypasses fill engine for one match"
```

---

### Task 7: wire the bar into `build_window`

**Tier:** complex (architect) — the composition root; touches both default
and `web_session_chrome` build paths; owns the allow-list enforcement
hook-up.

**Files:**
- Modify: `gui/src-tauri/src/commands/connect_web.rs:1702–1781` (attach
  the bar after `builder.build()` in both branches)
- Modify: `gui/src-tauri/src/commands/connect_web_chrome.rs` (surface the
  underlying `tauri::Window` so the bar can reach its raw handle)
- Test: integration test in `src/engine_tests/` (needs `test_utils`)
  **and** a unit test for allow-list refusal in the orchestrator

**Interfaces consumed:** `web_nav_bar::macos::attach` /
`windows::attach` / `linux::attach` from Tasks 2–4; `NavBarAudit`,
`DownloadLimiter` from Task 1; `RemotePolicy::on_download` from
`connect_web.rs:1596`; `WebShared` from `web.rs`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn test_download_outside_allowlist_refused() {
    let origins = OriginSet::from(["https://km.esi.fgv.br"]);
    let policy_hook = RemotePolicy::test_hook(&origins);
    let download = make_download_request("https://evil.example/x.pdf");
    let verdict = policy_hook(download);
    assert_eq!(verdict, DownloadVerdict::Refused);
    assert_last_audit_contains("reason=outside_allowlist");
}

// src/engine_tests/web_nav_bar_wiring.rs
#[tokio::test]
async fn test_bar_attached_in_default_build() { /* spawn window; assert handle non-null */ }
#[tokio::test]
#[cfg(feature = "web_session_chrome")]
async fn test_bar_attached_in_chrome_build() { /* same, chrome branch */ }
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cargo nextest run -p bastion_vault --lib web_nav_bar_wiring`
Expected: FAIL.

- [ ] **Step 3: Wire the bar in both branches**

Right after `builder.build()` in `connect_web.rs:1750` and after
`build_chrome_window` in :1778, obtain the raw window handle via
`win.window().raw_window_handle()?`, dispatch to the per-OS
`web_nav_bar::<os>::attach`, store the returned `Box<dyn NavBar>` on
`SessionWindow` (new field `nav_bar`), and arrange for `detach` on
window close via the existing close guard.

The `on_download` callback the bar receives is a thin wrapper that calls
`policy.on_download(cfg.allow_downloads)` for policy + audit sink; the
bar does not call `RemotePolicy` directly.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `cargo nextest run -p bastion_vault --lib web_nav_bar_wiring`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add gui/src-tauri/src/commands/connect_web.rs \
        gui/src-tauri/src/commands/connect_web_chrome.rs \
        src/engine_tests/web_nav_bar_wiring.rs
git commit -m "feat(gui): attach nav bar in default and chrome build paths"
```

---

### Task 8: tracking and changelog

**Tier:** routine (builder) — AGENTS.md §8 bookkeeping.

**Files:**
- Modify: `ROADMAP.md` (add `T<next>` row under `S105`)
- Modify: `CHANGELOG.md` (add `### Added` entry under `[Unreleased]`)
- Modify: `features/web-application-connect.md` (append one subsection
  "Session navigation bar (default + chrome build until Phase 5 absorbs)"
  pointing at the spec and marking Phase 5 the owner of the eventual
  consolidation)

**Interfaces consumed:** none.

- [ ] **Step 1: Verify PTF invariants hold now**

Run: `grep -n "^- \[" ROADMAP.md | tail -5` and read the task-id of the
latest row under `S105`; the new task is `T<that + 1>`.

- [ ] **Step 2: Edit ROADMAP.md**

Add under `S105 Web Application Connect` (keep the list format the
section already uses):

```
- [ ] T<n> Give web session windows a native back/forward/reload/download
  bottom bar on macOS, Windows and Linux, honouring the profile's
  allow_downloads flag (S105)
```

- [ ] **Step 3: Edit CHANGELOG.md**

Under `[Unreleased]` → `### Added`:

```
- **Give web session windows a native back/forward/reload/download bottom
  bar on macOS, Windows and Linux, honouring the profile's allow_downloads
  flag.** (T<n>, S105)
```

- [ ] **Step 4: Edit features/web-application-connect.md**

Append a short "Session navigation bar" subsection naming the spec file
and saying the bar ships in both builds until Phase 5 absorbs the
controls.

- [ ] **Step 5: Verify PTF invariants still hold**

Run (manually): PTF003 — the new T<n> is referenced from the changelog;
PTF004 — no `[x]` for T<n> yet (it is `[ ]`).

- [ ] **Step 6: Commit**

```bash
git add ROADMAP.md CHANGELOG.md features/web-application-connect.md
git commit -m "docs: track T<n> web session nav bar under S105"
```
