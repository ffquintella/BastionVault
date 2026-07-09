# Plugin App Extensions Roadmap (Extensibility v2)

**Status:** In progress — Phases 1–3 complete
**Owner:** Felipe Quintella
**Spec:** [`features/plugin-app-extensions.md`](../features/plugin-app-extensions.md) — read that first; this doc is phasing, effort, and acceptance bars only.
**Related:** [`features/plugin-extensibility.md`](../features/plugin-extensibility.md) (v1, shipped), [`features/plugin-system.md`](../features/plugin-system.md), [`features/plugin-testing.md`](../features/plugin-testing.md).

---

## 1. Motivation (delta over v1)

Extensibility v1 shipped declarative surfaces (menus/pages/forms from `surface.json`) and zero-capability form hooks. Three classes of plugin remain unbuildable:

1. **Stateful UX** — menus/badges that reflect server state ("3 pending approvals"), wizard flows in their own window.
2. **Client-driven API composition** — an app module that chains several mount reads and derives a view, instead of one binding per component.
3. **Outbound integrations** — webhook notifiers, status-page pushers — today only possible via process-runtime server plugins with *unconstrained OS egress* (the `allowed_hosts` manifest field is validated but unenforced; `src/plugins/process_runtime.rs` says so explicitly).

v2 adds a programmatic app-module layer with four capability families — dynamic menus, windows, vault-API, network — where network is double-gated: **manifest flag + explicit admin grant at install**.

## 2. Ground rules

- App modules run in the Tauri-backend Wasmtime sandbox (extension of `gui/src-tauri/src/plugin_hooks.rs`), never the webview. No DOM, no plugin JS.
- The `bvx.*` import set is the capability boundary; each import gates host-side per call (the `src/plugins/runtime.rs` pattern).
- Server ACLs remain the sole authority for vault data; `api_paths` is scoping, not the boundary.
- Every new capability field participates in `PluginCatalog::check_capability_widening`.

## 3. Phases

Each phase ships independently and leaves the system working.

### Phase 0 — Spec ratification (done with this commit pair)

Land `features/plugin-app-extensions.md` + this roadmap. Decide the ABI story: manifests using `capabilities.app` declare `abi_version = "1.1"`; bump `HOST_ABI_MINOR` to 1 when Phase 1 lands (older hosts refuse cleanly via `check_abi_compatibility`).

**Acceptance:** docs merged; roadmap.md row added.

### Phase 1 — Server: manifest + grants (1–1.5 weeks) — ✅ Complete

Shipped: `AppCapabilities { dynamic_menus, windows, api_paths, net }` under
`Capabilities.app` (all `serde(default)`, omitted from the canonical signing
message when default so v1 signatures survive); registration validation
(`api_paths` mount-scoped, `net.hosts` through the shared host-pattern rule,
`windows.max_open ≤ 4`, one `app-module` asset); widening-guard entries for every
`app` field; `HOST_ABI_MINOR = 1`; `src/plugins/grants.rs` (net-grant record at
`core/plugins/engine/grants/<name>`, `capability_sha256` pin, superset refusal,
`active_net_hosts` live-gate); `GET/PUT/DELETE /v1/sys/plugins/<name>/grants`
(admin ACL, audited via `emit_sys_audit`); grant hosts shipped in
`ActiveSurfaceEntry.grant` and folded into the bundle ETag. Tests: manifest
validation, surface ETag, grant round-trip/pinning/superset, catalog app-field
widening, and the register→grant→re-register-with-changed-net→invalidated
acceptance path.



- `bv-plugin-manifest`: `AppCapabilities { dynamic_menus, windows, api_paths, net }` under `Capabilities.app` (all `serde(default)`); validation (api_paths must start `{mount}`, net hosts through the `validate_net_allowlist` rules); `HOST_ABI_MINOR = 1`.
- `catalog.rs`: widening-guard entries for every `app` field; `client_assets.kind == "app-module"` uniqueness check.
- New `src/plugins/grants.rs`: grant record at `core/plugins/engine/grants/<name>`, `capability_sha256` pinning, `GET/PUT/DELETE /v1/sys/plugins/<name>/grants` (admin ACL), refusal of superset grants.
- Audit events `plugin.grant.net.approved` / `plugin.grant.net.revoked`.
- Grant hosts included in `ActiveSurfaceEntry` (new optional field, `serde(default)` so v1 clients ignore it).

**Acceptance:** unit tests for parse/validate/widening/pinning; integration test drives register → grant → re-register-with-changed-net → grant invalidated.

### Phase 2 — App-module runtime + dynamic menus (1.5–2 weeks) — ✅ Complete

Shipped: `gui/src-tauri/src/plugin_apps.rs` — a stateful per-plugin Wasmtime
instance (lazy create on bundle sync, teardown on sign-out/vault-switch/seal/
surface-update), the `bvx.log`/`now_unix_ms`/`set_result` imports, per-call
refuel, and the `bvx_init`/`bvx_menu_click`/`bvx_window_event`/`bvx_tick` entry
contract. `bvx.menu_upsert`/`menu_remove` with `SurfaceMenu`-shape + section +
route-prefix validation and the 16-entry cap; the merged dynamic-menu set is
pushed on the `plugin-menus-updated` Tauri event and merged in
`pluginSurfacesStore.menusForSection`; `PluginMenuSlot` renders them (with an
optional `badge`) identically to static menus and fires `plugin_app_menu_click`
→ `bvx_menu_click`. Operator state via `plugin_app_status`. A module importing an
unregistered `bvx.*` symbol fails to instantiate (acceptance invariant).

Original scope (all delivered):
- `gui/src-tauri/src/plugin_apps.rs`: per-(plugin, version) instance lifecycle (lazy create, teardown on sign-out/vault-switch/surface-update), `bvx.log`, `bvx.now_unix_ms`, `bvx.set_result`, `bvx_init` export contract, per-call refuel.
- `bvx.menu_upsert` / `bvx.menu_remove` with `SurfaceMenu`-shape validation + 16-entry cap; Tauri event `plugin-menus-updated`; `pluginSurfacesStore` merges dynamic menus; `bvx_menu_click` dispatch.
- Operator UX: instance state via `plugin_app_status` (running / errored / menu count).

**Acceptance (met):** WAT module adds a badge menu on init, a click reaches `bvx_menu_click`, teardown clears the menus; a module importing an undeclared `bvx.*` symbol fails instantiation.

### Phase 3 — Plugin windows (1–1.5 weeks) — ✅ Complete

Shipped: `plugin-*` window labels in `capabilities/default.json`;
`bvx.window_open`/`close`/`emit` recording ops applied host-side on the SSH/RDP
`WebviewWindowBuilder` pattern (route constrained to `/plugin/<name>/`,
`max_open` clamp → `WINDOW_LIMIT`, host-drawn `"<plugin> — "` title);
`CloseRequested` → `bvx_window_event {kind:"closed"}`; `SurfaceRouter` renders
plugin windows bare (no host chrome) when `?pluginWindow=<handle>` is present,
behind `ProtectedRoute`; the `subscribe` component flag makes `SurfaceDetail`
consume `plugin-window-data-<handle>` events (`bvx.window_emit`) instead of
polling. All of a plugin's windows close on instance teardown.

Original scope (all delivered):
- `"plugin-*"` window labels in `gui/src-tauri/capabilities/default.json`.
- `bvx.window_open/close/emit` on the SSH/RDP window pattern (`WebviewWindowBuilder` + hash route + `CloseRequested` teardown); routes constrained to `/plugin/<name>/`; `max_open` clamp.
- `SurfaceRouter` in secondary windows (behind `ProtectedRoute`); host-drawn title prefix `"<plugin> — "`; `subscribe: true` component flag delivering `plugin-window-data-<handle>` events.

**Acceptance (met):** WAT tests record window-open ops, enforce the `max_open` clamp (`WINDOW_LIMIT`), and refuse a route outside the plugin's prefix; `window_emit`/`closed`-event plumbing wired end-to-end.

### Phase 4 — Vault-API bridge (1 week)

- Extract `plugin_surface_dispatch`'s substitution/validation into a shared helper; `bvx.api_request` uses it + `AppState.backend` + session token; buffer-retry protocol; error envelope.
- `api_paths` prefix enforcement + per-call denial logging.

**Acceptance:** module lists + reads its mount through the bridge in both embedded and remote modes; a path targeting another mount or `sys/` returns forbidden without touching the backend.

### Phase 5 — Network + consent UX (1.5–2 weeks)

- Tauri-side enforcer for `bvx.net_http`: grant presence + `capability_sha256` match, scheme/host/wildcard checks, SSRF guard (loopback/RFC1918/link-local refused unless explicitly granted; re-check every redirect hop, 3-hop cap), 4 MiB response cap, ≤ 60 s timeout, no cookies.
- Register/activate consent panel in `PluginsPage`'s `RegisterModal` (requested hosts verbatim + publisher identity + explicit tick) → `PUT .../grants`; re-approval prompt on activate when the pin mismatches; grant revoke button.
- Per-plugin call ring buffer (last 100) + admin panel table.

**Acceptance:** end-to-end: unsigned dev plugin requesting `net` gets `NET_NOT_GRANTED` until the admin ticks consent; after grant, an allowed host succeeds, a non-allowlisted host / redirect-to-10.0.0.1 / plain-http each fail with the right code; revoke propagates ≤ 30 s.

### Phase 6 — SDK + testkit + reference plugins (1–1.5 weeks)

- SDK `app` feature: `app_module!` macro, typed `Host` wrappers for all `bvx.*` imports.
- `bastion-plugin-testkit`: `bvx` mock host (scripted API responses, captured menu/window calls, fake network allow/deny), conformance WAT extended, parity test against the real `plugin_apps.rs` linker.
- Reference: TOTP app module (menus + window + API) and `webhook-notify` (net grant flow); docs walkthrough.

**Acceptance:** both references pass `make plugins-test`; walkthrough reproduces from a clean checkout.

### Phase 7 — Server-side `bv.net_http` (stretch, 1 week)

- Extract the Phase-5 enforcement into a shared `net_gate` module; register `bv.net_http` in the server WASM runtime behind the same grant record; audit each call.
- Gives WASM server plugins constrained egress — removing the main remaining reason to choose the process runtime.

**Acceptance:** server-side WASM plugin reaches a granted host; ungranted returns `NET_NOT_GRANTED`; testkit + parity updated.

## 4. Effort estimate

| Phase | Engineer-weeks | Risk |
|---|---|---|
| 0 Spec | 0.5 | low |
| 1 Server grants | 1.5 | low |
| 2 Runtime + menus | 2.0 | medium (instance lifecycle vs. surface updates) |
| 3 Windows | 1.5 | medium (window/event plumbing) |
| 4 API bridge | 1.0 | low |
| 5 Network + consent | 2.0 | medium-high (SSRF guard correctness) |
| 6 SDK/testkit/refs | 1.5 | low |
| 7 Server net (stretch) | 1.0 | low |
| **Total** | **≈ 11 engineer-weeks** | |

Phases 1–2 alone deliver visible value (dynamic menus). Phase 5 is the security-sensitive one — its enforcement code should get a focused review pass before release.

## 5. Out of scope

- Plugin JS/CSS in the webview; custom component kinds beyond the v1 three (+ `subscribe` flag).
- Raw TCP/UDP from plugins (HTTP(S) only).
- Cross-plugin communication; plugin-to-plugin window messaging.
- Grant delegation (only admins grant; no user-level self-service grants).
- Mobile/web clients (same stance as v1).
