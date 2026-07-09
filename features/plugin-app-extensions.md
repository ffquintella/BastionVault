# Plugin App Extensions (Plugin Extensibility v2)

**Status:** In progress — **Phases 1–5 shipped**. P1 (server): `capabilities.app` manifest + validation + widening guard, `HOST_ABI_MINOR=1`, `src/plugins/grants.rs` net-grant records + `GET/PUT/DELETE /v1/sys/plugins/<name>/grants`, grant + app-module descriptor in the active-surfaces bundle. P2 (client): stateful Tauri-backend app-module runtime (`gui/src-tauri/src/plugin_apps.rs`, async Wasmtime) with `bvx.log`/`now`/`set_result` + dynamic menus (badge, 16-cap, `plugin-menus-updated`, `bvx_menu_click`). P3 (client): plugin windows (`bvx.window_*`, `plugin-*` labels, `pluginWindow` bare render, `subscribe` flag). P4 (client): `bvx.api_request` vault bridge (mount-scoped `api_paths`, session token, embedded+remote). P5 (client): `bvx.net_http` with the `net_gate` enforcer (scheme/host/wildcard + SSRF guard, per-hop redirect re-validation, 4 MiB/≤60 s caps, no cookies), per-plugin call ring, and the **Network access** admin consent panel. P6: `bastion-plugin-sdk` `app` feature (`AppHost` typed `bvx.*` wrappers, `AppModule` trait, `app_module!` macro, host_test stubs) — the testkit `bvx` driver + reference plugins (`plugins-ext` submodule) remain. P7: shared `net_gate` + `net_http::fetch` (reused by client + server) and server-side `bv.net_http` gated by the same grant + audited.
**Owner:** Felipe Quintella
**Related:** [`features/plugin-system.md`](plugin-system.md) (server substrate), [`features/plugin-extensibility.md`](plugin-extensibility.md) (v1 surfaces + form hooks), [`roadmaps/plugin-app-extensions.md`](../roadmaps/plugin-app-extensions.md) (phasing), [`features/plugin-testing.md`](plugin-testing.md) (test infrastructure).

---

## Summary

Extensibility v1 gave plugins a **declarative** GUI footprint: static menus and pages from `surface.json`, plus zero-capability form hooks. v2 adds an optional **programmatic** layer — an **app module**: a WASM asset executed in the Tauri-backend Wasmtime sandbox (never the webview) with a small set of **capability-gated host imports** that let a plugin:

1. **Create and update menu items at runtime** (`bvx.menu_*`) — e.g. show a "Pending approvals (3)" entry whose badge tracks server state.
2. **Open and drive its own windows** (`bvx.window_*`) — secondary Tauri windows rendering the plugin's *declarative surface pages*; the plugin gets window lifecycle events, never DOM access.
3. **Call the vault API** (`bvx.api_request`) — mount-scoped `{op, path, data}` requests through the user's live session; the server ACL pipeline stays the sole authority.
4. **Reach the network** (`bvx.net_http`) — HTTPS requests to a host allowlist that must be **both** requested by a manifest flag **and** explicitly authorized by an admin during install. Without the grant, the import returns `NET_NOT_GRANTED`; the manifest flag alone grants nothing.

Everything is opt-in and additive: a plugin that ships no app module behaves exactly as v1.

## Design principles (carried over from v1, still binding)

- **No plugin JavaScript in the webview, ever.** App modules run in Wasmtime inside the Tauri backend process, exactly where form hooks run today (`gui/src-tauri/src/plugin_hooks.rs`). The webview renders only host-owned React components.
- **The import set is the capability surface.** Same invariant as the server runtime (`src/plugins/runtime.rs`): host imports are the only doors, each is gated by a declared capability, and gating happens host-side per call.
- **Client-side checks are UX; the server is authority.** `bvx.api_request` rides the user's token — a malicious surface cannot widen permissions, only spend the ones the user already has.
- **Widening requires ceremony.** All new capability fields participate in `PluginCatalog::check_capability_widening`; the network grant additionally requires a fresh admin approval whenever the requested capability set changes.

## Delivery model — server-installed, zero per-client install

Plugins (and their app modules) are installed **once on the server**; no
artifact is ever installed on a client. Every connecting GUI is a generic
renderer that pulls the plugin's GUI footprint from whatever server it is
connected to, entirely over the `Backend` trait (in-process in embedded mode,
HTTP in remote mode — identical behaviour either way):

- **Surfaces** (menus/pages/forms) arrive in the aggregated
  `GET /v1/sys/plugins/active-surfaces` bundle, with the existing ETag +
  long-poll watcher so a server-side register/activate/delete propagates to
  live clients without a reload (≤ ~30 s).
- **The app-module WASM** is a content-addressed `client_assets` entry fetched
  on demand via `GET /v1/sys/plugins/<name>/<version>/asset/<sha256>` (served
  `immutable`), cached locally by sha256. The bundle's `app_module` descriptor
  (asset ref + capability gates) is folded into the bundle ETag, so a new
  version re-syncs and re-instantiates automatically.
- **Grants** ride in-band in the same bundle.

The `bvx.*` runtime is part of the GUI binary (host-owned) and is identical on
every client, so a plugin ships only its WASM + `surface.json` — never any
client-side runtime code. The app module *executes* in each client's Tauri
backend (sandboxed Wasmtime, no ambient authority, `bvx.*` imports only) but is
always *delivered* by the server. The only local artifact is a content-addressed
download cache, re-populated from the server and invalidated by sha/ETag — not
an install.

## Manifest extensions

A new optional `capabilities.app` block (all fields default off) plus a new client-asset kind:

```json
{
  "name": "approvals-x",
  "version": "2.0.0",
  "runtime": "wasm",
  "abi_version": "1.1",
  "capabilities": {
    "log_emit": true,
    "storage_prefix": "state",
    "app": {
      "dynamic_menus": true,
      "windows": { "max_open": 2 },
      "api_paths": ["{mount}/"],
      "net": { "hosts": ["hooks.example.com", "*.status.example.net"], "https_only": true }
    }
  },
  "client_assets": [
    { "name": "approvals-app.wasm", "kind": "app-module", "sha256": "…", "size": 65536 }
  ]
}
```

- `dynamic_menus` — enables `bvx.menu_upsert` / `bvx.menu_remove`.
- `windows.max_open` — enables `bvx.window_*`; hard cap on concurrently open plugin windows (host clamps to ≤ 4).
- `api_paths` — enables `bvx.api_request`. Entries are validated with the same rules as surface bindings: must start with `{mount}` (the plugin's own mount), no `..`, no absolute paths. `sys/…`, other mounts, and auth paths are unreachable by construction. (A later revision may add narrowly-scoped extra grants such as `sys/plugins/{self}/config` read.)
- `net.hosts` — requests the network capability. Validated at registration by the existing `PluginCatalog::validate_net_allowlist` rules (no bare `*`, no ports, wildcard only as the leading label). **Requesting is not receiving** — see the grant model below.
- `net.https_only` — defaults `true`; `false` is accepted at parse time but the client enforcer still refuses plain `http` unless the granted entry names an explicit host (never a wildcard).
- `kind: "app-module"` — at most one per plugin version; content-addressed and sha256-verified like every client asset.

`abi_version` bumps to `1.1` (minor: additive host surface; v1 hosts refuse `1.1` manifests via the existing `check_abi_compatibility`, which is the desired downgrade behavior).

## The admin network grant

Two independent keys must turn for a plugin to touch the network:

1. **The manifest requests it** (`capabilities.app.net.hosts`) — pinned at registration, subject to the widening guard (adding a host requires DELETE + re-register, same as `allowed_hosts` today).
2. **An admin authorizes it during install** — the GUI register flow detects the request and renders a consent panel (the requested hosts, verbatim, with the plugin's name/version/publisher); the admin must explicitly tick *"Authorize network access to these hosts"*. Registration without the tick still succeeds — the plugin simply gets `NET_NOT_GRANTED` at runtime.

The grant is a server-side record, not client state:

```
core/plugins/engine/grants/<name>  →  {
  "net": {
    "hosts": ["hooks.example.com", "*.status.example.net"],
    "granted_by": "<entity_id>",
    "granted_at": "<rfc3339>",
    "capability_sha256": "<sha256 of the canonical capabilities.app.net JSON>"
  }
}
```

- `capability_sha256` pins the grant to the exact requested capability. A new version whose `net` request differs (even narrower) invalidates the grant; the GUI prompts for re-approval on activate.
- HTTP surface (admin ACL on `sys/plugins/<name>/grants`):

  | Method & Path | Purpose |
  |---|---|
  | `GET /v1/sys/plugins/<name>/grants` | Current grant record (or empty). |
  | `PUT /v1/sys/plugins/<name>/grants` | Create/replace the grant. Body must echo the requested hosts exactly — the server refuses a grant that is a superset of the manifest request. |
  | `DELETE /v1/sys/plugins/<name>/grants` | Revoke. Takes effect on the next surface refresh (≤ 30 s via the existing long-poll watcher). |

- Audit events: `plugin.grant.net.approved`, `plugin.grant.net.revoked` — payload `{ plugin, version, hosts, actor_entity_id }`.
- The grant (hosts only, no metadata) is delivered to clients inside the `active-surfaces` bundle entry, so the Tauri-side enforcer needs no extra round trip and revocation propagates with the existing ETag/watcher machinery.

## App-module runtime (Tauri backend)

New module `gui/src-tauri/src/plugin_apps.rs`, sharing the Engine/limits infrastructure of `plugin_hooks.rs` but **stateful**: one instance per `(plugin, active version)` per signed-in session, created lazily on first use and torn down on sign-out, vault switch, or surface update.

**Sandbox limits:** 256 MiB memory, 100 M fuel *per entry-point call* (refueled each call), 4 MiB payload caps — identical numbers to the form-hook sandbox and the server runtime.

### Exports (plugin → host)

All optional except `memory` + `bv_alloc`:

```
bvx_init(ctx_ptr, ctx_len) -> i32          // once per instance; ctx JSON below
bvx_menu_click(ev_ptr, ev_len) -> i32      // user clicked a dynamic menu item
bvx_window_event(ev_ptr, ev_len) -> i32    // open/closed/page-event for an owned window
bvx_tick(now_ms: i64) -> i32               // optional periodic callback, min interval 30 s
```

`bvx_init` context: `{ "plugin": "...", "version": "...", "mount": "secret/approvals", "policies": [...], "locale": "en" }`. Non-zero returns are logged and surface as a toast in the operator UX; they never crash the GUI.

### Host imports (namespace `bvx`)

Same pointer/length + return-code conventions as the server `bv` ABI (`-1` not found, `-2` forbidden, `-3` buffer too small, `-4` internal), with new codes `NET_NOT_GRANTED = -6`, `NET_HOST_DENIED = -7`, `WINDOW_LIMIT = -8`. Every import is registered unconditionally and gated inside the closure (the server runtime's pattern), so plugins can degrade gracefully.

```
bvx.log(level, ptr, len)                              // always available
bvx.now_unix_ms() -> i64                              // always available
bvx.set_result(ptr, len)                              // response window for the current entry point

// dynamic_menus
bvx.menu_upsert(json_ptr, json_len) -> i32
bvx.menu_remove(id_ptr, id_len) -> i32

// windows
bvx.window_open(json_ptr, json_len) -> i32            // ≥ 0: window handle
bvx.window_close(handle) -> i32
bvx.window_emit(handle, json_ptr, json_len) -> i32    // push data to the window's page

// api_paths
bvx.api_request(req_ptr, req_len, out_ptr, out_max) -> i32

// net (manifest request + admin grant)
bvx.net_http(req_ptr, req_len, out_ptr, out_max) -> i32
```

### Dynamic menus

`bvx.menu_upsert` takes the existing `SurfaceMenu` JSON shape (`bv_plugin_surface::SurfaceMenu`) plus an optional `"badge": "3"` field. Validation is identical to registration-time surface validation — `route` must start `/plugin/<name>/`, `section` constrained to the four known sections — and runs host-side on every call. Accepted menus merge into the `pluginSurfacesStore` slice through a new Tauri event `plugin-menus-updated`; `PluginMenuSlot` renders them exactly like static ones (`min_policy` hint included). Dynamic menus are session-scoped: they vanish on instance teardown, and a plugin cannot exceed **16** dynamic entries.

### Windows

`bvx.window_open` spec:

```json
{ "route": "/plugin/approvals-x/review", "title": "Review request", "width": 720, "height": 520 }
```

The host creates a `WebviewWindowBuilder` window — the SSH/RDP session-window pattern in `gui/src-tauri/src/commands/connect.rs` — with:

- label `plugin-<name>-<n>` (a new `"plugin-*"` entry joins `ssh-*`/`rdp-*` in `gui/src-tauri/capabilities/default.json`);
- URL `index.html#<route>?pluginWindow=<handle>` — i.e. the window renders the plugin's **declarative surface page** through the existing `SurfaceRouter`, behind `ProtectedRoute`. There is no way to point a plugin window at a non-`/plugin/<name>/` route;
- `CloseRequested` → `bvx_window_event {"handle": n, "kind": "closed"}`;
- `bvx.window_emit` payloads arrive at the page as a Tauri event `plugin-window-data-<handle>`, consumable by `detail`/`table` components via a new optional `"subscribe": true` component flag (surface schema stays v1-compatible; the flag is ignored by older GUIs).

`max_open` is enforced host-side (`WINDOW_LIMIT`); all of a plugin's windows are closed on instance teardown.

### Vault API bridge

`bvx.api_request` body: `{ "op": "read|write|delete|list", "path": "{mount}/approvals/42", "data": {...} }`. The host resolves and validates the path with the **same code** as `plugin_surface_dispatch` (`{mount}` substitution, no unresolved `{`, no `..`, must stay under the plugin's mount and match a declared `api_paths` prefix), then dispatches through `AppState.backend` with the session token. The response JSON (or an error envelope `{"error": "..."}`) is written to the output buffer with the standard buffer-retry protocol. Works identically in embedded and remote modes because it rides the `Backend` trait.

### Network

`bvx.net_http` body: `{ "method": "GET", "url": "https://hooks.example.com/notify", "headers": {...}, "body_b64": "...", "timeout_ms": 30000 }`. The Tauri-side enforcer, in order:

1. Grant present in the active-surfaces bundle and `capability_sha256` matches → else `NET_NOT_GRANTED`.
2. URL scheme `https` (plain `http` only when the matched grant entry is an explicit non-wildcard host **and** the manifest set `https_only: false`) → else `NET_HOST_DENIED`.
3. Host matches a granted entry (leading-label wildcard semantics, exact port 443/80 only) → else `NET_HOST_DENIED`.
4. **SSRF guard:** the resolved IPs must not be loopback / RFC 1918 / link-local / ULA unless the granted entry is literally that IP or a `.internal`-suffixed name the admin typed. Checked again on every redirect hop; redirects capped at 3, each hop re-validated against the allowlist.
5. Response body capped at 4 MiB; timeout clamped to ≤ 60 s; no cookie jar, no ambient proxy credentials.

Every call (allowed or denied) is recorded in a per-plugin ring buffer (last 100: timestamp, method, host, status, bytes) surfaced on the Plugins admin page, so the admin can see exactly what a granted plugin does with the grant.

### Server-side parity (stretch)

The same grant record gates a future `bv.net_http` host import in the **server** WASM runtime — closing today's gap where "plugin needs network" forces the process runtime with unconstrained OS egress. Same enforcement code path (extracted into a shared `net_gate` module), same audit trail. Tracked as the final phase; not required for the client-side feature.

## Security model deltas

| Threat | Mitigation |
|---|---|
| App module calls vault paths the user can't access | It rides the user's token; server ACLs are unchanged and authoritative. `api_paths` scoping is defense-in-depth + audit clarity, not the boundary. |
| App module exfiltrates secrets read via `bvx.api_request` through `bvx.net_http` | This is the real new risk and precisely why network is double-gated: manifest flag (author intent, signed) + admin grant (operator consent, audited) + host allowlist + call ring visible to the admin. Admins should grant `net` only to plugins whose publisher they trust, and the consent UI says so. |
| Malicious redirect to an internal address after an allowed request | Every redirect hop re-validated; private/loopback ranges refused unless explicitly granted; 3-hop cap. |
| Plugin opens windows that spoof host UI (fake unlock dialog) | Plugin windows render only the plugin's own declarative surface pages behind `ProtectedRoute`; the window title bar is host-drawn and prefixed `"<plugin> — "`; no arbitrary HTML/JS exists to fake host chrome. |
| Menu spam / UI squatting | 16-entry cap, section whitelist, route-prefix validation, all enforced host-side per call. |
| Grant survives a hostile update | Grant pinned to `capability_sha256`; any change to the requested net capability voids it until an admin re-approves. Registration-time widening guard still applies on top. |
| Compromised admin token grants network silently | `plugin.grant.net.approved` audit event carries the actor entity; grants are enumerable via `GET .../grants` for compliance sweeps. |
| Fuel/memory abuse in the long-lived instance | Per-call refueling with the same 100 M budget; instance recycled on OOM/trap; `bvx_tick` floor of 30 s. |

## Compatibility

- v1 plugins: untouched (no `app` block, no `app-module` asset — nothing changes).
- v2 plugin on a v1 host: refused at registration by the ABI minor check (`abi_version 1.1` > host minor) — clean error, no partial behavior.
- v2 plugin on a v2 server with a v1 GUI: server accepts it; the old GUI ignores unknown asset kinds and never instantiates the app module; declarative surface keeps working.
- Network grant absent: every `bvx.net_http` returns `NET_NOT_GRANTED`; well-written plugins degrade (the SDK helper exposes this as a typed error).

## SDK & testing

- `bastion-plugin-sdk` grows an `app` feature: `app_module!` macro emitting the `bvx_*` export glue, plus typed wrappers (`Host::menu_upsert(Menu)`, `Host::api_read(path)`, `Host::http(Request)`) with the same buffer-retry ergonomics as the existing `Host` methods.
- `bastion-plugin-testkit` ([features/plugin-testing.md](plugin-testing.md)) grows a `bvx` mock host in lockstep: scripted API responses, captured menu/window calls, a fake network with per-host allow/deny — so app modules are unit-testable without a GUI. The testkit's conformance/parity pattern extends to the `bvx` surface.
- Reference plugin: extend the TOTP example with an app module that (a) adds a dynamic "Expiring soon (n)" menu, (b) opens a detail window, (c) reads codes via `bvx.api_request` — exercising everything except `net`; a second tiny `webhook-notify` example exercises the grant flow end-to-end.

## Implementation phases

See [`roadmaps/plugin-app-extensions.md`](../roadmaps/plugin-app-extensions.md). Summary:

| Phase | Scope | Ships value alone? |
|---|---|---|
| 0 | ✅ Spec ratification (this doc) + ABI minor bump plan | — |
| 1 | ✅ **Done.** Manifest `capabilities.app` + validation + widening guard + grants storage/endpoints/audit (server) | Yes — grant plumbing usable by API consumers |
| 2 | ✅ **Done.** App-module runtime in Tauri backend + `bvx.log/now/set_result` + dynamic menus end-to-end | Yes — first visible feature |
| 3 | ✅ **Done.** Plugin windows (capability wildcard, `window_*`, window events, `subscribe` flag) | Yes |
| 4 | ✅ **Done.** `bvx.api_request` bridge (shared validation with `plugin_surface_dispatch`) | Yes |
| 5 | ✅ **Done.** `bvx.net_http` + consent UX + call ring buffer | Yes |
| 6 | 🔶 **SDK `app` feature done** (macro + `AppHost` + host_test stubs); testkit `bvx` driver + reference plugins (`plugins-ext`) remain | Yes |
| 7 | ✅ **Done.** Server-side `bv.net_http` behind the same grant (shared `net_gate` + `net_http`) | Yes |

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), [`roadmaps/plugin-app-extensions.md`](../roadmaps/plugin-app-extensions.md), and this file's Status line.
