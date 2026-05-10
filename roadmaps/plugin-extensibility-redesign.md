# Plugin Extensibility Redesign

**Status:** Proposed
**Owner:** Felipe Quintella
**Tracking issue:** _(to be filed)_
**Related:** [`features/plugin-system.md`](../features/plugin-system.md), [`features/plugin-extensibility.md`](../features/plugin-extensibility.md) _(new — created by Phase 1)_

---

## 1. Motivation

The plugin system in BastionVault 0.4 (Phases 1–5 of [`features/plugin-system.md`](../features/plugin-system.md)) lets operators register, sign, version, hot-reload, and mount plugins as full **logical backends**. Plugins receive raw `{op, path, data}` envelopes and own their entire request surface. Concretely this means:

- A plugin's **functions** are only addressable through whatever paths it chooses to recognise inside its mount. There is no machine-readable description of what those paths are or what shape they expect.
- The **GUI** (`gui/src/routes/PluginsPage.tsx`) treats every plugin as an opaque "registered/activated" record. Operators can invoke plugins via the test endpoint and configure them, but cannot use a plugin's actual functionality from the GUI without bespoke per-plugin pages (the way `bastion-plugin-pmp` and `bastion-plugin-xca` had wizards hand-coded into the GUI).
- There is **no client-side artifact distribution.** Anything plugin-specific that the GUI displays has been built into the GUI binary itself.
- There is **no version-aware client cache.** Re-deploying a plugin on the server has no effect on connected clients beyond what the GUI was hard-coded to display.

The redesign in this document closes those gaps. The target workflow is:

```
1. Operator registers plugin on server.            (already supported)
2. Operator activates plugin on server.            (already supported, becomes "publish surface")
3. Server identifies and runs plugin functions.    (already supported, gains discovery API)
4. Client connects → server hands it a surface     (NEW)
   manifest describing menus, forms, paths.
5. Client caches surface + any client-side
   artifacts under (plugin, version, hash).         (NEW)
6. Server activates a new version → client          (NEW)
   transparently downloads + swaps next session.
7. Plugin authors describe new menus and forms      (NEW)
   declaratively; GUI renders them generically.
```

This is **additive**. The existing logical-backend plugin contract stays in place; surfaces are an opt-in layer on top of the same plugin binary.

## 2. Non-goals

- A plugin marketplace. Distribution stays operator-driven (operator uploads `.bvplugin`).
- Replacing the WASM/process runtimes or rewriting the existing capability gate model.
- Inter-plugin communication.
- Plugins running arbitrary JavaScript inside the GUI's main webview. Client-side plugin code, when present, runs in a Wasmtime sandbox the GUI already ships (`gui/src-tauri/src/plugins/...`); plugins do not get DOM access. (See §6 on the Form-Hook ABI.)
- Mobile / web clients. The redesign assumes the Tauri desktop GUI is the only client. The surface manifest format is platform-agnostic; a future web client could consume it without server changes.

## 3. Architecture overview

### 3.1 Two artifacts per plugin

A plugin is an `.bvplugin` bundle. Today: `magic || format-version || manifest-len || manifest JSON || wasm-or-binary`. The redesign extends the bundle layout to optionally carry **two more sections**:

```
BVPL || fmt=2 || manifest-len || manifest JSON
       || server-binary-len    || server.wasm | server-binary
       || surface-len          || surface.json          (NEW, optional)
       || client-asset-count   || N × (name-len, name, len, bytes)   (NEW, optional)
```

The manifest grows two siblings to `runtime`:

```json
{
  "name": "totp-x",
  "version": "1.4.0",
  "runtime": "wasm",
  "abi_version": 2,
  "surface": {
     "schema_version": 1,
     "ref": "surface.json"
  },
  "client_assets": [
     { "name": "totp-form-hooks.wasm",
       "kind": "form-hook",
       "sha256": "…",
       "size": 18432 }
  ]
}
```

Only `manifest` + `server-binary` are mandatory. A plugin with no GUI footprint omits both new sections. A plugin with declarative forms ships `surface.json`. A plugin with custom validation ships a `form-hook` WASM and references it from the surface.

### 3.2 Surface manifest

`surface.json` is the **machine-readable description of everything the GUI shows to the user**. Three top-level concerns:

- **Navigation** — where the plugin's pages appear in the sidebar / admin section / settings.
- **Pages** — the screens themselves: a tree of forms, tables, and detail views.
- **Bindings** — which server-side plugin path each interactive element posts to / reads from.

A small example:

```json
{
  "schema_version": 1,
  "title": "TOTP",
  "icon": "key-round",
  "menus": [
    {
      "id": "totp.main",
      "label": "TOTP",
      "section": "secrets",
      "route": "/plugin/totp-x/codes",
      "min_policy": "totp-user"
    }
  ],
  "pages": [
    {
      "route": "/plugin/totp-x/codes",
      "title": "TOTP codes",
      "components": [
        {
          "kind": "table",
          "id": "totp.list",
          "binding": { "op": "list", "path": "{mount}/codes" },
          "columns": [
            { "field": "name", "label": "Name" },
            { "field": "issuer", "label": "Issuer" }
          ],
          "row_actions": [
            { "label": "Delete", "binding": { "op": "delete", "path": "{mount}/codes/{name}" }, "confirm": true }
          ]
        },
        {
          "kind": "form",
          "id": "totp.create",
          "title": "New TOTP",
          "schema": {
            "type": "object",
            "required": ["name", "secret"],
            "properties": {
              "name":   { "type": "string", "title": "Name" },
              "issuer": { "type": "string", "title": "Issuer" },
              "secret": { "type": "string", "title": "Base32 secret", "format": "password" }
            }
          },
          "submit": {
            "label": "Save",
            "binding": { "op": "write", "path": "{mount}/codes/{name}" }
          },
          "hook": "totp-form-hooks#validate_create"
        }
      ]
    }
  ]
}
```

Key choices:

- **JSON Schema (Draft 2020-12) for forms.** No new vocabulary to learn. Existing `react-jsonschema-form`-style renderer in the GUI consumes it directly.
- **Bindings are server-side `{op, path}` envelopes**, identical to the current plugin invocation shape. The renderer fills `{mount}` from the plugin's actual mount path and substitutes form fields with `{name}`-style placeholders.
- **`min_policy`** lets the plugin declare which baseline ACL policy gates each menu. The GUI hides menus the current user can't act on, but the **server still enforces ACLs independently** — the client gate is a UX courtesy, never a security boundary.
- **`hook`** is a `<asset-name>#<export>` reference to a client-side WASM export. Optional. See §6.

### 3.3 Client cache

Client-side state lives at the OS-appropriate cache dir:

```
<cache>/com.bastionvault.gui/plugins/
  <vault-id>/                       — per-vault, so two vaults don't collide
    <plugin-name>/<version>/
      surface.json                  — pinned content (sha256 verified)
      assets/<sha256>.bin           — content-addressed, dedup across versions
      _meta.json                    — { activated_at, etag, ... }
```

The cache key is `(vault_id, plugin_name, version, content_hash)`. A new version is a new directory; old versions are kept until the next session boundary so an in-flight form submission can finish without ripping its UI out from under it.

### 3.4 End-to-end flow

```
┌─────────┐   register .bvplugin    ┌─────────┐
│Operator │ ───────────────────────▶│ Server  │
└─────────┘                          └─────────┘
                                         │
                                         │ activate version 1.4.0
                                         ▼
                        ┌─────────────────────────────────────┐
                        │  catalog.publish_surface(plugin)    │
                        │  audit("plugin.surface.published")  │
                        └─────────────────────────────────────┘

┌─────────┐  GET /v1/sys/plugins/active-surfaces?since=etag   ┌─────────┐
│ Client  │ ────────────────────────────────────────────────▶│ Server  │
└─────────┘ ◀──────────────────────────────────────────────── └─────────┘
                  304 Not Modified  |  200 + surface bundle

┌─────────┐  GET /v1/sys/plugins/<name>/<version>/asset/<hash>┌─────────┐
│ Client  │ ────────────────────────────────────────────────▶│ Server  │
└─────────┘ ◀──────────────────────────────────────────────── └─────────┘
                              200 + raw asset bytes

┌─────────┐  user clicks menu → renders page → posts form    ┌─────────┐
│ Client  │ ────────────────────────────────────────────────▶│ Server  │
└─────────┘  ── operation flows through the existing         └─────────┘
                plugin LogicalBackend; nothing new.
```

## 4. Phased implementation plan

Each phase ships independently and leaves the system in a working state. Phase boundaries match what we can ship in roughly a week of focused work; the listed acceptance bar is what proves the phase is done.

### Phase 0 — Spec ratification (1–2 days)

- Land [`features/plugin-extensibility.md`](../features/plugin-extensibility.md) with the proposal in this doc rendered as a feature spec.
- Bump plugin ABI version: server-side `abi_version: 1` → `abi_version: 2`. The catalog refuses to load `2`-tagged plugins until Phase 1 lands; refuses `1`-tagged plugins after Phase 4 lands.
- Update `make plugins-keygen` / `make plugins-sign` to handle the optional new bundle sections (the signature payload becomes `sha256(server-binary) || sha256(surface) || sha256(asset_1) || … || canonical_manifest_without_signature`).

**Acceptance:** spec doc merged, ABI version bumped, signing tools accept v2 bundles.

### Phase 1 — Surface manifest server-side (1–2 weeks)

- Define `SurfaceManifest`, `SurfaceMenu`, `SurfacePage`, `SurfaceComponent` types in `crates/bv_plugin_surface/` (new shared crate so SDK + server + GUI all reference the same definitions).
- Catalog stores surface JSON alongside the binary on `set_policy_internal`-style write paths. Surfaces are version-scoped (active version's surface is what clients see).
- New HTTP routes:

  | Route | Handler | Purpose |
  |---|---|---|
  | `GET /v1/sys/plugins/<name>/surface` | `sys_plugins_surface_get_handler` | Active-version surface + ETag |
  | `GET /v1/sys/plugins/active-surfaces` | `sys_plugins_active_surfaces_handler` | Aggregated surface bundle (one round trip) |
  | `GET /v1/sys/plugins/<name>/versions/<version>/asset/<sha256>` | `sys_plugins_asset_get_handler` | Raw asset by content hash |

- Audit emits `plugin.surface.published`, `plugin.surface.fetched`.
- Operator `min_policy` validation: if a referenced policy doesn't exist, registration fails with a clear error.

**Acceptance:** integration test registers a plugin with a 3-menu / 2-form `surface.json`; `GET .../active-surfaces` returns it; `If-None-Match` short-circuits to 304; deleting the plugin removes its surface from the aggregate.

### Phase 2 — `bv-client` surface fetch + cache (1 week)

- New module `crates/bv-client/src/surface.rs`. API: `Backend::active_surfaces() -> SurfaceBundle`.
- Cache at `<dirs::cache>/com.bastionvault.gui/plugins/<vault-id>/...`. Content-addressed assets (one shared dir per `sha256`).
- `If-None-Match` populated from `_meta.json` ETag; on 304, surfaces resolve from cache.
- `RemoteBackend` and `EmbeddedBackend` both implement the trait; embedded reads the catalog directly without HTTP.
- Cache eviction: on session end, anything not in the latest `active-surfaces` response is moved to `_old/` and tombstoned 7 days later.

**Acceptance:** unit + integration tests for cold cache (downloads), warm cache (304), version change (re-download new + keep old until session ends), cache corruption (drop and refetch).

### Phase 3 — GUI dynamic surface rendering (2–3 weeks)

- New top-level state slice `pluginSurfaces` populated on login from `bv-client`.
- New layout slot `<PluginMenuSlot section="…">` rendered in `gui/src/components/Layout.tsx`. Menus appear in their declared `section` (currently: `secrets`, `admin`, `settings`).
- New route `/plugin/:plugin/:rest*` resolves to a `<SurfaceRouter>` that picks the right `SurfacePage` from the cached manifest.
- New components:
  - `<SurfaceTable>` — drives `binding.op = "list"`; supports row actions and search.
  - `<SurfaceForm>` — renders a JSON Schema form using `@rjsf/core` + the project's existing dark theme. `submit.binding` is the server call.
  - `<SurfaceDetail>` — `read` with key parameters from the route.
- All rendered components route through `bv-client` as usual; **the renderer is a thin shell, not a plugin runtime**.
- Settings panel: per-plugin "show in menu" toggle (operator UX, doesn't affect ACLs).

**Acceptance:** with a single test plugin shipping `surface.json`, the GUI shows its menu, list, create form, and detail view without a single line of plugin-specific TS in the GUI repo.

### Phase 4 — Optional client-side WASM form hooks (1–2 weeks)

- Hook ABI (`bv_plugin_surface::hooks`):
  ```
  validate(form_json) -> { ok: bool, errors: { field: msg } }
  pre_submit(form_json) -> form_json'             // can rewrite payload
  post_response(server_json) -> ui_hint_json       // toast/redirect/refresh
  ```
- Hooks run inside a Wasmtime sandbox in the Tauri *backend* process (`gui/src-tauri/src/plugin_hooks/`), not the webview. Same fuel/memory caps as server WASM (256 MiB / 100 M instructions). No host imports — pure compute on a single string in / single string out.
- Surface declares `hook: "<asset>#<export>"`; the GUI calls into Tauri to evaluate it; the webview only sees the result.
- Asset bytes verified against `client_assets[].sha256` from the manifest before instantiation.

**Acceptance:** TOTP plugin's `validate_create` hook rejects a non-base32 secret with a field-level error returned by WASM; the GUI shows it inline; bypassing the hook (DOM tampering) still gets caught by server-side validation.

### Phase 5 — Auto-update on version change (1 week)

- Server: `GET /v1/sys/plugins/active-surfaces?watch=1` upgrades to a long-poll endpoint that returns when the aggregate ETag changes (or 30 s timeout). Cheaper than SSE/WS, fits the existing `actix-web` plumbing.
- Client: a single `tokio` task on the `bv-client` side polls; on change, refreshes the cache and emits a Tauri event `plugin-surface-updated`.
- The GUI listens, refreshes its surface state, and shows a non-modal toast: *"`<plugin>` updated to `<version>`. Open new pages to see changes."*. In-flight pages keep using the old surface until navigation.
- Operator setting: `auto_apply_surface_updates` (default on; off for compliance environments that pin a manifest hash).

**Acceptance:** activate a new plugin version while the GUI is on the plugin's page; the toast appears within ~30 s; a fresh navigation picks up the new form fields.

### Phase 6 — Operator UX redesign (1 week)

- `gui/src/routes/PluginsPage.tsx` reorganised:
  - **Engine settings** (existing; unchanged): allowlist, accept-unsigned.
  - **Registered plugins** — gains a "Surface" column showing menu count + a *Preview Surface* button that opens an admin-only sandboxed render of `surface.json` against a synthetic mount, useful for previewing before activation.
  - **Active surface map** — a tree view of every menu the active version of every active plugin contributes. Useful for spotting collisions.
- Audit page picks up the two new event types.

**Acceptance:** operator can see exactly which menus a not-yet-activated plugin would inject before flipping the activate switch.

### Phase 7 — Reference plugin + SDK + docs (1 week)

- Convert `bastion-plugin-totp` (the simplest existing plugin) to ship `surface.json` and a `validate_create` form hook. Existing test infrastructure for the plugin keeps passing.
- Update `crates/bv_plugin_sdk/` (or create it if not yet split out) with helpers: `surface_builder()`, `form_hook!` proc-macro for hook exports.
- Document end-to-end in `features/plugin-extensibility.md`:
  - bundle layout v2
  - manifest extensions
  - surface schema reference
  - hook ABI
  - client cache structure
  - operator workflow walkthrough
  - migration notes for v1 plugins (do nothing — they keep working with the operator UX they had)

**Acceptance:** TOTP plugin with surface ships in `plugins-ext/`; `make plugins-pack` produces a v2 bundle; install + activate + use end-to-end in a fresh GUI install.

## 5. Compatibility & migration

- v1 plugins (no surface, no client assets) continue to load and operate exactly as today. The aggregator endpoint omits them from the active-surface bundle. Operators administer them via the existing `Plugins` admin page.
- v2 plugins are signed over the union `sha256(server) || sha256(surface) || sha256(asset_1) || …`. v1 signatures don't roundtrip.
- The GUI in 0.4.x treats unknown `schema_version` values in `surface.json` as a soft error: surface ignored, plugin still functional via direct invoke. This means a 0.5 plugin on a 0.4 client degrades cleanly.

## 6. Security model deltas

Threat surface added by this redesign:

| Threat | Mitigation |
|---|---|
| Malicious surface JSON tries to cause GUI to call paths the user shouldn't be able to | The renderer **only** translates the bound `{op, path}` into a normal client request; the server's existing ACL pipeline gates it. Surface declarations cannot widen permissions. |
| Surface JSON crafts a path that targets *another plugin's* mount | Bindings are scoped through a `{mount}` placeholder bound to *this plugin's* registered mount. Raw absolute paths in bindings are rejected at validation. |
| Form hook WASM tries to exfiltrate / phone home | Hook sandbox has zero host imports. No fs, no net, no clocks, no audit, no storage. The string-in / string-out shape is the entire ABI surface. |
| Plugin pins a `min_policy` to "default" but the server-side ACL on the bound path requires "totp-admin" | Server ACL wins. The client opens the menu, the form posts, and the server returns 403. We make this a clear toast rather than a stack trace. |
| Stale cache on a downgraded plugin (operator activates v1.3 after v1.4) | Cache key includes `version`. Activation returns a new ETag; the watcher refresh swaps. The old `1.4` directory is tombstoned. |
| MITM modifies surface JSON in transit | TLS already covers the wire. Additionally, every asset (and the surface file itself) is verified against the `sha256` declared in the manifest before use. |
| Plugin tries to register a menu in `admin` section to elevate UX visibility | `section` is constrained to `{secrets, admin, settings, sharing}` and the renderer enforces `min_policy ⊇ admin-baseline` for `admin`-section menus. |

## 7. Open questions

- **Asset size cap?** First-pass proposal: 2 MiB per asset, 8 MiB total per plugin version. A future "rich-UI" plugin (e.g., a bundled PDF viewer) might want a higher ceiling, gated behind a capability flag.
- **Pinning for compliance environments.** Should there be an operator-side allowlist of `(plugin, version, surface_sha256)` triples that the client refuses to upgrade past, even if the server has activated something newer? Lean yes — fits the existing publisher allowlist pattern.
- **Plugin self-config UI.** Today `plugins_set_config` takes raw JSON. Should the surface optionally describe a config form too (`surface.config_form`)? Lean yes; it's one more `SurfaceForm` and falls out for free in Phase 3.

## 8. Effort estimate

| Phase | Engineer-weeks | Risk | Blocking |
|---|---|---|---|
| 0 Spec | 0.5 | low | — |
| 1 Server surface | 1.5 | low | 0 |
| 2 Client cache | 1.0 | low | 1 |
| 3 GUI render | 2.5 | medium (form renderer choice) | 2 |
| 4 Hook ABI | 1.5 | medium (Wasmtime fuel-tuning for hook latency) | 3 |
| 5 Auto-update | 1.0 | low | 2 |
| 6 Operator UX | 1.0 | low | 3 |
| 7 Reference + docs | 1.0 | low | 1–6 |
| **Total** | **≈10 engineer-weeks** | | |

Phases 1+2 alone (≈2.5 weeks) deliver the full server-side discovery surface — useful for non-GUI clients and for shipping the TOTP plugin's surface as a v2 bundle even without the GUI consuming it yet. Phase 3 is where the operator user-visible value lands.

## 9. Out of scope (deferred)

- Inter-plugin RPC. Plugins talk to clients through the host; never to each other.
- Plugin-defined dashboard widgets. Dashboard composition stays a host responsibility.
- Themed surfaces. The GUI's existing color tokens / typography apply to all surfaces; plugins do not bring their own CSS.
- A plugin-side build of the form-hook WASM in Rust is the only first-class path. We don't ship a TS-to-WASM toolchain.
