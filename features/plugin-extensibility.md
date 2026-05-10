# Plugin Extensibility

**Status:** In Progress (Phase 0 → Phase 1 foundation landed; see [roadmap](../roadmaps/plugin-extensibility-redesign.md))
**Owner:** Felipe Quintella

This is the operator- and plugin-author-facing spec for the redesign tracked in [`roadmaps/plugin-extensibility-redesign.md`](../roadmaps/plugin-extensibility-redesign.md). Read the roadmap first for motivation, threat model, and phasing. This spec is the contract.

---

## What ships in Plugin Extensibility v1

A plugin can opt in to two new things on top of the v1 plugin contract that already exists in [`features/plugin-system.md`](plugin-system.md):

1. **A surface manifest** (`surface.json`) — a declarative description of the menus, pages, forms, and tables the plugin contributes to the GUI. The GUI renders these generically; no plugin-specific TypeScript is required.
2. **Client-side WASM form hooks** (optional) — small WASM modules executed inside a Wasmtime sandbox in the **Tauri backend process** (not the webview) that can validate, rewrite, or react to form data without ever touching the DOM.

A plugin that ships neither continues to work exactly as it does today and is administered through the existing `Plugins` admin page.

## Bundle layout (format version 2)

The `.bvplugin` packer emits this layout when any v2 section is present:

```
"BVPL"                            (4 bytes magic)
fmt = 2                           (u8)
manifest_len                      (u32 LE)
manifest                          (JSON, UTF-8)
server_binary_len                 (u32 LE)
server_binary                     (raw bytes)
[ surface_len                     (u32 LE)
  surface_json                    (JSON, UTF-8) ] only if manifest declares one
[ asset_count                     (u32 LE)
  asset_count × (
      name_len  (u16 LE),
      name      (UTF-8),
      data_len  (u32 LE),
      data      (raw bytes)
  ) ] only if manifest declares any
```

Format version 1 bundles (the current shape) keep loading on hosts that understand v2. A v2 bundle on a v1-only host is rejected at registration with a clear `bvplugin format version 2 not supported by this server (max: 1)` error.

## Manifest extensions

The v2 manifest grows two optional sibling fields to `runtime`:

```json
{
  "name": "totp-x",
  "version": "1.4.0",
  "runtime": "wasm",
  "abi_version": "2.0",
  "sha256": "…",
  "size": 18432,
  "capabilities": { "log_emit": true, "audit_emit": true, "storage_prefix": "" },
  "config_schema": [],

  "surface": {
    "schema_version": 1,
    "ref": "surface.json"
  },
  "client_assets": [
    { "name": "totp-form-hooks.wasm",
      "kind": "form-hook",
      "sha256": "...64 hex chars...",
      "size": 18432 }
  ]
}
```

`surface.ref` is the asset name within the bundle. `client_assets[].sha256` is computed at pack time and verified before the GUI ever instantiates the WASM.

## Surface schema (v1)

The full schema lives in the [`bv_plugin_surface`](../crates/bv_plugin_surface/src/lib.rs) crate. The crate is the single source of truth — both server and GUI deserialize against the same Rust types.

### Top level

```json
{
  "schema_version": 1,
  "title": "TOTP",
  "icon": "key-round",
  "menus":   [ ... ],
  "pages":   [ ... ],
  "config_form": { ... }    // optional, replaces raw config-key editor
}
```

`schema_version` is a hard fence: a GUI that doesn't understand a `schema_version` greater than its own ignores the surface (the plugin still works via the admin page) and surfaces a single warning toast. **Never silently render an unknown schema.**

### Menus

```json
{
  "id": "totp.main",
  "label": "TOTP codes",
  "icon": "shield-check",
  "section": "secrets",          // one of: "secrets" | "admin" | "settings" | "sharing"
  "route": "/plugin/totp-x/codes",
  "min_policy": "totp-user"      // optional ACL hint, GUI-only courtesy
}
```

`min_policy` is a UX hint; the server's ACL pipeline is the only authority on whether the bound action succeeds. The GUI hides menus the active token doesn't satisfy to keep the sidebar tidy.

### Pages

```json
{
  "route": "/plugin/totp-x/codes",
  "title": "TOTP codes",
  "components": [ <SurfaceComponent>, ... ]
}
```

A page is a vertical stack of one or more **components**.

### Components

Three kinds of component, each with a fixed shape:

#### `table`

```json
{
  "kind": "table",
  "id": "totp.list",
  "binding": { "op": "list", "path": "{mount}/codes" },
  "columns": [
    { "field": "name",   "label": "Name" },
    { "field": "issuer", "label": "Issuer" }
  ],
  "row_actions": [
    { "label": "Delete",
      "binding": { "op": "delete", "path": "{mount}/codes/{name}" },
      "confirm": true }
  ],
  "empty_text": "No codes registered yet."
}
```

#### `form`

```json
{
  "kind": "form",
  "id": "totp.create",
  "title": "New TOTP",
  "schema": { "type": "object", "...": "JSON Schema 2020-12" },
  "submit": {
    "label": "Save",
    "binding": { "op": "write", "path": "{mount}/codes/{name}" }
  },
  "hook": "totp-form-hooks.wasm#validate_create"   // optional
}
```

The `schema` field is JSON Schema Draft 2020-12. The renderer treats `format: "password"` as a masked input, `format: "date"` as a date picker, and so on — see the surface crate's docs for the supported subset.

#### `detail`

```json
{
  "kind": "detail",
  "id": "totp.show",
  "binding": { "op": "read", "path": "{mount}/codes/{name}" },
  "fields": [
    { "field": "name",   "label": "Name" },
    { "field": "issuer", "label": "Issuer" },
    { "field": "code",   "label": "Current code", "live": true }
  ]
}
```

`live: true` re-issues the bound `read` on a 5-second cadence while the page is visible.

### Bindings

Every binding is a `{op, path}` envelope identical to what the existing `LogicalBackend` carries today. Two substitution points in the path:

- `{mount}` — replaced with this plugin's actual mount path (e.g., `secret/totp`).
- `{<form_field>}` — replaced with the form's value for that field at submit time. Only legal in `submit.binding` and `row_actions[].binding`.

Absolute paths (anything starting with `/`) and paths that don't begin with `{mount}` are rejected at registration. A plugin cannot bind to another plugin's mount, the audit log, or `sys/` paths.

### Allowed sections

`section` is constrained to:

| Section | Where it renders | Required policy floor |
|---|---|---|
| `secrets` | Top sidebar | (user-level) |
| `sharing` | Top sidebar | (user-level) |
| `admin` | Admin sidebar (collapsed by default) | admin baseline |
| `settings` | Settings page sub-nav | (user-level) |

Putting a menu in `admin` doesn't grant admin — it just controls where the link appears. The bound action's ACL still wins.

## Form-hook ABI

A form hook is a WASM module exporting one or more of:

```
validate(form_json_ptr, form_json_len) -> errors_ptr_len   (i64-packed)
pre_submit(form_json_ptr, form_json_len) -> form_json_ptr_len
post_response(server_json_ptr, server_json_len) -> ui_hint_ptr_len
```

Same pointer/length packing as the existing `bv_run` ABI. The host imports nothing — no `bv.log`, no `bv.storage_get`, no clock. The only state a hook can rely on is the bytes it received as input.

`errors_ptr_len` decodes to a JSON object `{ "ok": bool, "errors": { "field": "msg", ... }}`. `pre_submit` returns the rewritten form JSON (or the input unchanged). `post_response` returns a UI hint:

```json
{ "toast": { "kind": "success", "text": "Saved." },
  "navigate": "/plugin/totp-x/codes",
  "refresh_id": "totp.list" }
```

All three hooks are optional. Sandbox limits match the server-side WASM defaults: 256 MiB memory, 100 M instructions per call, no host calls.

## Client cache layout

```
<dirs::cache>/com.bastionvault.gui/plugins/
  <vault-id>/                              — sha256 of vault address+identifier
    <plugin-name>/<version>/
      surface.json                         — pinned content, sha256-verified
      _meta.json                           — { "etag": "...", "activated_at": "...",
                                              "asset_hashes": { "name": "sha256" } }
    _assets/<sha256>.bin                   — content-addressed, dedup across versions
    _old/<plugin-name>/<version>/...       — prior version, tombstoned at next session
```

The cache is invalidated by:

- a different `etag` in the `active-surfaces` response,
- a session boundary (sign-out / vault switch),
- a manual *Refresh plugin surfaces* action in the operator UX.

## Server endpoints (Phase 1)

| Method & Path | Auth | Purpose |
|---|---|---|
| `GET /v1/sys/plugins/<name>/surface` | `read` on `sys/plugins/<name>` | Active-version surface. Honours `If-None-Match`. |
| `GET /v1/sys/plugins/active-surfaces` | `read` on `sys/plugins/active-surfaces` | Aggregated bundle: every active plugin's surface, plus a top-level ETag. |
| `GET /v1/sys/plugins/<name>/<version>/asset/<sha256>` | `read` on `sys/plugins/<name>` | Raw bytes of a referenced client asset, content-hash-verified. |

The aggregated endpoint is the one clients hit on login. The per-plugin endpoint exists for the operator UX preview pane.

## Audit events

Two new event types:

- `plugin.surface.published` — emitted when a version is activated and that version carries a surface. Payload: `{ plugin, version, surface_sha256, asset_count }`.
- `plugin.surface.fetched` — emitted on every successful client fetch. Payload: `{ vault_id, etag_returned, plugins: [<names>] }`. Aggregated; one entry per request, not per plugin.

## Client-side ACL hinting

`min_policy` is checked client-side against the active token's resolved policy set (already known from the `auth/token/lookup-self` call) using the existing `gui/src/lib/acl.ts` helpers. **Never used as the only gate.** Two reasons it exists:

1. UX — hide menus that would always 403.
2. Operator preview — the *Active surface map* in the Plugins page can show "would not appear for `default` users" annotations next to each menu.

## Migration

**v1 plugins** (no surface, no client assets) keep working untouched. They appear in the admin Plugins page exactly as today and contribute zero menus.

**v1 GUI talking to a v2 server** ignores `active-surfaces` (route returns 404 on the older client because no command calls it) and behaves like today.

**v2 GUI talking to a v1 server** sees `active-surfaces` 404 and treats it as "no plugin surfaces" — no error, no degraded UI.

## Status

| Phase | What | Status |
|---|---|---|
| 0 | Spec ratification (this doc + ABI plan) | **Done** |
| 1 | Server surface storage + types crate + 3 HTTP routes | In Progress |
| 2 | `bv-client` surface fetch + content-addressed cache | Todo |
| 3 | GUI dynamic surface rendering | Todo |
| 4 | Form-hook ABI in Tauri backend | Todo |
| 5 | Auto-update via long-poll watcher | Todo |
| 6 | Operator UX redesign | Todo |
| 7 | Reference plugin (TOTP) + SDK + docs | Todo |
