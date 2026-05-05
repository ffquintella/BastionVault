# Feature: Import Password Manager Pro resources (external plugin)

## Current State

**All phases done — plugin parses + structures, GUI wizard walks the plan, encrypted-export rejection lands at validate time, version-matrix tests cover PMP 11/12/13 layouts, operator migration guide shipped.**

Shipped under [`plugins-ext/bastion-plugin-pmp`](../plugins-ext) (submodule):

- `validate` and `preview` / `import` operations over the standard line-delimited JSON-stdio plugin protocol; bootstrap-token check matches `bastion-plugin-xca`.
- Reads `.xls` (BIFF) and `.xlsx` (OOXML) via `calamine`. Header detection prefers the canonical `ExportPasswordView` sheet, falls back to the first sheet whose header carries every required column.
- Empty-cell sentinels (`""`, `N/A`, `null`, `none`, `-`) collapse uniformly to absent.
- PMP `OS Type` lookup table covers: `Linux` / `Windows` / `WindowsDomain` / `Unix` / `BSD` / `macOS` (server + os_type), `MS SQL Server` / `MySQL Server` / `PostgreSQL` / `Oracle DB Server` (database + engine), `Cisco IOS` (switch + vendor), `Fortimanager` (firewall + vendor), `Web Site Accounts` (website), `Generic Keys` / `Application Passwords` / `License Store` (KV), unknown values auto-slugged as a custom resource type. Per-call `type_overrides` flips the target while keeping the `vendor` / `engine` pre-fills.
- Multi-account collapse (one BV resource → N secrets) — verified against the operator's sample (99 rows → 55 resources + 8 KV blobs).
- KV routing under `secret/pmp-import/<batch-id>/<kind>/<resource>/<account>` with the JSON-envelope shape (`value_b64` + `pmp_resource_name` + `pmp_account` + `pmp_os_type` + preserved metadata + `tags[]`).
- Department → asset-group derivation (slug rule, `existing_asset_groups[]` echo, `members` + `secrets` arrays, `display_name` / `description` for new groups).
- Custom column handling (`preserve_unknown_columns` lifts non-canonical PMP columns into resource metadata / KV envelope; `tag_columns` routes them into `tags`).
- Unit tests (5) + fixture-driven integration tests (2) green; smoke-tested over real stdio against the operator's `.xls`.

Wizard shipped at `gui/src/routes/PmpImportPage.tsx`, route `/resources/import-pmp`, conditionally exposed via an "Import from PMP" button in the Resources page header that only renders when `pluginsList()` reports `pmp-import`. Three steps:

1. **Pick file** — Tauri file picker (`@tauri-apps/plugin-dialog`), runs `op=validate`, surfaces sheet/format/row-count + custom-column toggles (preserve-as-metadata + use-as-tag), batch ID, KV mount picker (filtered to `kv*` mount types), collision policy.
2. **Review** — summary metrics (resources / accounts / KV entries / asset groups), asset-groups panel with will-create / will-update badges, resources tree grouped by BV type with **per-resource expand showing the masked account list** (each row labelled `account` + sanitised key + `pmp_last_accessed`), KV-blobs tree, owner banner pinned at top.
3. **Run** — three-pass walk: (a) `read_asset_group` + `write_asset_group` per derived group (merge, not overwrite); (b) `write_resource` + `write_resource_secret`-per-account loop, with the account writes guaranteed to follow each resource write so `list_resource_secrets(name)` returns the full account set; (c) `write_secret` per KV blob under the operator-chosen mount. Live progress bar, error panel with per-target rows, post-run links to Resources / KV browser / Asset Groups.

**Phase 5 — hardening + docs**: encrypted-export rejection at validate time (CFB + UTF-16LE `EncryptedPackage` / `EncryptionInfo` sniff in the first 8 KiB; surfaces a friendly *"re-export without per-export encryption"* message instead of leaking the calamine error); synthetic-fixture matrix in [`tests/version_matrix.rs`](../plugins-ext/bastion-plugin-pmp/tests/version_matrix.rs) covering PMP 11.x minimal layout, PMP 12.x full layout with Department + custom columns, PMP 13.x reordered headers + KV-bound rows, plus regression tests for missing required columns / unknown PMP types / missing Password row-skip / encrypted-file rejection. Operator migration guide at [`plugins-ext/bastion-plugin-pmp/docs/migration-guide.md`](../plugins-ext/bastion-plugin-pmp/docs/migration-guide.md) — prerequisites, PMP-side export steps, three-step wizard walkthrough, post-import checklist (audit, asset-group ACLs, ownership transfer, re-run idempotency, cleanup), troubleshooting table.

**Pending:** None.

## Summary

Let an operator load a [ManageEngine **Password Manager Pro**](https://www.manageengine.com/products/passwordmanagerpro/)
(PMP) `ExportPasswordView` spreadsheet into BastionVault's
[Resource engine](resources.md) (and the KV engine, for the
non-resource-shaped row types — see *KV-bound row types* below).
The spreadsheet is the standard
PMP "Export Resources" report — a single sheet named
`ExportPasswordView` with one row per *(resource, account)* pair.

**The import always creates both a resource and the accounts that belong to it.** A single PMP `Resource Name` with N rows (one per account in PMP) yields one BastionVault resource and **N account secrets stored under that resource** via `write_resource_secret(name, key, data)` — keyed by the sanitised `User Account` and carrying the row's `Password` as the secret payload. Importing a resource without writing its accounts is never the right behaviour: the operator's mental model from PMP is *"this server has these logins"*, and the migration must preserve that linkage 1:1. See [Account secrets per resource](#account-secrets-per-resource) below for the contract.

This feature ships **as an external plugin** under
[`plugins-ext/bastion-plugin-pmp`](../plugins-ext) — *not* compiled
into the host. It sits alongside the existing reference plugins
(`bastion-plugin-totp`, `bastion-plugin-postgres`, `bastion-plugin-xca`)
and is loaded at runtime via the existing
[plugin system](plugin-system.md).

The host crate gains **zero** code: no new feature flag, no new
dep, no new HTTP routes. The plugin handles spreadsheet parsing
(both legacy `.xls` BIFF and modern `.xlsx`), the PMP-specific
column → resource-field mapping, and account de-duplication; the
GUI talks to it through the same
`POST /v1/sys/plugins/<name>/invoke` path the other plugins use,
then walks the returned plan against the existing
[Resource Tauri commands](resources.md#implementation).

Most PMP rows map onto BastionVault's Resource model. Three PMP
"resource types" don't fit the inventory shape (no hostname, no
account, no Connect button) — `Generic Keys`, `Application
Passwords`, and `License Store` — and route to the **KV engine**
instead (see [KV-bound row types](#kv-bound-row-types) below).

The Resource-bound mapping:

| PMP column | Maps to | Notes |
|---|---|---|
| `Resource Name` | `resource.name` | Multiple rows with the same value collapse into one resource (one row per account). Sanitised to `[A-Za-z0-9._-]`; collisions resolved per the GUI's collision policy. |
| `OS Type` | `resource.type` + `resource.metadata.os_type` | PMP overloads this column: real OS strings (`Linux`, `Windows`, `WindowsDomain`) become `os_type`; PMP resource-type strings (`MS SQL Server`, `MySQL Server`, `Oracle DB Server`, `PostgreSQL`, `Cisco IOS`, `Fortimanager`, `Web Site Accounts`, `Generic Keys`, `License Store`, `Application Passwords`) drive the BV `type` (`database`, `network_device`, `website`, `application`, …) per a fixed lookup table. |
| `DNS Name` | `resource.metadata.hostname` | Lower-cased; `N/A`/`null` → omitted. |
| `Resource URL` | `resource.metadata.url` (when type=website) or `metadata.console_url` | Falls back to `Console URL` for cloud-console rows. |
| `Description` | `resource.metadata.description` | |
| `Department` | **Asset group membership** + `resource.metadata.department` | The department string is slugified (lower-cased, `/` → `-`, whitespace collapsed) and used as an [asset group](asset-groups.md) name. The group is auto-created on first encounter; the imported resource name is appended to its `members` (and any KV blob path created for the same row to its `secrets`). The original PMP value is preserved verbatim under `metadata.department` for traceability. **Not** mapped to `metadata.owner` — see *Resource ownership* below. |
| `Location` | `resource.metadata.location` | |
| `Notes` | `resource.metadata.notes` | |
| `Ambiente` | `resource.tags += [<value>]` | Custom PMP field — kept verbatim (`Produção`, `Homologação`, `Desenvolvimento`, …); `null` → omitted. |
| `Instância` / `AWS Account` / `Role` | `resource.metadata.<key>` | Custom PMP fields — preserved verbatim under their original key. |
| `User Account` + `Password` | `resource_secret` under that resource | One secret per row. Secret name = sanitised `User Account`. The `Password` value is the secret payload. |
| `Last Accessed Time` | `secret.metadata.pmp_last_accessed` | Free-form ISO-8601-ish string preserved as metadata (informational only). |

The operator drives the import from a new GUI page (`Settings → Resources → Import from PMP`) that talks to the plugin's invoke endpoint. A preview pass parses the file and lists what would be imported (grouped by resource); a follow-up "run" pass walks the plan via the existing Resource Tauri commands. When the plugin isn't installed, the menu item simply doesn't render.

## Why an external plugin

- **Keeps the core small.** PMP migration is a one-shot tool for a specific class of operator. Bundling a spreadsheet parser (`calamine` pulls in BIFF + OOXML + zip + encoding decoders) into every host build pays a permanent cost for an episodic feature. A plugin flips that — operators who don't need it never compile or ship it.
- **Decoupled release cadence.** PMP's export columns drift between major releases (custom fields move, the sheet name has changed at least once historically). Tracking those shifts inside the host crate would mean a BastionVault release every time a PMP customer hits a new column layout. As a plugin, the operator drops in a new binary on their own schedule.
- **The plugin substrate already supports this.** Same shape as `bastion-plugin-xca`: process runtime, JSON-line stdio, no host capabilities required (the file is supplied by the operator; the plan is applied on the host side via existing Resource routes).
- **Plays well with the security model.** The plugin only parses + structures. All resource and secret writes happen on the host side via the regular policy-checked / audited Tauri command surface — ownership, sharing, ACLs, and audit log all engage as if the operator typed each entry by hand.

## Plugin runtime choice — Process, not WASM

The plugin lives in [`plugins-ext/bastion-plugin-pmp`](../plugins-ext) and uses the **out-of-process runtime** (the same one `bastion-plugin-xca` and `bastion-plugin-postgres` use), not WASM:

- **`calamine` is happy in WASM**, but encoding decoders (`encoding_rs`, needed for the legacy `.xls` BIFF code-page handling — the sample file is `Code page: 10000` Mac Roman) push the artefact past 2 MiB and the WASI text-codec story is still patchy.
- **Symmetry with `bastion-plugin-xca`.** Both are file-driven importers; sharing the runtime means operators uninstall/reinstall the same way they already do for XCA.
- **No new host audit surface.** The plugin uses the same crate ecosystem (`serde`, `serde_json`, `tokio`, `base64`) the host already vendors, plus `calamine` + `encoding_rs`. No new TLS / crypto / network deps.

The plugin protocol is line-delimited JSON over stdin/stdout — same as the postgres and XCA plugins — so the manifest declares `runtime = "process"` and the host's existing process supervisor launches the binary on demand.

## Host-side responsibilities (zero new code)

The host already exposes everything the plugin needs:

- **`POST /v1/sys/plugins`** — operator uploads the packed `.bvplugin` artefact. Existing route, no changes.
- **`POST /v1/sys/plugins/pmp-import/invoke`** — the plugin's endpoint. Body shape is plugin-defined; see *Plugin protocol* below.
- **Resource Tauri commands** — `write_resource`, `write_resource_secret`, `list_resources`, `read_resource` (for collision detection). The GUI invokes these directly with the data the plugin returned. No new resource routes needed.
- **KV Tauri command** — `write_secret` (`gui/src-tauri/src/commands/secrets.rs`). Used for the KV-bound row types (`Generic Keys`, `Application Passwords`, `License Store`) — see [KV-bound row types](#kv-bound-row-types).
- **Asset-group Tauri commands** — `list_asset_groups`, `read_asset_group`, `write_asset_group` (`gui/src-tauri/src/commands/asset_groups.rs`). The wizard reads the existing groups, creates the per-department groups it needs, and updates each group's `members` / `secrets` — see [Department → asset group](#department--asset-group).
- **Resource ownership** — every `write_resource` issued by the GUI is authenticated as the operator running the wizard; the existing `OwnerStore` automatically records that identity as the resource owner. No additional command needed — see [Resource ownership](#resource-ownership).
- **Resource type config** — the plugin's PMP→BV type lookup is a recommendation; the GUI lets the operator override per-resource and seeds any unrecognised PMP type into the existing custom-types config (`resource_types_write`) with the operator's consent.

## Plugin protocol

The plugin defines its own request shape on top of the substrate's `PluginRequest`. The host doesn't interpret these; the GUI constructs them and the plugin matches on `op`.

### `op = "validate"`

Cheap pass — opens the workbook, locates the `ExportPasswordView` sheet (or the first sheet whose header row matches the PMP column set), returns:

```json
{
  "ok": true,
  "format": "xls|xlsx",
  "sheet": "ExportPasswordView",
  "row_count": 99,
  "columns": ["Resource Name", "User Account", "Password", ...],
  "missing_required": [],
  "unknown_columns": ["Instância", "Ambiente", "AWS Account", "Console URL", "Role"]
}
```

`unknown_columns` lets the GUI render a "preserve as resource metadata?" toggle for each non-standard PMP column.

### `op = "preview"`

Full parse pass with no host writes. Input:

```json
{
  "op": "preview",
  "file_path": "/abs/path/to/ExportResources.xls",
  "preserve_unknown_columns": true,
  "type_overrides": { "Cisco IOS": "network_device" },
  "name_collision_policy": "skip|overwrite|rename",
  "tag_columns": ["Ambiente"]
}
```

(`file_b64` is also accepted in place of `file_path`, identical to the XCA plugin's contract — the plugin writes the bytes to a self-cleaning temp file because `calamine` needs a real `Read + Seek`.)

Returns:

```json
{
  "summary": {
    "resource_count": 63,
    "secret_count": 99,
    "skipped": [
      { "row": 17, "reason": "missing Resource Name" },
      { "row": 42, "reason": "missing User Account" }
    ],
    "type_distribution": { "server": 38, "database": 16, "switch": 1, "firewall": 2, "website": 5, "application": 0 },
    "kv_blob_count": 8,
    "kv_distribution": { "generic-keys": 5, "application-passwords": 2, "license-store": 1 },
    "asset_group_count": 4,
    "asset_groups_new": ["tic-infra", "eesp"],
    "asset_groups_existing": ["dba-team", "network-security"]
  },
  "kv_blobs": [
    {
      "kind": "generic-keys",
      "path": "secret/pmp-import/2026-05-05T1530/generic-keys/SOFTWARE-LICENSE-VAULT/admin",
      "data": {
        "value_b64": "<base64 password>",
        "pmp_resource_name": "SOFTWARE-LICENSE-VAULT",
        "pmp_account": "admin",
        "pmp_os_type": "Generic Keys",
        "description": "API key for vendor portal",
        "department": "TIC/INFRA",
        "ambiente": "Produção",
        "pmp_last_accessed": "2026-04-21 09:12:11.214"
      }
    }
  ],
  "asset_groups": [
    {
      "name": "tic-infra",
      "display_name": "TIC/INFRA",
      "description": "Imported from PMP department \"TIC/INFRA\"",
      "members": ["SRV-PSTDC1VDS0005", "SRV-EBSDC4VPR0001"],
      "secrets": ["secret/pmp-import/2026-05-05T1530/generic-keys/SOFTWARE-LICENSE-VAULT/admin"],
      "exists": false
    }
  ],
  "resources": [
    {
      "name": "SRV-PSTDC1VDS0005",
      "type": "database",
      "metadata": {
        "hostname": "pstdc1vds0005.fgv.br",
        "os_type": "linux",
        "description": "PostgresSQL",
        "department": "TIC/INFRA",
        "ambiente": "Desenvolvimento"
      },
      "asset_groups": ["tic-infra"],
      "tags": ["Desenvolvimento"],
      "secrets": [
        {
          "name": "root",
          "value_b64": "<base64 password>",
          "metadata": { "pmp_last_accessed": "2026-04-07 14:44:59.693" }
        }
      ]
    }
  ]
}
```

The `value_b64` envelope keeps non-UTF-8 bytes intact (PMP is happy to round-trip Latin-1 / Mac-Roman passwords). The GUI base64-decodes before calling `write_resource_secret` / `write_secret`.

### `op = "import"`

Returns the same payload as `preview`. The plugin **does not** call resource, KV, or asset-group routes itself — same security boundary as the XCA plugin. The GUI walks the response in three passes:

1. **Asset groups** (`asset_groups[]`) — for each group, `read_asset_group` to fetch the existing `members`/`secrets` (when `exists: true`); merge the import's contributions; `write_asset_group` with the union. New groups are created with `description = "Imported from PMP department <…>"`. Done first so the `members`/`secrets` arrays already reference paths that the next two passes are about to create — order is fine because asset-group membership is a name reference, not an FK.
2. **Resources** (`resources[]`) — one `write_resource` + N `write_resource_secret` per entry. Each `write_resource` runs as the operator's identity, so the existing `OwnerStore` records the operator as owner.
3. **KV blobs** (`kv_blobs[]`) — one `write_secret` per entry.

All three passes respect the chosen `name_collision_policy`.

If a future version wants the plugin to drive the writes itself, the substrate's existing `bv.storage_*` capabilities are scoped to the plugin's own UUID prefix and would not let the plugin reach the resource mount — so the GUI-orchestrated model is also the only one the substrate currently allows.

## Type / OS-Type translation table

The fixed PMP→BV lookup the plugin ships with (overridable per call via `type_overrides`):

| PMP `OS Type` value | BV `type` | BV `os_type` |
|---|---|---|
| `Linux`, `Unix`, `BSD` | `server` | `linux` / `unix` / `bsd` |
| `Windows` | `server` | `windows` |
| `WindowsDomain` | `server` | `windows` (note: tag `domain-account`) |
| `MS SQL Server`, `MySQL Server`, `PostgreSQL`, `Oracle DB Server` | `database` | (unset) — pre-fills `engine` to the canonical id (`mssql` / `mysql` / `postgresql` / `oracle`). Depends on [resource-types-firewall-switch-db](resource-types-firewall-switch-db.md). |
| `Cisco IOS` | `switch` (default; overridable to `firewall` for ASA, or `network_device` for routers / wireless via `type_overrides`) | (unset) — pre-fills `vendor=cisco`. Depends on [resource-types-firewall-switch-db](resource-types-firewall-switch-db.md). |
| `Fortimanager` | `firewall` | (unset) — pre-fills `vendor=fortinet`. Depends on [resource-types-firewall-switch-db](resource-types-firewall-switch-db.md). |
| `Web Site Accounts` | `website` | (unset) |
| `Generic Keys` | **KV blob** under `secret/pmp-import/<batch-id>/generic-keys/<resource>/<account>` | n/a — see [KV-bound row types](#kv-bound-row-types) below. |
| `Application Passwords` | **KV blob** under `secret/pmp-import/<batch-id>/application-passwords/<resource>/<account>` | n/a |
| `License Store` | **KV blob** under `secret/pmp-import/<batch-id>/license-store/<resource>/<account>` | n/a |
| `Arquivos de Incidentes` | **KV blob** under `secret/pmp-import/<batch-id>/incident-files/<resource>/<account>` | n/a — incident attachments. |
| `Resource Type`, **anything else not in this table** | **KV blob** under `secret/pmp-import/<batch-id>/other/<resource>/<account>` | The Resources inventory is for **connectable devices** (server / database / firewall / switch / network device / website / application). Unrecognised PMP `OS Type` values go to KV by default — operators who want a custom resource type for these register it via Settings → Resource Types and re-run with `type_overrides: { "<PMP value>": "<bv type id>" }`. The reverse direction also works: `type_overrides: { "Linux": "kv:other" }` forces a normally-resource row into KV. |

## KV-bound row types

PMP rows describe two distinct things: **connectable devices** (servers, databases, firewalls, switches, websites, applications) and **passive credentials / artefacts** (keys, licences, application passwords, incident attachments, custom catch-all categories the operator's PMP install added). The Resources inventory is for the first category — anything you'd open a session against. Everything else routes to the **KV engine** under `secret/pmp-import/<batch-id>/<kind>/<resource>/<account>`.

That's the rule. The known PMP types that always go to KV are `Generic Keys` (`generic-keys`), `Application Passwords` (`application-passwords`), `License Store` (`license-store`), and `Arquivos de Incidentes` (`incident-files`). Everything else not in the connectable-device list — including PMP's `Resource Type` value and any custom PMP resource type the operator's install defines — routes to KV under the catch-all `other`. Operators who want a custom BV resource type for one of these register it via **Settings → Resource Types** and re-run with `type_overrides: { "<PMP OS Type value>": "<bv type id>" }`. The reverse override `type_overrides: { "Linux": "kv:other" }` is also supported and forces a normally-resource row into KV.

Mapping rules:

- **No resource record is created** for these rows. The Resource page would otherwise show empty hostname / no-Connect cards that clutter the inventory.
- **Each row → one KV entry.** Path layout:

  ```
  secret/pmp-import/<batch-id>/generic-keys/<sanitised-resource-name>/<sanitised-account>
  secret/pmp-import/<batch-id>/application-passwords/<sanitised-resource-name>/<sanitised-account>
  secret/pmp-import/<batch-id>/license-store/<sanitised-resource-name>/<sanitised-account>
  ```

  When the row has no `User Account` (PMP allows blank accounts on `License Store` rows), the trailing segment becomes the literal `default` and the original resource name is preserved one level up.

- **The KV value is a JSON object**, not the bare password — this lets us preserve the row's PMP context (description, department, custom fields, last-accessed timestamp) alongside the secret. Shape:

  ```json
  {
    "value_b64": "<base64 of the Password column>",
    "pmp_resource_name": "<original Resource Name>",
    "pmp_account": "<original User Account, or empty>",
    "pmp_os_type": "Generic Keys|Application Passwords|License Store",
    "description": "...",
    "owner": "...",
    "ambiente": "...",
    "instancia": "...",
    "aws_account": "...",
    "console_url": "...",
    "role": "...",
    "pmp_last_accessed": "..."
  }
  ```

  Empty / `N/A` / `null` PMP fields are omitted, mirroring the resource-bound rules. The GUI's KV viewer renders this object natively; `value_b64` is masked behind the standard reveal control.

- **Mount.** The default `secret/` mount is used. If the operator's deployment uses a different default KV mount, step 1 of the wizard exposes a "KV mount" picker (populated from `list_mounts` filtered to KV) defaulting to whatever mount has `default = true`.

- **Collision policy** applies path-by-path the same way it does for resources: `Skip` (no-op if the path exists), `Overwrite` (KV write-on-write), `Rename` (append `-2`, `-3`, …).

- **Batch tag.** The same `pmp-import:<batch-id>` tag the wizard applies to resources is also written into the KV entry's `metadata.tags` so the operator can locate every blob from a given import in one place.

- **Why not the `application` resource type?** Because there's no useful inventory shape for these rows — they have no host, no Connect target, and frequently no account. Forcing them into `application` resources hides them behind a UI built around hostname + Connect button, and the operator ends up navigating to the resource just to copy a JSON value. The KV engine is the right surface and already ships the search, history, and ACL primitives this content needs.

## Resource ownership

Every resource and KV blob created by the importer is owned by **the operator running the wizard**, not by anyone named in the spreadsheet. PMP's `Department` column is a category (a team or cost-centre name), not an identity, so it would be wrong to translate it into BV `owner` — that field is consulted by ACLs and the sharing UI as a real principal.

Concretely:

- The wizard's writes (`write_resource`, `write_resource_secret`, `write_secret`, `write_asset_group`) all execute under the operator's existing token. The host's `OwnerStore` already keys ownership off the calling identity for every `write_resource`, so the operator is recorded as owner without an explicit `owner` field in the request body — the same path that already runs when an operator types a resource in by hand.
- The plugin's preview output **deliberately does not include** an `owner` field on resources or KV blobs. If `type_overrides` or future config flags want to set one, that must be the operator's identity, surfaced via a future host-side hook — not a value parsed from the spreadsheet.
- Operators who need a different post-import owner re-share or transfer ownership through the standard `transfer_resource_owner` flow (existing UI under Sharing → Transfer Owner). The import does not try to anticipate that.
- The PMP `Department` value is preserved verbatim under `metadata.department` (and inside the KV blob envelope) so the operator can later locate or filter resources by their original PMP department string, independent of the auto-created asset group.

## Account secrets per resource

The point of this importer is to land both halves of every PMP row: the resource (the server / database / firewall / …) **and** the account credentials that belong to it. The two are written through different Tauri commands, but they're a single logical unit — the wizard never writes a resource without then writing its accounts.

Concretely, for every selected resource in the plan:

1. The wizard calls `write_resource(name, metadata)` once. The `OwnerStore` records the importing operator as the resource owner.
2. The wizard then iterates `resource.secrets[]` and calls `write_resource_secret(name, key, data)` once per account. **Key** = the sanitised `User Account` (PMP's "User Account" column, run through the same `[A-Za-z0-9._-]` sanitiser as the resource name). **Value** = `{ value: <password as UTF-8 string>, pmp_last_accessed: <Last Accessed Time> }`. Multiple rows with the same `Resource Name` collapse into one resource carrying N distinct account secrets — they are never written as N separate resources.
3. If `write_resource` fails for some reason, **the account writes for that resource are skipped** rather than orphaned under a non-existent resource. The errors panel surfaces both the resource failure and the count of skipped accounts.

The plugin's `preview` / `import` plan shape encodes this directly. Each `resources[]` entry carries:

```json
{
  "name": "SRV-PSTDC1VDS0005",
  "type": "database",
  "metadata": { ... },
  "asset_groups": ["tic-infra"],
  "tags": ["Desenvolvimento"],
  "secrets": [
    { "name": "root", "value_b64": "<base64 password>",
      "metadata": { "pmp_last_accessed": "2026-04-07 14:44:59.693" } },
    { "name": "postgres", "value_b64": "...",
      "metadata": { "pmp_last_accessed": "2025-11-20 08:01:14.122" } }
  ]
}
```

`secrets[]` is **never empty** for a resource that the importer surfaces — a row with a missing `User Account` or `Password` is dropped from the plan with a `skipped` reason rather than producing an account-less resource. (Resources that would be entirely account-less can't legitimately come from an `ExportPasswordView` row, since each PMP row mandates both fields; we still defend against malformed exports.)

The wizard's review step shows the count under each resource (`{r.secrets.length} account(s)`) and the per-account list expands into the masked-password view, so the operator can confirm the resource→accounts linkage before clicking "Run".

## Department → asset group

PMP's `Department` is a recurring grouping label across many resources (`TIC/INFRA`, `EESP`, `DBA`, …). BastionVault's [Asset Groups](asset-groups.md) is the existing primitive for "a named set of resources + KV paths that share an ACL". The importer maps `Department` onto an asset group so the operator can run a single `share` or policy attach against the imported set.

Mapping rules:

- **Slug.** The asset-group `name` is the slugified department string: lower-cased, accents preserved as-is (BV asset-group names accept Unicode), `/` and whitespace collapsed to single `-`, leading/trailing `-` trimmed. Examples: `TIC/INFRA` → `tic-infra`, `EESP` → `eesp`, `Direção Geral` → `direção-geral`. The pre-slug string is preserved as `display_name` on the group's description for legibility.
- **Auto-create on first encounter.** During `preview`, the plugin checks the GUI-supplied `existing_asset_groups[]` list (the wizard fetches `list_asset_groups` once and passes the names down) and reports each group as either `exists: true` or `exists: false`. The wizard surfaces that to the operator: existing groups show their current member count next to "+N from import"; new groups carry a "will be created" badge.
- **Merge, don't overwrite.** When the operator confirms, the wizard fetches each existing group's full record (`read_asset_group`), unions the import's contributions into `members` (resource names) and `secrets` (KV paths), and writes back. The operator's prior membership of those groups is never removed.
- **Group description on creation.** New groups get `description = "Imported from PMP department \"<original value>\". Created by <operator> on <ISO date>."` — searchable from the asset-group browser.
- **`null` / `N/A` / empty department.** The row is *not* added to any asset group (and `metadata.department` is omitted). No `unassigned` group is auto-created — operators dislike default catch-all groups in our experience.
- **Per-row override.** Step 2 of the wizard exposes a per-row "Asset group" dropdown pre-selected with the auto-derived value plus an "(none)" option, so an operator can pull a single resource out of the bulk grouping at review time without editing the spreadsheet.
- **No automatic policy attach.** Creating an asset group does not bind a policy to it. Asset-group ACLs are an explicit operator step in the standard Asset Groups UI; the importer just establishes the membership.

## GUI

`Settings → Resources → Import from PMP` — three-step wizard, hidden when the plugin isn't registered:

1. **Pick file.** Native file picker (`*.xls`, `*.xlsx`). Runs `validate`. If `unknown_columns` is non-empty, shows a checkbox grid: *Preserve as metadata? Use as tag?* per column.
1.5. **Existing asset groups fetched.** Right after `validate`, the wizard calls `list_asset_groups` and passes the result back to the plugin in the `preview` request as `existing_asset_groups[]` so the plan can mark each derived department-group with `exists: true|false`. (Listed as a separate step here for clarity — in practice it's transparent.)

2. **Review.** Two grouped trees side by side:
   - **Resources** — grouped by inferred BV type (`server` / `database` / `firewall` / `switch` / `website` / `network_device` / `application`). Per-resource row shows: name, type, hostname, secret count, derived asset-group chip. Per-resource expand reveals the account list with the password masked + "Reveal" button. Per-row checkbox for inclusion; per-resource type override dropdown; per-row asset-group dropdown (defaults to the derived department group, "(none)" option available).
   - **KV blobs** — grouped by PMP kind (`Generic Keys`, `Application Passwords`, `License Store`). Each row shows the destination KV path (editable), the source PMP resource + account, the derived asset-group chip, and the masked value. KV-mount picker at the top of the section.
   - **Asset groups summary** — collapsible panel listing every derived group with: slug, original department string, member count contribution, "+N existing", "Will create" / "Will update" badge.
   - Single collision-policy dropdown (`Skip` / `Overwrite` / `Rename`) governs all three passes.
   - **Owner banner.** A non-dismissable info banner reads: *"All imported resources and KV entries will be owned by **&lt;operator email&gt;**. PMP's Department column maps to an asset group, not an owner."*
3. **Run.** Streams progress as the GUI walks the plan in three passes: (a) `read_asset_group` + `write_asset_group` for each derived department group; (b) `write_resource` + `write_resource_secret` for each Resource entry (the host's `OwnerStore` records the operator as owner); (c) `write_secret` for each KV blob. Final summary with three links — "view in Resources page" (filtered by `pmp-import:<batch-id>` tag), "view in KV browser" (filtered to `secret/pmp-import/<batch-id>/`), and "view asset groups" (filtered to the new + updated groups from this import).

Plugin-presence check: the GUI lists `/v1/sys/plugins` and looks for `name = "pmp-import"`. If absent, the menu entry under `Settings → Resources` is hidden — no broken link, no stub page.

## Out of scope (explicit)

- **Round-trip export back to PMP.** One-way migration only.
- **PMP API live sync.** This feature only consumes the static `ExportPasswordView` spreadsheet. A live REST connector would be a separate plugin (it'd need network capability + an API key — a bigger conversation).
- **Per-account access policies.** PMP's per-resource ACLs don't map to BV's policy model 1:1; the operator is recorded as owner on every created resource and KV blob (see [Resource ownership](#resource-ownership)), and they re-share via the standard ShareStore flow afterwards. Asset-group policy attach is also out of scope — the importer creates the groups, the operator binds policies to them by hand.
- **PMP ticket / incident attachments** (`Arquivos de Incidentes` entries). Skipped with a reason — the spreadsheet doesn't carry the actual blobs.
- **Encrypted PMP exports.** Recent PMP versions can encrypt the export with a per-export key; this is detected and surfaced as `unsupported_format` in `validate` — operator must re-export unencrypted.

## Phases (all inside the plugin repo, none in the host)

| # | Title | Notes |
|---|---|---|
| 1 | **Reader skeleton + manifest + invoke wiring** | `bastion-plugin-pmp` skeleton, `runtime = "process"`, declares the three operations. `validate` works against `.xls` and `.xlsx`; `preview` returns resources + secrets with no PMP-custom-column handling yet. Packaged via `bv-plugin-pack`. |
| 2 | **Column normalisation + type lookup table** | `N/A` / `null` / empty-string sentinels collapsed to absent fields; PMP-overloaded `OS Type` split into BV `type` + `os_type`; fixed lookup table; per-call `type_overrides`. Multi-row-per-resource collapse. |
| 2.5 | **KV-bound row routing** | `Generic Keys` / `Application Passwords` / `License Store` rows split out of `resources[]` into a dedicated `kv_blobs[]` array with the JSON-envelope shape and the `secret/pmp-import/<batch-id>/<kind>/...` path layout. |
| 2.6 | **Department → asset group derivation** | Slug rule, `existing_asset_groups[]` input, `asset_groups[]` output, per-row `asset_groups` reference. Plugin-side only — wizard wiring (read/write asset groups, owner banner) lands in Phase 4. |
| 3 | **Custom column handling** | `unknown_columns` reporting; `preserve_unknown_columns` + `tag_columns` flags; verbatim metadata preservation. Sample fixture from a real PMP export drives the unit tests (with passwords redacted). |
| 4 | **GUI wizard** | `Settings → Resources → Import from PMP` page. Plugin-presence check, three-step flow, per-item progress, collision policy, batch-id tag. Auto-registers any new custom resource type the operator approves. |
| 5 | **Hardening + docs** | Fixture matrix (PMP 11 / 12 `.xls`, PMP 13 `.xlsx`, mixed-encoding samples), operator-facing migration guide in the plugin's `README.md`. |

## Open questions

- **Plugin signing.** Same question as XCA — should this ship signed under a BastionVault publisher key from day one, or stay `accept_unsigned = true` until the operator workflow for publisher keys is documented?
- **Custom types vs. metadata.** When PMP's `OS Type` is unrecognised (e.g. `Arquivos de Incidentes`), should the plugin (a) fail-soft into the `application` BV type with a warning, or (b) auto-register a slugified custom resource type via `resource_types_write`? Current lean: (b), gated behind an explicit operator confirmation in step 1 of the wizard.
- **Password preservation.** Some PMP installations store passwords with trailing whitespace or embedded control characters that PMP itself trims on display. The plugin currently preserves bytes exactly. Worth a one-line note in the wizard's review step ("password lengths preserved exactly — trailing whitespace not stripped").

## Acceptance criteria

- The plugin builds standalone in [`plugins-ext/bastion-plugin-pmp`](../plugins-ext), packs to a `.bvplugin`, and registers cleanly via the existing `POST /v1/sys/plugins` route. **The host crate has no new code, no new dep, no new feature flag.**
- An operator can pick a real PMP `ExportPasswordView` spreadsheet (both `.xls` and `.xlsx`) and end up with new BastionVault resources whose `read_resource` + `read_resource_secret` flows return the imported metadata and account passwords.
- **For every imported resource, every account from the corresponding PMP row(s) is written as a `resource_secret` under that resource** — keyed by the sanitised `User Account`, payload includes the row's `Password`. Verifiable via `list_resource_secrets(name)` returning N entries for an N-account PMP resource.
- Multi-account resources collapse into one resource with N secrets — no duplicate resources from the same `Resource Name`.
- **Every imported resource and KV blob is owned by the operator running the wizard** (verifiable via `get_resource_owner` after the import). The plan output never carries an operator-derived `owner` field, and PMP's `Department` is **not** written into `metadata.owner`.
- **Each distinct PMP `Department` value yields one asset group** whose `members` includes every imported resource from that department and whose `secrets` includes every KV blob from that department. Existing groups with the same slug are merged into, not overwritten — pre-existing members survive a re-run. Rows with empty / `N/A` / `null` Department are not added to any group.
- Rows whose `OS Type` is `Generic Keys`, `Application Passwords`, or `License Store` land **only** in the KV engine under `secret/pmp-import/<batch-id>/<kind>/...` — no resource record is created for them, and the resulting `read_secret` call returns the JSON-shaped envelope (PMP context + base64 password).
- Uninstalling the plugin removes the menu entry; reinstalling it brings it back without restart.
- The import is idempotent in `Skip` collision mode (running twice is a no-op).
- Imported resources carry a `pmp-import:<batch-id>` tag the operator can use to filter or bulk-undo via the standard Resources page.
