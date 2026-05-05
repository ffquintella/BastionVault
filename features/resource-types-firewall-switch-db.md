# Feature: First-class `firewall`, `switch`, and refined `database` resource types

## Current State

**Done — all three phases shipped.**

- **Phase 1 — type definitions** — `firewall` and `switch` builtins added to [`gui/src/lib/resourceTypes.ts`](../gui/src/lib/resourceTypes.ts) (vendor enums, HA role / layer, firmware, model, location/site, owner; SSH-22 connect defaults). `database.engine` converted from free text to a closed enum (PostgreSQL, MySQL, MariaDB, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, SQLite, Other); `engine_version` + `tls_required` added. `network_device.device_type` placeholder narrowed to "Router / Load Balancer / Wireless". 4 new unit tests (vendor / HA / connect / engine / placeholder narrowing) green alongside the existing 9.
- **Phase 2 — PMP importer alignment** — the `bastion-plugin-pmp` plugin's lookup table maps `Fortimanager` → `firewall` (default `vendor=fortinet`) and `Cisco IOS` → `switch` (default `vendor=cisco`, overridable via `type_overrides`); the four PMP DB rows pre-fill the canonical `engine` id. Verified end-to-end against the operator's real PMP fixture (firewall + switch + database all show up in the wizard's type-distribution panel).
- **Phase 3 — docs** — built-in resource type table in [`features/resources.md`](resources.md) updated; CHANGELOG `[Unreleased] → Added` entry recorded.

## Summary

Add two new built-in resource types — **`firewall`** and **`switch`** — and tighten the existing **`database`** type so it carries a structured engine enum instead of a free-text `engine` field. These are the prerequisite resource shapes for the [Password Manager Pro importer](pmp-import.md): PMP exports list firewalls, switches, and per-engine databases as distinct rows, and the importer needs first-class targets to map them onto.

The work is **GUI-side only**. Resource types live in `gui/src/lib/resourceTypes.ts` and the operator-editable config served by the existing `resource_types_read` / `resource_types_write` Tauri commands; no host-crate code, no schema migration, no new Tauri command. Existing resources keyed under `network_device` keep working untouched — the new types are additive.

## Motivation

Today, `gui/src/lib/resourceTypes.ts` exposes a single generic `network_device` builtin with a free-text `device_type` field (`"Switch / Router / Firewall"`). That's fine for a small inventory, but it has three concrete pain points:

- **Visual / filter parity.** Operators want to filter "all firewalls" or "all switches" without remembering whether they typed `Switch` vs `switch` vs `L3 Switch` in `device_type`.
- **Connect defaults.** Firewalls and switches have meaningfully different sane defaults (firewalls often expose a captive-portal HTTPS UI on `:8443` alongside SSH; switches usually expose only SSH/console). The per-type `connect.default_ports` block (already shipped for server / website) lets us pre-seed the right protocol per type.
- **Importers need a stable target.** The PMP importer's lookup table maps `Fortimanager` → firewall and `Cisco IOS` → switch. Without dedicated types, the importer would have to write `network_device` everywhere and stuff the discriminator into a metadata field, defeating the inventory's main filter axis.

`database` already exists, but its `engine` field is free-text. PMP exports the engine as a closed set (`MS SQL Server`, `MySQL Server`, `Oracle DB Server`, `PostgreSQL`); converting the field to a `select` lets the importer round-trip cleanly and lets the GUI render an engine-coloured badge.

## What changes

### New: `firewall` builtin

```ts
firewall: {
  id: "firewall",
  label: "Firewall",
  color: "error",
  fields: [
    { key: "hostname",      label: "Hostname",      type: "fqdn", placeholder: "fw-edge-01" },
    { key: "ip_address",    label: "Management IP", type: "ip",   placeholder: "10.0.0.1" },
    { key: "port",          label: "Mgmt Port",     type: "number", placeholder: "22" },
    { key: "vendor",        label: "Vendor",        type: "select",
      options: [
        { value: "",          label: "(unset)" },
        { value: "fortinet",  label: "Fortinet" },
        { value: "palo_alto", label: "Palo Alto" },
        { value: "cisco",     label: "Cisco" },
        { value: "checkpoint",label: "Check Point" },
        { value: "juniper",   label: "Juniper" },
        { value: "sophos",    label: "Sophos" },
        { value: "pfsense",   label: "pfSense / OPNsense" },
        { value: "other",     label: "Other" },
      ] },
    { key: "model",         label: "Model",        type: "text", placeholder: "FortiGate 100F" },
    { key: "firmware",      label: "Firmware",     type: "text", placeholder: "FortiOS 7.4.3" },
    { key: "ha_role",       label: "HA Role",      type: "select",
      options: [
        { value: "",           label: "(unset)" },
        { value: "standalone", label: "Standalone" },
        { value: "active",     label: "HA — Active" },
        { value: "passive",    label: "HA — Passive" },
      ] },
    { key: "site",          label: "Site / Zone",  type: "text", placeholder: "DC-1 / DMZ" },
    { key: "owner",         label: "Owner",        type: "text", placeholder: "network-security" },
  ],
  connect: { enabled: true, default_ports: { ssh: 22 } },
}
```

### New: `switch` builtin

```ts
switch: {
  id: "switch",
  label: "Switch",
  color: "warning",
  fields: [
    { key: "hostname",     label: "Hostname",      type: "fqdn", placeholder: "sw-core-01" },
    { key: "ip_address",   label: "Management IP", type: "ip",   placeholder: "10.0.0.2" },
    { key: "port",         label: "Mgmt Port",     type: "number", placeholder: "22" },
    { key: "vendor",       label: "Vendor",        type: "select",
      options: [
        { value: "",          label: "(unset)" },
        { value: "cisco",     label: "Cisco" },
        { value: "arista",    label: "Arista" },
        { value: "juniper",   label: "Juniper" },
        { value: "hpe_aruba", label: "HPE Aruba" },
        { value: "huawei",    label: "Huawei" },
        { value: "mikrotik",  label: "MikroTik" },
        { value: "ubiquiti",  label: "Ubiquiti" },
        { value: "other",     label: "Other" },
      ] },
    { key: "model",        label: "Model",         type: "text", placeholder: "Catalyst 9300" },
    { key: "firmware",     label: "Firmware / OS", type: "text", placeholder: "IOS-XE 17.12.1" },
    { key: "switch_layer", label: "Layer",         type: "select",
      options: [
        { value: "",  label: "(unset)" },
        { value: "l2", label: "L2 (access / distribution)" },
        { value: "l3", label: "L3 (core / routed)" },
      ] },
    { key: "stack_member_count", label: "Stack Members", type: "number", placeholder: "1" },
    { key: "location",     label: "Location",     type: "text", placeholder: "DC-1 Rack A3" },
    { key: "owner",        label: "Owner",        type: "text", placeholder: "network-team" },
  ],
  connect: { enabled: true, default_ports: { ssh: 22 } },
}
```

### Refined: `database` builtin

Replace the existing free-text `engine` field with a `select`, and add `tls_required` so the importer can flag PMP rows that came from a TLS-only connection:

```ts
database: {
  id: "database",
  label: "Database",
  color: "error",
  fields: [
    { key: "hostname",      label: "Hostname",       type: "fqdn", placeholder: "db01.example.com" },
    { key: "ip_address",    label: "IP Address",     type: "ip",   placeholder: "10.0.2.10" },
    { key: "port",          label: "Port",           type: "number", placeholder: "5432" },
    { key: "engine",        label: "Engine",         type: "select",
      options: [
        { value: "",            label: "(unset)" },
        { value: "postgresql",  label: "PostgreSQL" },
        { value: "mysql",       label: "MySQL" },
        { value: "mariadb",     label: "MariaDB" },
        { value: "mssql",       label: "Microsoft SQL Server" },
        { value: "oracle",      label: "Oracle Database" },
        { value: "mongodb",     label: "MongoDB" },
        { value: "redis",       label: "Redis" },
        { value: "elasticsearch", label: "Elasticsearch / OpenSearch" },
        { value: "sqlite",      label: "SQLite" },
        { value: "other",       label: "Other" },
      ] },
    { key: "engine_version", label: "Engine Version", type: "text", placeholder: "16.2" },
    { key: "database_name",  label: "Database Name",  type: "text", placeholder: "myapp_production" },
    { key: "tls_required",   label: "TLS Required",   type: "select",
      options: [
        { value: "",     label: "(unset)" },
        { value: "yes",  label: "Yes" },
        { value: "no",   label: "No" },
      ] },
    { key: "owner",          label: "Owner",          type: "text", placeholder: "dba-team" },
  ],
}
```

### Existing `network_device` stays

`network_device` remains as the catch-all for routers, load balancers, wireless controllers, console servers, and anything that isn't cleanly a switch or a firewall. Its `device_type` placeholder is updated to drop "Switch / Firewall" since those are now first-class.

## Backwards compatibility

- **No data migration.** Existing `network_device` resources keep working — their type id never changes. Operators choosing to reclassify a device as `switch` or `firewall` re-save through the existing edit modal; the type id flips and the new fields render. Old `device_type` / `manufacturer` strings can be lifted into the new `vendor` field manually or via a one-shot script.
- **Existing `database.engine` strings** survive as raw values in the resource record. The new `select` widget shows the literal string under "Other" until the operator picks a canonical option. The PMP importer normalises on the way in so newly-imported rows always carry a canonical id.
- **Saved type config takes precedence.** `mergeTypeConfig()` already returns the saved config verbatim when present, so deployments that have customised types won't get the new builtins until they reset to defaults or copy the new entries in via Settings → Resource Types. Documented in the release notes.

## PMP importer integration

Updates to [`features/pmp-import.md`](pmp-import.md) — the lookup table replaces `network_device` rows with the new types:

| PMP `OS Type` value | BV `type` (was) | BV `type` (now) | Notes |
|---|---|---|---|
| `Fortimanager` | `network_device` | `firewall` | Default `vendor=fortinet`. |
| `Cisco IOS` | `network_device` | `switch` | Default `vendor=cisco`; the operator can override to `firewall` (Cisco ASA) or to plain `network_device` (router/wireless) at preview time via `type_overrides`. |
| `MS SQL Server` | `database` | `database` | Default `engine=mssql`. |
| `MySQL Server` | `database` | `database` | Default `engine=mysql`. |
| `Oracle DB Server` | `database` | `database` | Default `engine=oracle`. |
| `PostgreSQL` | `database` | `database` | Default `engine=postgresql`. |

The importer carries the engine / vendor default through `type_overrides`'s value side as `{type, defaults: {<key>: <value>}}` so the GUI's preview step shows the pre-filled fields.

## GUI

- **Resources page** filter chips automatically pick up the new types — the page reads `typeConfig` and renders one chip per id, so no `ResourcesPage.tsx` changes are required beyond the file ordering.
- **Settings → Resource Types** already lets operators add/edit types; the new builtins simply appear pre-populated.
- **Connect button** lights up automatically for `firewall` and `switch` (both declare `connect.enabled = true` with `default_ports.ssh = 22`); SSH × Secret credential source works out of the box. RDP is intentionally not exposed for these — vendors that ship an HTTPS GUI (FortiGate, ASA SDM, MikroTik WebFig) are still launched manually until the website-style "open in browser" connect path is generalised (out of scope here).

## Out of scope

- **Vendor-specific config-fetch / show-running automation** for switches and firewalls. The new types are inventory + credential-grouping shapes; running `show config` over the connection is a future, separate `bastion-plugin-net-config` plugin.
- **Layer-7 firewall policy modelling** (rule sets, NAT tables, VPN tunnels). Out of scope — that's a network management tool, not a vault.
- **Splitting `router` out as its own builtin.** Demand has been low; routers stay under `network_device` until an importer or operator request shows up.

## Phases

| # | Title | Notes |
|---|---|---|
| 1 | **Type definitions in `resourceTypes.ts`** | Add `firewall` + `switch` builtins; refine `database`; loosen `network_device` placeholder. Unit tests in `gui/src/test/resourceTypes.test.ts` for `getTypeDef("firewall")` / `getTypeDef("switch")` returning the new defs. |
| 2 | **PMP importer alignment** | Update [`features/pmp-import.md`](pmp-import.md)'s lookup table + the plugin's translation table once the plugin lands. |
| 3 | **Docs** | Update [`features/resources.md`](resources.md) "Built-in Resource Types" table with the three new rows; add a CHANGELOG entry. |

## Acceptance criteria

- `firewall` and `switch` appear as built-in choices in the create/edit-resource modal with their respective fields.
- Existing `network_device` resources continue to render and edit unchanged.
- The PMP importer (when it lands) maps `Fortimanager` → `firewall` and `Cisco IOS` → `switch` by default, with per-row override available in the wizard.
- `database.engine` is a closed enum in the GUI; legacy free-text values display under "Other" until manually reclassified.
- The Connect button is available on `firewall` and `switch` resources via SSH-on-22 by default, and disabling it via Settings → Resource Types still works (uses the existing `connect.enabled` toggle).
