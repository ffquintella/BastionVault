# Feature: Resource Management

## Summary

Add a "Resources" abstraction layer that lets users organize secrets by the infrastructure entity they belong to -- servers, network devices, websites, databases, applications, or custom types. A Resource is a metadata record (hostname, IP, OS, location, owner, tags) that groups related secrets under a common identity.

## Motivation

BastionVault stores secrets as flat key-value pairs in KV engines. In practice, operators manage credentials for specific resources: the admin password for a firewall, the SSH key for a server, the API token for a SaaS app. Without a resource concept, users must impose their own naming convention (e.g., `firewall-01/admin`) and mentally track which secrets belong to which device.

The Resources layer provides:
- **Inventory**: a searchable, filterable registry of all managed resources with metadata (type, hostname, IP, location, owner, tags, notes).
- **Grouping**: each resource has a dedicated namespace for its secrets, making it clear what credentials belong to what.
- **Dynamic types**: built-in types for common categories plus user-defined custom types.

## Current State

**Done.** Implementation landed beyond the original spec: resources live in a **dedicated barrier-encrypted storage engine** (`src/modules/resource/mod.rs`, 905 lines, auto-mounted at `resource/`) rather than as a prefix inside the KV engine. This gives clean isolation from KV and a per-engine audit trail.

Shipped pieces:

- **Server module** (`src/modules/resource/mod.rs`) — metadata CRUD, per-secret CRUD, append-only history log (`hist/<name>/<nanos>` — who/when/which fields, no values), per-secret version snapshots (`smeta/` + `sver/`), built-in + custom resource types stored under the system config space. Includes module-level tests.
- **Tauri command surface** (`gui/src-tauri/src/commands/resources.rs`) — 14 commands: `list_resources`, `read_resource`, `write_resource`, `delete_resource`, `list_resource_secrets`, `read_resource_secret`, `write_resource_secret`, `delete_resource_secret`, `list_resource_history`, `list_resource_secret_versions`, `read_resource_secret_version`, `resource_types_read`, `resource_types_write`, plus ownership/transfer wiring.
- **GUI** (`gui/src/routes/ResourcesPage.tsx`, 1,219 lines) — list page with type filter + search, detail view with Info / Secrets / History / Sharing tabs, create/edit modal with dynamic type-driven fields, masked secret values with reveal-on-demand, version browser, ownership + admin-transfer modal.
- **Integration** — ownership via `OwnerStore`, sharing via `ShareStore` (`ShareTargetKind::Resource`), membership in Asset Groups, all respected by the ACL evaluator and list-filter.

Note: the spec's `kv/_resources/...` layout in the *Data Model* section below is **historical** — it describes the original plan. The shipped layout is documented in the module header (`meta/` `hist/` `secret/` `smeta/` `sver/` inside the `resource/` mount).

## Data Model

Resources are stored in the existing KV engine at a reserved prefix (`_resources/`). No new secret engine or schema changes are required.

### Storage Layout

```
kv/_resources/web-server-01      → Resource metadata (JSON)
kv/_resources/core-switch-a      → Resource metadata (JSON)
kv/web-server-01/root-password   → Secret (regular KV entry)
kv/web-server-01/ssh-key         → Secret (regular KV entry)
kv/core-switch-a/admin           → Secret (regular KV entry)
kv/core-switch-a/enable-secret   → Secret (regular KV entry)
```

### Resource Metadata Schema

```json
{
  "_resource": true,
  "name": "web-server-01",
  "type": "server",
  "hostname": "web01.example.com",
  "ip_address": "10.0.1.50",
  "port": 22,
  "os": "Ubuntu 24.04",
  "location": "us-east-1 / rack-42",
  "owner": "infra-team",
  "tags": ["production", "web", "linux"],
  "notes": "Primary web server behind the load balancer. Maintained by the infra team.",
  "created_at": "2026-04-15T12:00:00Z",
  "updated_at": "2026-04-15T14:30:00Z"
}
```

### Built-in Resource Types

| Type | Description | Typical fields |
|------|-------------|----------------|
| `server` | Linux, Windows, macOS machines | hostname, IP, port (SSH/RDP), OS |
| `network_device` | Switches, routers, firewalls | hostname, IP, port, OS/firmware |
| `website` | URLs with login credentials | hostname (URL), port (443) |
| `database` | MySQL, PostgreSQL, etc. | hostname, IP, port, OS |
| `application` | SaaS/internal apps, API services | hostname (URL), notes |

Users can enter any custom type string when creating a resource. The type is a free-form field with the built-in values offered as suggestions.

## GUI Screens

### Resources List (`/resources`)
- Header with "Add Resource" button, type filter dropdown, and search input
- Card grid showing: resource name, type badge, hostname/IP, tag chips, secret count
- Click a card to open the resource detail view

### Resource Detail (`/resources/:name`)
- **Info tab**: Editable metadata form (type, hostname, IP, port, OS, location, owner, tags, notes)
- **Secrets tab**: List of secrets for this resource with add/view/edit/delete; values are masked by default

### Create/Edit Resource Modal
- Name input
- Type selector (dropdown with built-in types + "Custom..." option)
- Metadata fields: hostname, IP, port, OS, location, owner, tags (comma-separated), notes (textarea)

## Implementation

### Backend (Tauri Commands)

| Command | Description |
|---------|-------------|
| `list_resources(mount)` | List all resource names from `{mount}_resources/` |
| `read_resource(mount, name)` | Read metadata from `{mount}_resources/{name}` |
| `write_resource(mount, name, metadata)` | Write metadata to `{mount}_resources/{name}` |
| `delete_resource(mount, name)` | Delete metadata + all secrets under `{mount}{name}/` |
| `list_resource_secrets(mount, name)` | List keys under `{mount}{name}/` |
| `read_resource_secret(mount, name, key)` | Read `{mount}{name}/{key}` |
| `write_resource_secret(mount, name, key, data)` | Write `{mount}{name}/{key}` |
| `delete_resource_secret(mount, name, key)` | Delete `{mount}{name}/{key}` |

### Frontend

- `gui/src/routes/ResourcesPage.tsx` -- main page component
- `gui/src/lib/types.ts` -- ResourceMetadata interface
- `gui/src/lib/api.ts` -- invoke wrappers
- `gui/src/App.tsx` -- `/resources` route
- `gui/src/components/Layout.tsx` -- nav item

## Security Considerations

- Resources metadata is stored in the same KV engine as secrets, so it inherits the same encryption, ACL policies, and audit logging.
- The `_resources/` prefix is a convention, not a hard boundary. Policies can restrict access to `kv/_resources/*` separately from `kv/*` if needed.
- Resource deletion cascades to all secrets under the resource path. The GUI must confirm this with the user.
