# Feature: SQL Browser — query and change data on database resources (`dbms-management` plugin)

**Status: In progress (2026-10-30). Phase 0 and Phase 1 (T124) closed; Phases
2–4 (T125) closed by the maintainer with review gates open; Phase 5 (T126) in
the tree, not yet run end to end; Phases 6–9 (T127–T130) not started.** Proposed
2026-10-13. Tracked as ROADMAP
T124–T130 under M5 (see *Tracking*). Written against the tree at 0.44.31; every
"today" statement below was verified by reading the code on that date and
carries a file reference.

## Summary

An operator opens a **SQL browser** on a `database` resource — PostgreSQL,
MySQL, MariaDB, Microsoft SQL Server or Oracle Database — inside the desktop
GUI. The browser looks like the desktop database tools operators already know:
an object tree (catalogs, schemas, tables, views, routines) on the left, tabbed
SQL editors in the centre, a result grid with inline editing, and a message
pane that echoes each statement with its affected-row count and timing.

Unlike those tools, **the operator never holds the database credential and
never opens a connection to the database.** The session lives on the vault
server, inside a new process plugin, `dbms-management`. Every statement goes
through four steps:

1. **classified** by the plugin into the privileges it needs (`SELECT` on these
   objects, `UPDATE` on that table, `DROP` of that index …);
2. **authorized by BastionVault**: the kernel's policy evaluator decides each
   required privilege against the caller's policies, shares, ownership and
   asset-group membership. That evaluator is `bv_policy_core::decide`, the
   formally verified ACL core. The plugin does not keep a permission table of
   its own;
3. **executed** only if every required privilege was granted, using a database
   login that the host releases to the plugin. The login is never released to
   the operator, and it is chosen so that the database itself refuses what the
   grant does not allow wherever that is possible;
4. **audited** with the operator as the actor.

Access is granted per resource with a new family of capabilities. You can grant
**only `sql_select`**, or any combination of `sql_select`, `sql_insert`,
`sql_update`, `sql_delete`, `sql_alter`, `sql_create`, `sql_drop`,
`sql_execute` and `sql_admin`. **Exporting data (`sql_export`)** and **running
SQL scripts (`sql_script`)** are separate capabilities that no other grant
implies. You can grant them in an ACL policy (optionally down to a schema or
a table) or from the resource's **Sharing** tab, with chips and presets such
as *Read only*, *Read/write* and *Schema change*.

The connection uses either a **stored resource secret** or, once the
dynamic-secrets framework exists (T62) and the resource has a dynamic profile,
a **short-lived database account created for the session** and revoked when the
session ends.

Builds on [resources.md](resources.md) (S49),
[resource-types-firewall-switch-db.md](resource-types-firewall-switch-db.md) (S48),
[resource-connect.md](resource-connect.md) (S46),
[connect-only-access.md](connect-only-access.md) (S10),
[connect-mfa-and-fido2-ssh.md](connect-mfa-and-fido2-ssh.md) (S9),
[per-user-scoping.md](per-user-scoping.md) (S33),
[resource-groups.md](resource-groups.md) (S47),
[plugin-system.md](plugin-system.md) (S41),
[plugin-extensibility.md](plugin-extensibility.md) (S40),
[plugin-app-extensions.md](plugin-app-extensions.md) (S39),
[session-workspace.md](session-workspace.md) (S56) and
[dynamic-secrets.md](dynamic-secrets.md) (S13). It follows the shape of
[self-accounts.md](self-accounts.md) (S107): the plugin owns the domain logic,
and the host gains small, generic, reviewable substrate.

### Assumptions made in writing this spec

- "A new resource (SQL browser)" means a new **Connect protocol, `sql`, on the
  existing `database` resource type**, not a new resource type. Database
  resources already carry the engine, host, port and TLS fields
  ([gui/src/lib/resourceTypes.ts:37](../gui/src/lib/resourceTypes.ts:37)).
- "Validated by BastionVault" means the **authorization decision is made by the
  vault server's policy evaluator** for every statement. It is never made by
  the GUI, and never by a permission table kept inside the plugin.
- "Dynamic, if enabled" means a resource has a SQL profile whose credential
  source is a dynamic-secrets role. When such a profile can serve the caller,
  it is preferred over stored secrets.
- The plugin is named `dbms-management`. Its crate is
  `plugins-ext/bastion-plugin-dbms-management`, its suggested mount is `dbms/`,
  and every path is `v2`.

## Motivation

- **Database access is the gap in the PAM story.** BastionVault brokers SSH,
  RDP and web sessions without revealing credentials
  (S46, S10, S105). Database resources are inventory only: the type has no
  `connect` block and no protocol
  ([features/resources.md:74](resources.md)). Operators therefore read the
  database password and paste it into a desktop client. That is the exact path
  connect-only access exists to remove, and it leaves no record of what was
  run.
- **"Read-only" must actually be read-only.** The most common request is to let
  an analyst or an auditor *look* at a production database. With a pasted
  shared credential, read-only is a promise. Here it is enforced twice: by the
  vault's decision on every statement, and by the database refusing writes from
  a read-only login or a read-only transaction (§5).
- **Statement-level accountability.** For each statement the audit and the
  session journal record who ran it, against which resource, which privilege
  classes it used, which objects it touched, how many rows it changed and
  whether the vault refused it. A shared database login cannot attribute that
  to a person.
- **Exports and scripts are where the damage happens.** Bulk extraction and
  multi-statement scripts are the two operations that most often turn a
  mistake or a leak into an incident. They get their own grants, their own
  limits and, optionally, their own MFA step-up (§8).
- **Why a plugin.** Database drivers are large, and Oracle may need a native
  client library. None of that belongs in the vault server's process or its
  trusted computing base. As a plugin the feature is opt-in by installation,
  ships on its own cadence, and runs in a separate OS process. The authorization
  stays in the kernel, which is the point of "validated by BastionVault". This
  is the same split as Self-Accounts (S107) and the XCA importer (S63).

## Research — how others do it, and what we take

| Approach | Examples | What it gets right | What it misses |
|---|---|---|---|
| Desktop client holding the credential | Navicat, DBeaver, SSMS (the model in the request's screenshot) | rich editor, tree, grid, editing | the credential sits on the workstation; no central authorization; no reliable audit |
| PAM session manager | classic PAM vendors brokering a native client session, often recorded as video | the credential is hidden; the session is recorded | authenticates the *connection*, not each *statement*; recordings are not searchable SQL |
| Protocol proxy with short-lived identity | Teleport Database Access; HashiCorp Boundary with Vault's database secrets engine | native clients keep working; per-user or brokered database accounts | statement-level authorization is limited or absent; the client still drives the wire protocol |
| Server-side SQL workspace | Bytebase-style web SQL editors | statements run server-side; query and export are separately granted; changes can go through review | separate product, its own identity and permission model |

What this spec takes:

- **server-side execution** (the server-side workspace row), so the credential
  and the decision never leave the server;
- **export as a separate permission** (the same row);
- **per-session database accounts** (the protocol-proxy row and Vault's
  database engine), via T62, so the database enforces the grant too;
- **statement-level audit** (all rows);
- the **familiar desktop layout** (first row) for the GUI.

A native-protocol proxy, where `psql` or DBeaver connect *through*
BastionVault, is out of scope (see *Alternatives considered*).

## Current State

**Status: In progress.** Phase 0 is closed (see *Phase 0 findings*). Phase 1
subsystem 1 (the eleven `sql_*` capabilities, `ShareCap` at `u16`) and
subsystem 2 (`PolicyGate::sql_privileges` with denial records, the qualifier
edge, the share vocabulary and baseline rule, theorem T9) are in the tree; see
*Phase 1, subsystem 1 validation* and *Phase 1, subsystem 2*. Subsystem 3
(plugin ABI 1.4: the caller-bound host calls, their grants, actor-stamped
audit, multiplexed process invocations, lifecycle messages, the SDK process
runner and testkit parity) is in the tree too; see *Phase 1, subsystem 3*.
Subsystem 4 (the rolling-upgrade write gate for `sql_*`) and subsystem 5 (the
resource engine's `sql` protocol: strict profiles, credential resolution with
endpoint binding, the privileges read, connect MFA for `sql` profiles, and the
gate on `.bvx` import and BVBK restore) are in the tree; see *Phase 1,
subsystem 4* and *Phase 1, subsystem 5*. The GUI half (subsystem 6) followed,
and T124 closed on 2026-10-26 (see *Phase 1 exit gate*). Phase 2 (T125) is in
progress: the `bv-sql-classify` crate is in the tree with the PostgreSQL
dialect, the hazard corpus as tests, property tests and a cargo-fuzz target;
the fuzz campaign has not been run (see *Phase 2, the classifier crate*). The
plugin (Phase 3) is in the tree at `plugins-ext/bastion-plugin-dbms-management`,
not registered on any host and not released; its five subsystems are verified
with unit tests, the testkit and live PostgreSQL 16 containers, but not on a
running vault or a cluster (see *Phase 3, the plugin*). The GUI workspace
(Phase 4) is in the tree: the `sql-<token>` window and the Session Workspace
`sql` pane, the host-side `sql_*` Tauri commands with their pinned window
set, tree, editor, grid, messages, history, info and enforcement panels, grid
editing with conflict reporting, confirmations, and the Connect menu, profile
row and ⌘K entries. It is verified with unit and component tests and a
browser check against a mocked host, not against a registered plugin (see
*Phase 4, the GUI workspace*). Phase 5 (T126) is in the tree: action-bound
step-up tickets in the resource engine and the `connect_ticket_redeem` host
call, the plugin's `script`, `export` and `exports/<job>/<offset>` endpoints
with per-action step-up, and the GUI's script, `.sql` load, export-to-file and
step-up prompt. It is verified with unit tests, live PostgreSQL 16 tests, host
tests against a test vault and vitest, not against a registered plugin on a
running vault or in a real Tauri window (see *Phase 5, exports, scripts and
step-up*).
The Phase table maps each phase to its ROADMAP task.

| Phase | Task | Status |
|---|---|---|
| Phase 0 — verification spike and decisions | T124 | Done (2026-10-21) |
| Phase 1 — host substrate: SQL capabilities, plugin ABI 1.4, `sql` protocol | T124 | Done (2026-10-26) |
| Phase 2 — `bv-sql-classify` classifier crate | T125 | In progress (PostgreSQL crate, corpus, property tests and fuzz target in the tree; fuzz campaign not run) |
| Phase 3 — the `dbms-management` plugin with PostgreSQL | T125 | In progress (plugin in the tree; verified with the testkit and PostgreSQL 16 containers; not run on a real host, cluster or TLS-cancel path) |
| Phase 4 — GUI SQL workspace | T125 | In progress (in the tree; unit, component and mocked-host browser checks; not run against a registered plugin; editor is a textarea, not CodeMirror) |
| Phase 5 — export, scripts and per-action step-up | T126 | Complete (unit, live PostgreSQL, cucumber, host and vitest checks, `make test-release`; not run on a registered plugin or in a real Tauri window) |
| Phase 6 — MySQL and MariaDB | T127 | Todo |
| Phase 7 — Microsoft SQL Server | T128 | Todo |
| Phase 8 — Oracle Database | T129 | Todo |
| Phase 9 — dynamic database credentials | T130 | Blocked by T62 |

### Context this feature builds on (verified 2026-10-13)

**Plugins**

- **WASM plugins cannot reach a database.** Each call gets a fresh instance
  with no state. The only outbound import is the admin-granted HTTPS
  `bv.net_http`
  ([src/plugins/runtime.rs:418](../src/plugins/runtime.rs:418)). A SQL
  browser must therefore be a **process** plugin.
- **Long-lived process plugins are serialized and fragile under slow work.**
  `long_lived = true` keeps one child per plugin name, but every invoke takes a
  per-plugin `tokio::sync::Mutex`
  ([src/plugins/process_supervisor.rs:46](../src/plugins/process_supervisor.rs:46)).
  An invoke that exceeds `DEFAULT_INVOKE_TIMEOUT` (30 s,
  [process_supervisor.rs:77](../src/plugins/process_supervisor.rs:77)) tears the
  child down and counts as a crash. For a multi-user SQL browser this means one
  slow query blocks every user, and a timeout drops every open session. Phase 1
  changes it (§9.4).
- **Process plugins have a narrow host surface:** `config_get`, `log`,
  `now_unix_ms`, `storage_*` and `audit_emit`
  ([src/plugins/process_runtime.rs:349](../src/plugins/process_runtime.rs:349)).
  There is no call to check a capability, no call to resolve a credential and
  no call to redeem an MFA ticket.
- **Process plugins are not sandboxed, and their declared egress is not
  enforced.** `capabilities.allowed_hosts` is "declarative-only in v1"
  ([src/plugins/process_runtime.rs:37](../src/plugins/process_runtime.rs:37)).
- **The caller block exists (ABI 1.3).** With `caller_identity = true` the
  envelope carries `entity_id`, `display_name`, `principal` and `namespace`.
  It never carries policies, groups or the token
  ([src/plugins/logical_backend.rs:146](../src/plugins/logical_backend.rs:146)).
  The host ABI minor is 3
  ([crates/bv-plugin-manifest/src/lib.rs:529](../crates/bv-plugin-manifest/src/lib.rs:529)).
- **Plugin audit events have no actor.** `bv.audit_emit` writes
  `sys/plugins/<name>/event` with an empty token, so the entry carries no
  identity and lands in the root namespace
  ([src/plugins/runtime.rs:1032](../src/plugins/runtime.rs:1032),
  [src/audit/sys_emit.rs:31](../src/audit/sys_emit.rs:31)).
- **Plugin GUIs are declarative only.** `surface.json` (schema 2) offers
  `table`, `form` and `detail` pages with static columns
  ([crates/bv_plugin_surface/src/lib.rs:107](../crates/bv_plugin_surface/src/lib.rs:107)).
  No plugin JavaScript is loaded. GUI isolation rests on that rule, because
  plugin windows have a null CSP and every app command. A SQL editor and a
  virtualized grid cannot be expressed declaratively, so the workspace is host
  code (§10).
- **No plugin can add a Connect protocol.** The only Connect hook is the
  credential provider (`ssh | rdp | web`,
  [crates/bv-plugin-manifest/src/lib.rs:265](../crates/bv-plugin-manifest/src/lib.rs:265)).

**Policy, sharing, audit**

- **The ACL has no SQL vocabulary.** Capabilities are `deny, create, read,
  update, delete, list, sudo, patch, root, connect`, a bitset that ends at
  `Connect = 1 << 9`
  ([crates/bv-kernel/src/modules/policy/policy.rs:181](../crates/bv-kernel/src/modules/policy/policy.rs:181)).
  `create` only satisfies a write, and `Operation` has no create, so one path
  cannot separate INSERT from UPDATE.
- **`connect` is the precedent for a probe-only capability.** It maps to no
  `Operation`. It is checked by `PolicyStore::may_connect_target`
  ([policy_store.rs:2264](../crates/bv-kernel/src/modules/policy/policy_store.rs:2264))
  through `Request::share_capability_override`, and exposed to engines through
  `PolicyGate`
  ([crates/bv-kernel-api/src/policy.rs:26](../crates/bv-kernel-api/src/policy.rs:26)).
  Policy `read` implies `connect`; a share does not.
- **The share vocabulary is a closed list:** `read, list, update, delete,
  create, connect`
  ([crates/bv-kernel/src/modules/identity/share_store.rs:857](../crates/bv-kernel/src/modules/identity/share_store.rs:857)).
  Share targets are `kv-secret | resource | asset-group | file`.
- **Denials are not chained.** Only successful requests reach the hash-chained
  log; ACL denials go to the denial store
  ([crates/bv-core/src/core.rs:1207](../crates/bv-core/src/core.rs:1207)). A
  refusal that a plugin returns is not recorded as a denial.
- **No approval / four-eyes workflow exists**, and policies have no MFA clause.
  The reusable step-up is the resource engine's connect ticket: single use,
  120 s, bound to principal, namespace, resource and profile. Engines reach it
  through `VaultCtx::connect_mfa()`
  ([crates/bv-kernel-api/src/ctx.rs:250](../crates/bv-kernel-api/src/ctx.rs:250)).
  Plugins cannot reach it.

**Resources and Connect**

- **Connection profiles live in the resource record** (`connection_profiles`,
  [crates/bv-engine-resource/src/lib.rs:181](../crates/bv-engine-resource/src/lib.rs:181)).
  The protocol is a closed set in about five places:
  - `ProfileProtocol`
    ([gui/src-tauri/src/session/mod.rs:43](../gui/src-tauri/src/session/mod.rs:43));
  - `profile_protocol`
    ([crates/bv-engine-resource/src/connect_provider.rs:87](../crates/bv-engine-resource/src/connect_provider.rs:87));
  - the TS `ConnectProtocol` / `SessionProtocol` unions
    ([gui/src/lib/types.ts:499](../gui/src/lib/types.ts:499));
  - `CONNECT_PROTOCOLS`
    ([gui/src/lib/resourceTypes.ts:368](../gui/src/lib/resourceTypes.ts:368)).
- **The vault server opens no sockets for Connect today.** In direct mode the
  GUI host dials; in brokered mode Rustion dials. The SQL browser is the first
  feature where a server-side component dials the target, which is why the
  endpoint-binding rule in §5.4 is new.
- **Policy tiers can force databases through a bastion**
  (`connect.transport = rustion-required` on the `database` type is the worked
  example in [rustion-integration.md:333](rustion-integration.md)). Rustion's
  target protocols are SSH and RDP only.
- **The Session Workspace has pane kinds `ssh | rdp | replay`**
  ([gui/src/lib/sessionLayout.ts:27](../gui/src/lib/sessionLayout.ts:27)).
  Session windows load `session.html` with a pinned command set and no vault
  token (T110).

**Databases and secrets**

- **No database dynamic-secrets engine exists.** T62 is Todo, and
  `dynamic-engine-plugins/` is a placeholder. The lease substrate also has gaps
  this feature needs closed:
  - a backend revoke error is logged and the lease row is deleted anyway
    ([crates/bv-kernel/src/modules/auth/expiration.rs:736](../crates/bv-kernel/src/modules/auth/expiration.rs:736));
  - `sys/renew`, `sys/revoke` and `sys/revoke-prefix` are `//TODO` stubs that
    return success
    ([crates/bv-kernel/src/modules/system/mod.rs:1605](../crates/bv-kernel/src/modules/system/mod.rs:1605)).
- **`plugins-ext/bastion-plugin-postgres` is a proof of concept, not a base to
  build on.** It accepts a top-level `create | revoke` op that the mount path
  never sends ([main.rs:43](../plugins-ext/bastion-plugin-postgres/src/main.rs:43)
  vs [src/plugins/logical_backend.rs:234](../src/plugins/logical_backend.rs:234)).
  It also connects without TLS.
- **`bv-sql-guard` exists** for statements the code writes itself: literal-only
  `Sql`, plus `SqlIdent` restricted to `[A-Za-z_][A-Za-z0-9_]{0,62}`
  ([crates/bv-sql-guard/src/lib.rs:1](../crates/bv-sql-guard/src/lib.rs:1)).
  The escape-hatch register `docs/sql-escape-hatches.md` is empty.
- **The GUI has no code editor and no data grid** (`gui/package.json` has only
  xterm). Phase 4 adds dependencies.

## Scope

### In scope

- A `sql` Connect protocol on `database` resources whose `engine` is
  `postgresql`, `mysql`, `mariadb`, `mssql` or `oracle`, with engine-aware SQL
  connection profiles. A profile carries the target, the database or service,
  the TLS mode, a credential source and the privilege ceiling of its login.
- The SQL capability family in policies and shares, evaluated by the kernel,
  with object scoping in policies.
- The `dbms-management` process plugin:
  - sessions;
  - statement classification;
  - asynchronous execution with paging and cancellation;
  - the object browser;
  - structured grid edits;
  - transactions;
  - limits;
  - audit and a statement journal.
- Host substrate, Plugin ABI 1.4:
  - caller-bound authorization and credential-release calls;
  - MFA ticket redemption;
  - audit events stamped with the actor;
  - seal and shutdown lifecycle events;
  - concurrent long-lived process invocations.
- The GUI SQL workspace (main window route and Session Workspace pane), the
  SQL profile editor, SQL chips in the policy builder and in sharing.
- Export (CSV, JSON Lines, SQL `INSERT`) and script execution, each behind its
  own capability, limits and optional step-up.
- Dynamic per-session database accounts once T62 provides the framework
  (Phase 9).

### Out of scope (explicit)

- **Native-client proxying** (`psql`, DBeaver or SSMS connecting through the
  vault). This is a different product with five wire protocols to intercept.
- **Non-relational and file databases**: MongoDB, Redis, Elasticsearch and
  SQLite stay inventory-only.
- **Rustion-brokered database connections.** Rustion has no database transport.
  A resource whose effective transport is `rustion-required` is refused (§6.6).
- **Approvals / four-eyes for write statements**, **dynamic data masking** and
  **row-level filtering** (*Future work*).
- **Kerberos / Windows integrated authentication** and **client-certificate
  database authentication** in v1 (*Future work*).
- **XLSX export**, visual explain plans, ER diagrams and schema diff.
- **MCP tools and a dedicated CLI REPL.** The plugin's paths are ordinary
  logical paths, so `bvault write dbms/v2/sessions …` works generically.

## Design

### 1. Components

```
 GUI (React, host code)        Tauri host (Rust)             Vault server
 ──────────────────────        ─────────────────             ────────────
 SQL workspace ──► sql_* commands ──(host-held token)──► dbms/v2/sessions/…   (plugin mount; path ACL)
   tree / editor / grid                                        │
   message pane                                                ▼
                                                    host: process runtime (ABI 1.4, multiplexed)
                                                               │  invoke{id, caller, op, path, data}
                                                               ▼
                                              bastion-plugin-dbms-management (long-lived child)
                                               ├─ bv-sql-classify  (pure: text → required privileges)
                                               ├─ host_call resource_sql_authorize ──► PolicyGate::sql_privileges
                                               │                                        (bv_policy_core::decide,
                                               │                                         shares, owner, asset groups;
                                               │                                         refusals → denial store)
                                               ├─ host_call resource_sql_credential ─► resource engine resolves the
                                               │                                        profile's secret / dynamic role
                                               │                                        (endpoint binding, grant check,
                                               │                                         release audited)
                                               ├─ drivers: tokio-postgres · mysql_async · tiberius · Oracle (§Phase 8)
                                               │        └──── TLS (rustls) ────► database
                                               └─ host_call audit_emit (actor stamped by the host)
```

| Component | Owns | Where |
|---|---|---|
| `bastion-plugin-dbms-management` | sessions, runs, drivers, catalog browse, row edits, export / script jobs, journal | `plugins-ext/bastion-plugin-dbms-management` (process, long-lived) |
| `bv-sql-classify` | statement splitting and classification into required privileges and objects; pure, no I/O | `crates/bv-sql-classify` (Tier 0 leaf; published to `uox-bastionvault` for the plugin) |
| Policy kernel | SQL capability family, target resolution for `…/sql/**`, `sql_privileges`, denial records | `crates/bv-policy-core`, `crates/bv-kernel/src/modules/policy`, `crates/bv-kernel-api/src/policy.rs` |
| Share store | `sql_*` entries in the vocabulary for `resource` and `asset-group` targets | `crates/bv-kernel/src/modules/identity/share_store.rs` |
| Plugin substrate | ABI 1.4 host calls, grants, actor-stamped audit, lifecycle, multiplexed invocations, SDK process runner, testkit | `src/plugins/`, `crates/bv-plugin-manifest`, `crates/bastion-plugin-sdk`, `crates/bastion-plugin-testkit` |
| Resource engine | `sql` protocol, SQL profile validation, credential resolution and endpoint binding, `v2/sql/privileges`, MFA for `sql` profiles | `crates/bv-engine-resource` |
| GUI and Tauri host | SQL workspace, `sql_*` commands, profile editor, sharing and policy chips | `gui/src/`, `gui/src-tauri/src/commands/sql.rs` |

### 2. Trust boundaries — why the session lives on the server

| Placement | Who holds the credential | Who decides | Verdict |
|---|---|---|---|
| GUI host dials (like direct SSH) | the workstation | the GUI | **rejected**: any client-side check is bypassable, and a user who holds the password can connect with any tool |
| Plugin on the vault server dials | the plugin process, in memory, for the session | the kernel, per statement | **chosen** |
| Built-in engine in the server | the vault process | the kernel | rejected: drivers (and possibly a native Oracle client) would enter the vault server's TCB, and the request is for a plugin |

Consequences that the rest of the design carries:

- **The operator needs no `read` on the database secret.** This is connect-only
  access (S10) applied to databases. A user who can read the secret could
  bypass every control here with a native client. The Sharing tab therefore
  never suggests `read` together with SQL presets.
- **The GUI is untrusted.** It renders effective privileges to disable buttons,
  but every decision is server-side.
- **The plugin is trusted for classification and execution.** It is signed,
  admin-registered and admin-granted (§9.2). A compromised plugin holds live
  database credentials, which is why credentials are released per session and
  bound to an endpoint (§5.4). It is also why the database-side ceiling (§5) is
  the default rather than an option.

### 3. Privilege model

#### 3.1 Vocabulary

| Capability | Grants | Typical statements (full table in §4.2) |
|---|---|---|
| `sql_select` | read rows and metadata | `SELECT`, `WITH … SELECT`, `SHOW`, `DESCRIBE`, plan-only `EXPLAIN` |
| `sql_insert` | add rows | `INSERT`, `MERGE … INSERT`, `INSERT ALL` |
| `sql_update` | change rows, take row/table locks | `UPDATE`, `MERGE … UPDATE`, `SELECT … FOR UPDATE`, `LOCK TABLE` |
| `sql_delete` | remove rows | `DELETE`, multi-table `DELETE`, `MERGE … DELETE` |
| `sql_alter` | change existing objects | `ALTER …`, `COMMENT ON`, `RENAME`, maintenance (`VACUUM`, `REINDEX`, `OPTIMIZE TABLE`) |
| `sql_create` | create objects | `CREATE TABLE/VIEW/INDEX/SEQUENCE/FUNCTION/PROCEDURE/TRIGGER/SCHEMA` |
| `sql_drop` | destroy objects or all their rows irreversibly | `DROP …`, `TRUNCATE` |
| `sql_execute` | run code whose effect cannot be determined statically | `CALL`, `EXEC`, anonymous blocks, dynamic SQL, user functions outside a read-only session |
| `sql_admin` | server-level administration | `GRANT`, `REVOKE`, users / roles / logins, `SET ROLE`, `EXECUTE AS`, `ALTER SYSTEM`, `CREATE/DROP DATABASE`, `KILL` |
| `sql_export` | bulk export of a result set | the export endpoint (§8.1) |
| `sql_script` | multi-statement batches and script files | the script endpoint (§8.2) |

Rules:

- **No implication between them.** `sql_update` does not imply `sql_select`,
  and `sql_admin` does not imply `sql_drop`. A statement needs every privilege
  it uses: `UPDATE t SET a = 1 WHERE b = 2` reads `b`, so it needs `sql_update`
  *and* `sql_select` on `t`. This mirrors how PostgreSQL itself demands SELECT
  on the columns in `WHERE`.
- **Nothing implies them.** Policy `read` (which implies `connect`), `update`,
  `sudo` and `connect` grant no SQL privilege. Only the root token passes
  everything, as it does today.
- **`deny` wins.** An applying `deny` on a SQL path revokes, on enforcement as
  well as on display (the T119 / theorem `t1_deny_wins_on_enforcement`
  semantics).
- **Presets** in the GUI are only bundles of capabilities. Nothing new is
  stored for them:
  - *Read only* = `sql_select`;
  - *Read/write* = + `sql_insert`, `sql_update`, `sql_delete`;
  - *Schema change* = + `sql_alter`, `sql_create`, `sql_drop`;
  - *Full* = everything except `sql_export` and `sql_script`, which are always
    separate toggles.

#### 3.2 Where a grant lives: one path per check

Each check evaluates **one** synthetic ACL path under the resource's own
policy path. It is never routed; it exists only for evaluation:

```
resources/resources/<resource>/sql/server                                 server-level checks
resources/resources/<resource>/sql/objects/<catalog>/<schema>/<object>    object checks
```

| Engine | `<catalog>` | `<schema>` | `<object>` |
|---|---|---|---|
| PostgreSQL | database | schema | relation / routine / sequence |
| SQL Server | database | schema | object |
| Oracle | service (PDB) name | schema (owner) | object |
| MySQL / MariaDB | `def` (the catalog `information_schema` reports) | database | table / routine |

- **Server-level checks** cover statements that reference no object
  (`SELECT 1`, allow-listed `SET`, `SHOW VARIABLES`), `sql_admin`,
  `sql_script`, and opening a session.
- **Opening a session requires at least one SQL capability on `sql/server`.**
- **Resource-wide grant:** `resources/resources/<resource>/sql/*`.
- **Object-scoped grant:** a narrower rule under `sql/objects/…`. A policy that
  is *only* object-scoped should also grant `sql_select` on `sql/server`, or the
  user cannot open a session or run `SELECT now()`. The policy builder warns
  about this.
- **Names that cannot be addressed** — containing `/`, `*`, `+` or a control
  character, or whose canonical case cannot be determined (§4.4) — never match
  an object-scoped rule. Such objects are reachable only through resource-wide
  grants (fail closed).

Policy examples:

```hcl
# Analysts: SELECT only, on every object of one database resource.
path "resources/resources/netrisk-db/sql/*" {
  capabilities = ["sql_select"]
}

# Support: read everything, change rows in one schema only.
path "resources/resources/netrisk-db/sql/*" {
  capabilities = ["sql_select"]
}
path "resources/resources/netrisk-db/sql/objects/def/netrisk/*" {
  capabilities = ["sql_select", "sql_update", "sql_delete"]
}

# DBAs: schema changes, scripts and exports on every database in an asset group.
path "resources/resources/+/sql/*" {
  capabilities = ["sql_select", "sql_insert", "sql_update", "sql_delete",
                  "sql_alter", "sql_create", "sql_drop", "sql_script", "sql_export"]
  groups       = ["prod-databases"]
}

# Nobody drops anything in the PCI database, unless a more specific grant below says otherwise.
path "resources/resources/pci-db/sql/*" {
  capabilities = ["deny"]
}
```

The `deny` in the last example blocks every SQL capability on the path it
governs, and every layered grant (group, scope, share) on that path. A more
specific path wins over a broader one, so an ungated grant on a narrower path,
such as `.../sql/objects/...`, overrides a `deny` on `.../sql/*`. To make a
`deny` hold against a narrower grant, write the `deny` at the narrower path.
This rule is pending the maintainer's confirmation (ledger Ruling 10).

#### 3.3 Shares

- **The vocabulary is extended.** `share_store.rs`'s `ALLOWED` list gains the
  eleven `sql_*` names, accepted only for `resource` and `asset-group`
  targets. On other target kinds they are refused with a clear error, not
  dropped silently.
- **A share is resource-wide.** It grants its `sql_*` entries on every object
  of the resource (on every member resource for an asset-group share).
  Object-scoped shares are *Future work*.
- **Shares take effect through one shipped baseline rule**, in the same
  `default`, `namespace-shared` and `shared-access` baselines that already
  grant the connect endpoints:

  ```hcl
  path "resources/resources/+/sql/*" {
    capabilities = ["sql_select", "sql_insert", "sql_update", "sql_delete", "sql_alter",
                    "sql_create", "sql_drop", "sql_execute", "sql_admin",
                    "sql_export", "sql_script"]
    scopes       = ["shared"]
  }
  ```

  The rule is inert unless a share with the specific `sql_*` entry exists; the
  scope gate demands the share carry the probed capability. In namespaces it is
  templated like the existing connect grants.
- **Ownership grants nothing.** The owner of a resource *record* is whoever
  created the inventory entry, and that must not mean "may DROP tables". The
  baseline therefore has no `scopes = ["owner"]` SQL rule. An operator who
  wants one writes it.
- **The Sharing tab** (`ObjectSharingCard`) shows the SQL chips and presets for
  database resources, and asset groups show them too. *Read only* is the
  pre-selected preset. The chips carry a one-line hint stating that `read` on
  the resource reveals stored secrets and is not needed for the SQL browser.

#### 3.4 Evaluation

New kernel function, exposed to engines and to the plugin host call:

```rust
// crates/bv-kernel-api/src/policy.rs (PolicyGate)
async fn sql_privileges(
    &self,
    req: &Request,             // the caller's request — never another principal's
    resource: &str,
    checks: &[SqlCheck],       // (capability, SqlTarget::Server | SqlTarget::Object{catalog, schema, object})
) -> Result<Vec<SqlVerdict>, RvError>;   // one verdict per check; Err ⇒ refuse
```

As implemented (subsystem 2), the call also takes a `SqlPurpose` after `req`:
`Enforce { plugin }` records refusals naming the plugin, `Display` (the chips
read below) records nothing. See *Phase 1, subsystem 2*.

- **Same evaluator as every other check.** Each check is
  `ACL::explain_capability_for_request(path, cap)`, with the owner, share and
  asset-group qualifiers resolved for target `(resource, <resource>)` — the
  same machinery `may_connect_target` uses, so all arms decide identically.
- **Target resolution must learn `resources/resources/<R>/sql/**` → `(resource,
  R)`.** Without it, `scopes` and `groups` rules cannot apply. This is the one
  new edge in the qualifier resolver.
- **Refused checks are written to the denial store** with the actor, the
  namespace, the synthetic path, the capability and the plugin name. SQL
  refusals then appear on the Audit page's *denied* view with every other 403.
- **Fail closed.** Any evaluation error refuses the whole batch.

The GUI reads the caller's effective privileges for its chips from
`resources/v2/sql/privileges/<resource>` (§API). That is a convenience read;
nothing is enforced from it.

### 4. Statement classification

#### 4.1 The classifier

`crates/bv-sql-classify` is a pure function with no I/O, no async and no
driver types:

```rust
pub fn classify(dialect: Dialect, lexer: LexerSettings, text: &str, ctx: &NameContext)
    -> Result<Vec<ClassifiedStatement>, Unclassifiable>;

pub struct ClassifiedStatement {
    pub span: Range<usize>,                       // byte range in `text`
    pub kind: StatementKind,                      // Select, Update, CreateTable, Call, TxBegin, SetSession, …
    pub required: Vec<(SqlCapability, SqlTarget)>,
    pub opaque: bool,                             // effect not statically known (CALL, blocks, dynamic SQL)
    pub tx_control: bool,                         // BEGIN/COMMIT/ROLLBACK/SAVEPOINT
}
```

- **Parsing** builds on the `sqlparser` crate (Apache DataFusion's SQL parser),
  using its PostgreSQL, MySQL and MS SQL dialects. Phase 0 measures its Oracle
  and T-SQL coverage against a corpus before Phases 7 and 8 commit to it.
- **Classification is conservative and data-driven.** Each dialect has a table
  mapping AST nodes and known functions to required capabilities. Anything the
  table does not know is `Unclassifiable`, and an unclassifiable statement is
  refused (§4.3). The classifier never defaults to `sql_select`.
- **The crate is under the main workspace's CI** (unit tests, corpus,
  property tests, `cargo fuzz` target, clippy), but the host binary does not
  link it. The vault server's TCB does not grow; the plugin depends on the
  published crate.

#### 4.2 Statement → required privileges

| Statement (all engines unless noted) | Requires |
|---|---|
| `SELECT`, `WITH … SELECT`, `VALUES`, `TABLE t` (PG), `SHOW`, `DESCRIBE`, plan-only `EXPLAIN` | `sql_select` on every object read (`sql/server` when none) |
| `EXPLAIN ANALYZE` (PG), `ANALYZE <stmt>` (MariaDB), `EXPLAIN ANALYZE` (MySQL 8) | the inner statement's set (it executes) |
| `SELECT … FOR UPDATE/SHARE`, T-SQL lock hints (`UPDLOCK`, `XLOCK`, `HOLDLOCK`, `TABLOCKX`), `LOCK TABLE(S)` | `sql_select` + `sql_update` on the locked objects |
| `SELECT … INTO new_table` (PG, T-SQL) | `sql_create` (new object) + `sql_insert` (new object) + `sql_select` (sources) |
| `INSERT`, `INSERT … SELECT`, `MERGE … INSERT`, `INSERT ALL` (Oracle) | `sql_insert` (target) + `sql_select` (every object read, incl. `RETURNING`/`OUTPUT`) |
| `INSERT … ON DUPLICATE KEY UPDATE` / `ON CONFLICT DO UPDATE` | + `sql_update` (target) |
| `REPLACE` (MySQL / MariaDB) | `sql_insert` + `sql_delete` (target) |
| `UPDATE`, `MERGE … UPDATE` | `sql_update` (target) + `sql_select` (every object read) |
| `DELETE`, multi-table `DELETE … JOIN` (MySQL, T-SQL), `MERGE … DELETE` | `sql_delete` (each target) + `sql_select` (every object read) |
| `nextval()`, `setval()`, `NEXT VALUE FOR`, `seq.NEXTVAL` | `sql_update` on the sequence |
| `ALTER …`, `COMMENT ON`, `RENAME`, `CREATE OR REPLACE` of an existing object; maintenance: `VACUUM`, `ANALYZE` (PG), `REINDEX`, `CLUSTER`, `OPTIMIZE`/`REPAIR TABLE`, `UPDATE STATISTICS` | `sql_alter` on the object |
| `CREATE` table / view / index / sequence / type / function / procedure / trigger / schema | `sql_create` on the new object's path |
| `DROP …`, `TRUNCATE` | `sql_drop` on the object |
| `CALL`, `EXEC proc`, `DO` (PG), `BEGIN … END` / PL/SQL anonymous blocks, `EXECUTE IMMEDIATE`, `sp_executesql`, `EXEC('…')`, SQL-level `PREPARE`/`EXECUTE` | `sql_execute` (on the routine when named, on `sql/server` otherwise) — **opaque** |
| user-defined function in a query | `sql_select` in a *database-enforced read-only* session (§5.3); otherwise + `sql_execute` on the function |
| `GRANT`, `REVOKE`, `CREATE/ALTER/DROP USER/ROLE/LOGIN`, `SET ROLE`, `SET SESSION AUTHORIZATION`, `EXECUTE AS`, `ALTER SYSTEM`, `CREATE/DROP DATABASE`, `KILL`, `SHUTDOWN`, replication and backup commands | `sql_admin` on `sql/server` |
| `BEGIN`, `START TRANSACTION`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE` | an open session; counted as transaction control (§8.2) |
| allow-listed session settings: `SET search_path`, `USE db`, `SET TIME ZONE`, `SET TRANSACTION ISOLATION LEVEL`, `ALTER SESSION SET CURRENT_SCHEMA` / `NLS_*`, `SET NOCOUNT`, `SET DATEFORMAT` | `sql_select` on `sql/server` (`USE` re-scopes later statements) |
| any other `SET` / `ALTER SESSION`, including lexer-affecting settings (§4.3) | `sql_admin` — and lexer-affecting ones are refused |
| **always refused in v1**: server file and OS access — `COPY … TO/FROM 'file'` or `PROGRAM`, `pg_read_file`, `pg_read_binary_file`, `lo_import`, `lo_export`, `LOAD DATA [LOCAL] INFILE`, `SELECT … INTO OUTFILE/DUMPFILE`, `LOAD_FILE()`, `xp_cmdshell`, `sp_OA*`, `OPENROWSET`, `OPENDATASOURCE`, `BULK INSERT`, `UTL_FILE`, `UTL_HTTP`, external `DBMS_SCHEDULER` jobs | refused; `sql_admin` does not unlock them |
| unparseable or unknown | refused; a caller holding `sql_admin` may run it as **`unclassified`**, audited, and subject to step-up by default (§8.3) |

#### 4.3 Hazards, and the rules that close them

| Hazard | Rule |
|---|---|
| Data-modifying CTEs: `WITH d AS (DELETE … RETURNING *) SELECT * FROM d` | classify **every** statement node, never the leading keyword |
| Multi-statement smuggling: parser and server disagree on where a statement ends | the plugin **executes exactly the spans it classified, one per protocol round trip**, and never sends the original multi-statement text. Multi-statement execution is disabled at the protocol layer where the protocol allows it: PostgreSQL extended query (one statement per Parse), MySQL without `CLIENT_MULTI_STATEMENTS`, Oracle single-statement calls. **SQL Server's batch protocol cannot disable it**, so T-SQL relies on the lexer pinning below plus the database ceiling. This residual is stated in the GUI's enforcement panel |
| Lexer settings change meaning: MySQL `ANSI_QUOTES` / `NO_BACKSLASH_ESCAPES`, PostgreSQL `standard_conforming_strings`, T-SQL `QUOTED_IDENTIFIER` | the plugin reads the effective values at session start, configures the classifier to match, **and refuses any statement that changes them** |
| MySQL / MariaDB executable comments: `/*! … */`, `/*M! … */` | statements containing them are refused (the server executes their content) |
| `EXPLAIN ANALYZE` executes | classified as the inner statement |
| Side-effecting functions inside `SELECT` | per-dialect function table: known writers map to their real capability (`nextval` → `sql_update`), known dangerous ones to the always-refused list, unknown user functions to `sql_execute` outside read-only sessions |
| `SELECT … INTO` creates a table (PG, T-SQL) or writes a server file (MySQL) | creation → `sql_create` + `sql_insert`; file output → always refused |
| Dynamic SQL hides the real statement | opaque → `sql_execute`. Operators must understand that **`sql_execute` is only as narrow as the database login behind the session**, and the GUI says so |
| Unqualified names resolve through `search_path`, default schema, current schema or the current database | resolved through the catalog at classification time (§4.4) |
| Views and definer-rights routines reach objects the caller has no grant on | standard database semantics (the view owner's privileges apply); documented, not intercepted |

#### 4.4 Name resolution and object scoping

- **Resolution.** For object-scoped checks, the plugin resolves each referenced
  name to `(catalog, schema, object)` the way the database will: through the
  catalog, with the session's current `search_path`, default schema, current
  schema or current database. That state is re-read after every allow-listed
  `SET` or `USE`.
- **Canonical case.** PostgreSQL folds unquoted names to lower case and Oracle
  to upper case. SQL Server and MySQL (`lower_case_table_names`) follow
  collation and settings, and the plugin normalizes per engine. A name it
  cannot normalize unambiguously matches no object-scoped rule.
- **Race window.** Object scoping is decided at classification time, so an
  object created between check and execution (for example, a new table that
  shadows a name on the `search_path`) can redirect an unqualified reference.
  The **hard** guarantee for object scoping is the database login (§5), which
  is why the spec recommends pairing object-scoped grants with a tiered or
  dynamic login that enforces the same scope at the database.

### 5. Credentials and enforcement layers

#### 5.1 SQL profiles and privilege ceilings

A database resource carries one or more `sql` connection profiles in its
existing `connection_profiles` array:

```jsonc
{
  "id": "netrisk-ro",
  "protocol": "sql",
  "label": "Read-only (svc_netrisk_ro)",
  "target": { "host": "apldc1vds0044", "port": 3306 },        // defaults: resource hostname/ip_address and port
  "sql": {
    "catalog": "netrisk",                                       // PG/MySQL database · MSSQL database · Oracle service
    "instance": null,                                           // MSSQL named instance (optional)
    "tls": { "mode": "verify-full", "server_name": null, "ca_pem": null },  // verify-full | verify-ca | require | disable
    "ceiling": ["sql_select"],                                  // what this login CAN do at the database
    "require_mfa": false,
    "step_up": ["sql_drop", "sql_admin", "sql_export", "sql_script"]       // Phase 5
  },
  "credential_source": { "kind": "secret", "secret_id": "svc_netrisk_ro" } // Phase 9: { "kind": "dynamic", "mount": "db-mysql/", "role": "netrisk-ro" }
}
```

`ceiling` is the operator's statement of what the profile's login can do at the
database. It is parsed strictly: an unknown or wrongly typed field fails the
profile closed, the T101 precedent. Phases 3 and 6–8 add a **ceiling probe**
that reads the login's real privileges and flags a ceiling narrower than the
truth:

- PostgreSQL: `has_table_privilege` and role membership;
- MySQL / MariaDB: `SHOW GRANTS`;
- SQL Server: `fn_my_permissions`;
- Oracle: `SESSION_PRIVS` and `USER_TAB_PRIVS`.

The probe's output is advisory and shown on the Connection tab. It does not
replace the operator's statement.

#### 5.2 Which profile serves a session

At session open the plugin asks the host for the caller's effective privileges
on `sql/server` and resource-wide, and chooses among the resource's `sql`
profiles:

1. **Dynamic first.** If a `dynamic` profile exists and can serve the caller,
   it is used (Phase 9).
2. **Otherwise the smallest stored-secret profile whose `ceiling` covers the
   caller's effective capability set** (export and script excluded, since they
   are vault-level).
3. **If the caller's set is read-only** (`sql_select` only, optionally with
   export), only a profile whose ceiling is exactly `["sql_select"]` may serve
   it.

Under the default **`database-first`** enforcement mode, step 3 has no
fallback: a read-only grant on a resource with no read-only profile is refused,
with a message telling the administrator to add a read-only login or enable
dynamic credentials. The resource can opt into **`classifier-only`**
(`sql.enforcement` on the resource record). Then any profile whose ceiling
covers the grant may serve, and the GUI shows a persistent banner ("SQL grants
on this database are enforced by BastionVault only; the database login can do
more"). Every audit event for such a session carries
`db_enforced: false`. That makes the downgrade explicit and visible, never
silent.

When a write grant runs on a broader login (for example `sql_update` on a
read/write login that can also insert and delete), the excess is
classifier-enforced. The session's enforcement panel lists exactly which
capabilities the database enforces and which only the vault enforces.

#### 5.3 Session-level guards (defence in depth)

- **Read-only sessions:**
  - PostgreSQL connects with `default_transaction_read_only = on`;
  - MySQL and MariaDB use `SET SESSION TRANSACTION READ ONLY`;
  - Oracle uses `SET TRANSACTION READ ONLY` per transaction.

  Statements that would change these are refused (§4.3). SQL Server has no
  equivalent, so there the ceiling is the only database-side control. Oracle's
  autonomous transactions escape a read-only transaction, so for Oracle only a
  read-only login is a database-enforced read-only session.
- **Timeouts at the database:** `statement_timeout` and
  `idle_in_transaction_session_timeout` on PostgreSQL, `max_execution_time` for
  SELECT on MySQL, and driver-side deadlines elsewhere. The plugin's own run
  deadline (§6.3) applies regardless.
- **One connection per session.** No pooling across sessions, so temporary
  tables, session settings, transactions and `USE` never leak between
  operators.

#### 5.4 Credential release and endpoint binding

The plugin never reads secrets with its own authority. It calls
`resource_sql_credential(resource, profile, session_ref)` (§9.2), and the host
releases the credential only if all of the following hold:

1. the plugin holds the admin grant `resource-credentials`, pinned to the
   SHA-256 of its manifest's capability block, as the credential-provider
   grant is today;
2. the **current invocation's caller** holds at least one SQL capability on
   `resources/resources/<resource>/sql/server`;
3. the profile belongs to the resource, has `protocol: "sql"`, and parses
   strictly;
4. the effective Connect transport policy is not `rustion-required` (§6.6);
5. **endpoint binding**: the stored secret names the endpoint it may be sent
   to, in a reserved key `sql_endpoint` (`"host:port"` or a list), and the
   profile's resolved endpoint is in it. For dynamic profiles, the role's
   configured connection endpoint must match.

Rule 5 closes a credential-exfiltration path that only appears when a server
component dials. Without it, a user who may edit the resource *record* but may
not read its secret could repoint `hostname` at a host they control. A SQL
session would then deliver the password to it. That works with MySQL
`caching_sha2_password` full authentication over TLS, MSSQL SQL authentication,
and any cleartext-password method. With rule 5, redirecting a credential
requires `update` on the **secret**, the same authority as replacing it. The
SQL profile editor offers a **Bind credential to this endpoint** action, which
writes `sql_endpoint` and so needs that authority. Existing secrets without
the key cannot be used by the SQL browser until someone binds them, and the
editor says so.

Two further rules apply to every release:

- **Weak authentication is refused when TLS is off.** PostgreSQL `password`
  (cleartext) authentication, MySQL `mysql_clear_password`, and any method that
  sends a reversible password are refused unless the profile's TLS mode is at
  least `require`.
- **Releases are audited by the host**, as `resource-credential-release`:
  actor, namespace, resource, profile, secret id or dynamic role, plugin name,
  session reference. The audit never includes the value. The plugin keeps the
  credential in memory for the session's connection only, zeroizes it on close,
  and never writes it to storage, logs or responses.

#### 5.5 Dynamic credentials (Phase 9, blocked by T62)

With `credential_source.kind = "dynamic"`, the host asks the dynamic-secrets
framework for a database account from the profile's role. The account is
issued on behalf of the SQL session, under the plugin's grant, not the user's
token. Connect-only semantics require that the operator cannot fetch the
credential directly. The account's lease is owned by the session and revoked
when the session closes. Per-tier roles (`netrisk-ro`, `netrisk-rw`,
`netrisk-ddl`) are matched to ceilings exactly as stored profiles are. A
privilege-templated role, whose creation statements receive the caller's grant
rendered as `GRANT`s, is *Future work*.

T62 must provide the following for this phase. They are recorded here so that
T62's design can account for them:

| Requirement | Why | Today |
|---|---|---|
| a host-mediated issue call for engines and plugins, authorized by the session, not by the user's `read` on `creds/<role>` | connect-only: the operator must not be able to fetch the password | no lease or credential host API for plugins |
| early revoke of one lease by its owner component | close the account when the session closes | `revoke_lease_id` is `pub` in `expiration.rs` but not reachable through `bv-kernel-api`; `sys/revoke` is a stub |
| a `revoke-failed` state with retry and an alert | a failed `DROP ROLE` must not orphan a live database account | errors are logged and the lease row is deleted ([expiration.rs:736](../crates/bv-kernel/src/modules/auth/expiration.rs:736)) |
| renewal up to `max_ttl` = the session's absolute lifetime | sessions outlive a short TTL | `ExpirationManager::renew` has no production caller |
| a username template carrying the operator identity | database-side logs attribute actions to a person | — |
| engines for PostgreSQL, MySQL, MariaDB, SQL Server and Oracle | the five engines of this feature | T62 Phase 2 plans MySQL and MSSQL. MariaDB is "future", Oracle is absent |

### 6. Sessions, runs and results

#### 6.1 Lifecycle

```
open ──► idle ◄──► running ──► idle ── … ──► closed
            └─ in transaction ─┘
open:   POST dbms/v2/sessions {resource, profile?, catalog?, mfa_ticket?}
close:  DELETE dbms/v2/sessions/<id> · idle timeout · absolute lifetime · token no longer valid on the next call
        · seal / plugin reload / node shutdown · resource or profile deleted
```

- **Session identity.** A session id is 256 random bits, prefixed with the
  serving node's id. The session is bound to the caller's `entity_id`,
  namespace, resource, profile and an HMAC of the token accessor that the host
  supplies in ABI 1.4. Every request re-checks that binding. A session is
  never usable by another principal, from another namespace, or with a
  different token.
- **Authorization is per statement batch, not per session.** Revoking a share
  or a policy takes effect on the next statement. A statement already running
  is not interrupted, which is documented.
- **Closing with an open transaction rolls it back,** and the rollback is
  audited (`dbms.tx`, `reason`).
- **Idle-in-transaction timeout** (default 5 min) rolls back and keeps the
  session, so a forgotten transaction does not hold locks.

#### 6.2 Asynchronous runs

Every execution is a **run**:

- `execute` (one statement) and `script` (§8.2) authorize the whole request,
  start the run inside the plugin and return within the invoke deadline. The
  response carries `{run_id, state, statements: [{index, kinds, required, verdict}]}`.
- The client polls `runs/<run_id>`. Each response carries the next page,
  messages, the affected-row count and timing.
- `cancel` uses the driver's cancel mechanism:
  - PostgreSQL: `CancelRequest`;
  - MySQL / MariaDB: `KILL QUERY` on a side connection;
  - TDS: attention signal;
  - Oracle: break.
  Phase 0 confirms support per driver.
- Runs survive the 30 s invoke ceiling because they run inside the long-lived
  child, between invocations. No invoke ever holds a statement.

#### 6.3 Results

- **Paged and bounded.** Default page: 500 rows or 4 MiB, whichever comes
  first. Default grid cap per run: 10,000 rows. The plugin stops reading from
  the database when its buffer is full (PostgreSQL portal row limits, MySQL
  streaming result sets, TDS streaming, Oracle fetch arrays), so a huge result
  is never materialized in memory.
- **Type mapping.** Each column reports its native type name and a JSON kind
  (`string | number | boolean | null | binary | json | datetime`).
  - Integers within ±2^53 are JSON numbers. Every other numeric (bigint,
    decimal, numeric, money) is a string, so precision is never lost.
  - Binary is base64.
  - A cell over 64 KiB is truncated, with `truncated: true` and `full_length`.
    The full value is fetched on demand within the run's limits.
  - `NULL` is distinct from the empty string.
- **Per-session row budget** (optional, off by default): a cumulative cap on
  rows read through the grid. It makes page-by-page mass extraction hit a wall
  and an audit event. Without `sql_export`, that is the only bulk path.
- **No server-side result storage.** Pages live in the run buffer until
  fetched or the run expires (default 10 min after completion), and they are
  zeroized on drop.

#### 6.4 Transactions

- **Auto-commit by default.**
- **Manual-commit mode** in the GUI sends `BEGIN` and offers *Commit* and
  *Rollback*. A badge shows "transaction open · 3 statements · 42 s".
- On SQL Server, a T-SQL `BEGIN TRAN` typed by the user is tracked the same
  way.
- In engines with implicit commits on DDL (MySQL, MariaDB, Oracle), the GUI
  warns before a DDL statement inside a transaction.

#### 6.5 High availability

- **Sessions are node-local.** The database connection lives in one node's
  plugin child.
- **Requests for a session reaching another node** fail with a deterministic
  `409 session_on_other_node {node}`. The GUI's client is already sticky to one
  node (S62); on that error it reconnects to the named node, or reopens.
- **Node failure loses the session.** The database rolls back the dropped
  connection's open transaction. Stated in the docs, not hidden.
- **The journal survives.** It is barrier storage, replicated by hiqlite.

Phase 0 confirms how plugin requests are routed between leader and followers.

#### 6.6 Transport policy (Rustion)

The plugin dials from the vault server, so it honours the resource's effective
Connect transport policy:

- **`rustion-required`** — from any tier, locked or not — **refuses** SQL
  sessions with an explicit message naming the tier that set it.
- **`direct` or an unlocked `rustion` preference** permits a direct SQL
  session. The effective transport is shown in the session panel and recorded
  in the audit (`transport: "direct"`).

A Rustion database relay is *Future work*, and cross-repository.

#### 6.7 Seal, reload and shutdown

ABI 1.4 adds host→plugin lifecycle messages:

- on **seal**, **plugin reload or deregistration** and **node shutdown**, the
  plugin closes every session (rolling back open transactions), zeroizes every
  released credential and drops every run buffer;
- the host kills the child if it has not acknowledged within 10 s.

A sealed vault must not leave database sessions open on credentials it
released while unsealed.

### 7. Object browser and grid editing

- **Object browser** (`sessions/<id>/objects`). Catalogs → schemas → tables,
  views, materialized views, routines, sequences, triggers and indexes, loaded
  lazily per node.
  - Reads use plugin-authored catalog queries over `information_schema`,
    `pg_catalog`, `sys.*` and `ALL_*`. They are built only with `bv-sql-guard`
    literal SQL, with every name as a **bound parameter** and never
    interpolated.
  - Browsing a node needs `sql_select` on it; resource-wide grants see
    everything.
  - Objects outside the caller's object-scoped grants are hidden. Hiding is
    best-effort, since the catalog itself may be readable by the login; it is
    not a confidentiality boundary for metadata.
- **Describe** returns columns, keys, indexes and the DDL text (view and
  routine definitions where the login can read them).
- **Grid editing** (`sessions/<id>/rows`) uses **structured operations, not
  SQL text**: `{object, op: insert|update|delete, key: {...}, values: {...}, original: {...}}`.
  - The plugin builds parameterized statements; values are always bound.
    Classification is exact: `sql_update` / `sql_insert` / `sql_delete` plus
    `sql_select` on that object, with no parser involved.
  - Editing is offered only for objects with a primary key or a non-null unique
    key.
  - `UPDATE` and `DELETE` carry the original values of the edited columns in
    the `WHERE` clause. Zero affected rows reports a conflict instead of
    overwriting someone else's change.
  - Identifiers in these statements come from the catalog and must pass
    `SqlIdent`. Tables or columns with names outside
    `[A-Za-z_][A-Za-z0-9_]{0,62}` are **read-only in the grid**; users can still
    write the `UPDATE` by hand, classified normally. This keeps `bv-sql-guard`'s
    reject-don't-escape rule intact (*Open questions* 6).
  - Audit records the object, the operation, an HMAC of the key and the changed
    column names, never the values.

### 8. Export, scripts and step-up

#### 8.1 Export (`sql_export`)

- **Request.** `POST sessions/<id>/export {sql, format: csv|jsonl|sql-insert, max_rows?}`
  starts an export job. "Export table" in the tree composes
  `SELECT * FROM <qualified name>` as ordinary SQL.
- **What may be exported.** Every statement in an export must require only
  `sql_select`. Each object read additionally needs `sql_export` on the same
  object path, so export can be object-scoped too. DML with `RETURNING` cannot
  be exported.
- **Streamed, never staged.** The client pulls 1 MiB chunks
  (`exports/<job>?offset=`), and the plugin reads from the database cursor as
  the client consumes. Nothing is written to the vault host's disk. The Tauri
  host writes the chunks to the file the operator chose, and the webview never
  buffers the export.
- **CSV hardening.** RFC 4180, UTF-8. A *formula guard* is on by default: a
  cell starting with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'`.
- **Limits.** Defaults: 1,000,000 rows and 512 MiB per export; hard maxima in
  §12. An abandoned job expires after 5 min without a pull.
- **Audit** (`dbms.export`): format, row count, byte count, the SHA-256 of the
  exported stream, and the statement digest.
- **What `sql_export` is not.** It is a volume control and an attribution
  point, not data-loss prevention. A caller with `sql_select` can still read
  every row they can page through, so the grid cap and the optional row budget
  (§6.3) bound that path. The docs and the Sharing tab say this plainly.

#### 8.2 Scripts (`sql_script`)

- **The rule.** `execute` accepts exactly one statement, not counting
  transaction-control statements. Anything more is refused with
  `400 use_script`, server-side. The `script` endpoint accepts many and
  requires `sql_script` on `sql/server`, in addition to each statement's own
  privileges.
- **All-or-nothing authorization.** The whole script is split, classified and
  authorized **before the first statement runs**. One refused statement
  refuses the script, and the response names it.
- **Options:**
  - `on_error: stop | continue` (default `stop`);
  - `transaction: none | single`. `single` wraps the script in one
    transaction. The response warns when the engine commits DDL implicitly
    (MySQL, MariaDB, Oracle), so a failed script cannot be fully rolled back
    there.
- **Progress** is streamed through the run: per-statement result, affected
  rows and timing. This is the same message pane as the request screenshot.
- **Limits.** Defaults: 1,000 statements and 4 MiB per script. A `.sql` file
  "upload" is a GUI convenience that reads the file locally and submits its
  text.
- **Audit** (`dbms.script`): statement count, script digest, and a per-statement
  outcome summary. The statement text follows the journal policy (§11).

#### 8.3 Step-up (Phase 5)

- **At session open,** an `sql` profile with `require_mfa` needs a connect
  ticket. The GUI obtains it from the existing
  `resources/v2/connect/mfa/begin|verify`, and the plugin redeems it through
  the `connect_ticket_redeem` host call (§9.2). The 120 s single-use ticket is
  bound to principal, namespace, resource and profile, exactly as today.
- **Per action.** The profile's `step_up` list names capabilities whose *use*
  needs a fresh ticket bound additionally to that action. `sql_drop`,
  `sql_admin`, `sql_export` and `sql_script` are the suggested default.
  Phase 5 extends the ticket binding with an `action` field; older tickets
  without it are not accepted for an action.

### 9. Host substrate (Phase 1)

#### 9.1 Policy language and kernel

- **New capabilities.** Eleven variants in `Capability`: `SqlSelect = 1 << 10`
  … `SqlScript = 1 << 20`, spelled `sql_select` … `sql_script` in HCL.
  - They are probe-only: they map to no `Operation`, like `connect`.
  - They are not implied by any other capability, and they are rejected in
    `allowed_parameters`-style positions.
  - Phase 0 checks the enum's representation width and every bitmask consumer.
- **`bv-policy-core`.** The capability domain is widened. The Kani harnesses
  and the 1,000,000-case differential suite are extended over the new bits,
  and `docs/verification.md` (S108) is updated. Deny supremacy, fail-closed
  default and qualifier soundness must hold for them unchanged.
- **Qualifier resolver.** `resources/resources/<R>/sql/**` → `(resource, R)`.
- **`PolicyGate::sql_privileges`** (§3.4), implemented in `PolicyStore`, with
  denial-store records for refusals.
- **Share vocabulary** (§3.3) and the baseline rule.
- **Policy builder (S44).** SQL capabilities appear as chips. The validator
  explains a check against `…/sql/objects/<c>/<s>/<o>`, and warns when an
  object-scoped policy has no `sql/server` grant (§3.2).

This is an authorization change, so per AGENTS.md L4 (`make test-release`) and
the Kani gate run before it merges.

#### 9.2 Plugin ABI 1.4

`HOST_ABI_MINOR` becomes 4. A plugin declaring `abi_version = "1.4"` is refused
by older hosts, an explicit failure. All new host calls are **caller-bound**:
the host evaluates them against the token of the invocation in flight, which
the plugin never sees. They are valid only during that invocation.

| Host call | Manifest capability + admin grant | Does |
|---|---|---|
| `resource_sql_target {resource}` | `sql_gate = true` + grant `sql-gate` | returns the resource's engine, endpoint fields and parsed `sql` profiles, if the caller holds any SQL capability on it |
| `resource_sql_authorize {resource, checks[]}` | same | `PolicyGate::sql_privileges`; refusals go to the denial store |
| `resource_sql_credential {resource, profile, session_ref}` | `resource_credentials = ["sql"]` + grant `resource-credentials` | §5.4 release, audited by the host |
| `connect_ticket_redeem {resource, profile, ticket, action?}` | `sql_gate = true` | burns an MFA ticket through `VaultCtx::connect_mfa()` |
| `audit_emit` (changed semantics) | `audit_emit = true` | when called inside an invocation that has `caller_identity`, the host stamps the entry with the caller's entity, principal, namespace and token HMAC, and writes it to that namespace's chain. A plugin cannot set or forge the actor |

Grants live at `v2/sys/plugins/<name>/grants/{sql-gate,resource-credentials}`
(GET/PUT/DELETE), pinned to the SHA-256 of the manifest block that requests
them. Any change voids the approval, as the existing credential-provider and
network grants do. The testkit mirrors every new call, and
`tests/test_plugin_testkit_parity.rs` covers them.

#### 9.3 Manifest sketch

```toml
name         = "dbms-management"
version      = "0.1.0"
plugin_type  = "sql-browser"
runtime      = "process"
abi_version  = "1.4"

[capabilities]
long_lived            = true
concurrent            = true        # ABI 1.4 multiplexed invocations (§9.4)
caller_identity       = true
log_emit              = true
audit_emit            = true
storage_prefix        = "dbms/"     # journal + config (§11)
sql_gate              = true        # resource_sql_target / _authorize, connect_ticket_redeem
resource_credentials  = ["sql"]     # resource_sql_credential
sql_console           = true        # the GUI renders its SQL workspace against this mount (§10)
```

Unknown manifest keys are silently ignored today
([crates/bv-plugin-manifest/src/lib.rs](../crates/bv-plugin-manifest/src/lib.rs)).
Every key above that grants authority must be **rejected** by hosts that do
not implement it. The ABI 1.4 refusal guarantees that.

#### 9.4 Concurrent long-lived process invocations

- **Multiplexing.** The stdio JSON-lines protocol gains request ids:
  `invoke{id,…}` / `host_call{id,…}` / `done{id}` / `cancel{id}`. The host
  allows up to `max_concurrent` (default 32) invocations in flight per plugin,
  instead of one mutex-serialized invocation.
- **Timeouts cancel, not kill.** An invocation past its deadline is cancelled
  (`cancel{id}`, then a synthetic error to the caller). The child is torn down
  only for protocol violations or a missed heartbeat, so one slow handler no
  longer drops every user's sessions. The crash breaker is unchanged.
- **Opt-in.** Plugins opt in with `concurrent = true`. Others keep today's
  serialized behaviour unchanged.
- **SDK.** `bastion-plugin-sdk` gains the process runner it currently lacks:
  the read loop, dispatch, host calls and lifecycle messages.

#### 9.5 Resource engine

- **`sql` protocol.** Added to the closed protocol sets (§Current State), with
  a `connect` block for the `database` type. The block enables `sql` for the
  five engines, with default ports 5432, 3306, 3306, 1433 and 1521.
- **Strict SQL profile parsing.** A wrongly typed field fails closed. Older
  GUIs keep unknown-protocol profiles on save (T102).
- **`resources/v2/sql/privileges/<resource>`** (read): the caller's effective
  SQL capabilities on `sql/server` and resource-wide, plus an optional
  `?objects=` list. Granted in the baselines, templated for tenants.
- **MFA for `sql` profiles.** `v2/connect/mfa/begin|verify` accept them.
- **Credential resolution for `secret` sources** with the endpoint binding
  (§5.4). `dynamic` is reserved and refused until Phase 9.

### 10. GUI

- **Placement.**
  - The SQL workspace is **host code** in `gui/src/` (no plugin JavaScript).
    It is rendered when `GET v2/sys/plugins/active-surfaces` reports a mounted
    plugin declaring `sql_console`.
  - It opens from the resource's Connect menu ("Open SQL browser"), from the
    ⌘K palette (resource × `sql` profile), and as a new Session Workspace pane
    kind, `sql`, next to SSH and RDP panes.
  - In session windows (`session.html`), all plugin traffic goes through new
    Tauri commands (`sql_session_open`, `sql_execute`, `sql_script`, `sql_run`,
    `sql_cancel`, `sql_objects`, `sql_rows`, `sql_export_to_file`,
    `sql_session_close`) that use the host-held token. The webview never holds
    a vault token or a database credential, consistent with T110. The pinned
    command set for the `sql` window kind is exactly these.
- **Layout** (the familiar desktop-client model from the request):
  - left: the object tree, with a filter;
  - centre: editor tabs, with a toolbar holding the resource / profile picker,
    the catalog picker, *Run*, *Run selection*, *Stop*, *Explain*, *Format* and
    the transaction controls;
  - bottom: result tabs (one per statement), *Messages* (statement echo,
    affected rows, query time) and *History* (from the journal);
  - right: an info panel with the resource and profile, **effective SQL
    privileges as chips**, enforcement (database-enforced vs vault-only
    capabilities, `db_enforced`), transport, and session timers.
- **Privilege-aware UI.**
  - Buttons and grid editing are disabled for missing capabilities; this is a
    convenience only.
  - Refused statements show the vault's verdict: "needs `sql_update` on
    `netrisk.public.permission_to_user`".
  - Confirmation dialogs for `DROP`, `TRUNCATE`, and `DELETE` or `UPDATE`
    without `WHERE`. These are UX guards, not controls.
- **Libraries.** The GUI has no editor or grid today; Phase 0 confirms the
  bundle-size cost.
  - **CodeMirror 6** (`@codemirror/state`, `view`, `commands`, `autocomplete`,
    `lang-sql`; MIT). `lang-sql` ships PostgreSQL, MySQL, MariaDB, MSSQL and
    PL/SQL dialects. Autocomplete is fed from the object browser.
  - **`@tanstack/react-virtual`** (MIT, headless) for the grid.
- **Data handling.** Results are held in memory only and dropped when a tab or
  session closes. No result reaches disk except through an export the operator
  saves. Copying cells to the clipboard is allowed; that is a usability choice,
  not a boundary, and the docs say so.
- **Resource page.**
  - The **Connection** tab gains the SQL profile editor: engine-aware fields
    (Oracle service, MSSQL instance), TLS mode with CA / pin, the ceiling,
    `require_mfa`, `step_up`, the credential picker, *Bind credential to this
    endpoint*, and the ceiling-probe result.
  - The **Sharing** tab gains the SQL chips and presets (§3.3).
- **AGENTS.md GUI rules apply:** no `max-w-*` on pages, `min-w-0` + `truncate`
  on names and hosts, `Modal` sizes, and `grid grid-cols-2 gap-3` forms.

### 11. Audit and journal

| Event | When | Fields (beyond actor, namespace, resource, profile, session) |
|---|---|---|
| `dbms.session.open` / `.close` | open, close | engine, server version, enforcement mode, `db_enforced`, transport, close reason |
| `resource-credential-release` | host, per release | secret id or dynamic role, plugin, session ref |
| `dbms.statement` | every executed statement | kinds, required capabilities, objects, outcome, rows affected / returned, duration, statement digest (HMAC), `unclassified` flag |
| denial record | every refused check | synthetic path, capability, plugin (host-written to the denial store) |
| `dbms.row_edit` | grid edit | object, op, key HMAC, changed column names |
| `dbms.tx` | commit, rollback, auto-rollback | statement count, reason |
| `dbms.export` / `dbms.script` | export, script | §8 |

- **Actor.** Stamped by the host (§9.2), not by the plugin.
- **Redaction.** Audit bodies are HMAC-redacted by the existing device: string
  leaves become digests, while numbers and booleans pass through. Statement
  text in the audit stream is therefore a digest. Row counts stay readable.
- **The journal** is the readable record, kept in the plugin's barrier storage
  under `core/plugins/dbms-management/data/dbms/journal/<namespace>/<date>/<session>`.
  - Each record is versioned (`v: 1`) and lists every statement of a session
    with its outcome.
  - Statement text follows the resource's `journal_text` setting:
    - **`redacted`** (default): literals replaced by `?` through the parser;
    - `full`: exact text, for regulated environments that need it, with a
      warning that statements can carry personal data and secrets;
    - `none`.
  - Retention defaults to 90 days, purged daily.
  - Operators read their own history at `dbms/v2/journal/self/…`. Auditors read
    everyone's at `dbms/v2/journal/all/…`, a separate path an administrator
    grants. The host enforces both before dispatch, and the plugin filters
    `self` by the caller's entity.
- **Database error messages** are returned to the caller but stored only
  redacted. Errors like unique violations echo row values
  ("Key (email)=(…) already exists").

### 12. Configuration and limits

Plugin config (`dbms/v2/config`, admin). The resource or profile can lower
these, never raise them. Defaults are proposals that Phase 0 confirms.

| Setting | Default | Hard max |
|---|---|---|
| statement / run timeout | 60 s | 1 h |
| page size | 500 rows / 4 MiB | 5,000 rows / host payload limit |
| grid rows per run | 10,000 | 100,000 |
| per-session row budget | off | — |
| idle session | 15 min | 8 h |
| idle in transaction | 5 min | 1 h |
| absolute session lifetime | 8 h, never past the token's expiry | 24 h |
| sessions per user / per resource / per node | 5 / 20 / 200 | 50 / 500 / 2,000 |
| script statements / size | 1,000 / 4 MiB | 10,000 / 32 MiB |
| export rows / bytes | 1,000,000 / 512 MiB | 10,000,000 / 4 GiB |
| run buffer retention after completion | 10 min | 1 h |
| `allowed_networks` (CIDRs the plugin may dial) | private ranges; loopback, link-local and the vault's own listeners excluded | — |

`allowed_networks` is enforced by the plugin before dialling, and the dialled
address is re-checked after DNS resolution. It is defence in depth against a
resource record pointing at metadata services or the vault itself. Process
plugins have no OS sandbox today (§Current State), and that residual risk is
stated in *Security Considerations*.

### 13. Compatibility and migration

- **Policies (rolling upgrades).** Policies are HCL text and the change is
  additive. But a policy using `sql_*` must not be written while any cluster
  node still runs a version that cannot parse it. Phase 1 gates writing
  `sql_*` capabilities on every node reporting a version that understands them
  (*Open questions* 2). Older nodes would otherwise fail to load the policy.
  Implemented in *Phase 1, subsystem 4* (`GET v2/sys/policy-schema`).
- **Shares.** The vocabulary change is additive. Older nodes drop unknown
  entries on write and ignore them on read, which fails closed.
- **Resource records.** `sql` profiles and `sql.enforcement` are new keys in a
  schema-less record. Pre-T102 GUIs drop unknown-protocol profiles on save;
  the upgrade notes say to update GUIs first.
- **Secrets.** `sql_endpoint` is a new reserved key; existing secrets are
  untouched. Using a secret from the SQL browser requires binding it once
  (§5.4).
- **Plugin ABI.** 1.4 is additive. Plugins at 1.0–1.3 load unchanged, and
  their long-lived processes keep the serialized behaviour.
- **Journal.** A new versioned record (`v: 1`), read-old/write-new from its
  first release.
- **No existing persisted format changes shape.** The capability bitmask is
  computed at policy load and is not persisted (Phase 0 verifies).

## API surface (all `v2`)

Plugin mount (suggested `dbms/`); paths below are mount-relative.

| Path | Op | Purpose |
|---|---|---|
| `v2/config` | read, update | plugin limits, `allowed_networks`, journal defaults (admin) |
| `v2/sessions` | create, list | open a session; list the caller's own sessions |
| `v2/sessions/<id>` | read, delete | status; close |
| `v2/sessions/<id>/execute` | create | run one statement (plus transaction control) |
| `v2/sessions/<id>/script` | create | run a multi-statement script (`sql_script`) |
| `v2/sessions/<id>/runs/<run>` | read | state, next page, messages |
| `v2/sessions/<id>/runs/<run>/cancel` | create | cancel a run |
| `v2/sessions/<id>/objects` | list, read | object browser; `describe` |
| `v2/sessions/<id>/rows` | create | structured grid edit |
| `v2/sessions/<id>/export` | create | start an export (`sql_export`) |
| `v2/sessions/<id>/exports/<job>` | read | pull the next chunk |
| `v2/journal/self/…` | list, read | the caller's own statement history |
| `v2/journal/all/…` | list, read | everyone's history (auditors) |

A suggested `sql-browser-user` policy template, offered at plugin registration,
grants `create, read, update, delete, list` on `dbms/v2/sessions*` and `read,
list` on `dbms/v2/journal/self/*`. Granting the session paths is safe: the
session API does nothing without SQL capabilities on some resource.

Host additions:

| Path | Op | Purpose |
|---|---|---|
| `resources/v2/sql/privileges/<resource>` | read | caller's effective SQL capabilities |
| `resources/v2/connect/mfa/begin`, `…/verify` | create | now accept `sql` profiles (and, Phase 5, an `action`) |
| `v2/sys/plugins/<name>/grants/sql-gate` | read, update, delete | admin grant, pinned to the manifest block hash |
| `v2/sys/plugins/<name>/grants/resource-credentials` | read, update, delete | admin grant, pinned to the manifest block hash |

`docs/api.md`, `docs/configuration.md` and an operator guide
(`docs/sql-browser.md`) are written with the phases that ship each surface.

## Phases

### Phase 0 — verification spike and decisions (T124)

No production code. The answers are appended to this spec before Phase 1
starts.

1. **Capability model sign-off.** Confirm the SQL capability family (§3, §9.1)
   against the alternatives, given the `bv-policy-core` verification cost.
   Check `Capability`'s representation width and every bitmask consumer.
2. **Process runtime.** Design the multiplexed protocol (§9.4) and measure
   latency and memory with 50 concurrent sessions.
3. **Classifier corpus.** At least 500 statements per dialect, including every
   §4.3 hazard. Measure `sqlparser`'s coverage of PostgreSQL, MySQL / MariaDB,
   T-SQL and Oracle, and list the gaps per dialect.
4. **Drivers.** Build `tokio-postgres` with rustls, `mysql_async` with rustls
   and no default features, and `tiberius` with rustls inside `plugins-ext`.
   `cargo tree` must show no `openssl-sys`. Pick the rustls crypto provider
   consistently with root `Cargo.toml:291-298`. Confirm cancellation per
   driver, and MariaDB `client_ed25519` authentication.
5. **Oracle path.** Either a maintained pure-Rust thin-protocol driver
   (TCPS, 12c+ verifier authentication), or ODPI-C (`oracle` crate) with Oracle
   Instant Client **loaded at run time and never bundled**. The second mirrors
   how OpenH264 is loaded for RDP EGFX. It needs explicit operator opt-in, and
   is documented as a crypto/TCB exception confined to the plugin process.
6. **GUI.** Measure the bundle-size delta of CodeMirror 6 and TanStack Virtual.
7. **HA.** Which node serves plugin requests, and does the sticky client
   honour `session_on_other_node`?
8. **Payload limit.** Find the host's maximum plugin response size, which
   bounds the page size.
9. **Rolling upgrades.** Design the gate for writing `sql_*` capabilities.

#### Phase 0 findings (appendix, 2026-10-21)

Status legend: **verified** = checked in this tree or in the cited docs;
**decide** = needs the maintainer; **open** = needs a measurement or prototype
that has not been run, with the acceptance check named.

1. **Capability model — verified, decide D1.** `Capability` is
   a fieldless enum cast to `u32` by `*self as u32` with explicit
   discriminants (`crates/bv-kernel/src/modules/policy/policy.rs:181-206`); bits 10–20 are
   free, so `SqlScript = 1 << 20` fits. Consumers that must change with the
   eleven variants:
   - `CAP_*` constants and the bit-layout host test
     (`crates/bv-policy-core/src/lib.rs:64-82`);
   - the differential mapping table
     (`crates/bv-kernel/src/modules/policy/differential/mod.rs:440`);
   - `to_granting_capabilities`, which iterates `EnumIter`
     (`policy.rs:749-754`), so SQL names would appear in every listing;
   - the share vocabulary `ALLOWED`
     (`crates/bv-kernel/src/modules/identity/share_store.rs:857`);
   - **`ShareCap` is `u8` with four bits** (`bv-policy-core/src/model.rs:286-293`,
     Kani target `proofs.rs:430` is `u8`). The §3.3 share vocabulary cannot
     reuse that type without widening it and re-running the proofs. (Update,
   T124 subsystem 1: `ShareCap` is now `u16` with 15 variants; the share
   harness is `t6_scope_gate_is_sound`, and `proofs.rs:430` is the
   asset-group harness and stays `u8`.)

   **D1 (maintainer):** keep the eleven variants in the single `Capability`
   enum as §9.1 says (one decision path, deny supremacy proved once), accepting
   the widening of `ShareCap` and the Kani re-run; or put SQL in a separate
   bitmap evaluated only by `PolicyGate::sql_privileges`, which leaves the
   existing proofs untouched but duplicates the deny logic. Recommendation: the
   first, because §3.1 requires that deny and fail-closed behaviour hold for
   SQL unchanged, and a second evaluator is the larger proof burden.

   **Rolling-upgrade hazard (open, check before Phase 1):** an older node that
   meets `sql_select` in HCL must refuse or ignore it. Confirm whether
   `Capability::from_str` failure rejects the whole policy or one path. If it
   rejects the policy, the §Phase 9 gate must hold `sql_*` writes until every
   node is on ABI 1.4 (item 9).

2. **Process runtime — verified design gap, open measurement.** Today the host
   reads one invocation's stdout with `read_line` on a single `BufReader`
   (`src/plugins/process_runtime.rs:255`, `:292`), so invocations are
   serialized per child. §9.4 multiplexing needs one reader task that routes
   `done{id}` / `host_call{id}` to per-invocation channels, one writer behind a
   lock, `cancel{id}`, and `max_concurrent = 32`. The 50-session latency and
   memory target is **open**: it needs a prototype child that answers 50
   interleaved invocations, measured against the serialized baseline. The
   acceptance threshold is for the maintainer to set (**D5**).

3. **Classifier corpus and `sqlparser` coverage — external verified, open
   measurement.** `sqlparser` ships `PostgreSqlDialect`, `MySqlDialect`,
   `MsSqlDialect` and `OracleDialect` ([docs.rs dialect index](https://docs.rs/sqlparser/latest/sqlparser/dialect/index.html)).
   No corpus exists in the tree yet. The 500-per-dialect corpus must include
   every §4.3 hazard before any coverage number means anything. Acceptance: a
   table of parse failures per dialect, each row either classified or refused
   as `Unclassifiable`, with no row defaulting to `sql_select` (§4.1). Owner of
   the corpus: the `bv-sql-classify` work in Phase 2 unless the maintainer
   wants it earlier.

4. **Drivers and rustls — verified state, open build.** The existing
   `plugins-ext/bastion-plugin-postgres` uses `tokio-postgres` with
   `default-features = false, features = ["runtime"]` and no TLS
   (`plugins-ext/bastion-plugin-postgres/Cargo.toml:19-23`), so TLS is new
   work. None of `sqlparser`, `mysql_async`, `tiberius` or `tokio-postgres`
   appears in the root `Cargo.lock`. Root `Cargo.toml:241` pins rustls with
   `aws_lc_rs`; the drivers should use the same provider. The
   `cargo tree -i openssl-sys` check (must be empty) is **open**: it is a cold
   build inside `plugins-ext`, so run it once, alone, after the lock is
   generated.

5. **Oracle — external verified, decide D2.** Two routes:
   - Oracle's own pure-Rust thin driver `oracledb` is in preview
     (26.0.0-beta.1) and supports TCPS, but its cancellation API is
     plain-TCP only, with no TCPS or Windows support yet (crates.io and
     the project's README, found via web search). §6 requires cancellation per
     driver, so this route fails today on TCPS.
   - ODPI-C (`oracle` crate) with Instant Client loaded at run time, opt-in,
     and documented as a TCB exception confined to the plugin process (§Phase
     0 item 5 as written).

   **D2 (maintainer):** Recommendation: defer the Oracle choice to Phase 8 and
   re-check `oracledb` for GA with TCPS cancellation then. Phases 1–7 do not
   depend on it. If Oracle is needed sooner, choose ODPI-C behind explicit
   operator opt-in. Either way, vet the crate's publisher and supply chain
   before adding it.

6. **GUI bundle — verified baseline, open measurement.** `gui/package.json`
   has neither CodeMirror 6 nor TanStack Virtual, so the delta is additive.
   Measure with `vite build` before and after adding them, in a scratch
   worktree, and record gzip size. Accept if the SQL workspace adds less than
   the owner's budget (**D3**: maintainer sets the number).

7. **HA — open.** Not yet read: which node serves plugin requests, and whether
   the sticky client honours `session_on_other_node`. The answer needs a read
   of the HA client path before Phase 1 touches sessions. Acceptance: a
   written answer with `path:line` citations, and a test plan for a session
   opened on node A and invoked on node B.

8. **Payload limit — verified gap.** The process runtime has no response size
   cap. Stdout lines are read with unbounded `read_line`
   (`process_runtime.rs:292`). The only existing caps are
   `MAX_RESPONSE_BYTES = 4 MiB` for host HTTP (`src/plugins/net_http.rs:25`)
   and `MAX_PAYLOAD_BYTES = 4 MiB` for WASM hooks
   (`crates/bastion-plugin-testkit/src/hooks.rs:23`). **Proposal:** add a
   bounded line reader to the process runtime at 4 MiB, the same value,
   failing the invocation (not the child) on overflow. Page size is then
   derived from that cap, not chosen separately. This change is a prerequisite
   for §9.4, because a multiplexed child can otherwise starve the reader.

9. **Rolling upgrades — decide D4, open check.** Proposed gate: a cluster-wide
   setting that the host sets to "SQL capabilities writable" only when every
   active node reports `HOST_ABI_MINOR >= 4` and the policy schema version that
   accepts `sql_*`. Until then the validator refuses to write `sql_*` but the
   parser still accepts them on read, so an upgrade never leaves a policy that
   an old node cannot load silently. **D4:** confirm that a stored `sql_*`
   policy written before the gate closes must not be auto-removed on
   downgrade, only refused at evaluation on old nodes.

**Decisions recorded (2026-10-21, maintainer accepted the recommendations):**

- **D1 — accepted.** SQL capabilities stay in the single `Capability` enum.
  `ShareCap` is widened from `u8` and the Kani harnesses and differential suite
  are re-run over the new bits.
- **D2 — revised 2026-10-21: Oracle is implemented now, on ODPI-C.** The
  driver is the `oracle` crate with Oracle Instant Client loaded at run time,
  never bundled, behind explicit operator opt-in, confined to the plugin
  process as a TCB exception. Rejected: Oracle's pure-Rust `oracledb`, whose
  cancellation is plain-TCP only (§6 requires cancel over TCPS), and the
  pure-Rust `oracle-rs` (no cancellation API found).
  **Cancellation design:** `Connection::break_execution` (OCI break, sent from
  a second thread) as the primary path, with `set_call_timeout` armed before
  each call as the backstop. A cancelled call is reported as cancelled and the
  connection is discarded, not reused. Verify over TCPS in the spike below;
  if break does not interrupt a TCPS call, the session is torn down rather
  than left running.
  **Scope gate:** the spike needs no SQL capability, classifier or plugin
  wiring. It is a standalone crate in `plugins-ext` that connects, runs a
  long query, breaks it and checks the error, against `gvenzl/oracle-free` in
  Docker. Phases 1–3 still gate the production path (§Phase 8 depends on the
  plugin and classifier). The publisher and supply chain of the `oracle` crate
  and the Instant Client download source are vetted before the spike merges.

  **Spike results (2026-10-21, `oracle` 0.6.3, Oracle AI Database 26ai Free
  23.26.3.0.0 in `gvenzl/oracle-free:slim`, client libs from that image,
  linux/arm64, built in `rust:slim`; the spike lives in the session scratch
  directory, not in the repository):**

  - Connect, `query_row_as`, `set_call_timeout`, `break_execution` and reuse of
    the connection after a cancel: **verified over plain TCP.** A 3-second
    timeout cancels with ORA-03156 at 3.01 s. `break_execution` (from a second
    thread, via `Arc`) returns in 0.85–9.5 ms and cancels with ORA-01013 at
    3.0 s; the connection still answers `select 1`.
  - **TCPS: not verified.** The Free image has no `orapki` jars
    (`oraclepki.jar` is absent), so no Oracle wallet could be created. PEM and
    PKCS#12 (empty-password) wallets were both refused by the listener with
    ORA-28759 / TNS-00566. The listener was restored to plain TCP. TCPS
    cancellation stays open for D2 and needs a wallet made by a full Oracle
    install (`orapki`, or `dbca`'s TLS setup) before the decision is final.
  - The client needs more than `lib/`. A missing `nls`, `network`,
    `oracore/mesg` or `rdbms/mesg` directory segfaults inside `libclntsh` on
    the first OCI error. `libaio.so.1` is required; Debian ships
    `libaio.so.1t64`, so the test build symlinked it. Production packaging must
    ship the same set.
  - This image's server `sqlnet.ora` sets `DISABLE_OOB=ON` and
    `BREAK_POLL_SKIP=1000`. The spike client read no `sqlnet.ora`, so these did
    not affect the result. Check them against the cancel path before
    production, because OOB is the usual break channel.
  - `cargo tree -i openssl-sys` on the `oracle` crate was not run. It is still
    required before merge.

  D2 is accepted by the maintainer for TCP only (2026-10-21). Cancel over TCPS
  is not verified and must not be treated as working. TCPS stays an open item
  that blocks any production claim about cancellation over TLS.
- **D3 — no value.** The recommendation was that the maintainer sets the GUI
  bundle budget. No number was given, so the budget stays open and the
  measurement in item 6 is required before Phase 4 merges.
- **D4 — accepted.** Writes of `sql_*` are gated on every node reporting
  ABI 1.4. A stored `sql_*` policy is never auto-removed on downgrade; old
  nodes refuse it at evaluation.
- **D5 — no value.** The recommendation was that the maintainer sets the
  50-session threshold. No number was given, so the threshold stays open and
  is required before Phase 1 merges.

**Measurement results (2026-10-21):**

- **Item 1, rolling upgrade — confirmed.** `Policy::from_str` deserializes
  `capabilities` with `hcl::from_body` into `Vec<Capability>`
  (`crates/bv-kernel/src/modules/policy/policy.rs:327`, field at `:141`). An
  unknown name such as `sql_select` fails that call with `?`, so the whole
  policy is refused on an older node. That is fail-closed, but it removes every
  path of the policy there. This is the reason for the D4 write gate.
- **Item 2, 50-session model — measured on a model, not the runtime.** A child
  with a 20–200 ms sleep and no database, 50 sessions × 20 invocations, Docker
  on macOS arm64, one run per model:

  | Model | p50 | p99 | max | RSS harness / child |
  |---|---|---|---|---|
  | serialized (today) | 5674 ms | 6086 ms | 6198 ms | 2.8 / 2.6 MiB |
  | multiplexed (32 in flight, one reader) | 172 ms | 277 ms | 305 ms | 2.8 / 2.6 MiB |

  Serialized invocations at 50 sessions queue for seconds. Multiplexing adds
  about 24 KiB to the harness and 36 KiB to the child. Caveats: one run each,
  no host_call round trip, no cancel, no result payload, no real driver.
- **Item 3, sqlparser coverage — measured on our own corpus.** `sqlparser`
  0.63.0 over 520 generated statements per dialect (2,080 total): PostgreSQL
  512, T-SQL 506, MySQL/MariaDB 505, Oracle 497 accepted. Gaps that the
  classifier must handle explicitly in Phase 2: anonymous blocks and PL/SQL,
  `DO $$`, procedure bodies, MySQL executable comments and T-SQL `GO` (refuse
  them), file writes and `xp_cmdshell` (refuse, §4.2), and maintenance and
  utility commands (`VACUUM`, `REINDEX`, `OPTIMIZE`, `DBCC`, `BULK INSERT`,
  Oracle `INSERT ALL`). "Accepted" means no parse error only; tree correctness
  is not checked, and most hand-written families have one sample.
- **Item 4, drivers — checked, not built.** With `default-features = false`,
  `tokio-postgres` (`runtime` plus `tokio-postgres-rustls`), `mysql_async`
  (`rustls-tls`), `tiberius` (`rustls`) and `oracle` 0.6.3 show no
  `openssl-sys` in `cargo tree`. `aws-lc-sys` is present through rustls, which
  is the chosen provider (`Cargo.toml:241`). Not compiled or linked on
  macOS, Linux or Windows.
- **Item 6, GUI bundle — measured, minimum case.** A Vite build with React
  19 and CodeMirror 6 (`lang-sql`) plus TanStack Virtual adds 106 kB gzip to a
  68 KiB baseline (70,058 → 176,076 bytes). Most of the addition is
  `lang-sql`. The real workspace imports more, so this is a floor.
  Measured with the host Node (v26), not the `node:22-slim` image, which was
  not pulled.
- **Item 7, HA — read.** No `session_on_other_node` or sticky mechanism exists
  in `src/` or `crates/`. `bv-client` pins one node per backend and fails over
  only idempotent operations when the node is unavailable
  (`crates/bv-client/src/remote.rs:837`). Decision D6 below.

**Decided values (confirmed by the maintainer, 2026-10-21):**

- **D3, GUI bundle budget:** load the SQL workspace with a dynamic import so
  the main chunk is unchanged for users who never open it, and cap the SQL
  chunk at 150 kB gzip. The measured floor is 106 kB, leaving room for the
  real workspace.
- **D5, 50-session threshold:** on the model, multiplexed p99 must stay at or
  below 500 ms at 50 sessions with a 20–200 ms backend delay. The real runtime
  must then keep p99 within 1.5× of the single-session p99 on the same
  workload, and be re-measured with the real driver before Phase 1 merges.
- **D6, session-bound operations and node loss (confirmed 2026-10-21):**
  operations on an SQL session never fail over to another node. A session
  holds a live database connection, possibly an open transaction, and a
  credential released for one endpoint (§5.4). When the node holding it becomes
  unavailable, the session ends, the workspace says so, and the user opens a
  new session, which may land on another node. Read failover in `bv-client`
  stays limited to idempotent requests that are not bound to a session.
  Replicating sessions across nodes is out of scope for T124 and needs its own
  design before it is considered.

**Result of Phase 0 (closed 2026-10-21):** D1, D2 (TCP only), D3 (150 kB gzip
SQL chunk, lazy-loaded), D4, D5 (p99 ≤ 500 ms on the model, re-measured with
the real driver before Phase 1 merges) and D6 (no failover for session-bound
operations) are decided. Items 1 to 4, 6 and 7 are
measured or read. Open items that Phase 1 and later must close: TCPS
cancellation (D2), the `openssl-sys` check on the real build, the
rolling-upgrade gate, and the real-runtime 50-session measurement. Phase 1 may
start; T124 stays `[ ]` until its exit gate (`make test-release` and the Kani
gate) passes.

### Phase 1 — host substrate (T124)

§9 in full:

- SQL capabilities in the policy language, `bv-policy-core` with Kani and
  differential coverage, the qualifier resolver, `PolicyGate::sql_privileges`
  and denial records;
- the share vocabulary and the baseline rule;
- the policy-builder chips and the sharing chips and presets;
- ABI 1.4: the host calls, grants, actor-stamped audit, lifecycle messages,
  multiplexed invocations, the SDK process runner and testkit parity;
- the resource engine's `sql` protocol, profile parsing, credential resolution
  with endpoint binding, `v2/sql/privileges`, and MFA for `sql` profiles;
- the GUI SQL profile editor.

**Exit:** `make test-release` (L4: authz and plugin ABI) and the Kani gate are
green.

### Phase 2 — the `bv-sql-classify` crate (T125)

- dialect tables for PostgreSQL first (MySQL / MariaDB, T-SQL and Oracle
  tables land with their engine phases);
- the hazard corpus from Phase 0 as tests;
- property tests: every input yields classified statements with a non-empty
  requirement set, or `Unclassifiable`;
- a fuzz target that never panics and never yields an empty requirement set for
  a non-transaction-control statement;
- lexer-setting handling.

### Phase 3 — the plugin with PostgreSQL (T125)

- Sessions, profile selection and ceilings (§5.2), endpoint binding, TLS modes
  and weak-authentication refusal.
- Asynchronous runs, paging, cancel and transactions.
- The object browser, describe, structured row edits and the ceiling probe.
- Read-only guards, limits, `allowed_networks` and transport policy.
- HA affinity, and seal / reload / shutdown handling.
- Audit events and the journal.
- An `AuthorizedStatement` newtype that only the authorization step can
  construct. The single function that sends user SQL to a driver takes it, so a
  path that executes unauthorized SQL does not compile.

### Phase 4 — GUI SQL workspace (T125)

- the route, the Session Workspace `sql` pane and the `sql_*` Tauri commands
  with their pinned command set;
- tree, editor, grid, messages, history and the info panel;
- privilege chips and the enforcement panel;
- grid editing with conflict reporting;
- confirmations;
- the Connect menu and ⌘K entries.

### Phase 5 — export, scripts and per-action step-up (T126)

§8: export jobs (CSV, JSON Lines, SQL `INSERT`) with streaming, the formula
guard, limits and audit; the script endpoint with all-or-nothing
authorization, the `on_error` / `transaction` options and progress; and
per-action step-up (the ticket `action` binding).

### Phase 6 — MySQL and MariaDB (T127)

The `mysql_async` driver without `CLIENT_MULTI_STATEMENTS` and without a
`LOCAL INFILE` handler; `sql_mode` pinning; executable-comment refusal; the
MySQL / MariaDB dialect table; read-only transactions; the ceiling probe
(`SHOW GRANTS`); `KILL QUERY` cancellation; integration tests against both
servers.

### Phase 7 — Microsoft SQL Server (T128)

The `tiberius` driver over rustls with SQL authentication; named instances; the
T-SQL dialect table, including lock hints, `OUTPUT`, `EXEC`, `EXECUTE AS` and
the always-refused `xp_*` / `OPENROWSET` family; `QUOTED_IDENTIFIER` pinning;
the batch-protocol residual surfaced in the GUI (§4.3); the ceiling probe
(`fn_my_permissions`); integration tests.

### Phase 8 — Oracle Database (T129)

The Phase 0 driver decision implemented: services and PDBs; PL/SQL blocks as
opaque; `EXECUTE IMMEDIATE`; the `UTL_*` / `DBMS_*` function table; read-only
transactions with the autonomous-transaction caveat (§5.3); the ceiling probe
(`SESSION_PRIVS`); integration tests against Oracle Database Free.

### Phase 9 — dynamic database credentials (T130, blocked by T62)

`credential_source.kind = "dynamic"`; session-owned leases with early revoke;
per-tier roles matched to ceilings; dynamic-first profile selection; endpoint
match against the role's connection; audit. This needs T62 plus the
requirements in §5.5.

## Dependencies

| Depends on | For |
|---|---|
| S41 / S40 / S39 plugin system, extensibility, app extensions | runtime, manifest, grants, surfaces discovery |
| S42 plugin testing | testkit parity for ABI 1.4 |
| S33 per-user scoping (shares) | share vocabulary, scopes gate, baselines |
| S47 / S2 asset groups | `groups = [...]` qualifier, asset-group shares |
| S10 connect-only, S46 resource connect, S9 connect MFA | credential hiding, profiles, tickets |
| S48 database resource type | engine and endpoint fields |
| S51 Rustion | effective transport policy (§6.6) |
| S56 Session Workspace | the `sql` pane kind, `session.html` command pinning |
| S62 cluster client discovery | sticky node affinity (§6.5) |
| S65 / S108 formal verification | capability-domain extension of the verified core |
| S44 policy builder | SQL chips, object-path validation |
| S3 audit logging | redaction, chain, denial store |
| S13 dynamic secrets (T62) | Phase 9 only — blocks T130 |

## Security Considerations

| Threat | Control | Residual |
|---|---|---|
| A select-only user changes data | kernel decision per statement; read-only login required by default (`database-first`); read-only transaction guard | `classifier-only` resources rely on the classifier alone, which is visible and audited |
| The classifier is fooled (smuggling, lexer tricks, CTE DML) | execute only classified spans, one per round trip; protocol-level multi-statement off; lexer pinning; fail closed on unknown; corpus + fuzzing | SQL Server batches; mitigated by the ceiling |
| Side effects inside `SELECT` | function table; `sql_execute` for user functions outside read-only sessions; always-refused server file and OS functions | unknown built-ins with side effects — the database login is the backstop |
| Operator obtains the database password | never released to the client; no `read` needed; endpoint binding; weak authentication refused without TLS | a user with `read` on the secret can still read it — the share UI does not suggest it |
| Credential redirected to an attacker's host by editing the resource record | endpoint binding (`sql_endpoint` on the secret, §5.4) | none beyond secret-write authority |
| Plugin used as a network pivot (SSRF to metadata or internal services) | the endpoint comes from the host only; `allowed_networks` checked after DNS; vault listeners excluded | process plugins are not OS-sandboxed today: an OS-level egress policy (container network policy, firewall) is recommended in the operator guide; a host socket broker plus seccomp is *Future work* |
| A compromised plugin | signed, admin-granted (grants pinned to the manifest hash); per-session credential release, never at rest; database ceilings bound what any released login can do | a compromised plugin can use the logins it is given while sessions are open |
| Mass extraction | `sql_export` separate; grid cap; optional row budget; export audit with SHA-256 | a `sql_select` holder can page within caps — stated, not hidden |
| Sessions outlive authorization | per-batch authorization; token-accessor binding; idle and absolute limits; seal tears down | a running statement completes after revocation |
| Denials invisible | host-written denial records for every refused check | — |
| Forged audit actor | the host stamps the actor; the plugin cannot set it | — |
| Personal data in logs | statement text HMAC'd in audit; journal `redacted` by default; error messages redacted at rest | `journal_text = full` is an explicit opt-in |
| Lock-holding forgotten transactions | idle-in-transaction rollback | — |
| Cross-tenant use | session bound to namespace; per-namespace mounts; templated baselines | — |

Review priority, per AGENTS.md: secret leakage (§5.4) → authorization
correctness (§3, §4) → crypto (TLS modes, rustls only, the Oracle exception in
Phase 0) → migration (§13) → debuggability (§11) → performance (§6).

## Testing Plan

### Kernel and host (Rust unit, `-p bv-policy-core`, `-p bv-kernel`, `-p bastion_vault`)

- Capability parsing and round trip.
- Probe-only behaviour: not implied by `read`, `update`, `sudo` or `connect`;
  root passes.
- Deny supremacy on SQL paths. The policy, share, asset-group share and
  group-grantee arms. Owner grants nothing.
- Qualifier resolution for `…/sql/**`, and object versus `server` paths.
- Denial-store records written for refusals.
- Kani harnesses and the differential suite extended over the new bits.
- ABI 1.4 host calls refuse outside an invocation, refuse without their grant,
  and void the grant when the manifest block changes. Credential release
  refuses a missing or mismatched `sql_endpoint`, a non-`sql` profile, a caller
  with no SQL capability, and `rustion-required`.
- Actor stamping cannot be overridden by the plugin.
- Multiplexed invocations: concurrency, cancellation without killing the
  child, the crash breaker unchanged.
- Seal tears sessions down within the deadline.

### Classifier (`-p bv-sql-classify`)

- The per-dialect corpus, including every §4.3 hazard as a named test.
- Property tests and the fuzz target (Phase 2).
- Lexer settings: the same text under different `sql_mode` values.

### Plugin (testkit + containers)

- Testkit (`TestHost::invoke_process`) with mocked host calls: authorization
  outcomes, release refusals, actor-stamped audit, limits, session binding.
- Integration tests against containerized PostgreSQL, MySQL, MariaDB, SQL
  Server and Oracle Free, behind an opt-in `make test-dbms` target that is not
  part of `make test`, as the hiqlite suites are. Every refused hazard is
  checked to leave a **canary table unchanged**.

### Cucumber (`plugins-ext/bastion-plugin-dbms-management/tests/features/sql_browser.feature`, run by `make test-dbms`)

- A select-only share cannot update.
- Revoking a share takes effect on the next statement.
- Export without `sql_export` is refused.
- A script with one refused statement runs nothing.
- `classifier-only` sessions are flagged in audit.

### Frontend (vitest)

- Privilege chips and disabled actions; verdict messages.
- Grid edit and conflict.
- Script confirmation; the `classifier-only` banner; the profile editor's
  strict parsing.
- The `sql` window kind's pinned command set (Tauri ACL resolver test, the
  T110 precedent).

### Security regressions

- No HTTP response, log line or audit entry contains a released credential.
  Tests grep every captured response and log line for a planted password.
- The webview never receives one.

### Manual, per release

Each engine against a real server: TLS verify-full, cancel, an HA node switch,
and seal during a run.

## Tracking

| Task | Phases | State |
|---|---|---|
| T124 Grant SQL privileges in policies and shares, and let plugins ask the host to authorize statements and release database credentials | 0, 1 | `[x]` |
| T125 Browse, query and edit PostgreSQL databases in the SQL browser through the `dbms-management` plugin | 2, 3, 4 | `[ ]` |
| T126 Export query results and run SQL scripts only with their own grants | 5 | `[x]` |
| T127 Add MySQL and MariaDB to the SQL browser | 6 | `[ ]` |
| T128 Add SQL Server to the SQL browser | 7 | `[ ]` |
| T129 Add Oracle Database to the SQL browser | 8 | `[ ]` |
| T130 Open SQL browser sessions with dynamic database credentials | 9 | `[!]` blocked by T62 |

All seven tasks are under M5 (Resources) in `ROADMAP.md`; this spec is S109.

## Alternatives considered

1. **Dial from the GUI host, like direct SSH.** Rejected: the workstation would
   hold the credential, and every privilege would be advisory (§2).
2. **A WASM plugin.** Rejected: no sockets, and a fresh instance per call.
3. **A built-in engine crate.** Rejected: the request is for a plugin, and
   drivers (possibly a native Oracle client) would enter the vault server's
   TCB.
4. **A plugin-private grant table.** Rejected. Authorization would leave the
   verified evaluator, sharing, the policy builder and the denial store, which
   is the opposite of "validated by BastionVault".
5. **Privilege-as-path under the plugin mount with existing capabilities**
   (Vault style, for example `update` on `dbms/v2/grant/<r>/select`). Rejected:
   broad globs carrying ordinary capabilities would silently grant SQL
   privileges. "Connect to every resource" would become "DROP on every
   database", and policy `read` implies `connect`. Shares would still need new
   vocabulary.
6. **Plugin-declared capabilities registered at run time.** Rejected for v1:
   the verified core has a fixed capability domain, and policies naming
   capabilities of an uninstalled plugin need a semantics nobody has
   specified. It could revisit the design once a second plugin needs the same
   thing.
7. **Encode privileges as request parameters checked by
   `allowed_parameters`.** Rejected: the parameters are client-declared,
   object scope cannot be expressed, and shares cannot carry them.
8. **Classify statements in the host.** Deferred. It puts a SQL parser in the
   vault server's TCB and does not change the compromised-plugin case, since
   the plugin holds the credential anyway. The crate split (§4.1) keeps the
   option open.
9. **A native-protocol proxy.** Out of scope: five wire protocols, with
   interception at the protocol level (PostgreSQL extended query, TDS RPC).

## Open questions

1. **Eleven new bits in the verified core,** or fewer? For example, merge
   `sql_create` and `sql_drop` into one `sql_ddl` beside `sql_alter`. To be
   decided in Phase 0 by the maintainer.
2. **The rolling-upgrade gate** for writing `sql_*` capabilities: a version
   check across nodes, or an operator flag? *Answered in Phase 1, subsystem
   4:* a version check across the Raft membership, latched once it holds; no
   operator flag.
3. **The Oracle driver path** (Phase 0, item 5).
4. **Should `sql_admin` exist in v1**, or should administrative statements stay
   refused until approvals exist?
5. **Is `database-first` the right default**, given that it refuses read-only
   grants on resources that only store an administrator login?
6. **Grid editing of tables with names outside `SqlIdent`.** Should
   `bv-sql-guard` gain a reviewed, dialect-quoted identifier type, or is
   read-only acceptable?
7. **`journal_text` default.** `redacted` is proposed. It needs legal and
   compliance input (data-protection obligations such as LGPD) before release.
8. **Row budget.** Should the per-session row budget default on for resources
   tagged as holding personal data?
9. **Object-scoped shares** (a share narrowed to a schema): is v1's
   policy-only object scoping enough?

## Future work (not scheduled)

- A Rustion database relay transport (cross-repository).
- Approval (four-eyes) for write or DDL statements on selected resources.
- Dynamic data masking and row-level filters.
- A host socket broker with a seccomp / AppContainer sandbox for process
  plugins, so the plugin cannot `connect()` at all.
- Push of token-revocation events to plugins, so sessions close immediately.
- Privilege-templated dynamic roles (`{{grants}}` rendered from the caller's
  effective set).
- Kerberos / integrated authentication; client-certificate database
  authentication issued by the PKI engine.
- XLSX export; visual explain plans; read-only MCP SQL tools.

## Phase 1, subsystem 1 validation

Commands run from the `feat/t124-sql-policy-capabilities` worktree, one at a
time:

1. `make test-changed PKG=bv-policy-core` — exit 0.
   `Summary [ 114.848s] 934 tests run: 934 passed, 13 skipped`
2. `make test-changed PKG=bv-kernel` — exit 0.
   `Summary [ 124.701s] 900 tests run: 900 passed, 13 skipped`
3. `make verify-kani` — exit 0.
   `Complete - 14 successfully verified harnesses, 0 failures, 14 total.`
   `KANI GATE: PASS`
4. `make verify-differential CASES=1000000` — exit 0.
   `Summary [ 956.301s] 13 tests run: 13 passed (2 slow), 277 skipped`
   `==> verify differential: PASS (958.2 s)`

Subsystems 2–6 remain; T124 stays [ ].

## Phase 1, subsystem 2

Rebuilt on top of subsystem 1 (2026-10-26). Subsystem 1's representations are
kept unchanged: the `Capability` variants and their serde names, the
`CAP_SQL_*` constants, `ShareCap` at `u16`, and its decide, parser and listing
tests. This subsystem adds:

- **`PolicyGate::sql_privileges`** in `crates/bv-kernel-api/src/policy.rs`,
  with the pure `policy::sql` module (`SqlCapability`, `SqlCheck`,
  `SqlTarget`, `SqlVerdict`, `SqlPurpose`, `sql_check_path`), implemented in
  `crates/bv-kernel/src/modules/policy/sql_privileges.rs`. Each check is one
  `ACL::allow_operation` probe on a Read with the share override set to the
  probed `sql_*` name, the same arms `may_connect_target` uses. Evaluator
  errors are propagated, not defaulted to a refusal, so any error refuses the
  whole batch (§3.4). At most `SQL_MAX_CHECKS` (1024) checks per batch.
- **Denial records.** A refused check made with `SqlPurpose::Enforce` is
  written to the denial store with the actor, the namespace, the synthetic
  path, the capability and the plugin (`reason = "sql-privilege"`,
  `operation = "sql"`). The three new `DenialAuditEntry` fields are omitted
  when empty, so request denials serialize as before and a pre-T124 record
  reads back with them empty. Keys are now strictly increasing within a
  process, so several refusals appended for one statement cannot overwrite
  each other.
- **The qualifier edge.** `resource_name_from_path` already resolves
  `resources/resources/<R>/sql/**` to `(resource, R)`; a test now pins it at
  root and in a namespace, and pins that no KV, file or asset-group extractor
  claims those paths.
- **The share vocabulary and the baseline rule** (§3.3). The eleven names are
  accepted for `resource` and `asset-group` targets and refused with a `400`
  on `kv-secret` and `file` targets. A test ties the store's names to
  `ShareCap`'s SQL variants.
- **Parameter constraints refused** beside a SQL capability (§9.1): a probe
  never reads request parameters, so the constraint would be silently
  ignored.
- **Theorem T9** (`docs/verification.md`): `CAP_SQL_ALL` and `CAP_PROBE_ONLY`
  in `bv-policy-core` and two Kani harnesses. In the differential suite,
  generated shares and share overrides now include SQL names.

Decisions taken where the spec is silent or only sketches the interface:

- **`SqlPurpose`.** §3.4's signature has no way to name the plugin that §3.4
  requires in the denial record. The call takes `Enforce { plugin }` (an empty
  plugin name is an error) or `Display` (the chips read; nothing recorded), so
  rendering chips does not fill the denial store. Rejected: §3.4's
  three-argument call, which would record chip reads as refusals and could
  not name the plugin.
- **Resource names are canonicalized** (trimmed, lower-cased) in the
  synthetic path, as `OwnerStore::scope_target_name` keys owner, share and
  asset-group records. A mixed-case name therefore cannot slip past a
  lower-case `deny`. A name that cannot address exactly one path segment
  refuses the batch.
- **Unaddressable object names** (§3.2) are checked on `…/sql/objects/`. No
  rule naming a catalog, schema or object can match there; a resource-wide
  grant (`…/sql/*`) or a grant covering every object (`…/sql/objects/*`)
  does. Rejected: checking them on `…/sql/` itself, which would let a
  `…/sql/*` grant pass an object that a `…/sql/objects/*` deny covers.
- **A named namespace that does not resolve is an error**, not root, unlike
  `caller_namespace`.

Rolling upgrades (§13, D4): the baseline rule puts `sql_*` into `default` and
`shared-access`, which every node force-loads into storage at startup. An
older node cannot parse either, and refuses the whole policy. Subsystem 4's
write gate must therefore cover that force-load, not only operator writes.
Until it lands, `main` must not be released (ROADMAP T124).

### Phase 1, subsystem 2 validation

Commands run on branch `feat/t124-sql-policy-substrate`, one at a time:

1. `cargo clippy -p <crate> --lib` for `bv-policy-core`, `bv-kernel-api` and
   `bv-kernel` — exit 0 each; no warning in a touched file beyond the
   existing `maybe_async` trait pattern.
2. `cargo nextest run -p bv-policy-core -p bv-kernel-api -p bv-kernel --lib` —
   exit 0, `396 tests run: 396 passed` (rerun after the property below was
   removed).
3. `cargo nextest run -p bastion_vault --lib kernel_policy_sql` — exit 0,
   `5 tests run: 5 passed`.
4. `make verify-kani KANI_SET=full` — exit 0, `20 successfully verified
   harnesses, 0 failures`, `KANI GATE: PASS` (326 s wall).
5. `make verify-fast SEMGREP=0` — exit 0 (Semgrep is not installed locally,
   recorded as skipped).
6. `make test-changed` — exit 2, `1648/1660 tests run: 1646 passed, 2
   failed`. Both failures are `bvault-cli` `policy_list` / `policy_write`,
   whose seeded-policy fixture (`crates/bvault-cli/src/lib.rs`) predates the
   `self-accounts-user` baseline main added in dc3b135b; they fail the same
   way without this change. A rerun of `bvault-cli`, `bv-server` and
   `bastion_vault` with `--no-fail-fast` shows only those two.

The differential suite was skipped at the maintainer's request, and the
1,000,000-case run was stopped before it finished. Before that request, a
10,000-case `make verify-differential` had passed. In the stopped run, 12 of
14 tests had passed, the main property was killed, and a T9 property on real
strings (two ACLs built with and without the SQL capabilities) failed. Its
shrunk counterexample contains no SQL capability, so both ACLs were built from
identical text and still disagreed on `root_privs` in a capability probe
(`(false, false, false, deny)` against `(false, true, false, deny)`).
`PolicyConfig.path` is a `HashMap`, so rule order varies from one parse to the
next. That property was removed rather than left flaky. The disagreement is
open, does not involve SQL, and needs its own investigation: does any caller
read probe `root_privs` past a deny? `make test-release` (L4) has not been
run. Subsystems 3–6 remain; T124 stays `[/]`.

## Phase 1, subsystem 3

Plugin ABI 1.4 on the host (§9.2–§9.4), built on subsystem 2's
`PolicyGate::sql_privileges`:

- **ABI and manifest.** `HOST_ABI_MINOR` was 4 when this shipped (0.45.9);
  it is 5 since dynamic secrets (T62) took the next minor, and minor 5 still
  serves every 1.4 key unchanged. The new keys `concurrent`,
  `max_concurrent`, `sql_gate`, `resource_credentials = ["sql"]` and
  `sql_console` each require `abi_version` minor 4, so a 1.3 host refuses a
  plugin that declares them. They parse strictly: a wrong type, or a
  credential kind other than `sql`, fails the manifest. They are omitted
  from the signed bytes when off, so already-signed plugins keep verifying.
  `sql_gate` and `resource_credentials` require `caller_identity`, the
  process runtime, and (for credentials on a long-lived child)
  `concurrent`, because only a multiplexed child receives the seal message.
  Gaining `sql_gate`, a credential kind or `sql_console` on re-register is
  refused as capability widening.
- **Grants.** `v2/sys/plugins/<name>/grants/{sql-gate,resource-credentials}`
  (GET/PUT/DELETE), records `core/plugins/engine/sql-gate-grants/<name>` and
  `…/resource-credential-grants/<name>` (`v: 1`; a record that does not parse
  or has another version reads as absent).
- **Host calls** (`src/plugins/sql_host.rs`). Every call checks, in order:
  the manifest capability, an invocation caller, the live grant, strict
  parameters, then its own rules. `resource_sql_credential` applies §5.4
  rules 3–5 in the host and audits every attempt as
  `resource-credential-release` (actor stamped, value never recorded).
  `connect_ticket_redeem` refuses an `action`, which this host's tickets
  cannot bind (until T126; see *Phase 5, exports, scripts and step-up*). The resource engine's half is a seam (`SqlResourceSource`)
  whose default answers `not_available` until subsystem 5.
- **Actor-stamped `audit_emit`** in both runtimes for ABI 1.4 plugins with
  `caller_identity`, inside an invocation that has a caller.
- **Multiplexed invocations** (`src/plugins/process_mux.rs`): one reader
  task, one writer behind a lock, `max_concurrent` (default 32) slots, a
  4 MiB bounded line reader, `cancel{id}` on timeout, kill only for a
  protocol violation or a missed heartbeat (`ping`/`pong`), the unchanged
  crash breaker, and `lifecycle{seal|reload|shutdown}` with a 10 s
  acknowledgement deadline. Seal reaches the children through a module
  registered by the plugin runtime (`PluginLifecycleModule`).
- **SDK and testkit.** `bastion-plugin-sdk`'s `process` feature has the
  runner for the single-shot, serialized and multiplexed protocols and typed
  wrappers for every host call. The testkit mirrors the calls, the release
  rules and the stamping rule; `tests/test_plugin_testkit_parity.rs` checks
  both against the host.

Decisions taken where the spec is silent:

- **What the grants pin.** The SHA-256 of the whole canonical
  `[capabilities]` block. The requesting keys are flat flags, so a pin over
  them alone could never change. Rejected: pinning only `sql_gate` /
  `resource_credentials`, which would survive any other capability change.
- **"Holds any SQL capability".** A `Display` probe of the eleven
  capabilities on `sql/server` answers the common case without writing
  anything; when it finds none, the batch is re-run under `Enforce`, which
  records the refusals and decides. Rejected: always `Enforce`, which writes
  ten denial records for every successful select-only session.
- **Oversized lines.** Attributed by the `type` / `id` / `invocation` found at
  either end of the line; one that cannot be attributed is dropped and logged
  and its invocation times out and is cancelled. The child is never killed
  for size.
- **Old plugins.** 1.0–1.3 plugins keep the serialized protocol, the
  unbounded line reader and actor-less `audit_emit` unchanged.

Residual: the host cannot tell which thread of a multiplexed child made a
host call, so a plugin must name the right invocation; the authority it can
reach is that of callers whose invocations are in flight. Node shutdown
reaches a child through the closed stdin (the SDK runner calls
`on_lifecycle(Shutdown)`), not through an explicit `lifecycle{shutdown}`.
The GUI has no consent panel for the two grants yet.

## Phase 1, subsystem 4

The rolling-upgrade write gate for `sql_*` (§13, decision D4, *Open
questions* 2), in `crates/bv-kernel/src/modules/policy/sql_write_gate.rs`.

**Why the force-load had to be gated too.** Phase 0 found that an older node
refuses a whole policy that names `sql_*`. It is worse for `default`:
`force_load_acl_policy` reads the stored copy before comparing it, and the
parse error propagates, so an older node whose stored `default` names `sql_*`
cannot unseal at all. Subsystem 2 put the SQL rule in `default` and
`shared-access`, so without this gate the first upgraded node to unseal would
stop every older node from unsealing.

**Mechanism.**

- **Node records.** Each node writes `policy-schema/nodes/<node>` in the
  system barrier view (`v: 1`: `node`, `policy_schema`, `host_abi_minor`,
  `updated_at`). `<node>` is the Raft node id, or `standalone`. It is written
  at unseal (`PolicyModule::setup_policy`, before the baselines load) and every
  60 s by a heartbeat task (`PolicyModule::start_background`) until the gate
  opens. Policy schema 2 is the vocabulary with `sql_*`; the gate needs ABI
  minor 4 or later (a 0.45.9 node reports 4, a later one 5).
  The kernel keeps its own copy of `HOST_ABI_MINOR` (it sits below
  `bv_plugin_manifest`), pinned by a facade test.
- **Who must report.** Every member of the Raft membership, voters and
  learners, read from the hiqlite metrics, and not only the nodes that have
  written a record. A pre-T124 node writes no record, so the shape first
  sketched ("every live record ≥ 4") would hold with an older node still in
  the cluster. A deployment that is not a Raft cluster is one node, the process
  asking.
- **Decision.** The gate opens when every member has a record with policy
  schema ≥ 2 and ABI minor ≥ 4 that is at most 180 s old and not dated more
  than 30 s ahead. The evaluating node counts from its own constants. Anything
  unknown keeps the gate closed and names the first blocker: no record, a
  record that does not parse or has another `v`, an old schema or ABI, a stale
  or future record, unreadable membership or storage.
- **Latch.** Opening writes `policy-schema/sql-gate` (`v: 1`: `opened_at`,
  `opened_by`, `members`). The latch is monotonic: the gate never closes by
  itself, and heartbeats stop mattering. A latch that does not parse is not
  trusted; the gate is decided from the records again, and a valid latch
  replaces it when they hold.
- **Policy writes.** `PolicyStore::set_policy_internal` (root) and
  `set_policy_ns` (namespaces) are the funnels for every policy document
  write. Both refuse a policy naming `sql_*` with `409` while the gate is
  closed. That covers `sys/policy/{name}`, `sys/policies/acl/{name}` and the
  seeded baselines. The write that finds the evidence complete opens the gate.
- **Share writes.** `identity/sharing/…` PUT refuses a `capabilities` list
  naming `sql_*` with `409`, after the share-admin check, so a caller who may
  not share learns nothing about the gate. When the policy module cannot be
  reached, the share is refused too.
- **Baselines.** The SQL rule in `default` and `shared-access` sits between
  two marker comments. While the gate is closed they are force-loaded without
  it (the rest is byte for byte the bundled text), which every older node
  parses. When the gate opens they are force-loaded in full, by the heartbeat
  or by the write that opened it. A stored copy that already names `sql_*`
  while the gate is closed is kept, with an error logged: a stored `sql_*`
  policy is never removed automatically (D4). `namespace-shared` is parsed in
  process at ACL build and never stored, so it is not gated.
- **Observability.** `GET v2/sys/policy-schema` (read-only; never opens the
  gate) reports the state, the reason, each node's record and the state of
  the two baselines (`with-sql` / `without-sql`). Logs on target `security`:
  a warning at unseal while closed, with the reason; info when the gate opens
  and when the baselines are upgraded; an error when a stored baseline naming
  `sql_*` is kept while closed.

**Decisions taken where the spec was open.**

- **Open question 2: a version check, not an operator flag.** A flag is
  simpler and explicit. But setting it one node too early makes that older
  node unable to unseal, and the operator has no way to check the claim. The
  version check derives the decision from evidence each node writes about
  itself. Its costs are one small write per node per minute while the gate
  is closed, and the TTL window below.
- **The latch never closes.** Rejected: re-closing when a member stops
  reporting. It would make SQL shares flap with a missed heartbeat, and it
  protects nothing, because stored `sql_*` policies stay (D4).
- **Baseline text while closed.** The marked rule is removed and everything
  else is kept. Rejected: moving the SQL rule into an in-process policy like
  `namespace-shared`. That avoids storing `sql_*` in a baseline at all, but it
  hides the grant from operators who read `default`, and it changes subsystem
  2's design.
- **Status is read-only.** Rejected: letting `GET v2/sys/policy-schema` open
  the gate, which would give a read a side effect.

**Residual risks.**

- **TTL window.** A node rolled back to an older build less than 180 s after
  its last report still counts. If the gate opens in that window, that node
  cannot unseal. Do not roll back nodes during an upgrade, and read
  `v2/sys/policy-schema` before writing `sql_*`.
- **Clock skew.** A clock up to 30 s ahead extends a record's freshness by
  that much. A record further ahead is refused, which keeps the gate closed.
- **After the latch,** adding an older node or downgrading one is
  unsupported. That node cannot unseal, because the stored `default` names
  `sql_*` (D4).
- **Shared storage without Raft.** Several processes on one MySQL or cloud
  backend are not a cluster in this tree; each one sees only itself.
- **Engine shape.** Membership comes from the shape of hiqlite's metrics
  JSON (openraft 0.9, `membership_config.membership`). A changed shape reads
  as "membership unreadable" and keeps the gate closed, so the failure is
  safe and shows in the status.
- **Not gated (follow-up, closed in subsystem 5).** `.bvx` exchange import
  writes policy entries as raw barrier keys, bypassing the store, and a BVBK
  restore replaces storage wholesale. Neither consulted the gate; subsystem 5
  makes both refuse while it is closed (see *Phase 1, subsystem 5*).

### Phase 1, subsystem 4 validation

Commands run on branch `feat/t124-sql-policy-substrate`, one at a time, on
top of subsystem 3's uncommitted tree:

1. `cargo check -p bv-kernel`, `cargo check --lib`,
   `cargo check -p bv-server -p bvault-cli`: exit 0 each.
2. `cargo clippy -p bv-kernel --lib` and `cargo clippy -p bv-server --lib`:
   exit 0, with no warning in a touched file.
3. `cargo nextest run -p bv-kernel --lib`: exit 0, `330 tests run: 330
   passed` (20 of them are the gate's: decision, records, membership, marked
   baselines, and closed/open/fail-closed paths against a test vault).
4. `cargo nextest run -p bastion_vault --lib kernel_policy_sql`: exit 0,
   `7 tests run: 7 passed`.
5. `cargo nextest run -p bv-server --lib`: exit 0, `82 tests run: 82 passed`,
   including the golden route inventory.
6. `make test-changed PKG=bv-kernel`: exit 2, `972/984 tests run: 970
   passed, 2 failed`. Unseeded, `make test-plan` forces a full run because
   subsystem 3 changed `Cargo.lock`. The failures are `bvault-cli`
   `test_cli_policy_list` / `test_cli_policy_write`, whose fixture lacks
   `self-accounts-user` (as in subsystem 2). Fail-fast left 12 unrun, so
   `cargo nextest run -p bvault-cli --lib --no-fail-fast` was run: `51 tests
   run: 49 passed, 2 failed`, the same two.

Not run: `make test-release` (L4) and a real multi-node hiqlite cluster. The
cluster paths are covered through a `cfg(test)` topology seam, not against
Raft. T124 stays `[/]`.

## Phase 1, subsystem 5

The resource engine's `sql` protocol (§5, §9.5), the production
`SqlResourceSource` behind the subsystem-3 host calls, and the gate on the two
raw policy writers subsystem 4 left open.

- **`sql` profiles** (`crates/bv-engine-resource/src/sql_profile.rs`). A
  `database` resource whose `engine` is `postgresql`, `mysql`, `mariadb`,
  `mssql` or `oracle` offers `sql`, default ports 5432, 3306, 3306, 1433 and
  1521. The built-in block applies unless the saved type configuration says
  otherwise: `connect.enabled = false`, or a `connect.protocols` list without
  `sql` (any other `protocols` value offers nothing, as the GUI reads it); a
  `connect` block that does not parse refuses. A profile parses strictly,
  §5.1's shape: top-level `id`, `name`/`label`, `is_default`, `protocol`,
  `target {host, port}`, `sql`, `credential_source`; `sql` takes `catalog`,
  `instance` (SQL Server only), `tls {mode, server_name, ca_pem}` (`mode`
  defaults to `verify-full`), `ceiling` (required, non-empty, no repeats),
  `require_mfa`, `step_up`. Anything else, or a wrong type, fails the profile
  (`invalid_profile`). The record's own `sql` block takes `enforcement`
  (`database-first`, the default, or `classifier-only`). The endpoint is
  `target.host`, else `hostname`, else `ip_address`; `target.port`, else the
  record's `port`, else the engine default. Other protocols are never parsed
  here, so a record a pre-T102 GUI saved is untouched.
- **Credential resolution** (`sql_resource.rs`). `secret` reads
  `secret/<resource>/<secret_id>` from the mount's view; the secret needs a
  string `username` and `password`. The reserved `sql_endpoint` is passed to
  the host's rule 5 as stored, and a secret write with a malformed one is
  refused with `400` (`null` or `[]` unbinds). `dynamic` parses and is refused
  at release (`dynamic_not_available`). The password is read into a
  `Zeroizing` buffer and leaves only through the host call's reply.
- **The seam** (`src/plugins/sql_resource.rs`), installed at assembly
  (`BastionVault::new`). It reads the caller's namespace's `resources/` mount
  view, refusing a mount that is not the resource engine or is tainted, under
  the server's authority after the host has checked rule 2. The transport is
  Rustion's own resolver (`bv_engine_rustion::policy::resolve`) over its
  stored tiers; a lock violation or an unreadable tier refuses. The material
  now carries `require_mfa`.
- **`sql.require_mfa`.** `connect_ticket_redeem` records a redeemed ticket on
  the invocation (`InvocationCaller`); `resource_sql_credential` for a gated
  profile spends exactly one record for the same namespace, resource and
  profile, after rules 3–5, so a refusal the operator can fix does not spend
  it. The testkit mirrors this.
- **Host-call codes.** `404` from the engine is `not_found`, `409`/`422` are
  `refused`, `503` is `not_available`. The release audit records the stable
  second code (`refused: dynamic_not_available: …` → `dynamic_not_available`).
- **`resources/v2/sql/privileges/<resource>`** (read): `server`,
  `resource_wide` and per-object `objects` capabilities, with
  `SqlPurpose::Display`. Resource-wide is a check on `…/sql/objects/`, where
  only a grant covering every object applies. `?objects=` is comma-separated
  `catalog/schema/object` triples, segments percent-encoded, at most 64, so a
  batch stays under `SQL_MAX_CHECKS`. `objects` joins the query allowlist in
  `bv-logical`. The record is not read: no existence oracle.
- **Baselines.** `read` on `resources/v2/sql/privileges/+` in `default`,
  `shared-access`, templated `namespace-shared`, and restated in
  `administrator`. Outside the gated block: it names no `sql_*`, so the
  closed-gate text (tested) still grants it and still parses on an older
  node.
- **Connect MFA.** `connect/mfa/begin|verify` read the gate from
  `sql.require_mfa` for an `sql` profile (anything but absent or `false`
  gates it, read without the strict parse so a broken profile cannot skip
  it). A caller holding any `sql_*` on `sql/server` may call them without
  `connect`; one holding neither gets the connect grant's refusal. A profile
  that does not parse is refused with `422` before a factor is asked for.
  `connect/authorize` refuses an `sql` profile (`400 sql_profile_not_direct`)
  before touching the ticket. No `action` binding (Phase 5, T126).
- **The gate on raw writers** (`src/exchange/sql_gate.rs`). An exchange
  import carrying a policy that names `sql_*` (parsed; an unparseable one is
  scanned for the eleven names) is refused with `409` before any write while
  the gate is closed; a dry run warns. A BVBK restore into a running vault
  (`sys/restore`, the desktop app) that carries any policy document (keys are
  plaintext: `sys/policy/`, `policy-rgp/`, `policy-egp/`,
  `policy-ns/<b64>/acl/`, legacy or re-rooted) is refused with `409` before
  any write while the gate is closed. Opening the gate there upgrades the
  baselines, as a policy write does (`PolicyStore::sql_gate_open_or_reason`).

Decisions taken where the spec is silent:

- **Endpoint precedence `hostname` before `ip_address`**, unlike the provider
  target: §5.1 names them in that order, and `verify-full` needs the name.
- **Top-level `require_mfa` on an `sql` profile is refused**, not honoured:
  §5.1 places it in `sql`, and two flags for one gate is an ambiguity. The
  gate flag still reads it (either gates), so it cannot be skipped.
- **The privileges endpoint is ungated by the write gate.** Rejected: putting
  it inside the marked block, which would hide a read that names no `sql_*`.
- **Restore refuses on the presence of policy documents.** It cannot decrypt
  them without a new barrier API. Rejected: restore-then-verify-then-rollback,
  which is not atomic, and stripping, which D4 rules out.
- **MFA at release, not only at redeem.** The host refuses a gated profile's
  credential without a redemption in the same invocation. Rejected: trusting
  the plugin to redeem first, which a compromised plugin would skip.
- **`?objects=` needs `bv-logical`.** A GET's query reaches a handler only
  through the allowlist; the edit rebuilds most of the workspace.

Residual risks:

- **Rolling upgrades and exports.** Every export from a gate-open vault
  carries a `default` naming `sql_*`, so importing it into a cluster whose
  gate is closed is refused until the upgrade completes. A BVBK restore with
  policies is refused in the same window. `bvault operator restore` writes
  into a stopped backend and cannot consult the gate.
- **Legacy mixed-case resource keys.** A ticket binds the record's storage
  name; the host redeems with the lower-cased name, so a legacy mixed-case
  record cannot use connect MFA for `sql` until renamed.
- **The type gate reads `config/types` as saved.** A deployment that saved a
  `database` type with an explicit `protocols` list (say `["ssh"]`) has `sql`
  off until it adds it; the GUI (subsystem 6) must offer it.
- **Weak-authentication refusal without TLS** (§5.4) is plugin-side and lands
  with Phase 3; the host passes `tls.mode`.
- **`resource_sql_target` reveals `ca_pem`** to the plugin: public material,
  but a large bundle travels on every call.

### Phase 1, subsystem 5 validation

Commands run on branch `feat/t124-sql-policy-substrate`, one at a time, on
top of subsystems 3 and 4's uncommitted tree:

1. `cargo check -p bv-engine-resource`: exit 0. `cargo check --lib`: exit 101
   once (`Core::barrier` is a field in the facade), then exit 0.
   `cargo check -p bastion_vault --lib --tests`, `cargo check -p bv-server -p
   bvault-cli` and `cargo check -p bastion-vault-gui`: exit 0 each.
2. `cargo clippy --lib` for `bv-engine-resource`, `bv-logical`, `bv-kernel`,
   `bastion-plugin-testkit`, `bastion_vault` and `bv-server`: exit 0 each,
   no warning in a touched file.
3. `cargo nextest run --lib`: `bv-engine-resource` 138 passed (15 new),
   `bv-logical` (filter `util`) 8 passed, `bv-kernel` 331 passed,
   `bastion-plugin-testkit` 42 passed, `bastion_vault` (filters
   `resource_sql`, `sql_host`, `sql_gate`, `backup::restore`,
   `exchange::namespaces`, `invocation`, `kernel_policy_sql`) 42 passed.
   `cargo nextest run -p bastion_vault --test test_plugin_testkit_parity`:
   6 passed.
4. `scripts/test-changed.sh --pkg bv-logical --pkg bv-engine-resource --pkg
   bv-kernel --pkg bastion-plugin-testkit --pkg bastion_vault --pkg bv-server
   -- --no-fail-fast` (seeded: `Cargo.lock` is changed, so the unseeded plan
   is a full run): exit 100, `2108 tests run: 2106 passed, 2 failed`, the
   same two `bvault-cli` `test_cli_policy_list` / `test_cli_policy_write`
   fixture failures as subsystems 2 and 4. The plan's `bv-plugin-pack
   --bins` step, skipped after that failure, was run alone: 17 passed.
5. After L3, `mfa_target` stopped failing on a record that does not parse
   before the grant check, and the new files were run through `rustfmt`; the
   engine's lib tests (138) and the facade filters above were re-run, green.

Not run: `make test-release` (L4), `make plugins-test` beyond the parity
binary, and a GUI build (no `gui/src` change). T124 stays `[/]`; subsystem 6
(the GUI) remains.

## Phase 1, subsystem 6

The GUI parts of Phase 1 (§3.2, §3.3, §5, §9.1, §9.5, §10); the SQL workspace
itself is T125. Frontend in `gui/src/`, five Tauri commands in
`gui/src-tauri/`.

- **Policy builder and validator** (`lib/policyHcl.ts`, `lib/sqlPrivileges.ts`,
  `PolicyBlockEditor`, `PolicyValidatorPanel`).
  - The eleven `sql_*` chips appear on resource rules only
    (`resources/resources/…`, `resources/*`, behind any namespace prefix); a
    rule that already names one keeps them wherever its path points.
  - `lintPolicyModel` accepts the eleven names, and `lintSqlRules` adds three
    findings: an **error** for a SQL capability beside `allowed_parameters`,
    `denied_parameters` or `required_parameters` (the server refuses it, §9.1);
    a **warning** when the path can never carry a SQL check; a **warning** for
    an object-scoped grant with no grant on `…/sql/server` in the policy (§3.2).
    The env restriction is not offered on a SQL rule.
  - A validator case with a `sql_*` capability is explained against its
    synthetic path (`…/sql/server`, `…/sql/objects/<catalog>/<schema>/<object>`,
    or the `…/sql/objects/` bucket for an unaddressable name). The verdict is
    still the server's dry-run.
  - While a draft names `sql_*`, `GET v2/sys/policy-schema` is read and, if the
    gate is closed, a notice names the blocking node. A `409` on save (policy,
    share) is shown as one sentence with the same reason
    (`describeSqlWriteError`). The status read never opens the gate.
- **Sharing** (`ObjectSharingCard`). `sqlPrivileges` adds the eleven chips and
  the four presets of §3.3 to the grant form, honoured for `resource` and
  `asset-group` targets only (never `kv-secret` or `file`). Presets are
  cumulative; `sql_export` and `sql_script` stay separate toggles. A database
  resource's form starts on *Read only* (`sql_select`, not `read`) and says why
  `read` is not needed. The generic chips now carry `aria-pressed`.
- **SQL profile editor** (`SqlProfilesCard`, `lib/sqlProfile.ts`). A database
  resource gets the Connection tab (also when its type offers no launchable
  protocol) with a SQL card: profiles, enforcement and the type switch.
  - Fields and limits mirror `sql_profile.rs` one for one; the editor emits
    only the keys it accepts, `require_mfa` under `sql`, the port as a number,
    optional fields omitted. A stored profile the server would refuse is listed
    as invalid with the reason and can be repaired by saving it.
  - Credential source is a stored secret; *dynamic* is shown disabled ("later")
    and a stored one is kept as is. The editor shows the `host:port` the
    secret's reserved `sql_endpoint` must name, resolved as the server does
    (profile, then `hostname`, then `ip_address`; the profile's port, the
    record's, the engine's). It reads no secret.
  - Enforcement (`database-first` | `classifier-only`) is written to the
    record's `sql` block; `classifier-only` shows the downgrade banner text.
    Step-up is stored and labelled not enforced yet (T126).
  - `sql` profiles stay out of `ConnectionProfile` / `readProfiles`, so the
    launcher never lists or launches them; they ride the T102 "unknown" path
    and `profilesForWrite` re-appends them and every other unknown entry
    untouched.
  - A saved `database` type with an explicit `connect.protocols` list without
    `sql` shows an alert with *Add sql to the Database type* (only where that
    namespace saved the configuration itself; an inherited one points at the
    root). The type editor also gained an SQL checkbox on `database`, because
    saving the type with the four launchable protocols would otherwise have
    written a list without `sql` and turned the browser off.
  - The caller's own effective SQL privileges
    (`resources/v2/sql/privileges/<resource>`) are shown as chips.
- **Plugin admin** (`PluginsPage`). The page's grants surface is extended with
  a *SQL access* panel for plugins requesting `sql_gate` or
  `resource_credentials = ["sql"]`: one section per grant, consent checkbox,
  approve and revoke, the pinned capability-block hash, stale status. Tauri
  commands `plugins_{get,set,delete}_sql_grant` (embedded: the facade's
  `plugins::sql_grants`; remote: `v2/sys/plugins/<name>/grants/<kind>`),
  `policy_schema_status` and `resource_sql_privileges`.

Not done: no browser or visual check; the Tauri commands were compiled, not
exercised against a running vault or a remote server; the exchange-import and
restore pages do not yet translate the gate's `409` (the helper is ready);
there is no *Bind credential to this endpoint* button (the hint states the
value instead, so no secret is read or written from the card).

### Phase 1, subsystem 6 validation

Run in `gui/` and the repository root, one at a time: `npx tsc --noEmit`
(exit 0); `npx vitest run` over the whole GUI (102 files, 1276 tests passed,
of which the new files are `sqlPrivileges`, `sqlProfile`, `policySql`,
`sqlSharing`, `sqlProfilesCard`, `sqlResourcePage` and `pluginSqlGrants`);
`cargo check -p bastion-vault-gui` (exit 0).

## Phase 1 exit gate (T124 closed 2026-10-26)

- `make verify-kani KANI_SET=full` — `KANI GATE: PASS`.
- `make test-release`, in pieces: suites 1–5 (unit 2511/2511, integration 2613/2613, doctests, hiqlite, cucumber) in one run, after the `bvault-cli` fixture gained the `self-accounts-user` baseline; suites 6–9 (`plugins-test`, `gui-check`, `gui-test`, `test-pki-composite`, `check-hsm DEEP=1`) in a second run, once the worktree's `plugins-ext` submodule was initialised. All exited 0.
- Not run: the 1,000,000-case differential suite; a browser check of the GUI; a multi-node hiqlite run of the closed gate.
- Open, outside T124's gate: the `root_privs` disagreement between ACLs built from identical text (see subsystem 2), TCPS cancellation (D2), the real-driver 50-session measurement (D5).

## Phase 2, the classifier crate

`crates/bv-sql-classify` (T125, Phase 2; workspace member, Tier 0 leaf,
`publish = ["uox-bastionvault"]`, version 0.41.0). It depends on `sqlparser`
0.63 only (`default-features = false`, `std` + `visitor`: the default
`recursive-protection` feature would pull `stacker`/`psm`, a C/asm build) and,
for tests, `proptest`. It depends on no BastionVault crate: `SqlCapability`
mirrors `bv_kernel_api::policy::sql::SqlCapability` by spelling, pinned by a
test.

**API.** `classify(Dialect, LexerSettings, &str, &NameContext) ->
Result<Vec<ClassifiedStatement>, Unclassifiable>` as §4.1, all or nothing;
`classify_each` returns one result per statement for display. Deviations from
the §4.1 sketch: `NameContext` also carries the search path,
`max_identifier_length` and `database_read_only` (the §4.2 user-function rule
needs it); `SqlTarget::Object` holds an `ObjectRef { kind, catalog, schema:
Option, name }`, where `schema: None` is an unqualified reference the plugin
must resolve through the catalog (§4.4), and a name it cannot resolve must be
checked as unaddressable; `Unclassifiable` carries the statement index, the
span, a `Reason` (no statement text, safe to log) and a `Refusal`:
`Unknown` (a `sql_admin` holder may run it as `unclassified`) or `Never`.

**How a statement is classified.**

1. A lexer that follows PostgreSQL's `scan.l` splits the input (strings in
   every prefix form, `standard_conforming_strings`, nested comments, dollar
   quotes, `--` ending at `\r`, psql's `BEGIN ATOMIC` rule) and refuses what
   the server reads version-dependently: NUL, `\v`, `\` outside literals,
   number junk, non-alphanumeric non-ASCII outside literals, `U&` literals.
2. sqlparser's tokenizer must agree with that lexer on the start and end of
   every string, quoted identifier, dollar quote and comment; otherwise the
   statement is refused (`LexerDisagreement`, `Never`). The parser then runs
   on exactly the checked tokens and must find exactly one statement.
3. A statement table maps each statement to its own targets; a full AST walk
   (sqlparser's `Visitor`) classifies every relation, nested statement,
   table factor, expression and function call. Unknown statements, clauses,
   table factors and expressions refuse; nothing defaults to `sql_select`.
   CTE names shadow tables only in PostgreSQL's scope (a non-recursive CTE's
   own body sees the real table).
4. Statements sqlparser does not cover, or that need one rule only, are
   classified from tokens with a strict grammar first: `DO`, `VACUUM`,
   `ANALYZE`, `REINDEX`, `CLUSTER`, `REFRESH MATERIALIZED VIEW`,
   `CHECKPOINT`, `ABORT`, `MOVE`, `ALTER SYSTEM`, `ALTER SEQUENCE / VIEW /
   MATERIALIZED VIEW`, `LOAD`, and the `sql_admin` families (`GRANT`,
   `REVOKE`, roles, databases, extensions, servers, FDWs, publications,
   rules, casts, operators, languages, tablespaces, two-phase commit).
5. A non-transaction-control statement with no requirement is refused
   (`EmptyRequirementSet`). An `Unknown` refusal whose tokens name `COPY`,
   `LOAD`, `PROGRAM`, an always-refused function or an untrusted language is
   raised to `Never`.

**Decisions where §4.2 is silent or a sketch** (each covered by a test):
`CREATE INDEX`, `CREATE/DROP TRIGGER` and `CREATE/DROP POLICY` check the
table's path; a foreign key needs `sql_alter` on the referenced table;
schema-level DDL checks `sql/server`; `CASCADE` (`DROP`, `TRUNCATE`) adds
`sql_drop` on `sql/server`; `UPDATE`/`DELETE` add `sql_select` on the target
only when they read it (`WHERE`, `FROM`/`USING`, `RETURNING`, a non-literal
`SET` value); plan-only `EXPLAIN` keeps `sql_execute` for user functions (the
planner runs IMMUTABLE ones); `COPY … TO STDOUT` is `sql_select`, `COPY … FROM
STDIN` is `sql_insert`; advisory locks are `sql_update` on `sql/server`;
`NOTIFY`/`pg_notify` are `sql_execute` on `sql/server`; `nextval`/`setval`
need a literal sequence name (an OID or a run-time value refuses). Always
refused, beyond §4.2's list: the `pg_ls_*`/`pg_stat_file`/adminpack file
functions, `dblink*` whatever its schema (a second connection no read-only
transaction covers), `LOAD`, `CREATE TABLESPACE`, and functions or `DO`
blocks in C or an untrusted language. Refused as lexer changes:
`standard_conforming_strings`, `backslash_quote`, `client_encoding`/`SET
NAMES`, `RESET ALL`, `DISCARD ALL`, `ALTER SYSTEM RESET ALL`, and those names
through `set_config` or `ALTER SYSTEM`. Refused as read-only-guard changes:
`READ WRITE` transaction modes and `(default_)transaction_read_only`. When a
user schema precedes `pg_catalog` on the search path, every unqualified
function and operator counts as user code.

**Security findings while building it.**

- sqlparser 0.63 reads `DELETE FROM ONLY t` (and `FROM ONLY t`, `UPDATE ONLY
  t`) as table `only` aliased `t`. With a quoted table `"only"` in reach, a
  caller allowed to delete from it would have deleted from `t`. An unquoted
  PostgreSQL reserved keyword is never accepted as an object name
  (`ReservedWordAsName`); regression test
  `regression_reserved_word_parsed_as_a_name_is_refused`.
- sqlparser's frames are large enough in an unoptimised build that `NOT`×40,
  nested `CASE`×40 or 16 nested subqueries overflow a 2 MiB stack inside its
  own recursion budget, and a stack overflow aborts the process.
  Classification therefore runs on a scoped thread with a 64 MiB (virtual)
  stack; a panic there refuses the input (`InternalError`) instead of
  crashing the caller.

**What the plugin (Phase 3) must do with it.**

- Execute exactly the returned spans, one per extended-protocol round trip;
  run an `Unknown` refusal as `unclassified` only for a `sql_admin` holder,
  and never a `Never` one.
- Fill `NameContext` from `current_database()`, `current_schema()`,
  `current_schemas(true)` and `max_identifier_length`, and set
  `database_read_only` only when the database enforces it (§5.3). Re-read
  them after a `SetSession` statement and after any `opaque` one (a user
  function can call `set_config`).
- Pass `standard_conforming_strings` as read at session start, keep
  `client_encoding` at UTF8, and watch `ParameterStatus` for both: a change
  the classifier did not see (a user function, `ALTER SYSTEM` plus reload)
  must stop classification for the session.
- Resolve `schema: None` references through the catalog; check an
  unresolvable one as unaddressable (fail closed).

**Not done.** The fuzz target (`crates/bv-sql-classify/fuzz`, its own
workspace, `cargo +nightly fuzz run classify`) is written and type-checks but
has not been run under libFuzzer; the same invariants ran as property tests
(50,000 cases each, once). The corpus is about 280 hand-written PostgreSQL
statements, below Phase 0's 500 (Phase 0's generated corpus was never
committed). sqlparser cannot parse, so the classifier refuses as `Unknown`:
`TABLE t`, PostgreSQL's `CREATE PROCEDURE … AS $$…$$`, SQL-standard `BEGIN
ATOMIC` bodies, `ROWS FROM`, `xmlelement(name …)`, `FOR NO KEY UPDATE`,
`ATTACH PARTITION`, `OVERRIDING … VALUE`, `CREATE VIEW … WITH (…)` and custom
operators such as `===`. MySQL / MariaDB, T-SQL and Oracle tables are for
Phases 6–8.

### Phase 2 validation

Run one at a time from the repository root: `cargo check -p bv-sql-classify`
(exit 0); `cargo clippy -p bv-sql-classify --lib --tests` (exit 0, no
warnings); `cargo fmt -p bv-sql-classify` (exit 0); `cargo nextest run -p
bv-sql-classify --lib` (47 passed); `BV_SQL_CLASSIFY_CASES=50000 cargo
nextest run -p bv-sql-classify --lib props` (6 passed); `cargo check
--manifest-path crates/bv-sql-classify/fuzz/Cargo.toml` (exit 0).

## Phase 3, the plugin

`plugins-ext/bastion-plugin-dbms-management` (T125, Phase 3), a member of the
`plugins-ext` workspace (the submodule), `publish = false`, version 0.1.0,
`plugin.toml` at ABI 1.4 with `long_lived`, `concurrent`, `caller_identity`,
`audit_emit`, `log_emit`, `storage_prefix = "dbms/"`, `sql_gate`,
`resource_credentials = ["sql"]` and `sql_console`, and no declared egress.
It depends on `bastion-plugin-sdk` (`process`), `bv-sql-classify` and
`bv-sql-guard` by path, `tokio-postgres` 0.7.18 without TLS features, rustls
and tokio-rustls on the `ring` provider, `rustls-native-certs`, and `ring` for
session ids and HMACs. `cargo tree -i` finds neither `openssl-sys` nor
`aws-lc-sys` (`make test-dbms` checks it). The classifier gained one public
function, `redact` (literals to `?`, comments dropped, by its own lexer), for
the journal.

**Subsystem 1: sessions, profiles, TLS.**
- `POST v2/sessions {resource, profile?, catalog?, mfa_ticket?}`, strict
  fields. The caller needs an identity entity. `resource_sql_target` is
  parsed strictly (an unknown enforcement mode or a malformed profile is never
  selected). §5.2 selection over the server-level capabilities the target
  reports: the smallest `secret` profile whose ceiling covers the grant; a
  read-only grant under `database-first` only an exactly-`sql_select` login;
  a requested profile must itself qualify; `dynamic` profiles are skipped.
  `db_enforced` is true when the ceiling adds nothing to the grant, and
  `vault_only` lists the excess. An MFA profile redeems the ticket before the
  release. The released endpoint must equal the profile's, and the login is
  zeroized right after the connection opens, not at close.
- TLS (`src/tls.rs`): `verify-full` (chain and name), `verify-ca` (chain;
  only a name error is forgiven), `require` (encrypted, handshake signatures
  still checked), `disable`. An encrypted mode uses `SslMode::Require`, so a
  server that answers `N` ends the connection; nothing falls back.
- A wire watcher (`src/wire.rs`) sits on the decrypted backend stream. Without
  TLS it fails the read on `AuthenticationCleartextPassword` or
  `…MD5Password` before the driver holds the whole message, so the password is
  never sent (MD5 is refused too: it hands a replayable verifier to whoever is
  on the path). It also tracks `ReadyForQuery` (transaction state) and
  `ParameterStatus`.
- `allowed_networks` / `denied_networks` (`src/netpolicy.rs`) are applied to
  every resolved address, IPv4-mapped IPv6 judged as IPv4, deny wins, and the
  connection goes to the checked address (no second resolution).

**Subsystem 2: `AuthorizedStatement`.** `authz::prepare` classifies (the
`execute` rule: one statement plus transaction control, else `use_script`;
`Never` refusals stop there; `Unknown` ones need `sql_admin` on `sql/server`);
the session resolves `schema: None` names through the catalog (`to_regclass`,
`to_regtype`, and exactly-one-schema lookups for routines and collations; an
unresolved name is checked with an empty schema, which the host evaluates on
the objects root); `authz::authorize` sends the whole batch, requires one
verdict per check in order, and only when every check is allowed builds the
statements: private fields, not `Clone`, bound to the session id, each holding
exactly its classified span. `driver::PgConn` keeps the `Client` private and
its only path for caller SQL is `send_authorized(AuthorizedStatement)` (one
Parse per statement, so the server refuses a second command). Plugin SQL is
`PluginSql`, built only from `bv_sql_guard` literals or the row-edit builder.
`src/invariants.md` holds seven compile-fail doctests for these properties.

**Subsystem 3: runs.** `execute` returns `{run_id, state, statements}` at once
and the run continues on the plugin's runtime. `runs/<id>` pages (500 rows /
2,000,000 bytes by default, hard maximum 2,750,000 because a reply travels
base64-encoded in the host's 4 MiB line) out of a bounded buffer: the producer
stops reading while it is full. The grid cap and the optional row budget
cancel the query and keep what was read. Cancel and the run deadline send a
`CancelRequest` on a fresh connection to the same checked address. The
statement timeout is set at connect; read-only sessions connect with
`default_transaction_read_only = on`. One operation per session at a time
(`session_busy`). A sweep every 5 s closes idle, over-lifetime and lost
sessions and rolls back a transaction idle past `idle_tx_secs` (the server's
own `idle_in_transaction_session_timeout` is set 60 s later as a backstop).
Limits per user, resource and node count opens in progress. Values are typed
per §6.3 (`int8` and `numeric` as strings, binary as base64, 64 KiB cells).
After a `SetSession` or opaque statement the name context is re-read; if that
fails (an aborted transaction) only transaction control runs until it succeeds.
A watched setting changed behind the classifier's back taints the session,
which is closed on its next request.

**Subsystem 4: browser and edits.** `LIST objects` (schemas), `LIST
objects/<schema>` (relations, sequences, indexes, routines; a resource-wide
`sql_select`, checked on the objects root, shows all, otherwise one check per
object), `READ objects/<schema>/<object>` (columns, constraints, indexes,
triggers, view and routine definitions, editability), `POST rows` (structured
insert / update / delete, identifiers `SqlIdent`-checked and double-quoted,
values bound in text format, the key must be the table's primary or non-null
unique key exactly, the original values guard the `WHERE`, exactly one row or
a conflict, in a transaction or a savepoint), `READ ceiling` (the advisory
probe: role attributes, `has_*_privilege`, ownership, membership; `undeclared`
lists what the login can do beyond its declared ceiling).

**Subsystem 5: audit, journal, lifecycle, HA.** Events `dbms.session.open`
(also on failure), `.close`, `dbms.statement` (kinds, required checks,
objects, outcome, rows, duration, HMAC digest, `unclassified`, SQLSTATE),
`dbms.tx`, `dbms.row_edit` (key HMAC, column names), `dbms.cancel`,
`dbms.row_budget`, `dbms.config`; every one carries `db_enforced`, none carries
statement text, a value or a credential. The journal record (`v: 1`) is
written per session under `dbms/journal/<ns>/<date>/<session>`, text per
`journal_text` (`redacted` by default), errors as SQLSTATE only; `v2/journal/
self/…` filters by the caller's entity and namespace, `v2/journal/all/…` is
for auditors; days past retention are purged at most once a day. Seal, reload
and shutdown close every session in parallel within 8 s (rolling back open
transactions) and acknowledge. A session id is a per-process instance prefix
and 256 random bits; a request for another instance's session gets
`session_on_other_node`, and a session of another owner reads as absent.

Decisions where the spec is silent or could not be followed:

- **No token binding.** The host does not pass the token-accessor HMAC §6.1
  assumes, so a session is bound to entity, namespace and login (mount and
  name). Revocation still applies per statement, because every authorization
  is decided against the token of the request in flight. Rejected: deriving a
  binding from anything in the envelope the caller controls.
- **Selection uses the server-level capabilities only** (the target's Display
  probe). A resource-wide probe would go through `resource_sql_authorize`,
  which records a denial for every capability not held on every open.
  Object-scoped grants therefore never widen the chosen login (fail closed).
- **Background events wait in a per-owner outbox.** The multiplexed host
  refuses host calls outside an invocation, so a run's outcome, an idle close
  or a seal is emitted (and journalled) during the owner's next invocation,
  under the owner's identity. Rejected: emitting them in whichever invocation
  comes next, which would stamp another user as the actor.
- **Errors are plugin errors.** The host maps every non-zero plugin status to
  a 500 with the message, so codes are the message prefix
  (`session_on_other_node: …`, `use_script: …`); refused statements are a
  normal reply with `state: "refused"` and the verdicts.
- **The node is a plugin instance.** The host gives a plugin no node identity;
  the prefix names the process, so a restarted child also answers
  `session_on_other_node` for its old sessions.
- **COPY is refused by `execute`**; scripts and exports answer
  `unsupported` until T126.

Security findings while building it:

- **Catalog queries could run user code.** The plugin's own SQL runs on the
  caller's session, so an unqualified `=` or `IN` resolves through the
  caller's `search_path`; a user-defined `=(oid, regclass)` in a schema ahead
  of `pg_catalog` ran inside the name-resolution query (confirmed against
  PostgreSQL 16). Every operator in plugin catalog SQL is now
  `OPERATOR(pg_catalog.…)`, and a grid edit pins `search_path` to
  `pg_catalog, pg_temp` for its own duration (restoring the caller's inside a
  transaction). Regression test `live_internal_queries_ignore_user_operators`.
- **An aborted transaction would have stranded a session** whose name context
  could not be re-read; it now admits transaction control only, and recovers
  after `ROLLBACK` (`live_aborted_transaction_recovers_after_rollback`).

Residual risks:

- The plugin is not registered on a running vault in any test; the host half
  is the testkit mock plus the parity test of Phase 1. No cluster test.
- tokio-postgres keeps its own copy of the password in its `Config` until the
  connection is open, and SCRAM state inside the driver; neither is zeroized.
- The `plugins-ext` release profile sets `panic = "abort"`: a panic in the
  classifier ends the plugin process (every session closes, fail closed)
  instead of refusing one statement as the classifier intends.
- Browsing without a resource-wide grant records a denial for every object it
  hides. Grid edits on columns whose equality operator is outside `pg_catalog`
  (extension types) fail. Cell values over 64 KiB are not fetchable in full.
- Not done in Phase 3: per-resource or per-profile lowering of limits (the
  target view carries none), token-expiry capping of the session lifetime,
  step-up for `unclassified` (Phase 5), `docs/api.md` and the operator guide,
  the real-driver 50-session measurement (D5), TCPS cancel (D2, Oracle).

### Phase 3 validation

Run one at a time; the plugin commands from `plugins-ext/`, the classifier and
`make` targets from the repository root:

1. `cargo check -p bastion-plugin-dbms-management` (exit 0);
   `cargo clippy -p bastion-plugin-dbms-management --lib --tests` (exit 0, no
   warnings); `cargo fmt -p bastion-plugin-dbms-management --check` (exit 0).
2. `cargo nextest run -p bastion-plugin-dbms-management`: 74 passed (68 unit
   tests with a scripted host, a fake PostgreSQL server for the weak-auth and
   no-fallback cases, and the multiplexed seal acknowledgement; 6 running the
   built binary through the testkit, including the manifest against the
   host's rules and a planted password absent from responses, stderr, logs,
   storage and audit).
3. `cargo test -p bastion-plugin-dbms-management --doc`: 8 passed (7
   compile-fail invariants with pinned error codes).
4. `make test-dbms` (docker, `postgres:16` = 16.15): 7 live tests passed —
   sessions and enforcement (read-only login refusing a write the vault was
   told to allow, smuggling refused, binding, paging, grid cap, deadline,
   cancel, transactions, rollback on close, `SET search_path`, taint by
   `set_config` in a function, seal), TLS modes and cleartext-password
   refusal, limits / row budget / idle-in-transaction rollback, browser /
   describe / edits / probe, audit and journal, the operator-hijack
   regression, and recovery from an aborted transaction; then the
   `openssl-sys` / `aws-lc-sys` ban (exit 0).
5. `cargo check`, `cargo clippy --lib --tests`, `cargo fmt` and `cargo nextest
   run -p bv-sql-classify --lib` (48 passed); `make test-changed
   PKG=bv-sql-classify` (seeded, because `Cargo.toml` / `Cargo.lock` are
   already modified in the tree; 48 passed).

Not run: `make plugins-test` as a whole, `make test-release`, a registered
plugin on a running vault, a multi-node cluster.

## Phase 4, the GUI workspace

Host code in `gui/` (T125, Phase 4). Nothing in the plugin changed.

**Tauri host (`gui/src-tauri`).**
- A SQL session is a session kind: `ProfileProtocol::Sql`,
  `SessionState::Sql` (`session/sql.rs`) holding only the plugin mount, the
  plugin's session id (checked against the plugin's id shape before it is
  stored or used in a path), the namespace and resource at open, and the
  catalog. The webview gets a local `sess_…` token and nothing else: no vault
  token, no plugin session id, no credential.
- `commands/sql_workspace.rs`: `sql_session_open` (main window and workspace
  palette) resolves the console mount itself — the `plugin:<name>` mounts in
  the caller's ACL-filtered `sys/internal/ui/mounts` whose plugin declares
  `sql_console`, exactly one or an explicit error — posts `v2/sessions` with
  the host-held token, and places the session in its own `sql-<token>` window
  or as a workspace pane. `sql_session_status`, `sql_privileges` (display only,
  `resources/v2/sql/privileges/<r>` with object triples), `sql_execute`,
  `sql_run`, `sql_cancel`, `sql_objects` (schemas, objects, describe; names
  percent-encoded per segment), `sql_rows` (the plugin's structured edit
  shape only), `sql_history` (`v2/journal/self/…`) and `sql_session_close`
  each take the token and are refused unless the calling window holds the
  session (`require_session_window`); every call is pinned to the namespace
  of the open. Every stop path (pane close, window destroyed, watchdog, app
  exit) hands back a `SqlSessionClose` cleanup that `DELETE`s the plugin
  session once.
- Window ACL: capability `sql-window` (`sql-*`) and set `sql-window` =
  the nine `sql_*` commands above minus `sql_session_open`, plus
  `session_heartbeat` and the two window-close commands. The workspace set
  gains `sql_session_open` and the eight pane commands (a pane closes through
  `session_close`). Pinned in `window_acl_tests.rs` (`SQL_WINDOW`,
  `WORKSPACE_EXTRA`, Tauri's own resolver) and in
  `gui/src/test/sessionBundle.test.tsx` (exactly what the routes call).
- SQL panes are not saved in workspace layouts (restoring one would reopen a
  database session nobody asked for) and do not move between windows.

**Frontend (`gui/src`).** `routes/SessionSqlWindow.tsx` (`/session/sql` in
`session.html`), `components/sql/` (`SqlPane` lazy-loads `SqlWorkspace`,
D3), `lib/sqlWorkspace.ts` (lexer, statement at the cursor, confirmation
guard, formatter, plugin error codes, verdict text, structured edits),
`lib/sqlLaunch.ts` (MFA gate then open), API wrappers in `lib/api.ts`.
- Layout per §10: object tree with filter (Open, Describe); editor tabs;
  toolbar with Run (statement at the cursor), Run selection, Stop, Explain,
  Format and the commit mode (auto, or manual with BEGIN / Commit /
  Rollback and the transaction badge); result tabs per statement, Messages
  and History; info panel with resource, profile, timers, effective
  privilege chips and the enforcement panel (`db_enforced`, ceiling,
  vault-only capabilities, read-only, transport, TLS).
- Refused statements show the vault's verdict ("needs `sql_update` on
  `app.public.permission_to_user`"). Buttons and grid editing are disabled
  for capabilities the caller is known to lack (object-level when the table
  was opened from the tree); unknown privileges disable nothing. Convenience
  only.
- Grid: virtualised rows, `NULL` apart from `""`, copy of the selected cell.
  A table opened from the tree is editable when describe says so and the
  result holds its key: update (changed columns plus their originals),
  delete by key, insert of filled columns; binary, JSON and truncated cells
  are read-only; conflict, refusal and database error are shown on the row.
- Confirmations before `DROP`, `TRUNCATE`, and `DELETE` / `UPDATE` without a
  top-level `WHERE`, and before a grid delete. UX guards, stated as such.
- Entries: "Open SQL browser" in a database resource's card context menu
  (its only valid `sql` profile, else the plugin picks), an Open button per
  valid `sql` profile and an "Open SQL browser" button on the Connection
  tab's SQL card, and ⌘K entries for resource × valid `sql` profile (with the
  workspace's placement).

Deviations from §10 and the API table:
- **Pinned set.** `sql_script` and `sql_export_to_file` are not registered:
  the plugin answers `unsupported` until T126, and a granted command no route
  calls would widen the set. `sql_session_status`, `sql_privileges` and
  `sql_history` were added; the timers, chips and History tab need them.
- **Discovery.** `GET v2/sys/plugins/active-surfaces` does not report
  `sql_console` (it lists only plugins with a surface manifest), so the host
  resolves the mount from the caller's mounts and the plugin manifest. In
  remote mode reading `sys/plugins/<name>` needs a policy that grants it; a
  token without it gets an explicit error, never a guessed mount. The entry
  points are shown without that probe; opening fails with the reason.
- **Editor and grid libraries.** No CodeMirror 6 or TanStack Virtual: the
  editor is a plain textarea (no highlighting, no autocomplete) and the grid
  does its own windowing. Adding the packages needs a dependency change and
  a registry download not made in this phase.
- **HA.** On `session_on_other_node` the workspace says the session has
  ended and offers no automatic reconnect to the named node (D6: no
  failover); the operator opens a new session.

Security notes: the webview cannot name a path, mount or plugin session —
the host builds every path from its own record and validated or escaped
segments, and `sql_rows` forwards only the five structured keys. Nothing the
GUI disables is a control. Logs carry resource, profile, mount, token and
window label, never statement text, values or credentials.

### Phase 4 validation

Run one at a time from `gui/` and the repository root:

1. `npx tsc --noEmit` (exit 0).
2. `npx vitest run` over the whole GUI: 112 files, 1353 tests passed. New:
   `sqlWorkspace.test.ts` (lexer, guard, formatter, errors, edits),
   `sqlWorkspaceUi.test.tsx` (chips and enforcement panel, token-only calls,
   NULL vs empty, refused verdict, confirmation, structured edit and
   conflict, read-only results, session ended, manual commit and the
   transaction badge), `sqlEntries.test.tsx` (launcher and MFA gate, ⌘K
   entry with placement, Connection tab buttons, workspace adoption), and
   `sessionBundle.test.tsx` extended (route table, `sql-window` set equal to
   what `/session/sql` calls).
3. `cargo check -p bastion-vault-gui` and `--all-targets` (exit 0);
   `cargo clippy -p bastion-vault-gui --lib` (exit 0, no warning in the new
   code).
4. `cargo nextest run -p bastion-vault-gui --lib`: 775 run, 773 passed; the
   two failures are `local_keystore` tests racing on the macOS keychain when
   run in parallel (file untouched; all six pass with `-j 1`). Includes the
   new `session::sql` tests, the SQL window-ACL test and the SQL stop-path
   test in `attachments`.
5. `make test-plan PKG=bastion-vault-gui`: no Rust test target is affected
   (the GUI crate is outside `test-changed`), so `make test-changed` was not
   run for this phase.
6. Browser check: `session.html#/session/sql` served by `npm run dev`, with
   the Tauri IPC mocked in the page (no Tauri shell, no vault, no plugin):
   tree, Open, grid, a cell edit reported as a conflict, the confirmation
   for `UPDATE` without `WHERE`, the refused verdict and the History tab
   rendered as intended.

Not done or not verified: a registered `dbms-management` plugin behind a real
vault (embedded or remote), the Tauri shell itself (window creation, the ACL
at run time, closing a window closing the plugin session), the workspace pane
and the ⌘K palette in a real window, remote-mode discovery, `docs/api.md`.

## Phase 5, exports, scripts and step-up

T126, §8. Host, plugin and GUI.

**Step-up tickets (host, `crates/bv-engine-resource/src/connect_mfa.rs`).**
- The ticket record gains an optional `action`: the canonical set of `sql_*`
  names (policy-language order, comma-separated). Absent, it is not written,
  so a connect ticket's record is byte for byte what earlier releases wrote;
  a record written before T126 reads as no action. `consume` compares it like
  `mcp_call`: a ticket without an action is refused for an action, and an
  action ticket is refused at every connect.
- `connect/mfa/begin|verify` take `action` (a string or a list): `sql`
  profiles only, every name in the stored profile's `sql.step_up`, checked
  before any factor. With an action the gate is `step_up`, not `require_mfa`.
  `verify` refuses `action` with `mcp_call`.
- `redeem_sql_action_ticket` always demands and burns a ticket: there is no
  "not gated" pass for an action. The facade's `connect_ticket_redeem`
  (`src/plugins/sql_host.rs`) calls it directly (the facade may name the
  engine), so `bv-kernel-api`'s `ConnectMfaGate` is unchanged. It records no
  connect redemption, so an action ticket never unlocks a `require_mfa`
  release. The SDK gains `connect_ticket_redeem_action`; the testkit mirrors
  the binding and `test_plugin_testkit_parity` compares canonicalization.

**Plugin (`plugins-ext/bastion-plugin-dbms-management`).**
- `authz::Mode` (`Execute`, `Script`, `Export`). A script adds `sql_script` on
  `sql/server` to the batch; after a statement that may move the name context
  (`SET`, opaque, unclassified) its later unqualified names are checked with
  an empty schema, so only a resource-wide grant allows them. An export is
  checked before the host is asked (`Prepared::check_export`) and mirrors
  every `sql_select` check with `sql_export`.
- `script`: limits `script_statements` / `script_bytes`, `on_error`,
  `transaction: single` (the plugin's own `BEGIN` and `COMMIT` or `ROLLBACK`
  before the run reads as ended), result rows counted not returned, a
  per-statement deadline, `dbms.script` at start, refusal and end.
- `export` (`src/export.rs`): the renderer per format, a job with a 2 MiB
  high-water buffer the producer waits on, 1 MiB chunks, a retried pull, the
  SHA-256 of the stream, row and byte limits (`limit_reached`), abandonment
  after `export_idle_secs` (`expired`, buffer dropped), cancel, and the
  statement timeout raised to `export_timeout_secs` while it streams. A
  running export makes the session busy.
- Step-up on `execute`, `script`, `export` and grid edits: after the vault
  allowed the request, the capabilities it uses that the profile's `step_up`
  lists need `step_up_ticket` for exactly that action, redeemed through the
  host; without it the reply is `step_up_required` and nothing runs or is
  spent. `dbms.step_up` records each redemption.
- Config `v: 2` with `script_statements`, `script_bytes`, `export_rows`,
  `export_bytes`, `export_idle_secs`, `export_timeout_secs`; a `v: 1` record
  is read (its values kept, the new ones defaulted) and written back as v2.
- The profile view's `step_up` is parsed strictly; a missing list fails the
  profile.

**GUI.** Tauri commands `sql_script`, `sql_export_to_file`,
`sql_export_cancel`, `sql_step_up_begin`, `sql_step_up_verify`, in the
`sql-window` and workspace sets. The host opens the save dialog itself,
writes to `<file>.part`, checks the plugin's SHA-256, renames, and deletes the
part file on any failure or cancel (cancelling the job too). The step-up
ticket is held by the host (110 s, used once) and attached to the next
request; the webview gets the action and expiry only. Frontend: *Run script*
(always confirmed, *On error*, *One transaction*), *Load .sql* (read locally,
4 MiB), *Export* for the statement at the cursor and on tables in the tree
(`SELECT * FROM` the quoted name), the export dialog, the step-up prompt, the
profile's step-up chips in the info panel. New SQL profiles start with
`sql_drop`, `sql_admin`, `sql_export`, `sql_script` in `step_up`.

Decisions where the spec is silent or could not be followed:
- **One ticket per request, bound to the set of actions it uses** (a script
  with a `DROP` steps up once for `sql_drop,sql_script`). Rejected: one
  ticket per capability, which asks for two factors back to back, and a
  TOTP code cannot be replayed within its window.
- **The pull offset is a path segment** (`exports/<job>/<offset>`). A GET's
  query reaches a handler only through `bv-logical`'s allowlist, and the
  process-plugin envelope carries the body only. Rejected: widening both,
  which rebuilds most of the workspace and changes every plugin's envelope.
- **A stored profile without `step_up` steps up for nothing.** The default
  list is what the editor puts on a new profile. Rejected: reading an absent
  list as the default four, which would change profiles the T124 editor
  saved (it omits an empty list) and lock non-userpass callers out of those
  actions without notice.
- **The step-up list is read at session open**, as the ceiling and
  `require_mfa` are; a change applies to new sessions. Rejected: a target
  read per request, a host call each time.
- **Not an ABI bump.** `action` was already in the 1.4 table (§9.2); this
  host now honours it. A plugin asking for it on an older host gets
  `bad_request` and fails closed.
- **`on_error: continue` is refused with `transaction: single`** on
  PostgreSQL (an error aborts the transaction). **Script rows are not
  returned** (one run buffer cannot hold several result shapes); run a
  SELECT with *Run* to see it. **Script size stays at 4 MiB**, the
  classifier's and the request's cap, below §12's 32 MiB.
- **Export kinds** are SELECT, VALUES, SHOW and plan-only EXPLAIN; anything
  needing more than `sql_select` is refused before the host is asked.

Residual risks:
- Step-up is enforced by the plugin: the host binds and burns tickets but
  cannot tell which capability a statement uses. A compromised plugin can
  skip it, as it can use the login it holds (§2).
- A late PostgreSQL `CancelRequest` (row limit, cancel) can hit the
  statement after it; the timeout restore is retried once, and the plugin's
  own run deadline bounds later statements either way.
- One export cell is materialized whole (a 1 GB `bytea` would be).
- An export's statement timeout is `export_timeout_secs` (30 min default),
  not the 60 s run timeout.
- A failed `transaction: single` COMMIT reads `commit_failed`; the database
  rolled back.

### Phase 5 validation

Run one at a time; plugin commands from `plugins-ext/`, the rest from the
repository root or `gui/`:

1. `cargo check -p bv-engine-resource`, `cargo clippy -p bv-engine-resource
   --lib`, `-p bastion-plugin-testkit --lib`, `-p bastion-plugin-sdk --lib
   --features process`, `cargo clippy --lib`: exit 0, no warning in a
   touched file.
2. `cargo nextest run -p bv-engine-resource --lib connect_mfa` (10 passed),
   `-p bastion-plugin-testkit` (48 passed), `-p bastion_vault --lib` over the
   ticket, SQL-host and connect filters (49 passed, including
   `step_up_tickets_are_bound_to_their_action`), `--test
   test_plugin_testkit_parity` (9 passed).
3. Plugin: `cargo check` / `cargo clippy --lib --tests` (exit 0), `cargo
   nextest run -p bastion-plugin-dbms-management` (86 passed), and the three
   new live tests `live_exports`, `live_scripts`, `live_step_up` against
   `postgres:16` (3 passed).
4. GUI: `npx tsc --noEmit` (exit 0); `npx vitest run` over the SQL files (6
   files, 187 passed) and the new `sqlScriptExport.test.tsx` (10 passed);
   `cargo check` / `cargo clippy -p bastion-vault-gui --lib` (exit 0);
   `cargo nextest run -p bastion-vault-gui --lib` over `session::sql`, the
   window ACL and connect MFA (30 passed). The whole GUI: 113 files, 1363
   passed.
5. `make test-changed` (L3: `bastion-plugin-sdk`, `-testkit`,
   `bastion_vault`, `bv-engine-resource`, `bv-kernel`, `bv-server`,
   `bvault-cli`, `bv-plugin-pack`): exit 0, 1305 + 17 passed. `make
   test-dbms`: all 10 live tests passed and the `openssl-sys` / `aws-lc-sys`
   ban held; plugin doctests 8 passed, `cargo fmt --check` clean.

6. The five cucumber scenarios pass against PostgreSQL 16 (`make test-dbms`, 11
   live tests), and `make test-release` passed all 9 suites.

Not done: the plugin registered on a running vault (embedded or remote) and a
real Tauri window (the save dialog and the export loop are compiled, not run).

