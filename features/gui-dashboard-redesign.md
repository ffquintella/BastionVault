# Feature: GUI Dashboard Redesign — Operational PAM Landing View

## Summary

Replace the current GUI Dashboard ([gui/src/routes/DashboardPage.tsx](../gui/src/routes/DashboardPage.tsx)) — a static configuration listing of mounts and auth methods — with an **operational, statistics-driven landing view** modelled on how production PAM / secrets-management consoles (CyberArk, Delinea, BeyondTrust, HashiCorp Vault, Teleport) present situational awareness.

The redesigned dashboard answers the questions an operator actually opens the app to ask: *Is the fleet healthy? Who is connected right now? What happened in the last 24h? What needs my attention?* It is organised as a vertical narrative — **status → KPIs → activity → live sessions + audit → attention → quick actions** — built entirely from data the GUI can already fetch, with graceful degradation when an engine (Rustion, PKI, …) is not mounted.

The feature ships in six widget groups:

1. **Header health strip** — seal state + HA cluster node health, replacing the current "Signed in as" line.
2. **KPI tile row** — five at-a-glance counters with trend sub-lines (live sessions, healthy bastions, secrets stored, active tokens, audit events 24h).
3. **Session activity chart** — 24h bucketed bar/sparkline from the audit stream.
4. **Live sessions panel** — who is connected through the bastion right now, polled.
5. **Recent audit feed** — last N audit events with allow/deny coloring.
6. **"Needs attention" panel** — expiring certs, credentials due for rotation, failed logins, audit-write failures — plus a **quick actions** strip.

The feature is **backend-first**: Phase 1 ships a single server-side aggregation endpoint (`GET /v1/sys/dashboard/summary`) so the dashboard makes **one** call for its counters instead of fanning out N list-calls on every load. The GUI phases (2–5) then render against that endpoint, with a client-side fan-out fallback for tiles the summary doesn't cover or when talking to an older server.

## Motivation

- **The current dashboard has near-zero situational-awareness value.** It shows Vault Status (initialized/sealed — already in the header badge), the current user's policies, a Seal button, and two tables (Secret Engines, Auth Methods) that duplicate the Mounts admin page. An operator learns nothing about *what is happening* in the vault — no session count, no audit volume, no health, no risk surface.
- **Every comparable PAM/secrets console leads with operational metrics, not config.** Industry research on the landing views of the leading tools shows a consistent pattern:
  - **HashiCorp Vault** leads with per-node seal status, then usage metrics (tokens, secrets, leases, entities), an **audit-log-failure count that should read zero**, and request-rate/latency graphs.
  - **CyberArk / Delinea / BeyondTrust** lead with a KPI tile row (privileged accounts, active sessions, pending approvals, credentials due for rotation), then a risk/attention panel (failed logins, stale accounts, expiring credentials) and a live activity feed.
  - **Teleport** centres the landing view on active/joinable sessions and recent access events.
  The throughline is **status → counts-with-trend → live sessions → audit activity → attention → quick actions.**
- **BastionVault already has the richest data of any of them and surfaces none of it on the landing page.** Live bastion sessions, recordings, per-bastion health, audit events, PKI cert inventory, LDAP rotation roles, token TTLs, and HA cluster state are all fetchable today via existing Tauri commands and `bv_client`. The data exists; the dashboard simply doesn't use it.
- **Low risk, high visibility.** The redesign is additive on the data side (read-only list/health calls already exposed) and touches one page plus a handful of new presentational components. It does not change any server behavior in its baseline (Phases 1–4).

## Current State

**Status: Todo.** Spec drafted; no code yet.

The existing [DashboardPage.tsx](../gui/src/routes/DashboardPage.tsx) fetches `getVaultStatus()`, `listMounts()`, `listAuthMethods()`, and `loadEntity()` (for the display name), and renders a three-card row (Vault Status / Policies / Actions) plus the two mount tables. It uses an inline `Card`/`Row` helper rather than the shared `ui/Card` component.

## Design

### Layout

A single responsive page (no `max-w-*` on the container, per the GUI development rules in [CLAUDE.md](../CLAUDE.md)), stacked top-to-bottom:

```
┌──────────────────────────────────────────────────────────────┐
│ Dashboard                         [● Unsealed] [● 3/3 HA nodes]│  Header health strip
│ root namespace · signed in as felipe                          │
├────────┬────────┬────────┬────────┬────────────────────────────┤
│ Live   │ Bastn  │ Secrets│ Active │ Audit events 24h           │  KPI tile row
│  7     │ 12/13  │ 1,284  │  48    │ 3,902 · 14 denied          │  (auto-fit, 5 tiles)
├────────────────────────────────┬───────────────────────────────┤
│ Session activity · 24h         │ Needs attention                │  Chart + attention
│ ▁▂▃▅▆█▆▅▃▆▄▂                    │ · 3 PKI certs expiring <7d     │
│                                │ · 5 credentials due rotation   │
│                                │ · 2 failed logins (1h)         │
│                                │ · 0 audit write failures       │
├────────────────────────────────┼───────────────────────────────┤
│ Live sessions                  │ Recent audit                   │  Sessions + feed
│ felipe → prod-01      ● rec    │ ✓ token create  approle/ci  2m │
│ svc-deploy → hml-04   02:14    │ ✗ read denied   secret/...  6m │
│ m.silva → mysql       00:47    │ ✎ policy update admin      18m │
├────────────────────────────────┴───────────────────────────────┤
│ [Seal Vault]  [New secret]  [Issue cert]  [View audit log]      │  Quick actions
└──────────────────────────────────────────────────────────────┘
```

Responsive behavior (Tailwind):

- KPI row: `grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3`.
- Chart + attention and sessions + feed: `grid grid-cols-1 lg:grid-cols-2 gap-4` (chart column gets `lg:col-span-3` of a 5-col grid if a wider chart is wanted; baseline uses a simple 2-col split).
- All overflow-prone text (hostnames, paths, principals) uses `min-w-0` + `truncate`.

### Widget Catalog and Data Sources

Every widget maps to an existing command in [gui/src/lib/api.ts](../gui/src/lib/api.ts) or [gui/src/lib/rustion.ts](../gui/src/lib/rustion.ts). Tiles whose backing mount is absent render a muted `—` and a one-line "not mounted" hint instead of erroring.

| Widget | Value | Primary source | Notes / fallback |
|---|---|---|---|
| **Seal state** | sealed / unsealed | `getVaultStatus()` | Already fetched; keep. |
| **HA node health** | `healthy/total` nodes | `getServerInfo()` + cluster node list (`vaultStore` cluster state) | If single-node, show "standalone". |
| **Live sessions** | active count + "N recording" | `rustionTelemetryList()` | Gate on `rustion/` mount; `—` if absent. |
| **Bastions healthy** | `healthy/total` + degraded count | `rustionTargetHealthAll()` | Gate on `rustion/` mount. |
| **Secrets stored** | total across KV engines | Phase 1 summary `counts.secrets` | Server-side aggregate (expensive to count client-side). Fallback: per-kv top-level key count labelled "≈". |
| **Active tokens / entities** | token count + entity count | Phase 1 summary `counts.tokens_active` / `counts.entities` | Fallback: `tokenStatus()` self-TTL + `listGroups()` (self-token TTL always available even without the summary). |
| **Audit events 24h** | count + denied count | `listAuditEvents(from, to, limit)` | `from = now-24h`. Denied = events with a permission-denied/error outcome. |
| **Session activity chart** | hourly buckets, 24h | `listAuditEvents` bucketed client-side, or `rustionTelemetryList` history | Pure CSS bar chart (no chart lib needed for a 24-bar sparkline). |
| **Needs attention: certs** | certs expiring < 7d | `pkiListCerts()` → filter `not_after` | Gate on `pki/` mount. |
| **Needs attention: rotation** | credentials due | `ldapListRoles()` / openldap static roles next-rotation | Gate on `openldap/` mount. |
| **Needs attention: failed logins** | denied auth events (1h) | `listAuditEvents` filtered to auth path + error | Always available when audit is on. |
| **Needs attention: audit failures** | audit write-failure count (should be 0) | `listAuditEvents` / audit device health | Vault's "should read zero" signal; red if > 0. |
| **Recent audit feed** | last 5–10 events | `listAuditEvents(from, to, 10)` | Color by outcome: success/green, denied/red, write/blue. |
| **Quick actions** | Seal, New secret, Issue cert, View audit | navigation + existing `sealVault()` | Seal stays here (current behavior preserved). |

### Graceful Degradation and Loading

- All widget data is fetched with `Promise.allSettled` (not `Promise.all`) so one failing call (e.g. Rustion not mounted, or a remote backend that 404s a route) degrades that one tile to `—` rather than blanking the whole page.
- Mount-gated widgets first consult the `listMounts()` / `listAuthMethods()` result already fetched and only fire their detail call when the relevant mount exists.
- Each tile renders a skeleton state while its promise is pending; the page never blocks on the slowest call.
- Errors are surfaced per-tile (a small muted "couldn't load" with a refresh affordance), never as a page-level red banner, except for a hard `getVaultStatus()` failure.

### Polling

- Only the **Live sessions** tile + panel poll, on a 5s interval, matching the existing `RustionLiveSessionsPage` cadence. The interval is cleared on unmount.
- Everything else loads once on mount with a manual **Refresh** affordance in the header. No background polling for audit/KPIs — operators refresh when they want a new snapshot. (A future enhancement could add an opt-in auto-refresh toggle.)

### Components

Reuse the shared component library under [gui/src/components/ui/](../gui/src/components/ui/) — `Card`, `Badge`, `StatusBadge`, `Table`, `EmptyState` — rather than the inline `Card`/`Row` helpers currently in `DashboardPage.tsx`. New presentational components:

| Component | Purpose |
|---|---|
| `gui/src/components/dashboard/KpiTile.tsx` | Label + big number + colored sub-line (trend/secondary). Built on the surface-card pattern. |
| `gui/src/components/dashboard/HealthStrip.tsx` | Header badges for seal state + HA node health. |
| `gui/src/components/dashboard/SessionActivityChart.tsx` | Pure-CSS 24-bar hourly chart from bucketed counts (no chart dependency). |
| `gui/src/components/dashboard/AttentionPanel.tsx` | List of attention rows with severity icon + count, each linking to the relevant page. |
| `gui/src/components/dashboard/LiveSessionsCard.tsx` | Compact list of active sessions (principal → target, duration, recording dot), polled. |
| `gui/src/components/dashboard/RecentAuditCard.tsx` | Last N audit events, outcome-colored, linking to the Audit page. |
| `gui/src/components/dashboard/QuickActions.tsx` | Action button row (Seal, New secret, Issue cert, View audit). |

Theming uses the existing CSS variables in [gui/src/index.css](../gui/src/index.css) (`--color-surface`, `--color-text-muted`, `--color-success`, `--color-warning`, `--color-danger`, `--color-primary`). No new color tokens.

### Backend Aggregation (Phase 1)

Counting secrets/tokens/entities client-side by fanning out list calls is slow and chatty, especially in remote mode against a large vault. Phase 1 adds a single read-only summary endpoint so the dashboard makes **one** call for its counters:

```
GET /v1/sys/dashboard/summary        # (logical route; needs an actix shim for HTTP — see note)
```

Response shape:

```json
{
  "seal": { "sealed": false, "initialized": true },
  "ha":   { "nodes_total": 3, "nodes_healthy": 3 },
  "counts": {
    "secrets": 1284,
    "tokens_active": 48,
    "entities": 9,
    "resources": 211,
    "files": 37,
    "policies": 14
  },
  "audit_24h": { "total": 3902, "denied": 14, "write_failures": 0 },
  "attention": {
    "certs_expiring_7d": 3,
    "credentials_due_rotation": 5,
    "failed_logins_1h": 2
  },
  "sessions": { "active": 7, "recording": 3 },
  "bastions": { "total": 13, "healthy": 12 }
}
```

> **Note (HTTP routing):** per the project's known pattern, a logical-only `sys/*` route works in embedded mode but 404s over HTTP unless an actix shim is added in `configure_sys_routes`. The summary endpoint must register that shim so the dashboard works in remote mode too. The Tauri command must route through the `Backend` trait (not lock `AppState.vault` directly) so it doesn't throw "Vault not open" when connected to a remote server.

This endpoint is the **foundation Phase 1 delivers**. The GUI phases render against it directly. A client-side fan-out path is retained as a fallback for the handful of tiles the summary doesn't cover and for compatibility with an older server that lacks the route (the GUI feature-detects: if `dashboardSummary()` 404s, it falls back to per-tile list calls), but the summary endpoint is the primary, expected path.

## Implementation Scope

### Phase 1 — Backend summary endpoint

| File | Purpose |
|---|---|
| `src/http/sys.rs` (+ actix shim) | `GET /v1/sys/dashboard/summary` logical route + HTTP shim (so it works over HTTP, not just embedded). |
| `src/modules/.../dashboard_summary.rs` | Server-side aggregation of counts + audit-24h + attention, ACL- and namespace-scoped. |
| `gui/src-tauri/src/commands/*.rs` | `dashboard_summary` Tauri command routed via the `Backend` trait (works embedded + remote). |
| `gui/src/lib/api.ts` | `dashboardSummary()` typed wrapper. |

Ships the aggregation endpoint + Tauri command + typed wrapper, with the response shape above. Unit/integration tested independently of the UI (assert ACL/namespace scoping, audit-24h math, and HTTP reachability) so the GUI phases build on a verified data source.

### Phase 2 — Layout shell + KPI tiles + header health strip

| File | Purpose |
|---|---|
| `gui/src/routes/DashboardPage.tsx` (rewrite) | New layout; one `dashboardSummary()` call + `Promise.allSettled` fallback for uncovered/legacy tiles; mount-gating. |
| `gui/src/components/dashboard/KpiTile.tsx` | KPI tile component. |
| `gui/src/components/dashboard/HealthStrip.tsx` | Header seal + HA badges. |

Ships the header strip and the five KPI tiles (live sessions, bastions, secrets, tokens, audit 24h) fed by the Phase 1 summary, with per-tile loading/error/`—` states and feature-detected fallback to client-side counts if the server lacks the route.

### Phase 3 — Session activity chart + recent audit feed

| File | Purpose |
|---|---|
| `gui/src/components/dashboard/SessionActivityChart.tsx` | 24h CSS bar chart from bucketed audit counts. |
| `gui/src/components/dashboard/RecentAuditCard.tsx` | Last N audit events, outcome-colored. |

### Phase 4 — Live sessions panel (polled) + needs-attention panel

| File | Purpose |
|---|---|
| `gui/src/components/dashboard/LiveSessionsCard.tsx` | 5s-polled active-sessions list (Rustion-gated). |
| `gui/src/components/dashboard/AttentionPanel.tsx` | Expiring certs / due rotations / failed logins / audit failures (from the summary's `attention` block). |

### Phase 5 — Quick actions + polish

| File | Purpose |
|---|---|
| `gui/src/components/dashboard/QuickActions.tsx` | Seal + navigation actions; preserves current Seal behavior. |
| (polish) | Empty-state copy, deep-links from every attention row, vitest coverage. |

### Not In Scope

- **New charting dependency.** The 24-bar activity chart is pure CSS/flex. If richer time-series visualisation is wanted later, that is a separate enhancement.
- **Configurable / draggable widgets.** The layout is fixed in v1. Per-user widget customization is a future enhancement.
- **Background auto-refresh of non-session widgets.** Only live sessions poll; everything else is manual-refresh in v1.
- **New audit query capabilities.** Phase 1's summary returns coarse audit-24h counts and Phase 3 buckets/filters the existing `listAuditEvents` result client-side for the activity chart; neither adds a general server-side audit query API.
- **Cross-namespace roll-ups.** The dashboard reflects the currently-selected namespace, consistent with the rest of the GUI.

## Testing Requirements

### Unit / Component Tests (vitest)

- `KpiTile` renders value, label, and sub-line; renders `—` + hint when given a null/absent value.
- `HealthStrip` shows "Unsealed" vs "Sealed" and "N/M nodes" vs "standalone".
- `SessionActivityChart` buckets a synthetic 24h audit array into 24 bars with correct relative heights; handles an all-zero day (flat bars) and a single-spike day.
- `AttentionPanel` renders a green "0 audit write failures" and a red "> 0" variant; each row links to the right route.
- `RecentAuditCard` colors success/denied/write events correctly and truncates long paths.
- `LiveSessionsCard` renders the polled list, shows the recording dot, and clears its interval on unmount (assert no post-unmount state update).

### Integration / Behavior Tests

- Dashboard with **Rustion not mounted**: live-sessions + bastion tiles show `—`/"not mounted"; the rest of the page renders normally (no thrown error, `Promise.allSettled` path).
- Dashboard with **PKI not mounted**: the certs-expiring attention row is omitted, not errored.
- **Remote mode**: every tile's command routes through the `Backend` trait and renders (guard against the embedded-only "Vault not open" regression). Phase 5's summary endpoint is reachable over HTTP (actix shim present), not just embedded.
- **One slow/failing call** (e.g. audit query times out): its tile shows a per-tile error with refresh; sibling tiles still render.

### Manual / Preview Verification

- Render against the dev vault and confirm: counts match the underlying pages (Secrets, Users, Recordings, Live Sessions), the activity chart's totals match the Audit page for the same 24h window, and live-sessions count matches `/rustion` Live Sessions.

## Security Considerations

- **Read-only and ACL-respecting.** Every widget uses an existing list/read/health command; the dashboard adds no new write surface beyond the Seal action that already exists. All calls run as the logged-in token, so a user only ever sees counts/events their policies permit — the dashboard inherits the server's ACL, it does not bypass it. A user without audit read sees the audit widgets as `—`, not as someone else's data.
- **No secret material on the dashboard.** Tiles show counts and metadata (paths, principals, timestamps, statuses) — never secret values, token strings, or private keys. The recent-audit feed shows the same redacted event shape the Audit page already renders.
- **The Phase 1 summary endpoint is ACL-scoped and namespace-scoped.** The summary endpoint computes counts only within the caller's effective ACL and active namespace; it must not become a side-channel that reveals the existence of resources the caller cannot otherwise see. Counts are aggregate-only (no enumeration of names a list call would itself deny).
- **Audit-write-failure surfacing is a security feature, not just UX.** Mirroring Vault's "this should read zero" signal puts a tamper/availability indicator on the landing page, where an operator sees it immediately.
- **Polling is bounded.** Only the live-sessions widget polls (5s), and only while the page is mounted; the interval is cleared on unmount to avoid orphaned requests against a remote backend.

## Tracking

Add a roadmap row under **Infrastructure** near the GUI row:

```
| `[ ]` Todo | GUI Dashboard Redesign (operational PAM landing view) | [spec](features/gui-dashboard-redesign.md) — KPI tiles + session activity + live sessions + audit feed + attention panel; 4 GUI phases + 1 optional backend summary endpoint. |
```

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers.
