# Feature: IP-based DoS / request-abuse protection

## Summary

A configurable, per-client-IP request guard that defends the HTTP server against
volumetric request abuse and login brute-forcing. Each client IP's requests are
counted over a sliding window; an IP that exceeds the request ceiling is
**temporarily banned** for a configurable duration. A separate, stricter ceiling
applies to authentication/login paths so credential-stuffing is stopped well
before the general limit. Operators manage everything from the GUI Settings
**Abuse Protection** panel: live per-IP statistics, active bans, threshold
editing, and manual ban/unban.

Banned requests are rejected with `429 Too Many Requests` and a `Retry-After`
header before they reach routing. Health, seal-status, and metrics endpoints are
always exempt so monitoring and load balancers can never be banned.

## Motivation

- **No global request-abuse defense existed.** The only rate limiting was
  per-namespace quotas (`src/modules/namespace/quota.rs`) and per-mount login
  limits (Ferrogate); neither protects the server as a whole against one abusive
  IP flooding requests.
- **Brute-force resistance.** A stricter per-window ceiling on login paths
  raises the cost of credential-stuffing independently of the general limit.
- **Operator control.** Thresholds must be adjustable at runtime, and operators
  must be able to see who is hammering the server and ban/unban IPs by hand.

## Design

### Threshold model (`src/dos/config.rs`)

A single process-wide [`DosConfig`]:

| Field | Meaning | `0` means |
|---|---|---|
| `enabled` | Master switch | — |
| `window_secs` | Length of the per-IP counting window | (clamped ≥ 1) |
| `max_requests` | Max requests / window before a ban | rule disabled |
| `auth_max_requests` | Stricter ceiling for auth/login paths | rule disabled |
| `ban_secs` | Automatic ban duration | never auto-ban |
| `refresh_secs` | Manual-ban reload / sweep cadence | (clamped ≥ 5) |

Defaults are secure-but-non-disruptive: 200 req / 10 s general, 20 req / 10 s on
auth paths, 300 s bans.

### In-memory guard (`src/dos/guard.rs`)

`DosGuard` is the hot-path enforcer, held on `Core` (`core.dos_guard`) and
consulted by the middleware on every request. It keeps a fixed-window counter
per IP and a ban map (`Auto` / `Manual`). `check(ip, path)` records the request,
evaluates the general and auth thresholds, and returns a `BanInfo` (with
`retry_after_secs`) when the IP is banned. A `sweep()` drops expired bans and
stale windows on a timer. The guard is process-local by design — the request
path never touches storage.

### Middleware (`src/dos/middleware.rs`)

An actix `from_fn` layer wrapped outermost in the `App` (before logging and
metrics). It resolves the client IP with `ClientIp::resolve` — honoring
`BASTIONVAULT_TRUSTED_PROXIES` / `X-Forwarded-For` / `Forwarded` exactly as the
logical handler does, so deployments behind a reverse proxy key on the real
client, not the proxy — then calls `guard.check`. On a ban it short-circuits
with `429` + `Retry-After` and, only on the *transition* into an automatic ban,
emits one audit event (never one per blocked request; never logs bodies/tokens).
It **fails open** if connection info or the guard is unavailable, so a defect can
never lock out all traffic; it **fails closed** on an active ban.

### Persistence (`src/dos/store.rs`)

`DosStore` persists exactly two things through the core system view (barrier root
`sys/`, key `dos/state`): the `DosConfig` thresholds and the set of **manual**
bans. Both are encrypted and — under Hiqlite — replicated across the HA cluster.
Automatic bans and live counters are **not** persisted; they are ephemeral
per-node state.

### Startup seed (`src/cli/config.rs`)

An optional `dos { ... }` block seeds the thresholds on first unseal. The
barrier-persisted value (once an operator edits it) wins on every subsequent
unseal.

### Lifecycle

- At `post_unseal`, `Core::load_dos_state` loads persisted config + manual bans
  into the guard (best-effort — a failure leaves the seeded config).
- A background task in the server (`server.rs`) calls `Core::refresh_dos_bans`
  every `refresh_secs`: reloads persisted manual bans (so a ban applied on one HA
  node converges on the others) and sweeps expired in-memory state.

### Enforcement bounds (operational notes)

- **Per-node, in-memory enforcement.** Each node rate-limits the traffic it
  directly sees. In an HA cluster the counters are independent per node — this is
  standard and desirable (each node protects itself).
- **Manual-ban convergence.** A manual ban persists immediately and takes effect
  on the handling node at once; other nodes pick it up on their next refresh
  (default 30 s). For most deployments this is well within tolerance.
- **Embedded GUI mode is not rate-limited.** The embedded backend calls
  `core.handle_request` directly (no actix middleware), which is correct — it is
  a local, single-operator mode. The stats/config/ban endpoints still work there.

## API

All routes are root-scoped. Canonical form is `v2/sys/dos/*` (a `v1` mirror
exists only because the sys route builder is shared).

| Method | Path | Operation |
|---|---|---|
| GET | `v2/sys/dos/config` | Read thresholds |
| POST/PUT | `v2/sys/dos/config` | Update thresholds (partial; only supplied keys change) |
| GET | `v2/sys/dos/stats` | Live per-IP stats + active bans |
| POST/PUT | `v2/sys/dos/bans/{ip}` | Manually ban an IP (`{ttl_secs?, reason?}`) |
| DELETE | `v2/sys/dos/bans/{ip}` | Unban an IP |

Tauri commands: `get_dos_config`, `set_dos_config`, `get_dos_stats`, `ban_ip`,
`unban_ip`.

## GUI

Settings → **Abuse Protection** (`gui/src/components/DosProtectionPanel.tsx`):

- **Thresholds** card — edit/save the config; the effective (server-sanitized)
  values are echoed back.
- **Active Bans** card — table of banned IPs (type, reason, expiry) with an
  Unban action and a manual "Ban IP…" modal.
- **Client IP Activity** card — live per-IP request counts for the current
  window (5 s poll), with a Ban action on un-banned IPs.

## Current State

**Done.** Backend (`src/dos/` — config, guard, middleware, store; `Core`
integration; `server.rs` wiring + sweep task; `sys/dos/*` logical routes + HTTP
shims; `[dos]` startup config), GUI (Tauri commands + `api.ts` + panel + Settings
tab), and tests (guard unit tests, store round-trip, actix middleware
integration test, GUI vitest) all shipped.

## Testing

- `src/dos/guard.rs` — window counting, general/auth thresholds, ban expiry,
  manual ban/unban, exempt/auth classifiers, config re-arm.
- `src/dos/store.rs` — config + manual-ban round-trip; `Core` helper
  persist/reload into the guard.
- `src/dos/middleware.rs` — actix `TestRequest` proof that a flooding IP gets
  `429` while an exempt path never does.
- `gui/src/test/dosProtection.test.tsx` — panel renders stats/bans and drives
  ban/unban/save against a mocked API.
