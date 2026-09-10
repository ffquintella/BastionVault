# Feature: Client request efficiency and cache coherence

## Summary

The official desktop client must never be able to trigger the server's own
abuse defenses. Today it can: several GUI pages issue one HTTP request per
listed object, so a mount holding a few hundred certificates produces a few
hundred requests in one burst, crosses the `DosGuard` ceiling (default 200
requests / 10 s — see [`dos-abuse-protection.md`](dos-abuse-protection.md)),
and earns the operator a 300-second ban on their own vault.

This feature closes that in four layers, from backstop to root cause:

1. **A rate gate in the client transport**, so no page — present or future —
   can exceed a bounded request rate.
2. **Bulk metadata endpoints** on the engines that back list-heavy pages, so a
   listing costs one request instead of `1 + N`.
3. **Cursor pagination** on those endpoints, so cost is bounded by page size
   rather than by inventory size.
4. **A client-side read cache**, plus a **change-notification channel** so a
   write from one client invalidates the corresponding cache entries in every
   other connected client instead of waiting out a TTL.

Layer 4's notification channel also addresses a limitation
[`caching.md`](caching.md) records as a non-goal: server-side caches on one
cluster node do not learn about writes committed through another.

## Motivation

- **The client trips the server's own guard.** Reported from production: the
  PKI page rendered a stack of `HTTP 429: request temporarily blocked by DoS
  protection: request rate exceeded: >200 req/10s` toasts on a normal page
  load. Nothing was wrong with the vault, the operator, or the network.
- **Loosening the guard is the wrong fix.** The threshold is doing its job;
  raising it to accommodate a client bug weakens every deployment and only
  moves the cliff further out.
- **The fan-out shape is systemic, not a one-off.** `Promise.all(list.map(read))`
  appears in 19 GUI files. Any fix that only repairs the page that happened to
  break leaves the next one to be discovered in production.
- **Payload waste.** Each per-object read transfers a whole PEM so the client
  can display a common name and an expiry date. A listing of 500 certificates
  moves roughly a megabyte to render two columns.
- **Stale reads across clients.** With more than one operator connected — or
  one operator with the GUI and the CLI open — a change made in one place is
  invisible in the other until something is manually refreshed.

## Current State

**Complete.** All five phases are landed and wired into every page that had a
fan-out.

| Phase | Scope | Status |
|---|---|---|
| 1 | Client rate gate + `Retry-After` propagation | **Done** |
| 2 | PKI bulk metadata + cursor pagination | **Done** |
| 3 | Bulk metadata for the remaining list-heavy engines | **Done** |
| 4 | Client read cache with write-through invalidation | **Done** |
| 5 | Cross-client change-notification channel | **Done** |

The seven pages that had a per-object fan-out now each load a page, read
through the cache, and subscribe to their mount's change epoch: PKI
certificates, PKI outgoing CSRs, the PKI sign-request queue, SSH roles,
cert-lifecycle targets, userpass users, and namespaces.

## Design

### Phase 1 — client rate gate (`gui/src/lib/invoke.ts`)

Every GUI command goes through `lib/api.ts`, and every function there now
imports a gated `invoke` instead of Tauri's. One import change covers ~400 call
sites and every page.

The gate is a **token bucket**, not an in-flight cap, for two reasons. The
server guard counts requests per fixed window, so a rate limit maps onto
exactly what it measures; and tokens refill on wall-clock time, so a long-lived
command (an SSH session, a chunked recording fetch) cannot deadlock the queue
the way a concurrency cap would. Waiters are served FIFO, so a fan-out degrades
into a steady stream instead of starving whatever the operator clicks next.

Sizing: `RATE_PER_SEC = 8`, `BURST = 16`. Worst case in any 10-second server
window is `8 × 10 + 16 = 96`, comfortably under the 200 default, leaving room
for a second client — another GUI window, a CLI, a shared NAT egress — on the
same source IP.

On a `429` the gate parks the queue rather than letting every queued call fail
in turn and raise its own toast. It waits the server's `Retry-After` where one
is available, capped at 30 s: the point is to stop the toast storm, not to sit
out a five-minute ban behind a frozen UI. Accumulated tokens are dropped at the
same time, so resuming does not burst straight back into the guard.

`Retry-After` did not previously survive the trip to the client —
`bv-client` folded the status and body into a message string and dropped the
headers. `RemoteBackend::attempt` now captures the header before the body is
consumed and appends `(retry after Ns)` to the message on a 429, which is what
the gate parses.

### Phase 2 — PKI bulk metadata and pagination

`pki/certs` returns bare serials, so the Certificates tab reads every serial
individually to obtain a common name and an expiry. The common name and issuer
DN are not stored on the `CertRecord` at all — they are parsed from the PEM,
today in the Tauri host, once per certificate, after shipping every PEM over
the wire.

`pki/certs-info` (Read) returns a page of summaries with the parse done
server-side and the PEM omitted:

| Field | Source |
|---|---|
| `serial_number`, `issued_at`, `revoked_at`, `not_after`, `issuer_id`, `is_orphaned`, `source`, `key_id` | `CertRecord`, no parsing |
| `common_name`, `issuer_dn` | parsed from the stored PEM |

Pagination is an **`after` cursor**, not an offset: the page boundary stays
correct when a certificate is issued or revoked between requests, which an
offset does not. `limit` defaults to 100 and is capped server-side.

Both parameters arrive as query parameters, which requires adding `after` and
`limit` to `bv_logical`'s query allowlist. This stays a **Read** operation
deliberately: making it a write to carry a JSON body — the shape
`recordings/keystroke-search` uses for secrecy reasons — would mean a
read-only policy could not list certificates.

The client walks pages at 500 rows per request and keeps filtering and row
paging over the whole loaded set, so the tab behaves exactly as before — a
mount that exceeds the 5,000-row load ceiling now reports the real total
instead of silently showing a subset. A server without the route is detected
with `isRouteUnsupported` and the per-certificate read is used instead, so a
newer client against an older vault degrades in speed rather than breaking.

Still outstanding in this phase's shape: the two other unbounded PKI
fan-outs, the outgoing-CSR list and the sign-request queue, which are
folded into Phase 3.

### Phase 3 — remaining list-heavy engines

Seven endpoints, all the same shape, for every listing whose cost scales with
inventory:

| Endpoint | Replaced | Saving |
|---|---|---|
| `pki/certs-info` | `certs` + a read per serial | `1 + N` → 1 per 500 |
| `pki/csr-info` | `csr` + a read per pending CSR | `1 + N` → 1 per 500 |
| `pki/sign-request-info` | `sign-request` + a read per queued request | `1 + N` → 1 per 500 |
| `ssh/roles-info` | `roles` + a read per role, *per tab* | `1 + N` → 1 per 500 |
| `cert-lifecycle/targets-info` | `targets` + a target **and** a state read each | `1 + 2N` → 1 per 500 |
| `auth/<mount>/users-info` | `users` + a `get_user` **and** a FIDO2 read each | `1 + 2N` → 1 per 500 |
| `sys/namespaces-info` | `namespaces` LIST + a read per path | `levels + N` → 1 per level |

**Shared pagination (`crates/bv-logical/src/page.rs`).** `paginate` and
`page_response` give every endpoint one cursor contract — same envelope
(`keys`, `records`, `total`, `next`, `truncated`), same clamping, same
treatment of a cursor whose key has since been deleted. Written once because
the client's paging helper is written once, and because seven hand-rolled
copies of "resume after this key" would diverge.

**Two decisions worth recording.**

*Named `<list>-info`, not `<list>/info`.* The item patterns these sit beside
match a bare name — `roles/(?P<name>\w[\w-]*\w)` matches `roles/info` — so
the nested form would depend on route registration order *and* would make
`info` an unaddressable role, target, user or namespace name. The sibling
form cannot collide: patterns are anchored at both ends. `sys/namespaces-self`
already established the convention.

*Every projection is shared with the single read it replaces.* `read_user`,
`namespace_to_response`, `target_to_data` and `record_summary` were each
factored so the bulk handler renders an object through the *same* function.
This is not tidiness: `users-info` is exactly the sort of second listing
endpoint that reintroduces a credential leak by forgetting a redaction, and
sharing the projection makes `password_hash` and `credentials_json` impossible
to forget. The client mirrors it — one mapping function per record type,
used by both commands.

**Two candidates were assessed and deliberately skipped:**

- **AppRole.** The page lists role names and reads a role only when one is
  selected. There is no fan-out to remove, and an endpoint nothing calls is
  worse than none.
- **Resources.** The card grid already pages server-side through
  `resources/search`. The one remaining fan-out is the non-admin share-pointer
  fallback, which is bounded by the caller's own share count and is covered by
  the Phase 1 gate.

### Phase 4 — client read cache

`gui/src/lib/cache.ts`: a TTL cache keyed by topic (`<namespace>|<mount>`)
plus call, covering list and metadata reads only, with in-flight coalescing so
two components mounting at once share one request. Opt-in rather than blanket —
caching every read would cache seal status, token lookups and capability
checks, where staleness is a correctness problem rather than a latency one.

A write drops its topic *before* the reload that follows it, so a client always
sees its own writes; the whole cache is dropped on logout, session expiry and
namespace switch, because cached answers belong to the authorization context
that produced them.

**Two granularities meet in the topic, and conflating them is the mistake**
(`gui/src/lib/topics.ts`). The server's epoch granularity is the *mount* — the
finest signal it can send is "something under `pki/` changed". A client's cache
granularity is the *page*: three PKI tabs cache three listings off one mount,
and a local certificate write should not throw away this client's own
pending-CSR queue. So a topic is `<kind>|<mount>`: fine enough that a local
write drops only what it affects, while every topic watching a mount is
invalidated together when its epoch moves.

The namespace is deliberately absent from the client topic — the whole cache is
dropped on a namespace switch, so a topic can only hold entries for the active
one, and the server scopes its answer to the namespace the request is made in.

One mapping is easy to get wrong and fails *silently*: the GUI carries
userpass-style mounts as `userpass/` and builds paths as `auth/<mount>...`,
while the server files the epoch under the full `auth/userpass/`. A watcher
subscribed to the wrong string asks about a mount that never moves and simply
never invalidates, with no error anywhere. `authMount()` does the conversion
and there is a test asserting the Users page subscribes to `auth/userpass/`.

Under vitest the cache is reset before every test from `src/test/setup.ts`, so
no individual suite has to remember. Only `lib/cache` is imported there,
deliberately: `lib/changeWatcher` pulls in `lib/api` and therefore
`@tauri-apps/api/core`, and importing that from the setup file binds it before
a test file's own `vi.mock` can take effect, which breaks every suite that
mocks `invoke` itself.

### Phase 5 — cross-client change notification

**The registry** (`crates/bv-kernel-api/src/change_epochs.rs`). A per-topic
counter map plus a monotonic aggregate `version`, held on `Core` beside the DoS
guard. Bumped from **one** hook on the successful-write path
(`Core::record_change_epoch`) rather than from each engine: that is the only
place which sees every mutation, so a future engine cannot forget to
invalidate. Reads and lists do nothing; a write costs a prefix check and one
uncontended mutex.

Topics are `<namespace>\u{1f}<mount>`. The namespace is in the key so the
endpoint can scope its answer — without it, a snapshot would tell a tenant
which mounts exist in someone else's. The separator is a control character
because both halves are slash-delimited printable text, so a printable
separator could be forged into one to collide two topics. `auth/` mounts take
two segments (`auth/userpass/`), since filing every credential backend under
`auth/` would make a userpass write invalidate an AppRole listing.

**The endpoint** (`sys/cache/version`, shim in `bv-server/src/sys.rs`). Modeled
on the existing plugin-surface channel in the same file
(`sys/plugins/active-surfaces?watch=1`, ETag + `If-None-Match` + 304) — same
shape, already proven through this client and whatever proxy sits in front of
it. The ETag is the aggregate `version`, so one comparison answers "has
anything changed at all?", and a client polling a quiet vault costs a header
exchange rather than a body. `?watch=1` waits on a `tokio::sync::Notify` the
request path fires, so an invalidation reaches a waiting client immediately
instead of within a poll interval.

Three properties are deliberate and security-relevant:

- **No enumeration.** The caller must name its topics. Returning the registry
  wholesale would tell a tenant which mounts exist elsewhere, and tell any
  authenticated caller which mounts in its own namespace it cannot read.
- **Each named topic is authorized.** A topic is reported only if the caller's
  own capabilities cover reading that mount, evaluated with the same
  namespace-qualified probe `sys/capabilities-self` uses. A counter is not
  secret material, but it is an activity signal — "the `payroll/` mount was
  written to 40 times this hour" is worth refusing to someone who cannot read
  `payroll/`.
- **A refused topic is omitted, not zeroed.** A zero is a claim about the
  mount; an absent key is not.
- **Logins do not bump.** A login *does* touch the stored user record (the
  failed-attempt counter), but bumping on it would wake every watcher on every
  sign-in and turn a login storm into a refetch storm across every connected
  client. The cost is a `failed_login_count` that can lag by one cache TTL in
  an admin listing; the alternative costs more.

**The client** (`gui/src/lib/changeWatcher.ts`). One shared, refcounted poller:
five components watching a mount cost one request per interval, which would be
an embarrassing place to reintroduce the fan-out this feature exists to remove.
`notifyLocalChange` short-circuits the poll for this client's own writes — the
SSH Roles tab uses it so a role created in one tab appears in another tab's
picker immediately rather than up to 10 s later. It polls
every 10 s rather than holding a `?watch=1` request open — a desktop app with a
handful of operators is better served by one small conditional request per
interval than by a connection held open per client, and the long-poll stays
available for clients that prefer it. Failures are swallowed: an older server,
a token without the capability, or a transient error must not raise a toast,
because the TTL still bounds staleness.

**Honest limitation.** Epochs are per-node in-memory state, exactly like the
`DosGuard` counters, because bumping a persisted counter on every write would
double the write cost of the vault. `bv-client` pins a session to one node, so
a given client sees a coherent view of everything routed through its own node;
two clients pinned to different nodes in an HA cluster will not invalidate each
other. The TTL in Phase 4 remains the backstop for that case, and the cache
must stay correct — merely less fresh — without the channel. Counters also
reset on restart, so a client must treat only an *increase* as evidence of a
write; acting on a decrease would turn every failover into a cache-clear storm.

## Security considerations

- **No new data is exposed.** The bulk endpoints return a projection of records
  the caller can already read individually, and each page is authorized as a
  normal read of the listing path. They do not become a way to read certificates
  a policy would refuse one at a time.
- **`cert/*` versus `cert/+` still applies.** A bulk metadata endpoint must not
  become a path that a policy glob written for the singular `cert/<serial>`
  form unexpectedly grants; the new paths sit under the plural `certs/` prefix
  that already carries list semantics.
- **The gate is not a security control.** It protects usability, not the
  server. The server-side guard remains the enforcement point and is unchanged
  — a hostile client simply does not use the gate.
- **Epochs are metadata.** A topic epoch reveals that *something* changed under
  a mount and when. Subscription is authorized like any other read, and the
  response carries counters only — never paths, names, or values.
- **Cached material.** The client cache holds listing metadata only. Secret
  values are not cached client-side.

## Testing

- Gate: burst is admitted up to the allowance then queued; queue drains at the
  configured rate; a 429 parks the queue for the advertised `Retry-After`;
  the pause is capped; non-429 failures do not park it. *(`gui/src/test/requestGate.test.ts`, 5 tests, passing.)*
- `Retry-After` survives to the client's error message on a 429.
- Bulk endpoints: page boundaries with a cursor; `limit` clamping; a record
  written between two pages does not shift the boundary; malformed cursors are
  rejected rather than silently treated as the beginning.
- Parity: the bulk projection agrees field-for-field with the per-object read
  it replaces, including for records that predate each `#[serde(default)]`
  field. *(`src/engine_tests/bulk_info_endpoints.rs`, 11 tests over the real
  HTTP boundary — the query allowlist and the route-collision behaviour are
  properties of the HTTP path, invisible to an in-process test.)*
- No credential material in a bulk listing: `users-info` rows carry neither
  `password_hash` nor `credentials_json`.
- A role named `info` stays addressable at its own path *and* appears in the
  bulk listing — the collision the `-info` naming exists to prevent.
- Shared cursor contract: paging any two endpoints sees every key exactly
  once, `limit` clamps identically, and a cursor past the end is an empty
  non-truncated page rather than a rewind.
- Version skew: a GUI talking to a server without the bulk route falls back to
  the per-object path (`isRouteUnsupported`) rather than showing an error.
- Notification, server side *(`crates/bv-kernel-api` change-epoch unit tests,
  `crates/bv-core` topic-derivation tests, `src/engine_tests/cache_version.rs`
  over HTTP)*: a write bumps its mount and a read does not; a write to one
  mount leaves another alone; the endpoint reports only the topics it was
  given; a topic the caller cannot read is omitted rather than zeroed; the
  ETag is stable until something changes and then answers with a body; a login
  deliberately does not bump its auth mount; the topic map is bounded and says
  so when it stops itemizing; a watcher wakes on a bump, returns immediately
  when already behind, and times out cleanly when nothing happens.
- Notification, client side *(`gui/src/test/changeWatcher.test.ts`)*: the first
  epoch is a baseline rather than a change; a moved epoch invalidates and
  notifies; a subscriber whose own topic did not move is not notified; each
  mount is asked about once however many components watch it; `coarse` drops
  the whole cache; an omitted mount is ignored rather than treated as zero; an
  unavailable endpoint stays silent.
