# Feature: Web Application Connect — in-app web sessions with injected login or SSO

## Summary

Add a **web application** resource type and a third Connect protocol, `web`,
next to `ssh` and `rdp`. Pressing **Connect** on a web-application resource
opens a dedicated, isolated BastionVault window pointed at the application's
URL and signs the operator in, using one of four **login modes**:

| Login mode | What happens | Where the credential ends up |
|---|---|---|
| `open` | Window opens on the app, no login performed (the app's own SSO, or the operator types) | nowhere — no credential released |
| `form` | A declarative **login recipe** fills username / password / TOTP into the login form(s) and submits | the target page's DOM, for the instant between fill and submit |
| `http-auth` | HTTP Basic / Digest / NTLM challenge answered by the host, natively | the webview's auth handler, never the DOM |
| `sso` | BastionVault acts as the IdP (SAML 2.0 / OIDC, from [S19](identity-provider.md)) and launches an IdP-initiated login | no shared secret exists |

A later **proxy** variant of `form` (Phase 6) keeps the password out of the DOM
entirely by substituting it into the outgoing request at a host-local proxy.

A **future** transport, **Rustion browser isolation** (Phase 8, §12), runs the
browser on a Rustion-managed worker instead of the operator's machine. The
operator sees it over the existing RDP session path, the credential never
reaches the operator's endpoint, and the session is recorded like any brokered
RDP session. It needs work in the Rustion repo first and is not scheduled.

The operator never sees the password in any mode. Every launch passes the same
gates as SSH/RDP Connect: the `connect` capability, connect-time MFA, and a
server-side audit record. Each resource declares an **exposure level** so that
policy can forbid DOM injection for high-value accounts.

Builds on [features/resource-connect.md](resource-connect.md) (S46),
[features/connect-only-access.md](connect-only-access.md) (S10),
[features/connect-mfa-and-fido2-ssh.md](connect-mfa-and-fido2-ssh.md) (S9) and,
for the `sso` mode, [features/identity-provider.md](identity-provider.md) (S19).
Desktop GUI only, like the rest of Resource Connect.

## Motivation

- **Most privileged consoles are web UIs.** FortiGate, vCenter, iDRAC/iLO,
  pfSense, Grafana, Jenkins, Kubernetes dashboards and SaaS admin portals are all
  administered through HTTPS. Today an operator opens the resource, reveals the
  secret, copies it, and pastes it into a browser. That makes the reveal the
  normal path, and it defeats connect-only access.
- **The inventory already describes them.** The builtin `website` type carries a
  `url` field ([gui/src/lib/resourceTypes.ts:180](../gui/src/lib/resourceTypes.ts:180)),
  and [features/resources.md](resources.md) describes it as "URLs with login
  credentials". [features/resource-types-firewall-switch-db.md](resource-types-firewall-switch-db.md)
  explicitly defers vendor HTTPS GUIs "until the website-style 'open in browser'
  connect path is generalised". This spec is that generalisation.
- **Comparable products all ship it.** Examples include CyberArk Secure Web
  Sessions and PSM for Web, BeyondTrust PRA Web Jump, KeeperPAM Remote Browser
  Isolation, Delinea Credential Manager, ManageEngine PAM360 auto-logon, StrongDM
  Websites and Teleport App Access. See *Research* below.

## Research — how others do it, and what we take

There are five architectural patterns, listed here from lowest to highest
credential exposure on the operator's endpoint:

1. **Federation.** The vault is the IdP (SAML/OIDC), or the vault signs an
   identity header for an app behind a proxy (Teleport `Teleport-Jwt-Assertion`,
   Pomerium `X-Pomerium-Jwt-Assertion`, Cloudflare `Cf-Access-Jwt-Assertion`).
   No shared password exists. The cost is that every app must be configured as a
   relying party.
2. **Remote browser isolation.** A browser runs server-side and only pixels reach
   the operator. Examples: KeeperPAM RBI (Chromium in the gateway), CyberArk
   PSM-HTML5 (Selenium-driven browser on the PSM host). The credential never
   leaves the server.
3. **Credential-injecting reverse proxy.** Basic auth or an `Authorization`
   header is injected at the last hop (StrongDM Websites). It never reaches the
   client, but it only works for apps that accept header auth.
4. **Controlled local browser with recipe injection.** BeyondTrust Web Jump,
   CyberArk Secure Browser, and the KeeperPAM fill-rule format. The credential
   reaches the endpoint's DOM.
5. **Browser-extension autofill.** CyberArk SWS, Delinea DCM, PAM360. The
   exposure is the same as (4), plus the extension's own attack surface. The
   2025 DOM-based extension-clickjacking research found 10 of 11 password
   managers exploitable.

What we adopt:

- **Pattern 4 as the baseline.** It is the only pattern that works for an
  arbitrary form-login app without server-side infrastructure. It maps directly
  onto Tauri: the `WebviewWindow` is the controlled browser and the Rust host is
  the injector.
- **Recipe shape from KeeperPAM and CyberArk `WebFormFields`.** Ordered steps
  keyed by a URL pattern, each a `fill(selector, username | password | totp)`,
  `click`, or `wait`, plus explicit `success_when` and `failure_when`
  conditions. Multi-page logins (username page, then password page, then TOTP
  page) are one step group per page. BeyondTrust handles CAPTCHA by letting the
  operator solve it while the recipe waits; we do the same.
- **The autofill-safety rules from Silver et al.** ("Password Managers: Attacks
  and Defenses", USENIX Security 2014) **and the 2025 clickjacking work.**
  - Fill only in the top frame.
  - Fill only on an exact origin match over HTTPS.
  - Fill only visible, non-occluded fields of the expected type.
  - Never draw fill UI inside the page.
- **Patterns 3 and 1 as phases.** `http-auth` is the cheap form of pattern 3.
  The proxy mode is the general form. `sso` is pattern 1, and it depends on the
  Identity Provider feature.
- **Pattern 2 (server-side RBI) is a future phase, delivered through Rustion.**
  It is the right answer for the highest-assurance apps. Building a browser
  fleet and a pixel-streaming stack inside BastionVault is not. Rustion already
  has the three hard parts: it receives credentials from the vault in a sealed
  envelope, terminates and records RDP, and has a replay path BastionVault can
  already play. Phase 8 (§12) adds browser workers behind Rustion and reuses all
  three.
- **Not adopted: a browser extension.** It would move the injector out of the
  process we control and into the operator's everyday browser profile, alongside
  every other extension and tab.

Primary sources: CyberArk docs (Secure Web Sessions; PSM for web applications),
BeyondTrust PRA "Web Jump credential injection", KeeperPAM "RBI → browser
autofill", StrongDM "Websites", Teleport "App Access JWT", Pomerium "Headers"
reference, HashiCorp Boundary credential injection (SSH/RDP only; HTTPS targets
are a plain tunnel), Tauri v2 `WebviewWindowBuilder` / wry `WebViewBuilder`
docs, Tauri 2.4 and tauri-runtime 2.8 release notes (cookie APIs), Tauri
security / capability docs, Microsoft WebView2 "Basic authentication" docs, W3C
"A Well-Known URL for Changing Passwords".

## Current State

**Status: In progress — Phases 1 and 2 done, with caveats (below). Phase 2
shipped the server, desktop-host and GUI-editor halves (the host recipe engine,
fixed fill routine and `web_recipe_test`; the profile editor with recipe editor,
import / export, test button and vendor presets, **whose presets are unverified
against live appliances**); its per-platform manual checks are carried forward
as caveats. Phases 3–7 Todo, Phase 8 future.**

### What the Phase 2 server half shipped

`resources/v2/connect/web/{launch,totp,result,close}` in
[crates/bv-engine-resource/src/connect_web/](../crates/bv-engine-resource/src/connect_web/)
(handlers in `mod.rs`; `recipe.rs`, `exposure.rs`, `profile.rs`, `totp.rs`,
`launch_store.rs`). The request/response contract the host builds on is in
[docs/api.md](../docs/api.md) → *Web Connect (`form` mode)*. The desktop
host calls it (see *What the Phase 2 host half shipped*).

- **`launch`** runs the `connect/authorize` front half (the `connect` grant
  through `may_connect_target`, then the stored record), then every static
  check — protocol `web`, `login_mode: form`, transport `local`, a strictly
  parsed v1 recipe whose URLs sit on the profile's origin set, a credential
  source that can supply what the recipe fills — then the host's
  `recipe_hash`, then the §6 policy, then the Rustion transport tier, then
  the credential pre-checks, and only then burns the MFA ticket (the redeem
  step is shared with `connect/authorize`). It releases the credential,
  persists the launch and returns the bundle.
  - *Pre-checks before the ticket:* a `secret` source is read and checked
    (exists, carries what the recipe fills, a decodable `totp_seed` when the
    recipe fills `totp`); a `default-account` is resolved; an `ldap`
    source's mount must exist, be untainted and be an LDAP engine. Nothing
    is released before the ticket.
  - *What still spends the ticket:* the LDAP static-credential read or
    library check-out (it rotates a password, so it cannot run first), and
    persisting the launch. An incomplete check-out (an account but no
    password or lease) is checked straight back in.
- **Rustion transport tier, enforced server-side.** The host's
  `web_transport_refusal` is now also the server's rule: `rustion-required`
  or a policy lock violation refuses with `transport_policy`, before the
  ticket and before any credential read; `direct` and `rustion-preferred`
  are allowed. A patched host can no longer obtain a form credential on a
  resource the policy reserves for Rustion.
  - *Reused:* Rustion's own resolver, `rustion/policy/effective` (the
    endpoint the host reads; the same four-tier `policy::resolve` that
    `rustion/v2/session/open` applies). It is dispatched through the router
    under server authority, as `session/open` reads its store, so the
    caller's grant on the resolver endpoint cannot decide whether a
    restriction on them applies. The caller's `auth` and namespace ride
    along for the resolver's own resource gate. Asset-group hints come from
    the kernel `ResourceGroupIndex`, with errors propagated rather than
    read as "no groups".
  - *Mount unavailable / errors:* Rustion's `PolicyStore` keeps every tier
    in the **system view** under `rustion/policy/` (`global`, `type/`,
    `asset-group/`, `resource/`), not in the mount, and those records
    survive an unmount; the router also reports a mount tainted mid-unmount
    or mid-remount as not found. So `ErrRouterMountNotFound` is allowed only
    when listing that prefix proves no record exists at all. Records
    present, a sealed vault or a list error refuse with
    `transport_policy_unavailable`, as does any other failure (store not
    initialised, an undecodable tier record, an index error, an unknown
    verdict). The resource engine names Rustion's storage prefix only for
    this proof of absence.
- **Credential delivery.** Plaintext fields in the `launch` response body,
  as §3 draws it, minimised to what the recipe fills (`username`,
  `password`, the current `totp` + `totp_valid_until`). The seed never
  leaves; a `default-account`'s stored Windows password is never released.
- **Fill scope.** The bundle's `fill_scope` (`start_url`, the normalised
  origin set with the start origin first, `allow_insecure_http`) is the
  scope the server checked, and it is recorded on the launch. `recipe_hash`
  covers only `web.recipe`, and in heuristic mode the origin set is the only
  constraint on where a fill happens, so the host must start at
  `fill_scope.start_url` and fill only on `fill_scope.origins` — never on its
  own copy of the profile.
  - *Decision:* no extra envelope. The host is the TLS endpoint that would
    unwrap it, so sealing to a host key would add a new construction without
    protecting against anything the host can't already see; the audit
    pipeline already records response values HMAC-redacted.
- **Whose authority.** `secret` is read under the server's authority — the
  `connect` grant on the resource authorises it, as on
  `rustion/v2/session/open`, which is what makes connect-only real for web.
  `ldap` (`static_role`, `library_set`) and `default-account` go through the
  full request pipeline **as the caller**.
  - *Decision:* a stored profile can name any LDAP library or role in the
    namespace, and anyone who may edit the resource may edit its profiles,
    so resolving those under server authority would let a resource editor
    check out any library account. As-caller resolution keeps today's
    direct-path grants authoritative. The alternative, server authority plus
    a policy probe on the LDAP path, needs a `PolicyGate` question that does
    not exist (a `bv-kernel-api` change).
  - `ldap` `bind_mode: operator` and source `none` are refused for `form`.
- **TOTP.** From `totp_seed` (base32) in the `secret` source's secret, with
  `credential_source.totp = {algorithm, digits, period}` (default
  SHA1/6/30) and `credential_source.fields` to rename the keys. RFC 6238
  built from the same `hmac`/`sha1`/`sha2`/`base32` crates as
  `bv-engine-totp` and checked against the RFC vectors; an engine may not
  depend on another engine, hence the second copy.
  - *Decision:* not a TOTP-engine key reference. Read under server
    authority, that would let a profile author pull codes for any
    generate-mode key in the namespace; the seed in the resource's own
    secret stays inside the trust boundary the `connect` grant covers.
  - `totp` gives one refresh per recipe step that fills `totp` (heuristic
    mode: step `0`), inside the 60 s login window, and re-checks the
    `connect` grant.
- **`launch_id`.** 32 random bytes, base64url. Stored at the barrier root
  as `connect/web-launches/<hex sha256>`, as a versioned record with no
  credential in it: written as `v: 2` (which adds `fill_scope`), `v: 1`
  still read. Bound to (principal, namespace, resource, profile, recipe
  hash, fill scope). The principal is the first of: `username` on a known
  auth mount (the MFA ticket's binding); `entity:<entity_id>`;
  `token:<sha256 of the client token>` — this token store has no accessor,
  so a root token, which has no entity, binds to itself; `name:<display
  name>` on a known auth mount. A display name with no mount never binds.
  The login window is 60 s; `result` (once; a repeat is idempotent, a
  different outcome conflicts) and `close` (idempotent) work until close.
  Closed records are reaped after 15 min and never-closed ones after 24 h,
  by a pass `launch` runs at most once a minute per process, after the
  launch is persisted. A record of an unknown version is refused and never
  reaped.
- **Concurrency is per process.** Concurrent calls on one launch are
  refused (`launch_busy`), never raced — within one server process. On a
  multi-node deployment where more than one node serves requests against
  shared storage, two nodes could both refresh a TOTP step, or both attempt
  the LDAP check-in (the LDAP engine's own per-set lock and record delete
  make the second fail). Storage has no compare-and-swap to close this;
  standby nodes forwarding to the active node keep it to one process today.
- **`close`** records the end first, then checks an LDAP library account
  back in by `account` name. A failed check-in returns
  `ldap_checkin_failed` and stays pending, and the next `close` retries
  it.
- **§6 policy — deny unless opted in.** `web_exposure_max` /
  `allow_heuristic_fill` on `config/types[<type>].connect` and on the
  resource record (top-level keys). The effective cap starts at the type
  tier's cap, and at `none` when the resource's `type` is not in the saved
  `config/types`, the type sets no cap, or the configuration was never
  saved: form mode is then refused with `exposure_not_permitted`. The
  resource tier can only lower the type's cap. Because `type` is editable
  resource metadata, an unknown type is a denial, not an escape from the
  type tier, and the same resolved type is the one the Rustion type tier
  sees. An unreadable `config/types` refuses (`exposure_policy_invalid`),
  as does a value outside the enum. An explicit `false` for heuristics at
  either tier beats `true` at the other, and unset at both means no
  heuristics. `allow_insecure_http` is refused below `dom`.
  - The GUI's built-in `web_application` and `website` types carry
    `connect.web_exposure_max: "dom"`, so a type configuration saved by a
    current GUI opts them in. A saved type still wins as saved
    (`mergeTypeConfig`), so **a deployment that saved a `web_application`
    or `website` type before this change is denied until an administrator
    sets the cap on it.**
- **Recipe format (§2), frozen as v1.**
  - Strict: unknown version, key or verb refused.
  - Actions: `fill` / `click` / `submit` / `wait`; `value` is
    `username | password | totp | literal:<text>`.
  - At most 16 steps × 32 actions; `timeout_secs` 1–60, default 30.
  - `success_when` is required; `failure_when` is optional.
  - `pause_for_operator` takes `captcha` and `push_mfa`.
  - `vendor` is from the `web_application.vendor` enum and only says where
    the steps came from.
  - Origins are read more strictly than the host's WHATWG parser: no
    punycode-less Unicode hosts, no percent-encoding, no trailing dot.
    That can only add refusals.
  - `recipe_hash` = `sha256:` + hex of the RFC 8785 canonical form of the
    stored value. The module is `pub`, so the host can reuse the parser and
    the hash.
- **Audit** (`target: "audit"`): `connect.web.launch` (with `transport` and
  `fill_origins`), `.totp`, `.result`, `.close`, `.refused` (`op`, `reason`
  code), `.reaped` and `.launch_rollback`. They carry names, enum values,
  origins and the launch-id hash — never a value, code, raw id, full token
  hash, or URL path or query.
- **Zeroization.** Secret maps are scrubbed through nested objects and
  arrays; the HMAC output is copied into a `Zeroizing` buffer and the
  original scrubbed; a seed-length error does not reveal the decoded length.
- **Tests.** In-crate: recipe, exposure, profile, TOTP, launch-store state
  machine, audit-line shape. `src/engine_tests/resource_connect_web.rs`:
  end to end against a vault, covering connect-only release, every refusal
  class, MFA ticket burn, principal binding, the login window, a failed
  LDAP check-in on close, the Rustion transport tier (`rustion-required`
  refused with the ticket unspent, a lock violation refused,
  `rustion-preferred` / `direct` allowed, an undecodable tier record
  refused, a stored policy refused while `rustion/` is tainted or
  unmounted, no mount *and* no record allowed), the deny-by-default exposure
  matrix (unsaved configuration, unknown type, a `server` type, an unset
  cap, the resource tier alone, a type below `dom`, type `dom` with the
  resource at `none`, an unreadable configuration — each with the ticket
  unspent — and type `dom` allowed), the credential pre-checks (missing
  secret, missing seed, no LDAP mount, a non-LDAP mount, no default account
  — each with the ticket unspent), and the fill scope in bundle and record.

### What the Phase 2 GUI editor shipped

In [gui/src/](../gui/src/) — no server or host change. The recipe format, the
exposure rule and the dry run are the ones above; the GUI only edits, checks
and shows them.

- **Profile editor.** The **Form** login mode saves
  ([connectionProfiles.ts](../gui/src/lib/connectionProfiles.ts)
  `validateWebProfile`; it used to refuse every form profile). The credential
  source for form is the set the server releases from: `secret` (with
  `credential_source.fields` for key names and `credential_source.totp` for
  algorithm / digits / period), `ldap` `static_role` / `library_set`
  (operator bind is not offered), and `default-account` (username only).
  Switching the login mode moves the source and the recipe with it
  (`setWebLoginMode`). The Connection tab's profile list shows the source and a
  recipe summary.
- **Recipe editor** ([WebRecipeEditor.tsx](../gui/src/components/WebRecipeEditor.tsx)).
  Structured step / action list (fill username / password / TOTP / fixed text,
  click, submit, wait; reorder and remove), success and failure conditions,
  timeout, CAPTCHA / push-MFA pauses, vendor label, explicit or heuristic
  mode, and a raw JSON view. Unparseable text in the JSON view holds Save; the
  profile keeps the last valid recipe meanwhile.
- **Validation mirrors the server.**
  [webRecipe.ts](../gui/src/lib/webRecipe.ts) is a line-by-line port of
  `WebLoginRecipe::parse`, `check_origins`, `origin_key` and `split_url`
  (recipe.rs), in the same check order and with the server's `at` locations
  and wording; [webFormProfile.ts](../gui/src/lib/webFormProfile.ts) ports the
  rest of `parse_launch_profile` (profile.rs): origins read by the server's
  stricter `origin_key` rather than the browser's URL parser, the credential
  source's fields, and whether the source can supply what the recipe fills
  (`credential_unavailable`, `totp_not_configured`). The Rust test cases are
  ported to `src/test/webRecipe.test.ts`. **Not mirrored:** the
  integer-versus-float distinction of JSON numbers (`30.0`; a JS number can't
  tell, and the GUI sends `JSON.stringify` output, which prints integers
  plainly); `recipe_hash` (the dry run reports the host's); the launch-time
  checks that need the vault (the secret exists and carries a decodable TOTP
  seed, the LDAP mount exists, the default account is set). Keep the constants
  and the check order in step with recipe.rs when it changes.
- **Exposure notice.** [webExposure.ts](../gui/src/lib/webExposure.ts) ports
  `exposure.rs`: deny unless the *saved* `config/types` entry for the
  resource's `type` sets `connect.web_exposure_max` (`dom` for form), the
  resource tier can only lower it, heuristics need a tier to enable them and
  none to forbid them, insecure http is refused below `dom`, an unreadable
  value is a refusal. The editor reads the raw `resource_types_read` payload,
  not the merged config — the GUI shows `web_application` as opted in even when
  the server has nothing saved — and links to Settings → Resource Types; if the
  payload can't be read it says it can't tell. A hint only: the server enforces.
- **Settings → Resource Types.** Types that offer `web` get a **Web exposure
  cap** (unset / none / isolated / handler / proxy / dom) and **Allow heuristic
  fill** (unset / allowed / forbidden), written to `connect.web_exposure_max`
  and `connect.allow_heuristic_fill`. Unset removes the key; a saved value the
  build doesn't recognise is kept as saved.
- **Test recipe** calls `web_recipe_test` with the start URL, the allowed
  origins and the recipe, and renders the per-step, per-action status and match
  count, the success / failure flags and the recipe hash. The UI says it sends
  no credential and submits nothing; the request carries no credential field.
- **Import / export.** Copy to the clipboard, download as `.json`, import from a
  file, the clipboard or the JSON view. Imports go through `JSON.parse` and the
  strict reader only (256 KiB cap; unknown keys including `__proto__` refused);
  nothing is evaluated. The download uses a Blob link and is **not verified in
  the Tauri webview on each platform**; the clipboard route is the fallback the
  UI names.
- **Vendor presets** ([webRecipePresets.ts](../gui/src/lib/webRecipePresets.ts)):
  FortiGate, vCenter, iDRAC, iLO, pfSense, Grafana, Jenkins, each a function of
  the profile's origin. **Every preset is unverified against a live
  appliance.** They were written from each vendor's documented or widely known
  login form without recording a real login page, and `unverified: true` is a
  literal type, shown in the picker label, beside the note and in a banner
  after one is applied. Success and failure conditions are the least certain
  part (iLO, pfSense and Grafana sign in to a page on the same URL, so they
  judge success by an element). The tests hold each preset to the validator and
  the origin check, not to a real device. The spec's "tested against recorded
  login pages" is **not** done and stays a follow-up.
- **Session outcome in the main window.** The host emits
  `web-session-outcome` to the main window only, and the vault UI shows it as
  a toast ([webSessionOutcome.ts](../gui/src/lib/webSessionOutcome.ts),
  wired in `Layout.tsx`; see *What the Phase 2 host half shipped*).
- **Tests.** `src/test/webRecipe.test.ts` (validator, origin keys, presets,
  import, form-profile save checks, exposure matrix) and
  `src/test/webRecipeEditor.test.tsx` (exposure notice, presets, structured and
  JSON editing, import / export, dry run, Settings controls).

### What the Phase 2 host half shipped

In [gui/src-tauri/src/commands/connect_web.rs](../gui/src-tauri/src/commands/connect_web.rs)
and the Tauri-free modules under [gui/src-tauri/src/session/](../gui/src-tauri/src/session/):
`web_recipe.rs` (plan, globs, outcomes, TOTP decision, bundle, fill scope,
heuristics), `web_script.rs` + `web_fill_routine.js` (the fixed routine and
its argument encoding), `web_engine.rs` (the engine, generic over the page so
it is unit-tested with a fake), `web_launch.rs` (the four server calls and the
call-state machine).

- **`session_open_web`, form mode.** Parses the profile with the server's own
  `WebLoginRecipe::parse` and `recipe_hash`
  (`bastion_vault::modules::resource::connect_web::recipe`, reachable through
  the facade); `form` needs a `secret` / `ldap` / `default-account` source and
  a recipe. Order: early web/RDP check → **reserve the registry slot** (the
  authoritative web/RDP decision, taken before any credential is released) →
  `v2/connect/web/launch` instead of `connect/authorize` → bundle checks →
  window → engine. The bundle is parsed strictly (unknown `credential` /
  `fill_scope` keys refused), the credential moved into `Zeroizing` buffers,
  and cross-checked: resource, profile, `login_mode: form`, `exposure: dom`,
  `recipe_hash`, `heuristic` equal to the local recipe's mode, and the parts
  the recipe fills present. Any mismatch after the launch exists reports
  `aborted:<check>` and closes it before the error returns.
  - *Fill scope:* the window starts at `fill_scope.start_url` and its
    navigation allow-list **is** `fill_scope.origins`. The server may narrow
    the local copy (dropped origins are logged as
    `connect.web.fill_scope_narrowed`); an origin the local copy lacks, or
    `allow_insecure_http` it does not set, refuses the launch
    (`aborted:fill_scope`).
  - *Transport:* the host no longer calls `rustion/policy/effective` for a
    form launch — `launch` enforces the tier before the ticket and the
    credential, so the host/server disagreement noted below is closed. `open`
    mode still checks on the host.
- **How results travel without IPC.** The engine evaluates
  `(<fixed routine>)(<JSON args>)` through `WebviewWindow::eval_with_callback`
  (WKWebView `evaluateJavaScript`, WebView2 `ExecuteScript`, WebKitGTK
  `run_javascript`). The only thing that returns is the script's own return
  value — a JSON string, parsed strictly (`deny_unknown_fields`, version,
  status enum), and refused unparsed when either JSON layer exceeds
  `MAX_REPLY_BYTES` (4 KiB; the largest reply the routine can produce is
  under 700 bytes), so a page that patches `JSON.stringify` cannot hand the
  host a huge string to parse — delivered to a host closure. The page gets no channel and
  nothing it can call; no `tauri::ipc::Channel` is used, so the web/RDP
  exclusion predicate is unchanged. A reply can only make the engine refuse
  or take its next host-decided step; it never widens where a value goes.
- **The fixed routine.** Compiled into the binary (`include_str!`); no recipe
  or page text ever becomes script. Arguments are serialised by `serde_json`
  with `<`, `>`, `&`, U+2028, U+2029 additionally escaped, into a pre-sized
  zeroizing buffer. In the top document only (`window.top === window`, and
  `location.origin` must equal the origin the host checked): exactly one
  match; an `<input>` of the expected type (password only into
  `type=password`); enabled; visible (box ≥ 4×4 px, `visibility: visible`,
  cumulative opacity ≥ 0.5, in the viewport after one `scrollIntoView`); not
  covered at its centre (`elementFromPoint`, a `<label>` for the field
  allowed); its form's `action`, the `formaction` of every control that can
  submit it — the listed elements, every `<input type=image>` attached to it
  (which `form.elements` leaves out) and the clicked or submitted element
  itself — on an allowed origin, and the form's `target`, every
  `formtarget` and a document `<base target>` a keyword (`_self`, `_top`,
  `_parent`, `_blank`), never a frame name (`aborted:form_target`: a named
  target may be an `<iframe>`, and sub-frame navigations are not policed on
  Windows and Linux). All read through prototype accessors, so DOM clobbering
  cannot hide them. It fills through the native `HTMLInputElement` value setter and
  fires `input` / `change`; `submit` uses `requestSubmit`. After the outcome
  it clears every password field. It never returns a value.
- **The engine.** A step runs only on a finished top-frame load
  (`on_page_load`) whose URL matches its `when_url` (origin exact, `*` glob
  after it), on an origin of the fill scope; steps run in order, each at most
  once (a later step may be reached without an optional earlier one). Every
  action re-checks the host-observed origin; a navigation to another origin
  mid-step aborts (`aborted:navigated`). A failed safety check aborts at once;
  a check the page can still pass (`no_match`, `not_visible`, `occluded`,
  `disabled`, navigation in flight) is retried **unchanged** until
  `timeout_secs`, then reported as `aborted:<that check>`. A click or submit
  whose evaluation returned nothing is never repeated. Outcomes are judged
  only after a step ran, failure before success; then `web/result` once
  (`result.step` = last step started), the title shows it, password fields
  are cleared, and the credential is dropped with the engine.
  - *TOTP:* a `totp` fill after `totp_valid_until` (host clock) calls
    `web/totp` for that step when it is still in `totp_refresh_steps`, and
    only after a check-mode call shows the field passes every check, so a
    field that fails them never spends the step's one refresh; otherwise
    `aborted:totp_expired` and nothing is filled.
  - *Outcome event:* the host also sends the main window
    `web-session-outcome` `{token, resource, profile_id, outcome, step}`
    (`emit_to` the `main` webview window; no credential, code or URL), which
    the vault UI shows as a toast. Tauri delivers events by evaluating them
    in webviews that registered a listener, and a `web-*` window cannot
    register one (no capability). It is not a `tauri::ipc::Channel`, so the
    web/RDP exclusion predicate is unchanged.
  - *Heuristic mode:* only when the bundle says `heuristic: true` and the
    recipe is `"steps": "auto"`. One pass: `autocomplete=username`,
    `current-password` (else `type=password`), `one-time-code`, filling only
    what the source released; more than one candidate aborts
    (`ambiguous_match`); submits the last filled field's form.
- **Teardown.** `web/close` on every path — window closed, `session_close`,
  window build failure, the SSH/RDP drop paths, app exit (`RunEvent::Exit`,
  3 s budget, including teardowns the closing windows started) — through
  one idempotent state machine (`LaunchCalls`): a teardown before an outcome
  reports `aborted:window_closed|session_closed|window_build|app_exit|
  session_dropped|policy_violation` first; an undelivered `result` is resent
  unchanged once. `ldap_checkin_failed` is retried once, then logged as a
  warning. All four calls use the backend, token and namespace captured at
  launch.
- **`web_recipe_test`** (dry run). Opens a full web session window (IPC-less,
  ephemeral, origin allow-list, counts for the web/RDP exclusion) on the URL;
  the recipe's URLs must sit on its origin set. For every page a step names it
  runs every check of the routine in **check mode** — no value, no click, no
  submit — and probes the outcome selectors, then reports per step and action
  the routine's status and match count (no selectors or values echoed).
  - *Decision:* checks only, no placeholder credential (the spec said "a
    dummy credential"). A placeholder fill would send a real login attempt
    to the target — lockouts, IDS alarms — while verifying nothing the
    check-mode routine does not already verify. `run_check` has no credential
    parameter, and the command never reads the vault, asks for MFA or calls
    `launch`. Later pages are checked when the operator signs in by hand.
- **Host audit** (`target: "audit"`): `session.open: protocol=web
  login_mode=form` (fill origins, `launch_id_hash`), `connect.web.fill` /
  `connect.web.action` (step, action index, value kind, origin),
  `connect.web.totp_refresh`, `connect.web.login`, `connect.web.result`,
  `connect.web.close` (`ldap_checkin`), `*_failed` (refusal code only),
  `connect.web.fill_scope_narrowed`, `connect.web.recipe_test`,
  `connect.web.refused`. Never a value, TOTP code, raw `launch_id`, vault
  token, selector match, path or query.
- **Tests.** Rust (`cargo nextest run -p bastion-vault-gui --lib`): glob and
  step selection, plan building, outcome mapping, check names, TOTP refresh
  selection, strict bundle parsing and cross-checks, fill-scope narrowing vs
  widening, heuristics, script escaping of hostile values and selectors, reply
  parsing, the call-state machine on every teardown path, and the engine
  against a fake page (order, origin gating, mid-step navigation, permanent vs
  transient checks, refresh, no-result clicks, cancellation, heuristics, the
  dry run carrying no value). Vitest (`src/test/webFillRoutine.test.ts`): the
  real routine in jsdom — native setter, check mode, origin, match count,
  type, opacity / size / off-screen decoys, overlay vs own label, off-origin
  `action` / `formaction` under DOM clobbering, image-submit `formaction`,
  named-frame `target` / `formtarget` / `<base target>`, submit, probe, scan,
  clear. `src/test/webSessionOutcome.test.ts`: the outcome event payload.

**Host deviations from §5, decided here:**

- `when_url` and `success_when.url` see only URLs of finished top-frame loads,
  as §2 says — not same-document (`pushState`) route changes. A single-page
  app's multi-screen login is one step with `wait` actions, and its success
  condition a selector.
- A field outside any `<form>` is fillable (no form, no action to check);
  the navigation allow-list still blocks a native post off-origin.
- Transient checks are retried until the timeout instead of aborting at the
  first failure; the check itself never changes.
- `pause_for_operator` only changes the waiting text in the title; every
  recipe waits up to `timeout_secs` either way.

**Phase 2 caveats — carried forward.** Phase 2 is marked done with these
open; none of them is a missing feature, and each is a check or hardening step
that must still happen before the first release that ships `form` mode:

- The vendor presets are unverified against live appliances and the spec's
  "tested against recorded login pages" is not done (see *What the Phase 2 GUI
  editor shipped*).
- Per-platform manual checks (macOS, Windows, Linux) against the fixture site
  of the Testing Plan, including `eval_with_callback` returning on each
  webview and the `invoke`-rejected check of Phase 1.
- The routine runs in the page's main world, so a compromised allowed origin
  can patch DOM prototypes and make it misreport (it can read the filled
  password anyway — §5 *Exposure*). Evaluating in an isolated world
  (`WKContentWorld`, a CDP isolated world on WebView2) is a follow-up.
- An end-to-end LDAP library check-out test, which needs an LDAP fixture.
- `make test-release` (L4), which §Security Considerations requires before
  merging, since this touches authz.

### What Phase 1 shipped

- **Type and protocol.** `ResourceTypeDef.connect.protocols` and
  `web_exposure_max` are typed ([gui/src/lib/types.ts](../gui/src/lib/types.ts)).
  The builtin `web_application` type exists and `website` offers `web`
  ([gui/src/lib/resourceTypes.ts](../gui/src/lib/resourceTypes.ts)).
  `connectProtocols()` / `typeSupportsProtocol()` / `typeSupportsConnect()`
  are the single gate for the Connect chip, the card context menu, the
  Connection tab, the ⌘K palette, the profile editor's protocol list and the
  connect-validation static verdict. Settings → Resource Types has SSH / RDP /
  Web checkboxes.
  - **Decision: absent `protocols` means `["ssh","rdp"]` for the `server`
    type only, and `[]` for every other type** — not `["ssh","rdp"]` for
    every type as §1 first said. The chip used to be hard-gated to
    `type === "server"`, so this is what keeps today's behaviour exact:
    `firewall` / `switch` carry `connect.enabled: true` but never had a
    Connect chip, and saved configs of `database` etc. have no `connect` key
    at all. Reading absence as SSH/RDP everywhere would have put a Connect
    chip on all of them.
- **Saved-config merge with tombstones** (`parseTypeConfig` /
  `serializeTypeConfig`). Saved types win per type id; builtins absent from
  the saved config are added unless tombstoned. A saved type is never
  altered, so a deployment that saved `website` before this release keeps a
  `website` without `web` until an operator ticks it in Settings.
  - **Where the tombstone lives.** Older GUIs read `config/types` as
    `Record<string, ResourceTypeDef>` and iterate every value (`.id`,
    `.label`, `.color`, `.fields.length`), so a top-level array would crash
    them. The tombstone is a reserved entry `"$bv_meta"` shaped like a type
    (`fields: []`, `connect.enabled: false`, label "(internal) removed
    built-in types") with `removed_builtins: string[]`. `$` can't come out
    of Settings' id sanitiser, the entry is written last (never an older
    GUI's default pick in the create-resource modal) and only when at least
    one builtin is deleted. An older GUI shows it as one extra type and
    round-trips it untouched through its own saves; deleting it there
    loses the tombstones, after which deleted builtins reappear once.
  - **Pre-tombstone saves.** A config with no `$bv_meta` entry was written
    by a GUI whose saves always contained every builtin it offered. So a
    builtin from the frozen pre-T96 list (`PRE_TOMBSTONE_BUILTIN_IDS`) that
    such a config lacks was deleted by the operator, and is treated as
    tombstoned rather than re-added. Builtins added from T96 on are added.
- **`web` connection profiles, `open` mode only.** `SessionProtocol` is
  `"ssh" | "rdp" | "web"`; profiles carry the `web` block of §1.
  `CredentialSource` gains `{ kind: "none" }`, the only source `open` mode
  accepts (it releases nothing); `none` is refused on SSH/RDP, and
  `ssh-engine` / `pki` / `fido2` are refused on `web`. Form / http-auth /
  sso, `transport: "rustion-isolated"`, a non-empty `tls_pin_sha256`, a
  recipe and a profile `kind: "rustion"` are all refused with "not available
  yet" at save (GUI) and at connect (host) — never ignored. Origins follow
  the rules of §4: exact `scheme://host[:port]`, default ports normalised,
  lower-case / punycode host, no path, query, fragment or userinfo, no
  trailing dot, https unless `allow_insecure_http`. **Additionally refused:
  `localhost` and `*.localhost`**, because Tauri classes those as *local*
  origins (the dev server, `tauri.localhost`, `ipc.localhost`) and grants
  them IPC.
- **Strict protocol parsing.** `parseSessionProtocol` (TS) and
  `ProfileProtocol::of_profile` (host) refuse unknown, missing and
  mistyped protocols; `readProfiles` drops such profiles; every launcher
  dispatches through `openProfileSession`, which throws on an unknown
  protocol (the launchers used to open anything that wasn't SSH as RDP); and
  `session_open_ssh` / `session_open_rdp` / `session_open_web` each refuse a
  profile of another protocol before resolving anything. Pinned by
  `src/test/webConnect.test.ts` and `session::profile_protocol_tests`.
  - **Older releases, verified at v0.44.17 and v0.44.18:** their
    `readProfiles` keeps only `ssh` / `rdp` and their `isLaunchableProfile`
    refuses any other protocol on the card hints, so they never dial a `web`
    profile. Their host does not check the protocol, but no code path in
    those GUIs sends a `web` profile id. One caveat: saving profile edits
    from those releases on a resource that carries a `web` profile writes
    back only the profiles they parsed, which removes the `web` one. (Their
    Connection tab only exists on `server` resources.)
- **No server change.** `v2/connect/authorize`, the MFA ticket and the
  search-card `ConnectProfileHint` projection are protocol-agnostic: the
  projection passes `protocol: "web"` and `credential_source.kind: "none"`
  through as strings, and `authorize` reads only the profile's id and
  `require_mfa`.
- **`session_open_web`** ([gui/src-tauri/src/commands/connect_web.rs](../gui/src-tauri/src/commands/connect_web.rs),
  [gui/src-tauri/src/session/web.rs](../gui/src-tauri/src/session/web.rs)).
  Loads the resource and profile, requires `protocol == web`, validates the
  profile, refuses when the effective Rustion transport is
  `rustion-required` or the resolver reports a lock violation (no local
  fallback), then runs `authorize_direct` (MFA ticket burnt exactly as on
  the direct SSH path). The window: label `web-<token>`,
  `WebviewUrl::External`, `incognito(true)`, `devtools(false)`,
  `disable_drag_drop_handler()`, a per-session `data_directory` under
  `<app cache>/web-sessions/<instance>/<token>` (0700) on Windows and Linux, size from
  the profile, title `"<resource> — <origin>"` set by the host from
  `on_page_load`. Registered as `SessionState::Web` in `connect_sessions`;
  `session_close` and window destruction both tear it down (destroy the
  window, `session.close: protocol=web … duration_ms=…`, remove the data
  directory with retries). `<instance>` is one directory per running
  process holding a `.lock` file kept exclusively locked for the process
  lifetime; the sweep on each web-session open removes only *other*
  instance directories whose lock it can take (owner dead), so a second
  running copy never loses its live sessions. Host audit lines (`target: "audit"`): `session.open:
  protocol=web …` (origins only), `connect.web.navigation_blocked`,
  `connect.web.popup_blocked`, `connect.web.download` /
  `connect.web.download_blocked` (`reason=disabled|origin`: an allowed
  download must also come from an origin in the set),
  `connect.web.policy_violation`, `connect.web.refused`.
  `record_recent_session` records `protocol: "web"`.
- **Capability isolation test** (`capability_isolation_tests`, runs under
  `cargo nextest run -p bastion-vault-gui --lib`): walks every file under
  `gui/src-tauri/capabilities/`, plus any inline capability in
  `tauri.conf.json`, and fails if a `windows` / `webviews` glob matches a
  `web-<token>` label, if any capability declares `remote`, if a glob uses
  syntax the test can't evaluate, or if a non-JSON capability file appears.

### Phase 1 caveats — where it differs from §4

- **Pop-ups.** `on_new_window` never returns `Allow` (that hands the popup
  to the platform's default window, outside this window's handlers and
  store). An in-set popup is loaded **in the session window itself**
  (`navigate`), not in a child window sharing the store as §4 says; anything
  else is denied. `Create { window }` needs per-platform shared webview
  configuration (`with_related_view` / `with_environment` /
  `webview_configuration`) that 2.11.5 doesn't expose on the stable API.
  Pages that depend on `window.opener` (some OAuth popups) won't complete;
  add the IdP to `allowed_origins` and let it redirect instead.
- **Downloads.** When allowed, files go to the webview's default
  destination (the OS downloads folder), not through the save dialog —
  a blocking dialog can't run inside the webview's download callback. Each
  download is audited by file name on request and by size on completion
  (size `unknown` on macOS, where wry reports no path).
- **Clipboard.** Only `bidirectional` calls `enable_clipboard_access`;
  WebView2 and WebKitGTK can grant or refuse page clipboard access only as a
  whole, so `host-to-session` / `session-to-host` behave as `off`. Absent
  means `off`. The operator's own keyboard copy/paste is native and never
  blocked. On macOS the page clipboard can't be gated (the editor says so).
- **macOS data store.** No `data_store_identifier` and no `data_directory`:
  with `incognito(true)` wry gives each window a fresh
  `WKWebsiteDataStore.nonPersistentDataStore()`, which it prefers over an
  identifier, and WKWebView ignores `data_directory`.
- **Sub-frames.** wry consults the navigation handler for every frame on
  macOS but for top-level navigations only on Windows (WebView2
  `NavigationStarting`). On macOS a cross-origin iframe therefore needs its
  origin in the set; elsewhere iframes are not policed (nothing is filled
  in Phase 1). `about:blank`, `about:srcdoc` and `blob:` URLs of an allowed
  origin are allowed; `data:`, `file:`, `mailto:` and custom schemes are
  blocked. As a safety net, a top-frame page load the host sees for an
  origin outside the set closes the session (`connect.web.policy_violation`).
- **Tauri's IPC scripts still reach the page — mitigated by web/RDP mutual
  exclusion.** Tauri 2.11.5 injects its IPC initialisation script (including
  the invoke key) into every webview, remote ones included, and there is no
  stable API to withhold it. App and plugin commands from a remote origin are
  rejected by the ACL (`Webview::on_message`: remote origin and no matching
  capability ⇒ reject; Tauri's own test
  `remote_origin_blocked_for_custom_commands_without_app_manifest`). **One
  command is exempt upstream:** `plugin:__TAURI_CHANNEL__|fetch` ("TODO:
  Remove this special check in v3"), which returns — and removes — a queued
  IPC channel payload by a global, sequential id. A hostile page in a web
  session could poll it and read or steal large channel payloads destined
  for another window. The only `tauri::ipc::Channel` users in the GUI are
  the RDP frame path (`session_attach_rdp_frames`, `FrameSink`), so the risk
  is closed by **mutual exclusion**: `session_open_web` refuses while any RDP
  session is live, and `session_open_rdp` and `session_attach_rdp_frames`
  refuse while any web session is live (`session::web_rdp_conflict`,
  `connect.web.refused: reason=rdp_session_live` /
  `connect.rdp.refused: reason=web_session_live`). The decision is taken
  under the `connect_sessions` lock at the point each session registers, so a
  web and an RDP open racing each other cannot both succeed (an RDP open
  that loses is told to stop its already-dialled pump). SSH sessions do not
  use channels and are unaffected. The exclusion stays until upstream removes
  the exemption; any new `Channel` user must be added to the predicate, or
  the mitigation no longer holds.
- **Per-platform `invoke`-rejected check: still pending (manual).** The
  rejection above is established from the 2.11.5 source and its upstream
  test, not by running `window.__TAURI_INTERNALS__.invoke(...)` from a web
  window on macOS, Windows and Linux. Do that before the first release that
  ships this.
- **Server-side audit** (`connect.web.launch` / `result` / `close` through
  the resource mount) is Phase 2, with the launch endpoint, which the host
  calls for `form` sessions (see *What the Phase 2 host half shipped*). An
  `open`-mode session still writes the host-side lines above, and the server
  still sees only its `v2/connect/authorize` call.

### Context this feature builds on

- Resource types are GUI-only: an opaque JSON blob at the resource mount's
  `config/types` ([crates/bv-engine-resource/src/lib.rs:330](../crates/bv-engine-resource/src/lib.rs:330)).
- The `connect` capability, the MFA ticket (`v2/connect/mfa/{begin,verify}`)
  and the direct-path pre-flight `v2/connect/authorize` are
  protocol-agnostic ([bv-engine-resource/src/connect_mfa.rs](../crates/bv-engine-resource/src/connect_mfa.rs)).
  On the direct SSH/RDP path the GUI host resolves the credential itself,
  which needs `read` on the secret; the connect-only guarantee is hard only
  on the Rustion path. Phase 2's launch endpoint closes that for web.
- The Identity Provider (S19, T52) is fully unimplemented. There is no `idp`
  module.

## Scope

### In scope

- **Type and protocol.** A new builtin type `web_application`.
  - `ResourceTypeDef.connect` gains `protocols: ("ssh" | "rdp" | "web")[]`. The
    Connect chip is gated on that list instead of `type === "server"`.
  - The `web` protocol is also enabled on the existing `website` builtin. Its
    `url` field already exists.
- **`web` connection profiles** with a `web` block covering:
  - the start URL,
  - the navigation allow-list,
  - the login mode,
  - the recipe (for `form`),
  - the TLS pin (optional),
  - the window and session options.
- **Server-side launch:** `resources/v2/connect/web/launch`.
  - Authorises via `may_connect_target` and the MFA ticket.
  - Resolves the credential **server-side**.
  - Computes TOTP codes server-side.
  - Returns a short-lived launch bundle to the GUI host.
  - Writes the audit record.
  - This is what makes connect-only access real for web, unlike today's direct
    SSH path.
- **Tauri host session:** `session_open_web`.
  - An ephemeral, IPC-less `WebviewWindow` on an external URL, with origin
    enforcement on navigation, new-window and download.
  - The recipe engine.
  - Teardown, using the same `connect_sessions` registry and `on_close` cleanup
    as SSH/RDP.
- **Recipe editor** in the profile editor, with a "test login" dry run and
  recipe import/export as JSON.
- **`http-auth` mode** through native webview challenge handlers.
- **Per-profile TLS certificate pin** for appliances with self-signed or
  private-CA certificates, through native handlers.
- **`sso` mode** on top of S19, once that feature exists.
- **Exposure-level policy:** `web_exposure_max` at the type and resource tiers.
- **Proxy mode:** placeholder substitution at a host-local proxy. Phase 6 is a
  spike, gated on per-platform CA-trust feasibility.

### Out of scope (explicit)

- **Implementing server-side browser isolation now.** It is designed as Phase 8
  (§12), through Rustion, and left as future work. It depends on Rustion-side
  work that has not started.
- **Recording local web sessions** (Phases 1–7). Pixel capture of a
  WKWebView/WebView2 is a different project. Launch, navigation-origin and close
  events are audited instead. Recorded web sessions arrive with Phase 8, where
  Rustion records the RDP stream.
- **Routing a *local* webview's traffic through Rustion.** Rustion terminates SSH
  and RDP, not HTTP. The `proxy_url` hook used in Phase 6 is where a bastion
  HTTP egress could attach later, but Phase 8 moves the whole browser to the
  bastion side instead, which is the stronger design.
- **Passkeys / WebAuthn with a vault-held key.** Embedded webviews do not expose
  a usable platform-authenticator path:
  - WKWebView needs per-RP associated domains or the browser entitlement.
  - Conditional UI is unsupported.
  - A JS `navigator.credentials` shim would be fragile and would put key material
    in reach of page JS.
  - The operator's own FIDO2 key, used by the site directly, is *not* blocked.
    It simply is not something the vault injects.
- **Kerberos / Integrated Windows Auth.** WebView2 does not support it.
- **Opening in the operator's system browser with injection.** The system
  browser is not ours to control. `open` mode may offer "open in system browser"
  with **no** credential release.
- **Password rotation on check-in for `secret`-sourced web credentials.** This
  is a natural follow-up using `/.well-known/change-password` discovery and a
  second recipe. LDAP-library check-out/check-in works from day one through the
  existing `on_close` cleanup.

## Design

### 1. Data model

`ResourceTypeDef.connect` gains a protocol list. Existing configs with no
`protocols` key are read as `["ssh","rdp"]` when `enabled !== false`, which
preserves today's behaviour:

```ts
connect?: {
  enabled?: boolean;
  protocols?: ("ssh" | "rdp" | "web")[];
  default_ports?: { ssh?: number; rdp?: number };
  default_users?: { linux?: string; macos?: string; windows?: string };
  web_exposure_max?: WebExposure; // see §6
};
```

Builtin `web_application`:

- Fields: `url` (url), `vendor` (select: generic / fortigate / vcenter / idrac /
  ilo / pfsense / grafana / jenkins / other), `environment`, `owner`.
- `connect: { protocols: ["web"] }`.

`website` gains `connect: { protocols: ["web"] }`.

**Saved-config migration.** `mergeTypeConfig` changes from "saved replaces
defaults" to "saved wins per key; builtins absent from the saved config are
added". This is additive only: a saved type is never altered and a deleted
builtin is not resurrected unless it was never saved. The second condition needs
a `removed_builtins: string[]` tombstone list written when an operator deletes a
builtin. Without that tombstone, a deletion would come back on the next release.

`ConnectionProfile.protocol` becomes `"ssh" | "rdp" | "web"`. A `web` profile
carries:

```ts
web?: {
  start_url: string;              // https only (http only with allow_insecure_http, §6)
  allowed_origins: string[];      // exact scheme://host[:port]; start_url's origin is implicit
  login_mode: "open" | "form" | "http-auth" | "sso";
  transport?: "local" | "rustion-isolated"; // default "local"; "rustion-isolated" is Phase 8 (§12)
  recipe?: WebLoginRecipe;        // form only
  sso?: { idp_app: string };      // sso only — an S19 relying-party id
  tls_pin_sha256?: string[];      // SPKI pins, Phase 4
  allow_insecure_http?: boolean;  // default false
  allow_downloads?: boolean;      // default false
  allow_popups_same_origin_set?: boolean; // default true
  clipboard?: "bidirectional" | "host-to-session" | "session-to-host" | "off"; // Linux/Windows only
  window?: { width?: number; height?: number };
}
```

`credential_source` is reused unchanged. The valid sources for `web` are:

- `secret` — reads keys `username`, `password` and optional `totp_seed` (a
  mapping can override the key names).
- `ldap` — library check-out returns username and password; check-in on close
  through `on_close`.
- `default-account` — username only, for apps where the operator types the
  password.

`ssh-engine`, `pki` and `fido2` fail validation on a `web` profile.

**Strict parsing / old clients.** A GUI that predates this feature sees
`protocol: "web"`, which is outside its union.

- The profile parser must fail closed on an unknown protocol. It must not
  default to `ssh`.
- Phase 1 includes a test that pins this behaviour for the current release.
- Older releases are a compatibility risk and are documented in the CHANGELOG
  **Security** entry: an older GUI either ignores the profile or errors, and it
  never dials it as SSH.
  - This must be verified against the parser at the last two released tags
    before Phase 1 merges.

### 2. Login recipe

A recipe is declarative data, never script:

```jsonc
{
  "version": 1,
  "steps": [
    { "when_url": "https://fw01.example.com/login*",
      "actions": [
        { "fill": "input[name=username]", "value": "username" },
        { "fill": "input[name=secretkey]", "value": "password" },
        { "click": "button#login_button" }
      ] },
    { "when_url": "https://fw01.example.com/login/2fa*",
      "actions": [
        { "fill": "input[autocomplete=one-time-code]", "value": "totp" },
        { "submit": "form" }
      ] }
  ],
  "success_when": { "url": "https://fw01.example.com/ng/*" },
  "failure_when": { "selector": ".error-message, .login-error" },
  "timeout_secs": 30,
  "pause_for_operator": ["captcha"]
}
```

Rules:

- `value` is an enum: `username | password | totp | literal:<non-secret>`.
  Selectors and URLs are data. The host never evaluates operator-supplied
  JavaScript.
- `when_url` is matched against the **top-frame URL as reported by the host**
  (`on_page_load(Finished)`), never a URL the page reports about itself.
  - Its origin must be in the profile's origin set.
  - Its scheme must be `https` unless `allow_insecure_http` is set.
  - A profile save is rejected when a step's origin is outside the set.
- A recipe can carry `vendor` presets. Phase 2 ships presets for the
  `web_application.vendor` enum, starting points an operator tests with "Test
  recipe". **They are unverified against live appliances** (written from the
  vendors' documented login forms, not recorded), so they are not yet the
  "working recipe without writing selectors" this section set out to give.
- **Heuristic mode** (`"steps": "auto"`) finds fields by
  `autocomplete="username" | "current-password" | "one-time-code"`, then
  `type=password`. It is off unless the resource's policy allows it (§6).
  Heuristics increase the chance of filling the wrong field, so they are opt-in
  and visibly labelled in the editor.

### 3. Launch flow

```
GUI (main window)                      GUI host (Rust)                         Server
Connect ▸ web profile ──────────────▶ session_open_web(resource, profile)
                                       [MFA prompt if require_mfa] ─────────▶ v2/connect/mfa/{begin,verify}
                                       POST resources/v2/connect/web/launch ─▶ may_connect_target
                                                                               + burn MFA ticket
                                                                               + resolve credential (server-side)
                                                                               + compute TOTP now (never the seed)
                                                                               + audit connect.web.launch
                                       ◀── launch bundle {launch_id, username,
                                           password, totp?, totp_valid_until,
                                           recipe_hash, expires_at (≤ 60 s)}
                                       Zeroizing<..>; build ephemeral window
                                       navigate start_url; run recipe;
                                       drop bundle after success/failure/timeout
                                       ──────────────────────────────────────▶ v2/connect/web/result {launch_id, outcome}
```

- **Why server-side resolution.** It closes the direct-path gap noted in
  [connect-only-access.md](connect-only-access.md): an operator who holds only
  `connect` can launch without ever having `read` on the secret.
  - The launch endpoint is the only reader. It is subject to the same
    `may_connect_target` gate as Rustion open.
  - It returns credentials only for a `web` profile whose `login_mode` needs
    them.
  - This is an honest, bounded guarantee. The operator's own machine receives
    the plaintext for `form` mode, and it is labelled as exactly that (§6).
- **TOTP.** The seed never leaves the server. The bundle carries the current code
  and its validity window. If a recipe reaches its TOTP step after the code
  expires, the host asks for a fresh code at `v2/connect/web/totp` with
  `launch_id`. That call is single-use per step and bound to the launch.
- **`launch_id` binding.** Bound to (principal, namespace, resource, profile,
  recipe_hash) and valid for 60 s. Recorded server-side as SHA-256 only, using
  the MFA-ticket store pattern.
- **No silent fallback.**
  - An unreachable launch endpoint fails the connect. It never falls back to
    host-side secret resolution.
  - A failed recipe surfaces a failed state to the operator. It never falls back
    to heuristic mode.

### 4. The web session window

Built in `gui/src-tauri/src/commands/connect_web.rs` (new) and
`gui/src-tauri/src/session/web.rs` (new):

- **Label `web-<token>`.** A new capability test asserts that **no** capability
  file matches `web-*` and that no capability anywhere declares a `remote` URL
  list. The window has no IPC bridge. The test runs in
  `cargo nextest run -p bastion-vault-gui --lib`. With `withGlobalTauri: true`
  the global script may still be injected, so Phase 1 verifies on all three
  platforms that `invoke` from the web window is rejected. If it is not, the
  global script is disabled for `web-*` windows.
- **`WebviewUrl::External(start_url)`, `incognito(true)`.** On macOS 14+ the
  window also gets a per-session `data_store_identifier`. Elsewhere it gets a
  per-session `data_directory` under the app cache, removed in `on_close`. No
  cookie, cache or local storage outlives the session or is shared with the
  vault UI or another web session.
- **`on_navigation`.** Allows only origins in the profile set. A blocked
  navigation is cancelled, shown to the operator in the window title area, and
  audited as `connect.web.navigation_blocked` with the origin only (no path, no
  query, which can carry tokens).
- **`on_new_window`.**
  - In the origin set (OAuth popups, vendor consoles): opened in a child window
    sharing the session's data store, under the same rules.
  - Otherwise: denied.
- **`on_download`.** Denied unless `allow_downloads`, then saved through the
  existing save dialog. Downloads are audited by filename and size.
- **Devtools off.** Not enabled in release builds. The `devtools` Cargo feature
  stays off for the GUI crate. The context-menu "Inspect" disappears with it.
- **Clipboard.** `enable_clipboard_access` follows the profile's `clipboard`
  setting on Linux and Windows. On macOS the webview clipboard cannot be gated,
  which the profile editor states.
- **Window title.** Always `"<resource> — <current origin>"`, updated by the host
  from `on_page_load`. There is no address bar, so the title is the operator's
  only origin indicator and it must come from the host, never `document.title`.
  A small chrome strip (origin, lock state, Disconnect, Re-run login) needs
  Tauri's `unstable` multi-webview so that vault-controlled UI and the remote
  page live in separate webviews. It is Phase 5. Phase 1 uses the title plus the
  OS window close.
- **Teardown.** Same as SSH/RDP:
  - `CloseRequested` → `drop_session` → `run_cleanup`.
  - Cleanup clears the data directory, runs LDAP check-in, and posts
    `connect.web.close` with duration.

### 5. Recipe engine

Runs in the host. JavaScript only touches the page through one fixed, audited
fill routine that ships with the binary:

- Triggered on `on_page_load(Finished)` for the top frame. Any URL matching
  `when_url` makes the host first re-check the origin against the profile set.
- **Fill script.** For each action the host `eval`s the fixed routine with
  arguments serialised by `serde_json` (never string-concatenated). The routine:
  - resolves the selector in the **top document only**;
  - requires exactly one match;
  - requires the element to be an `<input>` of the expected type, visible
    (non-zero box, not `opacity:0` / `visibility:hidden`, not covered at its
    centre point according to `elementFromPoint`), and in a form whose `action`
    resolves to an allowed origin;
  - sets the value through the native `HTMLInputElement` value setter and
    dispatches `input` / `change`, so React- or Vue-controlled forms see it;
  - returns a structured result. Any failed check aborts the recipe. The host
    never retries with a looser selector.
- **After submit.** The routine clears password fields still present in the
  document, which covers SPAs that keep the form mounted. The host drops its
  `Zeroizing` copy at success, failure or timeout, whichever is first.
- **Frames.** Frames are not filled in Phase 1. A later recipe flag
  (`frame_origin`) may allow one named same-origin frame. Cross-origin frames are
  never filled. On Windows, wry adds initialization scripts to subframes, which
  is one reason the engine uses targeted `eval` after load instead of an
  initialization script.
- **Success and failure** are judged from host-observed URL and selector
  presence, reported to `v2/connect/web/result` and shown in the window title.
- **Pause for operator.** A step can wait (up to `timeout_secs`) for the operator
  to solve a CAPTCHA or approve a push MFA, then continue.

**Exposure, stated plainly.** In `form` mode the password exists in the page's
JavaScript realm from fill until submit and clear. Page scripts, any XSS on the
target, or a compromised third-party script there can read it. This is the same
exposure as every pattern-4/5 product. It is why §6 exists and why the proxy mode
(Phase 6) is on the roadmap.

### 6. Exposure levels and policy

```
WebExposure = "none"     // open, sso
            | "isolated" // Phase 8: any login mode over transport "rustion-isolated";
                         //   the credential reaches Rustion and its worker, never the operator's endpoint
            | "handler"  // http-auth: native challenge handler, never in the DOM
            | "proxy"    // Phase 6: placeholder in DOM, real secret only on the wire
            | "dom"      // form
```

- `web_exposure_max` can be set on the type (`ResourceTypeDef.connect`) and on
  the resource. The most restrictive value wins, matching the Rustion transport
  tier rule.
- **The default is deny.** Only the type tier can opt a resource in: the
  resource's `type` must name a type in the *saved* type configuration that
  sets `web_exposure_max`. Unset, a type missing from the saved configuration,
  or a configuration never saved all mean a cap of `none` — `open` and `sso`
  still work, and every login mode that releases a credential is refused. The
  resource tier can lower the type's cap, never raise it or opt in by itself,
  so editing a resource's `type` cannot escape the type tier. The built-in
  `web_application` and `website` types ship with `dom`. A type saved before
  that keeps its saved shape and stays denied until an administrator sets the
  cap.
- **Enforcement.**
  - The profile editor rejects a profile whose login mode exceeds the cap.
  - The server enforces the cap again in `v2/connect/web/launch`. GUI-side
    validation is a convenience, not the control.
- The order is `none < isolated < handler < proxy < dom`. A cap of `isolated`
  therefore means "SSO or Rustion browser isolation only". That is the setting
  for crown-jewel consoles once Phase 8 exists. Until then, a resource capped at
  `isolated` can still use `open` and `sso`, and `form` is refused, not
  silently run locally.
- **Heuristic recipes** need `allow_heuristic_fill: true` at the same tiers.
  Default is false.
- **`allow_insecure_http`.** Defaults false and is refused when the effective
  cap is below `dom`. A credential sent over plaintext HTTP is not "handler" or
  "proxy" exposure in any meaningful sense.

### 7. `http-auth` mode (Phase 3)

wry does not expose authentication challenges, so the host attaches native
handlers through `Webview::with_webview`:

| Platform | Handler |
|---|---|
| Windows | WebView2 `BasicAuthenticationRequested` (Basic, Digest, NTLM, proxy auth) |
| macOS | `WKNavigationDelegate webView:didReceiveAuthenticationChallenge:` for `NSURLAuthenticationMethodHTTPBasic` / `HTTPDigest` / `NTLM` |
| Linux | WebKitGTK `authenticate` signal |

The handler answers only when:

- the challenge's protection space host and port match an allowed origin, and
- the scheme is https (or `allow_insecure_http`).

It answers at most once per (origin, realm). A second challenge after a supplied
answer means the credential was rejected, which is reported as failure; the
handler does not loop. Kerberos/Negotiate is refused explicitly with a clear
message.

### 8. TLS pinning (Phase 4)

Appliances commonly serve self-signed certificates. The webviews reject those
by default, and the Phase 1 behaviour is to fail closed with the TLS error shown.
Phase 4 adds `tls_pin_sha256` (SPKI SHA-256, one or more), honoured through:

- WebView2 `ServerCertificateErrorDetected`
- WKWebView's server-trust challenge
- WebKitGTK `load-failed-with-tls-errors` plus a per-session certificate
  exception

The pin is the only override. There is no "accept any certificate" switch.

- The profile editor offers a "fetch and show fingerprint" helper. It is
  trust-on-first-use, explicitly labelled, and requires an operator to confirm.
- Where the PKI engine issued the appliance certificate, the editor proposes the
  issuing CA's pin instead.

### 9. `sso` mode (Phase 7, blocked by T52)

Once S19 ships the SAML IdP and OIDC OP:

- `web.sso.idp_app` names a registered relying party.
- **SAML.** The host asks `v2/idp/saml/initiate` (new, S19-side) for an
  IdP-initiated `SAMLResponse` for that SP. It opens the window on an
  auto-posting page served from the host's custom protocol, never from the vault
  UI webview, which posts to the SP's ACS URL. The ACS origin must be in the
  profile's origin set.
- **OIDC.** The host opens the RP's `initiate_login_uri` (OIDC Third-Party
  Initiated Login) with `iss` = the vault OP. The RP redirects back to the OP. The
  OP needs a session for the operator in this *ephemeral* store, so the host
  first plants a single-use OP login cookie with `set_cookie` (tauri-runtime
  ≥ 2.8), scoped to the OP origin and minted by `v2/idp/oidc/launch-session`
  bound to `launch_id`.
- Identity, entitlement checks and the `idp.issue` audit events are S19's. This
  feature contributes the launch plumbing and the profile mode only.
- **Apps that do their own SSO against a corporate IdP** (Entra ID, Okta,
  Keycloak) need no S19. They use `open` mode, with the IdP's origin added to
  `allowed_origins`.

### 10. Proxy mode (Phase 6, spike first)

- The webview is pointed at a host-local proxy (`proxy_url`, `http://127.0.0.1:<ephemeral>`;
  macOS 14+ with wry's `mac-proxy` feature).
- The proxy terminates TLS with a per-session leaf certificate issued by a
  per-session CA held in memory only.
- The recipe fills a random per-launch **placeholder** instead of the password.
- The proxy replaces the placeholder with the real secret in the outgoing request
  body only when all of these hold:
  - the request's origin and path match the recipe's submit target;
  - it is a POST;
  - the content type is form or JSON.
- Header injection (`Authorization`, StrongDM-style) is the same mechanism
  without a placeholder.

The open question that gates it is **making the webview trust the per-session CA
without installing it into the OS trust store**. Installing into the OS store
would be a persistent system-wide change and is refused.

- WebView2 can accept it per-instance through `ServerCertificateErrorDetected`.
- WKWebView through the server-trust challenge.
- WebKitGTK through a per-context TLS database.

The spike must confirm all three. If any platform cannot do it without touching
the OS store, proxy mode ships on the platforms that can and is **visibly
unavailable** elsewhere; it does not fall back to `dom`. Dependencies (a Rust
MITM-capable proxy and certificate generation) must stay inside the
`openssl-sys`/`aws-lc-sys`-free constraints in the root `Cargo.toml`. That
rules out several off-the-shelf proxies and is the second spike question.

### 11. Audit

Server-side, through the resource mount, using the existing audit broker:

| Event | Fields |
|---|---|
| `connect.web.launch` | principal, namespace, resource, profile, login_mode, exposure, credential_source kind, recipe_hash, mfa method, launch_id hash |
| `connect.web.result` | launch_id hash, outcome (`success` / `failure` / `timeout` / `aborted:<check>`), step reached |
| `connect.web.close` | launch_id hash, duration_ms |
| `connect.web.navigation_blocked` | launch_id hash, origin |
| `connect.web.download` | launch_id hash, filename, size (only when allowed) |

Never logged: credential values, TOTP codes, full URLs (paths and queries can
carry tokens; origins only), cookies, selectors' matched values. The host writes
the existing `target:"audit"` `session.open` line with `protocol=web`, so
host-side logs stay uniform with SSH/RDP.

### 12. Rustion browser isolation (Phase 8 — future, cross-repo)

**Status: future.** Designed so that Phases 1–7 do not paint it into a corner.
Not scheduled. It needs the Rustion-side work listed below before any
BastionVault code is written.

**Idea.** Move the browser from the operator's machine to a disposable worker
behind Rustion. Rustion already:

- receives credentials from BastionVault inside a signed, ML-KEM-sealed BVRG-v1
  envelope ([rustion-integration.md](rustion-integration.md), *Envelope format*);
- terminates RDP and records it as `.rdp-rec`;
- hands the recording back through the signed sidecar + `recording.ready`
  webhook that BastionVault already replays in `SessionReplayWindow`.

A web session then becomes an RDP session whose "target" is a browser.

```
Operator GUI                BastionVault                 Rustion                   Browser worker (per session)
Connect ▸ web profile ───▶ authorize + MFA ticket
 (transport: rustion-       resolve credential + TOTP
  isolated)                 BVRG-v1 op=open,
                            protocol=web ───────────▶ verify + decrypt
                                                      pick/spawn worker ───────▶ fresh container/VM:
                                                                                 Chromium kiosk, empty profile,
                                                                                 enterprise policies from envelope
                                                      hand recipe + credential ─▶ worker agent runs the recipe
                                                        over a local control       over CDP (localhost only)
                                                        channel
                           ◀── {sid, host, port, ticket, expires_at}
RDP client (existing,
IronRDP) ── ticket@sid ─────────────────────────────▶ RDP proxy + recorder ───▶ worker's RDP endpoint
                                                      on close: destroy worker,
                                                      sidecar + recording.ready ─▶ BV links recording
```

**What stays the same on the BastionVault side:**

- the profile model (§1), adding only `transport: "rustion-isolated"`;
- the recipe format (§2), which becomes a shared, versioned contract;
- the authorisation, MFA and exposure-cap checks (§3, §6);
- the RDP session window, ticket dialling, TTL renewal and recording replay from
  [rustion-integration.md](rustion-integration.md).

There is no new streaming code in the GUI.

**What BastionVault adds (when Phase 8 starts):**

- **BVRG-v1 payload additions** (additive, `v: 1` stays readable):
  - `target.protocol = "web"`;
  - `credential.kind = "web-form" | "web-http-auth" | "web-none"`;
  - `credential.extra = { totp_codes, recipe, recipe_hash, start_url,
    allowed_origins, tls_pin_sha256, allow_downloads, clipboard }`.
  - Rustion must reject an envelope with an unknown `credential.kind`; it must
    not ignore it.
- **TOTP.** The seed still never leaves BastionVault. The envelope carries the
  codes for the current and next time steps (about 60 s of validity). A login
  that takes longer fails and the operator relaunches. Keeping Rustion → vault
  traffic one-way is worth more than covering slow logins.
- **Routing.** A `rustion-isolated` profile goes through the same bastion
  selection as RDP (profile → asset group → type → global). Under
  `rustion-required` transport policy, a `web` profile with
  `transport: "local"` is refused. It never falls back to local.
- **Audit.** `connect.web.launch` with `transport=rustion-isolated`, plus the
  existing `session.open` / `recording.linked` events. Rustion's navigation
  origins (from the sidecar) are attached to the session timeline.

**What Rustion has to provide** (tracked in the Rustion repo; the preparation
prompt is in [roadmaps/prompts/rustion-browser-isolation.md](../roadmaps/prompts/rustion-browser-isolation.md)):

1. Accept and validate the `web` envelope additions, with fail-closed handling
   of unknown kinds.
2. A **browser worker** abstraction: a per-session, disposable environment
   running Chromium in kiosk mode with a fresh profile. It is reachable by
   Rustion over RDP and destroyed on close, with no state reused across
   sessions.
3. A **worker agent** that receives the recipe and credential from Rustion over
   an authenticated local channel and drives the login through the Chrome
   DevTools Protocol on localhost. It applies the same safety checks as §5
   (exact origin, top frame, visible single-match fields, form action origin)
   and reports the outcome.
4. **Policy enforced inside the worker**, not only in the recipe:
   - Chromium enterprise policies: URL allow-list, devtools disabled, download
     restrictions, no password manager, no extensions.
   - Network egress restricted to the allowed origins (plus DNS).
5. **Recording and audit:** the RDP stream recorded as usual, plus navigation
   origins and recipe outcome in the sidecar and Rustion's hash chain.
6. **Capacity and lifecycle:** worker pool or on-demand spawn, limits per
   authority, start-up time budget, cleanup on crash, health exposed through
   `GET /v1/health`.

**Exposure.** The credential reaches Rustion's process and the worker's memory
and DOM. Rustion is already trusted with SSH/RDP credentials, and the worker is
destroyed after each session. Page JavaScript on the target can still read a
filled password inside the worker, but it cannot exfiltrate it past the egress
allow-list, and the operator's endpoint never holds it. That is exposure level
`isolated`.

**Open questions for the Rustion-side design:**

- Worker technology: container (Podman) per session vs microVM vs a pre-warmed
  pool. Chromium's sandbox inside containers needs user namespaces or seccomp.
- RDP endpoint inside the worker: xrdp in the worker image vs an embedded
  `ironrdp-server` fed by a virtual framebuffer.
- Clipboard and file transfer: reuse Rustion's RDP channel policies.
- Chromium patch cadence: who rebuilds the worker image, and how fast after a
  Chromium security release.

## API surface (all `v2`)

| Path | Op | Purpose |
|---|---|---|
| `resources/v2/connect/web/launch` | write | authorise, resolve credential, return launch bundle |
| `resources/v2/connect/web/totp` | write | fresh TOTP code for an in-flight `launch_id` |
| `resources/v2/connect/web/result` | write | report recipe outcome |
| `resources/v2/connect/web/close` | write | report session end |

Tauri commands: `session_open_web`, `session_close` (existing, extended),
`web_recipe_test` (dry run against a URL with no credential at all — every
check of the fill routine, nothing filled, clicked or submitted — which never
calls `launch`).

`docs/api.md` gains a "Web connect" subsection. `docs/gui.md` gains the operator
walkthrough.

## Phases

### Phase 1 — type, protocol and `open` mode — **Done, with caveats**

See *Current State → Phase 1 caveats*: in-set pop-ups load in the session
window, allowed downloads skip the save dialog, the per-platform
`invoke`-rejected check is still manual, and Tauri's channel-fetch IPC
exemption is mitigated by refusing web and RDP sessions at the same time
(until upstream removes the exemption).


- `web_application` builtin, `connect.protocols`, and the `website` type enabled.
- The `mergeTypeConfig` additive migration with tombstones.
- The Connect chip gated on `protocols`.
- `web` profiles with `open` mode only.
- `session_open_web`:
  - ephemeral IPC-less window, navigation/new-window/download policy;
  - host-owned title;
  - teardown;
  - `v2/connect/authorize` pre-flight and MFA ticket reused.
- The no-capability-for-`web-*` test, the strict-protocol-parsing test, and the
  per-platform `invoke`-rejected check.

This phase alone removes the "reveal, copy, open browser" habit for SSO-fronted
apps and gives them an audited launch point.

### Phase 2 — `form` mode with recipes — **Done, with caveats**

See *Current State → What the Phase 2 host half shipped → Phase 2 caveats*:
the vendor presets are unverified against live appliances, the per-platform
manual checks and `make test-release` have not been run, the fill routine runs
in the page's main world, and there is no end-to-end LDAP check-out test.

- **Done:** the `resources/v2/connect/web/{launch,totp,result,close}`
  endpoints with server-side credential resolution and TOTP, server-side
  `web_exposure_max` / `allow_heuristic_fill` enforcement, the v1 recipe
  validator and hash, and LDAP library check-in on close. See *Current
  State*.
- **Done:** the host recipe engine and fixed fill routine, calling `launch`
  / `totp` / `result` / `close` on every teardown path, and the
  `web_recipe_test` dry run (checks only, no credential). See *Current State
  → What the Phase 2 host half shipped*.
- **Done:** the recipe editor (calling `web_recipe_test`), JSON
  import/export, the form-mode profile editor, the Settings → Resource Types
  exposure controls, and vendor presets (FortiGate, vCenter, iDRAC, iLO,
  pfSense, Grafana, Jenkins). The editor's validation and exposure check
  mirror the server's. See *Current State → What the Phase 2 GUI editor
  shipped*.
- **Carried forward as caveats:** testing the presets against recorded login
  pages or live appliances (they are **unverified** today, and labelled so),
  and the per-platform manual checks.
- **Done:** `resources/v2/connect/web/*` in the built-in baseline policies (`default`, `standard-user`, `shared-access` refreshed at startup; `administrator` is not refreshed but inherits `update` through `default`).

### Phase 3 — `http-auth` mode — **Todo**

Native challenge handlers on all three platforms (§7), answering once per
(origin, realm).

### Phase 4 — TLS SPKI pinning — **Todo**

Native certificate-error handlers honouring `tls_pin_sha256` only (§8), plus the
fingerprint helper and the PKI-issued-CA suggestion.

### Phase 5 — session chrome — **Todo**

A vault-owned toolbar webview (origin, lock state, Disconnect, Re-run login, TTL)
beside the remote webview, using Tauri's `unstable` multi-webview. The remote
webview keeps no IPC. Coordinates with [session-workspace.md](session-workspace.md)
(S56) so that web sessions can later become workspace tabs, with the remote
content always in its own webview, never a shared realm.

### Phase 6 — proxy mode — **Todo (spike first)**

The per-platform CA-trust spike, then placeholder substitution and header
injection (§10). Ships per platform where the spike succeeds.

### Phase 7 — `sso` mode — **Todo, blocked by T52 (S19)**

IdP-initiated SAML and OIDC third-party-initiated login (§9).

### Phase 8 — Rustion browser isolation — **Future (cross-repo, not scheduled)**

The `rustion-isolated` transport and the `isolated` exposure level (§12).
Depends on the Rustion-side browser worker, worker agent and envelope additions,
and on Phase 2's recipe format being frozen as a versioned shared contract.
BastionVault work starts only once Rustion ships its half. Tracked separately
as T97 in the roadmap backlog.

## Dependencies

- Tauri `>= 2.4` (cookie APIs), tauri-runtime `>= 2.8` for `set_cookie`
  (Phase 7). wry's `mac-proxy` feature is needed for Phase 6 only.
- Platform minimums:
  - macOS 14 for `data_store_identifier` and `proxy_url`; macOS 13 falls back to
    `incognito` plus a per-session `data_directory`.
  - WebView2 101+ for `incognito`.
- Native-handler work (Phases 3, 4 and 6) uses the `webview2-com`, `objc2` and
  `webkit2gtk` bindings already pulled in transitively by wry. Promoting them to
  direct dependencies needs the manifest justification §7 of AGENTS.md requires.
- S19 / T52 for Phase 7.
- Rustion (S51, [rustion-integration.md](rustion-integration.md)) browser worker
  support and BVRG-v1 `web` payload additions for Phase 8.

## Security Considerations

1. **Credential reaches the endpoint DOM in `form` mode.** This is inherent to
   pattern 4 and is stated in the UI, in docs and by the exposure level.
   Mitigations:
   - the fill/submit/clear window;
   - devtools off;
   - an ephemeral store;
   - the exposure cap that lets policy forbid `dom` for crown-jewel accounts;
   - LDAP-library and (follow-up) rotate-on-check-in credentials;
   - proxy mode as the real fix.
2. **Origin confusion and phishing.**
   - Exact-origin match, from host-observed URLs only, at every fill.
   - HTTPS required.
   - Top frame only.
   - Visible, non-occluded, correctly typed, single-match fields.
   - Form `action` must resolve to an allowed origin.
   - No fill UI inside the page.
   - The form-action check only stops script-free mis-targeting: a submit,
     input, change or click listener on an in-scope page can rewrite the
     destination after the check, so the navigation allow-list is the
     backstop — and at `dom` exposure in-scope script can read the value
     anyway.
3. **Remote content must never reach vault IPC.**
   - The `web-*` label has no capability.
   - Tests assert it.
   - A per-platform `invoke` check.
   - No shared data store with the main window.
   - Tauri 2.11.5 exempts `plugin:__TAURI_CHANNEL__|fetch` from the
     remote-origin ACL, so a web window and an RDP session (the only
     `Channel` user) are never live together. Mitigated by mutual
     exclusion until upstream removes the exemption (see Current State).
4. **Connect-only access.** The launch endpoint is a new secret reader gated by
   `connect`, not `read`. It must return credentials only for a `web` profile
   bound into the `launch_id`, only within the exposure cap, and only after the
   MFA ticket when required.
   - Reviewers should treat it like `rustion/v2/session/open`.
   - L4 (`make test-release`) is required before merging Phase 2, because it
     touches authz.
5. **No silent downgrade.** None of the following has a fallback path:
   - recipe mismatch → no heuristic fill;
   - launch failure → no host-side secret read;
   - proxy unavailable → no `dom`;
   - TLS error → no "accept anyway" without a pin.
6. **Logging.** Never values, codes, cookies or full URLs (§11). Recipe test runs
   use no credential at all and never call `launch`.
7. **Rustion isolation (Phase 8)** widens what Rustion handles from SSH/RDP
   credentials to web credentials and hostile web content. The browser must run
   in a disposable worker outside Rustion's own process, with egress restricted
   to the allowed origins. An envelope with an unknown `credential.kind` must be
   rejected by an older Rustion, never ignored.
8. **macOS clipboard** cannot be gated in WKWebView. This is documented, and the
   profile editor shows it when `clipboard` is set to anything but
   `bidirectional` on macOS.

## Testing Plan

### Rust unit tests

- `bv-engine-resource`:
  - `launch` authorises via `may_connect_target`;
  - `launch` refuses on a missing or used MFA ticket;
  - `launch` refuses over the exposure cap;
  - `launch` refuses a non-`web` profile or a recipe-hash mismatch;
  - `launch` never returns the TOTP seed;
  - `launch_id` is single-use, expires, and is stored hashed;
  - audit lines carry no secret.
- `bastion-vault-gui`:
  - the capability set has no `web-*` match and no `remote`;
  - origin matching (ports, IDNs, trailing dots, userinfo `https://a@b`, upper
    case, `http` vs `https`);
  - `when_url` glob semantics;
  - recipe parsing rejects unknown actions and non-enum values;
  - fill-routine argument serialisation round-trips hostile selectors.

### Frontend (vitest)

- The `mergeTypeConfig` additive merge and tombstones.
- The Connect chip appears for `protocols` including `web`.
- Profile validation: exposure cap, source/protocol compatibility, origin set
  coverage of recipe steps.
- Strict parsing of an unknown `protocol`.

### Integration / manual (per platform)

A fixture site served by the test harness with:

- single-page, two-page and TOTP logins;
- a React-controlled form;
- an opacity-0 decoy field;
- an overlay-covered field;
- a cross-origin iframe login;
- a form whose `action` posts off-origin;
- a redirect to a non-allowed origin;
- a self-signed certificate;
- a Basic-auth realm.

Each hostile case must abort with the documented `aborted:<check>` outcome.

## Tracking

Tracked as **T96** in `ROADMAP.md` (M5 Resources), spec **S105**. Phase 8
(Rustion browser isolation) is tracked separately as backlog task **T97**,
because it is cross-repo and unscheduled. When phases
land, update [CHANGELOG.md](../CHANGELOG.md) (the connect-only/launch endpoint
and exposure levels under **Security**), [ROADMAP.md](../ROADMAP.md), this
file's "Current State", [docs/api.md](../docs/api.md) and
[docs/gui.md](../docs/gui.md).

## Alternatives considered

- **Server-side browser isolation built into BastionVault** (a KeeperPAM /
  CyberArk PSM-HTML5 clone). Rejected in favour of Phase 8.
  - It would need a headless-Chromium fleet next to the vault, a new
    pixel-streaming path and viewer, and a recorder.
  - It would add a large hostile-content TCB to the system that holds the keys.
  - Rustion already has the credential handoff, the RDP proxy, recording and
    replay, so Phase 8 adds only the browser worker there.
- **A browser on a manually managed RDP RemoteApp jump host**, reached through
  the existing RDP Connect. Cheapest of all and usable today, but there is no
  automated login, no per-session disposal, and no origin policy tied to the
  resource. Phase 8 is the automated version of this.
- **Browser extension** (CyberArk SWS, Delinea DCM). Rejected:
  - the operator's everyday browser profile is not a controlled environment;
  - extensions have their own clickjacking record;
  - it would need a native-messaging bridge to the vault.
- **Opening the system browser with a one-time URL token.** Only works for apps
  that accept token login. Covered better by `sso` mode.
- **Initialization scripts instead of post-load `eval`.** Rejected:
  - they run on every page, and on Windows in every frame;
  - they live in the page's main world, so they can be observed and overridden
    before the vault's code acts;
  - targeted `eval` after host-verified load keeps the fill path small and
    origin-checked.
