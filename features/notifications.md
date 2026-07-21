# Feature: Notifications

**Status:** ✅ Shipped (v1). Core in-app notification system + plugin
notification extensibility + a reference email channel plugin.
**Owner:** Felipe Quintella
**Related:** [`features/plugin-system.md`](plugin-system.md),
[`features/plugin-app-extensions.md`](plugin-app-extensions.md),
[`features/identity-groups.md`](identity-groups.md).

---

## Summary

A first-class, in-app notification system plus the substrate that lets
plugins participate in it:

1. **In-app notifications** targetable to a **single user**, a **user
   group**, or **all users** — with a header **bell + notification
   center** in the GUI (unread badge, mark-read / mark-all-read,
   dismiss, click-through action links).
2. **Plugins can send notifications** — capability-gated host imports
   (`bv.notify_send` server-side, `bvx.notify_send` in client app
   modules).
3. **Plugins can add delivery channels** — a plugin declares
   `notification_channels` in its manifest (email / SMS / Slack / Teams
   / WhatsApp / webhook / …); the core delivery engine routes to the
   plugin over the existing invoke path with a `notify_deliver` envelope.
4. **Plugins can access notification messages and windows** —
   `bv.notify_list` / `bv.notify_get` (a plugin's own authored
   notifications, server-side) and `bvx.notify_list` / `bvx.notify_open`
   + a `bvx_notify_event` callback (the caller's own inbox + the
   notification-center window, client app modules).
5. **A reference email channel plugin** (`bastion-plugin-email`)
   supporting generic **SMTP** and **Office 365 (OAuth2 / Microsoft
   Graph `sendMail`)**, with credentials stored as barrier-encrypted
   secrets.

The design reuses existing substrate rather than inventing new
machinery: the `AuditBroker` fan-out is the template for the service,
capability-gated host imports (`bv.*` / `bvx.*`) are the template for
plugin access, and the process-runtime plugin is the template for the
email plugin.

## Architecture

Notifications are a **system logical backend** mounted at
`notifications/`, reached over the forward-going `/v2/notifications/*`
API (via the existing `/v2/{path:.*}` logical pipeline), so every route
rides the standard ACL + audit + namespace machinery and resolves the
caller from `req.auth`.

```
Sender (admin GUI / system / plugin)
    │  POST v2/notifications/send  {title, body, severity, target, channels}
    ▼
NotificationService (Core-reachable via module_manager)
    • resolve target → entity_ids (+ contact addresses for channels)
    • persist canonical message + one inbox pointer per recipient (in-app)
    • fan out to requested plugin channels
    ├── InAppChannel (built-in)  → per-user inbox → GUI bell/center
    └── PluginChannel(email/…)   → invoke plugin: op="notify_deliver"
```

Module tree (`src/modules/notifications/`): `types.rs` (Notification,
NotificationTarget, Severity, Recipient, ChannelInfo, NotificationConfig),
`store.rs` (namespace-aware `NotificationStore`), `contacts.rs` (target →
entity + userpass email resolution), `channel.rs` (registry + plugin
dispatch), `service.rs` (`NotificationService`), `mod.rs`
(`NotificationsModule` + logical backend paths).

### Storage (behind the system barrier)

```
sys/notifications/messages/<id>            -> Notification (canonical)
sys/notifications/inbox/<entity_id>/<id>   -> InboxEntry (per-user read state)
sys/notifications/config                   -> NotificationConfig
# non-root namespace:
notifications-ns/<b64url(ns)>/messages|inbox|config/...
```

### HTTP surface (v2)

| Method & path | Purpose | ACL |
|---|---|---|
| `POST v2/notifications/send` | Compose + send | `create` (admin) |
| `LIST/GET v2/notifications/inbox` | Caller's inbox | self (default policy) |
| `GET v2/notifications/inbox/unread-count` | Unread count | self |
| `POST v2/notifications/inbox/<id>/read` | Mark one read | self |
| `POST v2/notifications/inbox/read-all` | Mark all read | self |
| `DELETE v2/notifications/inbox/<id>` | Dismiss | self |
| `GET v2/notifications/channels` | List channels | admin |
| `POST v2/notifications/channels/<id>/test` | Send a test | admin |
| `LIST v2/notifications/sent` | Admin audit view | admin |
| `GET/PUT v2/notifications/config` | Retention / rate settings | admin |

Own-inbox access is granted to every authenticated token via the
`default` (and `namespace-self`) policy — the backend scopes every inbox
operation to the caller's `entity_id`, so a user only ever sees their
own. Sending / channels / sent / config are **not** in the default
policy: broadcasting requires an admin policy, which is how the ACL
enforces who may raise a notification.

## Plugin ABI (host ABI minor 2 → `abi_version = "1.2"`)

Manifest additions (all additive, `skip_serializing_if` so existing
signed plugins keep verifying):

- `capabilities.notify_emit` — gate `bv.notify_send`.
- `capabilities.notify_read` — gate `bv.notify_list` / `bv.notify_get`
  (a plugin's **own** authored notifications only — never a user's inbox).
- `capabilities.notification_channels[]` — `{id, name, kind,
  description}`; channels this plugin provides.
- `capabilities.app.notify` — `{read, windows}`; app-module access to
  `bvx.notify_list` / `bvx.notify_open` + the `bvx_notify_event` export.

All four participate in the catalog's capability-widening guard. Server
host imports live in `src/plugins/runtime.rs`; client app-module imports
in `gui/src-tauri/src/plugin_apps.rs`. Plugin sends are audited (plugin
name + target, **never** the body) and rate-limited per plugin.

The channel-delivery envelope a plugin receives:

```json
{ "op": "notify_deliver", "channel": "email",
  "notification": { "title": "...", "body": "...", "severity": "warning", "action_url": "..." },
  "recipients": [ { "entity_id": "...", "display_name": "Alice", "email": "alice@example.com" } ] }
```

The plugin returns `{"delivered": <n>, "failed": [{"recipient","error"}]}`.

## SDK & testkit

`bastion-plugin-sdk`: `Host::notify_{send,list,get}` (server `bv.*`),
`AppHost::notify_{send,list,open}` + `AppModule::notify_event` +
`app_module!` `bvx_notify_event` export (client `bvx.*`). The
`host_test` mocks capture sent notifications (`test_support`).

## Email channel plugin (`plugins-ext/bastion-plugin-email`)

Process runtime (real OS network for SMTP / HTTPS). Provides the `email`
channel. Config selects `mode = smtp | office365`; SMTP supports
STARTTLS / implicit-TLS / none with optional SMTP AUTH (via `lettre`
over rustls); Office 365 uses OAuth2 client-credentials + Microsoft
Graph `sendMail` (via `reqwest`, rustls). Passwords / client secrets use
the `secret` config kind (barrier-encrypted, never echoed back). See the
plugin README.

## GUI

- Header **bell + unread badge** (`gui/src/components/NotificationBell.tsx`)
  in the authed Layout sidebar header, with a dropdown **notification
  center**.
- **Admin page** (`gui/src/routes/NotificationsAdminPage.tsx`, route
  `/notifications`): compose (title/body/severity, target picker for
  user/group/all, channel multi-select), sent history, channel list +
  Test, retention/rate settings.
- Zustand `notificationsStore` with a 30 s unread poll; `listen`s for
  `notification-received` (badge refresh) and `notification-center-open`
  (from `bvx.notify_open`).
- Tauri commands in `gui/src-tauri/src/commands/notifications.rs`.

## Security model

- **Secrets:** channel credentials use `ConfigFieldKind::Secret` —
  barrier-encrypted, masked, returned as `"<set>"`. Bodies, credentials,
  and tokens are never logged.
- **AuthZ:** own-inbox reads are server-scoped by `entity_id`;
  broadcasting is admin-gated by ACL; plugin `notify_read` is limited to
  plugin-authored notifications; `bvx.notify_send` rides the user's token
  so the server ACL is authoritative (a plugin can only spend the user's
  own permissions).
- **Blast radius:** plugin sends are audited (no body) and per-plugin
  rate-limited; channel/notify capabilities obey the widening guard + the
  ABI-minor gate (old hosts reject `1.2` cleanly).
- **Egress:** the email plugin uses process-runtime OS networking
  (documented trust, like the postgres reference plugin); WASM channel
  plugins needing HTTP go through the admin-granted `bv.net_http`.
- **Compat/migration:** all manifest fields additive; new storage keys
  only (no format migration).

## Testing

- Manifest: notify caps require abi 1.2; channel-id uniqueness; notify
  fields omitted from the signing message when off
  (`crates/bv-plugin-manifest`).
- Server integration (`src/modules/notifications/mod.rs` tests):
  send-to-user roundtrip (send → inbox → unread-count → mark-read),
  all-users targeting + dismiss, channel list, admin sent view.
- Plugin testkit ABI-parity guard unaffected (the new `bv.notify_*`
  imports follow the `bv.net_http` precedent of not being mirrored in the
  testkit conformance set).
- GUI: `gui/src/test/notifications.test.tsx` (bell badge, center list,
  mark-all-read).

## Not yet implemented / follow-ups

- Threading `capabilities.app.notify` through the `bv_plugin_surface`
  active-surfaces bundle so the `bvx.notify_*` imports are gated on the
  declared capability at the client runtime (today they rely on the
  server ACL as the authority, riding the user's token).
- Firing `bvx_notify_event` on live arrival (the export + SDK hook exist;
  the client does not yet detect arrivals and call it).
- Digitally-signed / scheduled notifications, per-user channel
  preferences, and SMS/Slack/Teams reference channel plugins.
