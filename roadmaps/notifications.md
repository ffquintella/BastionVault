# Roadmap: Notifications

**Current State:** ✅ Complete — shipped in one pass. See
[`features/notifications.md`](../features/notifications.md) for the
operator- and plugin-author-facing spec.

An in-app notification system plus the plugin substrate to send
notifications and add delivery channels, with a reference email channel
plugin.

## Phases (all shipped)

| Phase | Scope | Status |
|---|---|---|
| 1 | **Core service** — `src/modules/notifications/` (types, store, contacts, channel, service, module); `notifications/` logical backend over `v2/notifications/*`; targeting (user / group / all); per-user inbox + read state; namespace-aware storage; audit via the standard pipeline; default-policy self-service inbox grant. | ✅ |
| 2 | **Built-in in-app channel** + channel registry + plugin channel dispatch (`notify_deliver` invoke, contact resolution from userpass email). | ✅ |
| 3 | **Plugin ABI (minor 2)** — manifest `notify_emit` / `notify_read` / `notification_channels` / `app.notify`; server `bv.notify_*` host imports (audited, rate-limited); widening guard; `HOST_ABI_MINOR = 2`. | ✅ |
| 4 | **SDK + testkit** — `Host::notify_*`, `AppHost::notify_*`, `AppModule::notify_event`, `app_module!` `bvx_notify_event`, host_test mocks. | ✅ |
| 5 | **GUI** — header bell + notification center, admin compose/channels/sent/settings page, zustand store + poll, Tauri commands, event listeners; client `bvx.notify_*` runtime. | ✅ |
| 6 | **Email channel plugin** — `plugins-ext/bastion-plugin-email` (generic SMTP via `lettre`, Office 365 OAuth2/Graph via `reqwest`, secret-backed credentials). | ✅ |

## What is not yet implemented

- Threading `capabilities.app.notify` through the `bv_plugin_surface`
  active-surfaces bundle so the client `bvx.notify_*` imports are gated on
  the declared capability at runtime (today they rely on the server ACL,
  riding the user's token).
- Firing `bvx_notify_event` on live notification arrival.
- Per-user channel preferences, scheduled/digest notifications, and
  additional reference channel plugins (SMS / Slack / Teams).
