//! Every route under `/v1/sys` and `/v2/sys`, as data.
//!
//! `init_sys_service` registers these tables and nothing else (see
//! [`crate::routes`]), so a `sys` route that is not listed here cannot exist,
//! and one that is listed carries its class: `privileged` entries register
//! through [`crate::authz::privileged`], which refuses a handler that does not
//! take the route's `Authorized<R>` witness, and every anonymous entry carries
//! its justification into `tests/golden/anonymous-routes.txt`.
//!
//! Order is registration order, and actix matches resources in that order: a
//! literal path must precede the wildcard that would swallow it.

use super::*;
use crate::routes::{resource, route, BodyLimit, ResourceSpec};

/// Served under both `/v1/sys` and `/v2/sys`. `v1` is frozen for Vault
/// compatibility: nothing new goes here.
pub(crate) const SHARED: &[ResourceSpec] = &[
    resource!("/init" => [
        route!(public_probe Get => sys_init_get_request_handler,
            "bootstrap: whether the vault is initialized is needed before any token can exist"),
        route!(public_probe Post => sys_init_put_request_handler,
            "one-time bootstrap that mints the root token and unseal shares; no token can exist before it, and Core::init refuses an initialized vault"),
        route!(public_probe Put => sys_init_put_request_handler,
            "one-time bootstrap that mints the root token and unseal shares; no token can exist before it, and Core::init refuses an initialized vault"),
    ]),
    resource!("/seal-status" => [
        route!(public_probe Get => sys_seal_status_request_handler,
            "unseal workflow: sealed, share counts and unseal progress are needed while no token can be validated; no secret material"),
    ]),
    resource!("/health" => [
        route!(public_probe Get => sys_health_request_handler,
            "load-balancer probe; exposes only initialized, sealed, standby and cluster_healthy"),
    ]),
    resource!("/info" => [
        route!(tiered Get => sys_info_request_handler,
            "initialized and sealed are needed before a token can exist; version, started_at, uptime_seconds and storage_type require a live token (v0.37.6)"),
    ]),
    resource!("/cluster-status" => [
        route!(cluster_local Get => sys_cluster_status_request_handler,
            "Raft role and membership: a live token, or a cluster-local socket peer (loopback or a configured node, never X-Forwarded-For); anyone else gets 403"),
    ]),
    resource!("/cluster/remove-node" => [route!(privileged SysClusterRemoveNode: Post => sys_cluster_remove_node_request_handler)]),
    resource!("/cluster/leave" => [route!(privileged SysClusterLeave: Post => sys_cluster_leave_request_handler)]),
    resource!("/cluster/failover" => [route!(privileged SysClusterFailover: Post => sys_cluster_failover_request_handler)]),
    resource!("/backup" => [route!(privileged SysBackup: Post => sys_backup_request_handler)]),
    resource!("/restore" => [route!(privileged SysRestore: Post => sys_restore_request_handler)]),
    resource!("/export/{path:.*}" => [route!(privileged SysExport: Get => sys_export_request_handler)]),
    resource!("/import/{mount:.*}" => [route!(privileged SysImport: Post => sys_import_request_handler)]),
    resource!("/exchange/export" => [route!(privileged SysExchangeExport: Post => sys_exchange_export_request_handler)]),
    resource!("/exchange/import" => [route!(privileged SysExchangeImport: Post => sys_exchange_import_request_handler)]),
    resource!("/exchange/import/preview" => [
        route!(privileged SysExchangeImportPreview: Post => sys_exchange_import_preview_handler),
    ]),
    resource!("/exchange/import/apply" => [
        route!(privileged SysExchangeImportApply: Post => sys_exchange_import_apply_handler),
    ]),
    resource!("/scheduled-exports" => [
        route!(privileged SysScheduledExportsList: Get => sys_scheduled_exports_list_handler),
        route!(privileged SysScheduledExportCreate: Post => sys_scheduled_exports_create_handler),
    ]),
    resource!("/scheduled-exports/{id}" => [
        route!(privileged SysScheduledExportRead: Get => sys_scheduled_exports_get_handler),
        route!(privileged SysScheduledExportUpdate: Put => sys_scheduled_exports_update_handler),
        // POST alias: the GUI's remote backend maps a logical Write to POST,
        // so accept it here too (PUT kept for REST clients).
        route!(privileged SysScheduledExportUpdate: Post => sys_scheduled_exports_update_handler),
        route!(privileged SysScheduledExportDelete: Delete => sys_scheduled_exports_delete_handler),
    ]),
    resource!("/scheduled-exports/{id}/runs" => [
        route!(privileged SysScheduledExportRuns: Get => sys_scheduled_exports_runs_handler),
    ]),
    resource!("/scheduled-exports/{id}/run-now" => [
        route!(privileged SysScheduledExportRunNow: Post => sys_scheduled_exports_run_now_handler),
    ]),
    resource!("/scheduled-exports/{id}/backups" => [
        route!(privileged SysScheduledExportBackups: Get => sys_scheduled_exports_backups_list_handler),
    ]),
    // Peer side of a cross-node restore: hands back one backup file this node
    // holds. Local-only by design — it never forwards.
    resource!("/scheduled-exports/{id}/backups/{filename}/fetch" => [
        route!(privileged SysScheduledExportBackupFetch: Get => sys_scheduled_exports_backup_fetch_handler),
    ]),
    resource!("/scheduled-exports/{id}/restore" => [
        route!(privileged SysScheduledExportRestore: Post => sys_scheduled_exports_restore_handler),
    ]),
    // Plugin registration uploads the manifest + binary (and optionally a
    // surface + client assets) inline as base64 inside one JSON body. A real
    // `.bvplugin` is comfortably bigger than actix's default 256 KiB
    // `web::Bytes` limit; without an explicit `PayloadConfig` the server
    // resets the connection mid-upload (Windows surfaces this as
    // `ConnectionAborted` / WSAECONNABORTED 10053). Use the same 32 MiB
    // ceiling logical and batch already settled on so operators don't hit a
    // different limit on a different route.
    resource!("/plugins", body_limit: BodyLimit::Payload(default_plugin_register_body_limit()) => [
        route!(privileged SysPluginsList: Get => sys_plugins_list_handler),
        route!(privileged SysPluginRegister: Post => sys_plugins_register_handler),
    ]),
    // Literal `/plugins/<word>` resources MUST be registered before the
    // `/plugins/{name}` wildcard — actix-web matches resources in registration
    // order, so a wildcard registered first would swallow `publishers`,
    // `accept_unsigned`, `quarantine`, and `active-surfaces` and answer 404
    // "plugin not found".
    resource!("/plugins/publishers" => [
        route!(privileged SysPluginPublishersRead: Get => sys_plugins_publishers_get_handler),
        route!(privileged SysPluginPublishersWrite: Put => sys_plugins_publishers_put_handler),
    ]),
    resource!("/plugins/accept_unsigned" => [
        route!(privileged SysPluginAcceptUnsigned: Put => sys_plugins_accept_unsigned_put_handler),
    ]),
    resource!("/plugins/quarantine" => [
        route!(privileged SysPluginQuarantine: Get => sys_plugins_quarantine_list_handler),
    ]),
    resource!("/plugins/active-surfaces" => [
        route!(privileged SysPluginActiveSurfaces: Get => sys_plugins_active_surfaces_handler),
    ]),
    resource!("/plugins/{name}" => [
        route!(privileged SysPluginRead: Get => sys_plugins_get_handler),
        route!(privileged SysPluginDelete: Delete => sys_plugins_delete_handler),
    ]),
    // Plugin invocations carry their input inline as base64 inside the JSON
    // body. Some plugins (e.g. `xca-import`) legitimately receive multi-MiB
    // blobs — an entire XCA `.xdb` database — so we'd otherwise blow through
    // actix's 256 KiB `web::Bytes` default and the server would reset the
    // connection mid-upload (ureq surfaces this as `BrokenPipe` / EPIPE on
    // macOS, `ConnectionAborted` on Windows). Reuse the 32 MiB ceiling
    // already established for registration / logical / batch.
    resource!("/plugins/{name}/invoke", body_limit: BodyLimit::Payload(default_plugin_invoke_body_limit()) => [
        route!(privileged SysPluginInvoke: Post => sys_plugins_invoke_handler),
    ]),
    resource!("/plugins/{name}/config" => [
        route!(privileged SysPluginConfigRead: Get => sys_plugins_config_get_handler),
        route!(privileged SysPluginConfigWrite: Put => sys_plugins_config_put_handler),
    ]),
    // Extensibility v2: admin network grants. See src/plugins/grants.rs.
    resource!("/plugins/{name}/grants" => [
        route!(privileged SysPluginGrantsRead: Get => sys_plugins_grants_get_handler),
        route!(privileged SysPluginGrantsWrite: Put => sys_plugins_grants_put_handler),
        route!(privileged SysPluginGrantsDelete: Delete => sys_plugins_grants_delete_handler),
    ]),
    resource!("/plugins/{name}/reload" => [route!(privileged SysPluginReload: Post => sys_plugins_reload_handler)]),
    resource!("/plugins/{name}/versions" => [route!(privileged SysPluginVersions: Get => sys_plugins_versions_list_handler)]),
    resource!("/plugins/{name}/versions/{version}/activate" => [
        route!(privileged SysPluginVersionActivate: Post => sys_plugins_versions_activate_handler),
    ]),
    resource!("/plugins/{name}/versions/{version}" => [
        route!(privileged SysPluginVersionDelete: Delete => sys_plugins_versions_delete_handler),
    ]),
    resource!("/plugins/{name}/surface" => [route!(privileged SysPluginSurface: Get => sys_plugins_surface_get_handler)]),
    resource!("/plugins/{name}/versions/{version}/asset/{sha256}" => [
        route!(privileged SysPluginAsset: Get => sys_plugins_asset_get_handler),
    ]),
    resource!("/seal" => [
        route!(privileged SysSeal: Post => sys_seal_request_handler),
        route!(privileged SysSeal: Put => sys_seal_request_handler),
    ]),
    resource!("/unseal" => [
        route!(public_probe Post => sys_unseal_request_handler,
            "the unseal key share is the credential: no token can be validated while the barrier is sealed"),
        route!(public_probe Put => sys_unseal_request_handler,
            "the unseal key share is the credential: no token can be validated while the barrier is sealed"),
    ]),
    resource!("/dashboard/summary" => [route!(routed Get => sys_dashboard_summary_request_handler, "sys/dashboard/summary")]),
    resource!("/mounts" => [route!(routed Get => sys_list_mounts_request_handler, "sys/mounts")]),
    resource!("/mounts/{path:.*}" => [
        route!(routed Get => sys_list_mounts_request_handler, "sys/mounts"),
        route!(routed Post => sys_mount_request_handler, "sys/mounts/{path}"),
        route!(routed Delete => sys_unmount_request_handler, "sys/mounts/{path}"),
    ]),
    resource!("/remount" => [
        route!(routed Post => sys_remount_request_handler, "sys/remount"),
        route!(routed Put => sys_remount_request_handler, "sys/remount"),
    ]),
    resource!("/auth" => [route!(routed Get => sys_list_auth_mounts_request_handler, "sys/auth")]),
    resource!("/auth/{path:.*}" => [
        route!(routed Get => sys_list_auth_mounts_request_handler, "sys/auth"),
        route!(routed Post => sys_auth_enable_request_handler, "sys/auth/{path}"),
        route!(routed Delete => sys_auth_disable_request_handler, "sys/auth/{path}"),
    ]),
    resource!("/policy" => [route!(routed Get => sys_list_policy_request_handler, "sys/policy")]),
    resource!("/policy/{name:.*}" => [
        route!(routed Get => sys_read_policy_request_handler, "sys/policy/{name}"),
        route!(routed Post => sys_write_policy_request_handler, "sys/policy/{name}"),
        route!(routed Delete => sys_delete_policy_request_handler, "sys/policy/{name}"),
    ]),
    resource!("/policies/acl" => [route!(routed Get => sys_list_policies_request_handler, "sys/policies/acl")]),
    resource!("/policies/acl/{name:.*}" => [
        route!(routed Get => sys_read_policies_request_handler, "sys/policies/acl/{name}"),
        route!(routed Post => sys_write_policies_request_handler, "sys/policies/acl/{name}"),
        route!(routed Delete => sys_delete_policies_request_handler, "sys/policies/acl/{name}"),
    ]),
    resource!("/audit/events" => [route!(routed Get => sys_audit_events_request_handler, "sys/audit/events")]),
    resource!("/audit" => [route!(routed Get => sys_audit_list_request_handler, "sys/audit")]),
    resource!("/audit/{path:.*}" => [
        route!(routed Post => sys_audit_enable_request_handler, "sys/audit/{path}"),
        route!(routed Delete => sys_audit_disable_request_handler, "sys/audit/{path}"),
    ]),
    resource!("/cache/flush" => [route!(routed Post => sys_cache_flush_request_handler, "sys/cache/flush")]),
    resource!("/owner/backfill" => [route!(routed Post => sys_owner_backfill_request_handler, "sys/owner/backfill")]),
    // Multi-tenancy namespace routes. Like the owner routes above, these live
    // on the sys backend's logical route table but need an explicit HTTP shim
    // — otherwise the `/v1/sys` scope 404s them before they reach the
    // `/v1/{path:.*}` logical catch-all, so they only worked in embedded vault
    // mode. `LIST` is the verb the clients use for list ops.
    resource!("/namespaces" => [
        route!(routed List => sys_namespace_list_request_handler, "sys/namespaces"),
        route!(routed Get => sys_namespace_list_request_handler, "sys/namespaces"),
    ]),
    // Caller-introspecting namespace list. Distinct literal from
    // `/namespaces/{path:.*}` (which cannot match `-self`), but registered
    // first so the intent stays obvious.
    resource!("/namespaces-self" => [route!(routed Get => sys_namespaces_self_request_handler, "sys/namespaces-self")]),
    // Cache-coherence channel. `GET` only; the long-poll and the ETag live in
    // the handler.
    resource!("/cache/version" => [route!(routed Get => sys_cache_version_handler, "sys/cache/version")]),
    // Bulk counterpart to the LIST above. Same reasoning as `-self`.
    resource!("/namespaces-info" => [route!(routed Get => sys_namespaces_info_request_handler, "sys/namespaces-info")]),
    resource!("/namespaces/{path:.*}" => [
        route!(routed Get => sys_namespace_path_request_handler, "sys/namespaces/{path}"),
        route!(routed Post => sys_namespace_path_request_handler, "sys/namespaces/{path}"),
        route!(routed Put => sys_namespace_path_request_handler, "sys/namespaces/{path}"),
        route!(routed Delete => sys_namespace_path_request_handler, "sys/namespaces/{path}"),
    ]),
    resource!("/namespace-links" => [
        route!(routed List => sys_namespace_links_request_handler, "sys/namespace-links"),
        route!(routed Get => sys_namespace_links_request_handler, "sys/namespace-links"),
        route!(routed Post => sys_namespace_links_request_handler, "sys/namespace-links"),
    ]),
    resource!("/namespace-links/{id}" => [
        route!(routed Get => sys_namespace_link_path_request_handler, "sys/namespace-links/{id}"),
        route!(routed Delete => sys_namespace_link_path_request_handler, "sys/namespace-links/{id}"),
    ]),
    // Per-principal namespace assignment (login-restriction).
    resource!("/identity/ns-assignment" => [
        route!(routed List => sys_ns_assignment_list_request_handler, "sys/identity/ns-assignment"),
        route!(routed Get => sys_ns_assignment_list_request_handler, "sys/identity/ns-assignment"),
    ]),
    resource!("/identity/ns-assignment/{path:.*}" => [
        route!(routed Get => sys_ns_assignment_path_request_handler, "sys/identity/ns-assignment/{path}"),
        route!(routed Post => sys_ns_assignment_path_request_handler, "sys/identity/ns-assignment/{path}"),
        route!(routed Put => sys_ns_assignment_path_request_handler, "sys/identity/ns-assignment/{path}"),
        route!(routed Delete => sys_ns_assignment_path_request_handler, "sys/identity/ns-assignment/{path}"),
    ]),
    // IP-based DoS / request-abuse protection. Canonical form is
    // `v2/sys/dos/*`; the v1 mirror is incidental (shared table).
    resource!("/dos/config" => [
        route!(routed Get => sys_dos_config_request_handler, "sys/dos/config"),
        route!(routed Post => sys_dos_config_request_handler, "sys/dos/config"),
        route!(routed Put => sys_dos_config_request_handler, "sys/dos/config"),
    ]),
    resource!("/dos/stats" => [route!(routed Get => sys_dos_stats_request_handler, "sys/dos/stats")]),
    resource!("/dos/bans/{ip:.*}" => [
        route!(routed Post => sys_dos_ban_request_handler, "sys/dos/bans/{ip}"),
        route!(routed Put => sys_dos_ban_request_handler, "sys/dos/bans/{ip}"),
        route!(routed Delete => sys_dos_ban_request_handler, "sys/dos/bans/{ip}"),
    ]),
    // Owner self-claim and admin transfer routes, shimmed for the same
    // reason as the namespace routes.
    resource!("/kv-owner/transfer" => [route!(routed Post => sys_kv_owner_transfer_request_handler, "sys/kv-owner/transfer")]),
    resource!("/kv-owner/claim" => [route!(routed Post => sys_kv_owner_claim_request_handler, "sys/kv-owner/claim")]),
    resource!("/resource-owner/transfer" => [
        route!(routed Post => sys_resource_owner_transfer_request_handler, "sys/resource-owner/transfer"),
    ]),
    resource!("/asset-group-owner/transfer" => [
        route!(routed Post => sys_asset_group_owner_transfer_request_handler, "sys/asset-group-owner/transfer"),
    ]),
    resource!("/file-owner/transfer" => [
        route!(routed Post => sys_file_owner_transfer_request_handler, "sys/file-owner/transfer"),
    ]),
    resource!("/internal/ui/mounts" => [
        route!(routed_unauthenticated Get => sys_get_internal_ui_mounts_request_handler, "sys/internal/ui/mounts",
            "Vault-compatible UI bootstrap in the system backend's unauth_paths; the handler judges any token itself and lists no mount to an anonymous caller"),
    ]),
    resource!("/internal/ui/mounts/{name:.*}" => [
        route!(routed_unauthenticated Get => sys_get_internal_ui_mount_request_handler, "sys/internal/ui/mounts/{name}",
            "Vault-compatible UI bootstrap in the system backend's unauth_paths; the handler refuses an anonymous caller and checks mount access for a token"),
    ]),
    // MCP Access (features/mcp-access.md): HTTP shims over the sys backend's
    // `mcp/*` logical routes (`crates/bv-kernel/.../mcp.rs`).
    resource!("/mcp/config" => [
        route!(routed Get => sys_mcp_config_request_handler, "sys/mcp/config"),
        route!(routed Post => sys_mcp_config_request_handler, "sys/mcp/config"),
    ]),
    resource!("/mcp/apps" => [
        route!(routed List => sys_mcp_apps_list_request_handler, "sys/mcp/apps"),
        route!(routed Get => sys_mcp_apps_list_request_handler, "sys/mcp/apps"),
    ]),
    resource!("/mcp/apps/{name}" => [
        route!(routed Get => sys_mcp_app_request_handler, "sys/mcp/apps/{name}"),
        route!(routed Post => sys_mcp_app_request_handler, "sys/mcp/apps/{name}"),
        route!(routed Delete => sys_mcp_app_request_handler, "sys/mcp/apps/{name}"),
    ]),
    resource!("/mcp/apps/{name}/machine-waiver" => [
        route!(routed Post => sys_mcp_app_waiver_request_handler, "sys/mcp/apps/{name}/machine-waiver"),
        route!(routed Delete => sys_mcp_app_waiver_request_handler, "sys/mcp/apps/{name}/machine-waiver"),
    ]),
    resource!("/mcp/tokens" => [
        route!(routed List => sys_mcp_tokens_list_request_handler, "sys/mcp/tokens"),
        route!(routed Get => sys_mcp_tokens_list_request_handler, "sys/mcp/tokens"),
    ]),
    resource!("/mcp/tokens/{accessor}" => [
        route!(routed Delete => sys_mcp_token_delete_request_handler, "sys/mcp/tokens/{accessor}"),
    ]),
];

/// Served under `/v2/sys` only, after [`SHARED`].
pub(crate) const V2_ONLY: &[ResourceSpec] = &[
    // The body-size limit is enforced by the per-route `JsonConfig`; when
    // `Config` is not available (tests without a loaded config) the default
    // 32 MiB plus the handler-level operation-count check applies.
    resource!("/batch", body_limit: BodyLimit::Json(default_batch_body_limit()) => [
        route!(dispatch Post => crate::batch::sys_batch_v2_request_handler,
            "carries caller-chosen logical operations; each is judged by pre_route on its own path through Core::handle_request"),
    ]),
    // Effective-capabilities lookup.
    resource!("/capabilities-self" => [
        route!(routed Post => sys_capabilities_self_request_handler, "sys/capabilities-self"),
    ]),
    // Policy effectivity test-case persistence (graphical builder regression
    // gate). Sibling to capabilities-self.
    resource!("/policy-tests/{name:.*}" => [
        route!(routed Get => sys_policy_tests_read_request_handler, "sys/policy-tests/{name}"),
        route!(routed Post => sys_policy_tests_write_request_handler, "sys/policy-tests/{name}"),
    ]),
    // Revoke every MCP token minted for one local pairing.
    resource!("/mcp/pairings/{id}" => [
        route!(routed Delete => sys_mcp_pairing_delete_request_handler, "sys/mcp/pairings/{id}"),
    ]),
    // Credential-provider grant and entity-data purge
    // (features/self-accounts.md §4.5, §4.7).
    resource!("/plugins/{name}/grants/credential-provider" => [
        route!(privileged SysPluginProviderGrantRead: Get => sys_plugins_provider_grant_get_handler),
        route!(privileged SysPluginProviderGrantWrite: Put => sys_plugins_provider_grant_put_handler),
        route!(privileged SysPluginProviderGrantDelete: Delete => sys_plugins_provider_grant_delete_handler),
    ]),
    resource!("/plugins/{name}/entity-data" => [
        route!(privileged SysPluginEntityDataUsage: Get => sys_plugins_entity_data_get_handler),
    ]),
    resource!("/plugins/{name}/entity-data/{entity_id}" => [
        route!(privileged SysPluginEntityDataPurge: Delete => sys_plugins_entity_data_delete_handler),
    ]),
    // HSM seal status (features/hsm-support.md). Read-only.
    resource!("/hsm/status" => [route!(routed Get => sys_hsm_status_request_handler, "sys/hsm/status")]),
    // Per-principal default resource accounts (Resource Connect). The `self`
    // and bare-list resources precede the `{path:.*}` wildcard so they win.
    resource!("/identity/default-account" => [
        route!(routed List => sys_default_account_list_request_handler, "sys/identity/default-account"),
        route!(routed Get => sys_default_account_list_request_handler, "sys/identity/default-account"),
    ]),
    resource!("/identity/default-account/self" => [
        route!(routed Get => sys_default_account_self_request_handler, "sys/identity/default-account/self"),
        route!(routed Post => sys_default_account_self_request_handler, "sys/identity/default-account/self"),
        route!(routed Put => sys_default_account_self_request_handler, "sys/identity/default-account/self"),
    ]),
    // Self-service profile (features/self-service-profile.md), caller-scoped:
    // each handler resolves the principal from the request token.
    resource!("/identity/profile/self" => [
        route!(routed Get => sys_profile_self_request_handler, "sys/identity/profile/self"),
    ]),
    resource!("/identity/profile/self/password" => [
        route!(routed Post => sys_profile_self_password_request_handler, "sys/identity/profile/self/password"),
        route!(routed Put => sys_profile_self_password_request_handler, "sys/identity/profile/self/password"),
    ]),
    resource!("/identity/profile/self/contact" => [
        route!(routed Post => sys_profile_self_contact_request_handler, "sys/identity/profile/self/contact"),
        route!(routed Put => sys_profile_self_contact_request_handler, "sys/identity/profile/self/contact"),
    ]),
    resource!("/identity/default-account/{path:.*}" => [
        route!(routed Get => sys_default_account_path_request_handler, "sys/identity/default-account/{path}"),
        route!(routed Post => sys_default_account_path_request_handler, "sys/identity/default-account/{path}"),
        route!(routed Put => sys_default_account_path_request_handler, "sys/identity/default-account/{path}"),
        route!(routed Delete => sys_default_account_path_request_handler, "sys/identity/default-account/{path}"),
    ]),
    // Per-principal SSH security keys (features/connect-mfa-and-fido2-ssh.md).
    // Same shape and order as the default-account routes: the literal `/self`
    // must precede the `{path:.*}` catch-all or the catch-all swallows it.
    resource!("/identity/ssh-security-key" => [
        route!(routed List => sys_ssh_security_key_list_request_handler, "sys/identity/ssh-security-key"),
        route!(routed Get => sys_ssh_security_key_list_request_handler, "sys/identity/ssh-security-key"),
    ]),
    resource!("/identity/ssh-security-key/self" => [
        route!(routed Get => sys_ssh_security_key_self_request_handler, "sys/identity/ssh-security-key/self"),
        route!(routed Post => sys_ssh_security_key_self_request_handler, "sys/identity/ssh-security-key/self"),
        route!(routed Put => sys_ssh_security_key_self_request_handler, "sys/identity/ssh-security-key/self"),
        route!(routed Delete => sys_ssh_security_key_self_request_handler, "sys/identity/ssh-security-key/self"),
    ]),
    resource!("/identity/ssh-security-key/{path:.*}" => [
        route!(routed Get => sys_ssh_security_key_path_request_handler, "sys/identity/ssh-security-key/{path}"),
        route!(routed Post => sys_ssh_security_key_path_request_handler, "sys/identity/ssh-security-key/{path}"),
        route!(routed Put => sys_ssh_security_key_path_request_handler, "sys/identity/ssh-security-key/{path}"),
        route!(routed Delete => sys_ssh_security_key_path_request_handler, "sys/identity/ssh-security-key/{path}"),
    ]),
];
