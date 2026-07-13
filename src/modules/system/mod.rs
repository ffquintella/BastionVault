//! The system module is mainly used to configure BastionVault itself. For instance, the 'mount/'
//! path is provided here to support mounting new modules in BastionVault via RESTful HTTP request.

pub mod denial_audit_store;

use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Weak},
};

use serde_json::{from_value, json, Map, Value};

use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        field::FieldTrait, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    modules::{
        auth::{AuthModule, AUTH_TABLE_TYPE},
        identity::IdentityModule,
        namespace::{
            router::namespace_header_from_map, NamespaceModule, NamespaceQuotas, NamespaceStore,
            NAMESPACE_MODULE_NAME,
        },
        policy::{acl::ACL, PolicyModule},
        resource_group::ResourceGroupModule,
        Module,
    },
    mount::{MountEntry, MOUNT_TABLE_TYPE},
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    bv_error_response_status, bv_error_string,
    storage::StorageEntry,
};

/// Per-event row in the aggregated audit trail. One instance per
/// history entry we pull from a subsystem's change log; we build a
/// Vec of these across policies, identity groups, and asset groups,
/// then serialize newest-first in `handle_audit_events`.
struct AuditEventBuilder {
    ts: String,
    user: String,
    op: String,
    category: String,
    target: String,
    changed_fields: Vec<String>,
    summary: String,
}

impl AuditEventBuilder {
    fn into_value(self) -> Value {
        let mut m = Map::new();
        m.insert("ts".into(), Value::String(self.ts));
        m.insert("user".into(), Value::String(self.user));
        m.insert("op".into(), Value::String(self.op));
        m.insert("category".into(), Value::String(self.category));
        m.insert("target".into(), Value::String(self.target));
        m.insert(
            "changed_fields".into(),
            Value::Array(
                self.changed_fields
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        m.insert("summary".into(), Value::String(self.summary));
        Value::Object(m)
    }
}

static SYSTEM_BACKEND_HELP: &str = r#"
The system backend is built-in to BastionVault and cannot be remounted or
unmounted. It contains the paths that are used to configure BastionVault itself
as well as perform core operations.
"#;

pub struct SystemModule {
    pub name: String,
    pub backend: Arc<SystemBackend>,
}

pub struct SystemBackend {
    pub core: Arc<Core>,
    pub self_ptr: Weak<SystemBackend>,
}

#[maybe_async::maybe_async]
impl SystemBackend {
    pub fn new(core: Arc<Core>) -> Arc<Self> {
        let system_backend = SystemBackend { core, self_ptr: Weak::default() };

        system_backend.wrap()
    }

    pub fn wrap(self) -> Arc<Self> {
        let mut wrap_self = Arc::new(self);
        let weak_self = Arc::downgrade(&wrap_self);
        unsafe {
            let ptr_self = Arc::into_raw(wrap_self) as *mut Self;
            (*ptr_self).self_ptr = weak_self;
            wrap_self = Arc::from_raw(ptr_self);
        }

        wrap_self
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let sys_backend_mount_table = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_mount_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_mount_delete = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_remount = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_renew = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_revoke = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_revoke_prefix = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_auth_table = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_auth_enable = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_auth_disable = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_list1 = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_list2 = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_delete = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policies_list1 = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policies_list2 = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policies_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policies_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policies_delete = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policies_history = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_kv_owner_transfer = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_kv_owner_claim = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_resource_owner_transfer = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_asset_group_owner_transfer = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_file_owner_transfer = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_audit_table = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_audit_events = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_audit_enable = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_audit_disable = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_raw_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_raw_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_raw_delete = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_internal_ui_mounts_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_internal_ui_mount_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_cache_flush = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_capabilities_self = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_test = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_tests_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_policy_tests_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_dashboard_summary = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_hsm_status = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_owner_backfill = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_sso_settings_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_sso_settings_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_sso_providers = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_namespace_list = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_namespace_self_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_namespace_self_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_namespace_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_namespace_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_namespace_delete = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nslink_list = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nslink_create = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nslink_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nslink_delete = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nsassign_list = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nsassign_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nsassign_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_nsassign_delete = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_defacct_list = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_defacct_self = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_defacct_read = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_defacct_write = self.self_ptr.upgrade().unwrap().clone();
        let sys_backend_defacct_delete = self.self_ptr.upgrade().unwrap().clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: "mounts$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_mount_table.handle_mount_table}
                    ]
                },
                {
                    pattern: "mounts/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: r#"The path to mount to. Example: "aws/east""#
                        },
                        "type": {
                            field_type: FieldType::Str,
                            description: r#"The type of the backend. Example: "kv""#
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: r#"User-friendly description for this mount."#
                        },
                        "options": {
                            field_type: FieldType::Map,
                            required: false,
                            description: r#"The options to pass into the backend. Should be a json object with string keys and values."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_mount_write.handle_mount},
                        {op: Operation::Delete, handler: sys_backend_mount_delete.handle_unmount}
                    ]
                },
                {
                    pattern: "remount",
                    fields: {
                        "from": {
                            field_type: FieldType::Str
                        },
                        "to": {
                            field_type: FieldType::Str
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_remount.handle_remount}
                    ]
                },
                {
                    pattern: "renew/(?P<lease_id>.+)",
                    fields: {
                        "lease_id": {
                            field_type: FieldType::Str,
                            description: "The lease identifier to renew. This is included with a lease."
                        },
                        "increment": {
                            field_type: FieldType::Int,
                            description: "The desired increment in seconds to the lease"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_renew.handle_renew}
                    ]
                },
                {
                    pattern: "revoke/(?P<lease_id>.+)",
                    fields: {
                        "lease_id": {
                            field_type: FieldType::Str,
                            description: "The lease identifier to renew. This is included with a lease."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_revoke.handle_revoke}
                    ]
                },
                {
                    pattern: "revoke-prefix/(?P<prefix>.+)",
                    fields: {
                        "prefix": {
                            field_type: FieldType::Str,
                            description: r#"The path to revoke keys under. Example: "prod/aws/ops""#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_revoke_prefix.handle_revoke_prefix}
                    ]
                },
                {
                    pattern: "auth$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_auth_table.handle_auth_table}
                    ]
                },
                {
                    pattern: "auth/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: r#"The path to mount to. Cannot be delimited. Example: "user""#
                        },
                        "type": {
                            field_type: FieldType::Str,
                            description: r#"The type of the backend. Example: "userpass""#
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: r#"User-friendly description for this crential backend."#
                        },
                        "options": {
                            field_type: FieldType::Map,
                            required: false,
                            description: r#"The options to pass into the backend. Should be a json object with string keys and values."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_auth_enable.handle_auth_enable},
                        {op: Operation::Delete, handler: sys_backend_auth_disable.handle_auth_disable}
                    ]
                },
                {
                    pattern: "policy/?$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policy_list1.handle_policy_list},
                        {op: Operation::List, handler: sys_backend_policy_list2.handle_policy_list}
                    ]
                },
                {
                    pattern: "policy/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: r#"The name of the policy. Example: "ops""#
                        },
                        "policy": {
                            field_type: FieldType::Str,
                            description: r#"The rules of the policy. Either given in HCL or JSON format."#
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policy_read.handle_policy_read},
                        {op: Operation::Write, handler: sys_backend_policy_write.handle_policy_write},
                        {op: Operation::Delete, handler: sys_backend_policy_delete.handle_policy_delete}
                    ]
                },
                {
                    pattern: "policies/acl/?$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policies_list1.handle_policy_list},
                        {op: Operation::List, handler: sys_backend_policies_list2.handle_policy_list}
                    ]
                },
                {
                    pattern: r"policies/acl/(?P<name>[^/]+)/history/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: r#"The name of the policy."#
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policies_history.handle_policy_history}
                    ]
                },
                {
                    // Stateless dry-run for the graphical policy
                    // builder/validator: parse a *draft* HCL policy and
                    // evaluate `(path, capability)` cases against it
                    // without ever persisting. Shares the
                    // `sys/policies/acl/*` ACL prefix so a policy author
                    // is already authorized. MUST be ordered before the
                    // `policies/acl/(?P<name>.+)` catch-all below; as a
                    // result `test` is a reserved policy name (writing a
                    // policy literally named "test" is not possible — see
                    // features/policy-builder-validator.md).
                    pattern: r"policies/acl/test$",
                    fields: {
                        "policy": {
                            field_type: FieldType::Str,
                            description: r#"The draft policy to evaluate, in HCL (or base64-encoded HCL)."#
                        },
                        "cases": {
                            field_type: FieldType::Array,
                            description: r#"Array of { path, capability } cases to evaluate against the draft."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_policy_test.handle_policy_test}
                    ]
                },
                {
                    // Savable effectivity test cases attached to a policy
                    // (the builder's regression gate). Stored alongside,
                    // not inside, the policy HCL — see
                    // features/policy-builder-validator.md. v2-only HTTP
                    // shim registered under /v2/sys.
                    pattern: r"policy-tests/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: r#"The name of the policy the test cases belong to."#
                        },
                        "cases": {
                            field_type: FieldType::Array,
                            description: r#"Array of { path, capability, expect, note? } test cases."#
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policy_tests_read.handle_policy_tests_read},
                        {op: Operation::Write, handler: sys_backend_policy_tests_write.handle_policy_tests_write}
                    ]
                },
                {
                    // Admin-only: transfer ownership of a KV secret to a
                    // different entity. Gated by the usual ACL on
                    // `sys/kv-owner/transfer`. Body:
                    //   { path, new_owner_entity_id }
                    pattern: r"kv-owner/transfer$",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: "Full logical path of the KV secret (e.g., secret/foo/bar or secret/data/foo/bar)."
                        },
                        "new_owner_entity_id": {
                            field_type: FieldType::Str,
                            description: "The entity_id that will become the new owner."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_kv_owner_transfer.handle_kv_owner_transfer}
                    ]
                },
                {
                    // Claim ownership of a currently *unowned* KV
                    // secret. Gated by the ACL on
                    // `sys/kv-owner/claim` — typical policy grants this
                    // to any authenticated entity, but the handler
                    // refuses to overwrite an existing owner so it
                    // cannot be used to steal a path. The caller's
                    // entity_id (or display_name fallback) is stamped
                    // as the owner.
                    pattern: r"kv-owner/claim$",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: "Full logical path of the KV secret (e.g., secret/foo/bar or secret/data/foo/bar)."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_kv_owner_claim.handle_kv_owner_claim}
                    ]
                },
                {
                    // Admin-only: transfer ownership of a resource.
                    // Body: { resource, new_owner_entity_id }
                    pattern: r"resource-owner/transfer$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            description: "Resource name."
                        },
                        "new_owner_entity_id": {
                            field_type: FieldType::Str,
                            description: "The entity_id that will become the new owner."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_resource_owner_transfer.handle_resource_owner_transfer}
                    ]
                },
                {
                    // Admin-only: transfer ownership of an asset group.
                    // Body: { name, new_owner_entity_id }
                    pattern: r"asset-group-owner/transfer$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Asset group name."
                        },
                        "new_owner_entity_id": {
                            field_type: FieldType::Str,
                            description: "The entity_id that will become the new owner."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_asset_group_owner_transfer.handle_asset_group_owner_transfer}
                    ]
                },
                {
                    // Admin-only: transfer ownership of a file resource.
                    // Body: { id, new_owner_entity_id }
                    pattern: r"file-owner/transfer$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            description: "File id (UUID)."
                        },
                        "new_owner_entity_id": {
                            field_type: FieldType::Str,
                            description: "The entity_id that will become the new owner."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_file_owner_transfer.handle_file_owner_transfer}
                    ]
                },
                {
                    pattern: "policies/acl/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: r#"The name of the policy. Example: "ops""#
                        },
                        "policy": {
                            field_type: FieldType::Str,
                            description: r#"The rules of the policy. Either given in HCL or JSON format."#
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policies_read.handle_policy_read},
                        {op: Operation::Write, handler: sys_backend_policies_write.handle_policy_write},
                        {op: Operation::Delete, handler: sys_backend_policies_delete.handle_policy_delete}
                    ]
                },
                {
                    pattern: "audit$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_audit_table.handle_audit_table}
                    ]
                },
                {
                    // Unified audit trail — aggregates per-subsystem
                    // history logs (policies, identity groups, asset
                    // groups, resources) into a flat newest-first
                    // timeline. Intended for the Admin → Audit GUI
                    // page. Routed ahead of the generic
                    // `audit/(?P<path>.+)` catch-all so it matches.
                    pattern: "audit/events/?$",
                    fields: {
                        "from": {
                            required: false,
                            field_type: FieldType::Str,
                            description: "Optional RFC3339 lower-bound timestamp."
                        },
                        "to": {
                            required: false,
                            field_type: FieldType::Str,
                            description: "Optional RFC3339 upper-bound timestamp."
                        },
                        "limit": {
                            required: false,
                            field_type: FieldType::Int,
                            description: "Maximum number of events to return (default 500)."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_audit_events.handle_audit_events}
                    ]
                },
                {
                    pattern: "audit/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: r#"The name of the backend. Cannot be delimited. Example: "mysql""#
                        },
                        "type": {
                            field_type: FieldType::Str,
                            description: r#"The type of the backend. Example: "mysql""#
                        },
                        "description": {
                            required: false,
                            field_type: FieldType::Str,
                            description: r#"User-friendly description for this audit backend."#
                        },
                        "options": {
                            field_type: FieldType::Map,
                            description: r#"Configuration options for the audit backend."#
                        },
                        "mirror": {
                            required: false,
                            field_type: FieldType::Bool,
                            description: r#"Root-only superuser mirror: when true on a root-namespace device, it additionally receives every namespace's audit stream."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_audit_enable.handle_audit_enable},
                        {op: Operation::Delete, handler: sys_backend_audit_disable.handle_audit_disable}
                    ]
                },
                {
                    pattern: "raw/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str
                        },
                        "value": {
                            field_type: FieldType::Str
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_raw_read.handle_raw_read},
                        {op: Operation::Write, handler: sys_backend_raw_write.handle_raw_write},
                        {op: Operation::Delete, handler: sys_backend_raw_delete.handle_raw_delete}
                    ]
                },
                {
                    pattern: "internal/ui/mounts",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_internal_ui_mounts_read.handle_internal_ui_mounts_read}
                    ]
                },
                {
                    pattern: "internal/ui/mounts/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: r#"The path of the mount."#
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_internal_ui_mount_read.handle_internal_ui_mount_read}
                    ]
                },
                {
                    // Report the calling token's effective capabilities on a
                    // set of paths, so the GUI can filter affordances it must
                    // not offer (e.g. hide credential values when the caller
                    // holds only `connect`, not `read`). Vault-compatible
                    // shape. v2-only (HTTP shim registered under /v2/sys).
                    pattern: "capabilities-self$",
                    fields: {
                        "paths": {
                            field_type: FieldType::Array,
                            description: r#"Paths to evaluate the caller's capabilities against."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_capabilities_self.handle_capabilities_self}
                    ]
                },
                {
                    // One-shot operational snapshot for the GUI Dashboard
                    // landing page: seal state + ACL-gated mount / policy /
                    // entity counts + a 24h audit-event total. Read-only;
                    // HTTP shim registered under /v1/sys.
                    pattern: "dashboard/summary$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_dashboard_summary.handle_dashboard_summary}
                    ]
                },
                {
                    // HSM seal status: seal type, backend, device serial,
                    // cluster epoch, enrolled-node count, recovery posture.
                    // Read-only, no secret material. HTTP shim under /v2/sys.
                    pattern: "hsm/status$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_hsm_status.handle_hsm_status}
                    ]
                },
                {
                    // Flush every in-memory cache (policy / token /
                    // secret) and zeroize held payloads. Sudo-gated.
                    // Intended for operator use after a revocation
                    // storm or suspected compromise; the vault will
                    // repopulate lazily.
                    pattern: "cache/flush$",
                    operations: [
                        {op: Operation::Write, handler: sys_backend_cache_flush.handle_cache_flush}
                    ]
                },
                {
                    // Admin-only: stamp ownership on currently-unowned
                    // KV paths and/or resource names. Intended as the
                    // one-shot migration tool for deployments that were
                    // running before per-user-scoping landed (owner
                    // records did not exist, so `owner`/`shared` ACL
                    // scopes deny those objects until they are claimed).
                    // Body:
                    //   { entity_id, resources?, kv_paths?, dry_run? }
                    // Only unowned targets are touched — existing
                    // owners are never overwritten (use the
                    // `*-owner/transfer` endpoints for that).
                    pattern: "owner/backfill$",
                    fields: {
                        "entity_id": {
                            field_type: FieldType::Str,
                            description: "Entity id to stamp as owner on every currently-unowned target in the request. Use 'root' for admin-managed objects."
                        },
                        "resources": {
                            field_type: FieldType::Array,
                            description: "Resource names to backfill."
                        },
                        "kv_paths": {
                            field_type: FieldType::Array,
                            description: "KV logical paths to backfill (e.g., 'secret/data/foo')."
                        },
                        "file_ids": {
                            field_type: FieldType::Array,
                            description: "File-resource ids (UUIDs) to backfill."
                        },
                        "dry_run": {
                            field_type: FieldType::Bool,
                            default: false,
                            description: "When true, returns what would be stamped without writing any owner records."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_owner_backfill.handle_owner_backfill}
                    ]
                },
                {
                    // Global SSO enable/disable toggle. Root-gated —
                    // flipping this off makes `sys/sso/providers` return
                    // an empty list, which the GUI uses to hide the
                    // SSO login tab entirely.
                    pattern: "sso/settings$",
                    fields: {
                        "enabled": {
                            field_type: FieldType::Bool,
                            default: false,
                            description: "When true, configured SSO backends are advertised via sys/sso/providers."
                        }
                    },
                    operations: [
                        {op: Operation::Read,  handler: sys_backend_sso_settings_read.handle_sso_settings_read},
                        {op: Operation::Write, handler: sys_backend_sso_settings_write.handle_sso_settings_write}
                    ]
                },
                {
                    // Unauthenticated discovery endpoint for the login
                    // page: returns a list of configured SSO backends
                    // by mount path + operator-supplied description.
                    // Returns an empty list when the toggle is off
                    // or when no SSO-capable backends are mounted.
                    // Deliberately does NOT expose provider config
                    // (discovery URL, client id) — only display metadata.
                    pattern: "sso/providers$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_sso_providers.handle_sso_providers}
                    ]
                },
                {
                    // Multi-tenancy: operate on the caller's *own* namespace —
                    // the one named by the X-BastionVault-Namespace header, or
                    // the root namespace when the request is unscoped. LIST
                    // returns the caller namespace's direct children; READ/WRITE
                    // read and update the caller namespace's own config. This is
                    // the only supported way to configure the *root* namespace:
                    // the by-path catch-all below requires a non-empty path, so
                    // the root record (path "") is unreachable through it.
                    pattern: "namespaces/?$",
                    fields: {
                        "max_storage_bytes": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max barrier-encrypted bytes (0 = unlimited)."
                        },
                        "max_leases": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max live leases (0 = unlimited)."
                        },
                        "request_rate": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: requests/sec token-bucket rate (0 = unlimited)."
                        },
                        "max_mounts": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max mounts (0 = unlimited)."
                        },
                        "max_entities": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max identity entities (0 = unlimited)."
                        },
                        "max_child_namespaces": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max child namespaces (0 = unlimited)."
                        },
                        "child_visible_default": {
                            field_type: FieldType::Bool,
                            default: false,
                            description: "Default child_visible flag for tokens minted in this namespace. WARNING: setting this on the root namespace makes every token minted at a root login able to operate in EVERY descendant namespace."
                        }
                    },
                    operations: [
                        {op: Operation::List,  handler: sys_backend_namespace_list.handle_namespace_list},
                        {op: Operation::Read,  handler: sys_backend_namespace_self_read.handle_namespace_self_read},
                        {op: Operation::Write, handler: sys_backend_namespace_self_write.handle_namespace_self_write}
                    ],
                    help: "List child namespaces, or read/update the caller's own (root when unscoped) namespace config."
                },
                {
                    // Read / create-or-update / delete a namespace by path.
                    // `path` may be multi-segment (e.g. engineering/platform).
                    pattern: r"namespaces/(?P<path>.+)$",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Slash-delimited namespace path."
                        },
                        "max_storage_bytes": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max barrier-encrypted bytes (0 = unlimited)."
                        },
                        "max_leases": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max live leases (0 = unlimited)."
                        },
                        "request_rate": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: requests/sec token-bucket rate (0 = unlimited)."
                        },
                        "max_mounts": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max mounts (0 = unlimited)."
                        },
                        "max_entities": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max identity entities (0 = unlimited)."
                        },
                        "max_child_namespaces": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Quota: max child namespaces (0 = unlimited)."
                        },
                        "child_visible_default": {
                            field_type: FieldType::Bool,
                            default: false,
                            description: "Default child_visible flag for tokens minted in this namespace."
                        }
                    },
                    operations: [
                        {op: Operation::Read,   handler: sys_backend_namespace_read.handle_namespace_read},
                        {op: Operation::Write,  handler: sys_backend_namespace_write.handle_namespace_write},
                        {op: Operation::Delete, handler: sys_backend_namespace_delete.handle_namespace_delete}
                    ],
                    help: "Read metadata + quotas, create/update, or delete a namespace."
                },
                {
                    // Cross-tenant identity links owned by the caller's namespace
                    // (the X-BastionVault-Namespace header). List existing links
                    // or create a new one. Distinct prefix from `namespaces/` so
                    // it does not collide with the namespace catch-all pattern.
                    pattern: "namespace-links/?$",
                    fields: {
                        "label": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Human-friendly label for the link (e.g. the person's name)."
                        },
                        "members": {
                            field_type: FieldType::Array,
                            required: false,
                            description: "Array of {namespace, entity_id} objects to correlate. Each namespace must be the caller's namespace or a descendant."
                        }
                    },
                    operations: [
                        {op: Operation::List,  handler: sys_backend_nslink_list.handle_namespace_link_list},
                        {op: Operation::Write, handler: sys_backend_nslink_create.handle_namespace_link_create}
                    ],
                    help: "List or create cross-tenant identity links."
                },
                {
                    pattern: r"namespace-links/(?P<id>.+)$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Identity-link UUID."
                        }
                    },
                    operations: [
                        {op: Operation::Read,   handler: sys_backend_nslink_read.handle_namespace_link_read},
                        {op: Operation::Delete, handler: sys_backend_nslink_delete.handle_namespace_link_delete}
                    ],
                    help: "Read or delete a cross-tenant identity link."
                },
                {
                    // Per-principal namespace assignment (login-restriction).
                    // List every principal that has a restriction on record.
                    // Root-scoped: these govern *where a credential may
                    // authenticate* and are operator-authored, independent of
                    // the request's active namespace.
                    pattern: "identity/ns-assignment/?$",
                    operations: [
                        {op: Operation::List, handler: sys_backend_nsassign_list.handle_ns_assignment_list}
                    ],
                    help: "List principals that have a namespace assignment."
                },
                {
                    // Address one principal by mount + name. `mount` is a single
                    // path segment (e.g. `userpass`); `name` is the remainder
                    // (the username or role name).
                    pattern: r"identity/ns-assignment/(?P<mount>[^/]+)/(?P<name>.+)$",
                    fields: {
                        "mount": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Auth mount the principal belongs to (e.g. userpass, approle)."
                        },
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Principal name (username or role name)."
                        },
                        "namespaces": {
                            field_type: FieldType::Array,
                            required: false,
                            description: "Allowed namespace paths (canonical; \"\" = root). An empty array clears the restriction (unrestricted)."
                        }
                    },
                    operations: [
                        {op: Operation::Read,   handler: sys_backend_nsassign_read.handle_ns_assignment_read},
                        {op: Operation::Write,  handler: sys_backend_nsassign_write.handle_ns_assignment_write},
                        {op: Operation::Delete, handler: sys_backend_nsassign_delete.handle_ns_assignment_delete}
                    ],
                    help: "Read, set, or clear a principal's allowed namespaces."
                },
                {
                    // Per-principal default resource accounts (Resource Connect).
                    // List every principal that has default accounts on record.
                    // Root-scoped: operator-authored, independent of the
                    // request's active namespace.
                    pattern: "identity/default-account/?$",
                    operations: [
                        {op: Operation::List, handler: sys_backend_defacct_list.handle_default_account_list}
                    ],
                    help: "List principals that have default resource accounts."
                },
                {
                    // The *calling* principal's own default accounts, resolved
                    // from the request token. Readable by any authenticated
                    // caller (NOT root-scoped) so the Connect path can fetch the
                    // connecting operator's accounts with its own token.
                    pattern: "identity/default-account/self$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_defacct_self.handle_default_account_self}
                    ],
                    help: "Read the calling principal's default resource accounts."
                },
                {
                    // Address one principal by mount + name. `mount` is a single
                    // path segment (e.g. `userpass`); `name` is the remainder.
                    pattern: r"identity/default-account/(?P<mount>[^/]+)/(?P<name>.+)$",
                    fields: {
                        "mount": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Auth mount the principal belongs to (e.g. userpass, approle)."
                        },
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Principal name (username or role name)."
                        },
                        "linux": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Default login name on Linux/Unix/BSD SSH targets."
                        },
                        "macos": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Default login name on macOS SSH targets."
                        },
                        "windows": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Default login name on Windows RDP targets."
                        },
                        "windows_password": {
                            field_type: FieldType::SecretStr,
                            required: false,
                            description: "Optional password for the Windows RDP account. Omit to keep the stored value; empty string clears it. Never returned on read (only `has_windows_password`)."
                        }
                    },
                    operations: [
                        {op: Operation::Read,   handler: sys_backend_defacct_read.handle_default_account_read},
                        {op: Operation::Write,  handler: sys_backend_defacct_write.handle_default_account_write},
                        {op: Operation::Delete, handler: sys_backend_defacct_delete.handle_default_account_delete}
                    ],
                    help: "Read, set, or clear a principal's default resource accounts."
                }
            ],
            // NB: `identity/default-account/*` is intentionally NOT root-scoped.
            // The `self` sub-path must stay readable by any authenticated caller
            // (the Connect path resolves the connecting operator's accounts with
            // its own token), and `root_paths` glob matching is longest-prefix —
            // a `default-account/*` entry would swallow `default-account/self`.
            // Admin reads/writes are gated by policy on the explicit
            // mount/name paths instead.
            root_paths: ["mounts/*", "auth/*", "remount", "policy", "policy/*", "audit", "audit/*", "seal", "raw/*", "revoke-prefix/*", "cache/flush", "owner/backfill", "sso/settings", "namespaces", "namespaces/*", "namespace-links", "namespace-links/*", "identity/ns-assignment", "identity/ns-assignment/*"],
            unauth_paths: ["internal/ui/mounts", "internal/ui/mounts/*", "init", "seal-status", "unseal", "sso/providers"],
            help: SYSTEM_BACKEND_HELP,
        });

        backend
    }

    pub async fn handle_mount_table(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut data: Map<String, Value> = Map::new();

        // Namespace-scoped mount table when the request carries a namespace
        // header; otherwise the root mount table.
        if let Some((uuid, path)) = self.resolve_request_namespace(_req).await? {
            let registry = self.namespace_registry()?;
            for (mount_path, logical_type, description) in
                registry.list_mounts(&self.core, &uuid, &path).await?
            {
                data.insert(mount_path, json!({ "type": logical_type, "description": description }));
            }
            return Ok(Some(Response::data_response(Some(data))));
        }

        let mounts_router = self.core.mounts_router();
        let mounts = mounts_router.entries.read()?;

        for mount_entry in mounts.values() {
            let entry = mount_entry.read()?;
            let info: Value = json!({
                "type": entry.logical_type.clone(),
                "description": entry.description.clone(),
            });
            data.insert(entry.path.clone(), info);
        }

        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_mount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;
        let logical_type = req.get_data("type")?;
        let description = req.get_data_or_default("description")?;
        let options = req.get_data_or_default("options")?;

        let path = path.as_str().unwrap();
        let logical_type = logical_type.as_str().unwrap();
        let description = description.as_str().unwrap();

        if logical_type.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut me = MountEntry::new(MOUNT_TABLE_TYPE, path, logical_type, description);
        me.options = options.as_map();

        match self.resolve_request_namespace(req).await? {
            Some((uuid, ns_path)) => {
                // Quota: refuse when the namespace is already at its mount cap.
                let store = self.resolve_namespace_store()?;
                if let Some(ns) = store.get_by_path(&ns_path).await? {
                    let current = self.namespace_registry()?.mount_count(&uuid);
                    crate::modules::namespace::quota::check_capacity(
                        "mounts",
                        current,
                        ns.quotas.max_mounts,
                    )?;
                }
                self.namespace_registry()?.mount(&self.core, &uuid, &ns_path, &me).await?;
            }
            None => self.core.mount(&me).await?,
        }
        Ok(None)
    }

    pub async fn handle_unmount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let suffix = req.path.trim_start_matches("mounts/").to_string();
        if suffix.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        match self.resolve_request_namespace(req).await? {
            Some((uuid, ns_path)) => {
                self.namespace_registry()?.unmount(&self.core, &uuid, &ns_path, &suffix).await?;
            }
            None => self.core.unmount(&suffix).await?,
        }
        Ok(None)
    }

    pub async fn handle_remount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let from = req.get_data("from")?;
        let to = req.get_data("to")?;

        let from = from.as_str().unwrap();
        let to = to.as_str().unwrap();
        if from.is_empty() || to.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let from_path = sanitize_path(from);
        let to_path = sanitize_path(to);

        if let Some(me) = self.core.router.matching_mount_entry(&from_path)? {
            let mount_entry_table_type;
            {
                let mount_entry = me.read()?;

                let dst_path_match = self.core.router.matching_mount(to)?;
                if !dst_path_match.is_empty() {
                    return Err(bv_error_response_status!(409, &format!("path already in use at {dst_path_match}")));
                }

                mount_entry_table_type = mount_entry.table.clone();

                std::mem::drop(mount_entry);
            }

            match mount_entry_table_type.as_str() {
                AUTH_TABLE_TYPE => {
                    let auth_module = self.get_module::<AuthModule>("auth")?;
                    auth_module.remount_auth(&from_path, &to_path).await?;
                }
                MOUNT_TABLE_TYPE => {
                    self.core.remount(&from_path, &to_path).await?;
                }
                _ => {
                    return Err(bv_error_response_status!(409, "Unknown mount table type."));
                }
            }
        } else {
            return Err(bv_error_response_status!(409, &format!("no matching mount at {from_path}")));
        }

        Ok(None)
    }

    pub async fn handle_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let _lease_id = req.get_data("lease_id")?;
        let _increment: i32 = from_value(req.get_data("increment")?)?;
        //TODO
        Ok(None)
    }

    pub async fn handle_revoke(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let _lease_id = req.get_data("lease_id")?;
        //TODO
        Ok(None)
    }

    pub async fn handle_revoke_prefix(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let _prefix = req.get_data("prefix")?;
        Ok(None)
    }

    pub async fn handle_auth_table(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut data: Map<String, Value> = Map::new();

        let auth_module = self.get_module::<AuthModule>("auth")?;

        let mounts = auth_module.mounts_router.entries.read()?;

        for mount_entry in mounts.values() {
            let entry = mount_entry.read()?;
            let info: Value = json!({
                "type": entry.logical_type.clone(),
                "description": entry.description.clone(),
            });
            data.insert(entry.path.clone(), info);
        }

        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_auth_enable(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;
        let logical_type = req.get_data("type")?;
        let description = req.get_data_or_default("description")?;
        let options = req.get_data_or_default("options")?;

        let path = sanitize_path(path.as_str().unwrap());
        let logical_type = logical_type.as_str().unwrap();
        let description = description.as_str().unwrap();

        if logical_type.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut me = MountEntry::new(AUTH_TABLE_TYPE, &path, logical_type, description);

        me.options = options.as_map();

        let auth_module = self.get_module::<AuthModule>("auth")?;

        auth_module.enable_auth(&me).await?;

        Ok(None)
    }

    pub async fn handle_auth_disable(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path = sanitize_path(req.path.trim_start_matches("auth/"));
        if path.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let auth_module = self.get_module::<AuthModule>("auth")?;

        auth_module.disable_auth(&path).await?;

        Ok(None)
    }

    pub async fn handle_policy_list(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_list(backend, req).await
    }

    pub async fn handle_policy_read(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_read(backend, req).await
    }

    pub async fn handle_policy_write(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_write(backend, req).await
    }

    pub async fn handle_policy_delete(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_delete(backend, req).await
    }

    pub async fn handle_policy_history(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_history(backend, req).await
    }

    pub async fn handle_policy_test(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_test(backend, req).await
    }

    pub async fn handle_policy_tests_read(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_tests_read(backend, req).await
    }

    pub async fn handle_policy_tests_write(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        policy_module.handle_policy_tests_write(backend, req).await
    }

    /// Admin-only: overwrite the KV-secret owner record with a new
    /// `entity_id`. Access is gated by the usual ACL on
    /// `sys/kv-owner/transfer` — no additional handler-level
    /// authorization.
    pub async fn handle_kv_owner_transfer(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path = req
            .get_data("path")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let new_owner = req
            .get_data("new_owner_entity_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        if path.trim().is_empty() || new_owner.trim().is_empty() {
            return Err(bv_error_response_status!(
                400,
                "path and new_owner_entity_id are required"
            ));
        }

        let identity = self.get_module::<IdentityModule>("identity")?;
        let store = identity.owner_store().ok_or_else(|| {
            bv_error_response_status!(500, "owner store not initialized")
        })?;

        store.set_kv_owner(&path, &new_owner).await?;

        let mut data = Map::new();
        data.insert("path".into(), Value::String(path));
        data.insert("new_owner_entity_id".into(), Value::String(new_owner));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Claim ownership of an *unowned* KV secret. Refuses if the path
    /// is already owned — the admin transfer endpoint must be used to
    /// reassign an existing owner, so this cannot be used to steal a
    /// path. The new owner is the caller's `entity_id` (preferring
    /// `caller_audit_actor`'s fallback to `display_name` so root-token
    /// claims still stamp a useful actor).
    pub async fn handle_kv_owner_claim(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path = req
            .get_data("path")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        if path.trim().is_empty() {
            return Err(bv_error_response_status!(400, "path is required"));
        }

        let caller_id = crate::modules::identity::caller_audit_actor(req);
        if caller_id.is_empty() {
            return Err(bv_error_response_status!(
                400,
                "caller has no entity_id; cannot claim ownership"
            ));
        }

        let identity = self.get_module::<IdentityModule>("identity")?;
        let store = identity.owner_store().ok_or_else(|| {
            bv_error_response_status!(500, "owner store not initialized")
        })?;

        if let Some(existing) = store.get_kv_owner(&path).await? {
            // Refuse to overwrite. Use sys/kv-owner/transfer (admin)
            // to reassign an existing owner.
            return Err(bv_error_response_status!(
                409,
                format!(
                    "path is already owned by entity_id={}; use kv-owner/transfer to reassign",
                    existing.entity_id
                )
            ));
        }

        store.set_kv_owner(&path, &caller_id).await?;

        let mut data = Map::new();
        data.insert("path".into(), Value::String(path));
        data.insert("owner_entity_id".into(), Value::String(caller_id));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Admin-only: overwrite the file-resource owner record with a
    /// new `entity_id`. Gated by the ACL on `sys/file-owner/transfer`.
    pub async fn handle_file_owner_transfer(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req
            .get_data("id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let new_owner = req
            .get_data("new_owner_entity_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        if id.trim().is_empty() || new_owner.trim().is_empty() {
            return Err(bv_error_response_status!(
                400,
                "id and new_owner_entity_id are required"
            ));
        }

        let identity = self.get_module::<IdentityModule>("identity")?;
        let store = identity.owner_store().ok_or_else(|| {
            bv_error_response_status!(500, "owner store not initialized")
        })?;

        store.set_file_owner(&id, &new_owner).await?;

        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("new_owner_entity_id".into(), Value::String(new_owner));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Admin-only: overwrite the resource owner record with a new
    /// `entity_id`.
    pub async fn handle_resource_owner_transfer(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let resource = req
            .get_data("resource")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let new_owner = req
            .get_data("new_owner_entity_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        if resource.trim().is_empty() || new_owner.trim().is_empty() {
            return Err(bv_error_response_status!(
                400,
                "resource and new_owner_entity_id are required"
            ));
        }

        let identity = self.get_module::<IdentityModule>("identity")?;
        let store = identity.owner_store().ok_or_else(|| {
            bv_error_response_status!(500, "owner store not initialized")
        })?;

        store.set_resource_owner(&resource, &new_owner).await?;

        let mut data = Map::new();
        data.insert("resource".into(), Value::String(resource));
        data.insert("new_owner_entity_id".into(), Value::String(new_owner));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Admin-only: transfer ownership of an asset group (the
    /// resource-group store's internal representation). Access is
    /// gated by the usual ACL on `sys/asset-group-owner/transfer`.
    pub async fn handle_asset_group_owner_transfer(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let new_owner = req
            .get_data("new_owner_entity_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        if name.trim().is_empty() || new_owner.trim().is_empty() {
            return Err(bv_error_response_status!(
                400,
                "name and new_owner_entity_id are required"
            ));
        }

        let module = self.get_module::<ResourceGroupModule>("resource-group")?;
        let store = module.store().ok_or_else(|| {
            bv_error_response_status!(500, "resource-group store not initialized")
        })?;

        store.set_owner(&name, &new_owner).await?;

        let mut data = Map::new();
        data.insert("name".into(), Value::String(name));
        data.insert("new_owner_entity_id".into(), Value::String(new_owner));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_audit_table(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(broker) = self.core.audit_broker.load().as_ref().cloned() else {
            let mut data = Map::new();
            data.insert("devices".into(), Value::Array(Vec::new()));
            return Ok(Some(Response::data_response(Some(data))));
        };

        // Multi-tenancy: list only the caller's namespace devices (plus the
        // root superuser mirror, which every namespace is shown).
        let namespace =
            crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        let entries = broker.list(&namespace);
        let mut arr: Vec<Value> = Vec::with_capacity(entries.len());
        for d in entries {
            let mut m = Map::new();
            m.insert("path".into(), Value::String(d.path));
            m.insert("type".into(), Value::String(d.device_type));
            m.insert("description".into(), Value::String(d.description));
            m.insert("namespace".into(), Value::String(d.namespace));
            m.insert("mirror".into(), Value::Bool(d.mirror));
            arr.push(Value::Object(m));
        }
        let mut data = Map::new();
        data.insert("devices".into(), Value::Array(arr));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Unified audit trail. Walks every per-subsystem change-history
    /// log we already maintain — ACL policies, identity user/app
    /// groups, and asset groups (resource-group store) — and presents
    /// them as a flat newest-first list. Admin-only (gated by the ACL
    /// on `sys/audit/events`). Optional `from` / `to` query params
    /// bound the time window; `limit` caps response size (default
    /// 500).
    ///
    /// Resource-metadata history lives in the resource mount's own
    /// barrier view (`hist/<name>/…`), which isn't reachable from the
    /// system backend without routing a sub-request — it's omitted
    /// from this aggregator for now. Operators can still view per-
    /// resource history via the Resources tab's History panel.
    pub async fn handle_audit_events(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let from = req
            .get_data("from")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty());
        let to = req
            .get_data("to")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty());
        let limit = req
            .get_data("limit")
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(500) as usize;

        // When the caller supplies a `from` bound, push it into the
        // collection so the append-only stores range-scan only the
        // recent tail instead of reading all history. A malformed or
        // absent `from` falls back to the full scan (the `to`/in-memory
        // filters below still apply).
        let since = from
            .as_deref()
            .and_then(|f| chrono::DateTime::parse_from_rfc3339(f).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        let mut events = self.collect_audit_events_since(since).await;

        // Sort newest-first. Timestamps are RFC3339 strings;
        // lexicographic order matches chronological for that format.
        events.sort_by(|a, b| b.ts.cmp(&a.ts));

        // Apply from/to bounds (string comparison, which is fine for
        // RFC3339). Malformed filters are ignored rather than
        // surfacing errors — the GUI always passes well-formed values.
        let filtered: Vec<_> = events
            .into_iter()
            .filter(|e| {
                if let Some(f) = &from {
                    if e.ts < *f {
                        return false;
                    }
                }
                if let Some(t) = &to {
                    if e.ts > *t {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .collect();

        let arr = Value::Array(filtered.into_iter().map(|e| e.into_value()).collect());
        let mut data = Map::new();
        data.insert("events".into(), arr);
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Gather every change-history event across the subsystems we track
    /// (ACL policies, identity user/app groups, asset groups, shares,
    /// user/role lifecycle, file/login/SSH events) into one unsorted Vec.
    /// Shared by `handle_audit_events` (which sorts / filters / serializes
    /// it) and `handle_dashboard_summary` (which counts a 24h window).
    ///
    /// When `since` is set, restricts the result to events at or after
    /// that instant. The append-only stores (user/file/login/SSH) push
    /// the bound into a range scan over their timestamp-ordered keys, so
    /// they read only the recent tail instead of all history; the
    /// per-name history sources (policy/group/share) are small and
    /// filtered by RFC3339 timestamp in memory. Pass `None` for the full
    /// unbounded aggregation.
    ///
    /// The independent per-subsystem reads run concurrently (each is its
    /// own storage round-trip), so the wall-clock cost is the slowest
    /// single source rather than their sum.
    async fn collect_audit_events_since(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Vec<AuditEventBuilder> {
        // RFC3339 cutoff for the in-memory-filtered history sources, and
        // the matching zero-padded-nanos key for the range-scanned append
        // logs (`hist_seq` keys are nanoseconds since the epoch).
        let cutoff_rfc: Option<String> = since.map(|t| t.to_rfc3339());
        let since_key: Option<String> = since.map(Self::hist_since_key);
        let cutoff = cutoff_rfc.as_deref();
        let skey = since_key.as_deref();

        #[cfg(not(feature = "sync_handler"))]
        let groups: [Vec<AuditEventBuilder>; 10] = {
            let (policy, idgroups, assets, shares, users, files, logins, ssh_ca, ssh_sign, denials) = tokio::join!(
                self.collect_policy_events(cutoff),
                self.collect_identity_group_events(cutoff),
                self.collect_asset_group_events(cutoff),
                self.collect_share_events(cutoff),
                self.collect_user_events(skey),
                self.collect_file_events(skey),
                self.collect_login_events(skey),
                self.collect_ssh_ca_events(skey),
                self.collect_ssh_sign_events(skey),
                self.collect_denial_events(skey),
            );
            [policy, idgroups, assets, shares, users, files, logins, ssh_ca, ssh_sign, denials]
        };

        // The sync handler build cannot use `tokio::join!`; run the
        // sources sequentially (these maybe-async methods resolve to
        // plain calls under `is_sync`).
        #[cfg(feature = "sync_handler")]
        let groups: [Vec<AuditEventBuilder>; 10] = [
            self.collect_policy_events(cutoff),
            self.collect_identity_group_events(cutoff),
            self.collect_asset_group_events(cutoff),
            self.collect_share_events(cutoff),
            self.collect_user_events(skey),
            self.collect_file_events(skey),
            self.collect_login_events(skey),
            self.collect_ssh_ca_events(skey),
            self.collect_ssh_sign_events(skey),
            self.collect_denial_events(skey),
        ];

        groups.into_iter().flatten().collect()
    }

    /// ACL policy change-history. Per-name histories are small, so the
    /// `cutoff` (when set) is applied by RFC3339 timestamp in memory.
    async fn collect_policy_events(&self, cutoff: Option<&str>) -> Vec<AuditEventBuilder> {
        use crate::modules::policy::PolicyModule;

        let mut events = Vec::new();
        if let Ok(policy_module) = self.get_module::<PolicyModule>("policy") {
            let store = policy_module.policy_store.load();
            if let Ok(names) = store.list_policy(crate::modules::policy::PolicyType::Acl).await {
                for name in names {
                    if let Ok(entries) = store.list_history(&name).await {
                        for e in entries {
                            if cutoff.map(|c| e.ts.as_str() >= c).unwrap_or(true) {
                                events.push(AuditEventBuilder {
                                    ts: e.ts,
                                    user: e.user,
                                    op: e.op,
                                    category: "policy".into(),
                                    target: name.clone(),
                                    changed_fields: Vec::new(),
                                    summary: String::new(),
                                });
                            }
                        }
                    }
                }
            }
        }
        events
    }

    /// Identity group change-history, both user and app kinds.
    async fn collect_identity_group_events(&self, cutoff: Option<&str>) -> Vec<AuditEventBuilder> {
        use crate::modules::identity::{GroupKind, IdentityModule};

        let mut events = Vec::new();
        if let Ok(identity_module) = self.get_module::<IdentityModule>("identity") {
            if let Some(gs) = identity_module.group_store() {
                for (kind, label) in [
                    (GroupKind::User, "identity-group-user"),
                    (GroupKind::App, "identity-group-app"),
                ] {
                    if let Ok(names) = gs.list_groups(kind).await {
                        for name in names {
                            if let Ok(entries) = gs.list_history(kind, &name).await {
                                for e in entries {
                                    if cutoff.map(|c| e.ts.as_str() >= c).unwrap_or(true) {
                                        events.push(AuditEventBuilder {
                                            ts: e.ts,
                                            user: e.user,
                                            op: e.op,
                                            category: label.into(),
                                            target: name.clone(),
                                            changed_fields: e.changed_fields,
                                            summary: String::new(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        events
    }

    /// Asset-group (resource-group) change-history.
    async fn collect_asset_group_events(&self, cutoff: Option<&str>) -> Vec<AuditEventBuilder> {
        use crate::modules::resource_group::ResourceGroupModule;

        let mut events = Vec::new();
        if let Ok(module) = self.get_module::<ResourceGroupModule>("resource-group") {
            if let Some(store) = module.store() {
                if let Ok(names) = store.list_groups().await {
                    for name in names {
                        if let Ok(entries) = store.list_history(&name).await {
                            for e in entries {
                                if cutoff.map(|c| e.ts.as_str() >= c).unwrap_or(true) {
                                    events.push(AuditEventBuilder {
                                        ts: e.ts,
                                        user: e.user,
                                        op: e.op,
                                        category: "asset-group".into(),
                                        target: name.clone(),
                                        changed_fields: e.changed_fields,
                                        summary: String::new(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        events
    }

    /// Share events — grants, revokes, cascade-revokes — drawn from the
    /// flat share history view. The `actor_entity_id` is used as the
    /// event's `user` so the Audit page's EntityLabel turns it back into
    /// a login.
    async fn collect_share_events(&self, cutoff: Option<&str>) -> Vec<AuditEventBuilder> {
        use crate::modules::identity::IdentityModule;

        let mut events = Vec::new();
        if let Ok(identity_module) = self.get_module::<IdentityModule>("identity") {
            if let Some(store) = identity_module.share_store() {
                if let Ok(entries) = store.list_all_history().await {
                    for e in entries {
                        if cutoff.map(|c| e.ts.as_str() >= c).unwrap_or(true) {
                            let target = format!("{}:{}", e.target_kind, e.target_path);
                            // Include the grantee on the changed_fields row
                            // so the search box matches recipient-centric
                            // queries like "shared with felipe".
                            let mut fields = Vec::new();
                            fields.push(format!("grantee={}", e.grantee_entity_id));
                            if !e.capabilities.is_empty() {
                                fields.push(format!("caps={}", e.capabilities.join(",")));
                            }
                            if !e.expires_at.is_empty() {
                                fields.push(format!("expires={}", e.expires_at));
                            }
                            events.push(AuditEventBuilder {
                                ts: e.ts,
                                user: e.actor_entity_id,
                                op: e.op,
                                category: "share".into(),
                                target,
                                changed_fields: fields,
                                summary: String::new(),
                            });
                        }
                    }
                }
            }
        }
        events
    }

    /// User / role lifecycle events. Mount distinguishes userpass
    /// (`userpass/`) from approle (`approle/`); we preserve it on the
    /// `target` so the GUI can still show "mount:name" at a glance.
    async fn collect_user_events(&self, since_key: Option<&str>) -> Vec<AuditEventBuilder> {
        use crate::modules::identity::IdentityModule;

        let mut events = Vec::new();
        if let Ok(identity_module) = self.get_module::<IdentityModule>("identity") {
            if let Some(store) = identity_module.user_audit_store() {
                let res = match since_key {
                    Some(k) => store.list_since(k).await,
                    None => store.list_all().await,
                };
                if let Ok(entries) = res {
                    for e in entries {
                        let mut fields = Vec::new();
                        fields.push(format!("mount={}", e.mount));
                        if !e.details.is_empty() {
                            fields.push(e.details.clone());
                        }
                        events.push(AuditEventBuilder {
                            ts: e.ts,
                            user: e.actor_entity_id,
                            op: e.op,
                            category: "user".into(),
                            target: format!("{}{}", e.mount, e.target),
                            changed_fields: fields,
                            summary: String::new(),
                        });
                    }
                }
            }
        }
        events
    }

    /// File-resource lifecycle events. Constructed lazily from the system
    /// view (see `FileAuditStore::from_core`) — if the core is sealed or
    /// the view hasn't been installed yet, we skip silently.
    async fn collect_file_events(&self, since_key: Option<&str>) -> Vec<AuditEventBuilder> {
        let mut events = Vec::new();
        if let Ok(store) =
            crate::modules::files::files_audit_store::FileAuditStore::from_core(&self.core)
        {
            let res = match since_key {
                Some(k) => store.list_since(k).await,
                None => store.list_all().await,
            };
            if let Ok(entries) = res {
                for e in entries {
                    let mut fields = Vec::new();
                    if !e.details.is_empty() {
                        fields.push(e.details.clone());
                    }
                    // Display the human name when present, and fall back
                    // to the id so the row is never empty. The id is
                    // always appended as a separate field so search still
                    // matches it.
                    let target = if e.name.is_empty() { e.file_id.clone() } else { e.name.clone() };
                    fields.push(format!("id={}", e.file_id));
                    events.push(AuditEventBuilder {
                        ts: e.ts,
                        user: e.actor_entity_id,
                        op: e.op,
                        category: "file".into(),
                        target,
                        changed_fields: fields,
                        summary: String::new(),
                    });
                }
            }
        }
        events
    }

    /// Authentication events (successful and failed logins, logouts) from
    /// the credential backends. Lazy-from-core, skip-on-sealed.
    async fn collect_login_events(&self, since_key: Option<&str>) -> Vec<AuditEventBuilder> {
        let mut events = Vec::new();
        if let Ok(store) =
            crate::modules::credential::login_audit_store::LoginAuditStore::from_core(&self.core)
        {
            let res = match since_key {
                Some(k) => store.list_since(k).await,
                None => store.list_all().await,
            };
            if let Ok(entries) = res {
                for e in entries {
                    let mut fields = Vec::new();
                    if !e.remote_addr.is_empty() {
                        fields.push(format!("from={}", e.remote_addr));
                    }
                    if !e.details.is_empty() {
                        fields.push(e.details.clone());
                    }
                    events.push(AuditEventBuilder {
                        ts: e.ts,
                        // The principal name is the most useful "who" for a
                        // login row; it is not an entity id, so the GUI
                        // renders it verbatim.
                        user: e.username.clone(),
                        // logout entries carry action="logout"; logins map
                        // to login / login-failed by success.
                        op: match e.action.as_str() {
                            "logout" => "logout".into(),
                            _ if e.success => "login".into(),
                            _ => "login-failed".into(),
                        },
                        category: "login".into(),
                        target: format!("{}{}", e.mount, e.username),
                        changed_fields: fields,
                        summary: String::new(),
                    });
                }
            }
        }
        events
    }

    /// Permission-denied requests from the core-level denial store.
    /// Lazy-from-core, skip-on-sealed. `authenticated` distinguishes an
    /// ACL rejection (valid token, insufficient policy) from a
    /// missing/invalid token — both render as op `denied`, with the
    /// reason carried in the fields column.
    async fn collect_denial_events(&self, since_key: Option<&str>) -> Vec<AuditEventBuilder> {
        let mut events = Vec::new();
        if let Ok(store) =
            crate::modules::system::denial_audit_store::DenialAuditStore::from_core(&self.core)
        {
            let res = match since_key {
                Some(k) => store.list_since(k).await,
                None => store.list_all().await,
            };
            if let Ok(entries) = res {
                for e in entries {
                    let mut fields = Vec::new();
                    if !e.operation.is_empty() {
                        fields.push(format!("op={}", e.operation));
                    }
                    fields.push(if e.authenticated {
                        "reason=policy".to_string()
                    } else {
                        "reason=invalid-token".to_string()
                    });
                    if !e.remote_addr.is_empty() {
                        fields.push(format!("from={}", e.remote_addr));
                    }
                    events.push(AuditEventBuilder {
                        ts: e.ts,
                        user: e.user,
                        op: "denied".into(),
                        category: "request".into(),
                        target: e.path,
                        changed_fields: fields,
                        summary: String::new(),
                    });
                }
            }
        }
        events
    }

    /// Zero-padded-nanoseconds key matching the append stores' `hist_seq`
    /// format, so a time instant can bound a range scan to the recent
    /// tail of a timestamp-keyed log.
    fn hist_since_key(t: chrono::DateTime<chrono::Utc>) -> String {
        let nanos = t.timestamp_nanos_opt().unwrap_or(0).max(0) as u128;
        format!("{nanos:020}")
    }

    /// Count permission denials recorded at or after `since`, read from
    /// the replicated denial store rather than the per-node in-memory
    /// stats ring — so the count is identical on every HA node. A sealed
    /// barrier or read error counts as zero (best-effort, like the other
    /// dashboard sources).
    async fn count_denials_since(&self, since: chrono::DateTime<chrono::Utc>) -> u64 {
        let since_key = Self::hist_since_key(since);
        match crate::modules::system::denial_audit_store::DenialAuditStore::from_core(&self.core) {
            Ok(store) => store.list_since(&since_key).await.map(|v| v.len() as u64).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Count failed authentication attempts recorded at or after `since`,
    /// read from the replicated login-audit store (see
    /// [`Self::count_denials_since`] for the HA rationale). A logout is
    /// not a failed login; only rejected login attempts are counted.
    async fn count_failed_logins_since(&self, since: chrono::DateTime<chrono::Utc>) -> u64 {
        let since_key = Self::hist_since_key(since);
        match crate::modules::credential::login_audit_store::LoginAuditStore::from_core(&self.core) {
            Ok(store) => store
                .list_since(&since_key)
                .await
                .map(|v| v.iter().filter(|e| !e.success && e.action != "logout").count() as u64)
                .unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// SSH CA lifecycle (create / delete of the signing CA) from the SSH
    /// engine's append store. Lazy-from-core, skip-on-sealed.
    async fn collect_ssh_ca_events(&self, since_key: Option<&str>) -> Vec<AuditEventBuilder> {
        let mut events = Vec::new();
        if let Ok(store) =
            crate::modules::ssh::ssh_ca_audit_store::SshCaAuditStore::from_core(&self.core)
        {
            let res = match since_key {
                Some(k) => store.list_since(k).await,
                None => store.list_all().await,
            };
            if let Ok(entries) = res {
                for e in entries {
                    let mut fields = Vec::new();
                    if !e.algorithm.is_empty() {
                        fields.push(format!("algorithm={}", e.algorithm));
                    }
                    let target = if e.mount.is_empty() {
                        "config/ca".to_string()
                    } else {
                        format!("{}config/ca", e.mount)
                    };
                    events.push(AuditEventBuilder {
                        ts: e.ts,
                        user: e.actor_entity_id,
                        op: e.op,
                        category: "ssh-ca".into(),
                        target,
                        changed_fields: fields,
                        summary: String::new(),
                    });
                }
            }
        }
        events
    }

    /// SSH certificate issuance (sign/:role) from the SSH engine's append
    /// store. Lazy-from-core, skip-on-sealed.
    async fn collect_ssh_sign_events(&self, since_key: Option<&str>) -> Vec<AuditEventBuilder> {
        let mut events = Vec::new();
        if let Ok(store) =
            crate::modules::ssh::ssh_sign_audit_store::SshSignAuditStore::from_core(&self.core)
        {
            let res = match since_key {
                Some(k) => store.list_since(k).await,
                None => store.list_all().await,
            };
            if let Ok(entries) = res {
                for e in entries {
                    let mut fields = Vec::new();
                    if !e.principals.is_empty() {
                        fields.push(format!("principals={}", e.principals));
                    }
                    if !e.cert_type.is_empty() {
                        fields.push(format!("cert_type={}", e.cert_type));
                    }
                    if !e.serial.is_empty() {
                        fields.push(format!("serial={}", e.serial));
                    }
                    if !e.algorithm.is_empty() {
                        fields.push(format!("algorithm={}", e.algorithm));
                    }
                    let role = if e.role.is_empty() { "?".to_string() } else { e.role.clone() };
                    let target = if e.mount.is_empty() {
                        format!("sign/{role}")
                    } else {
                        format!("{}sign/{role}", e.mount)
                    };
                    events.push(AuditEventBuilder {
                        ts: e.ts,
                        user: e.actor_entity_id,
                        op: e.op,
                        category: "ssh-sign".into(),
                        target,
                        changed_fields: fields,
                        summary: String::new(),
                    });
                }
            }
        }
        events
    }

    pub async fn handle_audit_enable(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(broker) = self.core.audit_broker.load().as_ref().cloned() else {
            return Err(bv_error_response_status!(503, "audit broker not initialized"));
        };

        let path = req.get_data("path")?.as_str().unwrap_or("").to_string();
        let device_type = req
            .get_data("type")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let description = req
            .get_data("description")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        // `options` is declared as FieldType::Map on the route — it
        // resolves to a `serde_json::Map` of string values. Other
        // shapes fall through to empty.
        let options: std::collections::HashMap<String, String> = req
            .get_data("options")
            .ok()
            .and_then(|v| match v {
                Value::Object(m) => Some(
                    m.iter()
                        .map(|(k, v)| {
                            (
                                k.clone(),
                                match v {
                                    Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                },
                            )
                        })
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default();

        if path.trim().is_empty() || device_type.trim().is_empty() {
            return Err(bv_error_response_status!(400, "path and type are required"));
        }

        // Multi-tenancy: the device is scoped to the namespace named by the
        // request header (root when absent). `mirror` is a root-only superuser
        // flag that shadows every namespace's stream onto this device.
        let namespace =
            crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        let mirror = req
            .get_data("mirror")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let cfg = crate::audit::AuditDeviceConfig {
            path,
            device_type,
            description,
            options,
            namespace,
            mirror,
        };
        broker.enable_device(cfg).await?;
        Ok(None)
    }

    /// Admin-only: stamp `entity_id` as the owner of every
    /// currently-unowned target in `resources` + `kv_paths`. Intended
    /// as the one-shot migration tool for deployments that were
    /// running before per-user-scoping landed — existing unowned
    /// objects are invisible to `owner`/`shared`-scoped policies until
    /// they are claimed. Never overwrites an existing owner (use the
    /// `*-owner/transfer` endpoints for that).
    ///
    /// Request fields:
    ///   `entity_id` (required, non-empty) — owner to stamp.
    ///   `resources` (optional array) — resource names.
    ///   `kv_paths` (optional array)  — KV paths (any of the v1/v2 forms
    ///                                   that `OwnerStore::canonicalize_kv_path`
    ///                                   accepts).
    ///   `dry_run` (optional bool)    — report-only when true.
    ///
    /// Response: per-kind counts (`stamped` / `already_owned` / `invalid`).
    pub async fn handle_owner_backfill(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let entity_id = req
            .get_data("entity_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        if entity_id.trim().is_empty() {
            return Err(bv_error_response_status!(
                400,
                "entity_id is required and must be non-empty"
            ));
        }

        let resources: Vec<String> = req
            .get_data("resources")
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.trim().is_empty())
            .collect();
        let kv_paths: Vec<String> = req
            .get_data("kv_paths")
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.trim().is_empty())
            .collect();
        let file_ids: Vec<String> = req
            .get_data("file_ids")
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.trim().is_empty())
            .collect();
        let dry_run = req
            .get_data("dry_run")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if resources.is_empty() && kv_paths.is_empty() && file_ids.is_empty() {
            return Err(bv_error_response_status!(
                400,
                "at least one of resources, kv_paths, or file_ids must be non-empty"
            ));
        }

        let identity = self.get_module::<IdentityModule>("identity")?;
        let store = identity.owner_store().ok_or_else(|| {
            bv_error_response_status!(500, "owner store not initialized")
        })?;

        let mut res_stamped = 0usize;
        let mut res_already = 0usize;
        let mut res_invalid: Vec<String> = Vec::new();
        for name in &resources {
            // `record_resource_owner_if_absent` already rejects names
            // containing `/` or empty strings — we mirror that as
            // "invalid" in the response instead of letting the whole
            // batch error out.
            if name.contains('/') {
                res_invalid.push(name.clone());
                continue;
            }
            match store.get_resource_owner(name).await? {
                Some(_) => res_already += 1,
                None => {
                    if !dry_run {
                        store
                            .record_resource_owner_if_absent(name, &entity_id)
                            .await?;
                    }
                    res_stamped += 1;
                }
            }
        }

        let mut kv_stamped = 0usize;
        let mut kv_already = 0usize;
        let mut kv_invalid: Vec<String> = Vec::new();
        for path in &kv_paths {
            // `canonicalize_kv_path` returns None for malformed input
            // (empty segments, `..`, etc.). We surface those separately
            // so the operator sees exactly which paths were skipped.
            if crate::modules::identity::owner_store::OwnerStore::canonicalize_kv_path(path)
                .is_none()
            {
                kv_invalid.push(path.clone());
                continue;
            }
            match store.get_kv_owner(path).await? {
                Some(_) => kv_already += 1,
                None => {
                    if !dry_run {
                        store
                            .record_kv_owner_if_absent(path, &entity_id)
                            .await?;
                    }
                    kv_stamped += 1;
                }
            }
        }

        let mut resources_summary = Map::new();
        resources_summary.insert("stamped".into(), Value::from(res_stamped));
        resources_summary.insert("already_owned".into(), Value::from(res_already));
        resources_summary.insert(
            "invalid".into(),
            Value::Array(res_invalid.into_iter().map(Value::String).collect()),
        );

        let mut kv_summary = Map::new();
        kv_summary.insert("stamped".into(), Value::from(kv_stamped));
        kv_summary.insert("already_owned".into(), Value::from(kv_already));
        kv_summary.insert(
            "invalid".into(),
            Value::Array(kv_invalid.into_iter().map(Value::String).collect()),
        );

        let mut file_stamped = 0usize;
        let mut file_already = 0usize;
        let mut file_invalid: Vec<String> = Vec::new();
        for id in &file_ids {
            if id.contains('/') {
                file_invalid.push(id.clone());
                continue;
            }
            match store.get_file_owner(id).await? {
                Some(_) => file_already += 1,
                None => {
                    if !dry_run {
                        store.record_file_owner_if_absent(id, &entity_id).await?;
                    }
                    file_stamped += 1;
                }
            }
        }

        let mut files_summary = Map::new();
        files_summary.insert("stamped".into(), Value::from(file_stamped));
        files_summary.insert("already_owned".into(), Value::from(file_already));
        files_summary.insert(
            "invalid".into(),
            Value::Array(file_invalid.into_iter().map(Value::String).collect()),
        );

        let mut data = Map::new();
        data.insert("entity_id".into(), Value::String(entity_id));
        data.insert("dry_run".into(), Value::Bool(dry_run));
        data.insert("resources".into(), Value::Object(resources_summary));
        data.insert("kv".into(), Value::Object(kv_summary));
        data.insert("files".into(), Value::Object(files_summary));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Flush every in-memory cache layer (policy / token / secret).
    /// Sudo-gated via `root_paths` — callers need a token whose policies
    /// grant capability on `sys/cache/flush`. Returns 204 on success
    /// matching the pattern used by `sys/audit` disable and `sys/seal`.
    pub async fn handle_cache_flush(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.core.flush_caches();
        Ok(None)
    }

    pub async fn handle_audit_disable(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(broker) = self.core.audit_broker.load().as_ref().cloned() else {
            return Ok(None);
        };
        let path = req.get_data("path")?.as_str().unwrap_or("").to_string();
        if path.trim().is_empty() {
            return Err(bv_error_response_status!(400, "path is required"));
        }
        let namespace =
            crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        broker.disable_device(&namespace, &path).await?;
        Ok(None)
    }

    pub async fn handle_raw_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;

        let path = path.as_str().unwrap();

        let entry = self.core.barrier.get(path).await?;
        if entry.is_none() {
            return Ok(None);
        }

        let data = json!({
            "value": String::from_utf8_lossy(&entry.unwrap().value),
        })
        .as_object()
        .cloned();

        Ok(Some(Response::data_response(data)))
    }

    pub async fn handle_raw_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;
        let value = req.get_data("value")?;

        let path = path.as_str().unwrap();
        let value = value.as_str().unwrap();

        let entry = StorageEntry { key: path.to_string(), value: value.as_bytes().to_vec() };

        self.core.barrier.put(&entry).await?;

        Ok(None)
    }

    /// Storage key for the global SSO toggle. Lives in the barrier
    /// (AEAD-encrypted at rest) alongside the rest of the system
    /// backend's persisted state.
    const SSO_SETTINGS_KEY: &'static str = "core/sso/settings";

    /// Auth-backend kinds that participate in the SSO login flow.
    /// The unauth `sys/sso/providers` endpoint filters the mount
    /// table by these kinds so only federation-capable backends
    /// surface to the login screen.
    const SSO_KINDS: &'static [&'static str] = &["oidc", "saml"];

    pub async fn handle_sso_settings_read(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let enabled = self.load_sso_enabled().await?;
        let mut data = Map::new();
        data.insert("enabled".into(), Value::Bool(enabled));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_sso_settings_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // `get_data` goes through the field-layer's Bool coercion,
        // which accepts true/false/"true"/"false"/1/0.
        let enabled = req
            .get_data("enabled")
            .ok()
            .and_then(|v| match v {
                Value::Bool(b) => Some(b),
                Value::String(s) => match s.to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => Some(true),
                    "false" | "0" | "no" | "off" => Some(false),
                    _ => None,
                },
                Value::Number(n) => n.as_i64().map(|i| i != 0),
                _ => None,
            })
            .ok_or_else(|| {
                RvError::ErrString("sso/settings: `enabled` must be a boolean".into())
            })?;

        let payload = json!({ "enabled": enabled });
        let entry = StorageEntry {
            key: Self::SSO_SETTINGS_KEY.to_string(),
            value: serde_json::to_vec(&payload)?,
        };
        self.core.barrier.put(&entry).await?;
        Ok(None)
    }

    pub async fn handle_sso_providers(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // Disabled: return an empty list rather than erroring so the
        // GUI's "no providers ⇒ hide tab" branch fires naturally.
        // This keeps the unauth surface minimal — callers learn
        // "SSO is not on", not "SSO exists but is turned off".
        let enabled = self.load_sso_enabled().await?;

        let mut providers: Vec<Value> = Vec::new();
        if enabled {
            let auth_module = self.get_module::<AuthModule>("auth")?;
            let mounts = auth_module.mounts_router.entries.read()?;
            for mount_entry in mounts.values() {
                let entry = mount_entry.read()?;
                if !Self::SSO_KINDS.iter().any(|k| *k == entry.logical_type) {
                    continue;
                }
                // `entry.path` already includes the trailing slash
                // enforced by the mount layer. Strip it for a clean
                // display/API shape; the OIDC callback routes accept
                // either form.
                let mount = entry.path.trim_end_matches('/').to_string();
                // Description is the operator-facing display label
                // (set via `sys/auth/<mount>` description field). Fall
                // back to the mount path so a blank description still
                // renders something clickable.
                let name = if entry.description.trim().is_empty() {
                    mount.clone()
                } else {
                    entry.description.clone()
                };
                let mut row = Map::new();
                row.insert("mount".into(), Value::String(mount));
                row.insert("name".into(), Value::String(name));
                row.insert("kind".into(), Value::String(entry.logical_type.clone()));
                providers.push(Value::Object(row));
            }
            // Stable ordering for the GUI — by display name, then by mount
            // so the list doesn't jitter between reads.
            providers.sort_by(|a, b| {
                let na = a.get("name").and_then(Value::as_str).unwrap_or("");
                let nb = b.get("name").and_then(Value::as_str).unwrap_or("");
                na.cmp(nb).then_with(|| {
                    let ma = a.get("mount").and_then(Value::as_str).unwrap_or("");
                    let mb = b.get("mount").and_then(Value::as_str).unwrap_or("");
                    ma.cmp(mb)
                })
            });
        }

        let mut data = Map::new();
        data.insert("enabled".into(), Value::Bool(enabled));
        data.insert("providers".into(), Value::Array(providers));
        Ok(Some(Response::data_response(Some(data))))
    }

    async fn load_sso_enabled(&self) -> Result<bool, RvError> {
        let Some(entry) = self.core.barrier.get(Self::SSO_SETTINGS_KEY).await? else {
            return Ok(false);
        };
        let parsed: Value = serde_json::from_slice(&entry.value).unwrap_or(Value::Null);
        Ok(parsed
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    pub async fn handle_raw_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;

        let path = path.as_str().unwrap();

        self.core.barrier.delete(path).await?;

        Ok(None)
    }

    /// `POST sys/capabilities-self` (exposed as `/v2/sys/capabilities-self`).
    ///
    /// Returns the calling token's effective capabilities on each requested
    /// path. Vault-compatible response shape: a top-level `capabilities` map
    /// (path → list of capability strings) plus per-path keys for callers
    /// that index by path directly. The GUI uses this to decide, for a
    /// resource's secret path, whether to show credential values (`read`
    /// present) or only a brokered "Connect" button (`connect` only).
    pub async fn handle_capabilities_self(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;

        let paths: Vec<String> = match req.get_data("paths") {
            Ok(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Ok(Value::String(s)) => vec![s],
            _ => Vec::new(),
        };
        if paths.is_empty() {
            return Err(bv_error_response_status!(400, "`paths` must be a non-empty array"));
        }

        // The capabilities are those of the authenticated caller. An
        // unauthenticated request cannot reach a `Write` route, so `auth`
        // is present; treat its absence as deny.
        let auth = req
            .auth
            .clone()
            .ok_or(RvError::ErrPermissionDenied)?;

        // Multi-tenancy honesty: `sys/capabilities-self` is a `sys/` path, so it
        // is exempt from `enforce_request_token_binding` and would otherwise
        // report a token's *policy* capabilities on paths inside a namespace the
        // token may not actually operate in — the GUI then enables write
        // controls the server rejects with 403 at request time. Mirror the
        // request-time binding verdict here: when the active namespace header
        // names a namespace this token cannot operate in, advertise no
        // capabilities and surface the mismatch so the UI can explain it rather
        // than let the caller walk into an opaque denial.
        let active_ns = self
            .resolve_request_namespace(req)
            .await?
            .map(|(_, path)| path);
        let operable = match active_ns.as_deref() {
            Some(ns_path) => {
                crate::modules::namespace::token_binding::token_operable_resolved(
                    &self.core, &auth, ns_path,
                )
                .await
            }
            None => true,
        };

        if !operable {
            let (token_ns, _) =
                crate::modules::namespace::token_binding::binding_from_metadata(&auth.metadata);
            let mut capabilities = Map::new();
            for path in &paths {
                capabilities.insert(path.clone(), Value::Array(vec![]));
            }
            let mut data = capabilities.clone();
            data.insert("capabilities".into(), Value::Object(capabilities));
            data.insert("namespace_operable".into(), Value::Bool(false));
            data.insert("token_namespace".into(), Value::String(token_ns));
            data.insert(
                "active_namespace".into(),
                Value::String(active_ns.unwrap_or_default()),
            );
            return Ok(Some(Response::data_response(Some(data))));
        }

        let policy_store = policy_module.policy_store.load();
        let acl: ACL = policy_store
            .new_acl_for_request(&auth.policies, None, &auth)
            .await?;

        let mut capabilities = Map::new();
        for path in &paths {
            let mut caps = acl.capabilities(path.clone());

            // `acl.capabilities` runs an `Operation::List` dry-run, and the
            // `is_list` short-circuit in `allow_operation` defers scope
            // filtering for genuine LISTs to post-route. That makes
            // scope-gated (`scopes = ["owner"|"shared"]`) rules advertise
            // their FULL capability set here without verifying the scope.
            // For capabilities-self that over-reports: a read-only
            // share-grantee would see `update`/`delete` they cannot exercise,
            // and the GUI would then enable Edit/Delete controls the server
            // rejects with 403. Re-verify each scope-sensitive capability
            // against the real gate (`can_operate` resolves ownership and
            // active shares) and drop any the caller cannot truly perform.
            // `root`/`deny` are absolute (never scope-gated) so leave them.
            if !caps.iter().any(|c| c == "root" || c == "deny") {
                for (cap_name, op) in [
                    ("read", Operation::Read),
                    ("list", Operation::List),
                    ("update", Operation::Write),
                    ("create", Operation::Write),
                    ("delete", Operation::Delete),
                ] {
                    if caps.iter().any(|c| c == cap_name)
                        && !policy_store.can_operate(&auth, path, op).await
                    {
                        caps.retain(|c| c != cap_name);
                    }
                }
            }

            capabilities.insert(
                path.clone(),
                Value::Array(caps.into_iter().map(Value::String).collect()),
            );
        }

        // Vault returns both a `capabilities` map and per-path top-level
        // keys; mirror that so existing clients work unchanged.
        let mut data = capabilities.clone();
        data.insert("capabilities".into(), Value::Object(capabilities));
        // Binding-awareness flag (see the early-return above). `true` here means
        // the token may operate in the active namespace (or the request is
        // root-scoped), so the advertised capabilities are actionable.
        data.insert("namespace_operable".into(), Value::Bool(true));

        Ok(Some(Response::data_response(Some(data))))
    }

    /// `GET sys/dashboard/summary` — one-shot operational snapshot for
    /// the GUI Dashboard landing page. Aggregates seal state, ACL-gated
    /// secret-engine / auth-method / policy / entity counts, and a 24h
    /// audit-event total so the dashboard makes a single call instead of
    /// fanning out N list requests. Every count respects the caller's
    /// effective ACL and the active namespace; a caller only ever sees
    /// totals their policies permit.
    pub async fn handle_dashboard_summary(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        use crate::modules::{identity::IdentityModule, policy::PolicyModule};

        let policy_module = self.get_module::<PolicyModule>("policy")?;
        let auth_module = self.get_module::<AuthModule>("auth")?;

        // Build the caller's ACL from their token (this is a Read route,
        // so we resolve it the same way handle_internal_ui_mounts_read
        // does rather than relying on req.auth). No policies → no mount
        // visibility.
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let acl: Option<ACL> = match token_store.check_token(&req.path, &req.client_token).await? {
            Some(auth) if !auth.policies.is_empty() => Some(
                policy_module
                    .policy_store
                    .load()
                    .new_acl_for_request(&auth.policies, None, &auth)
                    .await?,
            ),
            _ => None,
        };

        // Resolve the active namespace (None == root).
        let ns = self.resolve_request_namespace(req).await?;
        let ns_path = ns.as_ref().map(|(_, p)| p.clone()).unwrap_or_default();

        // --- Mount counts (secret engines + auth methods) -------------
        // Root: walk Core's mount table gated by the caller's ACL
        // (mirrors handle_internal_ui_mounts_read). Child namespace:
        // count the registry's mounts, already tenant-scoped.
        let (mut secret_mounts, mut auth_mounts) = (0usize, 0usize);
        if let Some((uuid, path)) = ns.as_ref() {
            if let Ok(registry) = self.namespace_registry() {
                if let Ok(mounts) = registry.list_mounts(&self.core, uuid, path).await {
                    for (_p, logical_type, _desc) in mounts {
                        if logical_type != "system" {
                            secret_mounts += 1;
                        }
                    }
                }
            }
        } else {
            let mounts_router = self.core.mounts_router();
            let entries = mounts_router.entries.read()?;
            for entry in entries.values() {
                let me = entry.read()?;
                let visible = acl
                    .as_ref()
                    .map(|a| {
                        if me.table == AUTH_TABLE_TYPE {
                            a.has_mount_access(&format!("{}/{}", AUTH_TABLE_TYPE, me.path))
                        } else {
                            a.has_mount_access(me.path.as_str())
                        }
                    })
                    .unwrap_or(false);
                if !visible {
                    continue;
                }
                if me.table == AUTH_TABLE_TYPE {
                    auth_mounts += 1;
                } else if me.logical_type != "system" {
                    secret_mounts += 1;
                }
            }
        }

        // --- Policy count ---------------------------------------------
        let policy_store = policy_module.policy_store.load();
        let policies = if ns_path.is_empty() {
            policy_store.list_policy(crate::modules::policy::PolicyType::Acl).await
        } else {
            policy_store
                .list_policy_ns(crate::modules::policy::PolicyType::Acl, &ns_path)
                .await
        }
        .map(|v| v.len())
        .unwrap_or(0);

        // --- Entity count ---------------------------------------------
        let entities = if let Ok(identity_module) = self.get_module::<IdentityModule>("identity") {
            if let Some(es) = identity_module.entity_store() {
                if ns_path.is_empty() {
                    es.list_entities().await
                } else {
                    es.list_entities_ns(&ns_path).await
                }
                .map(|v| v.len())
                .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        // --- 24h audit-event total ------------------------------------
        // Count change-history events from the last 24h. The bound is
        // pushed into the collection: append-only stores range-scan only
        // the recent tail and the small history sources are filtered by
        // timestamp, so this no longer reads (and decrypts) all history
        // just to produce a count.
        let now = chrono::Utc::now();
        let audit_24h = self
            .collect_audit_events_since(Some(now - chrono::Duration::hours(24)))
            .await
            .len();

        // Request-level outcome counters. These are process-wide (not
        // per-namespace) — they describe the server's health, which is the
        // same question regardless of which tenant the operator is
        // viewing. Denials and failed logins are counted from replicated
        // storage (`sys/denial-audit`, `sys/login-audit`) so every HA node
        // reports the same totals: the in-memory `stats` ring is per-node,
        // so a denial or failed login handled by another node would be
        // invisible to a summary served here. Audit-write failures have no
        // backing store yet, so they stay on the in-memory counter.
        let denied_24h = self.count_denials_since(now - chrono::Duration::hours(24)).await;
        let failed_logins_1h = self.count_failed_logins_since(now - chrono::Duration::hours(1)).await;
        let now_secs = now.timestamp();
        let stats = &self.core.stats;

        let data = json!({
            "version": "1",
            "seal": {
                "sealed": self.core.sealed(),
                "initialized": self.core.inited().await.unwrap_or(false),
            },
            "namespace": ns_path,
            "counts": {
                "secret_mounts": secret_mounts,
                "auth_mounts": auth_mounts,
                "policies": policies,
                "entities": entities,
            },
            "audit_24h": {
                "total": audit_24h,
                "denied": denied_24h,
                "write_failures": stats.audit_write_failures_24h(now_secs),
            },
            "attention": {
                "failed_logins_1h": failed_logins_1h,
            },
        })
        .as_object()
        .cloned();

        Ok(Some(Response::data_response(data)))
    }

    /// `GET v2/sys/hsm/status` — HSM seal posture for operators and the GUI.
    /// Reports the active seal provider's type and, for the HSM provider, the
    /// backend, device serial, cluster epoch, enrolled-node count, and recovery
    /// mode. Never returns secret material.
    pub async fn handle_hsm_status(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let provider = self.core.seal_provider();
        let mut status = provider.status().await?;
        if let Some(obj) = status.as_object_mut() {
            obj.insert("sealed".into(), json!(self.core.sealed()));
            obj.insert("initialized".into(), json!(self.core.inited().await.unwrap_or(false)));
        }
        Ok(Some(Response::data_response(status.as_object().cloned())))
    }

    pub async fn handle_internal_ui_mounts_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;
        let auth_module = self.get_module::<AuthModule>("auth")?;

        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };

        let mut secret_mounts = Map::new();
        let mut auth_mounts = Map::new();

        let mut is_authed = false;

        let acl: Option<ACL> = if let Some(auth) = token_store.check_token(&req.path, &req.client_token).await? {
            if auth.policies.is_empty() {
                None
            } else {
                is_authed = true;
                Some(policy_module.policy_store.load().new_acl_for_request(&auth.policies, None, &auth).await?)
            }
        } else {
            None
        };

        let has_access = |me: &MountEntry| -> bool {
            if !is_authed {
                return false;
            }

            let Some(acl) = acl.as_ref() else {
                return false;
            };

            if me.table == AUTH_TABLE_TYPE {
                acl.has_mount_access(&format!("{}/{}", AUTH_TABLE_TYPE, me.path))
            } else {
                acl.has_mount_access(me.path.as_str())
            }
        };

        // Secret-engine mounts are namespace-scoped: in a child namespace they
        // live in the namespace registry, NOT Core's (root) mount router.
        // Returning the root table here is what made the GUI believe
        // `secret/`, `resources/`, … existed in a child namespace that has no
        // such mount (child namespaces start empty) — every subsequent
        // operation then 404'd with `ErrRouterMountNotFound`. Resolve the
        // active namespace and enumerate the correct table. (Mirrors
        // `handle_mount_table` / `handle_dashboard_summary`.)
        match self.resolve_request_namespace(req).await? {
            Some((uuid, path)) => {
                // Child namespace: list the registry's tenant-scoped mounts,
                // ACL-gated like the root branch. The registry gives only
                // `(path, type, description)`, which is all this endpoint's
                // consumers (`list_mounts` / `list_auth_methods`) read.
                if let Some(acl) = acl.as_ref().filter(|_| is_authed) {
                    let registry = self.namespace_registry()?;
                    for (mount_path, logical_type, description) in
                        registry.list_mounts(&self.core, &uuid, &path).await?
                    {
                        if acl.has_mount_access(&mount_path) {
                            secret_mounts.insert(
                                mount_path,
                                json!({ "type": logical_type, "description": description }),
                            );
                        }
                    }
                }
            }
            None => {
                let mounts_router = self.core.mounts_router();
                let entries = mounts_router.entries.read()?;
                for (path, entry) in entries.iter() {
                    let me = entry.read()?;
                    if has_access(&me) {
                        if is_authed {
                            secret_mounts
                                .insert(path.clone(), Value::Object(self.mount_info(&me)));
                        } else {
                            secret_mounts.insert(
                                path.clone(),
                                json!({
                                    "type": me.logical_type.clone(),
                                    "description": me.description.clone(),
                                    "options": me.options.clone(),
                                }),
                            );
                        }
                    }
                }
            }
        }

        // Auth methods are global (not namespace-scoped) in the current
        // phases, so they always come from the root auth router regardless of
        // the active namespace.
        let entries = auth_module.mounts_router.entries.read()?;
        for (path, entry) in entries.iter() {
            let me = entry.read()?;
            if has_access(&me) {
                if is_authed {
                    auth_mounts.insert(path.clone(), Value::Object(self.mount_info(&me)));
                } else {
                    auth_mounts.insert(
                        path.clone(),
                        json!({
                            "type": me.logical_type.clone(),
                            "description": me.description.clone(),
                            "options": me.options.clone(),
                        }),
                    );
                }
            }
        }

        let data = json!({
            "secret": secret_mounts,
            "auth": auth_mounts,
        })
        .as_object()
        .cloned();

        Ok(Some(Response::data_response(data)))
    }

    pub async fn handle_internal_ui_mount_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let policy_module = self.get_module::<PolicyModule>("policy")?;
        let auth_module = self.get_module::<AuthModule>("auth")?;

        let path = sanitize_path(req.get_data("path")?.as_str().ok_or(RvError::ErrRequestInvalid)?);

        if auth_module.token_store.load().is_none() {
            return Err(RvError::ErrPermissionDenied);
        }

        let acl = if let Some(auth) =
            auth_module.token_store.load().as_ref().unwrap().check_token(&req.path, &req.client_token).await?
        {
            if auth.policies.is_empty() {
                return Err(RvError::ErrPermissionDenied);
            } else {
                policy_module.policy_store.load().new_acl_for_request(&auth.policies, None, &auth).await?
            }
        } else {
            return Err(RvError::ErrPermissionDenied);
        };

        let mount_entry =
            self.core.mounts_router().router.matching_mount_entry(&path)?.ok_or(RvError::ErrPermissionDenied)?;
        let me = mount_entry.read()?;

        let full_path =
            if me.table == AUTH_TABLE_TYPE { &format!("{}/{}", AUTH_TABLE_TYPE, me.path) } else { &me.path };

        if !acl.has_mount_access(full_path) {
            return Err(RvError::ErrPermissionDenied);
        }

        let mut data = self.mount_info(&me);
        data.insert("path".to_string(), Value::String(me.path.clone()));

        Ok(Some(Response::data_response(Some(data))))
    }

    fn get_module<T: Any + Send + Sync>(&self, name: &str) -> Result<Arc<T>, RvError> {
        if let Some(module) = self.core.module_manager.get_module::<T>(name) {
            return Ok(module);
        }

        Err(RvError::ErrModuleNotFound)
    }

    fn mount_info(&self, entry: &MountEntry) -> Map<String, Value> {
        let info = json!({
            "type": entry.logical_type.clone(),
            "description": entry.description.clone(),
            "uuid": entry.uuid.clone(),
            "options": entry.options.clone(),
        })
        .as_object()
        .unwrap()
        .clone();

        info.clone()
    }

    fn resolve_namespace_store(&self) -> Result<Arc<NamespaceStore>, RvError> {
        self.core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .ok_or_else(|| bv_error_string!("namespace store unavailable"))
    }

    fn namespace_registry(
        &self,
    ) -> Result<Arc<crate::modules::namespace::NamespaceMountRegistry>, RvError> {
        self.core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .map(|m| m.registry.clone())
            .ok_or_else(|| bv_error_string!("namespace registry unavailable"))
    }

    /// Resolve the namespace a `sys/mounts*` request targets from its
    /// `X-BastionVault-Namespace` header. Returns `None` for the root
    /// namespace (operate on `Core`'s mount table) or `Some((uuid, path))` for
    /// a child namespace (operate on the per-namespace registry).
    async fn resolve_request_namespace(
        &self,
        req: &Request,
    ) -> Result<Option<(String, String)>, RvError> {
        let Some(raw) = namespace_header_from_map(req.headers.as_ref()) else {
            return Ok(None);
        };
        let raw = raw.trim().to_string();
        if raw.is_empty() {
            return Ok(None);
        }
        let store = self.resolve_namespace_store()?;
        let ns = store
            .get_by_path(&raw)
            .await?
            .ok_or_else(|| bv_error_response_status!(404, &format!("no such namespace: {raw:?}")))?;
        if ns.is_root() {
            Ok(None)
        } else {
            Ok(Some((ns.uuid, ns.path)))
        }
    }

    fn namespace_to_response(ns: &crate::modules::namespace::Namespace) -> Response {
        let q = &ns.quotas;
        let data = json!({
            "uuid": ns.uuid,
            "path": ns.path,
            "parent_uuid": ns.parent_uuid,
            "created_at": ns.created_at,
            "child_visible_default": ns.child_visible_default,
            "quotas": {
                "max_storage_bytes": q.max_storage_bytes,
                "max_leases": q.max_leases,
                "request_rate": q.request_rate,
                "max_mounts": q.max_mounts,
                "max_entities": q.max_entities,
                "max_child_namespaces": q.max_child_namespaces,
            },
        })
        .as_object()
        .cloned();
        Response::data_response(data)
    }

    pub async fn handle_namespace_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_namespace_store()?;
        // List children of the caller's namespace: the namespace named by the
        // X-BastionVault-Namespace header, defaulting to root.
        let parent = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
        let children = store.list_children(&parent).await?;
        Ok(Some(Response::list_response(&children)))
    }

    /// Read the caller's *own* namespace config — the namespace named by the
    /// X-BastionVault-Namespace header, or the root namespace when the request
    /// is unscoped. This is the only route that can read the root record, which
    /// the by-path catch-all cannot reach (it requires a non-empty path).
    pub async fn handle_namespace_self_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_namespace_store()?;
        let path = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
        match store.get_by_path(&path).await? {
            Some(ns) => Ok(Some(Self::namespace_to_response(&ns))),
            None => Err(bv_error_response_status!(404, &format!("no such namespace: {path:?}"))),
        }
    }

    /// Update the caller's *own* namespace config (quotas + child-visible
    /// default). Update-only: the caller's namespace always exists, so this
    /// never creates. The primary use is configuring the *root* namespace,
    /// which the by-path catch-all cannot address.
    ///
    /// Security: enabling `child_visible_default` on the root namespace grants
    /// every token minted at a root login child-visible reach into *every*
    /// descendant namespace (see `token_binding::token_may_operate`). It is
    /// deliberately default-off and gated to root/sudo callers.
    pub async fn handle_namespace_self_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_namespace_store()?;
        let path = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();

        let quotas = NamespaceQuotas {
            max_storage_bytes: req.get_data_or_default("max_storage_bytes")?.as_u64().unwrap_or(0),
            max_leases: req.get_data_or_default("max_leases")?.as_u64().unwrap_or(0),
            request_rate: req.get_data_or_default("request_rate")?.as_u64().unwrap_or(0),
            max_mounts: req.get_data_or_default("max_mounts")?.as_u64().unwrap_or(0),
            max_entities: req.get_data_or_default("max_entities")?.as_u64().unwrap_or(0),
            max_child_namespaces: req
                .get_data_or_default("max_child_namespaces")?
                .as_u64()
                .unwrap_or(0),
        };
        let child_visible_default =
            req.get_data_or_default("child_visible_default")?.as_bool().unwrap_or(false);

        let ns = store.update(&path, Some(quotas), Some(child_visible_default)).await?;
        Ok(Some(Self::namespace_to_response(&ns)))
    }

    pub async fn handle_namespace_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_namespace_store()?;
        let path = req.get_data_as_str("path")?;
        match store.get_by_path(&path).await? {
            Some(ns) => Ok(Some(Self::namespace_to_response(&ns))),
            None => Err(bv_error_response_status!(404, &format!("no such namespace: {path:?}"))),
        }
    }

    pub async fn handle_namespace_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_namespace_store()?;
        let path = req.get_data_as_str("path")?;

        let quotas = NamespaceQuotas {
            max_storage_bytes: req.get_data_or_default("max_storage_bytes")?.as_u64().unwrap_or(0),
            max_leases: req.get_data_or_default("max_leases")?.as_u64().unwrap_or(0),
            request_rate: req.get_data_or_default("request_rate")?.as_u64().unwrap_or(0),
            max_mounts: req.get_data_or_default("max_mounts")?.as_u64().unwrap_or(0),
            max_entities: req.get_data_or_default("max_entities")?.as_u64().unwrap_or(0),
            max_child_namespaces: req
                .get_data_or_default("max_child_namespaces")?
                .as_u64()
                .unwrap_or(0),
        };
        let child_visible_default =
            req.get_data_or_default("child_visible_default")?.as_bool().unwrap_or(false);

        // Create-or-update (upsert): the logical operation model has no PATCH,
        // so a Write to an existing namespace updates its quotas and
        // child_visible default; a Write to a new path creates it.
        let ns = if store.get_by_path(&path).await?.is_some() {
            store.update(&path, Some(quotas), Some(child_visible_default)).await?
        } else {
            let ns = store.create(&path, quotas, child_visible_default).await?;
            // Seed the default secret engines so a new namespace is usable out
            // of the box (otherwise it starts empty and the GUI's mount-gated
            // nav collapses). Best-effort — see `seed_default_namespace_mounts`.
            self.seed_default_namespace_mounts(&ns.uuid, &ns.path).await;
            ns
        };
        Ok(Some(Self::namespace_to_response(&ns)))
    }

    /// Secret engines mounted into every newly created namespace so it is
    /// immediately usable. Mirrors the core defaults a fresh root install
    /// receives, minus `sys/` (implicit and global — never namespaced) and the
    /// bastion-fleet engines (`rustion/`, `ssh-broker/`) which are opt-in.
    /// `pki`/`ssh` are likewise not defaults anywhere and stay per-namespace.
    const DEFAULT_NAMESPACE_MOUNTS: &'static [(&'static str, &'static str, &'static str)] = &[
        ("secret/", "kv-v2", "key/value secret storage"),
        ("resources/", "resource", "infrastructure resource storage"),
        ("files/", "files", "binary file resources (keys, certs, configs)"),
        ("resource-group/", "resource-group", "named collections of resources"),
        ("identity/", "identity", "user and application group management"),
    ];

    /// Seed a freshly created namespace with [`Self::DEFAULT_NAMESPACE_MOUNTS`].
    /// Best-effort: a single mount failure is logged and does not abort the
    /// namespace creation, so the namespace still exists and the operator can
    /// mount the remainder manually.
    async fn seed_default_namespace_mounts(&self, ns_uuid: &str, ns_path: &str) {
        let Some(module) =
            self.core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
        else {
            log::warn!(target: "namespace", "cannot seed default mounts: namespace module unavailable");
            return;
        };
        for (path, logical_type, description) in Self::DEFAULT_NAMESPACE_MOUNTS {
            let me = crate::mount::MountEntry {
                table: crate::mount::MOUNT_TABLE_TYPE.to_string(),
                tainted: false,
                uuid: crate::utils::generate_uuid(),
                path: path.to_string(),
                logical_type: logical_type.to_string(),
                description: description.to_string(),
                ..Default::default()
            };
            if let Err(e) = module.registry.mount(&self.core, ns_uuid, ns_path, &me).await {
                log::warn!(
                    target: "namespace",
                    "seeding default mount {path} in namespace {ns_path:?} failed: {e}"
                );
            }
        }
    }

    pub async fn handle_namespace_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_namespace_store()?;
        let path = req.get_data_as_str("path")?;

        // Cascade-unmount: tear down the namespace's engines (and their data)
        // before removing the namespace record. Namespaces are auto-seeded with
        // default engines, so a strict "unmount everything first" guard would
        // make even an unused namespace undeletable. Child namespaces still
        // block deletion (enforced in `store.delete`). `unmount_one` clears each
        // engine's barrier view, so this destroys any secrets/resources the
        // namespace held — deleting a tenant removes the tenant's data.
        if let Some(ns) = store.get_by_path(&path).await? {
            if let Some(module) =
                self.core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            {
                let mounts = module
                    .registry
                    .list_mounts(&self.core, &ns.uuid, &ns.path)
                    .await
                    .unwrap_or_default();
                for (mount_path, _type, _desc) in mounts {
                    if let Err(e) =
                        module.registry.unmount(&self.core, &ns.uuid, &ns.path, &mount_path).await
                    {
                        log::warn!(
                            target: "namespace",
                            "cascade-unmount {mount_path} in namespace {:?} failed: {e}",
                            ns.path
                        );
                    }
                }
                module.registry.forget(&ns.uuid);
            }
        }

        // Mounts are gone now; `store.delete` still refuses the root and any
        // namespace that has child namespaces.
        store.delete(&path, 0).await?;
        Ok(None)
    }

    fn resolve_namespace_link_store(
        &self,
    ) -> Result<Arc<crate::modules::namespace::IdentityLinkStore>, RvError> {
        self.core
            .module_manager
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.link_store())
            .ok_or_else(|| bv_error_string!("namespace identity-link store unavailable"))
    }

    fn link_to_response(link: &crate::modules::namespace::IdentityLink) -> Response {
        let members: Vec<Value> = link
            .members
            .iter()
            .map(|m| json!({ "namespace": m.namespace, "entity_id": m.entity_id }))
            .collect();
        let data = json!({
            "id": link.id,
            "parent_namespace": link.parent_namespace,
            "label": link.label,
            "members": members,
            "created_at": link.created_at,
        })
        .as_object()
        .cloned();
        Response::data_response(data)
    }

    pub async fn handle_namespace_link_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let links = self.resolve_namespace_link_store()?;
        let parent = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
        let mut ids: Vec<String> = links.list(&parent).await?.into_iter().map(|l| l.id).collect();
        ids.sort();
        Ok(Some(Response::list_response(&ids)))
    }

    pub async fn handle_namespace_link_create(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let links = self.resolve_namespace_link_store()?;
        let ns_store = self.resolve_namespace_store()?;
        let parent = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
        let label = req
            .get_data("label")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let members_val = req.get_data("members")?;
        let arr = members_val
            .as_array()
            .ok_or_else(|| bv_error_response_status!(400, "members must be an array"))?;
        let mut members = Vec::with_capacity(arr.len());
        for m in arr {
            let namespace = m
                .get("namespace")
                .and_then(|v| v.as_str())
                .ok_or_else(|| bv_error_response_status!(400, "each member needs a namespace"))?
                .to_string();
            let entity_id = m
                .get("entity_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| bv_error_response_status!(400, "each member needs an entity_id"))?
                .to_string();
            members.push(crate::modules::namespace::IdentityLinkMember { namespace, entity_id });
        }

        let link = links.create(&ns_store, &parent, &label, members).await?;
        Ok(Some(Self::link_to_response(&link)))
    }

    pub async fn handle_namespace_link_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let links = self.resolve_namespace_link_store()?;
        let parent = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
        let id = req.get_data_as_str("id")?;
        match links.get(&parent, &id).await? {
            Some(link) => Ok(Some(Self::link_to_response(&link))),
            None => Err(bv_error_response_status!(404, &format!("no such identity link: {id:?}"))),
        }
    }

    pub async fn handle_namespace_link_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let links = self.resolve_namespace_link_store()?;
        let parent = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
        let id = req.get_data_as_str("id")?;
        links.delete(&parent, &id).await?;
        Ok(None)
    }

    fn resolve_ns_assignment_store(
        &self,
    ) -> Result<crate::modules::namespace::NsAssignmentStore, RvError> {
        crate::modules::namespace::NsAssignmentStore::new(&self.core)
    }

    /// Normalize a captured mount segment (e.g. `userpass`) to the
    /// trailing-slash form the login paths key on (`userpass/`), so a record
    /// written via the API is found by `enforce_login_assignment`.
    fn normalize_assignment_mount(mount: &str) -> String {
        format!("{}/", mount.trim_end_matches('/'))
    }

    fn ns_assignment_to_response(mount: &str, name: &str, namespaces: &[String], updated_at: &str) -> Response {
        let data = json!({
            "mount": mount,
            "name": name,
            "namespaces": namespaces,
            "updated_at": updated_at,
        })
        .as_object()
        .cloned();
        Response::data_response(data)
    }

    pub async fn handle_ns_assignment_list(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_ns_assignment_store()?;
        let mut records = store.list().await?;
        records.sort_by(|a, b| (a.mount.as_str(), a.name.as_str()).cmp(&(b.mount.as_str(), b.name.as_str())));
        let assignments: Vec<Value> = records
            .iter()
            .map(|a| json!({ "mount": a.mount, "name": a.name, "namespaces": a.namespaces, "updated_at": a.updated_at }))
            .collect();
        Ok(Some(Response::data_response(
            json!({ "assignments": assignments }).as_object().cloned(),
        )))
    }

    pub async fn handle_ns_assignment_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_ns_assignment_store()?;
        let mount = Self::normalize_assignment_mount(&req.get_data_as_str("mount")?);
        let name = req.get_data_as_str("name")?;
        match store.get(&mount, &name).await? {
            Some(a) => Ok(Some(Self::ns_assignment_to_response(&a.mount, &a.name, &a.namespaces, &a.updated_at))),
            // No record ⇒ unrestricted; report it explicitly (empty list) rather
            // than 404 so the GUI can render the "all namespaces" state.
            None => Ok(Some(Self::ns_assignment_to_response(&mount, &name, &[], ""))),
        }
    }

    pub async fn handle_ns_assignment_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_ns_assignment_store()?;
        let ns_store = self.resolve_namespace_store()?;
        let mount = Self::normalize_assignment_mount(&req.get_data_as_str("mount")?);
        let name = req.get_data_as_str("name")?;
        let namespaces: Vec<String> = req
            .get_data("namespaces")
            .ok()
            .and_then(|v| v.as_array().cloned())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        match store.set(&ns_store, &mount, &name, namespaces).await? {
            Some(a) => Ok(Some(Self::ns_assignment_to_response(&a.mount, &a.name, &a.namespaces, &a.updated_at))),
            None => Ok(None), // empty list cleared the restriction
        }
    }

    pub async fn handle_ns_assignment_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_ns_assignment_store()?;
        let mount = Self::normalize_assignment_mount(&req.get_data_as_str("mount")?);
        let name = req.get_data_as_str("name")?;
        store.delete(&mount, &name).await?;
        Ok(None)
    }

    fn resolve_default_account_store(
        &self,
    ) -> Result<crate::modules::identity::DefaultResourceAccountStore, RvError> {
        crate::modules::identity::DefaultResourceAccountStore::new(&self.core)
    }

    /// Build a default-account response. The Windows password is **never**
    /// echoed as plaintext on admin/list reads — only `has_windows_password` is
    /// surfaced. `reveal_password` is `Some` exactly on the caller-scoped `self`
    /// path, where the connect host needs the value to inject it.
    fn default_account_to_response(
        rec: Option<&crate::modules::identity::DefaultResourceAccount>,
        echo_mount: &str,
        echo_name: &str,
        reveal_password: bool,
    ) -> Response {
        let mut data = serde_json::Map::new();
        match rec {
            Some(a) => {
                data.insert("mount".into(), Value::String(a.mount.clone()));
                data.insert("name".into(), Value::String(a.name.clone()));
                data.insert("linux".into(), Value::String(a.linux.clone()));
                data.insert("macos".into(), Value::String(a.macos.clone()));
                data.insert("windows".into(), Value::String(a.windows.clone()));
                data.insert(
                    "has_windows_password".into(),
                    Value::Bool(a.has_windows_password()),
                );
                data.insert("updated_at".into(), Value::String(a.updated_at.clone()));
                if reveal_password {
                    data.insert(
                        "windows_password".into(),
                        Value::String(a.windows_password.clone()),
                    );
                }
            }
            None => {
                // No record ⇒ unconfigured; report explicitly (empty fields)
                // rather than 404 so the GUI renders an editable empty form.
                data.insert("mount".into(), Value::String(echo_mount.to_string()));
                data.insert("name".into(), Value::String(echo_name.to_string()));
                data.insert("linux".into(), Value::String(String::new()));
                data.insert("macos".into(), Value::String(String::new()));
                data.insert("windows".into(), Value::String(String::new()));
                data.insert("has_windows_password".into(), Value::Bool(false));
                data.insert("updated_at".into(), Value::String(String::new()));
                if reveal_password {
                    data.insert("windows_password".into(), Value::String(String::new()));
                }
            }
        }
        Response::data_response(Some(data))
    }

    pub async fn handle_default_account_list(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_default_account_store()?;
        let mut records = store.list().await?;
        records.sort_by(|a, b| {
            (a.mount.as_str(), a.name.as_str()).cmp(&(b.mount.as_str(), b.name.as_str()))
        });
        let accounts: Vec<Value> = records
            .iter()
            .map(|a| {
                // List never reveals stored passwords — only their presence.
                json!({
                    "mount": a.mount,
                    "name": a.name,
                    "linux": a.linux,
                    "macos": a.macos,
                    "windows": a.windows,
                    "has_windows_password": a.has_windows_password(),
                    "updated_at": a.updated_at,
                })
            })
            .collect();
        Ok(Some(Response::data_response(
            json!({ "accounts": accounts }).as_object().cloned(),
        )))
    }

    pub async fn handle_default_account_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_default_account_store()?;
        let mount = Self::normalize_assignment_mount(&req.get_data_as_str("mount")?);
        let name = req.get_data_as_str("name")?;
        let rec = store.get(&mount, &name).await?;
        // Admin read: password masked (has_windows_password only).
        Ok(Some(Self::default_account_to_response(
            rec.as_ref(),
            &mount,
            &name,
            false,
        )))
    }

    pub async fn handle_default_account_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_default_account_store()?;
        let mount = Self::normalize_assignment_mount(&req.get_data_as_str("mount")?);
        let name = req.get_data_as_str("name")?;
        let linux = req.get_data_as_str("linux").unwrap_or_default();
        let macos = req.get_data_as_str("macos").unwrap_or_default();
        let windows = req.get_data_as_str("windows").unwrap_or_default();
        // Password write-preserve semantics: the field is only changed when the
        // request explicitly carries `windows_password` (empty string clears
        // it). Omitting the key keeps whatever is stored, so re-saving the
        // record without re-typing the password does not wipe it.
        let windows_password = match req.get_data("windows_password") {
            Ok(v) => v.as_str().unwrap_or("").to_string(),
            Err(_) => store
                .get(&mount, &name)
                .await?
                .map(|a| a.windows_password)
                .unwrap_or_default(),
        };
        let rec = store
            .set(&mount, &name, &linux, &macos, &windows, &windows_password)
            .await?;
        match rec {
            // Echo back masked (never the plaintext that was just written).
            Some(a) => Ok(Some(Self::default_account_to_response(
                Some(&a),
                &mount,
                &name,
                false,
            ))),
            None => Ok(None), // all-empty cleared the record
        }
    }

    pub async fn handle_default_account_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_default_account_store()?;
        let mount = Self::normalize_assignment_mount(&req.get_data_as_str("mount")?);
        let name = req.get_data_as_str("name")?;
        store.delete(&mount, &name).await?;
        Ok(None)
    }

    /// Resolve the *calling* principal's own default accounts from the request
    /// token. Tries, in order: the `(mount_path, username)` stamped at login
    /// (userpass / ferrogate fast path), then every alias on the caller's
    /// identity entity (covers approle / OIDC / SAML / cert — any entity-backed
    /// login). The first principal with a record wins. When nothing is on file
    /// the response carries empty fields and the Connect path fails closed.
    ///
    /// This is the only path that reveals the stored Windows password, and only
    /// ever the caller's *own* — the connect host injects it into the RDP
    /// session. The endpoint is caller-scoped (not root), so a token can read
    /// only its own record.
    pub async fn handle_default_account_self(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        let auth = token_store
            .check_token(&req.path, &req.client_token)
            .await?
            .ok_or(RvError::ErrPermissionDenied)?;

        // Candidate principals to try, in priority order. Mounts are normalized
        // to the trailing-slash form the admin writes key on.
        let mut candidates: Vec<(String, String)> = Vec::new();
        let push = |c: &mut Vec<(String, String)>, mount: &str, name: &str| {
            if !mount.trim().is_empty() && !name.trim().is_empty() {
                let m = Self::normalize_assignment_mount(mount);
                if !c.iter().any(|(em, en)| em == &m && en == name) {
                    c.push((m, name.to_string()));
                }
            }
        };

        // 1) Fast path: backends that stamp mount_path + username.
        if let (Some(mp), Some(un)) = (
            auth.metadata.get("mount_path"),
            auth.metadata.get("username"),
        ) {
            push(&mut candidates, mp, un);
        }

        // 2) General path: every alias on the caller's identity entity.
        if let Some(eid) = auth.metadata.get("entity_id").filter(|s| !s.is_empty()) {
            if let Ok(identity) = self.get_module::<IdentityModule>("identity") {
                if let Some(entity_store) = identity.entity_store() {
                    if let Some(entity) = entity_store.get_entity(eid).await? {
                        push(&mut candidates, &entity.primary_mount, &entity.primary_name);
                        for alias in &entity.aliases {
                            push(&mut candidates, &alias.mount, &alias.name);
                        }
                    }
                }
            }
        }

        let store = self.resolve_default_account_store()?;
        for (mount, name) in &candidates {
            if let Some(a) = store.get(mount, name).await? {
                return Ok(Some(Self::default_account_to_response(
                    Some(&a),
                    mount,
                    name,
                    true,
                )));
            }
        }

        // Nothing on file — echo the best-known principal for context.
        let (em, en) = candidates.first().cloned().unwrap_or_default();
        Ok(Some(Self::default_account_to_response(None, &em, &en, true)))
    }
}

impl SystemModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self { name: "system".to_string(), backend: SystemBackend::new(core) }
    }
}

impl Module for SystemModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let sys = self.backend.clone();
        let sys_backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut sys_backend = sys.new_backend();
            sys_backend.init()?;
            Ok(Arc::new(sys_backend))
        };
        core.add_logical_backend("system", Arc::new(sys_backend_new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("system")
    }
}

fn sanitize_path(path: &str) -> String {
    let mut new_path = path.to_string();
    if !new_path.ends_with('/') {
        new_path.push('/');
    }
    if new_path.starts_with('/') {
        new_path = new_path[1..].to_string();
    }
    new_path
}

#[cfg(test)]
mod mod_system_tests {
    use super::*;
    use crate::test_utils::TestHttpServer;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_system_internal_ui_mounts() {
        let mut test_http_server = TestHttpServer::new("test_system_internal_ui_mounts", true).await;

        // set token
        test_http_server.token = test_http_server.root_token.clone();

        let ret = test_http_server.read("sys/internal/ui/mounts", None);
        assert!(ret.is_ok());
        let ret = ret.unwrap().1;
        assert!(ret.is_object());
        let ret = ret.as_object().unwrap();
        assert!(ret.contains_key("auth"));
        assert!(ret.contains_key("secret"));
        assert_eq!(ret["auth"]["token/"]["type"], Value::String("token".into()));
        assert!(ret["auth"]["token/"].is_object());
        assert!(ret["secret"]["secret/"].is_object());
        assert_eq!(ret["secret"]["secret/"]["type"], Value::String("kv-v2".into()));
        assert!(ret["secret"]["sys/"].is_object());
        assert_eq!(ret["secret"]["sys/"]["type"], Value::String("system".into()));
        // Identity mount for user/application groups.
        assert!(ret["secret"]["identity/"].is_object());
        assert_eq!(ret["secret"]["identity/"]["type"], Value::String("identity".into()));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_capabilities_self_connect_only_vs_read() {
        let mut server = TestHttpServer::new("test_capabilities_self_connect_only", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();
        // capabilities-self is a v2-only route; strip the hardcoded `/v1`
        // so `v2/sys/capabilities-self` resolves (mirrors the batch tests).
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        // A connect-only policy and a read+connect policy on the same path.
        server
            .write(
                "v1/sys/policies/acl/connect-only",
                serde_json::json!({
                    "policy": "path \"resources/secrets/db-prod/*\" { capabilities = [\"connect\"] }"
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap();
        server
            .write(
                "v1/sys/policies/acl/read-connect",
                serde_json::json!({
                    "policy": "path \"resources/secrets/db-prod/*\" { capabilities = [\"read\", \"list\", \"connect\"] }"
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap();

        // Two userpass users, one per policy.
        server
            .write(
                "v1/sys/auth/pass",
                serde_json::json!({ "type": "userpass" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        for (user, policy) in [("conn", "connect-only"), ("both", "read-connect")] {
            server
                .write(
                    &format!("v1/auth/pass/users/{user}"),
                    serde_json::json!({
                        "password": "hunter22XX!",
                        "token_policies": policy,
                        "ttl": 0,
                    })
                    .as_object()
                    .cloned(),
                    Some(&root),
                )
                .unwrap();
        }

        let login = |user: &str| -> String {
            server
                .write(
                    &format!("v1/auth/pass/login/{user}"),
                    serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                    None,
                )
                .unwrap()
                .1
                .get("auth")
                .and_then(|a| a.get("client_token"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        };

        let caps_for = |token: &str| -> Vec<String> {
            let (status, resp) = server
                .request(
                    "POST",
                    "v2/sys/capabilities-self",
                    serde_json::json!({ "paths": ["resources/secrets/db-prod/"] })
                        .as_object()
                        .cloned(),
                    Some(token),
                    None,
                )
                .unwrap();
            assert_eq!(status, 200, "capabilities-self must succeed: {resp:?}");
            resp.get("capabilities")
                .and_then(|c| c.get("resources/secrets/db-prod/"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };

        // Connect-only token: `connect` present, `read` absent — the
        // signal the GUI uses to hide credentials.
        let conn_caps = caps_for(&login("conn"));
        assert!(conn_caps.contains(&"connect".to_string()), "got {conn_caps:?}");
        assert!(!conn_caps.contains(&"read".to_string()), "got {conn_caps:?}");

        // read+connect token: both present.
        let both_caps = caps_for(&login("both"));
        assert!(both_caps.contains(&"connect".to_string()), "got {both_caps:?}");
        assert!(both_caps.contains(&"read".to_string()), "got {both_caps:?}");
    }

    /// Regression (namespace token binding): `capabilities-self` must reflect
    /// whether the calling token may actually *operate* in the active
    /// namespace — not just its raw policy capabilities. A token bound to one
    /// namespace, browsing another it cannot operate in, previously saw full
    /// capabilities (the handler is `sys/`-scoped, hence exempt from the
    /// request-time binding check), so the GUI enabled write controls the
    /// server then rejected with 403. This test reproduces the reported bug
    /// (a root-bound login switched to a child namespace) and also verifies
    /// that `child_visible_default` is honored at login.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_capabilities_self_namespace_binding_aware() {
        let mut server = TestHttpServer::new("test_caps_self_ns_binding", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        // Namespace tree: `nsa` mints child-visible tokens, `nsb` does not.
        for (path, cvd) in [("nsa", true), ("nsa/sub", true), ("nsb", false), ("nsb/sub", false)] {
            let (s, r) = server
                .write(
                    &format!("v1/sys/namespaces/{path}"),
                    serde_json::json!({ "child_visible_default": cvd }).as_object().cloned(),
                    Some(&root),
                )
                .unwrap();
            assert!((200..300).contains(&s), "ns create {path}: {s} {r:?}");
        }

        // A wildcard policy so ACL would grant everything everywhere — this
        // proves the empty result below comes from *binding*, not from a
        // missing policy grant.
        server
            .write(
                "v1/sys/policies/acl/broad",
                serde_json::json!({
                    "policy": "path \"*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"] }"
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap();
        server
            .write(
                "v1/sys/auth/pass",
                serde_json::json!({ "type": "userpass" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        server
            .write(
                "v1/auth/pass/users/alice",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "broad", "ttl": 0 })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();

        // Login carrying an optional namespace header; returns the token.
        let login_ns = |server: &TestHttpServer, ns: Option<&str>| -> String {
            let headers: Vec<(&str, &str)> =
                ns.map(|n| vec![("X-BastionVault-Namespace", n)]).unwrap_or_default();
            server
                .request_with_headers(
                    "POST",
                    "v1/auth/pass/login/alice",
                    serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                    None,
                    None,
                    &headers,
                )
                .unwrap()
                .1
                .get("auth")
                .and_then(|a| a.get("client_token"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        };

        // capabilities-self against `secret/data/x` with an optional active-ns header.
        let caps_ns = |server: &TestHttpServer, token: &str, ns: Option<&str>| -> Value {
            let headers: Vec<(&str, &str)> =
                ns.map(|n| vec![("X-BastionVault-Namespace", n)]).unwrap_or_default();
            let (s, r) = server
                .request_with_headers(
                    "POST",
                    "v2/sys/capabilities-self",
                    serde_json::json!({ "paths": ["secret/data/x"] }).as_object().cloned(),
                    Some(token),
                    None,
                    &headers,
                )
                .unwrap();
            assert_eq!(s, 200, "capabilities-self must 200: {r:?}");
            r
        };

        // The reported bug: a token bound to root (login with no header;
        // root's child_visible_default is false) switched to a child namespace
        // must report itself inoperable with empty capabilities.
        let root_bound = login_ns(&server, None);
        let denied = caps_ns(&server, &root_bound, Some("nsa"));
        assert_eq!(
            denied["namespace_operable"],
            serde_json::json!(false),
            "root-bound token must be inoperable in a child namespace: {denied:?}"
        );
        assert_eq!(denied["token_namespace"], serde_json::json!(""));
        assert_eq!(denied["active_namespace"], serde_json::json!("nsa"));
        assert_eq!(
            denied["capabilities"]["secret/data/x"],
            serde_json::json!([]),
            "capabilities must be empty when the token cannot operate here"
        );

        // Control: the SAME token at root is operable, and the wildcard policy
        // surfaces — confirming the empty result above was binding, not ACL.
        let at_root = caps_ns(&server, &root_bound, None);
        assert_eq!(at_root["namespace_operable"], serde_json::json!(true));
        assert!(
            at_root["capabilities"]["secret/data/x"]
                .as_array()
                .map(|a| a.contains(&serde_json::json!("create")))
                .unwrap_or(false),
            "root-scoped caps must surface: {at_root:?}"
        );

        // child_visible_default honored at login: read the minted token's
        // binding straight from the login response's `auth.metadata` (no
        // follow-up call, which would need a per-namespace policy grant). A
        // token minted in `nsa` (child_visible_default = true) carries
        // child_visible = true; one minted in `nsb` (false) does not.
        let login_meta = |server: &TestHttpServer, ns: &str| -> Value {
            server
                .request_with_headers(
                    "POST",
                    "v1/auth/pass/login/alice",
                    serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                    None,
                    None,
                    &[("X-BastionVault-Namespace", ns)],
                )
                .unwrap()
                .1["auth"]["metadata"]
                .clone()
        };

        let nsa_meta = login_meta(&server, "nsa");
        assert_eq!(
            nsa_meta["namespace_path"],
            serde_json::json!("nsa"),
            "token must be bound to its login namespace: {nsa_meta:?}"
        );
        assert_eq!(
            nsa_meta["child_visible"],
            serde_json::json!("true"),
            "login must honor child_visible_default = true: {nsa_meta:?}"
        );

        let nsb_meta = login_meta(&server, "nsb");
        assert_eq!(
            nsb_meta["child_visible"],
            serde_json::json!("false"),
            "login must honor child_visible_default = false: {nsb_meta:?}"
        );
    }

    /// Multi-tenancy regression: a token bound to a non-root namespace must be
    /// able to reach the self-service endpoints (`sys/capabilities-self`,
    /// `auth/token/lookup-self`, …). A child namespace "starts empty" — it has
    /// no `default` policy and inherits none from root — so before the implicit
    /// `namespace-self` grant these preflighted to 403, leaving a namespace
    /// principal unable to look itself up or query its own capabilities.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_bound_token_reaches_self_endpoints() {
        let mut server = TestHttpServer::new("test_ns_self_endpoints", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        // A child namespace and a userpass user whose only policy exists at
        // root (so it is absent from the child keyspace — the "empty
        // namespace" condition).
        let (s, r) = server
            .write("v1/sys/namespaces/nsx", serde_json::json!({}).as_object().cloned(), Some(&root))
            .unwrap();
        assert!((200..300).contains(&s), "ns create: {s} {r:?}");
        server
            .write(
                "v1/sys/policies/acl/rootonly",
                serde_json::json!({ "policy": "path \"secret/data/z\" { capabilities = [\"read\"] }" })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        server
            .write("v1/sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), Some(&root))
            .unwrap();
        server
            .write(
                "v1/auth/pass/users/bob",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "rootonly", "ttl": 0 })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();

        // Log in inside `nsx` → the minted token is bound to `nsx`.
        let (s, r) = server
            .request_with_headers(
                "POST",
                "v1/auth/pass/login/bob",
                serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
                None,
                &[("X-BastionVault-Namespace", "nsx")],
            )
            .unwrap();
        assert_eq!(s, 200, "namespace login must succeed: {r:?}");
        let token = r["auth"]["client_token"].as_str().unwrap().to_string();
        assert_eq!(r["auth"]["metadata"]["namespace_path"], serde_json::json!("nsx"));

        // capabilities-self succeeds (was 403 before the fix) and reports the
        // token as operable in its own namespace.
        let (s, r) = server
            .request_with_headers(
                "POST",
                "v2/sys/capabilities-self",
                serde_json::json!({ "paths": ["secret/data/z"] }).as_object().cloned(),
                Some(&token),
                None,
                &[("X-BastionVault-Namespace", "nsx")],
            )
            .unwrap();
        assert_eq!(s, 200, "namespace-bound capabilities-self must succeed: {r:?}");
        assert_eq!(r["namespace_operable"], serde_json::json!(true));

        // lookup-self succeeds and returns the caller's own token record.
        let (s, r) = server.read("v1/auth/token/lookup-self", Some(&token)).unwrap();
        assert_eq!(s, 200, "namespace-bound lookup-self must succeed: {r:?}");
        assert_eq!(
            r["data"]["meta"]["namespace_path"],
            serde_json::json!("nsx"),
            "lookup-self must return the caller's own record: {r:?}"
        );
    }

    /// Regression: `capabilities-self` must not advertise scope-gated
    /// (`scopes = ["shared"|"owner"]`) capabilities the caller has not
    /// actually been granted via ownership or an active share. The
    /// `acl.capabilities` dry-run runs as `Operation::List`, whose
    /// `is_list` short-circuit defers scope filtering and would otherwise
    /// leak the rule's full capability set (e.g. `update`) — making the GUI
    /// enable Edit/Delete for a read-only share-grantee that the server
    /// then rejects with 403. Ungated rules must still report fully.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_capabilities_self_scope_gated_not_leaked() {
        let mut server = TestHttpServer::new("test_capabilities_self_scope_gated", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        // One policy with a scope-gated rule (no share/owner exists for the
        // caller, so its caps must NOT surface) and an ungated rule (must
        // surface fully — guards against over-pruning).
        let policy_hcl = r#"
            path "resources/resources/shared-thing" {
                capabilities = ["read", "list", "update"]
                scopes       = ["shared"]
            }
            path "resources/resources/plain-thing" {
                capabilities = ["read", "update"]
            }
        "#;
        let (pol_status, pol_resp) = server
            .write(
                "v1/sys/policies/acl/scoped-res",
                serde_json::json!({ "policy": policy_hcl }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(
            (200..300).contains(&pol_status),
            "policy write must succeed: {pol_status} {pol_resp:?}"
        );

        server
            .write(
                "v1/sys/auth/pass",
                serde_json::json!({ "type": "userpass" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        server
            .write(
                "v1/auth/pass/users/grantee",
                serde_json::json!({
                    "password": "hunter22XX!",
                    "token_policies": "scoped-res",
                    "ttl": 0,
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap();

        let token = server
            .write(
                "v1/auth/pass/login/grantee",
                serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
            )
            .unwrap()
            .1
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let caps_for = |path: &str| -> Vec<String> {
            let (status, resp) = server
                .request(
                    "POST",
                    "v2/sys/capabilities-self",
                    serde_json::json!({ "paths": [path] }).as_object().cloned(),
                    Some(&token),
                    None,
                )
                .unwrap();
            assert_eq!(status, 200, "capabilities-self must succeed: {resp:?}");
            resp.get("capabilities")
                .and_then(|c| c.get(path))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };

        // Scope-gated rule, caller has no share/ownership: the rule's
        // capabilities (incl. `update`) must NOT leak.
        let shared = caps_for("resources/resources/shared-thing");
        assert!(
            !shared.contains(&"update".to_string()),
            "scope-gated `update` must not leak to a non-grantee: {shared:?}"
        );
        assert!(
            !shared.contains(&"read".to_string()),
            "scope-gated `read` must not leak to a non-grantee: {shared:?}"
        );

        // Ungated rule: full capabilities still reported (no over-pruning).
        let plain = caps_for("resources/resources/plain-thing");
        assert!(plain.contains(&"read".to_string()), "got {plain:?}");
        assert!(plain.contains(&"update".to_string()), "got {plain:?}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_acl_dry_run_endpoint() {
        let mut server = TestHttpServer::new("test_policy_acl_dry_run", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();
        // Dry-run lives under /v2 (project rule: new routes are v2-only);
        // strip the harness's hardcoded `/v1` so `v2/...` resolves.
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        // --- A draft exercising every match_kind + deny precedence ----
        let draft = r#"
            path "secret/data/exact" { capabilities = ["read"] }
            path "secret/data/team/*" { capabilities = ["read", "create"] }
            path "secret/data/team/+/config" { capabilities = ["update"] }
            path "secret/data/locked/*" { capabilities = ["deny"] }
        "#;
        let cases = serde_json::json!([
            { "path": "secret/data/exact", "capability": "read" },
            { "path": "secret/data/exact", "capability": "delete" },
            { "path": "secret/data/team/x/y", "capability": "create" },
            { "path": "secret/data/team/alpha/config", "capability": "update" },
            { "path": "secret/data/locked/thing", "capability": "read" },
            { "path": "nowhere/here", "capability": "read" }
        ]);
        let (status, resp) = server
            .request(
                "POST",
                "v2/sys/policies/acl/test",
                serde_json::json!({ "policy": draft, "cases": cases }).as_object().cloned(),
                Some(&root),
                None,
            )
            .unwrap();
        assert_eq!(status, 200, "dry-run must succeed: {resp:?}");
        assert_eq!(resp["parse_ok"], Value::Bool(true), "{resp:?}");
        let results = resp["results"].as_array().unwrap();
        assert_eq!(results.len(), 6);

        // exact grant
        assert_eq!(results[0]["allowed"], Value::Bool(true));
        assert_eq!(results[0]["match_kind"], "exact");
        assert_eq!(results[0]["matched_path"], "secret/data/exact");
        // exact rule present but capability absent
        assert_eq!(results[1]["allowed"], Value::Bool(false));
        assert_eq!(results[1]["match_kind"], "exact");
        // prefix grant
        assert_eq!(results[2]["allowed"], Value::Bool(true));
        assert_eq!(results[2]["match_kind"], "prefix");
        assert_eq!(results[2]["matched_path"], "secret/data/team/*");
        // segment-wildcard grant
        assert_eq!(results[3]["allowed"], Value::Bool(true));
        assert_eq!(results[3]["match_kind"], "segment_wildcard");
        assert_eq!(results[3]["matched_path"], "secret/data/team/+/config");
        // explicit deny
        assert_eq!(results[4]["allowed"], Value::Bool(false));
        assert_eq!(results[4]["denied_by_deny"], Value::Bool(true));
        // no match
        assert_eq!(results[5]["allowed"], Value::Bool(false));
        assert_eq!(results[5]["denied_by_deny"], Value::Bool(false));
        assert_eq!(results[5]["match_kind"], "none");
        assert_eq!(results[5]["matched_path"], Value::Null);

        // --- Parse error is a normal result, not an HTTP error --------
        let (status, resp) = server
            .request(
                "POST",
                "v2/sys/policies/acl/test",
                serde_json::json!({ "policy": "path \"x\" { capabilities = [", "cases": [] })
                    .as_object()
                    .cloned(),
                Some(&root),
                None,
            )
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(resp["parse_ok"], Value::Bool(false), "{resp:?}");
        assert!(!resp["errors"].as_array().unwrap().is_empty());

        // --- The forbidden `+*` wildcard combo is reported as a parse
        //     error (the parser rejects it before save). --------------
        let (_status, resp) = server
            .request(
                "POST",
                "v2/sys/policies/acl/test",
                serde_json::json!({ "policy": "path \"secret/+*\" { capabilities = [\"read\"] }", "cases": [] })
                    .as_object()
                    .cloned(),
                Some(&root),
                None,
            )
            .unwrap();
        assert_eq!(resp["parse_ok"], Value::Bool(false), "{resp:?}");

        // --- Correct verdict for a built-in: administrator grants every
        //     capability on every path via a `*` prefix rule. ----------
        let (status, admin) = server.read("v1/sys/policies/acl/administrator", Some(&root)).unwrap();
        assert_eq!(status, 200, "{admin:?}");
        let admin_hcl = admin["policy"].as_str().expect("administrator policy HCL");
        let (status, resp) = server
            .request(
                "POST",
                "v2/sys/policies/acl/test",
                serde_json::json!({
                    "policy": admin_hcl,
                    "cases": [ { "path": "secret/data/anything", "capability": "sudo" } ]
                })
                .as_object()
                .cloned(),
                Some(&root),
                None,
            )
            .unwrap();
        assert_eq!(status, 200, "{resp:?}");
        assert_eq!(resp["parse_ok"], Value::Bool(true));
        assert_eq!(resp["results"][0]["allowed"], Value::Bool(true));
        assert_eq!(resp["results"][0]["match_kind"], "prefix");

        // --- The dry-run never persists. The draft above had no `name`
        //     (stored internally as `__draft__`); it must not appear in
        //     the policy list, and the built-ins are untouched. --------
        let (status, list) = server.read("v1/sys/policies/acl", Some(&root)).unwrap();
        assert_eq!(status, 200, "{list:?}");
        let keys: Vec<String> = list["keys"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        assert!(!keys.iter().any(|k| k == "__draft__"), "dry-run must not persist: {keys:?}");
        assert!(keys.iter().any(|k| k == "administrator"), "built-ins intact: {keys:?}");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_tests_persistence_endpoint() {
        let mut server = TestHttpServer::new("test_policy_tests_persistence", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        // Empty by default.
        let (status, resp) = server.read("v2/sys/policy-tests/my-policy", Some(&root)).unwrap();
        assert_eq!(status, 200, "{resp:?}");
        assert_eq!(resp["cases"].as_array().unwrap().len(), 0);

        // Save two cases.
        let (status, _) = server
            .request(
                "POST",
                "v2/sys/policy-tests/my-policy",
                serde_json::json!({
                    "cases": [
                        { "path": "secret/data/x", "capability": "read", "expect": "allow", "note": "sre reads" },
                        { "path": "secret/data/x", "capability": "delete", "expect": "deny" }
                    ]
                })
                .as_object()
                .cloned(),
                Some(&root),
                None,
            )
            .unwrap();
        assert_eq!(status, 204, "write returns No Content");

        // Read them back intact.
        let (_status, resp) = server.read("v2/sys/policy-tests/my-policy", Some(&root)).unwrap();
        let cases = resp["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0]["path"], "secret/data/x");
        assert_eq!(cases[0]["capability"], "read");
        assert_eq!(cases[0]["expect"], "allow");
        assert_eq!(cases[0]["note"], "sre reads");
        assert_eq!(cases[1]["expect"], "deny");

        // An empty array clears them.
        let (status, _) = server
            .request(
                "POST",
                "v2/sys/policy-tests/my-policy",
                serde_json::json!({ "cases": [] }).as_object().cloned(),
                Some(&root),
                None,
            )
            .unwrap();
        assert_eq!(status, 204);
        let (_status, resp) = server.read("v2/sys/policy-tests/my-policy", Some(&root)).unwrap();
        assert_eq!(resp["cases"].as_array().unwrap().len(), 0);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_cache_flush_endpoint_as_root_succeeds() {
        let mut server = TestHttpServer::new("test_cache_flush_endpoint", true).await;
        server.token = server.root_token.clone();

        // POST sys/cache/flush as root succeeds. Same response shape as
        // sys/audit disable (204 No Content via Ok(None)).
        let _ = server.write("sys/cache/flush", None, None).unwrap();
    }

    /// Defense-in-depth regression: a userpass caller with only the
    /// `default` policy must NOT see any secret-engine or auth-method
    /// mounts via `sys/internal/ui/mounts`. This is the endpoint the
    /// Tauri dashboard now routes through after we closed the
    /// bypass that previously read the router's mount table directly.
    /// If a regression reintroduces that bypass — or the ACL filter
    /// in `handle_internal_ui_mounts_read` starts leaking — this test
    /// catches it.
    /// Userpass create / password-change / delete all show up in
    /// the audit trail under the `user` category. Regression for the
    /// gap where user lifecycle operations were invisible on the
    /// Admin → Audit page.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_includes_user_lifecycle() {
        let mut server =
            TestHttpServer::new("test_audit_events_includes_user_lifecycle", true).await;
        server.token = server.root_token.clone();

        let _ = server
            .write(
                "sys/auth/pass",
                serde_json::json!({ "type": "userpass" }).as_object().cloned(),
                None,
            )
            .unwrap();

        let _ = server
            .write(
                "auth/pass/users/alice",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "default" })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        let _ = server
            .write(
                "auth/pass/users/alice/password",
                serde_json::json!({ "password": "hunter22XX_new!" })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        let _ = server
            .delete("auth/pass/users/alice", None, None)
            .unwrap();

        let ret = server.read("sys/audit/events", None).unwrap().1;
        let events = ret
            .get("events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let matching: Vec<_> = events
            .iter()
            .filter(|e| {
                e.get("category").and_then(|v| v.as_str()) == Some("user")
                    && e.get("target").and_then(|v| v.as_str())
                        == Some("userpass/alice")
            })
            .collect();

        let ops: Vec<String> = matching
            .iter()
            .map(|e| {
                e.get("op")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        assert!(ops.contains(&"create".to_string()), "missing create in {ops:?}");
        assert!(
            ops.contains(&"password-change".to_string()),
            "missing password-change in {ops:?}",
        );
        assert!(ops.contains(&"delete".to_string()), "missing delete in {ops:?}");

        // Regression: root-token operations used to store an empty
        // actor (no `entity_id`), which rendered as "(unknown)" in
        // the Admin → Audit page. `caller_audit_actor` now falls
        // back to `auth.display_name` so root writes surface as
        // `"root"`.
        let users: Vec<String> = matching
            .iter()
            .map(|e| {
                e.get("user")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert!(
            users.iter().all(|u| u == "root"),
            "root-token audit rows should surface as 'root', got {users:?}",
        );
    }

    /// A password login records a `login` op and a self-revoke records a
    /// `logout` op, both under the `login` category. Regression for two
    /// gaps: the GUI's security-key login hits the userpass-integrated
    /// FIDO2 path (which v0.18.1 left un-instrumented while wiring the
    /// unused standalone `fido2/` backend), and logout neither revoked
    /// the token server-side nor produced an audit row.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_includes_login_and_logout() {
        let mut server =
            TestHttpServer::new("test_audit_events_includes_login_and_logout", true).await;
        server.token = server.root_token.clone();

        server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), None)
            .unwrap();
        server
            .write(
                "auth/pass/users/bob",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "default" })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        // Password login -> records a `login` event and mints bob's token.
        let login = server
            .write(
                "auth/pass/login/bob",
                serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
            )
            .unwrap()
            .1;
        let bob_token = login
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .expect("login should mint a client_token")
            .to_string();

        // Self-revoke with bob's own token -> records a `logout` event.
        // `default` policy is granted `update` on this path, so this also
        // exercises the ACL grant that was previously unserved.
        server
            .write("auth/token/revoke-self", None, Some(&bob_token))
            .unwrap();

        let ret = server.read("sys/audit/events", None).unwrap().1;
        let ops: Vec<String> = ret
            .get("events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|e| e.get("category").and_then(|v| v.as_str()) == Some("login"))
            .map(|e| e.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string())
            .collect();

        assert!(ops.contains(&"login".to_string()), "missing login op in {ops:?}");
        assert!(ops.contains(&"logout".to_string()), "missing logout op in {ops:?}");
    }

    /// A GUI token sign-in (presenting an existing token, validated via
    /// `lookup-self`) records a `login` event under the `token/` mount
    /// through the self-service `auth/token/audit-login` endpoint.
    /// Regression for the gap where token logins — unlike password /
    /// FIDO2 / approle — left no row on the Admin → Audit page because
    /// presenting a token is not a credential-backend login event.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_includes_token_login() {
        let mut server =
            TestHttpServer::new("test_audit_events_includes_token_login", true).await;
        server.token = server.root_token.clone();

        // The endpoint any authenticated token may call (granted by the
        // `default` policy) — this is the exact call the GUI makes after
        // a pasted token validates against `lookup-self`.
        let tok = server.root_token.clone();
        server
            .write("auth/token/audit-login", None, Some(&tok))
            .unwrap();

        let ret = server.read("sys/audit/events", None).unwrap().1;
        let rows: Vec<(String, String)> = ret
            .get("events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|e| e.get("category").and_then(|v| v.as_str()) == Some("login"))
            .map(|e| {
                (
                    e.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    e.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                )
            })
            .collect();

        assert!(
            rows.iter()
                .any(|(op, target)| op == "login" && target.starts_with("token/")),
            "missing token login row in {rows:?}"
        );
    }

    /// A rejected SSO callback records a `login-failed` event under the
    /// backend's mount (`oidc/` here) so failed federated sign-ins are
    /// auditable. Regression for the gap where the OIDC/SAML callback
    /// handlers minted tokens (or rejected attempts) without ever
    /// touching the login-audit trail. We exercise the failure path: a
    /// callback with an unknown `state` is rejected before any token is
    /// issued, which the wrapper still records.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_includes_sso_callback_failure() {
        let mut server =
            TestHttpServer::new("test_audit_events_includes_sso_callback_failure", true).await;
        server.token = server.root_token.clone();

        // Mount OIDC + SAML; both `callback` endpoints are unauth paths.
        server
            .write("sys/auth/oidc", serde_json::json!({ "type": "oidc" }).as_object().cloned(), None)
            .unwrap();
        server
            .write("sys/auth/saml", serde_json::json!({ "type": "saml" }).as_object().cloned(), None)
            .unwrap();

        // Unknown state (OIDC) / unconfigured mount (SAML) → both reject
        // before minting a token, exercising the failure-recording path.
        let _ = server.write(
            "auth/oidc/callback",
            serde_json::json!({ "state": "nope", "code": "nope" }).as_object().cloned(),
            Some(""),
        );
        let _ = server.write(
            "auth/saml/callback",
            serde_json::json!({ "saml_response": "bm9wZQ==", "relay_state": "nope" })
                .as_object()
                .cloned(),
            Some(""),
        );

        let ret = server.read("sys/audit/events", None).unwrap().1;
        let rows: Vec<(String, String)> = ret
            .get("events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|e| e.get("category").and_then(|v| v.as_str()) == Some("login"))
            .map(|e| {
                (
                    e.get("op").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    e.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                )
            })
            .collect();

        assert!(
            rows.iter()
                .any(|(op, target)| op == "login-failed" && target.starts_with("oidc/")),
            "missing oidc login-failed row in {rows:?}"
        );
        assert!(
            rows.iter()
                .any(|(op, target)| op == "login-failed" && target.starts_with("saml/")),
            "missing saml login-failed row in {rows:?}"
        );
    }

    /// Share grants and revocations show up in the audit trail under
    /// the `share` category. Regression for the original gap where
    /// the aggregator only pulled policy/group history and sharing
    /// activity was invisible on the Admin → Audit page.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_includes_share_grants_and_revokes() {
        let mut server = TestHttpServer::new(
            "test_audit_events_includes_share_grants_and_revokes",
            true,
        )
        .await;
        server.token = server.root_token.clone();

        // Grant a share — generates a `share`/`grant` row.
        // The URL segment is base64url(canonical_path) per the sharing
        // route definition; "secret/foo" encodes to "c2VjcmV0L2Zvbw".
        let target_b64 = "c2VjcmV0L2Zvbw";
        let grantee = "ent-grantee-uuid-111";
        let _ = server
            .write(
                &format!("identity/sharing/by-target/kv-secret/{target_b64}/{grantee}"),
                serde_json::json!({
                    "target_kind": "kv-secret",
                    "target_path": "secret/foo",
                    "capabilities": "read,list",
                })
                .as_object()
                .cloned(),
                None,
            )
            .unwrap();

        // Revoke it — generates a `share`/`revoke` row.
        let _ = server
            .delete(
                &format!("identity/sharing/by-target/kv-secret/{target_b64}/{grantee}"),
                None,
                None,
            )
            .unwrap();

        let ret = server.read("sys/audit/events", None).unwrap().1;
        let events = ret
            .get("events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let has_grant = events.iter().any(|e| {
            e.get("category").and_then(|v| v.as_str()) == Some("share")
                && e.get("op").and_then(|v| v.as_str()) == Some("grant")
                && e.get("target").and_then(|v| v.as_str()) == Some("kv-secret:secret/foo")
        });
        let has_revoke = events.iter().any(|e| {
            e.get("category").and_then(|v| v.as_str()) == Some("share")
                && e.get("op").and_then(|v| v.as_str()) == Some("revoke")
                && e.get("target").and_then(|v| v.as_str()) == Some("kv-secret:secret/foo")
        });
        assert!(has_grant, "expected share/grant event in {events:?}");
        assert!(has_revoke, "expected share/revoke event in {events:?}");
    }

    /// The audit aggregator returns a newest-first list of events
    /// drawn from policy, identity-group, and asset-group history.
    /// Smoke test: root creates a policy + group, reads
    /// `sys/audit/events`, gets at least those two events back.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_aggregator_basic() {
        let mut server = TestHttpServer::new("test_audit_events_aggregator_basic", true).await;
        server.token = server.root_token.clone();

        // Create a policy — shows up as a "policy" create event.
        let _ = server
            .write(
                "sys/policies/acl/audit-test-pol",
                serde_json::json!({ "policy": r#"path "secret/*" { capabilities = ["read"] }"# })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        // Create an identity user-group — shows up as "identity-group-user".
        let _ = server
            .write(
                "identity/group/user/audit-test-grp",
                serde_json::json!({ "members": "alice" }).as_object().cloned(),
                None,
            )
            .unwrap();

        let ret = server.read("sys/audit/events", None).unwrap().1;
        let events = ret
            .get("events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(!events.is_empty(), "audit trail should not be empty");

        let has_policy = events.iter().any(|e| {
            e.get("category").and_then(|v| v.as_str()) == Some("policy")
                && e.get("target").and_then(|v| v.as_str()) == Some("audit-test-pol")
        });
        let has_group = events.iter().any(|e| {
            e.get("category").and_then(|v| v.as_str()) == Some("identity-group-user")
                && e.get("target").and_then(|v| v.as_str()) == Some("audit-test-grp")
        });
        assert!(has_policy, "expected policy event in {events:?}");
        assert!(has_group, "expected identity-group-user event in {events:?}");
    }

    /// Regression: the `bv-client` remote backend sends a GET whose
    /// `from`/`to`/`limit` live in the JSON *body*, not the query string.
    /// The HTTP shim must read the body too, otherwise remote callers
    /// (the desktop GUI in remote mode) get an unwindowed, unbounded
    /// event list — which made the dashboard's "Recent activity" panel
    /// show stale events while the 24h KPI correctly read zero.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_filters_from_json_body() {
        let mut server =
            TestHttpServer::new("test_audit_events_filters_from_json_body", true).await;
        server.token = server.root_token.clone();

        for n in ["p-alpha", "p-beta", "p-gamma"] {
            let _ = server
                .write(
                    &format!("sys/policies/acl/{n}"),
                    serde_json::json!({ "policy": r#"path "secret/*" { capabilities = ["read"] }"# })
                        .as_object()
                        .cloned(),
                    None,
                )
                .unwrap();
        }

        let count =
            |v: &Value| v.get("events").and_then(|e| e.as_array()).map(|a| a.len()).unwrap_or(0);

        // Baseline: no params → every event present.
        let all = server.read("sys/audit/events", None).unwrap().1;
        assert!(count(&all) >= 3, "expected the three policy events: {all:?}");

        // `limit` in the JSON body of the GET must cap the result.
        let limited = server
            .request(
                "GET",
                "sys/audit/events",
                serde_json::json!({ "limit": 2 }).as_object().cloned(),
                Some(&server.root_token),
                None,
            )
            .unwrap()
            .1;
        assert_eq!(count(&limited), 2, "limit in the JSON body must cap results: {limited:?}");

        // A far-future `from` in the body must window everything out.
        let windowed = server
            .request(
                "GET",
                "sys/audit/events",
                serde_json::json!({ "from": "2099-01-01T00:00:00+00:00" }).as_object().cloned(),
                Some(&server.root_token),
                None,
            )
            .unwrap()
            .1;
        assert_eq!(count(&windowed), 0, "a future `from` must filter all events out: {windowed:?}");
    }

    /// `sys/dashboard/summary` returns the operational snapshot: an
    /// unsealed/initialized seal block, non-zero secret-engine and
    /// policy counts (a default vault mounts `secret/` and we add a
    /// policy here), and a 24h audit total that includes that policy's
    /// create event.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_dashboard_summary_basic() {
        let mut server = TestHttpServer::new("test_dashboard_summary_basic", true).await;
        server.token = server.root_token.clone();

        let _ = server
            .write(
                "sys/policies/acl/dash-test-pol",
                serde_json::json!({ "policy": r#"path "secret/*" { capabilities = ["read"] }"# })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        let ret = server.read("sys/dashboard/summary", None).unwrap().1;

        let seal = ret.get("seal").and_then(|v| v.as_object()).expect("seal block");
        assert_eq!(seal.get("sealed").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(seal.get("initialized").and_then(|v| v.as_bool()), Some(true));

        let counts = ret.get("counts").and_then(|v| v.as_object()).expect("counts block");
        assert!(
            counts.get("secret_mounts").and_then(|v| v.as_u64()).unwrap_or(0) >= 1,
            "root should see at least the secret/ engine: {ret:?}"
        );
        assert!(
            counts.get("policies").and_then(|v| v.as_u64()).unwrap_or(0) >= 1,
            "the policy we just wrote should be counted: {ret:?}"
        );

        let audit_total = ret
            .get("audit_24h")
            .and_then(|v| v.as_object())
            .and_then(|m| m.get("total"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert!(audit_total >= 1, "the policy create should be in the 24h total: {ret:?}");
    }

    /// A permission-denied request and a failed login flow through the
    /// request hot path into the in-memory stats aggregator, and show up
    /// in `sys/dashboard/summary` as `audit_24h.denied` and
    /// `attention.failed_logins_1h`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_dashboard_summary_counts_denials_and_failed_logins() {
        let mut server =
            TestHttpServer::new("test_dashboard_summary_counts_denials_and_failed_logins", true)
                .await;
        server.token = server.root_token.clone();

        // Provision a low-privilege user (default policy only).
        let _ = server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), None)
            .unwrap();
        let _ = server
            .write(
                "auth/pass/users/lowpriv",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "default", "ttl": 0 })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();

        // A failed login (wrong password) on a `/login` route → counted
        // as an auth failure.
        let _ = server.write(
            "auth/pass/login/lowpriv",
            serde_json::json!({ "password": "WRONG" }).as_object().cloned(),
            None,
        );

        // A successful login to get a low-priv token.
        let token = server
            .write(
                "auth/pass/login/lowpriv",
                serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
            )
            .unwrap()
            .1
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // A denied write — default policy cannot create ACL policies.
        let denied = server
            .write(
                "sys/policies/acl/should-be-denied",
                serde_json::json!({ "policy": r#"path "x" { capabilities = ["read"] }"# })
                    .as_object()
                    .cloned(),
                Some(&token),
            )
            .unwrap();
        assert_eq!(denied.0, 403, "low-priv policy write must be forbidden");

        // Read the summary as root and confirm the counters moved.
        let ret = server.read("sys/dashboard/summary", Some(&server.root_token)).unwrap().1;
        let audit = ret.get("audit_24h").and_then(|v| v.as_object()).expect("audit_24h");
        assert!(
            audit.get("denied").and_then(|v| v.as_u64()).unwrap_or(0) >= 1,
            "the forbidden write should be counted as denied: {ret:?}"
        );
        let attention = ret.get("attention").and_then(|v| v.as_object()).expect("attention");
        assert!(
            attention.get("failed_logins_1h").and_then(|v| v.as_u64()).unwrap_or(0) >= 1,
            "the wrong-password login should be counted as a failed login: {ret:?}"
        );
    }

    /// HA regression: the dashboard's `denied` and `failed_logins_1h`
    /// counters must be derived from replicated storage, not the per-node
    /// in-memory `stats` ring. In a cluster a denial handled by node A is
    /// invisible to the ring on node B, so a summary served by B would
    /// under-report. We simulate "an event another node recorded" by
    /// appending directly to the replicated stores (bypassing the request
    /// hot path that feeds the ring), then assert the summary reflects
    /// them — proving the counts come from storage.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_dashboard_summary_counters_come_from_storage_not_ring() {
        use crate::modules::credential::login_audit_store::{LoginAuditEntry, LoginAuditStore};
        use crate::modules::system::denial_audit_store::{DenialAuditEntry, DenialAuditStore};

        let mut server = TestHttpServer::new(
            "test_dashboard_summary_counters_come_from_storage_not_ring",
            true,
        )
        .await;
        server.token = server.root_token.clone();

        // Baseline: no denials or failed logins have flowed through this
        // process's request path, so the in-memory ring is empty.
        let now_secs = chrono::Utc::now().timestamp();
        assert_eq!(server.core.stats.denied_24h(now_secs), 0, "ring denials start at zero");
        assert_eq!(
            server.core.stats.failed_logins_1h(now_secs),
            0,
            "ring failed-logins start at zero"
        );

        // Append two denials and one failed login straight to the
        // replicated stores, as a peer node's request handling would —
        // without ever touching this node's stats ring.
        let denial_store = DenialAuditStore::from_core(&server.core).expect("denial store");
        for path in ["secret/data/a", "secret/data/b"] {
            denial_store
                .append(DenialAuditEntry {
                    ts: String::new(),
                    user: "peer-node-caller".into(),
                    path: path.into(),
                    operation: "read".into(),
                    authenticated: true,
                    remote_addr: String::new(),
                })
                .await
                .expect("append denial");
        }
        let login_store = LoginAuditStore::from_core(&server.core).expect("login store");
        login_store
            .append(LoginAuditEntry {
                ts: String::new(),
                username: "peer-node-user".into(),
                mount: "auth/pass/".into(),
                success: false,
                action: "login".into(),
                remote_addr: String::new(),
                details: "bad password".into(),
            })
            .await
            .expect("append failed login");
        // A logout must never count as a failed login. We give it
        // success=false (atypical — real logouts record success=true) so
        // the `!success` filter alone would let it through, proving the
        // `action != "logout"` guard is what excludes it.
        login_store
            .append(LoginAuditEntry {
                ts: String::new(),
                username: "peer-node-user".into(),
                mount: "auth/pass/".into(),
                success: false,
                action: "logout".into(),
                remote_addr: String::new(),
                details: String::new(),
            })
            .await
            .expect("append logout");

        // The ring is still empty — these events never went through it.
        assert_eq!(server.core.stats.denied_24h(now_secs), 0, "ring stays empty");
        assert_eq!(server.core.stats.failed_logins_1h(now_secs), 0, "ring stays empty");

        // The summary must nonetheless report the storage-backed counts.
        let ret = server.read("sys/dashboard/summary", Some(&server.root_token)).unwrap().1;
        let audit = ret.get("audit_24h").and_then(|v| v.as_object()).expect("audit_24h");
        assert_eq!(
            audit.get("denied").and_then(|v| v.as_u64()).unwrap_or(0),
            2,
            "denied must count the two stored denials, not the empty ring: {ret:?}"
        );
        let attention = ret.get("attention").and_then(|v| v.as_object()).expect("attention");
        assert_eq!(
            attention.get("failed_logins_1h").and_then(|v| v.as_u64()).unwrap_or(0),
            1,
            "failed_logins_1h must count the one stored failure (not the logout): {ret:?}"
        );
    }

    /// Regression: permission-denied requests must be persisted to the
    /// audit trail (`sys/audit/events`), not just tallied in the
    /// in-memory per-node dashboard counter. Covers both denial kinds:
    /// an authenticated ACL rejection (valid token, insufficient
    /// policy → `reason=policy`, user = display name) and an invalid
    /// token (`reason=invalid-token`, user = `(unauthenticated)`).
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_audit_events_include_denied_requests() {
        let mut server =
            TestHttpServer::new("test_audit_events_include_denied_requests", true).await;
        server.token = server.root_token.clone();

        // Provision a low-privilege user (default policy only) and log in.
        let _ = server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), None)
            .unwrap();
        let _ = server
            .write(
                "auth/pass/users/lowpriv",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "default", "ttl": 0 })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap();
        let token = server
            .write(
                "auth/pass/login/lowpriv",
                serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
            )
            .unwrap()
            .1
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // An ACL denial: default policy cannot create ACL policies.
        let denied = server
            .write(
                "sys/policies/acl/denied-into-audit",
                serde_json::json!({ "policy": r#"path "x" { capabilities = ["read"] }"# })
                    .as_object()
                    .cloned(),
                Some(&token),
            )
            .unwrap();
        assert_eq!(denied.0, 403, "low-priv policy write must be forbidden");

        // An invalid-token denial.
        let bad = server.read("sys/policies/acl", Some("not-a-real-token")).unwrap();
        assert_eq!(bad.0, 403, "an invalid token must be forbidden");

        // Both denials must now be visible in the unified audit trail.
        let ret = server.read("sys/audit/events", Some(&server.root_token)).unwrap().1;
        let events = ret.get("events").and_then(|v| v.as_array()).expect("events array");
        let denied_events: Vec<_> = events
            .iter()
            .filter(|e| e.get("op").and_then(|v| v.as_str()) == Some("denied"))
            .collect();

        let acl_denial = denied_events
            .iter()
            .find(|e| {
                e.get("target").and_then(|v| v.as_str())
                    == Some("sys/policies/acl/denied-into-audit")
            })
            .unwrap_or_else(|| panic!("ACL denial missing from audit trail: {events:?}"));
        assert_eq!(
            acl_denial.get("category").and_then(|v| v.as_str()),
            Some("request"),
            "denials carry the request category"
        );
        let who = acl_denial.get("user").and_then(|v| v.as_str()).unwrap_or_default();
        assert!(who.contains("lowpriv"), "ACL denial records the caller's display name: {who}");
        let fields = acl_denial
            .get("changed_fields")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|f| f.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();
        assert!(
            fields.contains(&"reason=policy"),
            "a valid-token denial is a policy rejection: {fields:?}"
        );

        let token_denial = denied_events
            .iter()
            .find(|e| {
                e.get("user").and_then(|v| v.as_str()) == Some("(unauthenticated)")
            })
            .unwrap_or_else(|| panic!("invalid-token denial missing from audit trail: {events:?}"));
        let fields = token_denial
            .get("changed_fields")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|f| f.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();
        assert!(
            fields.contains(&"reason=invalid-token"),
            "an invalid-token denial must not claim a policy rejection: {fields:?}"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_system_internal_ui_mounts_default_policy_shareable_mounts() {
        let mut test_http_server =
            TestHttpServer::new("test_system_internal_ui_mounts_default_policy_shareable_mounts", true)
                .await;

        // Mount userpass and provision a user with only `default`.
        test_http_server.token = test_http_server.root_token.clone();
        let _ = test_http_server
            .write(
                "sys/auth/pass",
                serde_json::json!({ "type": "userpass" }).as_object().cloned(),
                None,
            )
            .unwrap();
        let _ = test_http_server
            .write(
                "auth/pass/users/felipe",
                serde_json::json!({
                    "password": "hunter22XX!",
                    "token_policies": "default",
                    "ttl": 0,
                })
                .as_object()
                .cloned(),
                None,
            )
            .unwrap();

        // Log in as felipe.
        let login = test_http_server
            .write(
                "auth/pass/login/felipe",
                serde_json::json!({ "password": "hunter22XX!" })
                    .as_object()
                    .cloned(),
                None,
            )
            .unwrap()
            .1;
        let felipe_token = login
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // IMPORTANT: pass felipe's token explicitly. The helper falls
        // back to `self.root_token` when the per-call token is `None`;
        // using `test_http_server.token = ...` only helps the sidecar
        // VAULT_TOKEN path, not the HTTP `request` method.
        let ret = test_http_server.read("sys/internal/ui/mounts", Some(&felipe_token));
        assert!(ret.is_ok(), "felipe should still be able to hit the endpoint");
        let body = ret.unwrap().1;
        let secret = body
            .get("secret")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let auth = body
            .get("auth")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        // Mounts felipe MAY now see: the `default` policy carries
        // share-scoped grants (`scopes = ["shared"]`) on secret/,
        // resources/, and resource-group/ so a share *recipient* can
        // navigate to what was shared with them. Mount-level visibility
        // follows from carrying any grant under the mount (see
        // `ACL::has_mount_access`) and matches `standard-user`; it does
        // NOT imply item access — reading a specific resource/secret
        // still requires an active SecretShare resolved at authorize
        // time (covered by the policy/acl share-scope tests).
        for visible in ["secret/", "resources/", "resource-group/"] {
            assert!(
                secret.contains_key(visible),
                "felipe should see the shareable mount {visible} on dashboard, got {:?}",
                secret.keys().collect::<Vec<_>>(),
            );
        }
        // Mounts felipe MAY see (default grants paths under these):
        // sys/ via sys/capabilities-self etc., identity/ via the
        // templated identity/entity/id/{{identity.entity.id}} rule
        // (resolves to felipe's entity_id), auth/token/ via
        // auth/token/lookup-self etc. No assertion that these must
        // be present — only that the hidden mounts are absent.
        {
            let forbidden_auth = "pass/";
            assert!(
                !auth.contains_key(forbidden_auth),
                "felipe must not see {forbidden_auth} auth mount, got {:?}",
                auth.keys().collect::<Vec<_>>(),
            );
        }
    }

    /// `sys/internal/ui/mounts` must report the *active namespace's* secret
    /// engines, not the root mount table. Regression for the GUI showing
    /// root's full engine list inside a child namespace, so every real
    /// operation there 404'd with `ErrRouterMountNotFound`. Also covers mount
    /// seeding: a newly created namespace carries its own default engines.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_system_internal_ui_mounts_namespace_scoped() {
        let mut server = TestHttpServer::new("test_ui_mounts_ns_scoped", true).await;
        let root = server.root_token.clone();
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        // Creating a namespace seeds it with the default engines.
        let (s, r) = server
            .write(
                "v1/sys/namespaces/nschild",
                serde_json::json!({}).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!((200..300).contains(&s), "ns create: {s} {r:?}");

        let ui_mounts = |ns: Option<&str>| -> serde_json::Map<String, Value> {
            let headers: Vec<(&str, &str)> =
                ns.map(|n| vec![("X-BastionVault-Namespace", n)]).unwrap_or_default();
            let (s, r) = server
                .request_with_headers(
                    "GET",
                    "v1/sys/internal/ui/mounts",
                    None,
                    Some(&root),
                    None,
                    &headers,
                )
                .unwrap();
            assert_eq!(s, 200, "ui/mounts must 200: {r:?}");
            r.get("secret").and_then(|v| v.as_object()).cloned().unwrap_or_default()
        };

        // Root (no header): the default engines are present.
        let root_secret = ui_mounts(None);
        assert!(
            root_secret.contains_key("resources/") && root_secret.contains_key("secret/"),
            "root must list its default engines: {:?}",
            root_secret.keys().collect::<Vec<_>>()
        );

        // Child namespace: reports its OWN seeded default engines...
        let child_secret = ui_mounts(Some("nschild"));
        for engine in ["secret/", "resources/", "files/", "resource-group/", "identity/"] {
            assert!(
                child_secret.contains_key(engine),
                "seeded child namespace must report its default engine {engine}: {:?}",
                child_secret.keys().collect::<Vec<_>>()
            );
        }
        // ...but NOT root-only mounts (`rustion/`, `ssh-broker/` are core
        // defaults at root yet deliberately excluded from the namespace seed),
        // proving the listing is the child's tenant-scoped table — not root's
        // returned verbatim (the original bug).
        assert!(
            !child_secret.contains_key("rustion/"),
            "child namespace must not report root-only mounts (no cross-namespace leak): {:?}",
            child_secret.keys().collect::<Vec<_>>()
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_system_internal_ui_mounts_path() {
        let mut test_http_server = TestHttpServer::new("test_system_internal_ui_mounts_path", true).await;

        // set token
        test_http_server.token = test_http_server.root_token.clone();

        let ret = test_http_server.read("sys/internal/ui/mounts/secret", None);
        assert!(ret.is_ok());
        let ret = ret.unwrap().1;
        assert!(ret.is_object());
        let ret = ret.as_object().unwrap();
        assert_eq!(ret["type"], Value::String("kv-v2".into()));
    }
}
