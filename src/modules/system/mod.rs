//! The system module is mainly used to configure BastionVault itself. For instance, the 'mount/'
//! path is provided here to support mounting new modules in BastionVault via RESTful HTTP request.

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
        policy::{acl::ACL, PolicyModule},
        resource_group::ResourceGroupModule,
        Module,
    },
    mount::{MountEntry, MOUNT_TABLE_TYPE},
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    bv_error_response_status,
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
        let sys_backend_owner_backfill = self.self_ptr.upgrade().unwrap().clone();

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
                }
            ],
            root_paths: ["mounts/*", "auth/*", "remount", "policy", "policy/*", "audit", "audit/*", "seal", "raw/*", "revoke-prefix/*", "cache/flush", "owner/backfill"],
            unauth_paths: ["internal/ui/mounts", "internal/ui/mounts/*", "init", "seal-status", "unseal"],
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

        let mounts = self.core.mounts_router.entries.read()?;

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

        self.core.mount(&me).await?;
        Ok(None)
    }

    pub async fn handle_unmount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let suffix = req.path.trim_start_matches("mounts/");
        if suffix.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        self.core.unmount(suffix).await?;
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
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(broker) = self.core.audit_broker.load().as_ref().cloned() else {
            let mut data = Map::new();
            data.insert("devices".into(), Value::Array(Vec::new()));
            return Ok(Some(Response::data_response(Some(data))));
        };

        let entries = broker.list();
        let mut arr: Vec<Value> = Vec::with_capacity(entries.len());
        for d in entries {
            let mut m = Map::new();
            m.insert("path".into(), Value::String(d.path));
            m.insert("type".into(), Value::String(d.device_type));
            m.insert("description".into(), Value::String(d.description));
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
        use crate::modules::{
            identity::{GroupKind, IdentityModule},
            policy::PolicyModule,
            resource_group::ResourceGroupModule,
        };

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

        let mut events: Vec<AuditEventBuilder> = Vec::new();

        // Policies
        if let Ok(policy_module) = self.get_module::<PolicyModule>("policy") {
            let store = policy_module.policy_store.load();
            if let Ok(names) = store.list_policy(crate::modules::policy::PolicyType::Acl).await {
                for name in names {
                    if let Ok(entries) = store.list_history(&name).await {
                        for e in entries {
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

        // Identity groups — user + app
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

        // Asset groups (resource-group store).
        if let Ok(module) = self.get_module::<ResourceGroupModule>("resource-group") {
            if let Some(store) = module.store() {
                if let Ok(names) = store.list_groups().await {
                    for name in names {
                        if let Ok(entries) = store.list_history(&name).await {
                            for e in entries {
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

        // Share events — grants, revokes, cascade-revokes — drawn from
        // the flat share history view. The `actor_entity_id` is used
        // as the event's `user` so the Audit page's EntityLabel turns
        // it back into a login.
        if let Ok(identity_module) = self.get_module::<IdentityModule>("identity") {
            if let Some(store) = identity_module.share_store() {
                if let Ok(entries) = store.list_all_history().await {
                    for e in entries {
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

            // User / role lifecycle events. Mount distinguishes
            // userpass (`userpass/`) from approle (`approle/`);
            // we preserve it on the `target` so the GUI can still
            // show "mount:name" at a glance.
            if let Some(store) = identity_module.user_audit_store() {
                if let Ok(entries) = store.list_all().await {
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

        let cfg = crate::audit::AuditDeviceConfig {
            path,
            device_type,
            description,
            options,
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
        broker.disable_device(&path).await?;
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

        let entries = self.core.mounts_router.entries.read()?;
        for (path, entry) in entries.iter() {
            let me = entry.read()?;
            if has_access(&me) {
                if is_authed {
                    secret_mounts.insert(path.clone(), Value::Object(self.mount_info(&me)));
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

        let entries = self.core.mounts_router.entries.read()?;
        for (path, entry) in entries.iter() {
            let me = entry.read()?;
            if has_access(&me) {
                if is_authed {
                    secret_mounts.insert(path.clone(), Value::Object(self.mount_info(&me)));
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
            self.core.mounts_router.router.matching_mount_entry(&path)?.ok_or(RvError::ErrPermissionDenied)?;
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

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_system_internal_ui_mounts_default_policy_sees_nothing() {
        let mut test_http_server =
            TestHttpServer::new("test_system_internal_ui_mounts_default_policy_sees_nothing", true)
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

        // Mounts felipe MUST NOT see (no path in `default` grants
        // anything under these mounts): secret/, resources/,
        // resource-group/. If these appear, something leaked.
        for hidden in ["secret/", "resources/", "resource-group/"] {
            assert!(
                !secret.contains_key(hidden),
                "felipe must not see {hidden} on dashboard, got {:?}",
                secret.keys().collect::<Vec<_>>(),
            );
        }
        // Mounts felipe MAY see (default grants paths under these):
        // sys/ via sys/capabilities-self etc., identity/ via the
        // templated identity/entity/id/{{identity.entity.id}} rule
        // (resolves to felipe's entity_id), auth/token/ via
        // auth/token/lookup-self etc. No assertion that these must
        // be present — only that the hidden mounts are absent.
        for forbidden_auth in ["pass/"] {
            assert!(
                !auth.contains_key(forbidden_auth),
                "felipe must not see {forbidden_auth} auth mount, got {:?}",
                auth.keys().collect::<Vec<_>>(),
            );
        }
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
