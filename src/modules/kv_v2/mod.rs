//! KV v2 secret engine with versioning, soft-delete, destroy, undelete, and CAS support.
//!
//! Storage layout per secret:
//!   metadata/<name>            -> SecretMetadata JSON
//!   versions/<name>/<version>  -> VersionData JSON
//!   config                     -> EngineConfig JSON

pub mod metadata;
pub mod version;

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use chrono::Utc;
use derive_more::Deref;
use serde_json::{json, Value};

use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    modules::Module,
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    new_secret, new_secret_internal,
    storage::StorageEntry,
};

use self::metadata::{EngineConfig, SecretMetadata, VersionMetadata};
use self::version::VersionData;

static KV_V2_BACKEND_HELP: &str = r#"
The KV v2 backend stores versioned key-value secrets. Each write creates
a new version. Secrets support soft-delete with recovery, permanent
destruction, and check-and-set (CAS) for concurrency control.

All secrets are encrypted/decrypted by BastionVault and never stored
unencrypted in the backend.
"#;

pub struct KvV2Module {
    pub name: String,
    pub backend: Arc<KvV2Backend>,
}

pub struct KvV2BackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct KvV2Backend {
    #[deref]
    pub inner: Arc<KvV2BackendInner>,
}

impl KvV2Backend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(KvV2BackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_config_read = self.inner.clone();
        let h_config_write = self.inner.clone();
        let h_data_read = self.inner.clone();
        let h_data_write = self.inner.clone();
        let h_data_delete = self.inner.clone();
        let h_metadata_list_prefix = self.inner.clone();
        let h_metadata_read = self.inner.clone();
        let h_metadata_delete = self.inner.clone();
        let h_destroy = self.inner.clone();
        let h_undelete = self.inner.clone();
        let h_renew = self.inner.clone();
        let h_revoke = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: "config$",
                    fields: {
                        "max_versions": {
                            field_type: FieldType::Int,
                            default: "0",
                            description: "Maximum number of versions per secret (0 = unlimited)"
                        },
                        "cas_required": {
                            field_type: FieldType::Bool,
                            default: "false",
                            description: "If true, all writes must include a cas parameter"
                        },
                        "delete_version_after": {
                            field_type: FieldType::Str,
                            default: "0s",
                            description: "Duration after which versions are automatically soft-deleted"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_config_read.handle_config_read},
                        {op: Operation::Write, handler: h_config_write.handle_config_write}
                    ],
                    help: "Configure the KV v2 engine settings."
                },
                {
                    pattern: "data/(?P<name>.+)",
                    fields: {
                        "version": {
                            field_type: FieldType::Int,
                            default: "0",
                            description: "Version number to read (0 = latest)"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_data_read.handle_data_read},
                        {op: Operation::Write, handler: h_data_write.handle_data_write},
                        {op: Operation::Delete, handler: h_data_delete.handle_data_delete}
                    ],
                    help: "Read, write, or soft-delete versioned secret data."
                },
                {
                    pattern: "metadata/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Prefix"
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_metadata_list_prefix.handle_metadata_list}
                    ],
                    help: "List all secret names."
                },
                {
                    pattern: "metadata/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Secret name"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_metadata_read.handle_metadata_read},
                        {op: Operation::Delete, handler: h_metadata_delete.handle_metadata_delete}
                    ],
                    help: "Read or delete secret metadata."
                },
                {
                    pattern: "destroy/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Secret name"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_destroy.handle_destroy}
                    ],
                    help: "Permanently destroy specific versions of a secret."
                },
                {
                    pattern: "undelete/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Secret name"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_undelete.handle_undelete}
                    ],
                    help: "Recover soft-deleted versions of a secret."
                }
            ],
            secrets: [{
                secret_type: "kv-v2",
                renew_handler: h_renew.handle_noop,
                revoke_handler: h_revoke.handle_noop,
            }],
            help: KV_V2_BACKEND_HELP,
        });

        backend
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// Best-effort caller identity for audit purposes. Prefers the `username`
/// metadata field (populated by userpass login), falls back to
/// `auth.display_name`, and finally to `"unknown"` for root-token writes
/// and any path where auth was not resolved.
fn caller_username(req: &Request) -> String {
    if let Some(auth) = req.auth.as_ref() {
        if let Some(u) = auth.metadata.get("username") {
            if !u.is_empty() {
                return u.clone();
            }
        }
        if !auth.display_name.is_empty() {
            return auth.display_name.clone();
        }
    }
    "unknown".to_string()
}

fn get_name_from_request(req: &Request) -> Result<String, RvError> {
    if let Some(data) = req.data.as_ref() {
        if let Some(name) = data.get("name") {
            if let Some(s) = name.as_str() {
                if !s.is_empty() {
                    return Ok(s.to_string());
                }
            }
        }
    }
    Err(RvError::ErrRequestFieldNotFound)
}

fn get_versions_from_body(req: &Request) -> Vec<u64> {
    if let Some(body) = req.body.as_ref() {
        if let Some(versions) = body.get("versions") {
            if let Some(arr) = versions.as_array() {
                return arr.iter().filter_map(|v| v.as_u64()).collect();
            }
        }
    }
    Vec::new()
}

#[maybe_async::maybe_async]
impl KvV2BackendInner {
    async fn read_config(&self, req: &Request) -> Result<EngineConfig, RvError> {
        let entry = req.storage_get("config").await?;
        match entry {
            Some(e) => Ok(serde_json::from_slice(&e.value)?),
            None => Ok(EngineConfig::default()),
        }
    }

    async fn write_config(&self, req: &Request, config: &EngineConfig) -> Result<(), RvError> {
        let data = serde_json::to_vec(config)?;
        let entry = StorageEntry { key: "config".to_string(), value: data };
        req.storage_put(&entry).await
    }

    async fn read_metadata(&self, req: &Request, name: &str) -> Result<Option<SecretMetadata>, RvError> {
        let key = format!("metadata/{}", name);
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    async fn write_metadata(&self, req: &Request, name: &str, meta: &SecretMetadata) -> Result<(), RvError> {
        let key = format!("metadata/{}", name);
        let data = serde_json::to_vec(meta)?;
        let entry = StorageEntry { key, value: data };
        req.storage_put(&entry).await
    }

    async fn read_version(&self, req: &Request, name: &str, version: u64) -> Result<Option<VersionData>, RvError> {
        let key = format!("versions/{}/{}", name, version);
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    async fn write_version(&self, req: &Request, name: &str, vd: &VersionData) -> Result<(), RvError> {
        let key = format!("versions/{}/{}", name, vd.version);
        let data = serde_json::to_vec(vd)?;
        let entry = StorageEntry { key, value: data };
        req.storage_put(&entry).await
    }

    async fn delete_version_storage(&self, req: &Request, name: &str, version: u64) -> Result<(), RvError> {
        let key = format!("versions/{}/{}", name, version);
        req.storage_delete(&key).await
    }

    async fn prune_old_versions(
        &self,
        req: &Request,
        name: &str,
        meta: &mut SecretMetadata,
        max_versions: u64,
    ) -> Result<(), RvError> {
        if max_versions == 0 {
            return Ok(());
        }

        while meta.versions.len() as u64 > max_versions {
            let oldest = meta.oldest_version;
            self.delete_version_storage(req, name, oldest).await?;
            meta.versions.remove(&oldest.to_string());

            // Find the next oldest
            let mut next_oldest = oldest + 1;
            while next_oldest <= meta.current_version && !meta.versions.contains_key(&next_oldest.to_string()) {
                next_oldest += 1;
            }
            meta.oldest_version = next_oldest;
        }

        Ok(())
    }

    pub async fn handle_config_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.read_config(req).await?;
        let data = serde_json::to_value(&config)?.as_object().cloned();
        Ok(Some(Response::data_response(data)))
    }

    pub async fn handle_config_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut config = self.read_config(req).await?;

        if let Some(body) = req.body.as_ref() {
            if let Some(v) = body.get("max_versions").and_then(|v| v.as_u64()) {
                config.max_versions = v;
            }
            if let Some(v) = body.get("cas_required").and_then(|v| v.as_bool()) {
                config.cas_required = v;
            }
            if let Some(v) = body.get("delete_version_after").and_then(|v| v.as_str()) {
                config.delete_version_after = v.to_string();
            }
        }

        self.write_config(req, &config).await?;
        Ok(None)
    }

    pub async fn handle_data_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Determine which version to read
        let requested_version = req
            .body
            .as_ref()
            .and_then(|b| b.get("version"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let version = if requested_version == 0 { meta.current_version } else { requested_version };

        let version_key = version.to_string();
        let vm = match meta.versions.get(&version_key) {
            Some(vm) => vm,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        if vm.destroyed {
            return Err(RvError::ErrModuleKvV2VersionDestroyed);
        }

        if vm.is_soft_deleted() {
            let mut resp = Response::new();
            resp.data = json!({
                "data": null,
                "metadata": {
                    "version": version,
                    "created_time": vm.created_time,
                    "deletion_time": vm.deletion_time,
                    "destroyed": false,
                }
            })
            .as_object()
            .cloned();
            resp.add_warning(&format!("version {} has been deleted", version));
            return Ok(Some(resp));
        }

        let vd = match self.read_version(req, &name, version).await? {
            Some(vd) => vd,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        let resp_data = json!({
            "data": vd.data,
            "metadata": {
                "version": vd.version,
                "created_time": vd.created_time,
                "deletion_time": vd.deletion_time,
                "destroyed": vd.destroyed,
                "username": vd.username,
                "operation": vd.operation,
            }
        });

        Ok(Some(Response::data_response(resp_data.as_object().cloned())))
    }

    pub async fn handle_data_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let body = req.body.as_ref().ok_or(RvError::ErrModuleKvV2DataFieldMissing)?;

        // Extract data and options from body
        let secret_data = match body.get("data") {
            Some(Value::Object(d)) => d.clone(),
            _ => return Err(RvError::ErrModuleKvV2DataFieldMissing),
        };

        let cas_value = body
            .get("options")
            .and_then(|o| o.get("cas"))
            .and_then(|c| c.as_u64());

        let config = self.read_config(req).await?;
        let mut meta = self.read_metadata(req, &name).await?.unwrap_or_else(|| {
            let now = now_rfc3339();
            SecretMetadata {
                current_version: 0,
                oldest_version: 0,
                max_versions: 0,
                cas_required: false,
                delete_version_after: "0s".to_string(),
                created_time: now.clone(),
                updated_time: now,
                versions: std::collections::HashMap::new(),
            }
        });

        // CAS validation
        let cas_required = config.cas_required || meta.cas_required;
        if cas_required && cas_value.is_none() {
            return Err(RvError::ErrModuleKvV2CasRequired);
        }
        if let Some(cas) = cas_value {
            if cas != meta.current_version {
                return Err(RvError::ErrModuleKvV2CasMismatch);
            }
        }

        // Increment version
        let new_version = meta.current_version + 1;
        let now = now_rfc3339();
        let user = caller_username(req);
        let op = if new_version == 1 { "create" } else { "update" };

        let vd = VersionData {
            data: secret_data,
            version: new_version,
            created_time: now.clone(),
            deletion_time: String::new(),
            destroyed: false,
            username: user.clone(),
            operation: op.to_string(),
        };

        // Store version data
        self.write_version(req, &name, &vd).await?;

        // Update metadata
        meta.current_version = new_version;
        if meta.oldest_version == 0 {
            meta.oldest_version = 1;
        }
        meta.updated_time = now.clone();
        meta.versions.insert(
            new_version.to_string(),
            VersionMetadata {
                created_time: now,
                deletion_time: String::new(),
                destroyed: false,
                username: user,
                operation: op.to_string(),
            },
        );

        // Determine effective max_versions
        let effective_max = if meta.max_versions > 0 {
            meta.max_versions
        } else if config.max_versions > 0 {
            config.max_versions
        } else {
            0
        };

        self.prune_old_versions(req, &name, &mut meta, effective_max).await?;
        self.write_metadata(req, &name, &meta).await?;

        let resp_data = json!({
            "version": vd.version,
            "created_time": vd.created_time,
            "deletion_time": vd.deletion_time,
            "destroyed": vd.destroyed,
        });

        Ok(Some(Response::data_response(resp_data.as_object().cloned())))
    }

    pub async fn handle_data_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let mut meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        let versions_to_delete = get_versions_from_body(req);
        let now = now_rfc3339();

        if versions_to_delete.is_empty() {
            // Soft-delete the latest version
            let key = meta.current_version.to_string();
            if let Some(vm) = meta.versions.get_mut(&key) {
                if !vm.destroyed && vm.deletion_time.is_empty() {
                    vm.deletion_time = now.clone();
                }
            }
        } else {
            for ver in &versions_to_delete {
                let key = ver.to_string();
                if let Some(vm) = meta.versions.get_mut(&key) {
                    if !vm.destroyed && vm.deletion_time.is_empty() {
                        vm.deletion_time = now.clone();
                    }
                }
            }
        }

        meta.updated_time = now;
        self.write_metadata(req, &name, &meta).await?;
        Ok(None)
    }

    pub async fn handle_metadata_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        let data = serde_json::to_value(&meta)?.as_object().cloned();
        Ok(Some(Response::data_response(data)))
    }

    pub async fn handle_metadata_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Delete all version data
        for ver_key in meta.versions.keys() {
            if let Ok(ver) = ver_key.parse::<u64>() {
                let _ = self.delete_version_storage(req, &name, ver).await;
            }
        }

        // Delete metadata
        let meta_key = format!("metadata/{}", name);
        req.storage_delete(&meta_key).await?;

        Ok(None)
    }

    pub async fn handle_metadata_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list("metadata/").await?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }

    pub async fn handle_destroy(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let versions_to_destroy = get_versions_from_body(req);
        if versions_to_destroy.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        let now = now_rfc3339();
        for ver in &versions_to_destroy {
            let key = ver.to_string();
            if let Some(vm) = meta.versions.get_mut(&key) {
                if !vm.destroyed {
                    self.delete_version_storage(req, &name, *ver).await?;
                    vm.destroyed = true;
                    if vm.deletion_time.is_empty() {
                        vm.deletion_time = now.clone();
                    }
                }
            }
        }

        meta.updated_time = now;
        self.write_metadata(req, &name, &meta).await?;
        Ok(None)
    }

    pub async fn handle_undelete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = get_name_from_request(req)?;

        let versions_to_undelete = get_versions_from_body(req);
        if versions_to_undelete.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut meta = match self.read_metadata(req, &name).await? {
            Some(m) => m,
            None => return Err(RvError::ErrModuleKvV2VersionNotFound),
        };

        let now = now_rfc3339();
        for ver in &versions_to_undelete {
            let key = ver.to_string();
            if let Some(vm) = meta.versions.get_mut(&key) {
                if vm.is_soft_deleted() {
                    vm.deletion_time = String::new();
                }
            }
        }

        meta.updated_time = now;
        self.write_metadata(req, &name, &meta).await?;
        Ok(None)
    }

    pub async fn handle_noop(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl KvV2Module {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "kv-v2".to_string(),
            backend: Arc::new(KvV2Backend::new(core)),
        }
    }
}

impl Module for KvV2Module {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let kv = self.backend.clone();
        let kv_backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut kv_backend = kv.new_backend();
            kv_backend.init()?;
            Ok(Arc::new(kv_backend))
        };
        core.add_logical_backend("kv-v2", Arc::new(kv_backend_new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("kv-v2")
    }
}
