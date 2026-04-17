//! Dedicated resource storage engine.
//!
//! Stores resource metadata and per-resource secrets behind the vault barrier,
//! completely independent of the KV secret engine. All data is encrypted at rest.

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use derive_more::Deref;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation,
        Request, Response,
    },
    modules::Module,
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
    storage::StorageEntry,
};

static RESOURCE_BACKEND_HELP: &str = r#"
The resource backend provides dedicated storage for infrastructure resources
(servers, databases, network devices, etc.) and their associated secrets.
All data is encrypted behind the vault barrier.
"#;

// Storage key prefixes within this mount's barrier view
const META_PREFIX: &str = "meta/";
const SECRET_PREFIX: &str = "secret/";

// ── Data types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub ip_address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub tags: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

// ── Module boilerplate ─────────────────────────────────────────────

pub struct ResourceModule {
    pub name: String,
    pub backend: Arc<ResourceBackend>,
}

pub struct ResourceBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct ResourceBackend {
    #[deref]
    pub inner: Arc<ResourceBackendInner>,
}

impl ResourceBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            inner: Arc::new(ResourceBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_cfg_read = self.inner.clone();
        let h_cfg_write = self.inner.clone();
        let h_res_read = self.inner.clone();
        let h_res_write = self.inner.clone();
        let h_res_delete = self.inner.clone();
        let h_res_list = self.inner.clone();
        let h_sec_read = self.inner.clone();
        let h_sec_write = self.inner.clone();
        let h_sec_delete = self.inner.clone();
        let h_sec_list = self.inner.clone();
        let h_noop1 = self.inner.clone();
        let h_noop2 = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    // Resource type configuration (read/write the type schema)
                    pattern: "config/types$",
                    operations: [
                        {op: Operation::Read, handler: h_cfg_read.handle_config_types_read},
                        {op: Operation::Write, handler: h_cfg_write.handle_config_types_write}
                    ],
                    help: "Read or write the resource type definitions (fields per type)."
                },
                {
                    // List all resources
                    pattern: "resources/?$",
                    operations: [
                        {op: Operation::List, handler: h_res_list.handle_resource_list}
                    ],
                    help: "List all resources."
                },
                {
                    // CRUD a single resource
                    pattern: r"resources/(?P<name>[^/]+)$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_res_read.handle_resource_read},
                        {op: Operation::Write, handler: h_res_write.handle_resource_write},
                        {op: Operation::Delete, handler: h_res_delete.handle_resource_delete}
                    ],
                    help: "Read, create/update, or delete a resource."
                },
                {
                    // List secrets for a resource
                    pattern: r"secrets/(?P<resource>[^/]+)/?$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_sec_list.handle_secret_list}
                    ],
                    help: "List secrets for a resource."
                },
                {
                    // CRUD a single secret within a resource
                    pattern: r"secrets/(?P<resource>[^/]+)/(?P<key>[^/]+)$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        },
                        "key": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Secret key name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_sec_read.handle_secret_read},
                        {op: Operation::Write, handler: h_sec_write.handle_secret_write},
                        {op: Operation::Delete, handler: h_sec_delete.handle_secret_delete}
                    ],
                    help: "Read, create/update, or delete a secret within a resource."
                }
            ],
            secrets: [{
                secret_type: "resource",
                renew_handler: h_noop1.handle_noop,
                revoke_handler: h_noop2.handle_noop,
            }],
            help: RESOURCE_BACKEND_HELP,
        });

        backend
    }
}

// ── Handlers ───────────────────────────────────────────────────────

#[maybe_async::maybe_async]
impl ResourceBackendInner {
    // ── Config (type definitions) ────────────────────────────────

    pub async fn handle_config_types_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let entry = req.storage_get("config/types").await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None), // no config yet — frontend uses defaults
        }
    }

    pub async fn handle_config_types_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?;
        let data = serde_json::to_string(body)?;
        let entry = StorageEntry {
            key: "config/types".to_string(),
            value: data.into_bytes(),
        };
        req.storage_put(&entry).await?;
        Ok(None)
    }

    // ── Resource CRUD ──────────────────────────────────────────────

    pub async fn handle_resource_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list(META_PREFIX).await?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }

    pub async fn handle_resource_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().unwrap().to_string();
        let key = format!("{META_PREFIX}{name}");
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn handle_resource_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().unwrap().to_string();
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?;
        let key = format!("{META_PREFIX}{name}");
        let data = serde_json::to_string(body)?;
        let entry = StorageEntry {
            key,
            value: data.into_bytes(),
        };
        req.storage_put(&entry).await?;
        Ok(None)
    }

    pub async fn handle_resource_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data("name")?.as_str().unwrap().to_string();

        // Delete the resource metadata
        let meta_key = format!("{META_PREFIX}{name}");
        req.storage_delete(&meta_key).await?;

        // Delete all secrets under this resource
        let secret_prefix = format!("{SECRET_PREFIX}{name}/");
        let keys = req.storage_list(&secret_prefix).await?;
        for k in keys {
            req.storage_delete(&format!("{secret_prefix}{k}")).await?;
        }

        Ok(None)
    }

    // ── Per-resource secret CRUD ───────────────────────────────────

    pub async fn handle_secret_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
        let prefix = format!("{SECRET_PREFIX}{resource}/");
        let keys = req.storage_list(&prefix).await?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }

    pub async fn handle_secret_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn handle_secret_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?;
        let key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        let data = serde_json::to_string(body)?;
        let entry = StorageEntry {
            key,
            value: data.into_bytes(),
        };
        req.storage_put(&entry).await?;
        Ok(None)
    }

    pub async fn handle_secret_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let resource = req.get_data("resource")?.as_str().unwrap().to_string();
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        req.storage_delete(&key).await?;
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

// ── Module registration ────────────────────────────────────────────

impl ResourceModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "resource".to_string(),
            backend: Arc::new(ResourceBackend::new(core)),
        }
    }
}

impl Module for ResourceModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("resource", Arc::new(backend_new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("resource")
    }
}
