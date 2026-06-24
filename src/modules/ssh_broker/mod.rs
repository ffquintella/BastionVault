//! SSH login-broker policy module.
//!
//! Owns the four-tier **login-class** policy (`shared-credential` |
//! `brokered`) that lets an admin pin a resource / type / asset-group to
//! `brokered` — after which every SSH login is a per-connect minted
//! artifact from the SSH engine and no static SSH credential may be
//! attached. The resolver + storage live in [`policy`]; this file is the
//! HTTP route surface, mirroring the Rustion transport-policy routes on
//! a dedicated `ssh-broker/` logical mount.
//!
//! See `features/ssh-resource-login-brokering.md`.

use std::{any::Any, collections::HashMap, sync::Arc};

use derive_more::Deref;
use serde_json::{Map, Value};

use super::Module;
use crate::{
    bv_error_response_status, bv_error_string,
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request,
        Response,
    },
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal,
};

pub mod audit;
pub mod policy;

static SSH_BROKER_BACKEND_HELP: &str = r#"
The ssh-broker backend holds the four-tier SSH login-class policy.
A resource, resource-type, or asset-group can be pinned to `brokered`,
after which every SSH login is minted per-connect from the SSH engine
(CA-signed cert or OTP) and no static SSH credential may be attached.
The default class is `shared-credential` (unchanged historical behavior).
"#;

// ─── Field readers ──────────────────────────────────────────────────

fn read_tier_fields(req: &Request) -> policy::LoginClassTier {
    let login_class = req
        .get_data("login_class")
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .and_then(|s| policy::LoginClass::parse(&s));
    let lock = req
        .get_data("lock")
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    policy::LoginClassTier { login_class, lock }
}

/// Read the global tier's `login_class_default` / `login_class_lock`
/// field names (distinct from the per-tier `login_class` / `lock` so the
/// global config reads naturally, matching the spec).
fn read_global_tier_fields(req: &Request) -> policy::LoginClassTier {
    let login_class = req
        .get_data("login_class_default")
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .and_then(|s| policy::LoginClass::parse(&s));
    let lock = req
        .get_data("login_class_lock")
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    policy::LoginClassTier { login_class, lock }
}

fn tier_doc_to_map(
    tier: &policy::LoginClassTier,
    name: Option<&str>,
    priority: Option<i32>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(c) = tier.login_class {
        m.insert("login_class".into(), Value::String(c.as_str().into()));
    }
    m.insert("lock".into(), Value::Bool(tier.lock));
    if let Some(n) = name {
        m.insert("name".into(), Value::String(n.to_string()));
    }
    if let Some(p) = priority {
        m.insert("priority".into(), Value::Number(p.into()));
    }
    if let Some(t) = updated_at {
        m.insert("updated_at".into(), Value::String(t.to_rfc3339()));
    }
    m
}

fn effective_to_map(e: &policy::EffectiveLoginClass) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "login_class".into(),
        Value::String(e.login_class.as_str().into()),
    );
    m.insert(
        "login_class_source".into(),
        Value::String(e.login_class_source.into()),
    );
    m.insert(
        "locked_by".into(),
        Value::Array(
            e.locked_by
                .iter()
                .map(|s| Value::String((*s).to_string()))
                .collect(),
        ),
    );
    if let Some(t) = e.locked_at_tier {
        m.insert("locked_at_tier".into(), Value::String(t.to_string()));
    }
    m.insert(
        "login_class_chain".into(),
        Value::Array(e.chain.iter().cloned().map(Value::String).collect()),
    );
    m
}

// ─── Module ─────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SshBrokerModule {
    pub name: String,
    pub core: Arc<Core>,
    pub policy_store: arc_swap::ArcSwap<Option<Arc<policy::PolicyStore>>>,
}

pub struct SshBrokerBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct SshBrokerBackend {
    #[deref]
    pub inner: Arc<SshBrokerBackendInner>,
}

impl SshBrokerBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            inner: Arc::new(SshBrokerBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_global_read = self.inner.clone();
        let h_global_write = self.inner.clone();
        let h_type_read = self.inner.clone();
        let h_type_write = self.inner.clone();
        let h_type_delete = self.inner.clone();
        let h_ag_read = self.inner.clone();
        let h_ag_write = self.inner.clone();
        let h_ag_delete = self.inner.clone();
        let h_res_read = self.inner.clone();
        let h_res_write = self.inner.clone();
        let h_res_delete = self.inner.clone();
        let h_effective = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    // GET/PUT ssh-broker/policy/global — root-gated.
                    pattern: r"policy/global$",
                    fields: {
                        "login_class_default": { field_type: FieldType::Str, required: false, description: "shared-credential | brokered" },
                        "login_class_lock": { field_type: FieldType::Bool, required: false, description: "Freeze the default against lower tiers." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_global_read.handle_global_read},
                        {op: Operation::Write, handler: h_global_write.handle_global_write}
                    ],
                    help: "Global SSH login-class default + lock. Root-gated."
                },
                {
                    // GET/PUT/DELETE ssh-broker/policy/type/<type_name>.
                    pattern: r"policy/type/(?P<type_name>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "login_class": { field_type: FieldType::Str, required: false, description: "shared-credential | brokered" },
                        "lock": { field_type: FieldType::Bool, required: false, description: "Lock against lower tiers." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_type_read.handle_type_read},
                        {op: Operation::Write, handler: h_type_write.handle_type_write},
                        {op: Operation::Delete, handler: h_type_delete.handle_type_delete}
                    ],
                    help: "Per-resource-type SSH login-class policy. Admin-gated."
                },
                {
                    // GET/PUT/DELETE ssh-broker/policy/asset-group/<id>.
                    pattern: r"policy/asset-group/(?P<id>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "priority": { field_type: FieldType::Int, default: 0, description: "Higher wins on multi-group resolution." },
                        "login_class": { field_type: FieldType::Str, required: false, description: "shared-credential | brokered" },
                        "lock": { field_type: FieldType::Bool, required: false, description: "Lock against lower tiers." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_ag_read.handle_ag_read},
                        {op: Operation::Write, handler: h_ag_write.handle_ag_write},
                        {op: Operation::Delete, handler: h_ag_delete.handle_ag_delete}
                    ],
                    help: "Per-asset-group SSH login-class policy. Admin or group-owner gated."
                },
                {
                    // GET/PUT/DELETE ssh-broker/policy/resource/<id>.
                    // Resource ids are hostnames and may contain dots.
                    pattern: r"policy/resource/(?P<id>[^/]+)$",
                    fields: {
                        "login_class": { field_type: FieldType::Str, required: false, description: "shared-credential | brokered" }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_res_read.handle_res_read},
                        {op: Operation::Write, handler: h_res_write.handle_res_write},
                        {op: Operation::Delete, handler: h_res_delete.handle_res_delete}
                    ],
                    help: "Per-resource SSH login-class override. Owner-gated; only writable when no upstream tier is locked."
                },
                {
                    // POST ssh-broker/policy/effective — resolve the
                    // effective login class for a resource without
                    // connecting. Drives the GUI resolution chip + the
                    // connect-path enforcement decision.
                    pattern: r"policy/effective$",
                    fields: {
                        "resource_id": { field_type: FieldType::Str, required: false, description: "Resource id for per-resource policy lookup." },
                        "resource_type": { field_type: FieldType::Str, required: false, description: "Resource type for per-type policy lookup." },
                        "asset_group_ids": { field_type: FieldType::CommaStringSlice, required: false, description: "Asset group ids the resource belongs to." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_effective.handle_effective}
                    ],
                    help: "Resolve the effective SSH login class (and its locking tier) for a resource without opening a session."
                }
            ],
            help: SSH_BROKER_BACKEND_HELP,
        });

        backend
    }
}

#[maybe_async::maybe_async]
impl SshBrokerBackendInner {
    fn resolve_policy_store(&self) -> Result<Arc<policy::PolicyStore>, RvError> {
        let module = self
            .core
            .module_manager
            .get_module::<SshBrokerModule>("ssh-broker")
            .ok_or_else(|| bv_error_string!("ssh-broker module not registered"))?;
        module
            .policy_store()
            .ok_or_else(|| bv_error_string!("ssh-broker policy store not initialized"))
    }

    // ─── Global ─────────────────────────────────────────────────

    pub async fn handle_global_read(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let g = pol.get_global().await?;
        let mut m = Map::new();
        if let Some(c) = g.tier.login_class {
            m.insert(
                "login_class_default".into(),
                Value::String(c.as_str().into()),
            );
        }
        m.insert("login_class_lock".into(), Value::Bool(g.tier.lock));
        if let Some(t) = g.updated_at {
            m.insert("updated_at".into(), Value::String(t.to_rfc3339()));
        }
        Ok(Some(Response::data_response(Some(m))))
    }

    pub async fn handle_global_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let tier = read_global_tier_fields(req);
        let g = policy::GlobalPolicy {
            tier,
            updated_at: Some(chrono::Utc::now()),
        };
        pol.put_global(&g).await?;
        log::info!(
            "{}: login_class_default={} lock={}",
            audit::POLICY_GLOBAL_UPDATE,
            g.tier
                .login_class
                .map(|c| c.as_str())
                .unwrap_or("(unset)"),
            g.tier.lock
        );
        self.handle_global_read(_b, req).await
    }

    // ─── Per-type ───────────────────────────────────────────────

    pub async fn handle_type_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let name = req.path.strip_prefix("policy/type/").unwrap_or("").to_string();
        match pol.get_type(&name).await? {
            Some(p) => Ok(Some(Response::data_response(Some(tier_doc_to_map(
                &p.tier,
                Some(&p.type_name),
                None,
                Some(p.updated_at),
            ))))),
            None => Err(bv_error_response_status!(
                404,
                &format!("type login-class policy `{name}` not set")
            )),
        }
    }

    pub async fn handle_type_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let name = req.path.strip_prefix("policy/type/").unwrap_or("").to_string();
        let tier = read_tier_fields(req);
        let p = policy::TypePolicy {
            type_name: name.clone(),
            tier,
            updated_at: chrono::Utc::now(),
        };
        pol.put_type(&p).await?;
        log::info!("{}: type={}", audit::POLICY_TYPE_UPDATE, name);
        Ok(Some(Response::data_response(Some(tier_doc_to_map(
            &p.tier,
            Some(&p.type_name),
            None,
            Some(p.updated_at),
        )))))
    }

    pub async fn handle_type_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let name = req.path.strip_prefix("policy/type/").unwrap_or("").to_string();
        pol.delete_type(&name).await?;
        log::info!("{}: type={} (deleted)", audit::POLICY_TYPE_UPDATE, name);
        Ok(Some(Response::data_response(Some(Map::new()))))
    }

    // ─── Per-asset-group ────────────────────────────────────────

    pub async fn handle_ag_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let id = req
            .path
            .strip_prefix("policy/asset-group/")
            .unwrap_or("")
            .to_string();
        match pol.get_asset_group(&id).await? {
            Some(p) => Ok(Some(Response::data_response(Some(tier_doc_to_map(
                &p.tier,
                None,
                Some(p.priority),
                Some(p.updated_at),
            ))))),
            None => Err(bv_error_response_status!(
                404,
                &format!("asset-group login-class policy `{id}` not set")
            )),
        }
    }

    pub async fn handle_ag_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let id = req
            .path
            .strip_prefix("policy/asset-group/")
            .unwrap_or("")
            .to_string();
        let tier = read_tier_fields(req);
        let priority = req
            .get_data("priority")
            .ok()
            .and_then(|v| v.as_i64())
            .map(|n| n as i32)
            .unwrap_or(0);
        let p = policy::AssetGroupPolicy {
            asset_group_id: id.clone(),
            priority,
            tier,
            updated_at: chrono::Utc::now(),
        };
        pol.put_asset_group(&p).await?;
        log::info!(
            "{}: asset_group={} priority={}",
            audit::POLICY_ASSET_GROUP_UPDATE,
            id,
            priority
        );
        Ok(Some(Response::data_response(Some(tier_doc_to_map(
            &p.tier,
            None,
            Some(p.priority),
            Some(p.updated_at),
        )))))
    }

    pub async fn handle_ag_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let id = req
            .path
            .strip_prefix("policy/asset-group/")
            .unwrap_or("")
            .to_string();
        pol.delete_asset_group(&id).await?;
        log::info!(
            "{}: asset_group={} (deleted)",
            audit::POLICY_ASSET_GROUP_UPDATE,
            id
        );
        Ok(Some(Response::data_response(Some(Map::new()))))
    }

    // ─── Per-resource ───────────────────────────────────────────

    pub async fn handle_res_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let id = req
            .path
            .strip_prefix("policy/resource/")
            .unwrap_or("")
            .to_string();
        match pol.get_resource(&id).await? {
            Some(p) => Ok(Some(Response::data_response(Some(tier_doc_to_map(
                &p.tier,
                Some(&p.resource_id),
                None,
                Some(p.updated_at),
            ))))),
            None => Err(bv_error_response_status!(
                404,
                &format!("resource login-class policy `{id}` not set")
            )),
        }
    }

    pub async fn handle_res_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let id = req
            .path
            .strip_prefix("policy/resource/")
            .unwrap_or("")
            .to_string();
        let tier = read_tier_fields(req);
        // Refuse a per-resource write that would weaken a locked upstream
        // tier. The resolver reports `lock_violation` when the proposed
        // resource class is below a locked floor.
        if let Some(class) = tier.login_class {
            let global = pol.get_global().await?;
            // We don't have the resource's type / asset-group hints here,
            // so this guards against a locked *global* floor. The connect
            // path enforces the full chain; this is the write-time guard
            // matching the Rustion resource-policy behavior.
            let eff = policy::resolve(
                &global,
                None,
                &[],
                Some(&policy::ResourcePolicy {
                    resource_id: id.clone(),
                    tier: policy::LoginClassTier {
                        login_class: Some(class),
                        lock: false,
                    },
                    updated_at: chrono::Utc::now(),
                }),
            );
            if let Some(lv) = eff.lock_violation {
                return Err(bv_error_response_status!(
                    403,
                    &format!(
                        "login_class_locked: tier `{}` locked login_class; per-resource override refused ({})",
                        lv.locking_tier, lv.detail
                    )
                ));
            }
        }
        let p = policy::ResourcePolicy {
            resource_id: id.clone(),
            tier,
            updated_at: chrono::Utc::now(),
        };
        pol.put_resource(&p).await?;
        log::info!("{}: resource={}", audit::POLICY_RESOURCE_UPDATE, id);
        Ok(Some(Response::data_response(Some(tier_doc_to_map(
            &p.tier,
            Some(&p.resource_id),
            None,
            Some(p.updated_at),
        )))))
    }

    pub async fn handle_res_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let id = req
            .path
            .strip_prefix("policy/resource/")
            .unwrap_or("")
            .to_string();
        pol.delete_resource(&id).await?;
        log::info!("{}: resource={} (deleted)", audit::POLICY_RESOURCE_UPDATE, id);
        Ok(Some(Response::data_response(Some(Map::new()))))
    }

    // ─── Effective ──────────────────────────────────────────────

    pub async fn handle_effective(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let pick = |k: &str| -> String {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let resource_type = pick("resource_type");
        let resource_id = pick("resource_id");
        let asset_group_ids: Vec<String> = match req.get_data("asset_group_ids") {
            Ok(Value::Array(arr)) => arr
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            Ok(Value::String(s)) => s
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect(),
            _ => Vec::new(),
        };
        let eff = pol
            .resolve_for(&resource_type, &asset_group_ids, &resource_id)
            .await?;
        Ok(Some(Response::data_response(Some(effective_to_map(&eff)))))
    }
}

// ─── Module wiring ──────────────────────────────────────────────────

impl SshBrokerModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "ssh-broker".to_string(),
            core,
            policy_store: arc_swap::ArcSwap::new(Arc::new(None)),
        }
    }

    pub fn policy_store(&self) -> Option<Arc<policy::PolicyStore>> {
        self.policy_store.load().as_ref().clone()
    }
}

#[maybe_async::maybe_async]
impl Module for SshBrokerModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let backend_new_func = move |c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = SshBrokerBackend::new(c).new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("ssh-broker", Arc::new(backend_new_func))
    }

    async fn init(&self, core: &Core) -> Result<(), RvError> {
        let pol = policy::PolicyStore::new(core).await?;
        self.policy_store.store(Arc::new(Some(pol)));
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        self.policy_store.store(Arc::new(None));
        core.delete_logical_backend("ssh-broker")
    }
}
