//! Rustion integration module.
//!
//! Delegates Resource Connect sessions through one or more
//! [Rustion](https://github.com/ffquintella/Rustion) PQC bastions.
//! BastionVault remains the source of truth for identity, credentials,
//! and authorization; Rustion handles transport + recording.
//!
//! See `features/rustion-integration.md` for the full design. This
//! module ships **Phase 1**: the target registry, the health-state
//! machine, the master-cert configuration slot, the audit event
//! taxonomy, and the HTTP route surface they sit behind. The
//! background pinger (real probe), envelope crate, dispatcher,
//! session lifecycle, and policy ladder land in later phases.

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use derive_more::Deref;
use serde_json::{Map, Value};

use super::Module;
use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation,
        Request, Response,
    },
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
    bv_error_response_status, bv_error_string,
};

pub mod audit;
pub mod config;
pub mod dispatcher;
pub mod envelope;
pub mod health;
pub mod master;
pub mod probe;
pub mod session;
pub mod store;

pub use config::{
    HealthStatus, HybridPubKey, RustionTarget, RustionTargetHealth, RustionTargetInput,
};
pub use health::{apply_probe, ProbeOutcome, FAILURE_THRESHOLD};
pub use master::{MasterConfig, MasterPubKeyExport, MasterStore};
pub use probe::{
    probe_target_now, run_probe_pass, start_pinger, PROBE_AUTHORITY, PROBE_TIMEOUT, TICK_INTERVAL,
};
pub use store::RustionStore;

static RUSTION_BACKEND_HELP: &str = r#"
The rustion backend manages the registry of enrolled Rustion bastion
instances, their health, and the master signing-cert configuration
used to authenticate session-grant envelopes. Resource Connect uses
this registry to mediate SSH / RDP sessions through one or more PQC
bastions instead of opening direct connections from the GUI host.
"#;

#[derive(Default)]
pub struct RustionModule {
    pub name: String,
    pub core: Arc<Core>,
    pub store: ArcSwap<Option<Arc<RustionStore>>>,
    pub master_store: ArcSwap<Option<Arc<MasterStore>>>,
}

pub struct RustionBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct RustionBackend {
    #[deref]
    pub inner: Arc<RustionBackendInner>,
}

impl RustionBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            inner: Arc::new(RustionBackendInner { core }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_targets_list = self.inner.clone();
        let h_targets_create = self.inner.clone();
        let h_target_read = self.inner.clone();
        let h_target_write = self.inner.clone();
        let h_target_delete = self.inner.clone();
        let h_health_all = self.inner.clone();
        let h_probe_all = self.inner.clone();
        let h_probe_one = self.inner.clone();
        let h_master_read = self.inner.clone();
        let h_master_write = self.inner.clone();
        let h_master_pubkey = self.inner.clone();
        let h_session_open = self.inner.clone();
        let h_session_renew = self.inner.clone();
        let h_session_kill = self.inner.clone();
        let h_noop1 = self.inner.clone();
        let h_noop2 = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    // List + create. List returns target ids only; the
                    // GUI / CLI follow up with reads when it wants the
                    // full record. Create accepts the input payload as
                    // JSON body on a POST.
                    pattern: r"targets/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Operator-visible name. Unique per deployment."
                        },
                        "endpoint": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Control-plane endpoint, `host:port`. TLS-only."
                        },
                        "public_key_ed25519": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Base64 SPKI of the Ed25519 half of the Rustion identity keypair."
                        },
                        "public_key_mldsa65": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Base64 raw FIPS 204 ML-DSA-65 public key."
                        },
                        "kem_public_key": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Base64 raw FIPS 203 ML-KEM-768 public key — used to encrypt session-grant envelopes to this Rustion instance."
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Free-form description shown in the GUI."
                        },
                        "tags": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "Operator-set tags, e.g. `region=eu-west-1`."
                        },
                        "enabled": {
                            field_type: FieldType::Bool,
                            default: true,
                            description: "When false, the dispatcher skips this target regardless of health."
                        },
                        "default_recording_dir": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Optional: relative directory under the Rustion recordings root for diagnostics."
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_targets_list.handle_targets_list},
                        {op: Operation::Write, handler: h_targets_create.handle_target_create}
                    ],
                    help: "List enrolled Rustion targets, or POST a fresh enrolment."
                },
                {
                    pattern: r"targets/(?P<id>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Stable id allocated by the registry."
                        },
                        "name": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Operator-visible name. Unique per deployment."
                        },
                        "endpoint": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Control-plane endpoint, `host:port`."
                        },
                        "public_key_ed25519": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Base64 SPKI of the Ed25519 half."
                        },
                        "public_key_mldsa65": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Base64 raw ML-DSA-65 public key."
                        },
                        "kem_public_key": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Base64 raw FIPS 203 ML-KEM-768 public key — used to encrypt session-grant envelopes to this Rustion instance."
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Free-form description."
                        },
                        "tags": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "Operator-set tags."
                        },
                        "enabled": {
                            field_type: FieldType::Bool,
                            default: true,
                            description: "Soft toggle."
                        },
                        "default_recording_dir": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Optional diagnostic field."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_target_read.handle_target_read},
                        {op: Operation::Write, handler: h_target_write.handle_target_update},
                        {op: Operation::Delete, handler: h_target_delete.handle_target_delete}
                    ],
                    help: "Read, update, or delete one Rustion target."
                },
                {
                    pattern: r"targets/health/?$",
                    operations: [
                        {op: Operation::Read, handler: h_health_all.handle_health_all}
                    ],
                    help: "Cached health for every enrolled target (background-poller view)."
                },
                {
                    // Force a full probe sweep across every enabled
                    // target — same routine the background pinger
                    // runs on its 30s tick, exposed for operators who
                    // just changed an endpoint and want immediate
                    // feedback instead of waiting for the next tick.
                    pattern: r"targets/probe$",
                    operations: [
                        {op: Operation::Write, handler: h_probe_all.handle_probe_all}
                    ],
                    help: "Trigger an immediate health probe sweep across every enabled Rustion target."
                },
                {
                    // Per-target probe + read. The Write path probes,
                    // persists the result, then returns the fresh
                    // health record so the GUI's enrolment wizard
                    // can show "test connection" feedback synchronously.
                    pattern: r"targets/(?P<id>[A-Za-z0-9_\-]+)/probe$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Target id to probe."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_probe_one.handle_probe_one}
                    ],
                    help: "Probe a single Rustion target and return its fresh health record."
                },
                {
                    pattern: r"master/config$",
                    fields: {
                        "pki_mount": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "PKI mount the master cert is minted from (e.g. `pki-internal/`)."
                        },
                        "pki_role": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "PKI role under that mount."
                        },
                        "issuer_ref": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Issuer ref under the PKI mount. Empty = mount default."
                        },
                        "default_ttl_secs": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Default TTL when issuing / rotating. Zero = engine default (5y)."
                        },
                        "rotate_grace_secs": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Grace window during which the previous cert is accepted. Zero = default (1d)."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_master_read.handle_master_read},
                        {op: Operation::Write, handler: h_master_write.handle_master_write}
                    ],
                    help: "Read or update the master-cert configuration slot."
                },
                {
                    pattern: r"master/pubkey$",
                    operations: [
                        {op: Operation::Read, handler: h_master_pubkey.handle_master_pubkey}
                    ],
                    help: "Export the master pubkey (one-shot enrolment step for Rustion authorities)."
                },
                {
                    // POST rustion/session/renew — Phase 5.
                    pattern: r"session/renew$",
                    fields: {
                        "bastion_id": { field_type: FieldType::Str, default: "", description: "Bastion id that opened the session." },
                        "session_id": { field_type: FieldType::Str, default: "", description: "Session id returned by /session/open." },
                        "correlation_id": { field_type: FieldType::Str, default: "", description: "Correlation id from the original /session/open response." },
                        "extend_secs": { field_type: FieldType::Int, default: 1800, description: "Requested renewal duration in seconds." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_session_renew.handle_session_renew}
                    ],
                    help: "Renew a Rustion-mediated session, extending its TTL and consuming one renewal slot."
                },
                {
                    // DELETE rustion/session/kill — Phase 5.
                    pattern: r"session/kill$",
                    fields: {
                        "bastion_id": { field_type: FieldType::Str, default: "", description: "Bastion id that opened the session." },
                        "session_id": { field_type: FieldType::Str, default: "", description: "Session id returned by /session/open." },
                        "correlation_id": { field_type: FieldType::Str, default: "", description: "Correlation id from the original /session/open response." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_session_kill.handle_session_kill}
                    ],
                    help: "Forcibly terminate a Rustion-mediated session."
                },
                {
                    // POST rustion/session/open — run dispatcher,
                    // build envelope, POST at Rustion, return ticket.
                    pattern: r"session/open$",
                    fields: {
                        "target_host": { field_type: FieldType::Str, default: "", description: "Target SSH/RDP destination host." },
                        "target_port": { field_type: FieldType::Int, default: 22, description: "Target SSH/RDP destination port." },
                        "target_protocol": { field_type: FieldType::Str, default: "ssh", description: "ssh | rdp" },
                        "target_hostkey_pin": { field_type: FieldType::Str, default: "", description: "Optional TOFU host-key fingerprint." },
                        "credential_kind": { field_type: FieldType::Str, default: "", description: "ssh-key | ssh-password | rdp-password | rdp-cert | ..." },
                        "credential_username": { field_type: FieldType::Str, default: "", description: "Username on the target host." },
                        "credential_material": { field_type: FieldType::Str, default: "", description: "Base64-encoded credential bytes." },
                        "ttl_secs": { field_type: FieldType::Int, default: 3600, description: "Requested session TTL." },
                        "max_renewals": { field_type: FieldType::Int, default: 3, description: "Max renewal count." },
                        "recording": { field_type: FieldType::Str, default: "always", description: "always | off | input-redacted" },
                        "bastions": { field_type: FieldType::CommaStringSlice, required: false, description: "Pinned ordered target ids; empty = random global pool." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_session_open.handle_session_open}
                    ],
                    help: "Open a Rustion-mediated SSH/RDP session. Runs the dispatcher, builds a BVRG-v1 envelope, POSTs at the chosen Rustion target, and returns the session ticket bundle."
                }
            ],
            secrets: [{
                secret_type: "rustion",
                renew_handler: h_noop1.handle_noop,
                revoke_handler: h_noop2.handle_noop,
            }],
            help: RUSTION_BACKEND_HELP,
        });

        backend
    }
}

#[maybe_async::maybe_async]
impl RustionBackendInner {
    fn resolve_store(&self) -> Result<Arc<RustionStore>, RvError> {
        let module = self
            .core
            .module_manager
            .get_module::<RustionModule>("rustion")
            .ok_or_else(|| bv_error_string!("rustion module not registered"))?;
        let store = module.store();
        store.ok_or_else(|| bv_error_string!("rustion store not initialized"))
    }

    fn resolve_master_store(&self) -> Result<Arc<MasterStore>, RvError> {
        let module = self
            .core
            .module_manager
            .get_module::<RustionModule>("rustion")
            .ok_or_else(|| bv_error_string!("rustion module not registered"))?;
        let master = module.master_store();
        master.ok_or_else(|| bv_error_string!("rustion master store not initialized"))
    }

    fn input_from_req(req: &Request, fallback_name: &str) -> Result<RustionTargetInput, RvError> {
        let pick = |k: &str| -> String {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let name = if fallback_name.is_empty() {
            pick("name")
        } else {
            // PUT-by-id path lets the operator omit name on update;
            // the handler patches the existing record with whatever
            // the caller supplied. Empty name here means "preserve
            // the current name".
            let n = pick("name");
            if n.is_empty() {
                fallback_name.to_string()
            } else {
                n
            }
        };
        let tags = req
            .get_data("tags")
            .ok()
            .and_then(|v| match v {
                Value::Array(arr) => Some(
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>(),
                ),
                Value::String(s) => Some(
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default();
        let enabled = req
            .get_data("enabled")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        Ok(RustionTargetInput {
            name,
            endpoint: pick("endpoint"),
            public_key: HybridPubKey {
                ed25519: pick("public_key_ed25519"),
                mldsa65: pick("public_key_mldsa65"),
            },
            kem_public_key: pick("kem_public_key"),
            description: pick("description"),
            tags,
            enabled,
            default_recording_dir: pick("default_recording_dir"),
        })
    }

    pub async fn handle_noop(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    // ─── Targets ────────────────────────────────────────────────────

    pub async fn handle_targets_list(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let ids = store.list_target_ids().await?;
        Ok(Some(Response::list_response(&ids)))
    }

    pub async fn handle_target_create(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let input = Self::input_from_req(req, "")?;
        let target = store.create_target(input).await?;
        log::info!(
            "{}: id={} name={} endpoint={} fingerprint={}",
            audit::TARGET_ENROL,
            target.id,
            target.name,
            target.endpoint,
            target.fingerprint
        );
        Ok(Some(target_response(&target)))
    }

    pub async fn handle_target_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let id = req
            .get_data("id")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        match store.get_target(&id).await? {
            Some(t) => Ok(Some(target_response(&t))),
            None => Err(bv_error_response_status!(404, &format!(
                "rustion target `{id}` not found"
            ))),
        }
    }

    pub async fn handle_target_update(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let id = req
            .get_data("id")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let existing = store.get_target(&id).await?.ok_or_else(|| {
            bv_error_response_status!(404, &format!("rustion target `{id}` not found"))
        })?;
        // Patch semantics: empty fields preserve existing values.
        let mut input = Self::input_from_req(req, &existing.name)?;
        if input.endpoint.is_empty() {
            input.endpoint = existing.endpoint.clone();
        }
        if input.public_key.ed25519.is_empty() {
            input.public_key.ed25519 = existing.public_key.ed25519.clone();
        }
        if input.public_key.mldsa65.is_empty() {
            input.public_key.mldsa65 = existing.public_key.mldsa65.clone();
        }
        if input.kem_public_key.is_empty() {
            input.kem_public_key = existing.kem_public_key.clone();
        }
        if input.description.is_empty() {
            input.description = existing.description.clone();
        }
        if input.default_recording_dir.is_empty() {
            input.default_recording_dir = existing.default_recording_dir.clone();
        }
        let updated = store.update_target(&id, input).await?;
        let rotated = updated.public_key.ed25519 != existing.public_key.ed25519
            || updated.public_key.mldsa65 != existing.public_key.mldsa65;
        log::info!(
            "{}: id={} name={} endpoint={} fingerprint={}",
            if rotated {
                audit::TARGET_ROTATE
            } else {
                audit::TARGET_UPDATE
            },
            updated.id,
            updated.name,
            updated.endpoint,
            updated.fingerprint
        );
        Ok(Some(target_response(&updated)))
    }

    pub async fn handle_target_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let id = req
            .get_data("id")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        store.delete_target(&id).await?;
        log::info!("{}: id={}", audit::TARGET_DELETE, id);
        Ok(None)
    }

    // ─── Health ─────────────────────────────────────────────────────

    pub async fn handle_health_all(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let ids = store.list_target_ids().await?;
        let mut entries: Vec<Value> = Vec::with_capacity(ids.len());
        for id in ids {
            let health = store.get_health(&id).await?.unwrap_or_default();
            let target = store.get_target(&id).await?;
            let mut m = Map::new();
            m.insert("id".into(), Value::String(id.clone()));
            if let Some(t) = target.as_ref() {
                m.insert("name".into(), Value::String(t.name.clone()));
                m.insert("endpoint".into(), Value::String(t.endpoint.clone()));
                m.insert("enabled".into(), Value::Bool(t.enabled));
            }
            m.insert("status".into(), Value::String(health.status.as_str().into()));
            if let Some(ts) = health.last_ok_at {
                m.insert("last_ok_at".into(), Value::String(ts.to_rfc3339()));
            }
            m.insert("last_error".into(), Value::String(health.last_error));
            m.insert(
                "latency_ms_p50".into(),
                Value::Number(health.latency_ms_p50.into()),
            );
            m.insert(
                "consecutive_failures".into(),
                Value::Number(health.consecutive_failures.into()),
            );
            m.insert("version".into(), Value::String(health.version));
            m.insert(
                "active_sessions".into(),
                Value::Number(health.active_sessions.into()),
            );
            m.insert(
                "updated_at".into(),
                Value::String(health.updated_at.to_rfc3339()),
            );
            entries.push(Value::Object(m));
        }
        let mut data = Map::new();
        data.insert("targets".into(), Value::Array(entries));
        Ok(Some(Response::data_response(Some(data))))
    }

    // ─── Probe (manual trigger) ────────────────────────────────────

    pub async fn handle_probe_all(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let core = self.core.clone();
        probe::run_probe_pass(&core).await?;
        // Surface the freshened cache straight back so the caller
        // doesn't need a follow-up read.
        self.handle_health_all(_b, _req).await
    }

    pub async fn handle_probe_one(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = req
            .get_data("id")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let store = self.resolve_store()?;
        let target = store
            .get_target(&id)
            .await?
            .ok_or_else(|| bv_error_response_status!(404, &format!(
                "rustion target `{id}` not found"
            )))?;
        // Reuse the same client + state-machine path the background
        // pinger uses so single-target test = exactly one tick of
        // the regular probe loop.
        probe::probe_target_now(&store, &target).await;
        let health = store.get_health(&id).await?.unwrap_or_default();
        let mut data = Map::new();
        data.insert("id".into(), Value::String(target.id.clone()));
        data.insert("name".into(), Value::String(target.name.clone()));
        data.insert(
            "status".into(),
            Value::String(health.status.as_str().to_string()),
        );
        data.insert("last_error".into(), Value::String(health.last_error));
        data.insert(
            "latency_ms_p50".into(),
            Value::Number(health.latency_ms_p50.into()),
        );
        data.insert("version".into(), Value::String(health.version));
        data.insert(
            "active_sessions".into(),
            Value::Number(health.active_sessions.into()),
        );
        data.insert(
            "consecutive_failures".into(),
            Value::Number(health.consecutive_failures.into()),
        );
        if let Some(ts) = health.last_ok_at {
            data.insert("last_ok_at".into(), Value::String(ts.to_rfc3339()));
        }
        data.insert(
            "updated_at".into(),
            Value::String(health.updated_at.to_rfc3339()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    // ─── Master cert config ────────────────────────────────────────

    pub async fn handle_master_read(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_master_store()?;
        let cfg = store.get_or_default().await?;
        Ok(Some(master_config_response(&cfg)))
    }

    pub async fn handle_master_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_master_store()?;
        let mut cfg = store.get_or_default().await?;
        let mut touched = false;
        if let Some(v) = req.get_data("pki_mount").ok().and_then(|v| v.as_str().map(String::from))
        {
            if !v.is_empty() && v != cfg.pki_mount {
                cfg.pki_mount = v;
                touched = true;
            }
        }
        if let Some(v) = req.get_data("pki_role").ok().and_then(|v| v.as_str().map(String::from))
        {
            if !v.is_empty() && v != cfg.pki_role {
                cfg.pki_role = v;
                touched = true;
            }
        }
        if let Some(v) = req
            .get_data("issuer_ref")
            .ok()
            .and_then(|v| v.as_str().map(String::from))
        {
            if v != cfg.issuer_ref {
                cfg.issuer_ref = v;
                touched = true;
            }
        }
        if let Some(n) = req
            .get_data("default_ttl_secs")
            .ok()
            .and_then(|v| v.as_u64())
        {
            if n > 0 && n != cfg.default_ttl_secs {
                cfg.default_ttl_secs = n;
                touched = true;
            }
        }
        if let Some(n) = req
            .get_data("rotate_grace_secs")
            .ok()
            .and_then(|v| v.as_u64())
        {
            if n > 0 && n != cfg.rotate_grace_secs {
                cfg.rotate_grace_secs = n;
                touched = true;
            }
        }
        if touched {
            cfg.updated_at = chrono::Utc::now();
            store.put(&cfg).await?;
        }
        Ok(Some(master_config_response(&cfg)))
    }

    pub async fn handle_session_open(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let store = self.resolve_store()?;
        let master_store = self.resolve_master_store()?;
        let master = master_store
            .get_or_init_signing_key()
            .await
            .map_err(|e| bv_error_string!(&format!("master signing key: {e}")))?;

        let pick = |k: &str| -> String {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let pick_u = |k: &str, default: u64| -> u64 {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_u64())
                .unwrap_or(default)
        };

        let credential_material_b64 = pick("credential_material");
        let credential_material = STANDARD
            .decode(credential_material_b64.as_bytes())
            .map_err(|e| bv_error_string!(&format!("credential_material base64 decode: {e}")))?;

        let bastions_raw = req
            .get_data("bastions")
            .ok()
            .and_then(|v| match v {
                Value::Array(arr) => Some(
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>(),
                ),
                Value::String(s) => Some(
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect(),
                ),
                _ => None,
            });

        let hostkey_pin = pick("target_hostkey_pin");
        let request = session::SessionOpenRequest {
            target_host: pick("target_host"),
            target_port: u16::try_from(pick_u("target_port", 22)).unwrap_or(22),
            target_protocol: pick("target_protocol"),
            target_hostkey_pin: if hostkey_pin.is_empty() {
                None
            } else {
                Some(hostkey_pin)
            },
            credential_kind: pick("credential_kind"),
            credential_username: pick("credential_username"),
            credential_material,
            ttl_secs: u32::try_from(pick_u("ttl_secs", 3600)).unwrap_or(3600),
            max_renewals: u8::try_from(pick_u("max_renewals", 3)).unwrap_or(3),
            recording: pick("recording"),
            bastions: bastions_raw.filter(|v| !v.is_empty()),
        };

        // Operator context from the calling token's metadata. Source-IP
        // is pulled from the request's remote-addr field; the rest
        // come from the auth metadata stamped at login.
        let auth = req.auth.as_ref().ok_or_else(|| {
            bv_error_response_status!(401, "no authenticated caller")
        })?;
        let operator = envelope::OperatorContext {
            vault_user_id: auth
                .metadata
                .get("entity_id")
                .cloned()
                .unwrap_or_default(),
            vault_user_name: auth
                .metadata
                .get("username")
                .cloned()
                .unwrap_or_default(),
            vault_session_id: auth
                .metadata
                .get("session_id")
                .cloned()
                .unwrap_or_default(),
            src_ip: req.client_token.clone(), // placeholder; the route layer doesn't currently surface remote addr
            deployment_id: auth
                .metadata
                .get("deployment_id")
                .cloned()
                .unwrap_or_default(),
        };

        match session::open_session_v2(&store, &master, &operator, &request).await {
            Ok(resp) => {
                let mut data = Map::new();
                data.insert("session_id".into(), Value::String(resp.session_id));
                data.insert("host".into(), Value::String(resp.host));
                data.insert("port".into(), Value::Number(resp.port.into()));
                data.insert("ticket".into(), Value::String(resp.ticket));
                data.insert("expires_at".into(), Value::String(resp.expires_at));
                data.insert("protocol".into(), Value::String(resp.protocol));
                data.insert("recording_id".into(), Value::String(resp.recording_id));
                data.insert("bastion_id".into(), Value::String(resp.bastion_id));
                data.insert("bastion_name".into(), Value::String(resp.bastion_name));
                data.insert(
                    "bastion_selection".into(),
                    Value::String(resp.bastion_selection.to_string()),
                );
                data.insert(
                    "bastion_candidates_tried".into(),
                    Value::Array(
                        resp.bastion_candidates_tried
                            .into_iter()
                            .map(Value::String)
                            .collect(),
                    ),
                );
                data.insert(
                    "correlation_id".into(),
                    Value::String(resp.correlation_id),
                );
                log::info!(
                    "{}: session_id={} bastion={} candidates_tried={}",
                    audit::SESSION_OPEN,
                    data.get("session_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    data.get("bastion_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    data.get("bastion_candidates_tried")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                );
                Ok(Some(Response::data_response(Some(data))))
            }
            Err(session::SessionOpenError::NoCandidates) => Err(bv_error_response_status!(
                503,
                "bastion_unavailable: no candidate Rustion targets — every target is unhealthy, disabled, or unregistered"
            )),
            Err(session::SessionOpenError::AllRejected { attempts }) => {
                let detail = attempts
                    .iter()
                    .map(|a| format!("{}: {}", a.bastion_name, a.outcome))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(bv_error_response_status!(
                    502,
                    &format!("bastion_rejected: {detail}")
                ))
            }
            Err(e) => Err(bv_error_string!(&format!("{e}"))),
        }
    }

    // ─── Phase 5: renew + kill ──────────────────────────────────────

    pub async fn handle_session_renew(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let master_store = self.resolve_master_store()?;
        let master = master_store
            .get_or_init_signing_key()
            .await
            .map_err(|e| bv_error_string!(&format!("master signing key: {e}")))?;

        let pick = |k: &str| -> String {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let extend_secs = req
            .get_data("extend_secs")
            .ok()
            .and_then(|v| v.as_u64())
            .map(|n| u32::try_from(n).unwrap_or(1800))
            .unwrap_or(1800);

        let operator = self.operator_context(req)?;
        let request = session::SessionRenewRequest {
            bastion_id: pick("bastion_id"),
            session_id: pick("session_id"),
            correlation_id: pick("correlation_id"),
            extend_secs,
        };

        match session::renew_session(&store, &master, &operator, &request).await {
            Ok(resp) => {
                let mut data = Map::new();
                data.insert("session_id".into(), Value::String(resp.session_id.clone()));
                data.insert("expires_at".into(), Value::String(resp.expires_at));
                data.insert("renewals_used".into(), Value::Number(resp.renewals_used.into()));
                data.insert("max_renewals".into(), Value::Number(resp.max_renewals.into()));
                data.insert("bastion_id".into(), Value::String(resp.bastion_id.clone()));
                log::info!(
                    "{}: session_id={} bastion={} renewals_used={}/{}",
                    audit::SESSION_RENEW,
                    resp.session_id,
                    resp.bastion_id,
                    resp.renewals_used,
                    resp.max_renewals,
                );
                Ok(Some(Response::data_response(Some(data))))
            }
            Err(session::SessionRenewError::BastionNotFound(id)) => Err(bv_error_response_status!(
                404,
                &format!("bastion_not_found: {id}")
            )),
            Err(session::SessionRenewError::Http { status, body }) => {
                Err(bv_error_response_status!(
                    status,
                    &format!("bastion_rejected: {body}")
                ))
            }
            Err(e) => Err(bv_error_string!(&format!("{e}"))),
        }
    }

    pub async fn handle_session_kill(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let master_store = self.resolve_master_store()?;
        let master = master_store
            .get_or_init_signing_key()
            .await
            .map_err(|e| bv_error_string!(&format!("master signing key: {e}")))?;

        let pick = |k: &str| -> String {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let operator = self.operator_context(req)?;
        let request = session::SessionKillRequest {
            bastion_id: pick("bastion_id"),
            session_id: pick("session_id"),
            correlation_id: pick("correlation_id"),
        };

        match session::kill_session(&store, &master, &operator, &request).await {
            Ok(resp) => {
                let mut data = Map::new();
                data.insert("session_id".into(), Value::String(resp.session_id.clone()));
                data.insert("terminated_at".into(), Value::String(resp.terminated_at));
                data.insert("bastion_id".into(), Value::String(resp.bastion_id.clone()));
                log::info!(
                    "{}: session_id={} bastion={}",
                    audit::SESSION_TERMINATE,
                    resp.session_id,
                    resp.bastion_id,
                );
                Ok(Some(Response::data_response(Some(data))))
            }
            Err(session::SessionRenewError::BastionNotFound(id)) => Err(bv_error_response_status!(
                404,
                &format!("bastion_not_found: {id}")
            )),
            Err(session::SessionRenewError::Http { status, body }) => {
                Err(bv_error_response_status!(
                    status,
                    &format!("bastion_rejected: {body}")
                ))
            }
            Err(e) => Err(bv_error_string!(&format!("{e}"))),
        }
    }

    /// Extract OperatorContext from the caller's auth metadata.
    /// Phase 5: factored out so renew + kill share the open path's
    /// identity-stamping logic.
    fn operator_context(&self, req: &Request) -> Result<envelope::OperatorContext, RvError> {
        let auth = req
            .auth
            .as_ref()
            .ok_or_else(|| bv_error_response_status!(401, "no authenticated caller"))?;
        Ok(envelope::OperatorContext {
            vault_user_id: auth
                .metadata
                .get("entity_id")
                .cloned()
                .unwrap_or_default(),
            vault_user_name: auth
                .metadata
                .get("username")
                .cloned()
                .unwrap_or_default(),
            vault_session_id: auth
                .metadata
                .get("session_id")
                .cloned()
                .unwrap_or_default(),
            src_ip: req.client_token.clone(),
            deployment_id: auth
                .metadata
                .get("deployment_id")
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub async fn handle_master_pubkey(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // Phase 1 stub: the actual pubkey export reads the issued cert
        // out of the PKI engine and projects it into the hybrid shape
        // Rustion's authority record wants. That wiring lands in
        // Phase 2 alongside the envelope crate. For now we surface the
        // config + an empty pubkey envelope so the GUI can render the
        // "configure me first" state.
        let store = self.resolve_master_store()?;
        let cfg = store.get_or_default().await?;
        let export = MasterPubKeyExport {
            algorithm: cfg.algorithm.clone(),
            ed25519_pem: String::new(),
            mldsa65_pem: String::new(),
            fingerprint: String::new(),
            current_serial: cfg.current_serial.clone(),
            current_not_after: cfg.current_not_after,
        };
        let mut data = Map::new();
        data.insert("algorithm".into(), Value::String(export.algorithm));
        data.insert("ed25519_pem".into(), Value::String(export.ed25519_pem));
        data.insert("mldsa65_pem".into(), Value::String(export.mldsa65_pem));
        data.insert("fingerprint".into(), Value::String(export.fingerprint));
        data.insert(
            "current_serial".into(),
            Value::String(export.current_serial),
        );
        if let Some(ts) = export.current_not_after {
            data.insert("current_not_after".into(), Value::String(ts.to_rfc3339()));
        }
        data.insert(
            "issued".into(),
            Value::Bool(!cfg.current_serial.is_empty()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }
}

fn target_response(t: &RustionTarget) -> Response {
    let mut data: HashMap<String, Value> = HashMap::new();
    data.insert("id".into(), Value::String(t.id.clone()));
    data.insert("name".into(), Value::String(t.name.clone()));
    data.insert("endpoint".into(), Value::String(t.endpoint.clone()));
    let mut pk = Map::new();
    pk.insert("ed25519".into(), Value::String(t.public_key.ed25519.clone()));
    pk.insert("mldsa65".into(), Value::String(t.public_key.mldsa65.clone()));
    data.insert("public_key".into(), Value::Object(pk));
    data.insert(
        "kem_public_key".into(),
        Value::String(t.kem_public_key.clone()),
    );
    data.insert("fingerprint".into(), Value::String(t.fingerprint.clone()));
    data.insert("description".into(), Value::String(t.description.clone()));
    data.insert(
        "tags".into(),
        Value::Array(t.tags.iter().cloned().map(Value::String).collect()),
    );
    data.insert("enabled".into(), Value::Bool(t.enabled));
    data.insert(
        "default_recording_dir".into(),
        Value::String(t.default_recording_dir.clone()),
    );
    data.insert("created_at".into(), Value::String(t.created_at.to_rfc3339()));
    data.insert("updated_at".into(), Value::String(t.updated_at.to_rfc3339()));
    let map: Map<String, Value> = data.into_iter().collect();
    Response::data_response(Some(map))
}

fn master_config_response(cfg: &MasterConfig) -> Response {
    let mut data = Map::new();
    data.insert("pki_mount".into(), Value::String(cfg.pki_mount.clone()));
    data.insert("pki_role".into(), Value::String(cfg.pki_role.clone()));
    data.insert("issuer_ref".into(), Value::String(cfg.issuer_ref.clone()));
    data.insert("algorithm".into(), Value::String(cfg.algorithm.clone()));
    data.insert(
        "default_ttl_secs".into(),
        Value::Number(cfg.default_ttl_secs.into()),
    );
    data.insert(
        "rotate_grace_secs".into(),
        Value::Number(cfg.rotate_grace_secs.into()),
    );
    data.insert(
        "current_serial".into(),
        Value::String(cfg.current_serial.clone()),
    );
    if let Some(ts) = cfg.current_not_after {
        data.insert("current_not_after".into(), Value::String(ts.to_rfc3339()));
    }
    data.insert(
        "updated_at".into(),
        Value::String(cfg.updated_at.to_rfc3339()),
    );
    data.insert("configured".into(), Value::Bool(
        !cfg.pki_mount.is_empty() && !cfg.pki_role.is_empty(),
    ));
    Response::data_response(Some(data))
}

impl RustionModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "rustion".to_string(),
            core,
            store: ArcSwap::new(Arc::new(None)),
            master_store: ArcSwap::new(Arc::new(None)),
        }
    }

    pub fn store(&self) -> Option<Arc<RustionStore>> {
        self.store.load().as_ref().clone()
    }

    pub fn master_store(&self) -> Option<Arc<MasterStore>> {
        self.master_store.load().as_ref().clone()
    }
}

#[maybe_async::maybe_async]
impl Module for RustionModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let backend_new_func = move |c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = RustionBackend::new(c).new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("rustion", Arc::new(backend_new_func))
    }

    async fn init(&self, core: &Core) -> Result<(), RvError> {
        let store = RustionStore::new(core).await?;
        self.store.store(Arc::new(Some(store)));
        let master = MasterStore::new(core).await?;
        self.master_store.store(Arc::new(Some(master)));
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        self.master_store.store(Arc::new(None));
        core.delete_logical_backend("rustion")
    }
}
