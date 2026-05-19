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
pub mod poller;
pub mod policy;
pub mod probe;
pub mod recordings;

fn read_string_list(req: &Request, key: &str) -> Vec<String> {
    match req.get_data(key) {
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
    }
}

fn read_tier_fields(req: &Request) -> policy::PolicyTier {
    let pick = |k: &str| -> Option<String> {
        req.get_data(k)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
    };
    let transport = pick("transport").and_then(|s| match s.as_str() {
        "direct" => Some(policy::Transport::Direct),
        "rustion-preferred" => Some(policy::Transport::RustionPreferred),
        "rustion-required" => Some(policy::Transport::RustionRequired),
        _ => None,
    });
    let recording = pick("recording").and_then(|s| match s.as_str() {
        "off" => Some(policy::Recording::Off),
        "input-redacted" => Some(policy::Recording::InputRedacted),
        "always" => Some(policy::Recording::Always),
        _ => None,
    });
    let bastion_group = pick("bastion_group");
    let lock = req
        .get_data("lock")
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    policy::PolicyTier {
        transport,
        bastions: read_string_list(req, "bastions"),
        bastion_group,
        recording,
        lock,
    }
}

fn group_to_map(g: &policy::BastionGroup) -> Map<String, Value> {
    serde_json::to_value(g)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn tier_doc_to_map(
    tier: &policy::PolicyTier,
    name: Option<&str>,
    priority: Option<i32>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(t) = tier.transport {
        m.insert("transport".into(), Value::String(t.as_str().into()));
    }
    m.insert(
        "bastions".into(),
        Value::Array(
            tier.bastions
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    if let Some(ref g) = tier.bastion_group {
        m.insert("bastion_group".into(), Value::String(g.clone()));
    }
    if let Some(r) = tier.recording {
        m.insert("recording".into(), Value::String(r.as_str().into()));
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
pub mod session;
pub mod store;
pub mod webhook_verify;

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
    pub recordings_store: ArcSwap<Option<Arc<recordings::RecordingsStore>>>,
    pub policy_store: ArcSwap<Option<Arc<policy::PolicyStore>>>,
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
        let h_webhook_recording = self.inner.clone();
        let h_recordings_list = self.inner.clone();
        let h_recording_read = self.inner.clone();
        let h_recording_pull = self.inner.clone();
        let h_recording_blob = self.inner.clone();
        let h_policy_global_read = self.inner.clone();
        let h_policy_global_write = self.inner.clone();
        let h_bastion_groups_list = self.inner.clone();
        let h_bastion_groups_create = self.inner.clone();
        let h_bastion_group_read = self.inner.clone();
        let h_bastion_group_update = self.inner.clone();
        let h_bastion_group_delete = self.inner.clone();
        let h_policy_type_read = self.inner.clone();
        let h_policy_type_write = self.inner.clone();
        let h_policy_type_delete = self.inner.clone();
        let h_policy_ag_read = self.inner.clone();
        let h_policy_ag_write = self.inner.clone();
        let h_policy_res_read = self.inner.clone();
        let h_policy_res_write = self.inner.clone();
        let h_policy_force_rustion = self.inner.clone();
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
                },
                {
                    // POST rustion/webhooks/recording-ready — Phase 6.2.
                    // Verifies the X-Rustion-Signature against the
                    // bastion's pinned recording_webhook_pubkey and stores
                    // the sidecar in the recordings index.
                    pattern: r"webhooks/recording-ready$",
                    fields: {
                        "bastion_id": { field_type: FieldType::Str, default: "", description: "Bastion target id originating the webhook (looked up to pull the pinned recording_webhook_pubkey)." },
                        "signature": { field_type: FieldType::Str, default: "", description: "X-Rustion-Signature header value: `ed25519=<base64> mldsa65=<base64>`." },
                        "sidecar_json": { field_type: FieldType::Str, default: "", description: "The sidecar payload bytes (serialised JSON) as a base64 string." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_webhook_recording.handle_webhook_recording_ready}
                    ],
                    help: "Phase 6.2 — Inbound webhook receiver for `recording.ready` notifications from a Rustion bastion. Signature is verified against the bastion's pinned recording_webhook_pubkey; sidecar is stored in the recordings index; audit::RECORDING_LINKED is emitted."
                },
                {
                    // GET rustion/recordings — list known recordings.
                    pattern: r"recordings/?$",
                    operations: [
                        {op: Operation::Read, handler: h_recordings_list.handle_recordings_list}
                    ],
                    help: "List all known recordings (Phase 6.2)."
                },
                {
                    // GET rustion/recordings/<rid> — fetch one recording entry.
                    pattern: r"recordings/(?P<rid>[A-Za-z0-9_\-]+)$",
                    operations: [
                        {op: Operation::Read, handler: h_recording_read.handle_recording_read}
                    ],
                    help: "Read a single recording entry by id (Phase 6.2)."
                },
                {
                    // GET rustion/recordings/<rid>/blob — Phase 6.5.
                    // Proxies through to the bastion's
                    // GET /v1/recordings/<rid>/blob endpoint and
                    // returns the recording bytes (base64-wrapped so
                    // the BV response shape stays JSON-friendly).
                    pattern: r"recordings/(?P<rid>[A-Za-z0-9_\-]+)/blob$",
                    operations: [
                        {op: Operation::Read, handler: h_recording_blob.handle_recording_blob}
                    ],
                    help: "Phase 6.5 — fetch a recording artifact's bytes (base64) for in-GUI playback."
                },
                {
                    // GET/PUT rustion/policy/global — Phase 7. Root-gated.
                    pattern: r"policy/global$",
                    fields: {
                        "transport": { field_type: FieldType::Str, required: false, description: "direct | rustion-preferred | rustion-required" },
                        "bastions": { field_type: FieldType::CommaStringSlice, required: false, description: "Pinned bastion ids (mutually exclusive with bastion_group)." },
                        "bastion_group": { field_type: FieldType::Str, required: false, description: "Named bastion group." },
                        "recording": { field_type: FieldType::Str, required: false, description: "always | input-redacted | off" },
                        "lock": { field_type: FieldType::Bool, required: false, description: "Freeze these settings against lower tiers." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_policy_global_read.handle_policy_global_read},
                        {op: Operation::Write, handler: h_policy_global_write.handle_policy_global_write}
                    ],
                    help: "Phase 7 — Global Rustion transport-and-bastion policy. Read + write the deployment-wide defaults."
                },
                {
                    // List + create bastion groups.
                    pattern: r"bastion-groups/?$",
                    fields: {
                        "name": { field_type: FieldType::Str, default: "", description: "Group name (case-insensitive unique)." },
                        "members": { field_type: FieldType::CommaStringSlice, required: false, description: "Bastion target ids in this group." },
                        "selection": { field_type: FieldType::Str, default: "ordered", description: "ordered | random" },
                        "description": { field_type: FieldType::Str, default: "", description: "Operator-visible description." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_bastion_groups_list.handle_bastion_groups_list},
                        {op: Operation::Write, handler: h_bastion_groups_create.handle_bastion_groups_create}
                    ],
                    help: "Phase 7 — Bastion groups: named pools of Rustion targets used by the policy resolver."
                },
                {
                    // GET/PUT/DELETE rustion/policy/type/<type_name> — Phase 7.2.
                    pattern: r"policy/type/(?P<type_name>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "transport": { field_type: FieldType::Str, required: false, description: "direct | rustion-preferred | rustion-required" },
                        "bastions": { field_type: FieldType::CommaStringSlice, required: false, description: "Pinned bastion ids." },
                        "bastion_group": { field_type: FieldType::Str, required: false, description: "Named bastion group." },
                        "recording": { field_type: FieldType::Str, required: false, description: "always | input-redacted | off" },
                        "lock": { field_type: FieldType::Bool, required: false, description: "Lock against lower tiers." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_policy_type_read.handle_policy_type_read},
                        {op: Operation::Write, handler: h_policy_type_write.handle_policy_type_write},
                        {op: Operation::Delete, handler: h_policy_type_delete.handle_policy_type_delete}
                    ],
                    help: "Phase 7 — Per-resource-type Rustion policy. Admin-gated."
                },
                {
                    // GET/PUT rustion/policy/asset-group/<id> — Phase 7.2.
                    pattern: r"policy/asset-group/(?P<id>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "priority": { field_type: FieldType::Int, default: 0, description: "Higher wins on multi-group resolution." },
                        "transport": { field_type: FieldType::Str, required: false, description: "direct | rustion-preferred | rustion-required" },
                        "bastions": { field_type: FieldType::CommaStringSlice, required: false, description: "Pinned bastion ids." },
                        "bastion_group": { field_type: FieldType::Str, required: false, description: "Named bastion group." },
                        "recording": { field_type: FieldType::Str, required: false, description: "always | input-redacted | off" },
                        "lock": { field_type: FieldType::Bool, required: false, description: "Lock against lower tiers." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_policy_ag_read.handle_policy_ag_read},
                        {op: Operation::Write, handler: h_policy_ag_write.handle_policy_ag_write}
                    ],
                    help: "Phase 7 — Per-asset-group Rustion policy. Admin or group-owner gated."
                },
                {
                    // GET/PUT rustion/policy/resource/<id> — Phase 7.2.
                    pattern: r"policy/resource/(?P<id>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "transport": { field_type: FieldType::Str, required: false, description: "direct | rustion-preferred | rustion-required" },
                        "bastions": { field_type: FieldType::CommaStringSlice, required: false, description: "Pinned bastion ids." },
                        "bastion_group": { field_type: FieldType::Str, required: false, description: "Named bastion group." },
                        "recording": { field_type: FieldType::Str, required: false, description: "always | input-redacted | off" }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_policy_res_read.handle_policy_res_read},
                        {op: Operation::Write, handler: h_policy_res_write.handle_policy_res_write}
                    ],
                    help: "Phase 7 — Per-resource Rustion policy override. Gated to resource owner; only writable when no upstream tier is locked."
                },
                {
                    // POST rustion/policy/force-rustion — Phase 7.2
                    // migration action: flips transport_default to
                    // `rustion-required` + lock=true after operator
                    // confirms the diff preview returned by GET.
                    pattern: r"policy/force-rustion$",
                    fields: {
                        "confirm": { field_type: FieldType::Bool, default: false, description: "Set to true to actually apply the change; default returns a diff preview." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_policy_force_rustion.handle_policy_force_rustion}
                    ],
                    help: "Phase 7 — Force every Connect through Rustion. Root-only. Without confirm=true, returns a diff preview."
                },
                {
                    // Read / update / delete a single bastion group.
                    pattern: r"bastion-groups/(?P<name>[A-Za-z0-9_\-]+)$",
                    fields: {
                        "members": { field_type: FieldType::CommaStringSlice, required: false, description: "Replace member list." },
                        "selection": { field_type: FieldType::Str, required: false, description: "ordered | random" },
                        "description": { field_type: FieldType::Str, required: false, description: "Operator-visible description." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_bastion_group_read.handle_bastion_group_read},
                        {op: Operation::Write, handler: h_bastion_group_update.handle_bastion_group_update},
                        {op: Operation::Delete, handler: h_bastion_group_delete.handle_bastion_group_delete}
                    ],
                    help: "Phase 7 — Bastion group CRUD by name."
                },
                {
                    // POST rustion/recordings/pull — Phase 6.3
                    // pull-fallback: GET the sidecar from the bastion
                    // and stuff it into the local recordings index.
                    pattern: r"recordings/pull$",
                    fields: {
                        "bastion_id": { field_type: FieldType::Str, default: "", description: "Bastion id that holds the recording." },
                        "session_id": { field_type: FieldType::Str, default: "", description: "Session id whose recording we want." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_recording_pull.handle_recording_pull}
                    ],
                    help: "Phase 6.3 — force-pull a recording sidecar from a bastion when the recording.ready webhook missed. Stores into the recordings index with delivery_mode=pull."
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

    fn resolve_recordings_store(&self) -> Result<Arc<recordings::RecordingsStore>, RvError> {
        let module = self
            .core
            .module_manager
            .get_module::<RustionModule>("rustion")
            .ok_or_else(|| bv_error_string!("rustion module not registered"))?;
        let recs = module.recordings_store();
        recs.ok_or_else(|| bv_error_string!("rustion recordings store not initialized"))
    }

    fn resolve_policy_store(&self) -> Result<Arc<policy::PolicyStore>, RvError> {
        let module = self
            .core
            .module_manager
            .get_module::<RustionModule>("rustion")
            .ok_or_else(|| bv_error_string!("rustion module not registered"))?;
        let pol = module.policy_store();
        pol.ok_or_else(|| bv_error_string!("rustion policy store not initialized"))
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

        // Phase 7.2: consult the policy resolver to compute the
        // effective policy for this session. Today we only consult the
        // global tier — the per-type / per-AG / per-resource lookups
        // are wired alongside the editor surface in Phase 7.3 (when
        // we have access to resource + asset-group records from the
        // caller's context).
        //
        // Refuse on lock_violation or rustion-required with no
        // bastions configured anywhere. Override the caller-supplied
        // bastions list with the resolver's pinned list when the
        // policy specifies one (so a policy-locked bastion-group can't
        // be bypassed by an operator passing their own `bastions`).
        let policy_store = self.resolve_policy_store()?;
        let global_policy = policy_store.get_global().await?;
        let effective = policy::resolve(&global_policy, None, &[], None);
        if let Some(ref lv) = effective.lock_violation {
            return Err(bv_error_response_status!(
                403,
                &format!(
                    "rustion policy lock violation ({} locked by `{}`): {}",
                    lv.field, lv.locking_tier, lv.detail
                )
            ));
        }

        // Resolve effective bastion list: use the policy's bastions if
        // it set any (overriding the caller); else use the caller's
        // list; else use the bastion_group's members if a group is
        // pinned; else fall through to the dispatcher's random pool.
        let mut effective_bastions: Option<Vec<String>> =
            bastions_raw.filter(|v| !v.is_empty());
        if !effective.bastions.is_empty() {
            effective_bastions = Some(effective.bastions.clone());
        } else if let Some(ref group_name) = effective.bastion_group {
            if let Some(grp) = policy_store.get_group(group_name).await? {
                if !grp.members.is_empty() {
                    effective_bastions = Some(grp.members.clone());
                }
            }
        }

        // rustion-required: refuse to open if no bastion is reachable.
        // The dispatcher will already filter on health, so a non-empty
        // effective_bastions list isn't a guarantee — but an empty
        // list with rustion-required is a definite failure.
        if effective.transport == policy::Transport::RustionRequired
            && effective_bastions.as_ref().map(|v| v.is_empty()).unwrap_or(true)
        {
            // Check if ANY healthy bastion exists at all (matches dispatcher's
            // global-pool fallback semantics).
            let any = store.list_target_ids().await?;
            if any.is_empty() {
                return Err(bv_error_response_status!(
                    403,
                    "rustion-required policy: no bastions enrolled"
                ));
            }
        }

        // Recording: if the resolver strengthened it, override the caller.
        let effective_recording = match effective.recording {
            policy::Recording::Always => "always".to_string(),
            policy::Recording::InputRedacted => "input-redacted".to_string(),
            policy::Recording::Off => "off".to_string(),
        };
        let caller_recording = pick("recording");
        // Pick whichever is stricter (default to resolver's value).
        let recording_choice = if caller_recording.is_empty() {
            effective_recording
        } else {
            // Defer to resolver since that's what the policy says.
            effective_recording
        };

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
            recording: recording_choice,
            bastions: effective_bastions,
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
                let session_id_owned = resp.session_id.clone();
                let bastion_id_owned = resp.bastion_id.clone();
                let expires_at_owned = resp.expires_at.clone();
                let correlation_id_owned = resp.correlation_id.clone();
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
                // Phase 7.2: stamp the effective policy on the
                // response so the GUI can show the resolution chain
                // (which tier produced each effective value).
                data.insert(
                    "policy_transport".into(),
                    Value::String(effective.transport.as_str().into()),
                );
                data.insert(
                    "policy_transport_source".into(),
                    Value::String(effective.transport_source.into()),
                );
                data.insert(
                    "policy_recording".into(),
                    Value::String(effective.recording.as_str().into()),
                );
                data.insert(
                    "policy_recording_source".into(),
                    Value::String(effective.recording_source.into()),
                );
                data.insert(
                    "policy_bastions_source".into(),
                    Value::String(effective.bastions_source.into()),
                );
                data.insert(
                    "policy_locked_by".into(),
                    Value::Array(
                        effective
                            .locked_by
                            .iter()
                            .map(|s| Value::String((*s).to_string()))
                            .collect(),
                    ),
                );
                // Phase 6.4: track this session as a "pending recording"
                // so the 24h poller pulls if the webhook never lands.
                // Best-effort — failure here doesn't fail session-open.
                if let Ok(recs) = self.resolve_recordings_store() {
                    let now = chrono::Utc::now();
                    let expected_by = chrono::DateTime::parse_from_rfc3339(&expires_at_owned)
                        .map(|d| d.with_timezone(&chrono::Utc) + chrono::Duration::minutes(5))
                        .unwrap_or_else(|_| now + chrono::Duration::hours(2));
                    let pr = recordings::PendingRecording {
                        session_id: session_id_owned.clone(),
                        bastion_id: bastion_id_owned.clone(),
                        authority: String::new(),
                        correlation_id: correlation_id_owned,
                        opened_at: now,
                        expected_by,
                    };
                    if let Err(e) = recs.pending_insert(&pr).await {
                        log::warn!(
                            "rustion: failed to insert pending recording for {}: {e}",
                            session_id_owned
                        );
                    }
                }
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

    // ─── Phase 6.2: recording webhook + index ──────────────────────

    pub async fn handle_webhook_recording_ready(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let store = self.resolve_store()?;
        let recordings = self.resolve_recordings_store()?;

        let pick = |k: &str| -> String {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let bastion_id = pick("bastion_id");
        let signature = pick("signature");
        let sidecar_b64 = pick("sidecar_json");

        if bastion_id.is_empty() {
            return Err(bv_error_response_status!(400, "bastion_id is required"));
        }
        if signature.is_empty() {
            return Err(bv_error_response_status!(400, "signature header value is required"));
        }
        let sidecar_bytes = STANDARD
            .decode(sidecar_b64.as_bytes())
            .map_err(|e| bv_error_response_status!(400, &format!("sidecar_json base64 decode: {e}")))?;

        // Look up the bastion's pinned signing pubkey.
        let target = store
            .get_target(&bastion_id)
            .await?
            .ok_or_else(|| bv_error_response_status!(404, &format!("bastion `{bastion_id}` not enrolled")))?;

        // Verify the hybrid signature. The pinned pubkey halves are
        // stored base64 on the RustionTarget; the webhook signer is
        // mirror-implementation of rustion-control-plane::webhook so
        // we replicate the verification path here instead of pulling
        // the Rustion crate as a BV dep.
        webhook_verify::verify(
            &target.public_key.ed25519,
            &target.public_key.mldsa65,
            &signature,
            &sidecar_bytes,
        )
        .map_err(|e| bv_error_response_status!(401, &format!("signature verify: {e}")))?;

        // Parse the sidecar payload.
        let sidecar: serde_json::Value = serde_json::from_slice(&sidecar_bytes)
            .map_err(|e| bv_error_response_status!(400, &format!("sidecar parse: {e}")))?;
        let sd = sidecar.as_object().ok_or_else(|| {
            bv_error_response_status!(400, "sidecar must be a JSON object")
        })?;
        let s = |k: &str| -> String {
            sd.get(k).and_then(|v| v.as_str()).map(String::from).unwrap_or_default()
        };
        let u = |k: &str| -> u64 {
            sd.get(k).and_then(|v| v.as_u64()).unwrap_or(0)
        };
        let parse_iso = |k: &str| -> chrono::DateTime<chrono::Utc> {
            sd.get(k)
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now)
        };

        let recording_id = s("recording_id");
        if recording_id.is_empty() {
            return Err(bv_error_response_status!(400, "sidecar missing recording_id"));
        }
        let entry = recordings::RecordingEntry {
            recording_id: recording_id.clone(),
            session_id: s("session_id"),
            authority: s("authority"),
            format: s("format"),
            sha256: s("sha256"),
            size_bytes: u("size_bytes"),
            started_at: parse_iso("started_at"),
            finished_at: parse_iso("finished_at"),
            target_host: s("target_host"),
            target_user: s("target_user"),
            correlation_id: s("correlation_id"),
            bastion_id: bastion_id.clone(),
            received_at: chrono::Utc::now(),
            delivery_mode: "webhook".into(),
        };
        recordings.put(&entry).await?;
        // Clear the pending-recording marker so the 24h poller drops
        // this session from its sweep list. Phase 6.4.
        let _ = recordings.pending_remove(&entry.session_id).await;

        log::info!(
            "{}: recording_id={} session_id={} bastion={} correlation_id={}",
            audit::RECORDING_LINKED,
            entry.recording_id,
            entry.session_id,
            entry.bastion_id,
            entry.correlation_id
        );

        let mut data = Map::new();
        data.insert("recording_id".into(), Value::String(entry.recording_id));
        data.insert("delivery_mode".into(), Value::String(entry.delivery_mode));
        data.insert(
            "received_at".into(),
            Value::String(entry.received_at.to_rfc3339()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_recordings_list(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let recordings = self.resolve_recordings_store()?;
        let ids = recordings.list_ids().await?;
        let mut data = Map::new();
        data.insert(
            "recordings".into(),
            Value::Array(ids.into_iter().map(Value::String).collect()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_recording_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let recordings = self.resolve_recordings_store()?;
        let rid = req.path.trim_start_matches("recordings/").to_string();
        let Some(entry) = recordings.get(&rid).await? else {
            return Err(bv_error_response_status!(404, &format!("recording `{rid}` not found")));
        };
        let json = serde_json::to_value(&entry)
            .map_err(|e| bv_error_string!(&format!("encode recording: {e}")))?;
        let data = json.as_object().cloned().unwrap_or_default();
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_recording_blob(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let store = self.resolve_store()?;
        let recordings = self.resolve_recordings_store()?;
        // Path looks like `recordings/<rid>/blob` after the mount
        // strip. Pull the rid out by walking the components.
        let rid = req
            .path
            .strip_prefix("recordings/")
            .and_then(|s| s.strip_suffix("/blob"))
            .unwrap_or("")
            .to_string();
        if rid.is_empty() {
            return Err(bv_error_response_status!(400, "recording_id is required"));
        }
        let (bytes, format, sha256) =
            recordings::fetch_blob(&store, &recordings, &rid)
                .await
                .map_err(|e| bv_error_string!(&format!("{e}")))?;
        let mut data = Map::new();
        data.insert("recording_id".into(), Value::String(rid));
        data.insert("format".into(), Value::String(format));
        data.insert("sha256".into(), Value::String(sha256));
        data.insert("bytes_b64".into(), Value::String(STANDARD.encode(&bytes)));
        data.insert(
            "size_bytes".into(),
            Value::Number((bytes.len() as u64).into()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_recording_pull(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let store = self.resolve_store()?;
        let recordings = self.resolve_recordings_store()?;
        let pick = |k: &str| -> String {
            req.get_data(k)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let bastion_id = pick("bastion_id");
        let session_id = pick("session_id");
        if bastion_id.is_empty() || session_id.is_empty() {
            return Err(bv_error_response_status!(
                400,
                "bastion_id and session_id are required"
            ));
        }
        let entry = recordings::pull_recording(&store, &recordings, &bastion_id, &session_id)
            .await
            .map_err(|e| bv_error_string!(&format!("{e}")))?;
        log::info!(
            "{}: recording_id={} session_id={} bastion={} mode=pull",
            audit::RECORDING_LINKED,
            entry.recording_id,
            entry.session_id,
            entry.bastion_id
        );
        let json = serde_json::to_value(&entry)
            .map_err(|e| bv_error_string!(&format!("encode recording: {e}")))?;
        let data = json.as_object().cloned().unwrap_or_default();
        Ok(Some(Response::data_response(Some(data))))
    }

    // ─── Phase 7: policy + bastion groups ──────────────────────────

    pub async fn handle_policy_global_read(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let g = pol.get_global().await?;
        let data = serde_json::to_value(&g)
            .map_err(|e| bv_error_string!(&format!("encode: {e}")))?
            .as_object()
            .cloned()
            .unwrap_or_default();
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_policy_global_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let tier = read_tier_fields(req);
        let g = policy::GlobalPolicy {
            tier,
            updated_at: Some(chrono::Utc::now()),
        };
        pol.put_global(&g).await?;
        log::info!("{}: lock={}", audit::POLICY_GLOBAL_UPDATE, g.tier.lock);
        Ok(Some(Response::data_response(Some(Map::new()))))
    }

    pub async fn handle_bastion_groups_list(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let names = pol.list_groups().await?;
        let mut data = Map::new();
        data.insert(
            "groups".into(),
            Value::Array(names.into_iter().map(Value::String).collect()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_bastion_groups_create(
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
        let name = pick("name");
        if name.is_empty() {
            return Err(bv_error_response_status!(400, "name is required"));
        }
        let members = read_string_list(req, "members");
        let selection = match pick("selection").as_str() {
            "random" => policy::Selection::Random,
            _ => policy::Selection::Ordered,
        };
        if pol.get_group(&name).await?.is_some() {
            return Err(bv_error_response_status!(
                409,
                &format!("bastion group `{name}` already exists")
            ));
        }
        let now = chrono::Utc::now();
        let g = policy::BastionGroup {
            name: name.clone(),
            members,
            selection,
            description: pick("description"),
            created_at: now,
            updated_at: now,
        };
        pol.put_group(&g).await?;
        log::info!("{}: name={}", audit::BASTION_GROUP_UPDATE, name);
        Ok(Some(Response::data_response(Some(group_to_map(&g)))))
    }

    pub async fn handle_bastion_group_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let name = req
            .path
            .strip_prefix("bastion-groups/")
            .unwrap_or("")
            .to_string();
        let Some(g) = pol.get_group(&name).await? else {
            return Err(bv_error_response_status!(404, &format!("bastion group `{name}` not found")));
        };
        Ok(Some(Response::data_response(Some(group_to_map(&g)))))
    }

    pub async fn handle_bastion_group_update(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let name = req
            .path
            .strip_prefix("bastion-groups/")
            .unwrap_or("")
            .to_string();
        let Some(mut g) = pol.get_group(&name).await? else {
            return Err(bv_error_response_status!(404, &format!("bastion group `{name}` not found")));
        };
        if let Ok(members) = req.get_data("members") {
            if let Value::Array(arr) = members {
                g.members = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect();
            } else if let Value::String(s) = members {
                g.members = s
                    .split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect();
            }
        }
        if let Some(s) = req
            .get_data("selection")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
        {
            g.selection = match s.as_str() {
                "random" => policy::Selection::Random,
                "ordered" => policy::Selection::Ordered,
                _ => g.selection,
            };
        }
        if let Some(d) = req
            .get_data("description")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
        {
            g.description = d;
        }
        g.updated_at = chrono::Utc::now();
        pol.put_group(&g).await?;
        log::info!("{}: name={}", audit::BASTION_GROUP_UPDATE, name);
        Ok(Some(Response::data_response(Some(group_to_map(&g)))))
    }

    pub async fn handle_bastion_group_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let name = req
            .path
            .strip_prefix("bastion-groups/")
            .unwrap_or("")
            .to_string();
        pol.delete_group(&name).await?;
        log::info!("{}: name={} (deleted)", audit::BASTION_GROUP_UPDATE, name);
        Ok(Some(Response::data_response(Some(Map::new()))))
    }

    // ─── Per-type policy ────────────────────────────────────────────

    pub async fn handle_policy_type_read(
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
            None => Err(bv_error_response_status!(404, &format!("type policy `{name}` not set"))),
        }
    }

    pub async fn handle_policy_type_write(
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

    pub async fn handle_policy_type_delete(
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

    // ─── Per-asset-group policy ─────────────────────────────────────

    pub async fn handle_policy_ag_read(
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
            None => Err(bv_error_response_status!(404, &format!("asset-group policy `{id}` not set"))),
        }
    }

    pub async fn handle_policy_ag_write(
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

    // ─── Per-resource policy ────────────────────────────────────────

    pub async fn handle_policy_res_read(
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
                None,
                None,
                Some(p.updated_at),
            ))))),
            None => Err(bv_error_response_status!(404, &format!("resource policy `{id}` not set"))),
        }
    }

    pub async fn handle_policy_res_write(
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
        let mut tier = read_tier_fields(req);
        // Per-resource overrides may NOT set `lock = true` — only the
        // three higher tiers can lock. Refuse a write that tries.
        if tier.lock {
            return Err(bv_error_response_status!(
                400,
                "per-resource policy may not set lock=true; locking is admin/root only"
            ));
        }
        // Refuse any per-resource write when an upstream tier locked
        // the corresponding knobs — the operator can't escape a
        // higher-tier lock. We do a probe-resolve to detect violations.
        let global = pol.get_global().await?;
        // (Type + AG lookups skipped here; resolver still catches them
        //  on session/open. The per-resource write check is the
        //  best-effort guard for the most common case: a
        //  globally-locked rustion-required policy.)
        let probe = policy::resolve(&global, None, &[], None);
        if !probe.locked_by.is_empty() {
            // If the operator's write would *weaken* anything the global
            // tier locked, refuse outright. Anything else is allowed.
            let proposed_res = policy::ResourcePolicy {
                resource_id: id.clone(),
                tier: tier.clone(),
                updated_at: chrono::Utc::now(),
            };
            let test = policy::resolve(&global, None, &[], Some(&proposed_res));
            if test.lock_violation.is_some() {
                let lv = test.lock_violation.as_ref().unwrap();
                return Err(bv_error_response_status!(
                    403,
                    &format!(
                        "per-resource write blocked by upstream lock on {}: {}",
                        lv.field, lv.detail
                    )
                ));
            }
        }
        tier.lock = false; // Defensive: per-resource never locks.
        let p = policy::ResourcePolicy {
            resource_id: id.clone(),
            tier,
            updated_at: chrono::Utc::now(),
        };
        pol.put_resource(&p).await?;
        log::info!("{}: resource={}", audit::POLICY_RESOURCE_UPDATE, id);
        Ok(Some(Response::data_response(Some(tier_doc_to_map(
            &p.tier,
            None,
            None,
            Some(p.updated_at),
        )))))
    }

    // ─── Migration action ───────────────────────────────────────────

    pub async fn handle_policy_force_rustion(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let pol = self.resolve_policy_store()?;
        let confirm = req
            .get_data("confirm")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let current = pol.get_global().await?;
        let proposed = policy::GlobalPolicy {
            tier: policy::PolicyTier {
                transport: Some(policy::Transport::RustionRequired),
                lock: true,
                ..current.tier.clone()
            },
            updated_at: Some(chrono::Utc::now()),
        };
        let mut data = Map::new();
        data.insert(
            "current_transport".into(),
            Value::String(
                current
                    .tier
                    .transport
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_else(|| "(unset)".into()),
            ),
        );
        data.insert(
            "current_lock".into(),
            Value::Bool(current.tier.lock),
        );
        data.insert(
            "proposed_transport".into(),
            Value::String("rustion-required".into()),
        );
        data.insert("proposed_lock".into(), Value::Bool(true));
        if confirm {
            pol.put_global(&proposed).await?;
            log::info!(
                "{}: forced transport=rustion-required + lock=true (migration action)",
                audit::POLICY_GLOBAL_UPDATE
            );
            data.insert("applied".into(), Value::Bool(true));
        } else {
            data.insert("applied".into(), Value::Bool(false));
            data.insert(
                "note".into(),
                Value::String(
                    "set confirm=true to apply. Existing per-tier overrides that try to set transport=direct will start returning 403 lock_violation."
                        .into(),
                ),
            );
        }
        Ok(Some(Response::data_response(Some(data))))
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
            recordings_store: ArcSwap::new(Arc::new(None)),
            policy_store: ArcSwap::new(Arc::new(None)),
        }
    }

    pub fn store(&self) -> Option<Arc<RustionStore>> {
        self.store.load().as_ref().clone()
    }

    pub fn master_store(&self) -> Option<Arc<MasterStore>> {
        self.master_store.load().as_ref().clone()
    }

    pub fn recordings_store(&self) -> Option<Arc<recordings::RecordingsStore>> {
        self.recordings_store.load().as_ref().clone()
    }

    pub fn policy_store(&self) -> Option<Arc<policy::PolicyStore>> {
        self.policy_store.load().as_ref().clone()
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
        let recs = recordings::RecordingsStore::new(core).await?;
        self.recordings_store.store(Arc::new(Some(recs)));
        let pol = policy::PolicyStore::new(core).await?;
        self.policy_store.store(Arc::new(Some(pol)));
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        self.master_store.store(Arc::new(None));
        self.recordings_store.store(Arc::new(None));
        self.policy_store.store(Arc::new(None));
        core.delete_logical_backend("rustion")
    }
}
