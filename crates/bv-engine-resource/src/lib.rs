//! Dedicated resource storage engine.
//!
//! Stores resource metadata and per-resource secrets behind the vault barrier,
//! completely independent of the KV secret engine. All data is encrypted at rest.
//!
//! Storage layout within the mount's barrier view:
//!   meta/<name>                         -> ResourceEntry JSON (current)
//!   hist/<name>/<20-digit-nanos>        -> ResourceHistoryEntry JSON (append-only
//!                                          audit log of who-changed-what; values
//!                                          are NOT stored here)
//!   secret/<resource>/<key>             -> current value of a resource secret
//!                                          (kept for fast reads + backward compat)
//!   smeta/<resource>/<key>              -> ResourceSecretMeta JSON (version index)
//!   sver/<resource>/<key>/<version>     -> ResourceSecretVersion JSON (old values)

pub mod agent_access;
pub mod agent_limits;
mod agent_session;
pub mod agent_ssh;
pub mod agent_web;
pub mod connect_clipboard;
pub mod connect_mfa;
pub mod connect_provider;
pub mod connect_session;
pub mod connect_web;
pub mod kernel_service;
pub mod sql_profile;
pub mod sql_resource;
pub mod type_config;

// The substrate, under the names this engine already spells it by. Private:
// `crate::errors::RvError` and `crate::logical::Path` keep resolving inside
// the crate, and none of it leaks into the public API, so the extraction
// stayed a file move rather than an import rewrite.
// See roadmaps/workspace-decomposition.md § Phase 3.
use bv_context as context;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;
use bv_storage as storage;

// The eight backend-definition macros are `#[macro_export]`ed by `bv-logical`,
// which places them at *that* crate's root; the call sites import them as
// `crate::new_path` and friends. The `_internal` halves are the recursive arms
// the public macros expand into, so they must travel with them.
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    new_secret, new_secret_internal,
};

use std::{
    any::Any,
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::kernel_api::{
    engines::LoginClassVerdict,
    identity::{caller_audit_actor, ObjectKind},
    VaultCtx,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    storage::StorageEntry,
};
use bv_kernel_api::Module;

static RESOURCE_BACKEND_HELP: &str = r#"
The resource backend provides dedicated storage for infrastructure resources
(servers, databases, network devices, etc.) and their associated secrets.
All data is encrypted behind the vault barrier.

Each resource metadata write is recorded in an append-only history log
(who + when + which fields changed). Each resource-secret write snapshots
the previous value into a versioned entry so the full change history is
available for audit.
"#;

/// True when a resource-secret body looks like a *static SSH login
/// credential* — i.e. it carries a non-empty `private_key` or `password`
/// field, exactly the shape the SSH `secret` credential source feeds to
/// the dialler (`resolve_secret_ssh`). Brokered resources reject these at
/// attach time. A bare `passphrase` (a modifier, not a credential) does
/// not count on its own.
fn static_ssh_credential_shape(body: &Map<String, Value>) -> bool {
    let nonempty = |k: &str| body.get(k).and_then(|v| v.as_str()).map(|s| !s.trim().is_empty()).unwrap_or(false);
    nonempty("private_key") || nonempty("password")
}

/// Full (non-mount-relative) request path of a single resource's metadata
/// endpoint, minus the name: this engine is mounted at `resources/` and the
/// route inside it is `resources/<name>`. Backend handlers see the
/// mount-relative path, so anything that has to speak the ACL's language —
/// which is always the full path — rebuilds it from here. Mirrors the same
/// hardcoded convention in `policy_store::resource_name_from_path`.
const RESOURCE_METADATA_PATH_PREFIX: &str = "resources/resources/";

// Storage key prefixes within this mount's barrier view
const META_PREFIX: &str = "meta/";
const HIST_PREFIX: &str = "hist/";
const SECRET_PREFIX: &str = "secret/";
const SMETA_PREFIX: &str = "smeta/";
const SVER_PREFIX: &str = "sver/";

/// Projection of `ResourceMetadata` that the search endpoint returns.
/// Carries exactly what the GUI's card needs to render — keeping the
/// payload small so a page-of-30 response stays well under a few KB
/// even with tag-heavy resources.
#[derive(Debug, Serialize)]
pub struct ResourceCardEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// Per-profile facts the GUI's card-level Connect button needs to decide
    /// whether one click can launch anything for the calling operator. The
    /// launchability matrix (which protocol × credential-source combinations
    /// the in-app client can actually drive) lives client-side, so the card
    /// carries the inputs rather than a precomputed verdict. Deliberately
    /// omits targets, host-key pins and transport options — those stay on the
    /// full `resources/resources/<name>` read.
    ///
    /// Always serialised, empty array included: the GUI distinguishes "this
    /// resource has no launchable profile" (disable Connect) from "this card
    /// came from a path that doesn't carry the hints" (leave it enabled), and
    /// an omitted field would collapse the two.
    pub connect_profiles: Vec<ConnectProfileHint>,
}

/// See `ResourceCardEntry::connect_profiles`.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectProfileHint {
    /// `ssh` | `rdp`.
    pub protocol: String,
    /// Transport: `direct` | `rustion`. Omitted when the profile predates
    /// the field; the GUI reads an absent value as `direct`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub credential_source: ConnectProfileCredentialHint,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectProfileCredentialHint {
    pub kind: String,
    /// SSH-engine mint mode (`ca` | `otp` | `pqc`) where the source carries
    /// one — `pqc` certs aren't launchable from the in-app client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

impl ResourceCardEntry {
    fn from_metadata(name: &str, data: &Map<String, Value>) -> Self {
        let str_field = |k: &str| -> Option<String> {
            data.get(k).and_then(|v| v.as_str()).map(str::to_string).filter(|s| !s.is_empty())
        };
        Self {
            name: name.to_string(),
            kind: str_field("type").unwrap_or_default(),
            hostname: str_field("hostname"),
            ip_address: str_field("ip_address"),
            tags: str_field("tags"),
            connect_profiles: Self::profile_hints(data),
        }
    }

    /// Project `connection_profiles` down to the card hints. Tolerates the
    /// field being absent or malformed (the profile array is opaque metadata
    /// the host never validates) — an unparseable entry is skipped rather
    /// than failing the whole search page.
    fn profile_hints(data: &Map<String, Value>) -> Vec<ConnectProfileHint> {
        let Some(Value::Array(profiles)) = data.get("connection_profiles") else {
            return Vec::new();
        };
        let opt_str = |o: &Map<String, Value>, k: &str| -> Option<String> {
            o.get(k).and_then(|v| v.as_str()).map(str::to_string).filter(|s| !s.is_empty())
        };
        profiles
            .iter()
            .filter_map(|p| {
                let obj = p.as_object()?;
                let protocol = opt_str(obj, "protocol")?;
                let cred = obj.get("credential_source")?.as_object()?;
                Some(ConnectProfileHint {
                    protocol,
                    kind: opt_str(obj, "kind"),
                    credential_source: ConnectProfileCredentialHint {
                        kind: opt_str(cred, "kind")?,
                        mode: opt_str(cred, "mode"),
                    },
                })
            })
            .collect()
    }
}

// Resource-metadata fields that are not meaningful in a change-tracking diff.
// Timestamps are always updated on every write, and `name` is part of the
// identity -- including them would make every entry look like a change.
const HIST_IGNORED_FIELDS: &[&str] = &["created_at", "updated_at", "name"];

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

/// Audit log entry for a resource metadata change. Stores *what* field
/// names changed but not the before/after values -- per requirement, the
/// resource timeline is "who and when made the changes (and what field)".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
}

/// Per-version metadata for a resource secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSecretVersionMeta {
    pub created_time: String,
    pub username: String,
    /// "create" | "update" | "restore"
    pub operation: String,
}

/// Version index for a single resource secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSecretMeta {
    pub current_version: u64,
    pub versions: HashMap<String, ResourceSecretVersionMeta>,
}

/// On-disk payload for a single historical version of a resource secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSecretVersion {
    pub data: Map<String, Value>,
    pub version: u64,
    pub created_time: String,
    pub username: String,
    pub operation: String,
}

// ── Transfer bundle (`v2/transfer/import/<name>`) ──────────────────
//
// The wire shape the cross-namespace transfer orchestrator sends to the
// destination mount (features/cross-namespace-copy-move.md). It is a request
// body, never persisted as such: the import writes the existing `meta/`,
// `secret/`, `smeta/`, `sver/` and `hist/` records from it.

/// One version of a resource secret in a transfer bundle. No `Debug` on the
/// bundle types: they carry secret values, and a stray `{:?}` would print them.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SecretVersionBundle {
    pub version: u64,
    pub created_time: String,
    /// Always false for a resource secret: this engine has no per-version
    /// delete. The field is shared with the KV bundle, and a `true` here is
    /// refused rather than imported as a live version.
    #[serde(default)]
    pub deleted: bool,
    pub data: Map<String, Value>,
    /// Author and operation of the version at the origin
    /// (`ResourceSecretVersionMeta`). Optional so a bundle that does not
    /// carry them still imports; they are written back verbatim, empty
    /// included, never replaced by the importing caller.
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub operation: String,
}

/// A resource secret with its whole version history.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SecretBundle {
    pub key: String,
    pub versions: Vec<SecretVersionBundle>,
    /// The live version; must be the highest one in `versions`, as it always
    /// is in this engine (a write after the import continues from it).
    pub current: u64,
}

impl SecretBundle {
    fn current_data(&self) -> Option<&Map<String, Value>> {
        self.versions.iter().find(|v| v.version == self.current).map(|v| &v.data)
    }
}

/// Everything a resource carries across namespaces, minus ownership and
/// shares (the orchestrator's, see `handle_resource_import`).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ResourceBundle {
    pub meta: Map<String, Value>,
    #[serde(default)]
    pub secrets: Vec<SecretBundle>,
    /// The origin's change history. Each entry is keyed by its own `ts`, so
    /// the order the entries arrive in does not matter.
    #[serde(default)]
    pub history: Vec<ResourceHistoryEntry>,
    /// `refuse` (default, also when empty) | `rename`. There is no overwrite:
    /// the caller deletes the destination first (`DELETE resources/resources/<name>`).
    #[serde(default)]
    pub on_conflict: String,
    /// The origin's owner entity, recorded in the `transfer-in` history
    /// entry. Empty for an unowned origin.
    #[serde(default)]
    pub origin_owner: String,
    /// Where the resource came from (`<namespace>/<mount>/<name>`), recorded
    /// in the `transfer-in` history entry.
    pub origin: String,
}

/// What an import wrote: the final name (differs from the requested one
/// under `rename`) and how many secrets, versions and origin history entries
/// arrived. `history` does not count the `transfer-in` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceImportSummary {
    pub name: String,
    pub secrets: usize,
    pub versions: usize,
    pub history: usize,
}

// ── Module boilerplate ─────────────────────────────────────────────

pub struct ResourceModule {
    pub name: String,
    pub backend: Arc<ResourceBackend>,
}

pub struct ResourceBackendInner {
    pub core: Arc<dyn VaultCtx>,
    /// This node's MCP brokered-session limiter (`agent_limits`), shared by
    /// every resource mount and every protocol, built from the server config
    /// on first use. Read only by the session executors, so unread in a
    /// build without one.
    #[cfg_attr(
        not(all(any(feature = "mcp_sessions_ssh", feature = "mcp_sessions_web"), not(feature = "sync_handler"))),
        allow(dead_code)
    )]
    agent_limiter: std::sync::OnceLock<agent_limits::SessionLimiter>,
}

#[derive(Deref)]
pub struct ResourceBackend {
    #[deref]
    pub inner: Arc<ResourceBackendInner>,
}

impl ResourceBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { inner: Arc::new(ResourceBackendInner { core, agent_limiter: std::sync::OnceLock::new() }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_cfg_read = self.inner.clone();
        let h_cfg_write = self.inner.clone();
        let h_res_read = self.inner.clone();
        let h_res_write = self.inner.clone();
        let h_res_delete = self.inner.clone();
        let h_res_rename = self.inner.clone();
        let h_res_import = self.inner.clone();
        let h_res_list = self.inner.clone();
        let h_res_search = self.inner.clone();
        let h_res_hist = self.inner.clone();
        let h_sec_read = self.inner.clone();
        let h_sec_write = self.inner.clone();
        let h_sec_delete = self.inner.clone();
        let h_sec_list = self.inner.clone();
        let h_sec_hist = self.inner.clone();
        let h_sec_ver = self.inner.clone();
        let h_noop1 = self.inner.clone();
        let h_noop2 = self.inner.clone();
        let h_mfa_begin = self.inner.clone();
        let h_mfa_verify = self.inner.clone();
        let h_authorize = self.inner.clone();
        let h_provider_candidates = self.inner.clone();
        let h_providers = self.inner.clone();
        let h_web_launch = self.inner.clone();
        let h_web_totp = self.inner.clone();
        let h_web_result = self.inner.clone();
        let h_web_close = self.inner.clone();
        let h_clipboard_audit = self.inner.clone();
        let h_session_open = self.inner.clone();
        let h_cfg_effective = self.inner.clone();
        let h_agent_ssh_exec = self.inner.clone();
        let h_agent_web_fetch = self.inner.clone();
        let h_sql_privileges = self.inner.clone();

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
                    // The type configuration this mount is governed by: its
                    // own, or the root namespace's when a child namespace
                    // saved none (`type_config`).
                    pattern: r"v2/config/types/effective$",
                    operations: [
                        {op: Operation::Read, handler: h_cfg_effective.handle_config_types_effective}
                    ],
                    help: "Read the effective resource type definitions and where they come from (mount, root, none)."
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
                    // Paginated metadata search. POST body fields:
                    // q, type, offset, limit (all optional).
                    pattern: "resources/search$",
                    operations: [
                        {op: Operation::Write, handler: h_res_search.handle_resource_search}
                    ],
                    help: "Search and paginate resource metadata."
                },
                {
                    // Change history for a single resource (timeline of who/when/what fields)
                    pattern: r"resources/(?P<name>[^/]+)/history/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_res_hist.handle_resource_history}
                    ],
                    help: "Read the change history for a resource."
                },
                {
                    // Rename a resource: move its identity (and all
                    // associated data) to `new_name`. Write-only.
                    pattern: r"resources/(?P<name>[^/]+)/rename$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Current resource name."
                        },
                        "new_name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "New resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_res_rename.handle_resource_rename}
                    ],
                    help: "Rename a resource, migrating metadata, history, secrets, \
                           shares, group membership, and ownership to the new name."
                },
                {
                    // Cross-namespace transfer, destination side
                    // (features/cross-namespace-copy-move.md): write a
                    // resource bundle under `name`. Called by the transfer
                    // orchestrator with the caller's token; see
                    // `handle_resource_import` for what one ACL check covers.
                    pattern: r"v2/transfer/import/(?P<name>[^/]+)$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Destination resource name."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_res_import.handle_resource_import}
                    ],
                    help: "Import a resource bundle (metadata, every secret with all its versions, change history) \
                           under a name, keeping version numbers and timestamps. Body: meta, secrets, history, \
                           on_conflict (refuse|rename), origin, origin_owner. Authorized as a write of \
                           resources/<name>; the caller becomes the owner of the resource written. Shares are \
                           not written."
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
                    // History of a single resource secret (all versions with user/ts).
                    pattern: r"secrets/(?P<resource>[^/]+)/(?P<key>[^/]+)/history/?$",
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
                        {op: Operation::Read, handler: h_sec_hist.handle_secret_history}
                    ],
                    help: "Read the version list (history) of a resource secret."
                },
                {
                    // Read a specific historical version of a resource secret.
                    pattern: r"secrets/(?P<resource>[^/]+)/(?P<key>[^/]+)/version/(?P<version>\d+)$",
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
                        },
                        "version": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Version number."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_sec_ver.handle_secret_version_read}
                    ],
                    help: "Read a specific version of a resource secret."
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
                },
                {
                    // Connect-time MFA gate — step 1. Reports whether the
                    // named profile is gated and which factors the caller
                    // can satisfy it with. See
                    // features/connect-mfa-and-fido2-ssh.md.
                    pattern: r"v2/connect/mfa/begin$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id."
                        },
                        "action": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "SQL browser step-up (features/sql-browser.md §8.3): the sql_* \
                                          capabilities, comma-separated or a list, whose use the ticket is \
                                          for. Each must be in the `sql` profile's `step_up`."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_mfa_begin.handle_connect_mfa_begin}
                    ],
                    help: "Begin connect-time MFA re-validation for a connection profile."
                },
                {
                    // Connect-time MFA gate — step 2. Verifies one factor and
                    // mints the single-use connect ticket.
                    pattern: r"v2/connect/mfa/verify$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id."
                        },
                        "method": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Factor to verify: `totp` or `fido2`."
                        },
                        "totp_code": {
                            field_type: FieldType::SecretStr,
                            required: false,
                            description: "Current TOTP code. Required when method = totp."
                        },
                        "credential": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "JSON-encoded FIDO2 assertion. Required when method = fido2."
                        },
                        "mcp_call": {
                            field_type: FieldType::Map,
                            required: false,
                            description: "MCP gatekeeper only: {pairing_id, tool, args_hash} of the one \
                                          agent call this ticket is for (60 s, agent route only)."
                        },
                        "action": {
                            field_type: FieldType::CommaStringSlice,
                            required: false,
                            description: "SQL browser step-up (features/sql-browser.md §8.3): mint a ticket \
                                          bound to these sql_* capabilities, redeemable only for exactly \
                                          that action. Each must be in the `sql` profile's `step_up`."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_mfa_verify.handle_connect_mfa_verify}
                    ],
                    help: "Verify a second factor and mint a single-use connect ticket."
                },
                {
                    // Direct-path pre-flight: consume the ticket (when the
                    // profile is gated) and authorize the session open.
                    pattern: r"v2/connect/authorize$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id."
                        },
                        "connect_ticket": {
                            field_type: FieldType::SecretStr,
                            required: false,
                            description: "Ticket from connect/mfa/verify. Required for gated profiles."
                        },
                        "provider_account_id": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Account picked from connect/provider/candidates. Required for a \
                                          `provider` profile, refused for any other."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_authorize.handle_connect_authorize}
                    ],
                    help: "Authorize a direct-path session open, consuming the connect \
                           MFA ticket when the profile requires re-validation. For a `provider` \
                           profile, also release the picked account's credential."
                },
                {
                    // Credential providers (features/self-accounts.md §6):
                    // the caller's accounts that match this profile, as
                    // metadata only. Type, OS and target come from the stored
                    // record; the body names only the resource and profile.
                    pattern: r"v2/connect/provider/candidates$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id of a `provider` profile."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_provider_candidates.handle_connect_provider_candidates}
                    ],
                    help: "List the caller's credential-provider accounts that match a profile \
                           (metadata only), with the target they would be released for."
                },
                {
                    // The granted, active credential providers, for the
                    // connection-profile editor's source list
                    // (features/self-accounts.md §6, Phase 4). Names and the
                    // declared protocols / secret kinds only; no account data.
                    pattern: r"v2/connect/providers$",
                    operations: [
                        {op: Operation::Read, handler: h_providers.handle_connect_providers}
                    ],
                    help: "List the credential providers a connection profile can name: approved, \
                           active plugins with their display name, protocols and secret kinds."
                },
                {
                    // Web Application Connect, `form` mode: authorise, enforce
                    // the exposure policy and release the credential the
                    // recipe fills. See connect_web/mod.rs and
                    // features/web-application-connect.md §3.
                    pattern: r"v2/connect/web/launch$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id of a `web` / `form` profile."
                        },
                        "recipe_hash": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "`sha256:<hex>` of the canonical recipe the host loaded."
                        },
                        "connect_ticket": {
                            field_type: FieldType::SecretStr,
                            required: false,
                            description: "Ticket from connect/mfa/verify. Required for gated profiles."
                        },
                        "provider_account_id": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Account picked from connect/provider/candidates. Required for a \
                                          `provider` profile."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_web_launch.handle_connect_web_launch}
                    ],
                    help: "Launch a form-mode web session: returns a short-lived launch bundle \
                           with the credential the profile's recipe fills."
                },
                {
                    pattern: r"v2/connect/web/totp$",
                    fields: {
                        "launch_id": {
                            field_type: FieldType::SecretStr,
                            required: true,
                            description: "launch_id from connect/web/launch."
                        },
                        "step": {
                            field_type: FieldType::Int,
                            required: true,
                            description: "Index of the recipe step that fills `totp`."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_web_totp.handle_connect_web_totp}
                    ],
                    help: "Issue one fresh TOTP code for a recipe step of an in-flight launch."
                },
                {
                    pattern: r"v2/connect/web/result$",
                    fields: {
                        "launch_id": {
                            field_type: FieldType::SecretStr,
                            required: true,
                            description: "launch_id from connect/web/launch."
                        },
                        "outcome": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "success | failure | timeout | aborted:<check>."
                        },
                        "step": {
                            field_type: FieldType::Int,
                            required: false,
                            description: "Index of the last recipe step reached."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_web_result.handle_connect_web_result}
                    ],
                    help: "Record a web launch's recipe outcome (once)."
                },
                {
                    pattern: r"v2/connect/web/close$",
                    fields: {
                        "launch_id": {
                            field_type: FieldType::SecretStr,
                            required: true,
                            description: "launch_id from connect/web/launch."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_web_close.handle_connect_web_close}
                    ],
                    help: "Record a web session's end and check an LDAP library account back in. \
                           Idempotent."
                },
                {
                    // RDP clipboard redirection, vault-side audit row (T35
                    // Phase 4). Metadata only — see connect_clipboard.rs for
                    // why the shape has no slot for content or file names.
                    pattern: r"v2/connect/clipboard/audit$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the RDP profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id of the RDP profile."
                        },
                        "session": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "The desktop host's session token ([A-Za-z0-9_-], at most 64)."
                        },
                        "seq": {
                            field_type: FieldType::Int,
                            required: true,
                            description: "Batch sequence number within the session, from 0."
                        },
                        "final": {
                            field_type: FieldType::Bool,
                            required: false,
                            description: "True on the session's closing batch, which may be empty."
                        },
                        "transfers": {
                            field_type: FieldType::Map,
                            required: false,
                            description: "<direction>.<kind>.<outcome> -> array of per-transfer byte counts."
                        },
                        "overflow": {
                            field_type: FieldType::Map,
                            required: false,
                            description: "<direction>.<kind>.<outcome> -> {count, bytes} for rate-limited transfers."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_clipboard_audit.handle_connect_clipboard_audit}
                    ],
                    help: "Record a batch of RDP clipboard transfers (direction, kind, outcome, byte \
                           counts) for the audit trail. Never content or file names."
                },
                {
                    // Session open, recorded before the host dials the target
                    // so a failed audit write stops the connection. Metadata
                    // only: protocol, transport, host, port.
                    pattern: r"v2/connect/session/open$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id."
                        },
                        "protocol": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "One of ssh, rdp, sftp, web; must match the profile."
                        },
                        "transport": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "One of direct, rustion."
                        },
                        "host": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Target host the session dials."
                        },
                        "port": {
                            field_type: FieldType::Int,
                            required: true,
                            description: "Target port the session dials."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_session_open.handle_connect_session_open}
                    ],
                    help: "Record that a connection session is opening to a target, before the \
                           host dials it. Metadata only."
                },
                {
                    // MCP brokered sessions, SSH (features/mcp-brokered-sessions.md
                    // §5, §13). Answers only the MCP dispatcher: a request
                    // without `Request::mcp_dispatch` and an MCP binding is
                    // refused, so this is not a general remote-exec API. Not
                    // in the `default` policy: an administrator grants
                    // `update` on it. See agent_ssh/mod.rs.
                    pattern: r"v2/connect/agent/ssh/exec$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the SSH profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id of an SSH profile with agent_access = allow."
                        },
                        "command": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "The operator-confirmed command, run verbatim on one exec channel."
                        },
                        "timeout_secs": {
                            field_type: FieldType::Int,
                            required: false,
                            description: "Call budget in seconds, at most mcp.brokered_sessions.call_timeout_secs."
                        },
                        "connect_ticket": {
                            field_type: FieldType::SecretStr,
                            required: false,
                            description: "The operator's connect MFA ticket for this one call, relayed by the \
                                          gatekeeper. Required for an MFA-gated profile."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_agent_ssh_exec.handle_agent_ssh_exec}
                    ],
                    help: "Run one confirmed command on a resource over a vault-brokered SSH session \
                           (MCP bv_resource_ssh_exec only). Returns capped, credential-scrubbed, sanitized output."
                },
                {
                    // MCP brokered sessions, web (features/mcp-brokered-sessions.md
                    // §6, §13). Like the SSH route: answers only the MCP
                    // dispatcher, not in the `default` policy. See
                    // agent_web/mod.rs.
                    pattern: r"v2/connect/agent/web/fetch$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Resource name the web profile lives on."
                        },
                        "profile_id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Connection-profile id of a web profile with agent_access = allow."
                        },
                        "method": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "GET or HEAD."
                        },
                        "path": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "The operator-confirmed origin-relative path with its query."
                        },
                        "timeout_secs": {
                            field_type: FieldType::Int,
                            required: false,
                            description: "Call budget in seconds, at most mcp.brokered_sessions.call_timeout_secs."
                        },
                        "connect_ticket": {
                            field_type: FieldType::SecretStr,
                            required: false,
                            description: "The operator's connect MFA ticket for this one call, relayed by the \
                                          gatekeeper. Required for an MFA-gated profile."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_agent_web_fetch.handle_agent_web_fetch}
                    ],
                    help: "Fetch one page of a web resource with GET or HEAD over a vault-brokered HTTPS session \
                           (MCP bv_resource_web_fetch only). Returns status, content type and capped, \
                           credential-scrubbed, sanitized page text; never a cookie, header or session URL."
                },
                {
                    // The SQL browser's privilege chips (features/sql-browser.md
                    // §3.4, §9.5): the caller's own effective SQL capabilities.
                    // A display read; see sql_resource.rs.
                    pattern: r"v2/sql/privileges/(?P<resource>[^/]+)$",
                    fields: {
                        "resource": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Database resource name."
                        },
                        "objects": {
                            field_type: FieldType::Str,
                            required: false,
                            description: "Comma-separated catalog/schema/object triples (segments may be \
                                          percent-encoded) to report per object, at most 64."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_sql_privileges.handle_sql_privileges}
                    ],
                    help: "Read the caller's effective SQL capabilities on a database resource: on sql/server, \
                           resource-wide, and per named object. Display only; nothing is enforced from it."
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

// ── Helpers ────────────────────────────────────────────────────────

/// An agent opt-in refusal as a response error: the stable code first, so a
/// client (and the profile editor) can match on it.
fn agent_refusal_error(refusal: agent_access::AgentAccessRefusal) -> RvError {
    bv_error_response_status!(refusal.status(), &format!("{}: {}", refusal.code(), refusal))
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch, used
/// as the suffix of history log keys so `storage_list()` returns entries
/// in chronological order.
fn hist_seq() -> String {
    format!("{:020}", now_nanos())
}

fn now_nanos() -> u128 {
    let n = Utc::now().timestamp_nanos_opt().unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    n.max(0) as u128
}

/// A resource name or a resource-secret key is a storage key segment *and*
/// an ACL path segment: refuse anything that could escape the key space or
/// collide with a sub-path. Returns the message; the caller picks the error.
fn validate_name_segment(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} is required"));
    }
    if value.contains('/') || value.contains("..") {
        return Err(format!("{field} must not contain '/' or '..'"));
    }
    Ok(())
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

/// Return the sorted, deduped list of top-level field names that changed
/// between `old` and `new`, ignoring timestamp/identity fields.
fn diff_field_names(old: Option<&Map<String, Value>>, new: &Map<String, Value>) -> Vec<String> {
    let empty = Map::new();
    let old = old.unwrap_or(&empty);
    let mut changed: Vec<String> = Vec::new();

    for (k, v) in new {
        if HIST_IGNORED_FIELDS.contains(&k.as_str()) {
            continue;
        }
        match old.get(k) {
            Some(ov) if ov == v => { /* unchanged */ }
            _ => changed.push(k.clone()),
        }
    }
    for k in old.keys() {
        if HIST_IGNORED_FIELDS.contains(&k.as_str()) {
            continue;
        }
        if !new.contains_key(k) {
            changed.push(k.clone());
        }
    }
    changed.sort();
    changed.dedup();
    changed
}

/// Resolve a resource name from the request URL into the actual storage
/// key in use. New resources are written under their lowercase form; for
/// new writes this is the canonical name. Legacy data, however, was
/// written with mixed case (the resource module preserved case while the
/// resource-group store always lowercased its member references), so a
/// lowercase probe alone would 404 on every PMP-imported resource.
///
/// Lookup order:
///   1. Exact lowercase `meta/<lower>` — the canonical form going forward.
///   2. Exact as-supplied `meta/<raw>` — covers a caller that already
///      passes the legacy mixed-case form.
///   3. Case-insensitive scan of `meta/` — resolves legacy mixed-case
///      keys when the caller passes lowercase (the common path from
///      asset-group filtering, since group members are stored lowercase).
///
/// If nothing matches, returns the lowercase form so a fresh write lands
/// at the canonical key — i.e., new resources are always lowercase, and
/// any existing CI-equal record is updated in place rather than
/// duplicated.
pub(crate) async fn resolve_resource_name(req: &mut Request, raw: &str) -> Result<String, RvError> {
    let storage = req.storage.clone().ok_or(RvError::ErrRequestNotReady)?;
    resolve_resource_name_in(storage.as_ref(), raw).await
}

/// [`resolve_resource_name`] over the mount's storage view itself, for a
/// reader that holds the view rather than a request routed to the mount.
#[maybe_async::maybe_async]
pub(crate) async fn resolve_resource_name_in(view: &dyn storage::Storage, raw: &str) -> Result<String, RvError> {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();

    if view.get(&format!("{META_PREFIX}{lower}")).await?.is_some() {
        return Ok(lower);
    }
    if trimmed != lower && view.get(&format!("{META_PREFIX}{trimmed}")).await?.is_some() {
        return Ok(trimmed.to_string());
    }
    for k in view.list(META_PREFIX).await? {
        if k.eq_ignore_ascii_case(trimmed) {
            return Ok(k);
        }
    }
    Ok(lower)
}

/// The storage name of the record `name` collides with, if any: the exact
/// key, or a differently-cased legacy one (the case-insensitive rule of
/// [`resolve_resource_name_in`]), so neither a rename nor an import can
/// silently clobber a record.
#[maybe_async::maybe_async]
async fn existing_resource_key_in(view: &dyn storage::Storage, name: &str) -> Result<Option<String>, RvError> {
    if view.get(&format!("{META_PREFIX}{name}")).await?.is_some() {
        return Ok(Some(name.to_string()));
    }
    Ok(view.list(META_PREFIX).await?.into_iter().find(|k| k.eq_ignore_ascii_case(name)))
}

// ── Transfer import ────────────────────────────────────────────────
//
// `v2/transfer/import/<name>`. The pieces below take the mount's storage view
// rather than a request so they are testable in-crate; the handler adds the
// write-time gates that need the vault (`check_import_write_gates`).

/// Upper bound on the `<name>-<n>` candidates `on_conflict = rename` tries.
const IMPORT_RENAME_MAX_SUFFIX: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportConflict {
    Refuse,
    Rename,
}

impl ImportConflict {
    /// An unknown mode is refused, never read as the default. `overwrite` is
    /// refused too: through this route it would skip the delete ACL and the
    /// owner, share and asset-group cleanup a real delete runs.
    fn parse(raw: &str) -> Result<Self, RvError> {
        match raw.trim() {
            "" | "refuse" => Ok(Self::Refuse),
            "rename" => Ok(Self::Rename),
            "overwrite" => Err(bad_import(
                "on_conflict must be refuse or rename; to overwrite, DELETE resources/resources/<name> first, \
                 then import",
            )),
            other => Err(bad_import(format!("on_conflict must be refuse or rename, not '{other}'"))),
        }
    }
}

fn bad_import(message: impl Into<String>) -> RvError {
    RvError::ErrResponseStatus(400, format!("invalid resource import: {}", message.into()))
}

fn import_conflict(message: impl Into<String>) -> RvError {
    RvError::ErrResponseStatus(409, message.into())
}

/// A validated import, ready to write.
struct ResourceImportPlan {
    /// The destination name: the requested one, lower-cased, or under
    /// `rename` the first free `<name>-<n>`.
    name: String,
    /// History keys (nanoseconds), one per `bundle.history` entry.
    history_seq: Vec<u128>,
    bundle: ResourceBundle,
}

/// Decode a request body into a [`ResourceBundle`]. serde's message quotes
/// the offending value on a type error (`invalid type: string "…"`), and in
/// a bundle that value can be secret material, so only a missing-field
/// message, which names a field and nothing else, is passed through.
fn parse_resource_bundle(body: &Map<String, Value>) -> Result<ResourceBundle, RvError> {
    serde_json::from_value(Value::Object(body.clone())).map_err(|e| {
        let message = e.to_string();
        if message.starts_with("missing field") {
            bad_import(message)
        } else {
            bad_import(
                "the body does not have the bundle's shape (meta: object; secrets: [{key, versions: \
                 [{version, created_time, deleted, data: object}], current}]; history: [{ts, user, op, \
                 changed_fields}]; on_conflict, origin, origin_owner: strings)",
            )
        }
    })
}

/// Everything about a bundle that can be checked without storage. Returns
/// the history keys: each entry is keyed by its own `ts`, bumped by a
/// nanosecond on a tie, so the entries sort in time whatever order they
/// arrive in.
fn validate_resource_bundle(bundle: &ResourceBundle) -> Result<Vec<u128>, RvError> {
    if bundle.origin.trim().is_empty() {
        return Err(bad_import("origin is required"));
    }
    let mut keys = HashSet::new();
    for (i, secret) in bundle.secrets.iter().enumerate() {
        validate_name_segment(&format!("secrets[{i}].key"), &secret.key).map_err(bad_import)?;
        if !keys.insert(secret.key.as_str()) {
            return Err(bad_import(format!("secrets[{i}].key repeats an earlier secret's key")));
        }
        let mut versions = BTreeSet::new();
        for (j, v) in secret.versions.iter().enumerate() {
            if v.version == 0 {
                return Err(bad_import(format!("secrets[{i}].versions[{j}].version must be 1 or greater")));
            }
            if v.deleted {
                return Err(bad_import(format!(
                    "secrets[{i}].versions[{j}] is marked deleted; a resource secret has no per-version delete"
                )));
            }
            if !versions.insert(v.version) {
                return Err(bad_import(format!("secrets[{i}].versions[{j}].version {} appears twice", v.version)));
            }
        }
        let Some(&latest) = versions.last() else {
            return Err(bad_import(format!("secrets[{i}] has no versions")));
        };
        if secret.current != latest {
            return Err(bad_import(format!("secrets[{i}].current must be the latest version, {latest}")));
        }
        // The live value passes the check `handle_secret_write` runs.
        if let Some(data) = secret.current_data() {
            sql_profile::validate_sql_endpoint_on_write(data).map_err(|m| bad_import(format!("secrets[{i}]: {m}")))?;
        }
    }

    let mut used = BTreeSet::new();
    let mut seq = Vec::with_capacity(bundle.history.len());
    for (i, entry) in bundle.history.iter().enumerate() {
        let nanos = chrono::DateTime::parse_from_rfc3339(&entry.ts)
            .ok()
            .and_then(|t| t.timestamp_nanos_opt())
            .ok_or_else(|| bad_import(format!("history[{i}].ts is not a representable RFC 3339 timestamp")))?;
        let mut key = nanos.max(0) as u128;
        while !used.insert(key) {
            key += 1;
        }
        seq.push(key);
    }
    Ok(seq)
}

/// The first secret version in `bundle`, live or not, that carries a static
/// SSH credential, as `(key, version)`. Every version counts: an old one is
/// readable at `secrets/<name>/<key>/version/<n>` once imported.
fn first_static_credential(bundle: &ResourceBundle) -> Option<(&str, u64)> {
    bundle.secrets.iter().find_map(|s| {
        s.versions.iter().find(|v| static_ssh_credential_shape(&v.data)).map(|v| (s.key.as_str(), v.version))
    })
}

/// True when secret data is stored under `name`, record or not. Without a
/// record it is what an interrupted import leaves behind (it writes `meta/`
/// last), or a secret written before its resource; an import never merges
/// into it.
#[maybe_async::maybe_async]
async fn has_secret_data_in(view: &dyn storage::Storage, name: &str) -> Result<bool, RvError> {
    for prefix in [SECRET_PREFIX, SMETA_PREFIX, SVER_PREFIX] {
        if !view.list(&format!("{prefix}{name}/")).await?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The first `<base>-<n>` (n from 2) with neither a record, in any case,
/// nor secret data under it.
#[maybe_async::maybe_async]
async fn free_resource_name_in(view: &dyn storage::Storage, base: &str) -> Result<String, RvError> {
    let taken: HashSet<String> = view.list(META_PREFIX).await?.into_iter().map(|k| k.to_ascii_lowercase()).collect();
    for n in 2..=IMPORT_RENAME_MAX_SUFFIX {
        let candidate = format!("{base}-{n}");
        if !taken.contains(&candidate) && !has_secret_data_in(view, &candidate).await? {
            return Ok(candidate);
        }
    }
    Err(import_conflict(format!("no free name for '{base}' up to '{base}-{IMPORT_RENAME_MAX_SUFFIX}'")))
}

/// Validate a bundle and settle the destination name. Writes nothing.
#[maybe_async::maybe_async]
async fn plan_resource_import(
    view: &dyn storage::Storage,
    raw_name: &str,
    bundle: ResourceBundle,
) -> Result<ResourceImportPlan, RvError> {
    let mode = ImportConflict::parse(&bundle.on_conflict)?;
    let requested = raw_name.trim().to_ascii_lowercase();
    validate_name_segment("name", &requested).map_err(bad_import)?;
    let history_seq = validate_resource_bundle(&bundle)?;

    let existing = existing_resource_key_in(view, &requested).await?;
    let leftovers = has_secret_data_in(view, &requested).await?;
    let name = match (mode, existing) {
        (_, None) if !leftovers => requested,
        (ImportConflict::Refuse, Some(key)) => {
            return Err(import_conflict(format!("a resource named '{key}' already exists")));
        }
        (ImportConflict::Refuse, None) => {
            return Err(import_conflict(format!(
                "secret data with no resource record is stored under '{requested}' (an interrupted \
                 operation?); import with on_conflict=rename to use another name"
            )));
        }
        (ImportConflict::Rename, _) => free_resource_name_in(view, &requested).await?,
    };
    Ok(ResourceImportPlan { name, history_seq, bundle })
}

/// Write a history entry at `seq`, or the next free key after it, and
/// return the key used. History is an audit trail: an existing entry is
/// never overwritten, and an identical one (the same origin entry imported
/// before) is left as it is.
#[maybe_async::maybe_async]
async fn put_history_entry(
    view: &dyn storage::Storage,
    name: &str,
    seq: u128,
    entry: &ResourceHistoryEntry,
) -> Result<u128, RvError> {
    let value = serde_json::to_vec(entry)?;
    let mut seq = seq;
    loop {
        let key = format!("{HIST_PREFIX}{name}/{seq:020}");
        match view.get(&key).await? {
            None => {
                view.put(&StorageEntry { key, value }).await?;
                return Ok(seq);
            }
            Some(existing) if existing.value == value => return Ok(seq),
            Some(_) => seq += 1,
        }
    }
}

/// `put` a value that carries secret material, then scrub this process's
/// copy of the serialised bytes.
#[maybe_async::maybe_async]
async fn put_scrubbed(view: &dyn storage::Storage, key: String, value: Vec<u8>) -> Result<(), RvError> {
    let mut entry = StorageEntry { key, value };
    let result = view.put(&entry).await;
    entry.value.zeroize();
    result
}

/// Write a planned import: every secret with all its versions, then the
/// origin's history and a `transfer-in` entry, and `meta/` last. An import
/// that fails partway therefore leaves no record (a listing never shows a
/// half-written resource), and a retry sees the leftover secret data as a
/// collision rather than merging into it.
#[maybe_async::maybe_async]
async fn apply_resource_import(
    view: &dyn storage::Storage,
    plan: ResourceImportPlan,
    user: &str,
) -> Result<ResourceImportSummary, RvError> {
    let ResourceImportPlan { name, history_seq, bundle } = plan;
    let ResourceBundle { mut meta, secrets, history, origin, origin_owner, .. } = bundle;

    let mut last_seq = 0;
    let secret_count = secrets.len();
    let mut version_count = 0;
    for secret in secrets {
        let mut index = ResourceSecretMeta { current_version: secret.current, versions: HashMap::new() };
        let mut current = None;
        for v in secret.versions {
            index.versions.insert(
                v.version.to_string(),
                ResourceSecretVersionMeta {
                    created_time: v.created_time.clone(),
                    username: v.username.clone(),
                    operation: v.operation.clone(),
                },
            );
            let payload = ResourceSecretVersion {
                data: v.data,
                version: v.version,
                created_time: v.created_time,
                username: v.username,
                operation: v.operation,
            };
            if payload.version == secret.current {
                current = Some(serde_json::to_vec(&payload.data)?);
            }
            let key = format!("{SVER_PREFIX}{name}/{}/{}", secret.key, payload.version);
            put_scrubbed(view, key, serde_json::to_vec(&payload)?).await?;
            version_count += 1;
        }
        let smeta =
            StorageEntry { key: format!("{SMETA_PREFIX}{name}/{}", secret.key), value: serde_json::to_vec(&index)? };
        view.put(&smeta).await?;
        // `validate_resource_bundle` made `current` one of the versions.
        let current = current.ok_or_else(|| bad_import(format!("secret '{}' has no current version", secret.key)))?;
        put_scrubbed(view, format!("{SECRET_PREFIX}{name}/{}", secret.key), current).await?;
    }

    for (seq, entry) in history_seq.iter().zip(&history) {
        last_seq = last_seq.max(put_history_entry(view, &name, *seq, entry).await?);
    }
    let changed_fields = vec![format!("origin: {origin}"), format!("origin_owner: {origin_owner}")];
    let arrival = ResourceHistoryEntry {
        ts: now_rfc3339(),
        user: user.to_string(),
        op: "transfer-in".to_string(),
        changed_fields,
    };
    put_history_entry(view, &name, (last_seq + 1).max(now_nanos()), &arrival).await?;

    meta.insert("name".to_string(), Value::String(name.clone()));
    view.put(&StorageEntry { key: format!("{META_PREFIX}{name}"), value: serde_json::to_vec(&meta)? }).await?;

    Ok(ResourceImportSummary { name, secrets: secret_count, versions: version_count, history: history.len() })
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

    /// `GET resources/v2/config/types/effective`. `source` is `mount`,
    /// `root` (a child namespace inheriting the root namespace's saved
    /// configuration) or `none`; `types` is the raw saved object, or null.
    /// The root configuration is type metadata (labels, fields, connect
    /// policy), and when inherited it *is* this namespace's policy.
    pub async fn handle_config_types_effective(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = type_config::effective_type_config(self.core.as_ref(), req).await.map_err(|e| match e {
            type_config::TypeConfigError::Storage(e) => e,
            type_config::TypeConfigError::Malformed(source) => bv_error_response_status!(
                422,
                &format!("the {} resource type configuration is not a JSON object", source.as_str())
            ),
        })?;
        let mut data = Map::new();
        data.insert("source".into(), Value::String(config.source.as_str().into()));
        data.insert("types".into(), config.types.map(Value::Object).unwrap_or(Value::Null));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_config_types_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?;
        // `connect.agent_sessions_max` is the type tier of the MCP
        // brokered-session opt-in; a typo there must be refused, not stored
        // and read as `deny` later.
        agent_access::validate_type_config(body).map_err(agent_refusal_error)?;
        let data = serde_json::to_string(body)?;
        let entry = StorageEntry { key: "config/types".to_string(), value: data.into_bytes() };
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

    /// Paginated search over resource metadata.
    ///
    /// Request body fields (all optional):
    ///   - `q`      — substring matched (case-insensitive) against
    ///                `name`, `hostname`, `ip_address`, and `tags`.
    ///   - `type`   — exact match against the `type` metadata field.
    ///   - `offset` — 0-based start of the page (default 0).
    ///   - `limit`  — page size, clamped to `[1, 200]` (default 30).
    ///
    /// Response:
    ///   ```json
    ///   {
    ///     "items":   [{ "name", "type", "hostname", "ip_address", "tags",
    ///                   "connect_profiles" }, …],
    ///     "total":    <u64>,
    ///     "has_more": <bool>
    ///   }
    ///   ```
    ///
    /// Implementation walks `META_PREFIX` once per call and reads each
    /// metadata blob (we don't yet maintain a search index — at the
    /// volumes this is built for, the cost is dominated by storage
    /// read latency, which Hiqlite/embedded SQLite serves in single-
    /// digit microseconds per row). If profiling later shows search
    /// latency dominating, add an `RwLock<Option<Arc<Index>>>` on
    /// `ResourceBackendInner` populated lazily and invalidated by
    /// `handle_resource_write` / `handle_resource_delete`.
    pub async fn handle_resource_search(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let body = req.body.clone().unwrap_or_default();
        let q = body.get("q").and_then(|v| v.as_str()).map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty());
        let type_filter = body.get("type").and_then(|v| v.as_str()).map(|s| s.to_string()).filter(|s| !s.is_empty());
        let offset = body.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let limit = body.get("limit").and_then(|v| v.as_u64()).unwrap_or(30).clamp(1, 200) as usize;

        let keys = req.storage_list(META_PREFIX).await?;

        // Scan every metadata blob so we honour the full match surface
        // (name, hostname, ip_address, tags). An earlier revision had
        // a name-only fast path that skipped reads when only `q` was
        // set, but that silently dropped tag-only matches — exactly
        // the case a tag-organised vault relies on. If query latency
        // becomes a bottleneck past ~5k resources, add a lazy
        // `RwLock<Option<Arc<SearchIndex>>>` on `ResourceBackendInner`,
        // populated on first search and invalidated by
        // `handle_resource_write` / `handle_resource_delete`. The
        // embedded SQLite/file backends serve 5k reads well under
        // 100ms today.
        let mut matches: Vec<(String, ResourceCardEntry)> = Vec::new();
        for key in &keys {
            let storage_key = format!("{META_PREFIX}{key}");
            let entry = match req.storage_get(&storage_key).await? {
                Some(e) => e,
                None => continue,
            };
            let data: Map<String, Value> = match serde_json::from_slice(&entry.value) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(t) = &type_filter {
                if data.get("type").and_then(|v| v.as_str()) != Some(t.as_str()) {
                    continue;
                }
            }
            if let Some(needle) = &q {
                let name_lc = key.to_ascii_lowercase();
                let host_lc =
                    data.get("hostname").and_then(|v| v.as_str()).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
                let ip_lc =
                    data.get("ip_address").and_then(|v| v.as_str()).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
                let tags_lc =
                    data.get("tags").and_then(|v| v.as_str()).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
                if !name_lc.contains(needle)
                    && !host_lc.contains(needle)
                    && !ip_lc.contains(needle)
                    && !tags_lc.contains(needle)
                {
                    continue;
                }
            }
            matches.push((key.clone(), ResourceCardEntry::from_metadata(key, &data)));
        }

        // Stable sort by name so paging is deterministic across calls.
        matches.sort_by(|a, b| a.0.cmp(&b.0));

        // Per-object visibility filter. `post_auth` authorized the *endpoint*
        // path (`resources/resources/search`), not the resources in the
        // response — so without this pass, anyone who may search learns every
        // resource's name, hostname, IP, tags and connection-profile shape,
        // including resources they cannot read. `readable_targets` re-runs the
        // real evaluator against each candidate's own
        // `resources/resources/<name>` path, honouring ungated grants,
        // `groups = [...]`, `scopes = ["owner", "shared"]` and root exactly as
        // a direct read would.
        //
        // Applied after the `q` / `type` match so the cost is bounded by the
        // candidate set rather than the whole vault, and before `total` so the
        // count and `has_more` describe what the caller can actually see.
        //
        // `req.auth == None` is the in-process server-authority path (a module
        // dispatching through the router on the server's own behalf, not a
        // caller's — the same convention the credential resolvers rely on);
        // those are left unfiltered. Every token-bearing request is filtered.
        //
        // Cost: up to three extra reads per candidate (owner, shares, asset
        // groups), on top of the one metadata read the scan already does —
        // for every caller whose ACL has a gated or scoped rule, admins
        // included, because a gated or scoped deny can revoke an ungated
        // grant (T119). An ACL with no such rule adds no reads. If that shows
        // up in profiling before the search index this comment block has long
        // promised, the shape to build is the inverse query — enumerate what
        // the caller owns and what is shared with them from the owner/share
        // indexes, then intersect — rather than
        // probing every candidate.
        if req.auth.is_some() {
            // ACLs are evaluated against the *full* request path, but a backend
            // handler receives the mount-relative one (`resources/search`, not
            // `resources/resources/search`), so rebuild the mount prefix here.
            // In a child namespace the policy — and the rewritten path the
            // pipeline would evaluate for a direct read — carries the `<ns>/`
            // prefix, so it goes back on too; probing the bare path would
            // consult the root namespace's same-named resource.
            let ns_prefix = match req.namespace_path.as_deref() {
                Some(ns) if !ns.trim().trim_matches('/').is_empty() => {
                    format!("{}/", ns.trim().trim_matches('/'))
                }
                _ => String::new(),
            };
            let base = format!("{ns_prefix}{RESOURCE_METADATA_PATH_PREFIX}");
            let targets: Vec<String> = matches.iter().map(|(name, _)| format!("{base}{name}")).collect();
            let policy = self.core.policy().ok_or_else(|| bv_error_string!("policy module not registered"))?;
            let visible = policy.readable_targets(req, &targets).await;
            let mut kept = Vec::with_capacity(matches.len());
            for (entry, ok) in matches.into_iter().zip(visible) {
                if ok {
                    kept.push(entry);
                }
            }
            matches = kept;
        }

        let total = matches.len();
        let page_end = (offset + limit).min(total);
        let items: Vec<Value> = if offset >= total {
            Vec::new()
        } else {
            matches[offset..page_end]
                .iter()
                .map(|(_, card)| serde_json::to_value(card).unwrap_or(Value::Null))
                .collect()
        };

        let mut resp = Map::new();
        resp.insert("items".into(), Value::Array(items));
        resp.insert("total".into(), Value::Number((total as u64).into()));
        resp.insert("has_more".into(), Value::Bool(page_end < total));
        Ok(Some(Response::data_response(Some(resp))))
    }

    pub async fn handle_resource_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        let name = resolve_resource_name(req, &raw).await?;
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
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        // Resolve to either the existing storage key (any case) or the
        // canonical lowercase form for a fresh write. This collapses
        // would-be duplicates from PMP-style imports that send mixed
        // case after we've already standardized on lowercase.
        let name = resolve_resource_name(req, &raw).await?;
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?.clone();
        let key = format!("{META_PREFIX}{name}");

        // Load previous value (if any) so we can compute the field diff
        // before overwriting.
        let previous: Option<Map<String, Value>> = match req.storage_get(&key).await? {
            Some(e) => serde_json::from_slice(&e.value).ok(),
            None => None,
        };
        let mut op = if previous.is_some() { "update" } else { "create" };
        let mut changed_fields = diff_field_names(previous.as_ref(), &body);

        // MCP brokered sessions (`features/mcp-brokered-sessions.md` §12): a
        // profile that turns `agent_access` on needs the type's consent and
        // its protocol's static requirements. Only new or changed profiles
        // are vetted, and the type configuration is read only when one turns
        // it on, so an ordinary write costs nothing extra.
        if agent_access::write_needs_type_check(previous.as_ref(), &body) {
            let type_id = body.get("type").and_then(Value::as_str).unwrap_or_default();
            let types = type_config::effective_type_config(self.core.as_ref(), req).await.map_err(|e| match e {
                type_config::TypeConfigError::Storage(e) => e,
                type_config::TypeConfigError::Malformed(source) => bv_error_response_status!(
                    422,
                    &format!("the {} resource type configuration is not a JSON object", source.as_str())
                ),
            })?;
            agent_access::validate_profiles_on_write(previous.as_ref(), &body, types.type_def(type_id))
                .map_err(agent_refusal_error)?;
        }

        // A write whose only diff is `recent_sessions` came from the
        // GUI's session-recorder (`record_recent_session` in
        // `commands/connect.rs`). That isn't a metadata edit — it's the
        // operator opening a session — so we relabel it as a "connect"
        // event with no field pill, and surface it on the security log
        // so an operator tailing security.log sees connection activity
        // without having to cross-reference operations.log.
        let is_connect = op == "update" && changed_fields.len() == 1 && changed_fields[0] == "recent_sessions";
        if is_connect {
            op = "connect";
            changed_fields.clear();
            log::info!(
                target: "security",
                "resource-connect: user={} resource={}",
                caller_username(req),
                name
            );
        }

        // Only append a history entry if something actually changed -- the
        // GUI saves on every Save button click which may be a no-op.
        // (Always record the initial create, though, even if `body` is empty.)
        let record_history = op == "create" || op == "connect" || !changed_fields.is_empty();

        // Write the new metadata.
        let data = serde_json::to_string(&body)?;
        let entry = StorageEntry { key, value: data.into_bytes() };
        req.storage_put(&entry).await?;

        if record_history {
            let hist = ResourceHistoryEntry {
                ts: now_rfc3339(),
                user: caller_username(req),
                op: op.to_string(),
                changed_fields,
            };
            let hist_key = format!("{HIST_PREFIX}{name}/{}", hist_seq());
            let hist_entry = StorageEntry { key: hist_key, value: serde_json::to_string(&hist)?.into_bytes() };
            req.storage_put(&hist_entry).await?;
        }

        Ok(None)
    }

    pub async fn handle_resource_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        let name = resolve_resource_name(req, &raw).await?;

        // Record the delete in the history log *before* wiping it. The
        // entry stays available for audit even after the resource is gone
        // (until the caller also purges the hist/ prefix).
        let hist = ResourceHistoryEntry {
            ts: now_rfc3339(),
            user: caller_username(req),
            op: "delete".to_string(),
            changed_fields: Vec::new(),
        };
        let hist_key = format!("{HIST_PREFIX}{name}/{}", hist_seq());
        let hist_entry = StorageEntry { key: hist_key, value: serde_json::to_string(&hist)?.into_bytes() };
        req.storage_put(&hist_entry).await?;

        // Delete the resource metadata.
        let meta_key = format!("{META_PREFIX}{name}");
        req.storage_delete(&meta_key).await?;

        // Prune the resource from every resource-group it is a member of.
        // Resource-groups are an optional subsystem — if the module isn't
        // loaded or the store isn't initialized yet, skip the prune.
        // Failures are logged but do not block resource deletion: a stale
        // group member will be cleaned up on the next group write or by
        // the `resource-group/reindex` endpoint.
        if let Some(groups) = self.core.resource_groups() {
            if let Err(e) = groups.prune_resource(&name, req.namespace_path.as_deref()).await {
                log::warn!(
                    "resource-group prune failed for deleted resource '{name}': {e}. \
                     Use the resource-group/reindex endpoint to clean up.",
                );
            }
        }

        // Delete all current-value secrets under this resource.
        let secret_prefix = format!("{SECRET_PREFIX}{name}/");
        for k in req.storage_list(&secret_prefix).await? {
            req.storage_delete(&format!("{secret_prefix}{k}")).await?;
        }

        // Delete all secret version metadata + version payloads.
        let smeta_prefix = format!("{SMETA_PREFIX}{name}/");
        for k in req.storage_list(&smeta_prefix).await? {
            req.storage_delete(&format!("{smeta_prefix}{k}")).await?;
        }
        let sver_prefix = format!("{SVER_PREFIX}{name}/");
        // The sver/ tree is two levels deep: <resource>/<key>/<version>.
        // storage_list returns the next-level children; recurse one step.
        for k in req.storage_list(&sver_prefix).await? {
            let sub = format!("{sver_prefix}{k}");
            // k typically ends with "/" because there is a further level.
            // Strip any trailing slash and iterate its children.
            let sub_prefix = if sub.ends_with('/') { sub.clone() } else { format!("{sub}/") };
            for v in req.storage_list(&sub_prefix).await? {
                req.storage_delete(&format!("{sub_prefix}{v}")).await?;
            }
            // Some backends may also return a leaf without a trailing slash;
            // delete that too (no-op if already gone).
            let _ = req.storage_delete(&sub).await;
        }

        Ok(None)
    }

    /// Rename a resource, moving its identity and every piece of data
    /// keyed by name to `new_name`. This is a multi-step migration across
    /// several storage domains — there is no cross-backend transaction, so
    /// the order is deliberately **write-new-then-delete-old**: a failure
    /// partway through leaves a recoverable duplicate under the old name,
    /// never a half-deleted resource.
    ///
    /// Migrated in this handler:
    ///   - `meta/<name>` (this mount's view)
    ///   - `secret/`, `smeta/`, `sver/` (this mount's view)
    ///   - `hist/<name>/*` (copied forward; a `rename` entry is appended)
    ///   - asset-group membership + reverse index (resource-group store)
    ///   - explicit share grants (identity share store)
    ///   - ownership record (identity owner store)
    ///
    /// File resources (`FileEntry.resource`) live in a separate mount and
    /// are re-pointed by the caller via the files engine's
    /// `files/repoint-resource` endpoint — they are NOT touched here.
    ///
    /// Policy documents that reference the old ACL path are intentionally
    /// left untouched (they may use globs/templates that cannot be safely
    /// rewritten); the operator is warned in the GUI to update them.
    pub async fn handle_resource_rename(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw_old = req.get_data("name")?.as_str().unwrap_or("").to_string();
        let old = resolve_resource_name(req, &raw_old).await?;

        // Validate the target name. Names are the storage key *and* the
        // ACL path segment, so reject anything that could escape the key
        // space or collide with a sub-path.
        let raw_new = req.get_data("new_name")?.as_str().unwrap_or("").trim().to_string();
        let new = raw_new.to_ascii_lowercase();
        validate_name_segment("new_name", &new).map_err(|m| bv_error_string!(m))?;
        if new == old {
            return Err(bv_error_string!("new_name is the same as the current name"));
        }

        // Source must exist.
        let old_meta_key = format!("{META_PREFIX}{old}");
        let Some(old_entry) = req.storage_get(&old_meta_key).await? else {
            return Err(bv_error_string!("resource not found"));
        };

        // Target must be free. Check the canonical key and a
        // case-insensitive scan (mirrors `resolve_resource_name`) so a
        // rename can never silently clobber a differently-cased record.
        let new_meta_key = format!("{META_PREFIX}{new}");
        let storage = req.storage.clone().ok_or(RvError::ErrRequestNotReady)?;
        if existing_resource_key_in(storage.as_ref(), &new).await?.is_some() {
            return Err(bv_error_string!(format!("a resource named '{new}' already exists")));
        }

        // ── 1. Metadata: write the new record (name + updated_at) ──────
        let mut meta: Map<String, Value> = serde_json::from_slice(&old_entry.value).unwrap_or_default();
        meta.insert("name".to_string(), Value::String(new.clone()));
        meta.insert("updated_at".to_string(), Value::String(now_rfc3339()));
        req.storage_put(&StorageEntry { key: new_meta_key, value: serde_json::to_vec(&meta)? }).await?;

        // ── 2. Secrets: current values, version index, version payloads ─
        // Copy every key from the old prefix to the new, then delete the
        // old copies. Mirrors the enumeration in `handle_resource_delete`.
        let old_secret_prefix = format!("{SECRET_PREFIX}{old}/");
        let new_secret_prefix = format!("{SECRET_PREFIX}{new}/");
        for k in req.storage_list(&old_secret_prefix).await? {
            if let Some(e) = req.storage_get(&format!("{old_secret_prefix}{k}")).await? {
                req.storage_put(&StorageEntry { key: format!("{new_secret_prefix}{k}"), value: e.value }).await?;
            }
        }

        let old_smeta_prefix = format!("{SMETA_PREFIX}{old}/");
        let new_smeta_prefix = format!("{SMETA_PREFIX}{new}/");
        for k in req.storage_list(&old_smeta_prefix).await? {
            if let Some(e) = req.storage_get(&format!("{old_smeta_prefix}{k}")).await? {
                req.storage_put(&StorageEntry { key: format!("{new_smeta_prefix}{k}"), value: e.value }).await?;
            }
        }

        // The sver/ tree is two levels deep: <resource>/<key>/<version>.
        let old_sver_prefix = format!("{SVER_PREFIX}{old}/");
        let new_sver_prefix = format!("{SVER_PREFIX}{new}/");
        for k in req.storage_list(&old_sver_prefix).await? {
            let key_seg = k.trim_end_matches('/');
            let old_sub = format!("{old_sver_prefix}{key_seg}/");
            let new_sub = format!("{new_sver_prefix}{key_seg}/");
            for v in req.storage_list(&old_sub).await? {
                if let Some(e) = req.storage_get(&format!("{old_sub}{v}")).await? {
                    req.storage_put(&StorageEntry { key: format!("{new_sub}{v}"), value: e.value }).await?;
                }
            }
        }

        // ── 3. History: carry the timeline forward, then log the rename ─
        let old_hist_prefix = format!("{HIST_PREFIX}{old}/");
        let new_hist_prefix = format!("{HIST_PREFIX}{new}/");
        for k in req.storage_list(&old_hist_prefix).await? {
            if let Some(e) = req.storage_get(&format!("{old_hist_prefix}{k}")).await? {
                req.storage_put(&StorageEntry { key: format!("{new_hist_prefix}{k}"), value: e.value }).await?;
            }
        }
        let hist = ResourceHistoryEntry {
            ts: now_rfc3339(),
            user: caller_username(req),
            op: "rename".to_string(),
            changed_fields: vec![format!("{old} -> {new}")],
        };
        req.storage_put(&StorageEntry {
            key: format!("{new_hist_prefix}{}", hist_seq()),
            value: serde_json::to_vec(&hist)?,
        })
        .await?;
        log::info!(
            target: "security",
            "resource-rename: user={} old={} new={}",
            caller_username(req),
            old,
            new
        );

        // ── 4. Cross-module references (best-effort, like delete) ──────
        // Asset-group membership + reverse index.
        if let Some(groups) = self.core.resource_groups() {
            if let Err(e) = groups.rename_resource(&old, &new, req.namespace_path.as_deref()).await {
                log::warn!(
                    "resource-group rename failed for '{old}' -> '{new}': {e}. \
                     Use the resource-group/reindex endpoint to clean up.",
                );
            }
        }

        // Shares + ownership. The namespace-scoped keying of owner and share
        // records is the identity module's, so the whole move is one call:
        // this engine should not know that a resource inside a namespace is
        // keyed `<ns>/<name>`.
        if let Some(identity) = self.core.identity() {
            identity
                .rename_object(
                    ObjectKind::Resource,
                    &old,
                    &new,
                    req.namespace_path.as_deref(),
                    &caller_audit_actor(req),
                )
                .await;
        }

        // ── 5. Delete the old resource-mount keys (identity now moved) ──
        req.storage_delete(&old_meta_key).await?;
        for k in req.storage_list(&old_secret_prefix).await? {
            req.storage_delete(&format!("{old_secret_prefix}{k}")).await?;
        }
        for k in req.storage_list(&old_smeta_prefix).await? {
            req.storage_delete(&format!("{old_smeta_prefix}{k}")).await?;
        }
        for k in req.storage_list(&old_sver_prefix).await? {
            let key_seg = k.trim_end_matches('/');
            let old_sub = format!("{old_sver_prefix}{key_seg}/");
            for v in req.storage_list(&old_sub).await? {
                req.storage_delete(&format!("{old_sub}{v}")).await?;
            }
            let _ = req.storage_delete(&format!("{old_sver_prefix}{key_seg}")).await;
        }
        for k in req.storage_list(&old_hist_prefix).await? {
            req.storage_delete(&format!("{old_hist_prefix}{k}")).await?;
        }

        let mut data = Map::new();
        data.insert("name".to_string(), Value::String(new));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `resources/v2/transfer/import/<name>`: destination side of a
    /// cross-namespace copy or move; writes a [`ResourceBundle`], `meta/` last.
    /// Security: ONE ACL check, on `resources/resources/<name>` (the policy
    /// layer's `transfer_target`), covers every secret, version and history
    /// entry; per-secret ACLs are not consulted, so the orchestrator probes them.
    /// Only `refuse` or `rename`. Content gates apply (`check_import_write_gates`);
    /// `post_route` stamps the owner, and shares are not touched.
    pub async fn handle_resource_import(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap_or("").to_string();
        let bundle = parse_resource_bundle(req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?)?;
        let storage = req.storage.clone().ok_or(RvError::ErrRequestNotReady)?;

        let plan = plan_resource_import(storage.as_ref(), &raw, bundle).await?;
        self.check_import_write_gates(req, &plan).await?;

        // Names, counts and the origin path only: never a secret value.
        let origin = plan.bundle.origin.clone();
        let user = caller_username(req);
        let summary = apply_resource_import(storage.as_ref(), plan, &user).await?;
        log::info!(
            target: "security",
            "resource-transfer-in: user={} resource={} origin={:?} secrets={} versions={} history={}",
            user,
            summary.name,
            origin,
            summary.secrets,
            summary.versions,
            summary.history
        );

        let mut data = Map::new();
        data.insert("name".to_string(), Value::String(summary.name));
        data.insert("secrets".to_string(), Value::from(summary.secrets));
        data.insert("versions".to_string(), Value::from(summary.versions));
        data.insert("history".to_string(), Value::from(summary.history));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// The write-time checks the ordinary endpoints run on what an import
    /// makes live, against the *destination's* configuration (it can differ
    /// from the origin's): MCP brokered-session profiles need this
    /// namespace's type consent (`handle_resource_write`), and a brokered
    /// resource may not carry a static SSH credential (`handle_secret_write`).
    async fn check_import_write_gates(&self, req: &Request, plan: &ResourceImportPlan) -> Result<(), RvError> {
        let meta = &plan.bundle.meta;
        let type_id = meta.get("type").and_then(Value::as_str).unwrap_or_default();

        // `previous = None`: every profile is new to this namespace.
        if agent_access::write_needs_type_check(None, meta) {
            let types = type_config::effective_type_config(self.core.as_ref(), req).await.map_err(|e| match e {
                type_config::TypeConfigError::Storage(e) => e,
                type_config::TypeConfigError::Malformed(source) => bv_error_response_status!(
                    422,
                    &format!("the {} resource type configuration is not a JSON object", source.as_str())
                ),
            })?;
            agent_access::validate_profiles_on_write(None, meta, types.type_def(type_id))
                .map_err(agent_refusal_error)?;
        }

        if let Some((key, version)) = first_static_credential(&plan.bundle) {
            let eff = self.resolve_login_class_for_type(req, &plan.name, type_id).await?;
            if eff.brokered {
                return Err(bv_error_response_status!(
                    409,
                    &format!(
                        "brokered_resource_no_static_credential: resource `{}` is brokered in this \
                         namespace (login_class via tier `{}`); secret `{key}` version {version} carries \
                         a static SSH credential, which may not be attached. Bind an `ssh-engine` \
                         credential source instead.",
                        plan.name, eff.source
                    )
                ));
            }
        }
        Ok(())
    }

    pub async fn handle_resource_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("name")?.as_str().unwrap().to_string();
        let name = resolve_resource_name(req, &raw).await?;
        let prefix = format!("{HIST_PREFIX}{name}/");

        let mut keys = req.storage_list(&prefix).await?;
        // storage_list returns children in insertion order for some backends
        // and lexicographic order for others; sort explicitly so timelines
        // always render newest-first after the reverse() below.
        keys.sort();
        keys.reverse();

        let mut entries: Vec<Value> = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = req.storage_get(&full).await? {
                if let Ok(v) = serde_json::from_slice::<Value>(&e.value) {
                    entries.push(v);
                }
            }
        }

        let mut data = Map::new();
        data.insert("entries".to_string(), Value::Array(entries));
        Ok(Some(Response::data_response(Some(data))))
    }

    // ── Per-resource secret CRUD ───────────────────────────────────

    pub async fn handle_secret_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
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
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        let entry = req.storage_get(&key).await?;
        match entry {
            Some(e) => {
                let data: Map<String, Value> = serde_json::from_slice(&e.value)?;
                // Read of a secret value is the most sensitive event
                // this module produces. The dispatcher's audit broker
                // already records the request, but mirroring it on the
                // security target gets it into security.log alongside
                // the connect events, where ops watches for "who is
                // pulling credentials right now."
                log::info!(
                    target: "security",
                    "resource-secret-read: user={} resource={} key={}",
                    caller_username(req),
                    resource,
                    key_name
                );
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    /// Resolve the effective SSH login class for a resource, walking the
    /// four-tier `ssh-broker` policy. Returns `SharedCredential` (the
    /// default) when the ssh-broker module isn't registered or no tier is
    /// set — so a deployment that never configures brokering is
    /// unaffected. The resource's classification hints (type + asset-group
    /// memberships) come from the resource record and the resource-group
    /// reverse index.
    async fn resolve_login_class(&self, req: &Request, resource: &str) -> Result<LoginClassVerdict, RvError> {
        if self.core.login_class().is_none() {
            return Ok(LoginClassVerdict::default());
        }

        // Resource type from the metadata record.
        let resource_type = match req.storage_get(&format!("{META_PREFIX}{resource}")).await? {
            Some(e) => serde_json::from_slice::<Map<String, Value>>(&e.value)
                .ok()
                .and_then(|m| m.get("type").and_then(|v| v.as_str().map(String::from)))
                .unwrap_or_default(),
            None => String::new(),
        };
        self.resolve_login_class_for_type(req, resource, &resource_type).await
    }

    /// [`Self::resolve_login_class`] for a resource whose type is known but
    /// whose record may not be stored yet (an import writes `meta/` last).
    async fn resolve_login_class_for_type(
        &self,
        req: &Request,
        resource: &str,
        resource_type: &str,
    ) -> Result<LoginClassVerdict, RvError> {
        let Some(policy) = self.core.login_class() else {
            return Ok(LoginClassVerdict::default());
        };

        // Asset-group memberships from the resource-group reverse index.
        let asset_groups = match self.core.resource_groups() {
            Some(groups) => {
                groups.groups_for_resource(resource, req.namespace_path.as_deref()).await.unwrap_or_default()
            }
            None => Vec::new(),
        };

        policy.resolve_for(resource_type, &asset_groups, resource).await
    }

    pub async fn handle_secret_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let body = req.body.as_ref().ok_or(RvError::ErrRequestNoDataField)?.clone();

        // `sql_endpoint` is the SQL browser's endpoint binding (§5.4 rule 5):
        // reserved, so a malformed value is refused here, not stored.
        sql_profile::validate_sql_endpoint_on_write(&body).map_err(|m| bv_error_response_status!(400, m))?;

        // Brokered-resource enforcement: a resource pinned to `brokered`
        // (at any tier) may not carry a *static SSH credential*. Reject at
        // attach time — not merely hidden in the GUI — so the control is
        // enforceable, not advisory. A static secret carrying a
        // `private_key` or `password` is exactly what the SSH `secret`
        // credential source would hand the dialler; on a brokered resource
        // every login must be minted per-connect from the SSH engine.
        if static_ssh_credential_shape(&body) {
            let eff = self.resolve_login_class(req, &resource).await?;
            if eff.brokered {
                return Err(bv_error_response_status!(
                    409,
                    &format!(
                        "brokered_resource_no_static_credential: resource `{resource}` is \
                         brokered (login_class via tier `{}`); a static SSH credential may \
                         not be attached — every SSH login is minted per-connect from the \
                         SSH engine. Bind an `ssh-engine` credential source instead.",
                        eff.source
                    )
                ));
            }
        }

        let curr_key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        let smeta_key = format!("{SMETA_PREFIX}{resource}/{key_name}");

        // Load (or initialize) the version index for this secret.
        let mut meta: ResourceSecretMeta = match req.storage_get(&smeta_key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => ResourceSecretMeta::default(),
        };

        let new_version = meta.current_version + 1;
        let now = now_rfc3339();
        let user = caller_username(req);
        let op = if new_version == 1 { "create" } else { "update" };

        // Snapshot the new value to the version store.
        let ver_payload = ResourceSecretVersion {
            data: body.clone(),
            version: new_version,
            created_time: now.clone(),
            username: user.clone(),
            operation: op.to_string(),
        };
        let ver_key = format!("{SVER_PREFIX}{resource}/{key_name}/{new_version}");
        req.storage_put(&StorageEntry { key: ver_key, value: serde_json::to_string(&ver_payload)?.into_bytes() })
            .await?;

        // Keep the current-value entry for O(1) reads.
        let data = serde_json::to_string(&body)?;
        req.storage_put(&StorageEntry { key: curr_key, value: data.into_bytes() }).await?;

        // Update and persist the version index.
        meta.current_version = new_version;
        meta.versions.insert(
            new_version.to_string(),
            ResourceSecretVersionMeta { created_time: now, username: user, operation: op.to_string() },
        );
        req.storage_put(&StorageEntry { key: smeta_key, value: serde_json::to_string(&meta)?.into_bytes() }).await?;

        Ok(None)
    }

    pub async fn handle_secret_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();

        // Delete current value.
        let curr_key = format!("{SECRET_PREFIX}{resource}/{key_name}");
        req.storage_delete(&curr_key).await?;

        // Delete all version payloads.
        let sver_prefix = format!("{SVER_PREFIX}{resource}/{key_name}/");
        for v in req.storage_list(&sver_prefix).await? {
            req.storage_delete(&format!("{sver_prefix}{v}")).await?;
        }

        // Delete the version index.
        let smeta_key = format!("{SMETA_PREFIX}{resource}/{key_name}");
        req.storage_delete(&smeta_key).await?;

        Ok(None)
    }

    pub async fn handle_secret_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();

        let smeta_key = format!("{SMETA_PREFIX}{resource}/{key_name}");
        let meta: ResourceSecretMeta = match req.storage_get(&smeta_key).await? {
            Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
            None => {
                // No version index yet (legacy secret written before
                // versioning). Return an empty list rather than an error.
                let mut data = Map::new();
                data.insert("current_version".to_string(), Value::from(0u64));
                data.insert("versions".to_string(), Value::Array(Vec::new()));
                return Ok(Some(Response::data_response(Some(data))));
            }
        };

        // Convert the HashMap<String, VersionMeta> into a sorted array for
        // the frontend. Descending version order puts the newest first.
        let mut versions: Vec<(u64, &ResourceSecretVersionMeta)> =
            meta.versions.iter().filter_map(|(k, v)| k.parse::<u64>().ok().map(|n| (n, v))).collect();
        versions.sort_by_key(|v| std::cmp::Reverse(v.0));

        let mut entries = Vec::with_capacity(versions.len());
        for (ver, vm) in versions {
            let mut e = Map::new();
            e.insert("version".to_string(), Value::from(ver));
            e.insert("created_time".to_string(), Value::from(vm.created_time.clone()));
            e.insert("username".to_string(), Value::from(vm.username.clone()));
            e.insert("operation".to_string(), Value::from(vm.operation.clone()));
            entries.push(Value::Object(e));
        }

        let mut data = Map::new();
        data.insert("current_version".to_string(), Value::from(meta.current_version));
        data.insert("versions".to_string(), Value::Array(entries));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_secret_version_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let raw = req.get_data("resource")?.as_str().unwrap().to_string();
        let resource = resolve_resource_name(req, &raw).await?;
        let key_name = req.get_data("key")?.as_str().unwrap().to_string();
        let version_str = req.get_data("version")?.as_str().unwrap().to_string();
        let version: u64 = version_str.parse().map_err(|_| RvError::ErrRequestInvalid)?;

        let ver_key = format!("{SVER_PREFIX}{resource}/{key_name}/{version}");
        let entry = match req.storage_get(&ver_key).await? {
            Some(e) => e,
            None => return Ok(None),
        };
        let v: ResourceSecretVersion = serde_json::from_slice(&entry.value).map_err(|_| RvError::ErrRequestInvalid)?;

        let mut data = Map::new();
        data.insert("version".to_string(), Value::from(v.version));
        data.insert("created_time".to_string(), Value::from(v.created_time));
        data.insert("username".to_string(), Value::from(v.username));
        data.insert("operation".to_string(), Value::from(v.operation));
        data.insert("data".to_string(), Value::Object(v.data));
        // Historical-version reads disclose secret material just like
        // current-value reads; record them on the same security
        // channel with the version tag included.
        log::info!(
            target: "security",
            "resource-secret-read: user={} resource={} key={} version={}",
            caller_username(req),
            resource,
            key_name,
            version
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_noop(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

// ── Module registration ────────────────────────────────────────────

impl ResourceModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { name: "resource".to_string(), backend: Arc::new(ResourceBackend::new(core)) }
    }
}

impl Module for ResourceModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn register(self: Arc<Self>, services: &crate::kernel_api::KernelServices) {
        kernel_service::register(self, services);
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("resource", Arc::new(backend_new_func))
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_logical_backend("resource")
    }
}

// ── Unit tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn diff_create_treats_everything_as_changed() {
        let new = obj(json!({
            "hostname": "h",
            "owner": "alice",
            "created_at": "t",
            "updated_at": "t",
            "name": "x",
        }));
        let changed = diff_field_names(None, &new);
        // name/created_at/updated_at are ignored; the rest is considered changed.
        assert_eq!(changed, vec!["hostname".to_string(), "owner".to_string()]);
    }

    #[test]
    fn diff_equal_returns_empty() {
        let a = obj(json!({ "hostname": "h", "owner": "alice" }));
        let b = a.clone();
        assert!(diff_field_names(Some(&a), &b).is_empty());
    }

    #[test]
    fn diff_detects_changed_added_and_removed_fields() {
        let old = obj(json!({ "hostname": "old", "port": 22, "owner": "alice" }));
        let new = obj(json!({ "hostname": "new", "port": 22, "tags": "web" }));
        // Changed: hostname; added: tags; removed: owner.
        let changed = diff_field_names(Some(&old), &new);
        assert_eq!(changed, vec!["hostname".to_string(), "owner".to_string(), "tags".to_string()]);
    }

    #[test]
    fn diff_ignores_timestamps_even_when_different() {
        let old = obj(json!({ "hostname": "h", "updated_at": "2020" }));
        let new = obj(json!({ "hostname": "h", "updated_at": "2030" }));
        assert!(diff_field_names(Some(&old), &new).is_empty());
    }

    #[test]
    fn hist_seq_is_sortable_and_20_digits() {
        let a = hist_seq();
        // Sleep a hair so nanos advance even on fast CPUs.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = hist_seq();
        assert_eq!(a.len(), 20);
        assert_eq!(b.len(), 20);
        assert!(a < b, "expected {a} < {b}");
    }

    #[test]
    fn static_ssh_credential_shape_detects_key_and_password() {
        assert!(static_ssh_credential_shape(&obj(json!({ "private_key": "x" }))));
        assert!(static_ssh_credential_shape(&obj(json!({ "password": "p" }))));
        // Empty values don't count as a credential.
        assert!(!static_ssh_credential_shape(&obj(json!({ "password": "" }))));
        // A bare passphrase or a generic KV blob is not a static credential.
        assert!(!static_ssh_credential_shape(&obj(json!({ "passphrase": "p" }))));
        assert!(!static_ssh_credential_shape(&obj(json!({ "token": "t" }))));
    }

    // ── Transfer import (`v2/transfer/import/<name>`) ─────────────────

    use std::{collections::BTreeMap, sync::Mutex};

    use crate::storage::Storage;

    /// A flat in-memory `Storage` with the barrier's `list` semantics
    /// (immediate children, sub-trees as `name/`) that also records the
    /// order of every `put`, so a test can assert what was written last.
    #[derive(Default)]
    struct MemStorage {
        map: Mutex<BTreeMap<String, Vec<u8>>>,
        puts: Mutex<Vec<String>>,
    }

    impl MemStorage {
        fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
            self.map.lock().unwrap().clone()
        }

        fn json(&self, key: &str) -> Value {
            let map = self.map.lock().unwrap();
            let raw = map.get(key).unwrap_or_else(|| panic!("missing storage key {key}"));
            serde_json::from_slice(raw).unwrap()
        }

        fn seed(&self, key: &str, value: Value) {
            self.map.lock().unwrap().insert(key.to_string(), serde_json::to_vec(&value).unwrap());
        }

        fn keys_under(&self, prefix: &str) -> Vec<String> {
            self.map.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect()
        }
    }

    #[maybe_async::maybe_async]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let map = self.map.lock().unwrap();
            let mut out: Vec<String> = Vec::new();
            for k in map.keys().filter(|k| k.starts_with(prefix)) {
                let rest = &k[prefix.len()..];
                let child = match rest.find('/') {
                    Some(i) => rest[..=i].to_string(),
                    None => rest.to_string(),
                };
                if !out.contains(&child) {
                    out.push(child);
                }
            }
            Ok(out)
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            Ok(self.map.lock().unwrap().get(key).map(|v| StorageEntry { key: key.into(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.puts.lock().unwrap().push(entry.key.clone());
            self.map.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// What the handler does after routing, minus the write-time gates that
    /// need the vault (`check_import_write_gates`).
    #[maybe_async::maybe_async]
    async fn import(mem: &MemStorage, name: &str, body: Value) -> Result<ResourceImportSummary, RvError> {
        let bundle = parse_resource_bundle(body.as_object().unwrap())?;
        let plan = plan_resource_import(mem, name, bundle).await?;
        apply_resource_import(mem, plan, "carol").await
    }

    fn bundle() -> Value {
        json!({
            "meta": {
                "name": "srv1-origin",
                "type": "server",
                "hostname": "h1",
                "created_at": "2025-01-01T00:00:00+00:00"
            },
            "secrets": [{
                "key": "admin",
                "versions": [
                    {"version": 1, "created_time": "2025-01-02T00:00:00+00:00", "deleted": false,
                     "data": {"password": "v1-S3CRET"}},
                    {"version": 2, "created_time": "2025-01-03T00:00:00+00:00", "deleted": false,
                     "data": {"password": "v2-S3CRET"}}
                ],
                "current": 2
            }],
            "history": [
                {"ts": "2025-01-01T00:00:00+00:00", "user": "alice", "op": "create", "changed_fields": ["hostname"]},
                {"ts": "2025-01-04T00:00:00+00:00", "user": "bob", "op": "update", "changed_fields": ["notes"]}
            ],
            "origin": "ns-a/resources/srv1",
            "origin_owner": "entity-alice"
        })
    }

    /// `body` with the value at `pointer` replaced; a top-level field the
    /// bundle omits (`on_conflict`) is added.
    fn with(mut body: Value, pointer: &str, value: Value) -> Value {
        match body.pointer_mut(pointer) {
            Some(slot) => *slot = value,
            None => {
                let field = pointer.strip_prefix('/').filter(|f| !f.contains('/'));
                let field = field.unwrap_or_else(|| panic!("no {pointer} in bundle"));
                body.as_object_mut().unwrap().insert(field.to_string(), value);
            }
        }
        body
    }

    fn status(r: Result<ResourceImportSummary, RvError>) -> u16 {
        match r {
            Err(RvError::ErrResponseStatus(s, _)) => s,
            other => panic!("expected a status error, got {other:?}"),
        }
    }

    /// The history timeline of `name`, oldest first, as the history
    /// endpoint orders it (by key).
    fn timeline(mem: &MemStorage, name: &str) -> Vec<ResourceHistoryEntry> {
        let mut keys = mem.keys_under(&format!("{HIST_PREFIX}{name}/"));
        keys.sort();
        keys.iter().map(|k| serde_json::from_value(mem.json(k)).unwrap()).collect()
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_writes_meta_secrets_versions_and_history() {
        let mem = MemStorage::default();
        let summary = import(&mem, "srv1", bundle()).await.unwrap();
        assert_eq!(summary, ResourceImportSummary { name: "srv1".into(), secrets: 1, versions: 2, history: 2 });

        // The record lands under the destination name, everything else verbatim.
        let meta = mem.json("meta/srv1");
        assert_eq!(meta["name"], "srv1");
        assert_eq!(meta["hostname"], "h1");
        assert_eq!(meta["created_at"], "2025-01-01T00:00:00+00:00");

        // Version numbers and timestamps are the bundle's, not the import's.
        for (n, ts, pw) in
            [(1u64, "2025-01-02T00:00:00+00:00", "v1-S3CRET"), (2, "2025-01-03T00:00:00+00:00", "v2-S3CRET")]
        {
            let v: ResourceSecretVersion = serde_json::from_value(mem.json(&format!("sver/srv1/admin/{n}"))).unwrap();
            assert_eq!(v.version, n);
            assert_eq!(v.created_time, ts);
            assert_eq!(v.data["password"], pw);
        }
        let smeta: ResourceSecretMeta = serde_json::from_value(mem.json("smeta/srv1/admin")).unwrap();
        assert_eq!(smeta.current_version, 2);
        assert_eq!(smeta.versions.len(), 2);
        assert_eq!(smeta.versions["1"].created_time, "2025-01-02T00:00:00+00:00");
        assert_eq!(smeta.versions["2"].created_time, "2025-01-03T00:00:00+00:00");
        assert_eq!(mem.json("secret/srv1/admin"), json!({"password": "v2-S3CRET"}));

        // The origin's timeline, in order, then the arrival.
        let hist = timeline(&mem, "srv1");
        assert_eq!(hist.len(), 3);
        assert_eq!((hist[0].user.as_str(), hist[0].op.as_str()), ("alice", "create"));
        assert_eq!(hist[0].ts, "2025-01-01T00:00:00+00:00");
        assert_eq!(hist[0].changed_fields, vec!["hostname".to_string()]);
        assert_eq!((hist[1].user.as_str(), hist[1].op.as_str()), ("bob", "update"));
        let arrival = &hist[2];
        assert_eq!(arrival.op, "transfer-in");
        assert_eq!(arrival.user, "carol");
        assert!(arrival.changed_fields.contains(&"origin: ns-a/resources/srv1".to_string()), "{arrival:?}");
        assert!(arrival.changed_fields.contains(&"origin_owner: entity-alice".to_string()), "{arrival:?}");

        // `meta/` is written last, so a half-written import is invisible to
        // listings.
        assert_eq!(mem.puts.lock().unwrap().last().map(String::as_str), Some("meta/srv1"));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_refuses_existing_name_by_default() {
        // A legacy mixed-case record collides case-insensitively.
        let mem = MemStorage::default();
        mem.seed("meta/Srv1", json!({"name": "Srv1", "hostname": "old"}));
        let before = mem.snapshot();
        assert_eq!(status(import(&mem, "srv1", bundle()).await), 409);
        assert_eq!(status(import(&mem, "SRV1", with(bundle(), "/on_conflict", json!("refuse"))).await), 409);
        assert_eq!(mem.snapshot(), before, "a refused import writes nothing");

        // Secret data left under a name with no record (an interrupted
        // import) is a collision too: never merged into the new resource.
        let mem = MemStorage::default();
        mem.seed("secret/srv2/stale", json!({"password": "left-behind"}));
        let before = mem.snapshot();
        assert_eq!(status(import(&mem, "srv2", bundle()).await), 409);
        assert_eq!(mem.snapshot(), before);

        // An unknown conflict mode is refused, not read as the default.
        let mem = MemStorage::default();
        assert_eq!(status(import(&mem, "srv3", with(bundle(), "/on_conflict", json!("merge"))).await), 400);
        assert!(mem.snapshot().is_empty());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_refuses_overwrite_and_rename_picks_free_name() {
        let mem = MemStorage::default();
        mem.seed("meta/srv1", json!({"name": "srv1", "hostname": "old"}));
        mem.seed("secret/srv1/old-key", json!({"password": "old"}));
        mem.seed("smeta/srv1/old-key", json!({"current_version": 1, "versions": {}}));
        mem.seed("sver/srv1/old-key/1", json!({"data": {"password": "old"}, "version": 1}));
        mem.seed("hist/srv1/00000000000000000001", json!({"ts": "t", "user": "u", "op": "create"}));
        let existing = mem.snapshot();

        // Overwrite is not a mode of this route: it would skip the delete ACL
        // and the owner, share and asset-group cleanup a real delete runs. It
        // is refused before storage is read, whatever is at the name.
        for name in ["srv1", "fresh", ""] {
            let r = import(&mem, name, with(bundle(), "/on_conflict", json!("overwrite"))).await;
            let Err(RvError::ErrResponseStatus(400, message)) = r else {
                panic!("{name:?}: expected a 400, got {r:?}")
            };
            assert!(message.contains("refuse or rename"), "{name:?}: {message}");
        }
        assert_eq!(mem.snapshot(), existing, "a refused overwrite writes nothing");

        // Rename: the first free `<name>-<n>`, the existing record untouched.
        let renamed = import(&mem, "srv1", with(bundle(), "/on_conflict", json!("rename"))).await.unwrap();
        assert_eq!(renamed.name, "srv1-2");
        assert_eq!(mem.json("meta/srv1-2")["name"], "srv1-2");
        assert_eq!(mem.json("secret/srv1-2/admin"), json!({"password": "v2-S3CRET"}));
        for (k, v) in &existing {
            assert_eq!(mem.snapshot().get(k), Some(v), "{k} changed under a rename import");
        }
        let again = import(&mem, "srv1", with(bundle(), "/on_conflict", json!("rename"))).await.unwrap();
        assert_eq!(again.name, "srv1-3");

        // Rename with nothing in the way keeps the requested name.
        let fresh = import(&mem, "fresh", with(bundle(), "/on_conflict", json!("rename"))).await.unwrap();
        assert_eq!(fresh.name, "fresh");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_rejects_name_with_slash_or_dotdot() {
        let mem = MemStorage::default();
        for name in ["a/b", "..", "a..b", "../x", "", "   "] {
            assert_eq!(status(import(&mem, name, bundle()).await), 400, "name {name:?}");
        }
        assert!(mem.snapshot().is_empty(), "a refused import writes nothing");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_rejects_unsafe_secret_keys_and_malformed_versions() {
        let version = |n: u64| json!({"version": n, "created_time": "t", "deleted": false, "data": {"k": "v"}});
        let cases: Vec<(&str, Value)> = vec![
            ("key with '/'", with(bundle(), "/secrets/0/key", json!("a/b"))),
            ("key '..'", with(bundle(), "/secrets/0/key", json!(".."))),
            ("key containing '..'", with(bundle(), "/secrets/0/key", json!("x..y"))),
            ("empty key", with(bundle(), "/secrets/0/key", json!(""))),
            ("duplicate key", {
                let mut b = bundle();
                let dup = b["secrets"][0].clone();
                b["secrets"].as_array_mut().unwrap().push(dup);
                b
            }),
            ("no versions", with(bundle(), "/secrets/0/versions", json!([]))),
            ("version 0", with(bundle(), "/secrets/0/versions", json!([version(0)]))),
            ("duplicate version", with(bundle(), "/secrets/0/versions", json!([version(1), version(1)]))),
            ("current not a version", with(bundle(), "/secrets/0/current", json!(3))),
            ("current not the latest", with(bundle(), "/secrets/0/current", json!(1))),
            ("deleted version", with(bundle(), "/secrets/0/versions/0/deleted", json!(true))),
            ("version not a number", with(bundle(), "/secrets/0/versions/0/version", json!("1/../2"))),
            ("empty origin", with(bundle(), "/origin", json!(""))),
        ];
        for (what, body) in cases {
            let mem = MemStorage::default();
            assert_eq!(status(import(&mem, "srv1", body).await), 400, "{what}");
            assert!(mem.snapshot().is_empty(), "{what}: a refused import writes nothing");
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn import_never_overwrites_an_existing_history_entry() {
        // An entry already stored at the key an imported entry would take
        // (2025-01-01T00:00:00Z in nanoseconds) is an audit record: kept, and
        // the imported entry moves to the next free key.
        let mem = MemStorage::default();
        let taken = "hist/srv1/01735689600000000000";
        mem.seed(taken, json!({"ts": "x", "user": "earlier", "op": "delete", "changed_fields": []}));
        import(&mem, "srv1", bundle()).await.unwrap();
        assert_eq!(mem.json(taken)["user"], "earlier");
        assert_eq!(mem.json("hist/srv1/01735689600000000001")["user"], "alice");
    }

    #[test]
    fn import_finds_static_credential_in_any_version() {
        // Only the first version holds a password; the live one does not.
        let body = with(bundle(), "/secrets/0/versions/1/data", json!({"token": "t"}));
        let bundle = parse_resource_bundle(body.as_object().unwrap()).ok().unwrap();
        assert_eq!(first_static_credential(&bundle), Some(("admin", 1)));

        let body = with(body, "/secrets/0/versions/0/data", json!({"username": "u"}));
        let bundle = parse_resource_bundle(body.as_object().unwrap()).ok().unwrap();
        assert_eq!(first_static_credential(&bundle), None);
    }

    #[test]
    fn import_bundle_parse_errors_never_echo_values() {
        // A secret value in the wrong place must not come back in the error:
        // serde's own message quotes the offending string.
        let body = with(bundle(), "/secrets/0/versions/0/data", json!("hunter2-S3CRET"));
        let err = parse_resource_bundle(body.as_object().unwrap()).err().expect("a string is not a data map");
        assert!(matches!(err, RvError::ErrResponseStatus(400, _)), "{err:?}");
        assert!(!format!("{err:?} {err}").contains("hunter2"), "{err:?}");

        // A missing field is named, since a field name is not a value.
        let mut body = bundle();
        body.as_object_mut().unwrap().remove("origin");
        let err = parse_resource_bundle(body.as_object().unwrap()).err().expect("origin is required");
        assert!(format!("{err}").contains("origin"), "{err}");
    }
}
