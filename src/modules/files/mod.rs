//! File Resources — dedicated storage engine for binary-blob "files"
//! that live alongside secrets and resources in the vault.
//!
//! Phase 1 (this file) delivers the engine scaffold, metadata + content
//! CRUD, and the v2 HTTP surface described in `features/file-resources.md`.
//! Everything lives under the `files/` mount inside a dedicated
//! barrier-encrypted engine, independent of the KV secret engine and the
//! resource engine.
//!
//! Storage layout inside the mount's barrier view:
//!
//!   meta/<id>      -> `FileEntry` JSON (metadata + SHA-256 of the bytes)
//!   blob/<id>      -> raw content bytes (single-blob in Phase 1; the
//!                     chunking layout from the feature file — chunks/<id>/<seq>
//!                     — will land in a later slice when the 32 MiB
//!                     inline cap becomes limiting)
//!   hist/<id>/<ns> -> `FileHistoryEntry` JSON (who/when/op/changed-fields;
//!                     never content bytes or their hash)
//!
//! Phase 1 scope — shipped here:
//!   * module + logical-backend + `files/` default mount
//!   * v2/files POST / LIST / GET{meta,content} / PUT / DELETE / history
//!   * 32 MiB hard cap enforced server-side (configurable later)
//!   * SHA-256 over plaintext recorded in metadata for whole-file integrity
//!   * per-file history log
//!
//! Intentionally deferred to later slices — see `features/file-resources.md`:
//!   * chunking for files above the inline cap
//!   * ownership / sharing / asset-group wiring via `OwnerStore` and
//!     `ShareStore` (Phase 2 of the feature)
//!   * sync targets (local FS / SMB / SCP / SFTP) (Phases 3, 5, 6)
//!   * GUI (Phase 4)
//!   * content-versioning (Phase 8)

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

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
    utils::generate_uuid,
};

pub mod files_audit_store;
pub mod scheduler;
#[cfg(feature = "files_smb")]
pub mod smb;
#[cfg(feature = "files_ssh_sync")]
pub mod ssh_sync;
use files_audit_store::{FileAuditEntry, FileAuditStore};

static FILES_BACKEND_HELP: &str = r#"
The files backend provides dedicated storage for binary files
(certificates, keys, configs, small archives) behind the vault barrier.
Each file is addressed by a server-assigned UUID; its metadata and
content bytes are encrypted at rest. A SHA-256 hash over the plaintext
is stored in metadata so readers can verify integrity after decryption.

A bounded hard cap on file size is enforced server-side to keep a
secrets manager from being repurposed as a general-purpose blob store.
"#;

// Storage key prefixes within this mount's barrier view.
pub(crate) const META_PREFIX: &str = "meta/";
pub(crate) const BLOB_PREFIX: &str = "blob/";
pub(crate) const HIST_PREFIX: &str = "hist/";
pub(crate) const SYNC_PREFIX: &str = "sync/";
pub(crate) const SYNC_STATE_PREFIX: &str = "sync-state/";
pub(crate) const VMETA_PREFIX: &str = "vmeta/";
pub(crate) const VBLOB_PREFIX: &str = "vblob/";

/// How many previous content versions to retain per file. On each
/// write, the pre-write blob is snapshotted; when the retained-version
/// count exceeds this limit, the oldest version is pruned. Set to `0`
/// to disable versioning — pre-write snapshots stop being taken and
/// any existing version records are left in place until the file is
/// deleted.
const DEFAULT_VERSION_RETENTION: usize = 5;

/// Hard upper bound on file content size in Phase 1. Rejections happen
/// server-side before any bytes are persisted. Matches the default in
/// `features/file-resources.md`.
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Fields in `FileEntry` that are noisy in a change-log diff (timestamps
/// always move; `id` and `sha256` are derived from content and identity).
const HIST_IGNORED_FIELDS: &[&str] =
    &["created_at", "updated_at", "id", "sha256", "size_bytes"];

// ── Data types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 over the plaintext content. Re-computed on
    /// every write; readers can re-hash after decryption to verify
    /// integrity.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// One sync target attached to a file. `kind` selects the transport;
/// `target_path` is interpreted by the transport (a filesystem path
/// for `local-fs`, a UNC-style URL for `smb`).
///
/// `local-fs` ships in Phase 3. `smb` ships in Phase 5 behind the
/// `files_smb` Cargo feature; without that feature the engine still
/// accepts `kind = "smb"` configs (so config round-trips don't break
/// across builds with different feature sets) but `push` returns a
/// clear "compiled without files_smb support" error. SCP / SFTP
/// remain Phase 6 follow-ons.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSyncTarget {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub target_path: String,
    /// Unix-style mode. Applied on `local-fs` after write. Empty leaves
    /// the OS default (umask-derived) alone. Ignored by other transports.
    #[serde(default)]
    pub mode: String,
    // ── SMB-specific fields ─────────────────────────────────────────
    // Stored barrier-encrypted at rest like every other sync-target
    // field. Only relevant when `kind = "smb"`; serde defaults keep
    // the wire format clean for non-SMB targets.
    /// Username for NTLM bind. Local SAM accounts work as `username`;
    /// AD accounts can be supplied as `DOMAIN\username` or just
    /// `username` with `smb_domain` set separately.
    #[serde(default)]
    pub smb_username: String,
    /// Password for NTLM bind. Returned **redacted** by the read API
    /// (same pattern as the LDAP engine's `bindpass`).
    #[serde(default)]
    pub smb_password: String,
    /// Optional NetBIOS / AD domain. When empty, NTLM uses an empty
    /// domain field — fine for local SAM auth and most workgroup
    /// shares. Required for AD member servers that enforce
    /// domain-qualified logon.
    #[serde(default)]
    pub smb_domain: String,
    // ── SSH (sftp / scp) credentials ─────────────────────────────
    // Stored barrier-encrypted at rest like everything else. Either
    // password or private_key (or both) must be set; the credential
    // resolver tries the key first and falls back to the password.
    #[serde(default)]
    pub ssh_username: String,
    /// Password for password-auth. Write-only on read; redacted.
    #[serde(default)]
    pub ssh_password: String,
    /// PEM-encoded SSH private key. OpenSSH / PKCS#8 / RFC 8410 /
    /// legacy RSA all parsed by `russh-keys::decode_secret_key`.
    /// Write-only on read; redacted with a `_set` boolean.
    #[serde(default)]
    pub ssh_private_key: String,
    /// Optional passphrase if the private key is encrypted.
    /// Write-only on read; redacted with a `_set` boolean.
    #[serde(default)]
    pub ssh_passphrase: String,
    /// Optional pinned host-key fingerprint in OpenSSH `SHA256:<b64>`
    /// format. When set, the connection refuses any server key
    /// whose fingerprint doesn't match. When empty, accepts any
    /// server key on first connect (TOFU-without-pinning) and logs
    /// the observed fingerprint at WARN.
    #[serde(default)]
    pub ssh_host_key_fingerprint: String,
    /// When true, every successful file-content write fires an
    /// immediate push to this target as part of the same request.
    /// Failure of the inline push does not roll back the content
    /// write — the failure is recorded on the target's `FileSyncState`
    /// and the next periodic tick (or manual push) retries.
    #[serde(default)]
    pub sync_on_write: bool,
    /// Periodic re-sync cadence in seconds. `0` (default) means the
    /// target is push-on-demand only — the scheduler skips it.
    /// Otherwise the scheduler runs a push when
    /// `now - state.last_attempt_at >= auto_sync_interval_seconds`
    /// and `now >= state.next_retry_at` (the latter implements
    /// exponential-backoff after consecutive failures).
    #[serde(default)]
    pub auto_sync_interval_seconds: u64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// Per-target sync state. Captures the last-push outcome so operators
/// can see at a glance whether a file has been pushed since its last
/// content change, and what the last transport error (if any) was.
/// Never stores content bytes or their hash beyond what the metadata
/// already holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSyncState {
    #[serde(default)]
    pub last_success_at: String,
    #[serde(default)]
    pub last_success_sha256: String,
    #[serde(default)]
    pub last_failure_at: String,
    #[serde(default)]
    pub last_error: String,
    /// Unix-second timestamp of the most recent attempt (success or
    /// failure). The scheduler uses this to decide whether the
    /// target's `auto_sync_interval_seconds` window has elapsed.
    /// Zero means "never attempted."
    #[serde(default)]
    pub last_attempt_at_unix: u64,
    /// Earliest unix-second timestamp at which the scheduler is
    /// allowed to retry this target after a failure. Set by the
    /// exponential-backoff logic; zero means "no backoff in effect."
    #[serde(default)]
    pub next_retry_at_unix: u64,
    /// Number of consecutive failed pushes since the last success.
    /// Drives the exponential backoff: backoff seconds =
    /// `min(2 ** consecutive_failures, MAX_BACKOFF_SECS)`.
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Source of the most recent attempt: `"manual"`, `"on_write"`,
    /// or `"scheduler"`. Useful for an operator triaging a flapping
    /// target.
    #[serde(default)]
    pub last_attempt_source: String,
}

/// Per-version metadata for a historical snapshot of a file's
/// content. Captures the state of the bytes that were displaced by a
/// later write so an operator can roll forward or back.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileVersionInfo {
    pub version: u64,
    pub size_bytes: u64,
    pub sha256: String,
    /// The file's metadata `name` at the time the snapshot was taken
    /// — useful when a rename happened between versions.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mime_type: String,
    pub created_at: String,
    pub user: String,
}

/// Version index for a single file. `current_version` is the latest
/// content version; `versions` is the ordered list of retained
/// historical snapshots (oldest first). `current_version` is never in
/// the list — only *previous* content is versioned.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileVersionMeta {
    #[serde(default)]
    pub current_version: u64,
    #[serde(default)]
    pub versions: Vec<FileVersionInfo>,
}

/// Per-write change-log entry. Captures *which* top-level metadata
/// fields moved; never the content bytes or their hash. Matches the
/// shape of `ResourceHistoryEntry` in the resource module.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
}

// ── Module boilerplate ─────────────────────────────────────────────

pub struct FilesModule {
    pub name: String,
    pub backend: Arc<FilesBackend>,
}

pub struct FilesBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct FilesBackend {
    #[deref]
    pub inner: Arc<FilesBackendInner>,
}

impl FilesBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(FilesBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_list = self.inner.clone();
        let h_create = self.inner.clone();
        let h_read = self.inner.clone();
        let h_write = self.inner.clone();
        let h_delete = self.inner.clone();
        let h_content = self.inner.clone();
        let h_history = self.inner.clone();
        let h_sync_list = self.inner.clone();
        let h_sync_write = self.inner.clone();
        let h_sync_delete = self.inner.clone();
        let h_sync_push = self.inner.clone();
        let h_sync_tick = self.inner.clone();
        let h_versions_list = self.inner.clone();
        let h_version_read = self.inner.clone();
        let h_version_content = self.inner.clone();
        let h_version_restore = self.inner.clone();
        let h_noop1 = self.inner.clone();
        let h_noop2 = self.inner.clone();

        let backend = new_logical_backend!({
            paths: [
                {
                    // `LIST files/` returns ids; `POST files/` creates
                    // a new file (server assigns the id).
                    pattern: "files/?$",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "Human-readable file name."
                        },
                        "resource": {
                            field_type: FieldType::Str,
                            description: "Optional resource this file belongs to."
                        },
                        "mime_type": {
                            field_type: FieldType::Str,
                            description: "MIME type of the content."
                        },
                        "tags": {
                            field_type: FieldType::CommaStringSlice,
                            description: "Comma-separated list of tags."
                        },
                        "notes": {
                            field_type: FieldType::Str,
                            description: "Free-form notes."
                        },
                        "content_base64": {
                            field_type: FieldType::Str,
                            description: "Base64-encoded content bytes."
                        }
                    },
                    operations: [
                        {op: Operation::List, handler: h_list.handle_list},
                        {op: Operation::Write, handler: h_create.handle_create}
                    ],
                    help: "List file ids, or create a new file."
                },
                {
                    // Content stream for a file. `GET` returns the
                    // content as base64 in the JSON response envelope.
                    pattern: r"files/(?P<id>[^/]+)/content$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id (UUID)."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_content.handle_content_read}
                    ],
                    help: "Read the content bytes of a file as base64."
                },
                {
                    // Change-log for a single file (metadata-only;
                    // never content bytes).
                    pattern: r"files/(?P<id>[^/]+)/history/?$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_history.handle_history}
                    ],
                    help: "Read the change history for a file."
                },
                {
                    // List retained content versions for a file.
                    pattern: r"files/(?P<id>[^/]+)/versions/?$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_versions_list.handle_versions_list}
                    ],
                    help: "List the retained historical versions of a file's content."
                },
                {
                    // Read content bytes of a specific historical version.
                    pattern: r"files/(?P<id>[^/]+)/versions/(?P<version>\d+)/content$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        },
                        "version": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Historical version number."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_version_content.handle_version_content_read}
                    ],
                    help: "Read the content bytes of a specific historical version as base64."
                },
                {
                    // Restore a historical version as the current
                    // content. Takes another snapshot (of the
                    // about-to-be-displaced current) before swapping.
                    pattern: r"files/(?P<id>[^/]+)/versions/(?P<version>\d+)/restore$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        },
                        "version": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Historical version to restore."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_version_restore.handle_version_restore}
                    ],
                    help: "Restore a historical version as the file's current content. Snapshots the displaced content as a new version, so restore is itself versioned and reversible."
                },
                {
                    // Read metadata of a specific historical version.
                    pattern: r"files/(?P<id>[^/]+)/versions/(?P<version>\d+)$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        },
                        "version": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Historical version number."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_version_read.handle_version_read}
                    ],
                    help: "Read metadata for a specific historical version (sha256, size, author, name-at-time)."
                },
                {
                    // List sync targets attached to a file.
                    pattern: r"files/(?P<id>[^/]+)/sync/?$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_sync_list.handle_sync_list}
                    ],
                    help: "List the configured sync targets for a file."
                },
                {
                    // On-demand push: re-sync the file's current
                    // content to the named target. POST so it matches
                    // mutative semantics (state gets updated).
                    pattern: r"files/(?P<id>[^/]+)/sync/(?P<name>[^/]+)/push$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        },
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Sync target name."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_sync_push.handle_sync_push}
                    ],
                    help: "Push the file's current content to the named sync target. Fails the request only on transport error; the target's sync-state record is updated either way."
                },
                {
                    // Mount-wide manual scheduler tick. Runs the same
                    // sweep the periodic scheduler runs every 60 s,
                    // but on demand. Operators that disable the
                    // internal scheduler (acme/config-style master
                    // switch) drive the sweep externally via cron
                    // hitting this endpoint.
                    pattern: r"sync-tick$",
                    operations: [
                        {op: Operation::Write, handler: h_sync_tick.handle_sync_tick}
                    ],
                    help: "Run the periodic sync sweep across this mount on demand."
                },
                {
                    // CRUD a single sync target attached to a file.
                    pattern: r"files/(?P<id>[^/]+)/sync/(?P<name>[^/]+)$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        },
                        "name": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "Sync target name."
                        },
                        "kind": {
                            field_type: FieldType::Str,
                            description: "Transport kind: `local-fs` or `smb` (the latter requires the `files_smb` build feature)."
                        },
                        "target_path": {
                            field_type: FieldType::Str,
                            description: "Destination path interpreted by the transport. local-fs: a filesystem path. smb: `smb://server[:port]/share/path/to/file` or a backslash UNC `\\\\server\\share\\path`."
                        },
                        "mode": {
                            field_type: FieldType::Str,
                            description: "Optional Unix mode applied after write (e.g., \"0600\"). Ignored by transports other than local-fs."
                        },
                        "sync_on_write": {
                            field_type: FieldType::Bool,
                            default: false,
                            description: "Push to this target as part of every successful file content write. Failure does not roll back the write."
                        },
                        "auto_sync_interval_seconds": {
                            field_type: FieldType::Int,
                            default: 0,
                            description: "Periodic re-sync cadence in seconds. 0 = push-on-demand only (scheduler skips this target)."
                        },
                        "smb_username": {
                            field_type: FieldType::Str,
                            description: "Username for NTLM bind (smb only). Local SAM accounts work as bare `username`; AD accounts can be `DOMAIN\\\\username` or `username` + `smb_domain`."
                        },
                        "smb_password": {
                            field_type: FieldType::Str,
                            description: "Password for NTLM bind (smb only). Write-only on read; redacted in responses."
                        },
                        "smb_domain": {
                            field_type: FieldType::Str,
                            description: "Optional NetBIOS / AD domain for NTLM bind (smb only)."
                        },
                        "ssh_username": {
                            field_type: FieldType::Str,
                            description: "Username for SSH auth (sftp / scp). Alternative: `user@` in target_path."
                        },
                        "ssh_password": {
                            field_type: FieldType::Str,
                            description: "Password for SSH password-auth. Write-only on read."
                        },
                        "ssh_private_key": {
                            field_type: FieldType::Str,
                            description: "PEM-encoded SSH private key (OpenSSH / PKCS#8 / RFC 8410 / legacy RSA). Write-only on read."
                        },
                        "ssh_passphrase": {
                            field_type: FieldType::Str,
                            description: "Optional passphrase for an encrypted private key. Write-only on read."
                        },
                        "ssh_host_key_fingerprint": {
                            field_type: FieldType::Str,
                            description: "Pinned host-key fingerprint, OpenSSH SHA256:<base64> form. Empty = TOFU on first connect."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_sync_write.handle_sync_write},
                        {op: Operation::Delete, handler: h_sync_delete.handle_sync_delete}
                    ],
                    help: "Create, replace, or delete a sync target attached to a file."
                },
                {
                    // CRUD on a single file (metadata + content). `PUT`
                    // / `POST` replaces both; `DELETE` drops metadata
                    // + bytes + history.
                    pattern: r"files/(?P<id>[^/]+)$",
                    fields: {
                        "id": {
                            field_type: FieldType::Str,
                            required: true,
                            description: "File id."
                        },
                        "name": {
                            field_type: FieldType::Str,
                            description: "Human-readable file name."
                        },
                        "resource": {
                            field_type: FieldType::Str,
                            description: "Resource this file belongs to."
                        },
                        "mime_type": {
                            field_type: FieldType::Str,
                            description: "MIME type of the content."
                        },
                        "tags": {
                            field_type: FieldType::CommaStringSlice,
                            description: "Comma-separated tags."
                        },
                        "notes": {
                            field_type: FieldType::Str,
                            description: "Free-form notes."
                        },
                        "content_base64": {
                            field_type: FieldType::Str,
                            description: "Base64-encoded content bytes (required on write)."
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_read.handle_read},
                        {op: Operation::Write, handler: h_write.handle_write},
                        {op: Operation::Delete, handler: h_delete.handle_delete}
                    ],
                    help: "Read metadata, replace, or delete a file."
                }
            ],
            secrets: [{
                secret_type: "files",
                renew_handler: h_noop1.handle_noop,
                revoke_handler: h_noop2.handle_noop,
            }],
            help: FILES_BACKEND_HELP,
        });

        backend
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}

/// Record one entry in the admin-facing file audit log.
///
/// Failure to write the audit entry is logged and swallowed — we do
/// not want a write-through error on the audit side to block the
/// primary operation from succeeding, since the per-file history log
/// inside the mount still captures the event for the operator-facing
/// timeline. Matches the fail-soft pattern used for `UserAuditStore`
/// writes in `path_users.rs` / `path_role.rs`.
async fn record_file_audit(
    core: &Core,
    actor: &str,
    op: &str,
    file_id: &str,
    name: &str,
    details: &str,
) {
    let store = match FileAuditStore::from_core(core) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("file audit: could not open store: {e}");
            return;
        }
    };
    let entry = FileAuditEntry {
        ts: String::new(),
        actor_entity_id: actor.to_string(),
        op: op.to_string(),
        file_id: file_id.to_string(),
        name: name.to_string(),
        details: details.to_string(),
    };
    if let Err(e) = store.append(entry).await {
        log::warn!("file audit: append failed: {e}");
    }
}

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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn diff_field_names(old: Option<&FileEntry>, new: &FileEntry) -> Vec<String> {
    let mut changed: Vec<String> = Vec::new();
    macro_rules! cmp {
        ($field:ident) => {
            if !HIST_IGNORED_FIELDS.contains(&stringify!($field)) {
                let old_v = old.map(|e| &e.$field);
                let new_v = &new.$field;
                if old_v != Some(new_v) {
                    changed.push(stringify!($field).to_string());
                }
            }
        };
    }
    cmp!(name);
    cmp!(resource);
    cmp!(mime_type);
    cmp!(tags);
    cmp!(notes);
    changed.sort();
    changed.dedup();
    changed
}

/// Decode and length-check the caller's base64 content. Returns `Err`
/// with a clear message on malformed base64 or size overrun.
fn decode_content(content_b64: &str) -> Result<Vec<u8>, RvError> {
    if content_b64.is_empty() {
        return Err(RvError::ErrString(
            "content_base64 is required and must not be empty".into(),
        ));
    }
    let bytes = STANDARD
        .decode(content_b64.as_bytes())
        .map_err(|e| RvError::ErrString(format!("content_base64: invalid base64: {e}")))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(RvError::ErrString(format!(
            "content is {} bytes, exceeds hard cap of {} bytes",
            bytes.len(),
            MAX_FILE_BYTES
        )));
    }
    Ok(bytes)
}

fn get_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Write `bytes` to `target.target_path` on the local filesystem,
/// applying `target.mode` if non-empty. Returns a descriptive
/// `RvError::ErrString` on any IO / permission / parse error; the
/// caller records this into the file's sync-state record.
///
/// Creates parent directories as needed so operators don't need to
/// pre-create the directory structure. Writes atomically via a
/// Outcome of a successful sync push. The error case carries an
/// `RvError` directly via the `Result`, which is why this struct
/// only describes the success shape.
pub struct SyncPushOutcome {
    pub sha256: String,
}

/// Per-mount tick report. Surfaced to operators via the manual
/// `sync-tick` endpoint and to logs by the periodic scheduler.
#[derive(Debug, Clone, Default)]
pub struct SyncTickReport {
    pub attempted: u64,
    pub succeeded: u64,
    pub failed: u64,
    /// Targets considered by the sweep but not pushed this tick
    /// (auto_sync_interval_seconds == 0, or window not elapsed, or
    /// in backoff).
    pub skipped: u64,
}

/// Run one mount-wide sweep using the storage view bound to `req`.
/// Walks every file id, every sync target, and pushes each that is
/// due (`auto_sync_interval_seconds > 0` AND the window has elapsed
/// AND any backoff has cleared). Used by both the manual
/// `sync-tick` endpoint and the periodic scheduler — keeping a
/// single implementation guarantees the operator-driven and
/// scheduler-driven sweeps behave identically.
pub async fn run_sync_tick_for_storage(
    inner: &FilesBackendInner,
    req: &mut Request,
) -> Result<SyncTickReport, RvError> {
    let mut report = SyncTickReport::default();
    let now = unix_now();
    let file_ids = req.storage_list(META_PREFIX).await.unwrap_or_default();
    for id in file_ids {
        let target_prefix = format!("{SYNC_PREFIX}{id}/");
        let target_names = req.storage_list(&target_prefix).await.unwrap_or_default();
        for name in target_names {
            let cfg_key = format!("{SYNC_PREFIX}{id}/{name}");
            let target: FileSyncTarget = match req.storage_get(&cfg_key).await? {
                Some(e) => match serde_json::from_slice(&e.value) {
                    Ok(t) => t,
                    Err(_) => {
                        report.skipped += 1;
                        continue;
                    }
                },
                None => {
                    report.skipped += 1;
                    continue;
                }
            };
            if target.auto_sync_interval_seconds == 0 {
                report.skipped += 1;
                continue;
            }
            let state_key = format!("{SYNC_STATE_PREFIX}{id}/{name}");
            let state: FileSyncState = match req.storage_get(&state_key).await? {
                Some(e) => serde_json::from_slice(&e.value).unwrap_or_default(),
                None => FileSyncState::default(),
            };
            if !sync_target_due(now, target.auto_sync_interval_seconds, &state) {
                report.skipped += 1;
                continue;
            }
            report.attempted += 1;
            match inner.run_sync_push(req, &id, &name, "scheduler").await {
                Ok(_) => report.succeeded += 1,
                Err(e) => {
                    report.failed += 1;
                    log::warn!("files/sync: tick push {id}/{name} failed: {e:?}");
                }
            }
        }
    }
    Ok(report)
}

/// True when the scheduler should fire this target on the current
/// tick: cadence window elapsed AND any exponential-backoff window
/// has cleared. Pure function so the scheduler tests can drive it
/// without a mount.
pub fn sync_target_due(now: u64, interval_secs: u64, state: &FileSyncState) -> bool {
    if state.next_retry_at_unix > now {
        return false;
    }
    if state.last_attempt_at_unix == 0 {
        return true;
    }
    now.saturating_sub(state.last_attempt_at_unix) >= interval_secs
}

/// Dispatch a push by transport kind. Single source of truth shared
/// by the manual handler, the `sync_on_write` inline-push path, and
/// the periodic scheduler.
fn dispatch_push(target: &FileSyncTarget, bytes: &[u8]) -> Result<(), RvError> {
    match target.kind.as_str() {
        "local-fs" => push_local_fs(target, bytes),
        "smb" => {
            #[cfg(feature = "files_smb")]
            {
                crate::modules::files::smb::push_smb(target, bytes)
            }
            #[cfg(not(feature = "files_smb"))]
            {
                Err(RvError::ErrString(
                    "sync target kind `smb` requires building with --features files_smb".into(),
                ))
            }
        }
        "sftp" => {
            #[cfg(feature = "files_ssh_sync")]
            {
                crate::modules::files::ssh_sync::push_sftp(target, bytes)
            }
            #[cfg(not(feature = "files_ssh_sync"))]
            {
                Err(RvError::ErrString(
                    "sync target kind `sftp` requires building with --features files_ssh_sync"
                        .into(),
                ))
            }
        }
        "scp" => {
            #[cfg(feature = "files_ssh_sync")]
            {
                crate::modules::files::ssh_sync::push_scp(target, bytes)
            }
            #[cfg(not(feature = "files_ssh_sync"))]
            {
                Err(RvError::ErrString(
                    "sync target kind `scp` requires building with --features files_ssh_sync"
                        .into(),
                ))
            }
        }
        other => Err(RvError::ErrString(format!(
            "sync target kind `{other}` is not supported yet"
        ))),
    }
}

/// Maximum backoff after a streak of failed pushes — 15 minutes.
/// Picked so a target that's been broken for hours isn't slamming
/// the network every tick, while still recovering reasonably quickly
/// once the underlying issue is fixed.
const MAX_BACKOFF_SECS: u64 = 15 * 60;

/// Exponential backoff: `2^failures` seconds, capped at
/// `MAX_BACKOFF_SECS`. First failure waits 2s before the next
/// scheduler-driven retry; tenth failure caps at 15 minutes.
pub fn backoff_secs(consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    let shift = consecutive_failures.min(20); // u64 wraparound guard
    let candidate = 1u64
        .checked_shl(shift)
        .unwrap_or(MAX_BACKOFF_SECS);
    candidate.min(MAX_BACKOFF_SECS)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `<path>.<pid>.tmp` + rename so a concurrent reader of the target
/// never sees a partially-written file.
fn push_local_fs(target: &FileSyncTarget, bytes: &[u8]) -> Result<(), RvError> {
    use std::{fs, io::Write, path::PathBuf};
    if target.target_path.trim().is_empty() {
        return Err(RvError::ErrString("target_path is empty".into()));
    }
    let dest = PathBuf::from(&target.target_path);
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| RvError::ErrString(format!("create_dir_all({}): {e}", parent.display())))?;
        }
    }
    let tmp = dest.with_extension(format!("bvsync.{}.tmp", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| RvError::ErrString(format!("create({}): {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| RvError::ErrString(format!("write({}): {e}", tmp.display())))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, &dest)
        .map_err(|e| RvError::ErrString(format!("rename({} -> {}): {e}", tmp.display(), dest.display())))?;

    if !target.mode.is_empty() {
        apply_unix_mode(&dest, &target.mode)?;
    }
    Ok(())
}

#[cfg(unix)]
fn apply_unix_mode(path: &std::path::Path, mode: &str) -> Result<(), RvError> {
    use std::{fs, os::unix::fs::PermissionsExt};
    let trimmed = mode.trim_start_matches("0o").trim_start_matches('0');
    let m = if trimmed.is_empty() {
        0
    } else {
        u32::from_str_radix(trimmed, 8)
            .map_err(|e| RvError::ErrString(format!("invalid mode `{mode}`: {e}")))?
    };
    let perms = fs::Permissions::from_mode(m);
    fs::set_permissions(path, perms)
        .map_err(|e| RvError::ErrString(format!("chmod({}): {e}", path.display())))
}

#[cfg(not(unix))]
fn apply_unix_mode(_path: &std::path::Path, _mode: &str) -> Result<(), RvError> {
    // On Windows the `mode` field is advisory and skipped. Operators
    // who need ACLs should manage them out-of-band.
    Ok(())
}

fn get_tags(req: &Request) -> Vec<String> {
    // `CommaStringSlice` resolves to a JSON array of strings at the
    // field layer, but callers can also pass a plain comma string; be
    // lenient in both directions.
    match req.get_data("tags") {
        Ok(Value::Array(a)) => a
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        Ok(Value::String(s)) => s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

// ── Handlers ───────────────────────────────────────────────────────

#[maybe_async::maybe_async]
impl FilesBackendInner {
    pub async fn handle_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list(META_PREFIX).await?;
        Ok(Some(Response::list_response(&keys)))
    }

    pub async fn handle_create(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let content_b64 = get_str(req, "content_base64");
        let bytes = decode_content(&content_b64)?;

        let id = generate_uuid();
        let now = now_rfc3339();

        let entry = FileEntry {
            id: id.clone(),
            name: get_str(req, "name"),
            resource: get_str(req, "resource"),
            mime_type: get_str(req, "mime_type"),
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            tags: get_tags(req),
            notes: get_str(req, "notes"),
            created_at: now.clone(),
            updated_at: now,
        };

        self.write_entry_and_blob(req, &id, &entry, &bytes, None, "create").await?;

        // Stamp ownership inline — post_route cannot because the new
        // id is only known here. Uses the same caller_audit_actor
        // fallback as KV / resource owners so root-token writes stamp
        // `"root"` rather than orphan the record.
        let audit_actor = crate::modules::identity::caller_audit_actor(req);
        if !audit_actor.is_empty() {
            if let Some(core) = self.core.self_ptr.upgrade() {
                if let Some(identity) = core
                    .module_manager
                    .get_module::<crate::modules::identity::IdentityModule>("identity")
                {
                    if let Some(owner_store) = identity.owner_store() {
                        let _ = owner_store
                            .record_file_owner_if_absent(&id, &audit_actor)
                            .await;
                    }
                }
            }
        }

        // Admin audit log — parallel to the per-file history write
        // in `write_entry_and_blob`. Uses the same caller_audit_actor
        // fallback so root-token writes show up as `"root"`.
        if let Some(core) = self.core.self_ptr.upgrade() {
            record_file_audit(&core, &audit_actor, "create", &id, &entry.name, "").await;
        }

        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("size_bytes".into(), Value::from(entry.size_bytes));
        data.insert("sha256".into(), Value::String(entry.sha256));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        match self.load_entry(req, &id).await? {
            Some(entry) => {
                let data = serde_json::to_value(&entry)?
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn handle_content_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let Some(entry) = self.load_entry(req, &id).await? else {
            return Ok(None);
        };
        let blob_key = format!("{BLOB_PREFIX}{id}");
        let blob = req
            .storage_get(&blob_key)
            .await?
            .ok_or(RvError::ErrResponse(
                "file content missing from storage".into(),
            ))?;

        // Integrity check: the metadata's SHA-256 must match the blob
        // we just read. A mismatch here means either storage corruption
        // or an out-of-band write; surface it as an error rather than
        // returning potentially-wrong bytes.
        let computed = sha256_hex(&blob.value);
        if !entry.sha256.is_empty() && computed != entry.sha256 {
            return Err(RvError::ErrString(format!(
                "file {id}: content hash mismatch (metadata={}, actual={})",
                entry.sha256, computed
            )));
        }

        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("mime_type".into(), Value::String(entry.mime_type));
        data.insert("size_bytes".into(), Value::from(entry.size_bytes));
        data.insert(
            "content_base64".into(),
            Value::String(STANDARD.encode(&blob.value)),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let content_b64 = get_str(req, "content_base64");
        let bytes = decode_content(&content_b64)?;

        let previous = self.load_entry(req, &id).await?;

        let now = now_rfc3339();
        let created_at = previous
            .as_ref()
            .map(|e| e.created_at.clone())
            .unwrap_or_else(|| now.clone());

        // For a metadata field that the caller omitted, fall back to
        // the previous value so `PUT` with only `content_base64` works
        // as "replace content, keep metadata". Empty-string on a first
        // write just stays empty.
        let merge_str = |new: &str, old: Option<&str>| -> String {
            if !new.is_empty() {
                new.to_string()
            } else {
                old.unwrap_or("").to_string()
            }
        };
        let new_tags_raw = get_tags(req);
        let tags = if !new_tags_raw.is_empty() || previous.is_none() {
            new_tags_raw
        } else {
            previous.as_ref().map(|e| e.tags.clone()).unwrap_or_default()
        };

        let entry = FileEntry {
            id: id.clone(),
            name: merge_str(
                &get_str(req, "name"),
                previous.as_ref().map(|e| e.name.as_str()),
            ),
            resource: merge_str(
                &get_str(req, "resource"),
                previous.as_ref().map(|e| e.resource.as_str()),
            ),
            mime_type: merge_str(
                &get_str(req, "mime_type"),
                previous.as_ref().map(|e| e.mime_type.as_str()),
            ),
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            tags,
            notes: merge_str(
                &get_str(req, "notes"),
                previous.as_ref().map(|e| e.notes.as_str()),
            ),
            created_at,
            updated_at: now,
        };
        let op_label = if previous.is_some() { "update" } else { "create" };

        self.write_entry_and_blob(
            req,
            &id,
            &entry,
            &bytes,
            previous.as_ref(),
            op_label,
        )
        .await?;

        // Admin audit log. Summarize the change set the same way the
        // per-file history does: metadata field names + "content" when
        // the hash moved. Record nothing on a no-op write (same
        // fields, same SHA) so the audit page stays signal-heavy.
        if let Some(core) = self.core.self_ptr.upgrade() {
            let actor = crate::modules::identity::caller_audit_actor(req);
            let mut changed = diff_field_names(previous.as_ref(), &entry);
            let content_changed = previous
                .as_ref()
                .map(|p| p.sha256 != entry.sha256)
                .unwrap_or(false);
            if content_changed {
                changed.push("content".to_string());
                changed.sort();
                changed.dedup();
            }
            if op_label == "create" || !changed.is_empty() {
                let details = if changed.is_empty() {
                    String::new()
                } else {
                    format!("fields={}", changed.join(","))
                };
                record_file_audit(&core, &actor, op_label, &id, &entry.name, &details).await;
            }
        }

        // sync_on_write: fire an inline push to every target whose
        // flag is set. Failure does NOT roll back the content write
        // (the bytes are already persisted) — the failure lands on
        // the target's FileSyncState and the next periodic tick
        // retries with backoff. We surface the per-target outcome
        // in the response so an operator-driven write knows whether
        // the inline push succeeded without a separate poll.
        let inline_pushes = self.run_sync_on_write(req, &id).await;

        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("size_bytes".into(), Value::from(entry.size_bytes));
        data.insert("sha256".into(), Value::String(entry.sha256));
        if !inline_pushes.is_empty() {
            data.insert(
                "sync_on_write".into(),
                Value::Array(
                    inline_pushes
                        .into_iter()
                        .map(|(name, ok, err)| {
                            let mut o = Map::new();
                            o.insert("name".into(), Value::String(name));
                            o.insert("ok".into(), Value::Bool(ok));
                            if let Some(e) = err {
                                o.insert("error".into(), Value::String(e));
                            }
                            Value::Object(o)
                        })
                        .collect(),
                ),
            );
        }
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Run the inline `sync_on_write` push for every target on this
    /// file that has the flag set. Returns one tuple per target:
    /// `(name, ok, optional_error_message)`. Never errors — the
    /// caller carries the report into the response so the operator
    /// sees per-target outcomes, but no individual transport failure
    /// rolls back the file write that just happened.
    pub async fn run_sync_on_write(
        &self,
        req: &mut Request,
        id: &str,
    ) -> Vec<(String, bool, Option<String>)> {
        let mut out: Vec<(String, bool, Option<String>)> = Vec::new();
        let prefix = format!("{SYNC_PREFIX}{id}/");
        let names = match req.storage_list(&prefix).await {
            Ok(v) => v,
            Err(_) => return out,
        };
        for name in names {
            let cfg_key = format!("{SYNC_PREFIX}{id}/{name}");
            let target: FileSyncTarget = match req.storage_get(&cfg_key).await {
                Ok(Some(e)) => match serde_json::from_slice(&e.value) {
                    Ok(t) => t,
                    Err(_) => continue,
                },
                _ => continue,
            };
            if !target.sync_on_write {
                continue;
            }
            match self.run_sync_push(req, id, &name, "on_write").await {
                Ok(_) => out.push((name, true, None)),
                Err(e) => out.push((name, false, Some(format!("{e}")))),
            }
        }
        out
    }

    pub async fn handle_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");

        // Snapshot the name before wiping metadata so the admin
        // audit entry still has a usable label after the delete.
        let name_snapshot = self
            .load_entry(req, &id)
            .await
            .ok()
            .flatten()
            .map(|e| e.name)
            .unwrap_or_default();

        // Record the delete in the history log *before* wiping the
        // metadata — consistent with the resource module. The entry
        // stays available until the `hist/<id>/` prefix is purged.
        let hist = FileHistoryEntry {
            ts: now_rfc3339(),
            user: caller_username(req),
            op: "delete".to_string(),
            changed_fields: Vec::new(),
        };
        let hist_key = format!("{HIST_PREFIX}{id}/{}", hist_seq());
        let hist_entry = StorageEntry {
            key: hist_key,
            value: serde_json::to_string(&hist)?.into_bytes(),
        };
        req.storage_put(&hist_entry).await?;

        let meta_key = format!("{META_PREFIX}{id}");
        let blob_key = format!("{BLOB_PREFIX}{id}");
        req.storage_delete(&meta_key).await?;
        req.storage_delete(&blob_key).await?;

        // Clean up any sync-target configs + sync-state records so a
        // later file with the same id (unlikely with UUIDs, but
        // deterministic) wouldn't inherit stale sync history. Uses
        // `storage_list` to enumerate because there's no "delete
        // prefix" primitive on the view. Errors are logged and
        // swallowed — the file delete itself already succeeded, and
        // leaving a dangling sync record never widens access.
        let sync_prefix = format!("{SYNC_PREFIX}{id}/");
        if let Ok(names) = req.storage_list(&sync_prefix).await {
            for n in names {
                let _ = req.storage_delete(&format!("{sync_prefix}{n}")).await;
            }
        }
        let state_prefix = format!("{SYNC_STATE_PREFIX}{id}/");
        if let Ok(names) = req.storage_list(&state_prefix).await {
            for n in names {
                let _ = req.storage_delete(&format!("{state_prefix}{n}")).await;
            }
        }

        // Version index + historical blobs. Same contract as sync
        // records: errors during the sweep are logged implicitly
        // (swallowed here) because the file delete already succeeded,
        // and a dangling version blob can never widen access — its
        // owner/share records are gone.
        let _ = req.storage_delete(&format!("{VMETA_PREFIX}{id}")).await;
        let vblob_prefix = format!("{VBLOB_PREFIX}{id}/");
        if let Ok(names) = req.storage_list(&vblob_prefix).await {
            for n in names {
                let _ = req.storage_delete(&format!("{vblob_prefix}{n}")).await;
            }
        }

        // Admin audit.
        if let Some(core) = self.core.self_ptr.upgrade() {
            let actor = crate::modules::identity::caller_audit_actor(req);
            record_file_audit(&core, &actor, "delete", &id, &name_snapshot, "").await;
        }

        Ok(None)
    }

    pub async fn handle_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let prefix = format!("{HIST_PREFIX}{id}/");
        let keys = req.storage_list(&prefix).await?;

        let mut entries: Vec<FileHistoryEntry> = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(se) = req.storage_get(&full).await? {
                if let Ok(h) = serde_json::from_slice::<FileHistoryEntry>(&se.value) {
                    entries.push(h);
                }
            }
        }
        // Newest first (hist keys sort oldest-first by construction).
        entries.reverse();

        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("entries".into(), serde_json::to_value(&entries)?);
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_sync_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let prefix = format!("{SYNC_PREFIX}{id}/");
        let names = req.storage_list(&prefix).await?;

        let mut targets: Vec<Map<String, Value>> = Vec::with_capacity(names.len());
        for n in &names {
            let key = format!("{prefix}{n}");
            if let Some(se) = req.storage_get(&key).await? {
                if let Ok(t) = serde_json::from_slice::<FileSyncTarget>(&se.value) {
                    let mut entry =
                        serde_json::to_value(&t)?.as_object().cloned().unwrap_or_default();
                    // Never re-disclose secret-shaped fields; surface
                    // booleans so the GUI can show "set / not set"
                    // without round-tripping the secret.
                    let smb_pw_set = !t.smb_password.is_empty();
                    let ssh_pw_set = !t.ssh_password.is_empty();
                    let ssh_key_set = !t.ssh_private_key.is_empty();
                    let ssh_passphrase_set = !t.ssh_passphrase.is_empty();
                    entry.remove("smb_password");
                    entry.remove("ssh_password");
                    entry.remove("ssh_private_key");
                    entry.remove("ssh_passphrase");
                    entry.insert("smb_password_set".into(), Value::Bool(smb_pw_set));
                    entry.insert("ssh_password_set".into(), Value::Bool(ssh_pw_set));
                    entry.insert("ssh_private_key_set".into(), Value::Bool(ssh_key_set));
                    entry.insert(
                        "ssh_passphrase_set".into(),
                        Value::Bool(ssh_passphrase_set),
                    );
                    // Attach state so the GUI doesn't need a second call.
                    let state_key = format!("{SYNC_STATE_PREFIX}{id}/{n}");
                    let state: FileSyncState = match req.storage_get(&state_key).await? {
                        Some(ss) => serde_json::from_slice(&ss.value).unwrap_or_default(),
                        None => FileSyncState::default(),
                    };
                    entry.insert(
                        "state".into(),
                        serde_json::to_value(&state).unwrap_or(Value::Null),
                    );
                    targets.push(entry);
                }
            }
        }

        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert(
            "targets".into(),
            Value::Array(targets.into_iter().map(Value::Object).collect()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_sync_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let name = get_str(req, "name");
        if id.trim().is_empty() || name.trim().is_empty() {
            return Err(RvError::ErrString("id and name are required".into()));
        }
        let kind = get_str(req, "kind");
        let target_path = get_str(req, "target_path");
        let mode = get_str(req, "mode");
        let sync_on_write = req
            .get_data("sync_on_write")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let auto_sync_interval_seconds = req
            .get_data("auto_sync_interval_seconds")
            .ok()
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let smb_username = get_str(req, "smb_username");
        let smb_password = get_str(req, "smb_password");
        let smb_domain = get_str(req, "smb_domain");
        let ssh_username = get_str(req, "ssh_username");
        let ssh_password = get_str(req, "ssh_password");
        let ssh_private_key = get_str(req, "ssh_private_key");
        let ssh_passphrase = get_str(req, "ssh_passphrase");
        let ssh_host_key_fingerprint = get_str(req, "ssh_host_key_fingerprint");

        if kind.is_empty() || target_path.is_empty() {
            return Err(RvError::ErrString(
                "kind and target_path are required".into(),
            ));
        }
        // Validate kind up front so operators don't save configs that
        // fail later. `local-fs` and `smb` are supported; SCP / SFTP
        // remain Phase 6 follow-ons.
        match kind.as_str() {
            "local-fs" => {}
            "smb" => {
                if smb_username.trim().is_empty() {
                    return Err(RvError::ErrString(
                        "smb: smb_username is required when kind = smb".into(),
                    ));
                }
                if smb_password.is_empty() {
                    return Err(RvError::ErrString(
                        "smb: smb_password is required when kind = smb".into(),
                    ));
                }
                // Validate the URL shape now so the operator gets an
                // immediate config error instead of a push-time
                // failure later.
                #[cfg(feature = "files_smb")]
                {
                    let _ = super::files::smb::validate_target_path(&target_path)?;
                }
                // When the build doesn't include `files_smb`, we
                // still accept `kind = "smb"` so configs round-trip
                // across builds with different feature sets — the
                // push handler emits the not-compiled-in error.
            }
            "sftp" | "scp" => {
                if ssh_username.trim().is_empty() && !target_path.contains('@') {
                    return Err(RvError::ErrString(format!(
                        "{kind}: ssh_username (or user@ in URL) is required"
                    )));
                }
                if ssh_password.is_empty() && ssh_private_key.is_empty() {
                    return Err(RvError::ErrString(format!(
                        "{kind}: at least one of ssh_password / ssh_private_key is required"
                    )));
                }
                #[cfg(feature = "files_ssh_sync")]
                {
                    if kind == "sftp" {
                        super::files::ssh_sync::validate_target_path_sftp(&target_path)?;
                    } else {
                        super::files::ssh_sync::validate_target_path_scp(&target_path)?;
                    }
                }
                // Same pattern as smb: configs round-trip across
                // builds; the push handler emits the not-compiled-in
                // error if the feature is off.
            }
            other => {
                return Err(RvError::ErrString(format!(
                    "sync target kind `{other}` is not supported yet; available: local-fs, smb, sftp, scp"
                )));
            }
        }

        // The file must exist — don't create dangling sync records.
        if self.load_entry(req, &id).await?.is_none() {
            return Err(RvError::ErrString(format!("file {id} not found")));
        }

        let now = now_rfc3339();
        let existing_key = format!("{SYNC_PREFIX}{id}/{name}");
        let created_at = match req.storage_get(&existing_key).await? {
            Some(se) => serde_json::from_slice::<FileSyncTarget>(&se.value)
                .map(|t| t.created_at)
                .unwrap_or_else(|_| now.clone()),
            None => now.clone(),
        };

        // Preserve the existing barrier-encrypted secret fields if
        // the operator did not supply new values — same
        // write-only-on-update pattern the LDAP engine uses for
        // `bindpass`. We do this for every secret-shaped field
        // across every transport in one pass so the read API can
        // safely redact the lot.
        let existing_target: Option<FileSyncTarget> = req
            .storage_get(&existing_key)
            .await?
            .and_then(|se| serde_json::from_slice::<FileSyncTarget>(&se.value).ok());
        let smb_password = if smb_password.is_empty() {
            existing_target
                .as_ref()
                .map(|t| t.smb_password.clone())
                .unwrap_or_default()
        } else {
            smb_password
        };
        let ssh_password = if ssh_password.is_empty() {
            existing_target
                .as_ref()
                .map(|t| t.ssh_password.clone())
                .unwrap_or_default()
        } else {
            ssh_password
        };
        let ssh_private_key = if ssh_private_key.is_empty() {
            existing_target
                .as_ref()
                .map(|t| t.ssh_private_key.clone())
                .unwrap_or_default()
        } else {
            ssh_private_key
        };
        let ssh_passphrase = if ssh_passphrase.is_empty() {
            existing_target
                .as_ref()
                .map(|t| t.ssh_passphrase.clone())
                .unwrap_or_default()
        } else {
            ssh_passphrase
        };

        let target = FileSyncTarget {
            name: name.clone(),
            kind,
            target_path,
            auto_sync_interval_seconds,
            smb_username,
            smb_password,
            smb_domain,
            ssh_username,
            ssh_password,
            ssh_private_key,
            ssh_passphrase,
            ssh_host_key_fingerprint,
            mode,
            sync_on_write,
            created_at,
            updated_at: now,
        };
        let entry = StorageEntry {
            key: existing_key,
            value: serde_json::to_vec(&target)?,
        };
        req.storage_put(&entry).await?;
        Ok(None)
    }

    pub async fn handle_sync_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let name = get_str(req, "name");
        let key = format!("{SYNC_PREFIX}{id}/{name}");
        let state_key = format!("{SYNC_STATE_PREFIX}{id}/{name}");
        req.storage_delete(&key).await?;
        req.storage_delete(&state_key).await?;
        Ok(None)
    }

    /// Manual scheduler tick. Same sweep the periodic scheduler
    /// runs, but on demand. Returns the count of pushes attempted /
    /// succeeded / failed for operator visibility.
    pub async fn handle_sync_tick(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let report = run_sync_tick_for_storage(self, req).await?;
        let mut data = Map::new();
        data.insert("attempted".into(), Value::Number(report.attempted.into()));
        data.insert("succeeded".into(), Value::Number(report.succeeded.into()));
        data.insert("failed".into(), Value::Number(report.failed.into()));
        data.insert("skipped".into(), Value::Number(report.skipped.into()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_sync_push(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let name = get_str(req, "name");
        if id.trim().is_empty() || name.trim().is_empty() {
            return Err(RvError::ErrString("id and name are required".into()));
        }
        let outcome = self.run_sync_push(req, &id, &name, "manual").await?;
        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("name".into(), Value::String(name));
        data.insert("status".into(), Value::String("pushed".into()));
        data.insert("sha256".into(), Value::String(outcome.sha256));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Reusable push-and-update-state helper. Used by the manual
    /// `POST /sync/<name>/push` endpoint, by the `sync_on_write`
    /// inline-push path on file content updates, and by the periodic
    /// scheduler tick. `source` is recorded on the state record so an
    /// operator can tell which path produced the most recent attempt.
    pub async fn run_sync_push(
        &self,
        req: &mut Request,
        id: &str,
        name: &str,
        source: &str,
    ) -> Result<SyncPushOutcome, RvError> {
        let cfg_key = format!("{SYNC_PREFIX}{id}/{name}");
        let Some(cfg_raw) = req.storage_get(&cfg_key).await? else {
            return Err(RvError::ErrString(format!(
                "sync target `{name}` not configured for file {id}"
            )));
        };
        let target: FileSyncTarget = serde_json::from_slice(&cfg_raw.value)?;

        let entry = self
            .load_entry(req, id)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("file {id} not found")))?;
        let blob = req
            .storage_get(&format!("{BLOB_PREFIX}{id}"))
            .await?
            .ok_or_else(|| RvError::ErrString("file content missing".into()))?;

        let state_key = format!("{SYNC_STATE_PREFIX}{id}/{name}");
        let mut state: FileSyncState = match req.storage_get(&state_key).await? {
            Some(ss) => serde_json::from_slice(&ss.value).unwrap_or_default(),
            None => FileSyncState::default(),
        };

        let push_result = dispatch_push(&target, &blob.value);
        let now_rfc = now_rfc3339();
        let now_unix = unix_now();
        state.last_attempt_at_unix = now_unix;
        state.last_attempt_source = source.to_string();
        match push_result {
            Ok(()) => {
                state.last_success_at = now_rfc;
                state.last_success_sha256 = entry.sha256.clone();
                state.last_error.clear();
                state.last_failure_at.clear();
                state.consecutive_failures = 0;
                state.next_retry_at_unix = 0;
                let ss = StorageEntry {
                    key: state_key,
                    value: serde_json::to_vec(&state)?,
                };
                req.storage_put(&ss).await?;
                Ok(SyncPushOutcome {
                    sha256: entry.sha256,
                })
            }
            Err(e) => {
                state.last_failure_at = now_rfc;
                state.last_error = e.to_string();
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.next_retry_at_unix =
                    now_unix.saturating_add(backoff_secs(state.consecutive_failures));
                let ss = StorageEntry {
                    key: state_key,
                    value: serde_json::to_vec(&state)?,
                };
                // Record failure state before surfacing the error so
                // the GUI's Sync tab + the scheduler's next decision
                // both see the latest attempt outcome.
                let _ = req.storage_put(&ss).await;
                Err(e)
            }
        }
    }

    pub async fn handle_versions_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let vmeta = self.load_version_meta(req, &id).await?;
        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("current_version".into(), Value::from(vmeta.current_version));
        data.insert("versions".into(), serde_json::to_value(&vmeta.versions)?);
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_version_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let version: u64 = get_str(req, "version")
            .parse()
            .map_err(|_| RvError::ErrString("version must be a positive integer".into()))?;
        let vmeta = self.load_version_meta(req, &id).await?;
        let Some(v) = vmeta.versions.iter().find(|v| v.version == version) else {
            return Ok(None);
        };
        let data = serde_json::to_value(v)?
            .as_object()
            .cloned()
            .unwrap_or_default();
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_version_content_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let version: u64 = get_str(req, "version")
            .parse()
            .map_err(|_| RvError::ErrString("version must be a positive integer".into()))?;
        let vmeta = self.load_version_meta(req, &id).await?;
        let Some(info) = vmeta.versions.iter().find(|v| v.version == version).cloned()
        else {
            return Ok(None);
        };
        let blob_key = format!("{VBLOB_PREFIX}{id}/{version:020}");
        let blob = req
            .storage_get(&blob_key)
            .await?
            .ok_or(RvError::ErrString(
                "historical content missing from storage".into(),
            ))?;
        // Integrity: recompute and compare against the recorded hash.
        let computed = sha256_hex(&blob.value);
        if computed != info.sha256 {
            return Err(RvError::ErrString(format!(
                "file {id} version {version}: content hash mismatch (metadata={}, actual={computed})",
                info.sha256
            )));
        }
        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("version".into(), Value::from(version));
        data.insert("mime_type".into(), Value::String(info.mime_type));
        data.insert("size_bytes".into(), Value::from(info.size_bytes));
        data.insert(
            "content_base64".into(),
            Value::String(STANDARD.encode(&blob.value)),
        );
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_version_restore(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let id = get_str(req, "id");
        let version: u64 = get_str(req, "version")
            .parse()
            .map_err(|_| RvError::ErrString("version must be a positive integer".into()))?;

        let vmeta = self.load_version_meta(req, &id).await?;
        let Some(info) = vmeta.versions.iter().find(|v| v.version == version).cloned()
        else {
            return Err(RvError::ErrString(format!(
                "no version {version} retained for file {id}"
            )));
        };
        let blob_key = format!("{VBLOB_PREFIX}{id}/{version:020}");
        let blob = req
            .storage_get(&blob_key)
            .await?
            .ok_or(RvError::ErrString(
                "historical content missing from storage".into(),
            ))?;

        // Build the restored FileEntry by combining the current
        // metadata (to preserve tags / notes / resource / name as they
        // are today) with the restored version's size_bytes / sha256
        // / mime_type. Name from the snapshot is informational only —
        // we keep the current name to avoid surprise renames on
        // restore. Operators who want the old name can rename after.
        let previous = self.load_entry(req, &id).await?.ok_or_else(|| {
            RvError::ErrString(format!("file {id} not found"))
        })?;
        let now = now_rfc3339();
        let restored = FileEntry {
            id: previous.id.clone(),
            name: previous.name.clone(),
            resource: previous.resource.clone(),
            mime_type: if !info.mime_type.is_empty() {
                info.mime_type.clone()
            } else {
                previous.mime_type.clone()
            },
            size_bytes: info.size_bytes,
            sha256: info.sha256.clone(),
            tags: previous.tags.clone(),
            notes: previous.notes.clone(),
            created_at: previous.created_at.clone(),
            updated_at: now,
        };
        // Piggyback on the regular write path so the displaced
        // content is itself snapshotted (restore is reversible).
        self.write_entry_and_blob(req, &id, &restored, &blob.value, Some(&previous), "restore")
            .await?;

        // Admin audit — include the version number so the operator
        // can see which snapshot was promoted.
        if let Some(core) = self.core.self_ptr.upgrade() {
            let actor = crate::modules::identity::caller_audit_actor(req);
            let details = format!("version=v{version}");
            record_file_audit(&core, &actor, "restore", &id, &restored.name, &details).await;
        }

        let mut data = Map::new();
        data.insert("id".into(), Value::String(id));
        data.insert("restored_version".into(), Value::from(version));
        data.insert("sha256".into(), Value::String(restored.sha256));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_noop(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    // ── Internal helpers on the backend (not route handlers) ──────

    async fn load_entry(
        &self,
        req: &mut Request,
        id: &str,
    ) -> Result<Option<FileEntry>, RvError> {
        let meta_key = format!("{META_PREFIX}{id}");
        match req.storage_get(&meta_key).await? {
            Some(se) => Ok(Some(serde_json::from_slice(&se.value)?)),
            None => Ok(None),
        }
    }

    async fn load_version_meta(
        &self,
        req: &mut Request,
        id: &str,
    ) -> Result<FileVersionMeta, RvError> {
        let key = format!("{VMETA_PREFIX}{id}");
        match req.storage_get(&key).await? {
            Some(se) => Ok(serde_json::from_slice(&se.value).unwrap_or_default()),
            None => Ok(FileVersionMeta::default()),
        }
    }

    async fn save_version_meta(
        &self,
        req: &mut Request,
        id: &str,
        meta: &FileVersionMeta,
    ) -> Result<(), RvError> {
        let entry = StorageEntry {
            key: format!("{VMETA_PREFIX}{id}"),
            value: serde_json::to_vec(meta)?,
        };
        req.storage_put(&entry).await
    }

    /// Snapshot the current-on-disk content + metadata of a file into
    /// a new historical version, then prune older versions beyond the
    /// retention window. Called from `write_entry_and_blob` before an
    /// update overwrites the live blob.
    async fn snapshot_current_as_version(
        &self,
        req: &mut Request,
        id: &str,
        prev: &FileEntry,
        blob: &[u8],
        user: String,
    ) -> Result<(), RvError> {
        let mut vmeta = self.load_version_meta(req, id).await?;
        // Assign a monotonically increasing version number. The
        // `current_version` field tracks the *live* version (1-based
        // after the first update); snapshots get the version the old
        // content *used to be*.
        if vmeta.current_version == 0 {
            // First-ever snapshot: the pre-existing blob was v1.
            vmeta.current_version = 1;
        }
        let snapshot_version = vmeta.current_version;
        let next_version = snapshot_version + 1;

        // Write the displaced blob under its version key.
        let blob_key = format!("{VBLOB_PREFIX}{id}/{snapshot_version:020}");
        let blob_entry = StorageEntry { key: blob_key, value: blob.to_vec() };
        req.storage_put(&blob_entry).await?;

        // Record the snapshot in the version index.
        vmeta.versions.push(FileVersionInfo {
            version: snapshot_version,
            size_bytes: prev.size_bytes,
            sha256: prev.sha256.clone(),
            name: prev.name.clone(),
            mime_type: prev.mime_type.clone(),
            created_at: prev.updated_at.clone(),
            user,
        });
        vmeta.current_version = next_version;

        // Prune. Versions are appended in order, so the oldest are at
        // the front. Keep the newest `DEFAULT_VERSION_RETENTION`.
        while vmeta.versions.len() > DEFAULT_VERSION_RETENTION {
            let dropped = vmeta.versions.remove(0);
            let _ = req
                .storage_delete(&format!(
                    "{VBLOB_PREFIX}{id}/{:020}",
                    dropped.version
                ))
                .await;
        }

        self.save_version_meta(req, id, &vmeta).await
    }

    async fn write_entry_and_blob(
        &self,
        req: &mut Request,
        id: &str,
        entry: &FileEntry,
        bytes: &[u8],
        previous: Option<&FileEntry>,
        op: &str,
    ) -> Result<(), RvError> {
        let meta_key = format!("{META_PREFIX}{id}");
        let blob_key = format!("{BLOB_PREFIX}{id}");

        // On update: snapshot the current-on-disk blob + metadata into
        // a new historical version *before* overwriting. `previous`
        // carries the metadata state; we pull the live blob straight
        // from storage so a concurrent read-through-cache doesn't
        // return stale bytes. Versioning is skipped entirely on create,
        // and when the content hash matches (a metadata-only write).
        if let Some(prev) = previous {
            let content_changed = prev.sha256 != entry.sha256;
            if content_changed && DEFAULT_VERSION_RETENTION > 0 {
                if let Some(old_blob) = req.storage_get(&blob_key).await? {
                    self.snapshot_current_as_version(
                        req,
                        id,
                        prev,
                        &old_blob.value,
                        caller_username(req),
                    )
                    .await?;
                }
            }
        }

        let meta_entry = StorageEntry {
            key: meta_key,
            value: serde_json::to_vec(entry)?,
        };
        req.storage_put(&meta_entry).await?;

        let blob_entry = StorageEntry {
            key: blob_key,
            value: bytes.to_vec(),
        };
        req.storage_put(&blob_entry).await?;

        // History: always record on create; on update only when
        // something moved or the content hash changed. Content movement
        // surfaces as "content" in `changed_fields` so the timeline
        // reflects that even when no metadata edit happened.
        let mut changed = diff_field_names(previous, entry);
        let content_changed = previous
            .map(|p| p.sha256 != entry.sha256)
            .unwrap_or(false);
        if content_changed {
            changed.push("content".to_string());
            changed.sort();
            changed.dedup();
        }
        let record = op == "create" || !changed.is_empty();
        if record {
            let hist = FileHistoryEntry {
                ts: now_rfc3339(),
                user: caller_username(req),
                op: op.to_string(),
                changed_fields: changed,
            };
            let hist_key = format!("{HIST_PREFIX}{id}/{}", hist_seq());
            let hist_entry = StorageEntry {
                key: hist_key,
                value: serde_json::to_vec(&hist)?,
            };
            req.storage_put(&hist_entry).await?;
        }

        Ok(())
    }
}

// ── Module registration ────────────────────────────────────────────

impl FilesModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self { name: "files".to_string(), backend: Arc::new(FilesBackend::new(core)) }
    }
}

impl Module for FilesModule {
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
        core.add_logical_backend("files", Arc::new(backend_new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("files")
    }
}

// ── Unit tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_deterministic_and_lowercase() {
        let a = sha256_hex(b"");
        // Known SHA-256 of the empty string.
        assert_eq!(
            a,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn decode_content_rejects_empty_and_oversized() {
        assert!(decode_content("").is_err(), "empty content is rejected");

        // Synthesize a base64 string that decodes to MAX_FILE_BYTES + 1.
        let oversized = vec![0u8; MAX_FILE_BYTES + 1];
        let b64 = STANDARD.encode(&oversized);
        let err = decode_content(&b64);
        assert!(err.is_err(), "must reject content above the cap");
    }

    #[test]
    fn decode_content_roundtrip_under_cap() {
        let bytes = b"gateway-tls.pem contents here".to_vec();
        let b64 = STANDARD.encode(&bytes);
        let decoded = decode_content(&b64).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn diff_field_names_ignores_noisy_fields() {
        let old = FileEntry {
            id: "id1".into(),
            name: "a".into(),
            sha256: "old".into(),
            size_bytes: 1,
            created_at: "t0".into(),
            updated_at: "t0".into(),
            ..Default::default()
        };
        let new = FileEntry {
            id: "id1".into(),
            name: "a".into(),        // unchanged
            sha256: "new".into(),    // IGNORED in field diff
            size_bytes: 2,           // IGNORED in field diff
            created_at: "t0".into(), // IGNORED
            updated_at: "t1".into(), // IGNORED
            ..Default::default()
        };
        let changed = diff_field_names(Some(&old), &new);
        assert!(
            changed.is_empty(),
            "only noisy fields moved; field diff must be empty, got: {changed:?}"
        );
    }

    #[test]
    fn diff_field_names_flags_real_changes() {
        let old = FileEntry {
            name: "a".into(),
            notes: "old".into(),
            tags: vec!["x".into()],
            ..Default::default()
        };
        let new = FileEntry {
            name: "a-renamed".into(),
            notes: "new".into(),
            tags: vec!["x".into(), "y".into()],
            ..Default::default()
        };
        let mut changed = diff_field_names(Some(&old), &new);
        changed.sort();
        assert_eq!(changed, vec!["name", "notes", "tags"]);
    }

    #[test]
    fn caller_username_prefers_metadata() {
        use crate::logical::Auth;
        use std::collections::HashMap;

        let mut meta = HashMap::new();
        meta.insert("username".to_string(), "alice".to_string());
        let mut req = Request::default();
        req.auth = Some(Auth {
            display_name: "fallback".into(),
            metadata: meta,
            ..Auth::default()
        });
        assert_eq!(caller_username(&req), "alice");
    }

    #[test]
    fn caller_username_falls_back_to_display_name() {
        use crate::logical::Auth;
        let mut req = Request::default();
        req.auth = Some(Auth {
            display_name: "root".into(),
            ..Auth::default()
        });
        assert_eq!(caller_username(&req), "root");
    }

    #[test]
    fn caller_username_final_fallback_is_unknown() {
        let req = Request::default();
        assert_eq!(caller_username(&req), "unknown");
    }
}

#[cfg(test)]
mod integration_tests {
    //! End-to-end tests driving `/files/…` through `core.handle_request`.
    //! Exercise the real logical-backend pipeline (auth → routing →
    //! handler → storage) and the public response shape — not just
    //! individual helpers in isolation.

    use serde_json::json;

    use crate::test_utils::{new_unseal_test_bastion_vault, test_write_api};

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_create_read_roundtrip() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_create_read_roundtrip").await;

        let content = b"-----BEGIN CERTIFICATE-----\nMIIDtest\n-----END CERTIFICATE-----\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(content);

        let body = json!({
            "name": "gateway-tls.pem",
            "mime_type": "application/x-pem-file",
            "tags": "tls,production",
            "notes": "test cert",
            "content_base64": b64,
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .expect("create must succeed")
            .expect("create returns data envelope");
        let data = resp.data.expect("data present");
        let id = data
            .get("id")
            .and_then(|v| v.as_str())
            .expect("id returned")
            .to_string();
        assert!(!id.is_empty());
        assert_eq!(data.get("size_bytes").and_then(|v| v.as_u64()), Some(content.len() as u64));
        let sha_returned = data.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(sha_returned.len(), 64);

        // Read metadata back.
        let mut req = crate::logical::Request::new(format!("files/files/{id}"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let meta_resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let meta = meta_resp.data.expect("meta data");
        assert_eq!(meta.get("name").and_then(|v| v.as_str()), Some("gateway-tls.pem"));
        assert_eq!(
            meta.get("mime_type").and_then(|v| v.as_str()),
            Some("application/x-pem-file")
        );
        assert_eq!(
            meta.get("sha256").and_then(|v| v.as_str()),
            Some(sha_returned),
            "metadata sha256 must equal the one returned at create"
        );

        // Read content back; verify round-trip.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let content_resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let cdata = content_resp.data.expect("content data");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(
                cdata
                    .get("content_base64")
                    .and_then(|v| v.as_str())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(decoded, content, "round-tripped bytes must match");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_oversized_rejected_before_store() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_oversized_rejected").await;

        // One byte over the cap. base64 encoding inflates ~4/3; this
        // is still a valid but oversized payload.
        let oversized = vec![0u8; super::MAX_FILE_BYTES + 1];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&oversized);
        let body = json!({ "name": "huge.bin", "content_base64": b64 })
            .as_object()
            .cloned();

        // test_write_api with `is_ok = false` asserts the call errors.
        let _ = test_write_api(&core, &root_token, "files/files", false, body).await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_update_replaces_content() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_update_replaces_content").await;

        let v1 = b"version-1".to_vec();
        let v2 = b"VERSION-2-DIFFERENT".to_vec();
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "cfg.txt",
            "content_base64": engine.encode(&v1),
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // PUT new content.
        let put_body = json!({ "content_base64": engine.encode(&v2) }).as_object().cloned();
        let put = test_write_api(&core, &root_token, &format!("files/files/{id}"), true, put_body)
            .await
            .unwrap()
            .unwrap();
        let put_data = put.data.unwrap();
        let new_sha = put_data.get("sha256").and_then(|v| v.as_str()).unwrap();
        assert_ne!(new_sha, super::sha256_hex(&v1), "sha must change on content replace");
        assert_eq!(new_sha, super::sha256_hex(&v2));

        // Read content back → must be v2.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let content_resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let decoded = engine
            .decode(
                content_resp
                    .data
                    .unwrap()
                    .get("content_base64")
                    .and_then(|v| v.as_str())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(decoded, v2);

        // History must have two entries (create + update with
        // "content" in changed_fields).
        let mut hist_req = crate::logical::Request::new(format!("files/files/{id}/history"));
        hist_req.operation = crate::logical::Operation::Read;
        hist_req.client_token = root_token.clone();
        let hist_resp = core.handle_request(&mut hist_req).await.unwrap().unwrap();
        let entries = hist_resp
            .data
            .unwrap()
            .get("entries")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(entries.len() >= 2, "create + update must produce ≥2 history entries");
        let update_entry = entries
            .iter()
            .find(|e| e.get("op").and_then(|v| v.as_str()) == Some("update"))
            .expect("an update entry exists");
        let changed = update_entry
            .get("changed_fields")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(
            changed.iter().any(|v| v.as_str() == Some("content")),
            "content change must be recorded in changed_fields, got: {changed:?}"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_resource_delete_then_read_is_gone() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_resource_delete_gone").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "temp.txt",
            "content_base64": engine.encode(b"bye"),
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // DELETE
        let mut del = crate::logical::Request::new(format!("files/files/{id}"));
        del.operation = crate::logical::Operation::Delete;
        del.client_token = root_token.clone();
        let _ = core.handle_request(&mut del).await.unwrap();

        // Subsequent metadata read must return None (which the HTTP
        // layer renders as 404).
        let mut req = crate::logical::Request::new(format!("files/files/{id}"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let after = core.handle_request(&mut req).await.unwrap();
        assert!(after.is_none(), "deleted file must not be readable");
    }

    use base64::Engine;

    // ── Phase 2: ownership / sharing / backfill ──────────────────

    use crate::modules::identity::IdentityModule;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_create_stamps_root_owner() {
        // Phase 2: a root-token write stamps `root` as the file's
        // owner. Mirrors `test_root_token_resource_write_captures_owner`.
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_create_stamps_root_owner").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "ssh.key",
            "content_base64": engine.encode(b"PRIVATE KEY PAYLOAD"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let identity = core
            .module_manager
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");
        let rec = owner_store
            .get_file_owner(&id)
            .await
            .unwrap()
            .expect("owner record must exist after root-token file write");
        assert_eq!(rec.entity_id, "root");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_delete_forgets_owner_and_cascades_shares() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_delete_forgets_owner").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // Create a file.
        let body = json!({
            "name": "temp.key",
            "content_base64": engine.encode(b"to-be-deleted"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let identity = core
            .module_manager
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");
        assert!(owner_store.get_file_owner(&id).await.unwrap().is_some());

        // Seed a share against this file so we can verify cascade.
        let share_store = identity.share_store().expect("share store");
        let share = crate::modules::identity::share_store::SecretShare {
            target_kind: "file".to_string(),
            target_path: id.clone(),
            grantee_entity_id: "some-user-entity".to_string(),
            granted_by_entity_id: "root".to_string(),
            capabilities: vec!["read".into()],
            granted_at: chrono::Utc::now().to_rfc3339(),
            expires_at: String::new(),
        };
        share_store.set_share(share).await.expect("seed share");

        // Delete the file via the logical API.
        let mut del = crate::logical::Request::new(format!("files/files/{id}"));
        del.operation = crate::logical::Operation::Delete;
        del.client_token = root_token.clone();
        core.handle_request(&mut del).await.unwrap();

        // Owner record gone.
        assert!(
            owner_store.get_file_owner(&id).await.unwrap().is_none(),
            "delete must forget owner"
        );

        // Share cascade-revoked.
        let remaining = share_store
            .list_shares_for_target(
                crate::modules::identity::share_store::ShareTargetKind::File,
                &id,
            )
            .await
            .unwrap();
        assert!(
            remaining.is_empty(),
            "share_store must drop shares targeting the deleted file, got: {remaining:?}"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_backfill_stamps_unowned_files() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_backfill_files").await;

        let body = json!({
            "entity_id": "root",
            "file_ids": [
                "018f3b2a-abcd-1234-5678-000000000001",
                "018f3b2a-abcd-1234-5678-000000000002",
                "has/slash/invalid",
            ],
            "dry_run": false,
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "sys/owner/backfill", true, body)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        let files = data.get("files").expect("files summary present");
        assert_eq!(files.get("stamped").and_then(|v| v.as_u64()), Some(2));
        let invalid: Vec<String> = files
            .get("invalid")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        assert_eq!(invalid, vec!["has/slash/invalid".to_string()]);

        // The stamped records should now exist.
        let identity = core
            .module_manager
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");
        for id in [
            "018f3b2a-abcd-1234-5678-000000000001",
            "018f3b2a-abcd-1234-5678-000000000002",
        ] {
            let rec = owner_store.get_file_owner(id).await.unwrap();
            assert!(rec.is_some(), "{id} must be stamped");
            assert_eq!(rec.unwrap().entity_id, "root");
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_owner_transfer_admin_endpoint() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_owner_transfer").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "cfg.yml",
            "content_base64": engine.encode(b"original"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let identity = core
            .module_manager
            .get_module::<IdentityModule>("identity")
            .expect("identity module");
        let owner_store = identity.owner_store().expect("owner store");

        // Pre: root is the owner.
        assert_eq!(
            owner_store.get_file_owner(&id).await.unwrap().unwrap().entity_id,
            "root"
        );

        // Transfer to a different entity id.
        let xfer = json!({
            "id": id,
            "new_owner_entity_id": "ent-alice",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "sys/file-owner/transfer",
            true,
            xfer,
        )
        .await
        .unwrap();

        // Post: new owner recorded.
        assert_eq!(
            owner_store.get_file_owner(&id).await.unwrap().unwrap().entity_id,
            "ent-alice",
            "transfer must overwrite owner unconditionally"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sync_target_local_fs_push_writes_file() {
        use std::fs;

        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_sync_local_fs_push").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // 1. Create a file.
        let content = b"PRIVATE KEY CONTENT";
        let body = json!({
            "name": "jump.key",
            "content_base64": engine.encode(content),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // 2. Configure a local-fs sync target.
        let tmp = std::env::temp_dir().join(format!("bvault-sync-{id}/key.pem"));
        // Ensure clean slate (prior test run leftovers).
        let _ = fs::remove_file(&tmp);
        let cfg = json!({
            "kind": "local-fs",
            "target_path": tmp.to_string_lossy(),
            "mode": "0600",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            true,
            cfg,
        )
        .await
        .unwrap();

        // 3. Push.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary/push"),
            true,
            None,
        )
        .await
        .unwrap();

        // 4. Target file must exist with the right bytes.
        let got = fs::read(&tmp).expect("sync push must produce the target file");
        assert_eq!(got, content, "target bytes must match file content");

        // 5. Sync state must show last_success_at + matching hash.
        let mut list_req = crate::logical::Request::new(format!("files/files/{id}/sync"));
        list_req.operation = crate::logical::Operation::Read;
        list_req.client_token = root_token.clone();
        let list_resp = core.handle_request(&mut list_req).await.unwrap().unwrap();
        let targets = list_resp
            .data
            .unwrap()
            .get("targets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(targets.len(), 1);
        let state = targets[0].get("state").expect("state node present");
        let last_ok = state.get("last_success_at").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            !last_ok.is_empty(),
            "last_success_at must be populated: {state:?}"
        );
        assert_eq!(
            state.get("last_success_sha256").and_then(|v| v.as_str()),
            Some(super::sha256_hex(content).as_str())
        );

        let _ = fs::remove_file(&tmp);
    }

    /// `sync_on_write = true` causes the file-content write to push
    /// the bytes to the target inline, without a separate `push`
    /// call. The response carries a `sync_on_write` array with one
    /// entry per target attempted.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sync_on_write_inline_push() {
        use std::fs;
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_sync_on_write_inline").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // Create the file.
        let v1 = b"v1-content";
        let body = json!({
            "name": "config.yaml",
            "content_base64": engine.encode(v1),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Configure a local-fs sync target with sync_on_write = true.
        let tmp = std::env::temp_dir().join(format!("bvault-sow-{id}/config.yaml"));
        let _ = fs::remove_file(&tmp);
        let cfg = json!({
            "kind": "local-fs",
            "target_path": tmp.to_string_lossy(),
            "sync_on_write": true,
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            true,
            cfg,
        )
        .await
        .unwrap();

        // Update the file content. The write handler should fire
        // an inline push to the target.
        let v2 = b"v2-content-with-sync-on-write";
        let body = json!({
            "name": "config.yaml",
            "content_base64": engine.encode(v2),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            body,
        )
        .await
        .unwrap()
        .unwrap();
        let data = resp.data.unwrap();
        let pushes = data
            .get("sync_on_write")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(pushes.len(), 1, "exactly one target should have fired");
        assert_eq!(pushes[0].get("name").and_then(|v| v.as_str()), Some("primary"));
        assert_eq!(pushes[0].get("ok").and_then(|v| v.as_bool()), Some(true));

        // Target file must carry the v2 bytes — proves the inline
        // push ran as part of the write handler.
        let got = fs::read(&tmp).expect("sync_on_write must produce the target file");
        assert_eq!(got, v2);

        let _ = fs::remove_file(&tmp);
    }

    /// The manual `POST /v1/<mount>/sync-tick` endpoint runs the
    /// scheduler sweep on demand. Targets without
    /// `auto_sync_interval_seconds` are skipped; targets with it set
    /// are pushed (and their `last_attempt_source = "scheduler"`).
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_manual_sync_tick_endpoint() {
        use std::fs;
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_manual_sync_tick").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "deploy.cfg",
            "content_base64": engine.encode(b"deploy-bytes"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let tmp = std::env::temp_dir().join(format!("bvault-tick-{id}/deploy.cfg"));
        let _ = fs::remove_file(&tmp);

        // Configure two targets: one with auto_sync, one without.
        let cfg_auto = json!({
            "kind": "local-fs",
            "target_path": tmp.to_string_lossy(),
            "auto_sync_interval_seconds": 60u64,
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/auto"),
            true,
            cfg_auto,
        )
        .await
        .unwrap();
        let tmp2 = std::env::temp_dir().join(format!("bvault-tick-{id}/manual.cfg"));
        let cfg_manual = json!({
            "kind": "local-fs",
            "target_path": tmp2.to_string_lossy(),
            // auto_sync_interval_seconds omitted = 0 = scheduler skips
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/manual"),
            true,
            cfg_manual,
        )
        .await
        .unwrap();

        // Trigger the tick.
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/sync-tick",
            true,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        let data = resp.data.unwrap();
        let attempted = data.get("attempted").and_then(|v| v.as_u64()).unwrap_or(0);
        let succeeded = data.get("succeeded").and_then(|v| v.as_u64()).unwrap_or(0);
        let skipped = data.get("skipped").and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!(attempted, 1, "exactly the auto target should have been attempted");
        assert_eq!(succeeded, 1, "the local-fs auto push should succeed");
        assert!(skipped >= 1, "the manual target should be skipped");

        // The auto target should have produced the file. The manual
        // target should not have been touched.
        let got = fs::read(&tmp).expect("auto target must be written by the tick");
        assert_eq!(got, b"deploy-bytes");
        assert!(!tmp2.exists(), "manual-only target must not be written by the tick");

        let _ = fs::remove_file(&tmp);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_sync_target_unsupported_kind_rejected_at_save() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_sync_unsupported_kind").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "cfg",
            "content_base64": engine.encode(b"x"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let cfg = json!({
            "kind": "sftp",
            "target_path": "/etc/ssl/thing.pem",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;

        // smb without credentials: rejected at save time so the
        // operator gets an immediate error rather than discovering
        // the misconfig at first push.
        let cfg = json!({
            "kind": "smb",
            "target_path": "smb://server/share/file.txt",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;

        // smb with malformed URL: also rejected at save time.
        let cfg = json!({
            "kind": "smb",
            "target_path": "not-a-smb-url",
            "smb_username": "user",
            "smb_password": "pw",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;

        // sftp without credentials: rejected at save time.
        let cfg = json!({
            "kind": "sftp",
            "target_path": "sftp://server/srv/x.txt",
            "ssh_username": "alice",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error: at least one of ssh_password / ssh_private_key required
            cfg,
        )
        .await;

        // scp with malformed URL: rejected at save time.
        let cfg = json!({
            "kind": "scp",
            "target_path": "scp://no-path-here",
            "ssh_username": "alice",
            "ssh_password": "pw",
        })
        .as_object()
        .cloned();
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}/sync/primary"),
            false, // expect error
            cfg,
        )
        .await;
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_versioning_snapshots_on_update() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_versioning_snapshots").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let v1 = b"content-v1".to_vec();
        let v2 = b"content-v2-different".to_vec();
        let v3 = b"content-v3-different-again".to_vec();

        // Create with v1.
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/files",
            true,
            json!({ "name": "versioned.txt", "content_base64": engine.encode(&v1) })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // No versions yet — only one content write so far.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let entries: Vec<serde_json::Value> = r
            .data
            .unwrap()
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(entries.is_empty(), "no versions before first update");

        // First update: snapshots v1 as version 1, current = 2.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            json!({ "content_base64": engine.encode(&v2) })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // Second update: snapshots v2 as version 2, current = 3.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            json!({ "content_base64": engine.encode(&v3) })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // List versions: 2 entries.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let data = r.data.unwrap();
        let current_version = data.get("current_version").and_then(|v| v.as_u64()).unwrap();
        let versions: Vec<serde_json::Value> = data
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(current_version, 3);
        assert_eq!(versions.len(), 2);
        let v1_hash = super::sha256_hex(&v1);
        let v2_hash = super::sha256_hex(&v2);
        assert_eq!(versions[0].get("version").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(versions[0].get("sha256").and_then(|v| v.as_str()), Some(v1_hash.as_str()));
        assert_eq!(versions[1].get("version").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(versions[1].get("sha256").and_then(|v| v.as_str()), Some(v2_hash.as_str()));

        // Read historical content of v1.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions/1/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let b64 = r
            .data
            .unwrap()
            .get("content_base64")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let decoded = engine.decode(&b64).unwrap();
        assert_eq!(decoded, v1);

        // Restore v1 as current. Expected: current_version bumps; v3
        // becomes another snapshot; content read returns v1.
        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions/1/restore"));
        req.operation = crate::logical::Operation::Write;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let rdata = r.data.unwrap();
        assert_eq!(rdata.get("restored_version").and_then(|v| v.as_u64()), Some(1));

        let mut req = crate::logical::Request::new(format!("files/files/{id}/content"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let b64 = r
            .data
            .unwrap()
            .get("content_base64")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let decoded = engine.decode(&b64).unwrap();
        assert_eq!(decoded, v1, "restore must make v1 the live content");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_versioning_retention_prunes_oldest() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_versioning_retention").await;
        let engine = base64::engine::general_purpose::STANDARD;

        // Create.
        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/files",
            true,
            json!({ "name": "churn.txt", "content_base64": engine.encode(b"v1") })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Seven updates → should retain only the last DEFAULT_VERSION_RETENTION (5).
        for i in 2..=8 {
            let _ = crate::test_utils::test_write_api(
                &core,
                &root_token,
                &format!("files/files/{id}"),
                true,
                json!({ "content_base64": engine.encode(format!("v{i}").as_bytes()) })
                    .as_object()
                    .cloned(),
            )
            .await
            .unwrap();
        }

        let mut req = crate::logical::Request::new(format!("files/files/{id}/versions"));
        req.operation = crate::logical::Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let data = r.data.unwrap();
        let versions: Vec<serde_json::Value> = data
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            versions.len(),
            super::DEFAULT_VERSION_RETENTION,
            "retention must prune oldest beyond cap"
        );
        // Oldest retained version number = total_writes (8) - retention (5) = 3.
        // versions[0] is version 4 (after pruning 1, 2, 3).
        // Total content writes = 1 create + 7 updates = 8 ⇒ current_version = 8, first retained = 4.
        let first = versions[0].get("version").and_then(|v| v.as_u64()).unwrap();
        let last = versions
            .last()
            .unwrap()
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(first, 3, "after 8 writes with retention=5, oldest retained is v3");
        assert_eq!(last, 7);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_file_delete_sweeps_versions() {
        use crate::logical::{Operation, Request as Lreq};
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_file_delete_sweeps_versions").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let resp = crate::test_utils::test_write_api(
            &core,
            &root_token,
            "files/files",
            true,
            json!({ "name": "x", "content_base64": engine.encode(b"a") })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap()
        .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        // One update → one snapshot exists.
        let _ = crate::test_utils::test_write_api(
            &core,
            &root_token,
            &format!("files/files/{id}"),
            true,
            json!({ "content_base64": engine.encode(b"b") })
                .as_object()
                .cloned(),
        )
        .await
        .unwrap();

        // Delete file.
        let mut del = Lreq::new(format!("files/files/{id}"));
        del.operation = Operation::Delete;
        del.client_token = root_token.clone();
        core.handle_request(&mut del).await.unwrap();

        // Version list must be empty (vmeta swept).
        let mut req = Lreq::new(format!("files/files/{id}/versions"));
        req.operation = Operation::Read;
        req.client_token = root_token.clone();
        let r = core.handle_request(&mut req).await.unwrap().unwrap();
        let data = r.data.unwrap();
        assert_eq!(data.get("current_version").and_then(|v| v.as_u64()), Some(0));
        assert!(data
            .get("versions")
            .and_then(|v| v.as_array())
            .unwrap()
            .is_empty());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_identity_owner_file_read_endpoint() {
        let (_bv, core, root_token) =
            new_unseal_test_bastion_vault("test_identity_owner_file_read").await;
        let engine = base64::engine::general_purpose::STANDARD;

        let body = json!({
            "name": "api.key",
            "content_base64": engine.encode(b"stuff"),
        })
        .as_object()
        .cloned();
        let resp = crate::test_utils::test_write_api(&core, &root_token, "files/files", true, body)
            .await
            .unwrap()
            .unwrap();
        let id = resp
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // `identity/owner/file/<id>` returns { target_kind, target, owner }.
        let resp =
            crate::test_utils::test_read_api(&core, &root_token, &format!("identity/owner/file/{id}"), true)
                .await
                .unwrap()
                .unwrap();
        let data = resp.data.expect("owner envelope");
        assert_eq!(data.get("target_kind").and_then(|v| v.as_str()), Some("file"));
        assert_eq!(data.get("target").and_then(|v| v.as_str()), Some(id.as_str()));
        assert_eq!(data.get("owned").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(data.get("entity_id").and_then(|v| v.as_str()), Some("root"));
    }
}
