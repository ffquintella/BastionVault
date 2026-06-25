//! Tauri commands backing the GUI Schedules tab.
//!
//! Embedded mode: dispatches directly to
//! `bastion_vault::scheduled_exports::ScheduleStore` against the open
//! vault's barrier-decrypted storage.
//!
//! Remote mode: routes through the `bv_client::Backend` trait
//! (`crate::commands::make_request`) to the server's HTTP API under
//! `/v{1,2}/sys/scheduled-exports/*`. Without this branch every command
//! failed with "Vault not open" whenever the GUI was connected to a
//! remote server (where `AppState::vault` is always `None`).

use bastion_vault::scheduled_exports::{
    runner, DestinationKind, RunRecord, RunStatus, Schedule, ScheduleInput, ScheduleStore,
};
use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::commands::make_request;
use crate::error::{CmdResult, CommandError};
use crate::state::{AppState, VaultMode};

/// True when the GUI is connected to a remote server rather than an
/// in-process embedded vault.
async fn is_remote(state: &State<'_, AppState>) -> bool {
    matches!(*state.mode.lock().await, VaultMode::Remote)
}

/// Serialize a command input into the JSON object the HTTP API expects
/// as a request body.
fn body_of<T: Serialize>(input: &T) -> CmdResult<Map<String, Value>> {
    match serde_json::to_value(input).map_err(|e| CommandError::from(e.to_string()))? {
        Value::Object(map) => Ok(map),
        _ => Err("failed to encode request body".into()),
    }
}

/// Issue a logical request through the active backend and return its
/// `data` map (the HTTP handlers reply with a bare object, so the
/// client surfaces the whole body as `data`).
async fn remote_data(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> CmdResult<Map<String, Value>> {
    let resp = make_request(state, operation, path, body).await?;
    Ok(resp.and_then(|r| r.data).unwrap_or_default())
}

fn parse_field<T: serde::de::DeserializeOwned>(
    data: &Map<String, Value>,
    key: &str,
) -> CmdResult<T> {
    let value = data.get(key).cloned().unwrap_or(Value::Null);
    serde_json::from_value(value)
        .map_err(|e| CommandError::from(format!("unexpected server response: {e}")))
}

#[derive(Debug, Serialize)]
pub struct ScheduleListResult {
    pub schedules: Vec<Schedule>,
}

#[derive(Debug, Serialize)]
pub struct ScheduleRunsResult {
    pub runs: Vec<RunRecord>,
}

#[tauri::command]
pub async fn scheduled_exports_list(state: State<'_, AppState>) -> CmdResult<ScheduleListResult> {
    if is_remote(&state).await {
        let data = remote_data(&state, Operation::Read, "sys/scheduled-exports".into(), None).await?;
        let schedules = parse_field(&data, "schedules")?;
        return Ok(ScheduleListResult { schedules });
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let store = ScheduleStore::new();
    let schedules = store
        .list(core.barrier.as_storage())
        .await
        .map_err(CommandError::from)?;
    Ok(ScheduleListResult { schedules })
}

#[tauri::command]
pub async fn scheduled_exports_create(
    state: State<'_, AppState>,
    input: ScheduleInput,
) -> CmdResult<Schedule> {
    use std::str::FromStr;
    cron::Schedule::from_str(&input.cron).map_err(|_| "invalid cron expression")?;

    if is_remote(&state).await {
        let body = body_of(&input)?;
        let data = remote_data(&state, Operation::Write, "sys/scheduled-exports".into(), Some(body)).await?;
        return parse_field(&data, "schedule");
    }

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let sched = Schedule {
        id,
        name: input.name,
        cron: input.cron,
        format: input.format,
        scope: input.scope,
        destination: input.destination,
        password_ref: input.password_ref,
        allow_plaintext: input.allow_plaintext,
        comment: input.comment,
        created_at: now.clone(),
        updated_at: now,
        enabled: input.enabled,
    };
    let store = ScheduleStore::new();
    store
        .put(core.barrier.as_storage(), &sched)
        .await
        .map_err(CommandError::from)?;
    Ok(sched)
}

#[tauri::command]
pub async fn scheduled_exports_update(
    state: State<'_, AppState>,
    id: String,
    input: ScheduleInput,
) -> CmdResult<Schedule> {
    use std::str::FromStr;
    cron::Schedule::from_str(&input.cron).map_err(|_| "invalid cron expression")?;

    if is_remote(&state).await {
        let body = body_of(&input)?;
        let path = format!("sys/scheduled-exports/{id}");
        let data = remote_data(&state, Operation::Write, path, Some(body)).await?;
        return parse_field(&data, "schedule");
    }

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    let store = ScheduleStore::new();
    let existing = store
        .get(core.barrier.as_storage(), &id)
        .await
        .map_err(CommandError::from)?
        .ok_or("schedule not found")?;
    let sched = Schedule {
        id: existing.id,
        name: input.name,
        cron: input.cron,
        format: input.format,
        scope: input.scope,
        destination: input.destination,
        password_ref: input.password_ref,
        allow_plaintext: input.allow_plaintext,
        comment: input.comment,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now().to_rfc3339(),
        enabled: input.enabled,
    };
    store
        .put(core.barrier.as_storage(), &sched)
        .await
        .map_err(CommandError::from)?;
    Ok(sched)
}

#[tauri::command]
pub async fn scheduled_exports_delete(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    if is_remote(&state).await {
        let path = format!("sys/scheduled-exports/{id}");
        remote_data(&state, Operation::Delete, path, None).await?;
        return Ok(());
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let store = ScheduleStore::new();
    store
        .delete(core.barrier.as_storage(), &id)
        .await
        .map_err(CommandError::from)?;
    Ok(())
}

#[tauri::command]
pub async fn scheduled_exports_runs(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<ScheduleRunsResult> {
    if is_remote(&state).await {
        let path = format!("sys/scheduled-exports/{id}/runs");
        let data = remote_data(&state, Operation::Read, path, None).await?;
        let runs = parse_field(&data, "runs")?;
        return Ok(ScheduleRunsResult { runs });
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let store = ScheduleStore::new();
    let runs = store
        .list_runs(core.barrier.as_storage(), &id)
        .await
        .map_err(CommandError::from)?;
    Ok(ScheduleRunsResult { runs })
}

/// Trigger an immediate one-off run, separate from the cron cadence.
#[tauri::command]
pub async fn scheduled_exports_run_now(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<RunRecord> {
    if is_remote(&state).await {
        let path = format!("sys/scheduled-exports/{id}/run-now");
        let data = remote_data(&state, Operation::Write, path, None).await?;
        return parse_field(&data, "run");
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let store = ScheduleStore::new();
    let sched = store
        .get(core.barrier.as_storage(), &id)
        .await
        .map_err(CommandError::from)?
        .ok_or("schedule not found")?;

    // Resolve through the runner so the schedule's password-ref logic +
    // destination writer match what the cron-driven path uses.
    let core_arc: std::sync::Arc<bastion_vault::core::Core> =
        std::sync::Arc::clone(&*core);
    drop(vault_guard);
    let outcome = runner::run_once(&core_arc, &sched).await;
    let record = match outcome {
        Ok((bytes, dest)) => RunRecord {
            schedule_id: sched.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            status: RunStatus::Success,
            bytes_written: bytes,
            destination: dest,
            error: None,
        },
        Err(e) => RunRecord {
            schedule_id: sched.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            status: RunStatus::Failed,
            bytes_written: 0,
            destination: sched.destination.clone(),
            error: Some(format!("{e}")),
        },
    };
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let _ = store
        .append_run(core.barrier.as_storage(), &record)
        .await;
    Ok(record)
}

// ── Backup file discovery + restore ──────────────────────────────────────
//
// The cron runner writes `{schedule_id}-{timestamp}.{bvx|json}` files to the
// schedule's local destination directory (see
// `bastion_vault::scheduled_exports::runner::write_local`). These commands
// let the GUI enumerate those produced files and read one back as bytes so it
// can be fed through the existing `exchange_preview` / `exchange_apply` import
// flow — i.e. a restore.
//
// Both are embedded-only: they touch the local filesystem of the BastionVault
// host. In remote mode the backups live on the server's disk, unreachable from
// the GUI process, so the commands fail fast with a clear message rather than
// the misleading "Vault not open".

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct BackupFile {
    pub name: String,
    pub size_bytes: u64,
    /// RFC3339 last-modified timestamp, when the platform reports one.
    pub modified: Option<String>,
    /// "bvx" | "json", derived from the file extension.
    pub format: String,
}

#[derive(Debug, Serialize)]
pub struct BackupListResult {
    /// The resolved local destination directory that was scanned.
    pub dir: String,
    pub files: Vec<BackupFile>,
}

/// Resolve a schedule's `local_path` destination, erroring if the schedule
/// uses a non-local destination kind.
fn local_dir(dest: &DestinationKind) -> CmdResult<&str> {
    match dest {
        DestinationKind::LocalPath { path } => Ok(path.as_str()),
    }
}

/// Map a file name's extension to a known export format, or `None` for files
/// that are not backups we recognise.
fn format_of(name: &str) -> Option<&'static str> {
    if name.ends_with(".bvx") {
        Some("bvx")
    } else if name.ends_with(".json") {
        Some("json")
    } else {
        None
    }
}

/// Load a schedule by id from the open embedded vault.
async fn get_schedule(state: &State<'_, AppState>, id: &str) -> CmdResult<Schedule> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let store = ScheduleStore::new();
    store
        .get(core.barrier.as_storage(), id)
        .await
        .map_err(CommandError::from)?
        .ok_or_else(|| "schedule not found".into())
}

/// List the backup files present in a schedule's local destination directory,
/// newest first. Files that are not `.bvx`/`.json` are ignored.
#[tauri::command]
pub async fn scheduled_exports_backups_list(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<BackupListResult> {
    if is_remote(&state).await {
        // The backup files live on the server's filesystem; ask the server to
        // enumerate them rather than touching the (non-existent) local disk.
        let path = format!("sys/scheduled-exports/{id}/backups");
        let data = remote_data(&state, Operation::Read, path, None).await?;
        let dir = parse_field(&data, "dir")?;
        let files = parse_field(&data, "files")?;
        return Ok(BackupListResult { dir, files });
    }
    let sched = get_schedule(&state, &id).await?;
    let dir = local_dir(&sched.destination)?.to_string();

    let mut files: Vec<BackupFile> = Vec::new();
    let read_dir = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        // A directory that does not exist yet (no run has fired) is not an
        // error — it just means there are no backups to list.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BackupListResult { dir, files })
        }
        Err(e) => return Err(format!("cannot read {dir}: {e}").into()),
    };

    for entry in read_dir.flatten() {
        let meta = match entry.metadata() {
            Ok(m) if m.is_file() => m,
            _ => continue,
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        // Skip in-flight temp files written by the atomic-rename path.
        if name.starts_with('.') {
            continue;
        }
        let Some(format) = format_of(&name) else { continue };
        let modified = meta
            .modified()
            .ok()
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
        files.push(BackupFile {
            name,
            size_bytes: meta.len(),
            modified,
            format: format.to_string(),
        });
    }

    // Newest first: by modified time when known, then file name descending so
    // the timestamp-suffixed runner names fall in chronological order.
    files.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| b.name.cmp(&a.name))
    });

    Ok(BackupListResult { dir, files })
}

#[derive(Debug, Serialize, serde::Deserialize, Default)]
pub struct RestoreItem {
    pub mount: String,
    pub path: String,
    /// "new" | "identical" | "conflict"
    pub classification: String,
}

/// Outcome of a restore. On `dry_run` the `new`/`identical`/`conflict` counts
/// and `items` describe the classification; on a real apply the
/// `written`/`unchanged`/`skipped`/`renamed` counts describe what was written.
#[derive(Debug, Serialize, serde::Deserialize, Default)]
pub struct RestoreResult {
    pub dry_run: bool,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub new: u64,
    #[serde(default)]
    pub identical: u64,
    #[serde(default)]
    pub conflict: u64,
    #[serde(default)]
    pub written: u64,
    #[serde(default)]
    pub unchanged: u64,
    #[serde(default)]
    pub skipped: u64,
    #[serde(default)]
    pub renamed: u64,
    #[serde(default)]
    pub items: Vec<RestoreItem>,
}

/// Restore one of a schedule's backup files into the vault.
///
/// The whole operation — reading the file off disk and writing the imported
/// items — runs against the vault host: embedded mode does it in-process,
/// remote mode delegates to `POST /v{1,2}/sys/scheduled-exports/{id}/restore`
/// so the (possibly full-vault) backup never round-trips through the GUI.
///
/// `dry_run` classifies without writing, backing the modal's "Preview" button;
/// a real apply uses `conflict_policy` (`skip` | `overwrite` | `rename`).
#[tauri::command]
pub async fn scheduled_exports_restore(
    state: State<'_, AppState>,
    id: String,
    filename: String,
    password: Option<String>,
    allow_plaintext: Option<bool>,
    conflict_policy: Option<String>,
    dry_run: bool,
) -> CmdResult<RestoreResult> {
    let allow_plaintext = allow_plaintext.unwrap_or(false);
    let conflict_policy = conflict_policy.unwrap_or_else(|| "skip".to_string());

    if is_remote(&state).await {
        let mut body = Map::new();
        body.insert("filename".into(), Value::String(filename));
        if let Some(p) = password {
            body.insert("password".into(), Value::String(p));
        }
        body.insert("allow_plaintext".into(), Value::Bool(allow_plaintext));
        body.insert("conflict_policy".into(), Value::String(conflict_policy));
        body.insert("dry_run".into(), Value::Bool(dry_run));
        let path = format!("sys/scheduled-exports/{id}/restore");
        let data = remote_data(&state, Operation::Write, path, Some(body)).await?;
        return serde_json::from_value(Value::Object(data))
            .map_err(|e| CommandError::from(format!("unexpected server response: {e}")));
    }

    // ── Embedded: read + classify/import in-process. ──────────────────────
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
    {
        return Err("invalid backup file name".into());
    }
    let format = format_of(&filename).ok_or("backup file must be a .bvx or .json file")?;

    let sched = get_schedule(&state, &id).await?;
    let dir = local_dir(&sched.destination)?;
    let path = std::path::Path::new(dir).join(&filename);
    let file_bytes = std::fs::read(&path)
        .map_err(|e| CommandError::from(format!("cannot read backup file: {e}")))?;

    let document_bytes = match format {
        "bvx" => {
            let pw = password.as_deref().ok_or("password required for bvx format")?;
            bastion_vault::exchange::decrypt_bvx(&file_bytes, pw).map_err(CommandError::from)?
        }
        // "json"
        _ => {
            if !allow_plaintext {
                return Err("plaintext restore refused (set allowPlaintext: true)".into());
            }
            file_bytes
        }
    };

    let document: bastion_vault::exchange::ExchangeDocument =
        serde_json::from_slice(&document_bytes).map_err(|_| "document is not valid bvx.v1 JSON")?;
    document
        .validate_schema_tag()
        .map_err(|_| "unsupported bvx schema tag")?;

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    if dry_run {
        // Classify via the one engine in dry-run mode so the preview agrees
        // with the real restore on every item type (KV, raw non-KV engines,
        // structured resources / files / groups) and resolves keys under the
        // re-rooted layout the write path uses.
        let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
        let mounts = bastion_vault::exchange::scope::MountIndex::from_core(&core_arc)
            .map_err(CommandError::from)?;
        let classify = bastion_vault::exchange::scope::import_from_document(
            core.barrier.as_storage(),
            &mounts,
            &document,
            bastion_vault::exchange::ConflictPolicy::Skip,
            true, // dry_run
        )
        .await
        .map_err(CommandError::from)?;
        let (new, identical, conflict) = classify.classification_counts();
        let items: Vec<RestoreItem> = classify
            .items
            .iter()
            .map(|i| RestoreItem {
                mount: i.mount.clone(),
                path: i.path.clone(),
                classification: match i.classification {
                    bastion_vault::exchange::ImportClassification::New => "new",
                    bastion_vault::exchange::ImportClassification::Identical => "identical",
                    bastion_vault::exchange::ImportClassification::Conflict => "conflict",
                }
                .to_string(),
            })
            .collect();
        return Ok(RestoreResult {
            dry_run: true,
            total: items.len() as u64,
            new,
            identical,
            conflict,
            items,
            ..Default::default()
        });
    }

    let policy = match conflict_policy.as_str() {
        "skip" => bastion_vault::exchange::ConflictPolicy::Skip,
        "overwrite" => bastion_vault::exchange::ConflictPolicy::Overwrite,
        "rename" => bastion_vault::exchange::ConflictPolicy::Rename,
        _ => return Err("conflict_policy must be skip|overwrite|rename".into()),
    };

    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    let mounts =
        bastion_vault::exchange::scope::MountIndex::from_core(&core_arc).map_err(CommandError::from)?;
    let result = bastion_vault::exchange::scope::import_from_document(
        core.barrier.as_storage(),
        &mounts,
        &document,
        policy,
        false,
    )
    .await
    .map_err(CommandError::from)?;

    drop(vault_guard);
    let owner = state.token.lock().await.clone().unwrap_or_default();
    let mut audit_body = Map::new();
    audit_body.insert("schedule_id".into(), Value::String(id));
    audit_body.insert("filename".into(), Value::String(filename));
    audit_body.insert("conflict_policy".into(), Value::String(conflict_policy));
    audit_body.insert("written".into(), Value::Number(result.written.into()));
    audit_body.insert("unchanged".into(), Value::Number(result.unchanged.into()));
    audit_body.insert("skipped".into(), Value::Number(result.skipped.into()));
    audit_body.insert("renamed".into(), Value::Number(result.renamed.into()));
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &owner,
        "sys/scheduled-exports/restore",
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        None,
    )
    .await;

    Ok(RestoreResult {
        dry_run: false,
        written: result.written,
        unchanged: result.unchanged,
        skipped: result.skipped,
        renamed: result.renamed,
        ..Default::default()
    })
}
