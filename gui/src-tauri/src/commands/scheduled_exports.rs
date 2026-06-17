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
    runner, RunRecord, RunStatus, Schedule, ScheduleInput, ScheduleStore,
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
