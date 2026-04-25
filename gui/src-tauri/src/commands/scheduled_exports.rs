//! Tauri commands backing the GUI Schedules tab.
//!
//! Embedded mode: dispatches directly to
//! `bastion_vault::scheduled_exports::ScheduleStore` against the open
//! vault's barrier-decrypted storage.

use bastion_vault::scheduled_exports::{
    runner, RunRecord, RunStatus, Schedule, ScheduleInput, ScheduleStore,
};
use serde::Serialize;
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

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
