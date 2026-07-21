//! Tauri commands for the in-app notification system. Thin proxies over
//! the `notifications/*` logical backend (reached as `v2/notifications/*`
//! on the wire) via the shared `make_request` helper. The vault ACL
//! pipeline is authoritative — a user only ever reads their own inbox;
//! composing/broadcasting sits behind `create` on `v2/notifications/send`.

use bv_client::{JsonResponse, Operation};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

fn data_of(resp: Option<JsonResponse>) -> Map<String, Value> {
    resp.and_then(|r| r.data).unwrap_or_default()
}

/// The caller's inbox (read + unread), newest first.
#[tauri::command]
pub async fn notifications_inbox(state: State<'_, AppState>) -> CmdResult<Value> {
    let resp = make_request(&state, Operation::Read, "notifications/inbox".into(), None).await?;
    let data = data_of(resp);
    Ok(data
        .get("notifications")
        .cloned()
        .unwrap_or(Value::Array(vec![])))
}

/// Unread count for the bell badge.
#[tauri::command]
pub async fn notifications_unread_count(state: State<'_, AppState>) -> CmdResult<u64> {
    let resp = make_request(
        &state,
        Operation::Read,
        "notifications/inbox/unread-count".into(),
        None,
    )
    .await?;
    Ok(data_of(resp)
        .get("unread")
        .and_then(|v| v.as_u64())
        .unwrap_or(0))
}

#[tauri::command]
pub async fn notifications_mark_read(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Write,
        format!("notifications/inbox/{id}/read"),
        Some(Map::new()),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn notifications_mark_all_read(state: State<'_, AppState>) -> CmdResult<u64> {
    let resp = make_request(
        &state,
        Operation::Write,
        "notifications/inbox/read-all".into(),
        Some(Map::new()),
    )
    .await?;
    Ok(data_of(resp)
        .get("marked")
        .and_then(|v| v.as_u64())
        .unwrap_or(0))
}

#[tauri::command]
pub async fn notifications_dismiss(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("notifications/inbox/{id}"),
        None,
    )
    .await?;
    Ok(())
}

/// Compose and send a notification. `target` is a `{kind, …}` object
/// (`{"kind":"all_users"}`, `{"kind":"user","entity_id":"…"}`,
/// `{"kind":"username","name":"…"}`, `{"kind":"group","group_kind":"user","name":"…"}`).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn notifications_send(
    state: State<'_, AppState>,
    title: String,
    body: String,
    severity: String,
    target: Value,
    channels: Vec<String>,
    action_url: Option<String>,
) -> CmdResult<Value> {
    let mut b = Map::new();
    b.insert("title".into(), Value::String(title));
    b.insert("body".into(), Value::String(body));
    b.insert("severity".into(), Value::String(severity));
    b.insert("target".into(), target);
    b.insert(
        "channels".into(),
        Value::Array(channels.into_iter().map(Value::String).collect()),
    );
    if let Some(url) = action_url {
        if !url.is_empty() {
            b.insert("action_url".into(), Value::String(url));
        }
    }
    let resp = make_request(&state, Operation::Write, "notifications/send".into(), Some(b)).await?;
    Ok(Value::Object(data_of(resp)))
}

/// Available delivery channels (in-app + plugin-provided).
#[tauri::command]
pub async fn notifications_channels(state: State<'_, AppState>) -> CmdResult<Value> {
    let resp =
        make_request(&state, Operation::Read, "notifications/channels".into(), None).await?;
    Ok(data_of(resp)
        .get("channels")
        .cloned()
        .unwrap_or(Value::Array(vec![])))
}

/// Send a test notification through a channel to a supplied address.
#[tauri::command]
pub async fn notifications_channel_test(
    state: State<'_, AppState>,
    channel: String,
    to: String,
) -> CmdResult<Value> {
    let mut b = Map::new();
    b.insert("to".into(), Value::String(to));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("notifications/channels/{channel}/test"),
        Some(b),
    )
    .await?;
    Ok(Value::Object(data_of(resp)))
}

/// Every notification sent in the namespace (admin audit view).
#[tauri::command]
pub async fn notifications_sent(state: State<'_, AppState>) -> CmdResult<Value> {
    let resp = make_request(&state, Operation::Read, "notifications/sent".into(), None).await?;
    Ok(data_of(resp)
        .get("notifications")
        .cloned()
        .unwrap_or(Value::Array(vec![])))
}

#[tauri::command]
pub async fn notifications_config_get(state: State<'_, AppState>) -> CmdResult<Value> {
    let resp = make_request(&state, Operation::Read, "notifications/config".into(), None).await?;
    Ok(Value::Object(data_of(resp)))
}

#[tauri::command]
pub async fn notifications_config_put(
    state: State<'_, AppState>,
    inbox_cap: Option<u32>,
    plugin_rate_per_min: Option<u32>,
) -> CmdResult<()> {
    let mut b = Map::new();
    if let Some(n) = inbox_cap {
        b.insert("inbox_cap".into(), Value::from(n));
    }
    if let Some(n) = plugin_rate_per_min {
        b.insert("plugin_rate_per_min".into(), Value::from(n));
    }
    make_request(&state, Operation::Write, "notifications/config".into(), Some(b)).await?;
    Ok(())
}
