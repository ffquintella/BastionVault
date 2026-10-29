//! Tauri commands of the SQL workspace (features/sql-browser.md §10, T125
//! Phase 4). `sql_session_open` opens a plugin session with the host-held
//! token; every other command names the local session token and is refused
//! unless the calling window holds that session (`require_session_window`).
//! The vault and the plugin decide every statement: nothing here gates SQL.

use bv_client::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{AppHandle, State, Webview};

use super::connect::{
    now_rfc3339, open_context, place_in_workspace, require_session_window, resolve_session_layout, run_cleanup,
    spawn_own_session_window,
};
use crate::error::{CmdResult, CommandError};
use crate::session::{
    self,
    attachments::SessionDescriptor,
    sql::{self as sqls, SqlSessionState},
    workspace::Placement,
    SessionCleanupKind, SessionState,
};
use crate::state::AppState;

/// Largest statement text forwarded (`bv_sql_classify::MAX_TEXT_BYTES`).
const MAX_SQL_BYTES: usize = 4 * 1024 * 1024;
/// Most objects one privileges read asks about.
const MAX_PRIVILEGE_OBJECTS: usize = 64;

/// One call to the plugin, with the current host token, pinned to the
/// namespace the session was opened in. Returns the reply's `data`.
async fn call(
    state: &State<'_, AppState>,
    namespace: Option<&str>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> CmdResult<Map<String, Value>> {
    let token = state.token.lock().await.clone().unwrap_or_default();
    let resp = super::dispatch_with_token_ns(state, operation, path, body, &token, namespace).await?;
    Ok(resp.and_then(|r| r.data).unwrap_or_default())
}

/// The SQL console mount: among the `plugin:<name>` mounts the caller's
/// policy shows, exactly one whose plugin declares `sql_console`.
async fn resolve_console_mount(state: &State<'_, AppState>) -> CmdResult<String> {
    let mounts = super::system::read_ui_mounts(state, "secret").await?;
    let mut consoles = Vec::new();
    let mut unconfirmed = Vec::new();
    for (mount, plugin) in sqls::plugin_mounts(&mounts) {
        match super::plugins::plugin_declares_sql_console(state, &plugin).await {
            Ok(true) => consoles.push((mount, plugin)),
            Ok(false) => {}
            Err(e) => unconfirmed.push(format!("{plugin}: {e}")),
        }
    }
    if consoles.is_empty() && !unconfirmed.is_empty() {
        return Err(CommandError::from(format!(
            "cannot confirm which plugin mount is the SQL console ({}); this token may not read the plugin \
             catalog",
            unconfirmed.join("; ")
        )));
    }
    sqls::pick_console_mount(&consoles).map_err(CommandError::from)
}

/// The calling window's SQL session behind `token`.
async fn session_for(state: &State<'_, AppState>, webview: &Webview, token: &str) -> CmdResult<SqlSessionState> {
    require_session_window(state, webview, token).await?;
    match state.connect_sessions.lock().await.get(token) {
        Some(SessionState::Sql(s)) => Ok(s.clone()),
        Some(_) => Err(CommandError::from(format!("session `{token}` is not a SQL session"))),
        None => Err(CommandError::from("the SQL session has ended".to_string())),
    }
}

/// `DELETE <mount>v2/sessions/<id>`: the close hook of every stop path.
pub(crate) async fn close_plugin_session(
    state: &State<'_, AppState>,
    mount: &str,
    session_id: &str,
    namespace: Option<&str>,
) -> CmdResult<Map<String, Value>> {
    if !sqls::plugin_session_id_ok(session_id) {
        return Err(CommandError::from("refusing to address a malformed SQL session id".to_string()));
    }
    let path = sqls::session_path(mount, session_id, "");
    call(state, namespace, Operation::Delete, path, None).await.map(sqls::scrub_status)
}

#[derive(Deserialize)]
pub struct SqlOpenRequest {
    pub resource_name: String,
    /// Absent: the plugin picks the smallest qualifying profile (§5.2).
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub catalog: Option<String>,
    /// Connect-time MFA ticket for a `require_mfa` profile; the plugin
    /// redeems it through the host before any login is released.
    #[serde(default)]
    pub connect_ticket: Option<String>,
    #[serde(default)]
    pub placement: Option<Placement>,
}

#[derive(Serialize)]
pub struct SqlOpenResponse {
    pub token: String,
    pub window_label: String,
    pub label: String,
    /// The plugin's session status, without its session id.
    pub status: Map<String, Value>,
}

/// Open a SQL session and render it in its own window (`sql-<token>`) or
/// as a Session Workspace pane.
#[tauri::command]
pub async fn sql_session_open(
    state: State<'_, AppState>,
    app: AppHandle,
    request: SqlOpenRequest,
) -> CmdResult<SqlOpenResponse> {
    let opened_in = open_context(&state, None).await?;
    let (placement, layout_prefs) = resolve_session_layout(request.placement)?;
    let namespace = state.active_namespace.lock().await.clone().filter(|n| !n.is_empty());
    let body = sqls::open_body(
        &request.resource_name,
        request.profile_id.as_deref(),
        request.catalog.as_deref(),
        request.connect_ticket.as_deref(),
    )
    .map_err(CommandError::from)?;
    let mount = resolve_console_mount(&state).await?;
    let reply = call(&state, namespace.as_deref(), Operation::Write, format!("{mount}v2/sessions"), Some(body)).await?;
    let text = |k: &str| reply.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let session_id = text("session_id");
    if !sqls::plugin_session_id_ok(&session_id) {
        // Cannot be addressed safely, so it is not closed from here; the
        // plugin's idle sweep ends it.
        log::warn!("resource-connect/sql: the plugin returned a malformed session id (mount={mount})");
        return Err(CommandError::from("the SQL browser plugin returned a malformed session id".to_string()));
    }
    let resource = Some(text("resource")).filter(|r| !r.is_empty()).unwrap_or(request.resource_name.clone());
    let (profile, catalog) = (text("profile"), text("catalog"));
    let label = sqls::label(&resource, &profile, &catalog);
    let token = session::ssh::new_token();
    let st = SqlSessionState {
        mount: mount.clone(),
        session_id,
        namespace,
        resource: resource.clone(),
        catalog,
        opened_on: sqls::utc_date(chrono::Utc::now().timestamp_millis()),
    };
    state.connect_sessions.lock().await.insert(token.clone(), SessionState::Sql(st));
    let descriptor = SessionDescriptor {
        token: token.clone(),
        protocol: session::ProfileProtocol::Sql,
        label: label.clone(),
        resource_name: resource.clone(),
        profile_id: profile.clone(),
        stdout_event: None,
        closed_event: String::new(),
        resize_event: None,
        cursor_event: None,
        width: None,
        height: None,
        opened_at: now_rfc3339(),
        placement,
        pane_ref: None,
        namespace: opened_in.namespace,
        vault_id: opened_in.vault_id,
    };
    // Either path stops the session (and closes the plugin's) on failure.
    let window_label = if placement.is_workspace() {
        place_in_workspace(&app, &state, descriptor).await?
    } else {
        spawn_own_session_window(&app, &state, descriptor, &layout_prefs).await?
    };
    log::info!(
        target: "audit",
        "session.open: resource={resource} protocol=sql profile={profile} mount={mount} token={token} window={window_label}"
    );
    Ok(SqlOpenResponse { token, window_label, label, status: sqls::scrub_status(reply) })
}

#[derive(Deserialize)]
pub struct SqlTokenRequest {
    pub token: String,
}

/// Session status: engine, enforcement, `db_enforced`, privileges, ceiling,
/// transport, TLS mode, transaction and timers.
#[tauri::command]
pub async fn sql_session_status(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlTokenRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    call(&state, s.namespace.as_deref(), Operation::Read, s.path(""), None).await.map(sqls::scrub_status)
}

#[derive(Deserialize)]
pub struct SqlObjectRef {
    pub schema: String,
    pub object: String,
}

#[derive(Deserialize)]
pub struct SqlPrivilegesRequest {
    pub token: String,
    #[serde(default)]
    pub objects: Vec<SqlObjectRef>,
}

/// The caller's own effective SQL capabilities on the session's resource
/// (`resources/v2/sql/privileges/<r>`), for chips and disabled buttons.
/// Display only: the plugin and the vault decide every statement.
#[tauri::command]
pub async fn sql_privileges(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlPrivilegesRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    if s.resource.is_empty() || s.resource.contains(['/', '?', '#']) {
        return Err(CommandError::from("resource name must be a single path segment".to_string()));
    }
    if request.objects.len() > MAX_PRIVILEGE_OBJECTS {
        return Err(CommandError::from(format!("at most {MAX_PRIVILEGE_OBJECTS} objects per read")));
    }
    let mut path = format!("resources/v2/sql/privileges/{}", s.resource);
    if !request.objects.is_empty() {
        let triples: Vec<String> =
            request.objects.iter().map(|o| sqls::privileges_triple(&s.catalog, &o.schema, &o.object)).collect();
        path.push_str("?objects=");
        path.push_str(&triples.join(","));
    }
    call(&state, s.namespace.as_deref(), Operation::Read, path, None).await
}

#[derive(Deserialize)]
pub struct SqlExecuteRequest {
    pub token: String,
    pub sql: String,
}

/// Run one statement (plus transaction control). The reply is `{run_id,
/// state, statements}` or, when the vault refuses, `{state: "refused",
/// message, statements}` with the verdicts.
#[tauri::command]
pub async fn sql_execute(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlExecuteRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    if request.sql.trim().is_empty() {
        return Err(CommandError::from("nothing to run".to_string()));
    }
    if request.sql.len() > MAX_SQL_BYTES {
        return Err(CommandError::from("the statement is larger than 4 MiB".to_string()));
    }
    let mut body = Map::new();
    body.insert("sql".into(), Value::String(request.sql));
    call(&state, s.namespace.as_deref(), Operation::Write, s.path("execute"), Some(body)).await
}

#[derive(Deserialize)]
pub struct SqlRunRequest {
    pub token: String,
    pub run_id: String,
}

fn run_suffix(run_id: &str, tail: &str) -> CmdResult<String> {
    if !sqls::run_id_ok(run_id) {
        return Err(CommandError::from("run id must be 1-32 letters, digits, `_` or `-`".to_string()));
    }
    Ok(format!("runs/{run_id}{tail}"))
}

/// The next page of a run: columns, rows, messages, state.
#[tauri::command]
pub async fn sql_run(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlRunRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    let suffix = run_suffix(&request.run_id, "")?;
    call(&state, s.namespace.as_deref(), Operation::Read, s.path(&suffix), None).await
}

/// Ask the database to cancel a run.
#[tauri::command]
pub async fn sql_cancel(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlRunRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    let suffix = run_suffix(&request.run_id, "/cancel")?;
    call(&state, s.namespace.as_deref(), Operation::Write, s.path(&suffix), None).await
}

#[derive(Deserialize)]
pub struct SqlObjectsRequest {
    pub token: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub object: Option<String>,
}

/// The object browser: schemas, a schema's objects, or one object's
/// description (columns, keys, indexes, definition, editability).
#[tauri::command]
pub async fn sql_objects(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlObjectsRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    let suffix =
        sqls::objects_suffix(request.schema.as_deref(), request.object.as_deref()).map_err(CommandError::from)?;
    call(&state, s.namespace.as_deref(), Operation::Read, s.path(&suffix), None).await
}

#[derive(Deserialize)]
pub struct SqlRowsRequest {
    pub token: String,
    pub edit: Map<String, Value>,
}

/// A structured grid edit (`{object, op, key, values, original}`); the
/// plugin builds the parameterized statement and reports a conflict when
/// the row changed since it was read.
#[tauri::command]
pub async fn sql_rows(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlRowsRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    sqls::check_edit(&request.edit).map_err(CommandError::from)?;
    call(&state, s.namespace.as_deref(), Operation::Write, s.path("rows"), Some(request.edit)).await
}

#[derive(Deserialize)]
pub struct SqlHistoryRequest {
    pub token: String,
    /// `YYYY-MM-DD`: list the caller's sessions of that day.
    #[serde(default)]
    pub date: Option<String>,
    /// With `date`: that session's journal record.
    #[serde(default)]
    pub session: Option<String>,
}

/// The caller's own statement history from the plugin's journal
/// (`v2/journal/self/…`; the plugin filters by the caller's entity). No
/// arguments: this session's record.
#[tauri::command]
pub async fn sql_history(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlHistoryRequest,
) -> CmdResult<Map<String, Value>> {
    let s = session_for(&state, &webview, &request.token).await?;
    let ns = s.namespace.as_deref();
    let base = format!("{}v2/journal/self", s.mount);
    match (request.date.as_deref(), request.session.as_deref()) {
        (None, None) => {
            let mut dates = vec![s.opened_on.clone()];
            dates.extend(sqls::adjacent_dates(&s.opened_on));
            let mut last = None;
            for date in dates.iter().filter(|d| sqls::journal_date_ok(d)) {
                match call(&state, ns, Operation::Read, format!("{base}/{date}/{}", s.session_id), None).await {
                    Ok(record) => return Ok(record),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| CommandError::from("no journal record for this session yet".to_string())))
        }
        (Some(date), session) => {
            if !sqls::journal_date_ok(date) {
                return Err(CommandError::from("date must be YYYY-MM-DD".to_string()));
            }
            let path = match session {
                None => format!("{base}/{date}"),
                Some(id) if sqls::plugin_session_id_ok(id) => format!("{base}/{date}/{id}"),
                Some(_) => return Err(CommandError::from("not a SQL session id".to_string())),
            };
            call(&state, ns, Operation::Read, path, None).await
        }
        (None, Some(_)) => Err(CommandError::from("a session's history needs its date".to_string())),
    }
}

/// Close the calling window's SQL session: drop it from every registry and
/// close the plugin's session (rolling back an open transaction).
#[tauri::command]
pub async fn sql_session_close(
    state: State<'_, AppState>,
    webview: Webview,
    request: SqlTokenRequest,
) -> CmdResult<Map<String, Value>> {
    session_for(&state, &webview, &request.token).await?;
    match session::attachments::stop_session(&state, &request.token).await {
        Some(cleanup) => match cleanup.kind {
            SessionCleanupKind::SqlSessionClose { mount, session_id, namespace } => {
                close_plugin_session(&state, &mount, &session_id, namespace.as_deref()).await
            }
            _ => {
                run_cleanup(&state, cleanup).await;
                Ok(Map::new())
            }
        },
        // Another stop path took it first; it closes the plugin session.
        None => Ok(Map::new()),
    }
}
