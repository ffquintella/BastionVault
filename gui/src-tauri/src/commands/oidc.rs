//! OIDC login flow for the GUI — three Tauri commands that bridge
//! the system browser to the vault's `oidc` auth backend.
//!
//! ```text
//!   oidc_login_start(mount, role)   ─► {sessionId, authUrl}
//!                                      └► frontend `shellOpen(authUrl)`
//!
//!   oidc_login_complete(sessionId)  ─► blocks on loopback listener
//!                                      ◄─ LoginResponse{token, policies}
//!
//!   oidc_login_cancel(sessionId)    ─► drops listener
//! ```
//!
//! Split shape (start / complete / cancel) exists so the frontend
//! can open the consent URL in the user's real system browser via
//! the Tauri shell plugin between the two calls — same pattern we
//! use for Cloud Storage Target connect. The vault's `oidc`
//! backend handles the PKCE + JWKS + ID-token verification
//! server-side; this module only has to carry the loopback bytes.
//!
//! Works against both embedded and remote vaults:
//!   * Embedded — calls flow through `vault.core.handle_request`.
//!   * Remote   — calls flow through the configured `remote_client`.
//! `dispatch_to_vault` picks the right path off `AppState`.

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Map, Value};
use tauri::{async_runtime, State};

use crate::{
    commands::auth::LoginResponse,
    error::CommandError,
    state::{AppState, OidcLoginSession},
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcLoginStartResult {
    pub session_id: String,
    pub auth_url: String,
}

/// Bind a loopback port, ask the vault's `oidc` backend for an
/// authorization URL pointing at the IdP, stash the session, and
/// return the URL so the frontend can open it in the system
/// browser.
#[tauri::command]
pub async fn oidc_login_start(
    state: State<'_, AppState>,
    mount: String,
    role: Option<String>,
) -> Result<OidcLoginStartResult, String> {
    let mount = mount.trim().trim_end_matches('/').to_string();
    if mount.is_empty() {
        return Err("oidc: `mount` is required (e.g. `oidc` or `okta`)".into());
    }

    // Bind a fresh port on loopback. Random port is fine here —
    // each login flow is a one-off, and the redirect_uri we pass
    // to the vault's auth_url is the same URL the IdP will call
    // back, so stability across runs doesn't matter (unlike the
    // Cloud Storage Target flow where the provider pre-registers
    // a specific URI).
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("oidc: bind loopback: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("oidc: local_addr: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    // Ask the vault to compose the auth URL. Body carries
    // `redirect_uri` + optional `role`. Returns `{auth_url}`.
    let mut body = Map::new();
    body.insert("redirect_uri".into(), Value::String(redirect_uri.clone()));
    if let Some(r) = role.as_deref().map(|r| r.trim()).filter(|r| !r.is_empty()) {
        body.insert("role".into(), Value::String(r.to_string()));
    }
    let path = format!("auth/{mount}/auth_url");
    let resp = dispatch_vault_write(&state, &path, body)
        .await
        .map_err(|e| format!("oidc: {path}: {e}"))?;
    let auth_url = resp
        .get("auth_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "oidc: vault response missing `auth_url`".to_string())?
        .to_string();

    let session_id = short_id();
    let entry = OidcLoginSession {
        listener,
        redirect_uri,
        mount,
    };
    state
        .oidc_sessions
        .lock()
        .map_err(|e| format!("oidc session map poisoned: {e}"))?
        .insert(session_id.clone(), entry);

    Ok(OidcLoginStartResult {
        session_id,
        auth_url,
    })
}

/// Block (up to `timeout_secs`) waiting for the IdP to redirect
/// back to our loopback, then POST `{code, state}` to the vault's
/// `callback`. On success, the vault returns an `Auth` with a
/// ready-to-use `client_token`, which we stash into `AppState` and
/// hand back to the frontend.
#[tauri::command]
pub async fn oidc_login_complete(
    state: State<'_, AppState>,
    session_id: String,
    timeout_secs: Option<u64>,
) -> Result<LoginResponse, String> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(300));

    // Take the session out of the map — we're about to block on it.
    // Holding the map lock across the accept loop would deadlock
    // every other Tauri command.
    let OidcLoginSession {
        listener,
        redirect_uri: _,
        mount,
    } = state
        .oidc_sessions
        .lock()
        .map_err(|e| format!("oidc session map poisoned: {e}"))?
        .remove(&session_id)
        .ok_or_else(|| {
            "oidc: no such session (it may have timed out or been cancelled)".to_string()
        })?;

    // Wait for the callback on a worker so the tokio runtime isn't
    // parked on the accept loop.
    let params = async_runtime::spawn_blocking(move || -> Result<OidcCallback, String> {
        wait_for_callback(listener, timeout).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("oidc worker: {e}"))??;

    // Call the vault's `callback` with the returned code + state.
    let mut body = Map::new();
    body.insert("state".into(), Value::String(params.state.clone()));
    body.insert("code".into(), Value::String(params.code.clone()));
    let path = format!("auth/{mount}/callback");
    let resp = dispatch_vault_write(&state, &path, body)
        .await
        .map_err(|e| format!("oidc: {path}: {e}"))?;

    // The vault's `callback` handler returns an `Auth` embedded in
    // the response envelope. In the logical layer that's
    // `{auth: {client_token, policies, ...}}`. Over HTTP it's
    // `{auth: {...}}` with `data` possibly null. Accept either.
    let auth_obj = resp
        .get("auth")
        .and_then(|v| v.as_object())
        .cloned()
        .ok_or_else(|| {
            "oidc: vault response missing `auth` — callback may have failed".to_string()
        })?;
    let client_token = auth_obj
        .get("client_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "oidc: vault response missing `client_token`".to_string())?
        .to_string();
    let policies: Vec<String> = auth_obj
        .get("policies")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["default".to_string()]);

    // Persist into state for the rest of the GUI to use.
    *state.token.lock().await = Some(client_token.clone());

    Ok(LoginResponse {
        token: client_token,
        policies,
    })
}

#[tauri::command]
pub async fn oidc_login_cancel(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    state
        .oidc_sessions
        .lock()
        .map_err(|e| format!("oidc session map poisoned: {e}"))?
        .remove(&session_id);
    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────

#[derive(Debug)]
struct OidcCallback {
    code: String,
    state: String,
}

/// Accept the first TCP connection, parse `GET /callback?...`,
/// respond with a tiny success page, return the callback params.
/// Non-blocking accept loop with polling so the timeout is
/// respected even when the user never completes consent.
fn wait_for_callback(listener: TcpListener, timeout: Duration) -> Result<OidcCallback, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("oidc: set nonblocking: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            return Err("oidc: timed out waiting for browser callback".into());
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .ok();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .ok();
                return handle_callback(stream);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("oidc: accept: {e}")),
        }
    }
}

fn handle_callback(mut stream: TcpStream) -> Result<OidcCallback, String> {
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("oidc: read request line: {e}"))?;
    // Drain headers so the peer doesn't get ECONNRESET when we
    // start writing the response.
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("oidc: read headers: {e}"))?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let params = parse_callback_request(&request_line)?;
    // Always acknowledge, even before reporting errors upstream, so
    // the user sees the familiar "you can close this window" page.
    let _ = respond_ok(&mut stream);
    Ok(params)
}

fn parse_callback_request(line: &str) -> Result<OidcCallback, String> {
    let trimmed = line.trim_end_matches(&['\r', '\n']);
    let mut it = trimmed.splitn(3, ' ');
    let method = it
        .next()
        .ok_or_else(|| "oidc: empty request line".to_string())?;
    if method != "GET" {
        return Err(format!("oidc: expected GET callback, got {method}"));
    }
    let path_and_query = it
        .next()
        .ok_or_else(|| "oidc: malformed request line".to_string())?;

    // We only need `code`, `state`, `error`, `error_description`
    // from the query string, so a tiny manual parser is simpler
    // than pulling in a whole URL-parsing crate just for this.
    // The URL shape is fixed (`/callback?k=v&k=v...`) so standard
    // percent-decoding on `+` and `%HH` is sufficient.
    let query = path_and_query
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default();

    let mut code = None;
    let mut state = None;
    let mut err_param = None;
    let mut err_desc = None;
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = form_urldecode(v);
        match k {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => err_param = Some(v),
            "error_description" => err_desc = Some(v),
            _ => {}
        }
    }
    if let Some(e) = err_param {
        let desc = err_desc.unwrap_or_default();
        return Err(format!("oidc: provider returned error `{e}`: {desc}"));
    }
    let code = code.ok_or_else(|| "oidc: callback missing `code`".to_string())?;
    let state = state.ok_or_else(|| "oidc: callback missing `state`".to_string())?;
    Ok(OidcCallback { code, state })
}

/// Minimal x-www-form-urlencoded decoder for query-string values:
/// `+` → space, `%HH` → that byte, everything else passed through.
/// Matches what browsers emit on OAuth redirects; good enough for
/// our fixed `code` / `state` / `error*` field set.
fn form_urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| {
        // Malformed UTF-8 in the callback is a provider bug; we
        // still hand back the lossy version so the caller can
        // decide what to do — usually the downstream vault call
        // will reject the state anyway.
        String::from_utf8_lossy(e.as_bytes()).into_owned()
    })
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn respond_ok(stream: &mut TcpStream) -> std::io::Result<()> {
    let body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>BastionVault</title>\
<style>body{font-family:sans-serif;text-align:center;padding:3em;color:#333}</style></head>\
<body><h1>\u{2713} Signed in</h1><p>You can close this window and return to BastionVault.</p></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Send a write-shaped request into the vault. Picks the embedded
/// core (`vault.core.handle_request`) when the mode is `Embedded`,
/// otherwise routes through the remote HTTP client.
///
/// Returns the response `data` object unwrapped — `auth_url` sits
/// in the data payload for `auth/<mount>/auth_url`, and the `auth`
/// field for `callback` sits at the top of the envelope. We merge
/// both into a single object for the caller to introspect.
async fn dispatch_vault_write(
    state: &State<'_, AppState>,
    path: &str,
    body: Map<String, Value>,
) -> Result<Map<String, Value>, CommandError> {
    use crate::state::VaultMode;

    let mode = state.mode.lock().await.clone();
    match mode {
        VaultMode::Embedded => {
            let vault_guard = state.vault.lock().await;
            let vault = vault_guard.as_ref().ok_or("Vault not open")?;
            let core = vault.core.load();

            use bastion_vault::logical::{Operation, Request};
            let mut req = Request::default();
            req.operation = Operation::Write;
            req.path = path.to_string();
            req.body = Some(body);
            // The oidc/auth_url + oidc/callback endpoints are
            // marked `unauth` on the backend, so a missing token
            // is fine.

            let resp = core
                .handle_request(&mut req)
                .await
                .map_err(CommandError::from)?;
            let resp = resp.ok_or("vault returned empty response")?;
            let mut out = Map::new();
            if let Some(data) = resp.data {
                for (k, v) in data {
                    out.insert(k, v);
                }
            }
            if let Some(auth) = resp.auth {
                // Project the Auth struct into the JSON shape the
                // frontend side already expects.
                let mut auth_obj = Map::new();
                auth_obj.insert(
                    "client_token".into(),
                    Value::String(auth.client_token.clone()),
                );
                auth_obj.insert(
                    "policies".into(),
                    Value::Array(auth.policies.iter().cloned().map(Value::String).collect()),
                );
                auth_obj.insert(
                    "display_name".into(),
                    Value::String(auth.display_name.clone()),
                );
                out.insert("auth".into(), Value::Object(auth_obj));
            }
            Ok(out)
        }
        VaultMode::Remote => {
            let client_guard = state.remote_client.lock().await;
            let client = client_guard
                .as_ref()
                .ok_or("Not connected to remote server")?;
            let endpoint = format!("{}/{}", client.api_prefix(), path);
            let resp = client
                .request_write(endpoint, Some(body))
                .map_err(|e| CommandError::from(format!("remote write failed: {e}")))?;
            let mut out = Map::new();
            if let Some(data) = resp.response_data {
                if let Some(obj) = data.as_object() {
                    for (k, v) in obj {
                        out.insert(k.clone(), v.clone());
                    }
                }
            }
            Ok(out)
        }
    }
}

/// Short opaque session id. Not security-sensitive (the bound port
/// is the real secret) — just needs to be unique within the map.
fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    format!("o{:x}{:x}", nanos, pid)
}

