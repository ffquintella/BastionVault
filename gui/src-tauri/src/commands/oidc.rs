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
//! Works against both embedded and remote vaults — `dispatch_vault_write`
//! routes through the shared `Backend` trait object on `AppState`,
//! so the embedded path goes through `Core::handle_request` and the
//! remote path goes through `RemoteBackend` over HTTP. Same JSON
//! shape either way.

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
    preferences::OidcCallbackPrefs,
    state::{AppState, OidcLoginSession},
};

/// Loopback address the GUI listens on for the OIDC callback. The port
/// comes from `Preferences::oidc_callback`: a fixed list (default 8473,
/// distinct from the Cloud Storage Target callback port 8472) or an
/// OS-assigned one.
pub const OIDC_CALLBACK_HOST: &str = "127.0.0.1";

fn redirect_uri_for(port: u16) -> String {
    format!("http://{OIDC_CALLBACK_HOST}:{port}/callback")
}

/// Bind the callback listener per `prefs` and return it with the
/// `redirect_uri` to send. Fixed mode tries the configured ports in order
/// and uses the first free one; if none is free it fails naming them all.
/// There is no fallback to a port the operator did not list: the provider
/// would reject an unregistered URI with a confusing error.
fn bind_callback(prefs: &OidcCallbackPrefs) -> Result<(TcpListener, String), String> {
    prefs.validate().map_err(|e| format!("oidc: {e}"))?;
    if prefs.is_dynamic() {
        let listener = TcpListener::bind((OIDC_CALLBACK_HOST, 0)).map_err(|e| format!("oidc: bind loopback: {e}"))?;
        let port = listener.local_addr().map_err(|e| format!("oidc: local_addr: {e}"))?.port();
        return Ok((listener, redirect_uri_for(port)));
    }
    let mut failures = Vec::new();
    for port in &prefs.ports {
        match TcpListener::bind((OIDC_CALLBACK_HOST, *port)) {
            Ok(listener) => return Ok((listener, redirect_uri_for(*port))),
            Err(e) => failures.push(format!("{port} ({e})")),
        }
    }
    Err(format!(
        "oidc: cannot listen for the login callback on {OIDC_CALLBACK_HOST} port(s) {} \
         (is another program using them?)",
        failures.join(", ")
    ))
}

#[tauri::command]
pub async fn get_oidc_callback_prefs() -> Result<OidcCallbackPrefs, String> {
    Ok(crate::preferences::load().unwrap_or_default().oidc_callback)
}

/// Validated before it is written. Loads strictly: a preferences file that
/// does not parse is reported, not overwritten with defaults (which would
/// drop the saved vault list).
#[tauri::command]
pub async fn set_oidc_callback_prefs(prefs: OidcCallbackPrefs) -> Result<(), CommandError> {
    prefs.validate().map_err(CommandError::from)?;
    let mut all = crate::preferences::load()?;
    all.oidc_callback = prefs;
    crate::preferences::save(&all)
}

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

    // A login abandoned without `oidc_login_cancel` still holds its
    // listener (and, in fixed mode, the port), so drop any pending session
    // first: only one interactive login runs at a time.
    state.oidc_sessions.lock().map_err(|e| format!("oidc session map poisoned: {e}"))?.clear();
    let prefs = crate::preferences::load().map_err(|e| format!("oidc: preferences: {e}"))?.oidc_callback;
    let (listener, redirect_uri) = bind_callback(&prefs)?;

    // Ask the vault to compose the auth URL. Body carries
    // `redirect_uri` + optional `role`. Returns `{auth_url}`.
    let mut body = Map::new();
    body.insert("redirect_uri".into(), Value::String(redirect_uri.clone()));
    if let Some(r) = role.as_deref().map(|r| r.trim()).filter(|r| !r.is_empty()) {
        body.insert("role".into(), Value::String(r.to_string()));
    }
    let path = format!("auth/{mount}/auth_url");
    let resp = dispatch_vault_write(&state, &path, body).await.map_err(|e| format!("oidc: {path}: {e}"))?;
    let auth_url = resp
        .get("auth_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "oidc: vault response missing `auth_url`".to_string())?
        .to_string();

    let session_id = short_id();
    let entry = OidcLoginSession { listener, redirect_uri, mount };
    state
        .oidc_sessions
        .lock()
        .map_err(|e| format!("oidc session map poisoned: {e}"))?
        .insert(session_id.clone(), entry);

    Ok(OidcLoginStartResult { session_id, auth_url })
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
    let OidcLoginSession { listener, redirect_uri: _, mount } = state
        .oidc_sessions
        .lock()
        .map_err(|e| format!("oidc session map poisoned: {e}"))?
        .remove(&session_id)
        .ok_or_else(|| "oidc: no such session (it may have timed out or been cancelled)".to_string())?;

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
    let resp = dispatch_vault_write(&state, &path, body).await.map_err(|e| format!("oidc: {path}: {e}"))?;

    // The vault's `callback` handler returns an `Auth` embedded in
    // the response envelope. In the logical layer that's
    // `{auth: {client_token, policies, ...}}`. Over HTTP it's
    // `{auth: {...}}` with `data` possibly null. Accept either.
    let auth_obj = resp
        .get("auth")
        .and_then(|v| v.as_object())
        .cloned()
        .ok_or_else(|| "oidc: vault response missing `auth` — callback may have failed".to_string())?;
    let client_token = auth_obj
        .get("client_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "oidc: vault response missing `client_token`".to_string())?
        .to_string();
    let policies: Vec<String> = auth_obj
        .get("policies")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|p| p.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| vec!["default".to_string()]);

    // Persist into state for the rest of the GUI to use.
    *state.token.lock().await = Some(client_token.clone());

    Ok(LoginResponse { token: client_token, policies })
}

#[tauri::command]
pub async fn oidc_login_cancel(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    state.oidc_sessions.lock().map_err(|e| format!("oidc session map poisoned: {e}"))?.remove(&session_id);
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
    listener.set_nonblocking(true).map_err(|e| format!("oidc: set nonblocking: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            return Err("oidc: timed out waiting for browser callback".into());
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
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
    reader.read_line(&mut request_line).map_err(|e| format!("oidc: read request line: {e}"))?;
    // Drain headers so the peer doesn't get ECONNRESET when we
    // start writing the response.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|e| format!("oidc: read headers: {e}"))?;
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
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut it = trimmed.splitn(3, ' ');
    let method = it.next().ok_or_else(|| "oidc: empty request line".to_string())?;
    if method != "GET" {
        return Err(format!("oidc: expected GET callback, got {method}"));
    }
    let path_and_query = it.next().ok_or_else(|| "oidc: malformed request line".to_string())?;

    // We only need `code`, `state`, `error`, `error_description`
    // from the query string, so a tiny manual parser is simpler
    // than pulling in a whole URL-parsing crate just for this.
    // The URL shape is fixed (`/callback?k=v&k=v...`) so standard
    // percent-decoding on `+` and `%HH` is sufficient.
    let query = path_and_query.split_once('?').map(|(_, q)| q).unwrap_or_default();

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

/// Send a write-shaped request into the vault, going through the
/// shared `Backend` trait so both Embedded and Remote modes use the
/// same path. Returns a flat Map containing the response's `data`
/// object plus an `auth` field (if any) so the existing oidc
/// callback parsing on the JS side can keep its shape.
///
/// The oidc/auth_url + oidc/callback endpoints are marked `unauth`
/// on the backend, so we explicitly pass an empty token rather
/// than leaking whatever's in `state.token`.
async fn dispatch_vault_write(
    state: &State<'_, AppState>,
    path: &str,
    body: Map<String, Value>,
) -> Result<Map<String, Value>, CommandError> {
    use bv_client::Operation;

    let resp = crate::commands::dispatch_with_token(state, Operation::Write, path.to_string(), Some(body), "")
        .await?
        .ok_or("vault returned empty response")?;

    let mut out = Map::new();
    if let Some(data) = resp.data {
        for (k, v) in data {
            out.insert(k, v);
        }
    }
    if let Some(auth) = resp.auth {
        // `auth` already arrives as a JSON Value (RemoteBackend
        // forwarded it verbatim, EmbeddedBackend serialized the
        // server-side Auth struct via serde). Pass it through
        // untouched — the frontend already knows how to read
        // `auth.client_token` / `auth.policies`.
        out.insert("auth".into(), auth);
    }
    Ok(out)
}

/// Short opaque session id. Not security-sensitive (the bound port
/// is the real secret) — just needs to be unique within the map.
fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let pid = std::process::id() as u128;
    format!("o{:x}{:x}", nanos, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs(mode: &str, ports: &[u16]) -> OidcCallbackPrefs {
        OidcCallbackPrefs { mode: mode.into(), ports: ports.to_vec() }
    }

    #[test]
    fn default_is_fixed_8473() {
        assert_eq!(redirect_uri_for(OidcCallbackPrefs::default().ports[0]), "http://127.0.0.1:8473/callback");
    }

    #[test]
    fn dynamic_mode_gets_an_os_port() {
        let (l, uri) = bind_callback(&prefs("dynamic", &[8473])).unwrap();
        let port = l.local_addr().unwrap().port();
        assert_eq!(uri, redirect_uri_for(port));
    }

    #[test]
    fn fixed_mode_uses_first_free_port_in_order_and_fails_when_all_busy() {
        // Two ephemeral ports, found free then released for the test.
        let a = TcpListener::bind((OIDC_CALLBACK_HOST, 0)).unwrap().local_addr().unwrap().port();
        let b = TcpListener::bind((OIDC_CALLBACK_HOST, 0)).unwrap().local_addr().unwrap().port();
        let p = prefs("fixed", &[a, b]);
        let (first, uri) = bind_callback(&p).unwrap();
        assert_eq!(uri, redirect_uri_for(a));
        // `a` is now held, so the next login falls to `b`.
        let (second, uri) = bind_callback(&p).unwrap();
        assert_eq!(uri, redirect_uri_for(b));
        // Both held: a clear error naming both ports, no other port tried.
        let err = bind_callback(&p).unwrap_err();
        assert!(err.contains(&a.to_string()) && err.contains(&b.to_string()), "{err}");
        drop((first, second));
    }

    #[test]
    fn invalid_prefs_are_refused() {
        assert!(bind_callback(&prefs("fixed", &[])).is_err());
    }
}
