//! The local MCP server, hosted by the desktop app (`features/mcp-access.md`
//! Phase 5, T131).
//!
//! An AI assistant reaches it without the `bvault` CLI: it launches this same
//! binary with `--mcp-stdio` ([`relay`]), which connects to the running app's
//! owner-only Unix socket and relays its stdin/stdout. The app runs the
//! shared gatekeeper ([`bv_mcp::local`]) with
//!
//! * a [`link::GuiVaultLink`]: the app's own connection, embedded or remote,
//!   bound to the vault session the server was started under;
//! * a [`prompter::GuiPrompter`]: pairing consent and per-call confirmation as
//!   dialogs in the main window, refused when nobody answers.
//!
//! Off unless the operator turns it on. It runs only while a non-root vault
//! session is unlocked, stops on sign-out, lock and vault switch (and
//! whenever a call finds the session it was started for has ended), and on
//! stopping it forgets every token it minted. No token, minted or of the
//! session, is ever sent to the frontend or written to disk.

// Only a Unix build serves (the socket needs Unix domain sockets); elsewhere
// the session-bound link and the dialog prompter compile but are never
// constructed, and the switch reports the platform unsupported.
#[cfg_attr(not(unix), allow(dead_code))]
pub mod link;
#[cfg_attr(not(unix), allow(dead_code))]
pub mod prompter;
pub mod relay;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bv_client::Operation;
#[cfg(unix)]
use bv_mcp::pairing::now_secs;
use serde::Serialize;
#[cfg(unix)]
use tauri::Manager;
use tauri::{AppHandle, Emitter};

use crate::state::AppState;
use prompter::PromptBroker;
#[cfg(unix)]
use prompter::{McpPrompt, PromptSink};

/// The main window's event for a prompt to show (payload `McpPrompt`).
#[cfg_attr(not(unix), allow(dead_code))]
pub const PROMPT_EVENT: &str = "mcp-prompt";
/// The main window's event for a prompt that stopped waiting (payload: id).
pub const PROMPT_CLOSED_EVENT: &str = "mcp-prompt-closed";
/// Broadcast when the server starts or stops (payload [`McpServerStatus`]).
pub const STATUS_EVENT: &str = "mcp-server-status";
const MAIN_WINDOW: &str = "main";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct McpServerStatus {
    /// This platform can host the server (Unix domain sockets).
    pub supported: bool,
    /// The operator's saved preference: serve whenever a session is unlocked.
    pub enabled: bool,
    pub running: bool,
    pub socket_path: Option<String>,
    pub started_at: Option<u64>,
    /// Why the server last stopped or failed, for the Settings panel.
    pub last_error: Option<String>,
}

// Constructed only where the server can run (Unix).
#[cfg_attr(not(unix), allow(dead_code))]
struct Running {
    /// Which start this is, so a late stop meant for an earlier instance
    /// cannot stop this one.
    instance: u64,
    #[cfg(unix)]
    socket: bv_mcp::local::uds::SocketServer,
    /// The gatekeeper itself, for what Settings shows about its tokens.
    #[cfg(unix)]
    server: Arc<bv_mcp::local::LocalServer>,
    socket_path: PathBuf,
    started_at: u64,
}

pub struct McpHost {
    running: Mutex<Option<Running>>,
    /// The running server's prompt slot. Each start gets a fresh one, so a
    /// connection of a stopped server can never put a dialog in front of the
    /// operator, or hold the slot, after an off/on.
    prompts: Mutex<Arc<PromptBroker>>,
    last_error: Arc<Mutex<Option<String>>>,
    next_instance: AtomicU64,
}

impl Default for McpHost {
    fn default() -> Self {
        Self::new()
    }
}

/// Shows prompts in the main window, and only while the session the server
/// runs under is the live one.
#[cfg(unix)]
struct TauriSink {
    session: Arc<link::SessionGuard>,
}

#[cfg(unix)]
impl PromptSink for TauriSink {
    fn operator_present(&self) -> bool {
        self.session.app.get_webview_window(MAIN_WINDOW).is_some() && self.session.is_current()
    }

    fn show(&self, prompt: &McpPrompt) -> bool {
        let app = &self.session.app;
        let Some(window) = app.get_webview_window(MAIN_WINDOW) else {
            return false;
        };
        if app.emit_to(MAIN_WINDOW, PROMPT_EVENT, prompt).is_err() {
            return false;
        }
        // Draw the operator's eye; the dialog itself is in the window.
        let _ = window.request_user_attention(Some(tauri::UserAttentionType::Critical));
        true
    }

    fn withdraw(&self, id: &str) {
        let _ = self.session.app.emit_to(MAIN_WINDOW, PROMPT_CLOSED_EVENT, id);
    }
}

#[cfg(unix)]
fn log_notice(message: &str) {
    log::info!(target: "mcp", "{message}");
}

impl McpHost {
    pub fn new() -> Self {
        Self {
            running: Mutex::new(None),
            prompts: Mutex::new(Arc::new(PromptBroker::new())),
            last_error: Arc::new(Mutex::new(None)),
            next_instance: AtomicU64::new(1),
        }
    }

    /// The prompt slot of the server running now (a closed one otherwise).
    pub fn prompts(&self) -> Arc<PromptBroker> {
        lock(&self.prompts).clone()
    }

    pub fn status(&self) -> McpServerStatus {
        let running = lock(&self.running);
        McpServerStatus {
            supported: cfg!(unix),
            enabled: enabled_preference(),
            running: running.is_some(),
            socket_path: running
                .as_ref()
                .map(|r| r.socket_path.display().to_string())
                .or_else(|| default_socket_path().ok().map(|p| p.display().to_string())),
            started_at: running.as_ref().map(|r| r.started_at),
            last_error: lock(&self.last_error).clone(),
        }
    }

    /// Where each live minted token is bound, by pairing id (T457): what
    /// Settings → AI Assistants shows. Empty while the server is off.
    pub fn token_namespaces(&self) -> std::collections::HashMap<String, Option<String>> {
        #[cfg(unix)]
        if let Some(running) = lock(&self.running).as_ref() {
            return running.server.token_namespaces();
        }
        std::collections::HashMap::new()
    }

    fn set_last_error(&self, message: Option<String>) {
        *lock(&self.last_error) = message;
    }

    /// Starts serving for the session that is live now. Refuses -- with a
    /// reason the operator can act on -- when there is no unlocked session or
    /// it is a root session (the vault refuses to mint MCP tokens from one).
    pub async fn start(&self, app: &AppHandle, state: &AppState) -> Result<McpServerStatus, String> {
        if !cfg!(unix) {
            return Err(
                "serving AI assistants needs Unix domain sockets, which this platform's build does not support yet"
                    .into(),
            );
        }
        if lock(&self.running).is_some() {
            return Ok(self.status());
        }
        let Some((fingerprint, session)) = link::current_session(state).await else {
            return Err("unlock your vault and sign in first".into());
        };
        refuse_root_session(state, &session.token).await?;
        drop(session);
        // The session may have ended while the vault was asked; bind to it
        // only if it is still the live one.
        if link::current_session(state).await.map(|(now, _)| now) != Some(fingerprint.clone()) {
            return Err("the vault session changed while starting; try again".into());
        }

        let started = self.start_serving(app, fingerprint);
        match &started {
            Ok(_) => self.set_last_error(None),
            Err(e) => self.set_last_error(Some(e.clone())),
        }
        started?;
        let status = self.status();
        let _ = app.emit(STATUS_EVENT, &status);
        Ok(status)
    }

    #[cfg(unix)]
    fn start_serving(&self, app: &AppHandle, fingerprint: link::SessionFingerprint) -> Result<(), String> {
        use bv_mcp::local::{uds, LocalServer};
        use bv_mcp::pairing::PairingStore;

        let mut running = lock(&self.running);
        if running.is_some() {
            return Ok(());
        }
        let socket_path = default_socket_path()?;
        let store = PairingStore::at(PairingStore::default_path().map_err(|e| e.to_string())?);
        let vault_label = match fingerprint.vault.strip_prefix("remote:") {
            Some(address) => address.to_string(),
            None => "the local vault on this device".to_string(),
        };
        let session = Arc::new(link::SessionGuard { app: app.clone(), fingerprint });
        let instance = self.next_instance.fetch_add(1, Ordering::SeqCst);
        let broker = Arc::new(PromptBroker::new());

        let ended_app = app.clone();
        let link = link::GuiVaultLink {
            session: session.clone(),
            operator_namespace: Mutex::new(None),
            last_error: self.last_error.clone(),
            on_session_ended: Box::new(move || {
                // Off the calling connection's stack: stopping cuts that very
                // connection. Only this instance: a fresh sign-in may already
                // have started another.
                let app = ended_app.clone();
                std::thread::spawn(move || {
                    app.state::<AppState>().mcp_host.stop_instance(instance, Some(&app), link::SESSION_ENDED);
                });
            }),
        };
        let prompter = prompter::GuiPrompter {
            broker: broker.clone(),
            sink: Box::new(TauriSink { session }),
            same_uid: Some(uds::current_uid()),
            vault_label,
        };
        let server = LocalServer::new(Box::new(link), Box::new(prompter), store)
            .with_server_version(env!("CARGO_PKG_VERSION"))
            .with_notice(log_notice);

        // Open and install before the first connection can arrive, so its
        // pairing prompt is shown and answerable at once.
        broker.open();
        *lock(&self.prompts) = broker.clone();
        let server = Arc::new(server);
        let socket = match uds::SocketServer::start(server.clone(), &socket_path) {
            Ok(socket) => socket,
            Err(e) => {
                broker.close();
                return Err(format!("could not open {}: {e}", socket_path.display()));
            }
        };
        log::info!(target: "mcp", "serving AI assistants on {} (owner-only)", socket_path.display());
        *running = Some(Running { instance, socket, server, socket_path, started_at: now_secs() });
        Ok(())
    }

    #[cfg(not(unix))]
    fn start_serving(&self, _app: &AppHandle, _fingerprint: link::SessionFingerprint) -> Result<(), String> {
        Err("serving AI assistants needs Unix domain sockets, which this platform's build does not support yet".into())
    }

    /// Stops serving, if it is: the prompt on screen is abandoned (a
    /// refusal), every connection is cut, the socket is removed, and every
    /// minted token is forgotten. Returns the vault accessors of those
    /// tokens. Synchronous and quick -- it never waits on the vault -- so the
    /// sign-out, lock and vault-switch commands call it inline.
    pub fn stop(&self, app: Option<&AppHandle>, reason: &str) -> Vec<String> {
        let Some(running) = lock(&self.running).take() else {
            return Vec::new();
        };
        self.halt(running, app, reason)
    }

    /// [`Self::stop`], but only if instance `instance` is the one running.
    pub fn stop_instance(&self, instance: u64, app: Option<&AppHandle>, reason: &str) -> Vec<String> {
        let running = {
            let mut running = lock(&self.running);
            if running.as_ref().map(|r| r.instance) != Some(instance) {
                return Vec::new();
            }
            running.take()
        };
        running.map(|r| self.halt(r, app, reason)).unwrap_or_default()
    }

    fn halt(&self, running: Running, app: Option<&AppHandle>, reason: &str) -> Vec<String> {
        if let Some(id) = self.prompts().close() {
            if let Some(app) = app {
                let _ = app.emit_to(MAIN_WINDOW, PROMPT_CLOSED_EVENT, id);
            }
        }
        #[cfg(unix)]
        let accessors = running.socket.stop();
        #[cfg(not(unix))]
        let accessors = Vec::new();
        log::info!(target: "mcp", "stopped serving AI assistants on {}: {reason}", running.socket_path.display());
        self.set_last_error(Some(format!("stopped: {reason}")));
        if let Some(app) = app {
            let _ = app.emit(STATUS_EVENT, &self.status());
        }
        accessors
    }

    /// [`Self::stop`] at the operator's request, with the session still
    /// live: the forgotten tokens are also revoked on the vault, best effort.
    /// A revocation the session may not perform is not an error -- the
    /// tokens are children of the session and die with it at sign-out, and
    /// expire on their own otherwise.
    pub async fn stop_and_revoke(&self, app: &AppHandle, state: &AppState) {
        let accessors = self.stop(Some(app), "turned off");
        self.set_last_error(None);
        if accessors.is_empty() {
            let _ = app.emit(STATUS_EVENT, &self.status());
            return;
        }
        let token = state.token.lock().await.clone().unwrap_or_default();
        let backend = state.backend.lock().await.clone();
        let (mut revoked, total) = (0usize, accessors.len());
        if let (false, Some(backend)) = (token.is_empty(), backend) {
            for accessor in accessors {
                let path = format!("sys/mcp/tokens/{accessor}");
                if backend.handle_with_namespace(Operation::Delete, &path, None, &token, None).await.is_ok() {
                    revoked += 1;
                }
            }
        }
        log::info!(target: "mcp", "revoked {revoked} of {total} MCP tokens minted while serving");
        if revoked < total {
            self.set_last_error(Some(format!(
                "turned off; {} of {total} minted tokens could not be revoked on the vault and expire on their own",
                total - revoked
            )));
        }
        let _ = app.emit(STATUS_EVENT, &self.status());
    }
}

/// The vault refuses `mcp/token` from a root token; say so up front rather
/// than at the first assistant's first call.
async fn refuse_root_session(state: &AppState, token: &str) -> Result<(), String> {
    let backend = state.backend.lock().await.clone().ok_or("no vault is open")?;
    let resp = backend
        .handle_with_namespace(Operation::Read, "auth/token/lookup-self", None, token, None)
        .await
        .map_err(|e| format!("could not read the current session: {e}"))?;
    let policies: Vec<String> = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("policies").cloned())
        .and_then(|p| serde_json::from_value(p).ok())
        .unwrap_or_default();
    if policies.iter().any(|p| p == "root") {
        return Err("AI assistants cannot be served from a root session: the vault never mints an MCP token from a \
                    root token. Sign in as a regular user, then turn this on."
            .into());
    }
    Ok(())
}

pub fn default_socket_path() -> Result<PathBuf, String> {
    bv_mcp::local::default_gui_socket_path().map_err(|e| e.to_string())
}

pub fn enabled_preference() -> bool {
    crate::preferences::load().map(|p| p.mcp_local_server.enabled).unwrap_or(false)
}

pub fn set_enabled_preference(enabled: bool) -> Result<(), String> {
    let mut prefs = crate::preferences::load().map_err(|e| e.to_string())?;
    prefs.mcp_local_server.enabled = enabled;
    crate::preferences::save(&prefs).map_err(|e| e.to_string())
}

/// Starts the server when the operator enabled it and a session is unlocked;
/// a failure is recorded for the Settings panel, not raised.
pub async fn autostart(app: &AppHandle, state: &AppState) -> McpServerStatus {
    let host = &state.mcp_host;
    if enabled_preference() && cfg!(unix) && state.token.lock().await.as_deref().is_some_and(|t| !t.is_empty()) {
        if let Err(e) = host.start(app, state).await {
            log::warn!(target: "mcp", "AI-assistant server did not start: {e}");
        }
    }
    host.status()
}

/// The vault session is ending (sign-out, seal, vault switch, reset): stop
/// serving it. A no-op when the server is off.
pub fn session_ending(app: Option<&AppHandle>, state: &AppState, reason: &str) {
    state.mcp_host.stop(app, reason);
}

/// What the Settings panel shows for connecting an assistant: this binary's
/// path, the socket it serves, and ready-to-paste client configuration.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct McpClientSetup {
    pub binary_path: String,
    pub socket_path: String,
    pub claude_code_command: String,
    pub claude_desktop_config: String,
}

pub fn client_setup(binary: &std::path::Path, socket: &std::path::Path) -> McpClientSetup {
    let binary_path = binary.display().to_string();
    let claude_desktop_config = serde_json::to_string_pretty(&serde_json::json!({
        "mcpServers": {
            "bastionvault": {
                "command": binary_path,
                "args": [relay::FLAG],
            }
        }
    }))
    .unwrap_or_default();
    McpClientSetup {
        claude_code_command: format!(
            "claude mcp add bastionvault -s user -- {} {}",
            shell_quote(&binary_path),
            relay::FLAG
        ),
        claude_desktop_config,
        socket_path: socket.display().to_string(),
        binary_path,
    }
}

/// POSIX shell quoting for a path pasted into a terminal: left bare when it
/// is made only of characters no shell treats specially, single-quoted
/// otherwise.
fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "/._-+:,@%".contains(c));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::state::VaultMode;

    #[test]
    fn the_claude_code_command_is_the_documented_one() {
        let setup = client_setup(
            Path::new("/Applications/BastionVault.app/Contents/MacOS/bastion-vault-gui"),
            Path::new("/Users/me/.config/bvault/mcp-gui.sock"),
        );
        assert_eq!(
            setup.claude_code_command,
            "claude mcp add bastionvault -s user -- /Applications/BastionVault.app/Contents/MacOS/bastion-vault-gui --mcp-stdio"
        );
        let desktop: serde_json::Value = serde_json::from_str(&setup.claude_desktop_config).unwrap();
        assert_eq!(
            desktop["mcpServers"]["bastionvault"]["command"],
            serde_json::json!("/Applications/BastionVault.app/Contents/MacOS/bastion-vault-gui")
        );
        assert_eq!(desktop["mcpServers"]["bastionvault"]["args"], serde_json::json!(["--mcp-stdio"]));
        assert!(desktop["mcpServers"]["bastionvault"].get("env").is_none(), "no secret, no address: nothing to leak");
    }

    #[test]
    fn a_path_with_spaces_or_quotes_is_quoted_for_the_shell() {
        let setup = client_setup(Path::new("/Users/me/My Apps/it's/bastion-vault-gui"), Path::new("/s"));
        assert_eq!(
            setup.claude_code_command,
            r"claude mcp add bastionvault -s user -- '/Users/me/My Apps/it'\''s/bastion-vault-gui' --mcp-stdio"
        );
        assert_eq!(shell_quote("/opt/bv/bin"), "/opt/bv/bin");
        assert_eq!(shell_quote("$(rm -rf ~)"), "'$(rm -rf ~)'");
    }

    #[test]
    fn a_session_is_one_mode_one_vault_one_token() {
        let a = link::SessionFingerprint::of(VaultMode::Remote, "remote:https://a:8200".into(), "tok");
        assert_eq!(a, link::SessionFingerprint::of(VaultMode::Remote, "remote:https://a:8200".into(), "tok"));
        assert_ne!(a, link::SessionFingerprint::of(VaultMode::Remote, "remote:https://b:8200".into(), "tok"));
        assert_ne!(a, link::SessionFingerprint::of(VaultMode::Remote, "remote:https://a:8200".into(), "tok2"));
        assert_ne!(a, link::SessionFingerprint::of(VaultMode::Embedded, "remote:https://a:8200".into(), "tok"));
        assert!(!format!("{a:?}").contains("\"tok\""), "the fingerprint holds a hash, not the token");
    }

    #[test]
    fn a_host_that_never_started_is_off_and_stopping_it_is_a_no_op() {
        let host = McpHost::new();
        assert!(host.stop(None, "test").is_empty());
        assert!(host.stop_instance(1, None, "test").is_empty());
        let status = host.status();
        assert!(!status.running);
        assert!(status.started_at.is_none());
        assert_eq!(status.supported, cfg!(unix));
    }
}
