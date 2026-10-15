//! The operator side of the GUI-hosted MCP server: a pairing-consent or a
//! per-call confirmation becomes an event to the main window, and the
//! asking connection waits -- bounded -- for the operator's answer, which
//! arrives through the `mcp_prompt_answer` command.
//!
//! Fail-closed at every step: no main window, no unlocked session, a server
//! that is stopping, a window that never answers -- each is `None` to the
//! gatekeeper, which refuses the pairing or the call. One prompt is shown at
//! a time; a second waits its turn.
//!
//! A brokered-session call (`features/mcp-brokered-sessions.md` §3.1, §9) is
//! shown field by field, and on an MFA-gated profile the operator proves a
//! factor in the same dialog. The factor goes from `mcp_prompt_answer` to
//! the waiting connection, which has the gatekeeper verify it with the vault;
//! the resulting ticket stays in the gatekeeper's memory, and the dialog is
//! told only whether it worked.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex, MutexGuard,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bv_mcp::{
    catalogue,
    local::{normalize_grant, ConfirmRequest, MfaFactor, PairingDecision, PairingGrant, PairingRequest, Prompter},
    pairing::{default_tool_allowlist, DEFAULT_TOKEN_TTL_SECS, MAX_TOKEN_TTL_SECS},
    sanitize::{escape_for_display, sanitize_for_model},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

/// How long a pairing-consent dialog stays open. Long enough to read the
/// request and choose a scope; an assistant that gave up waiting reconnects
/// and finds the pairing recorded.
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a per-call confirmation stays open before the call is refused.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);
/// The second factors this host can collect for a session call: a TOTP code
/// typed in the dialog, and the native security-key assertion.
pub const MFA_METHODS: &[&str] = &["totp", "fido2"];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A pairing request, as the consent dialog shows it. Every string the
/// client chose is sanitized; nothing here is secret.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct PairingPrompt {
    pub id: String,
    pub client_name: String,
    pub client_version: String,
    pub transport: String,
    pub peer_uid: Option<u32>,
    /// The kernel confirmed the client runs as the user running this app.
    pub same_user: bool,
    /// The vault this session is signed in to: the remote address, or the
    /// local vault. An approval is not bound to it (see `link`).
    pub vault: String,
    pub deadline_unix_ms: u64,
    /// The read-only tools that never reveal a value: the default grant.
    pub default_tools: Vec<String>,
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
}

/// A call that needs the operator's yes, as the confirmation dialog shows
/// it. `summary` names what the call touches (mount, path, key...), never a
/// value it carries.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ConfirmPrompt {
    pub id: String,
    pub client_name: String,
    pub tool: String,
    pub tool_description: String,
    pub summary: String,
    pub reveals: bool,
    pub destructive: bool,
    pub deadline_unix_ms: u64,
    /// A brokered-session call: what it will do, field by field. Its
    /// confirmation is mandatory.
    pub session: Option<SessionPrompt>,
    /// The profile requires the operator's MFA, completed in this dialog.
    pub mfa: Option<MfaPrompt>,
    /// The WebAuthn request options for the security-key path. Kept here,
    /// never sent to the window: the host runs the assertion itself.
    #[serde(skip)]
    pub fido2_challenge: Option<Value>,
}

/// A session call as the dialog lays it out. Every string is escaped for
/// display: a character that could hide or disguise text is shown as
/// `\u{XXXX}`, never rendered.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct SessionPrompt {
    pub resource: String,
    pub profile: String,
    pub protocol: String,
    /// The exact command, escaped for display; line breaks kept.
    pub command: String,
    /// Bytes of the command as it will run.
    pub command_bytes: usize,
    pub timeout_secs: Option<u64>,
}

/// The factors the dialog may offer: the operator's enrolled ones this host
/// can collect, in the vault's order.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct MfaPrompt {
    pub methods: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpPrompt {
    Pairing(PairingPrompt),
    Confirm(ConfirmPrompt),
}

impl McpPrompt {
    pub fn id(&self) -> &str {
        match self {
            McpPrompt::Pairing(p) => &p.id,
            McpPrompt::Confirm(c) => &c.id,
        }
    }
}

/// The grant the consent dialog sends back. Validated with
/// [`normalize_grant`] before it can resolve a prompt. There is no
/// `confirm_connect`: session calls are always confirmed.
#[derive(Deserialize, Clone, Debug)]
pub struct McpGrantInput {
    pub tool_allowlist: Vec<String>,
    pub path_scope: Vec<String>,
    pub reveal_allowed: bool,
    pub destructive_allowed: bool,
    pub confirm_reveal: bool,
    pub confirm_destructive: bool,
    #[serde(default)]
    pub connect_allowed: bool,
    pub ttl_secs: u64,
}

/// The factor the operator chose in a session confirmation.
#[derive(Deserialize, Clone)]
pub struct McpMfaInput {
    /// `totp` or `fido2`.
    pub method: String,
    /// The TOTP code; absent for `fido2`, whose assertion the host runs.
    #[serde(default)]
    pub code: Option<String>,
}

impl std::fmt::Debug for McpMfaInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpMfaInput").field("method", &self.method).field("code", &"<redacted>").finish()
    }
}

/// The operator's answer, from the frontend.
#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpPromptAnswer {
    Pairing {
        approved: bool,
        #[serde(default)]
        grant: Option<McpGrantInput>,
    },
    Confirm {
        allow: bool,
        #[serde(default)]
        mfa: Option<McpMfaInput>,
    },
}

/// A factor for the waiting connection to verify, and where to say whether
/// it was accepted.
#[derive(Debug)]
pub struct MfaReply {
    pub factor: MfaFactor,
    pub done: mpsc::Sender<Result<(), String>>,
}

#[derive(Debug)]
pub struct ConfirmReply {
    pub allow: bool,
    pub mfa: Option<MfaReply>,
}

#[derive(Debug)]
pub enum PromptReply {
    Pairing(PairingDecision),
    Confirm(ConfirmReply),
}

/// Turns the frontend's answer into the reply the waiting connection gets,
/// refusing (without resolving the prompt) an approval whose grant does not
/// validate, so the operator can correct it. An answer carrying a factor is
/// not handled here: `mcp_prompt_answer` builds that reply itself, because
/// it waits for the verification.
pub fn reply_for(answer: McpPromptAnswer) -> Result<PromptReply, String> {
    match answer {
        McpPromptAnswer::Pairing { approved: false, .. } => Ok(PromptReply::Pairing(PairingDecision::Denied)),
        McpPromptAnswer::Pairing { approved: true, grant: None } => {
            Err("an approval must carry the scope it grants".to_string())
        }
        McpPromptAnswer::Pairing { approved: true, grant: Some(g) } => {
            let grant = normalize_grant(PairingGrant {
                tool_allowlist: g.tool_allowlist,
                path_scope: g.path_scope,
                reveal_allowed: g.reveal_allowed,
                destructive_allowed: g.destructive_allowed,
                confirm_reveal: g.confirm_reveal,
                confirm_destructive: g.confirm_destructive,
                connect_allowed: g.connect_allowed,
                // Forced on with `connect_allowed` by `normalize_grant`.
                confirm_connect: g.connect_allowed,
                ttl_secs: g.ttl_secs,
            })?;
            Ok(PromptReply::Pairing(PairingDecision::Approved(grant)))
        }
        McpPromptAnswer::Confirm { allow: true, mfa: Some(_) } => {
            Err("an answer with a second factor is completed by the host".to_string())
        }
        McpPromptAnswer::Confirm { allow, .. } => Ok(PromptReply::Confirm(ConfirmReply { allow, mfa: None })),
    }
}

/// A typed TOTP code, checked for shape before it is sent anywhere.
pub fn totp_factor(code: Option<&str>) -> Result<MfaFactor, String> {
    let code = code.map(str::trim).unwrap_or_default();
    if !(6..=10).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("enter the current 6-digit code from your authenticator app".to_string());
    }
    Ok(MfaFactor::Totp(Zeroizing::new(code.to_string())))
}

/// Where a prompt is shown. The Tauri implementation emits to the main
/// window; tests use a fake, so the broker is exercised with no display.
pub trait PromptSink: Send + Sync {
    /// Whether a human can answer at all: the main window exists and the
    /// vault session the server runs under is still the live one.
    fn operator_present(&self) -> bool;
    /// Shows the prompt; `false` if it could not be delivered.
    fn show(&self, prompt: &McpPrompt) -> bool;
    /// Takes a prompt down that is no longer waiting (answered elsewhere,
    /// timed out, cancelled).
    fn withdraw(&self, id: &str);
}

struct Pending {
    prompt: McpPrompt,
    reply: mpsc::Sender<PromptReply>,
}

/// The one prompt slot shared by the server's connections and the
/// `mcp_prompt_*` commands.
#[derive(Default)]
pub struct PromptBroker {
    accepting: AtomicBool,
    one_at_a_time: Mutex<()>,
    pending: Mutex<Option<Pending>>,
    next_id: AtomicU64,
}

impl PromptBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lets prompts through; called when the server starts.
    pub fn open(&self) {
        self.accepting.store(true, Ordering::SeqCst);
    }

    /// Refuses every prompt from now on and abandons the one on screen,
    /// whose connection then gets `None` (a refusal) at once.
    pub fn close(&self) -> Option<String> {
        self.accepting.store(false, Ordering::SeqCst);
        lock(&self.pending).take().map(|p| p.prompt.id().to_string())
    }

    /// The prompt waiting for an answer, for a window that (re)mounted
    /// after it was emitted.
    pub fn pending(&self) -> Option<McpPrompt> {
        lock(&self.pending).as_ref().map(|p| p.prompt.clone())
    }

    /// The security-key challenge of confirmation `id`, while it waits.
    pub fn pending_fido2_challenge(&self, id: &str) -> Option<Value> {
        match lock(&self.pending).as_ref().map(|p| &p.prompt) {
            Some(McpPrompt::Confirm(c)) if c.id == id => c.fido2_challenge.clone(),
            _ => None,
        }
    }

    /// Resolves the waiting prompt `id`. An answer for any other prompt, or
    /// of the wrong kind, resolves nothing.
    pub fn answer(&self, id: &str, reply: PromptReply) -> Result<(), String> {
        let mut pending = lock(&self.pending);
        let Some(current) = pending.as_ref() else {
            return Err("no AI-assistant request is waiting for an answer (it may have timed out)".to_string());
        };
        if current.prompt.id() != id {
            return Err("that AI-assistant request is no longer waiting for an answer".to_string());
        }
        let kind_matches = matches!(
            (&current.prompt, &reply),
            (McpPrompt::Pairing(_), PromptReply::Pairing(_)) | (McpPrompt::Confirm(_), PromptReply::Confirm(_))
        );
        if !kind_matches {
            return Err("the answer does not match the request it was given for".to_string());
        }
        let current = pending.take().expect("checked above");
        // A send fails only if the asking side already gave up; the prompt
        // is gone either way.
        let _ = current.reply.send(reply);
        Ok(())
    }

    fn new_id(&self) -> String {
        format!("mcp-prompt-{}", self.next_id.fetch_add(1, Ordering::SeqCst))
    }

    /// Shows one prompt and waits up to `timeout` for its answer. `None`
    /// whenever no human answered: closed, nobody present, undeliverable,
    /// timed out or cancelled.
    pub fn ask(
        &self,
        sink: &dyn PromptSink,
        build: impl FnOnce(String) -> McpPrompt,
        timeout: Duration,
    ) -> Option<PromptReply> {
        let _one = lock(&self.one_at_a_time);
        if !self.accepting.load(Ordering::SeqCst) || !sink.operator_present() {
            return None;
        }
        let prompt = build(self.new_id());
        let id = prompt.id().to_string();
        let (tx, rx) = mpsc::channel();
        *lock(&self.pending) = Some(Pending { prompt: prompt.clone(), reply: tx });
        // Checked again with the slot filled: a `close` that ran in between
        // emptied it, or will find it.
        if !self.accepting.load(Ordering::SeqCst) || !sink.show(&prompt) {
            self.clear(&id);
            return None;
        }
        let reply = rx.recv_timeout(timeout).ok();
        if reply.is_none() {
            self.clear(&id);
        }
        sink.withdraw(&id);
        reply
    }

    fn clear(&self, id: &str) {
        let mut pending = lock(&self.pending);
        if pending.as_ref().is_some_and(|p| p.prompt.id() == id) {
            *pending = None;
        }
    }
}

/// The [`Prompter`] the GUI-hosted server runs with.
pub struct GuiPrompter {
    pub broker: Arc<PromptBroker>,
    pub sink: Box<dyn PromptSink>,
    pub same_uid: Option<u32>,
    /// Shown in the consent dialog: which vault the client would act on.
    pub vault_label: String,
}

impl Prompter for GuiPrompter {
    fn approve(&self, request: &PairingRequest<'_>) -> Option<PairingDecision> {
        let build = |id| {
            McpPrompt::Pairing(PairingPrompt {
                id,
                client_name: sanitize_for_model(request.client_name),
                client_version: sanitize_for_model(request.client_version),
                transport: request.transport.as_str().to_string(),
                peer_uid: request.peer_uid,
                same_user: request.peer_uid.is_some() && request.peer_uid == self.same_uid,
                vault: self.vault_label.clone(),
                deadline_unix_ms: now_ms() + PAIRING_TIMEOUT.as_millis() as u64,
                default_tools: default_tool_allowlist(),
                default_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
                max_ttl_secs: MAX_TOKEN_TTL_SECS,
            })
        };
        match self.broker.ask(self.sink.as_ref(), build, PAIRING_TIMEOUT)? {
            PromptReply::Pairing(decision) => Some(decision),
            // `answer` refuses a reply of the other kind; deny rather than
            // trust an impossible state.
            PromptReply::Confirm(_) => Some(PairingDecision::Denied),
        }
    }

    fn confirm(&self, request: &ConfirmRequest<'_>) -> Option<bool> {
        let session = request.session.map(|call| SessionPrompt {
            resource: escape_for_display(&call.resource),
            profile: escape_for_display(&call.profile),
            protocol: call.protocol.to_string(),
            command: escape_for_display(&call.command),
            command_bytes: call.command.len(),
            timeout_secs: call.timeout_secs,
        });
        let mfa = request.mfa.as_ref().map(|step| MfaPrompt {
            methods: step.challenge.methods.iter().filter(|m| MFA_METHODS.contains(&m.as_str())).cloned().collect(),
        });
        let fido2_challenge = request.mfa.as_ref().and_then(|step| step.challenge.fido2.clone());
        let build = |id| {
            McpPrompt::Confirm(ConfirmPrompt {
                id,
                client_name: sanitize_for_model(request.client_name),
                tool: sanitize_for_model(request.tool),
                tool_description: catalogue::find(request.tool).map(|t| t.description.to_string()).unwrap_or_default(),
                summary: sanitize_for_model(request.summary),
                reveals: request.reveals,
                destructive: request.destructive,
                deadline_unix_ms: now_ms() + CONFIRM_TIMEOUT.as_millis() as u64,
                session,
                mfa,
                fido2_challenge,
            })
        };
        let reply = match self.broker.ask(self.sink.as_ref(), build, CONFIRM_TIMEOUT)? {
            PromptReply::Confirm(reply) => reply,
            PromptReply::Pairing(_) => return Some(false),
        };
        match (reply.allow, reply.mfa, &request.mfa) {
            (false, mfa, _) => {
                if let Some(mfa) = mfa {
                    let _ = mfa.done.send(Err("the call was denied".to_string()));
                }
                Some(false)
            }
            // Gated, and no factor: not an approval.
            (true, None, Some(_)) => Some(false),
            (true, None, None) => Some(true),
            (true, Some(mfa), None) => {
                let _ = mfa.done.send(Err("this call did not ask for MFA".to_string()));
                Some(false)
            }
            (true, Some(mfa), Some(step)) => {
                // Verified here, on the asking connection, by the gatekeeper:
                // the ticket goes to its memory, the window learns only this.
                let verified = (step.verify)(mfa.factor);
                let ok = verified.is_ok();
                let _ = mfa.done.send(verified);
                Some(ok)
            }
        }
    }

    fn mfa_methods(&self) -> &[&'static str] {
        MFA_METHODS
    }

    fn mfa_unavailable_message(&self) -> &str {
        "this connection profile requires your MFA, and your account has no TOTP key or security key this app can \
         use; enrol one, or ask an administrator to clear require_mfa on the profile"
    }

    fn pairing_unavailable_message(&self) -> &str {
        "this client is not paired, and nobody approved it in the BastionVault app in time; open the app with your vault unlocked, approve the request, then reconnect"
    }

    fn confirmation_unavailable_message(&self) -> &str {
        "this call needs your confirmation in the BastionVault app, and none was given in time"
    }
}

#[cfg(test)]
mod tests {
    use bv_mcp::pairing::Transport;

    use super::*;

    #[derive(Default)]
    struct FakeSink {
        absent: AtomicBool,
        undeliverable: AtomicBool,
        shown: Mutex<Vec<McpPrompt>>,
        withdrawn: Mutex<Vec<String>>,
    }

    impl PromptSink for Arc<FakeSink> {
        fn operator_present(&self) -> bool {
            !self.absent.load(Ordering::SeqCst)
        }
        fn show(&self, prompt: &McpPrompt) -> bool {
            lock(&self.shown).push(prompt.clone());
            !self.undeliverable.load(Ordering::SeqCst)
        }
        fn withdraw(&self, id: &str) {
            lock(&self.withdrawn).push(id.to_string());
        }
    }

    fn prompter(sink: &Arc<FakeSink>) -> (Arc<PromptBroker>, Arc<GuiPrompter>) {
        let broker = Arc::new(PromptBroker::new());
        broker.open();
        let p = Arc::new(GuiPrompter {
            broker: broker.clone(),
            sink: Box::new(sink.clone()),
            same_uid: Some(501),
            vault_label: "https://vault.example.com:8200".into(),
        });
        (broker, p)
    }

    fn pairing_request() -> PairingRequest<'static> {
        PairingRequest {
            client_name: "claude-code\u{1b}[31m",
            client_version: "2.1",
            transport: Transport::Uds,
            peer_uid: Some(501),
        }
    }

    /// Waits for the prompt to be on screen, then answers it from "the window".
    fn answer_when_shown(broker: Arc<PromptBroker>, answer: McpPromptAnswer) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for _ in 0..500 {
                if let Some(p) = broker.pending() {
                    broker.answer(p.id(), reply_for(answer).unwrap()).unwrap();
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("the prompt was never shown");
        })
    }

    fn grant_input() -> McpGrantInput {
        McpGrantInput {
            tool_allowlist: default_tool_allowlist(),
            path_scope: vec!["secret/metadata/ai/*".into()],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            connect_allowed: false,
            ttl_secs: 3600,
        }
    }

    /// A grant with sessions gets them confirmed; a session tool without
    /// `connect_allowed` is refused with the reason.
    #[test]
    fn a_grant_with_sessions_is_always_confirmed() {
        let mut g = grant_input();
        g.tool_allowlist.push("bv_resource_ssh_exec".into());
        assert!(reply_for(McpPromptAnswer::Pairing { approved: true, grant: Some(g.clone()) })
            .unwrap_err()
            .contains("connect_allowed"));
        g.connect_allowed = true;
        let Ok(PromptReply::Pairing(PairingDecision::Approved(grant))) =
            reply_for(McpPromptAnswer::Pairing { approved: true, grant: Some(g) })
        else {
            panic!("a grant with sessions allowed is accepted")
        };
        assert!(grant.connect_allowed && grant.confirm_connect);
    }

    #[test]
    fn an_approved_pairing_returns_the_validated_grant_and_the_dialog_saw_the_peer() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        let answering =
            answer_when_shown(broker, McpPromptAnswer::Pairing { approved: true, grant: Some(grant_input()) });
        let decision = p.approve(&pairing_request()).unwrap();
        answering.join().unwrap();
        let PairingDecision::Approved(grant) = decision else { panic!("expected an approval") };
        assert_eq!(grant.path_scope, vec!["secret/metadata/ai/*".to_string()]);
        assert!(!grant.confirm_reveal, "nothing to confirm when reveals are off");

        let shown = lock(&sink.shown);
        let McpPrompt::Pairing(prompt) = &shown[0] else { panic!("expected a pairing prompt") };
        assert_eq!(prompt.client_name, "claude-code", "client-chosen strings are sanitized");
        assert_eq!((prompt.transport.as_str(), prompt.peer_uid, prompt.same_user), ("uds", Some(501), true));
        assert_eq!(prompt.vault, "https://vault.example.com:8200", "the dialog names the vault asked for");
        assert_eq!(prompt.default_tools, default_tool_allowlist());
        assert_eq!(lock(&sink.withdrawn).as_slice(), std::slice::from_ref(&prompt.id));
    }

    #[test]
    fn a_denial_is_a_denial() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        let answering = answer_when_shown(broker, McpPromptAnswer::Pairing { approved: false, grant: None });
        assert_eq!(p.approve(&pairing_request()), Some(PairingDecision::Denied));
        answering.join().unwrap();
    }

    #[test]
    fn no_window_or_no_session_means_no_prompt_and_no_answer() {
        let sink = Arc::new(FakeSink::default());
        sink.absent.store(true, Ordering::SeqCst);
        let (_broker, p) = prompter(&sink);
        assert_eq!(p.approve(&pairing_request()), None);
        assert!(lock(&sink.shown).is_empty(), "nothing is shown to nobody");
    }

    #[test]
    fn an_undeliverable_prompt_is_a_refusal_and_leaves_nothing_pending() {
        let sink = Arc::new(FakeSink::default());
        sink.undeliverable.store(true, Ordering::SeqCst);
        let (broker, p) = prompter(&sink);
        assert_eq!(p.approve(&pairing_request()), None);
        assert!(broker.pending().is_none());
    }

    #[test]
    fn a_closed_broker_prompts_nobody() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        broker.close();
        let call = ConfirmRequest {
            client_name: "c",
            tool: "bv_kv_delete",
            summary: "mount=secret",
            reveals: false,
            destructive: true,
            detail: None,
            session: None,
            open_world: false,
            mfa: None,
        };
        assert_eq!(p.confirm(&call), None);
        assert!(lock(&sink.shown).is_empty());
    }

    #[test]
    fn closing_abandons_the_prompt_on_screen_at_once() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        let closer = {
            let broker = broker.clone();
            std::thread::spawn(move || {
                for _ in 0..500 {
                    if broker.pending().is_some() {
                        assert!(broker.close().is_some());
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                panic!("the prompt was never shown");
            })
        };
        let started = std::time::Instant::now();
        assert_eq!(p.approve(&pairing_request()), None);
        assert!(started.elapsed() < Duration::from_secs(10), "did not wait out the timeout");
        closer.join().unwrap();
    }

    #[test]
    fn a_confirmation_shows_the_call_and_returns_the_operators_answer() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        let call = ConfirmRequest {
            client_name: "claude-code",
            tool: "bv_kv_read",
            summary: "mount=secret path=ai/x",
            reveals: true,
            destructive: false,
            detail: None,
            session: None,
            open_world: false,
            mfa: None,
        };
        let answering = answer_when_shown(broker.clone(), McpPromptAnswer::Confirm { allow: false, mfa: None });
        assert_eq!(p.confirm(&call), Some(false));
        answering.join().unwrap();
        let answering = answer_when_shown(broker, McpPromptAnswer::Confirm { allow: true, mfa: None });
        assert_eq!(p.confirm(&call), Some(true));
        answering.join().unwrap();

        let shown = lock(&sink.shown);
        let McpPrompt::Confirm(prompt) = &shown[0] else { panic!("expected a confirmation") };
        assert_eq!((prompt.tool.as_str(), prompt.summary.as_str()), ("bv_kv_read", "mount=secret path=ai/x"));
        assert!(prompt.reveals && !prompt.destructive);
        assert!(!prompt.tool_description.is_empty());
    }

    #[test]
    fn answers_must_name_the_waiting_prompt_and_match_its_kind() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        let yes = || PromptReply::Confirm(ConfirmReply { allow: true, mfa: None });
        assert!(broker.answer("mcp-prompt-0", yes()).is_err(), "nothing is waiting");

        let waiting = {
            let p = p.clone();
            std::thread::spawn(move || p.approve(&pairing_request()))
        };
        let id = loop {
            if let Some(prompt) = broker.pending() {
                break prompt.id().to_string();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(broker.answer("mcp-prompt-999", PromptReply::Pairing(PairingDecision::Denied)).is_err());
        assert!(broker.answer(&id, yes()).is_err(), "a yes to a call cannot approve a pairing");
        assert!(broker.pending().is_some(), "a rejected answer leaves the prompt waiting");
        broker.answer(&id, PromptReply::Pairing(PairingDecision::Denied)).unwrap();
        assert_eq!(waiting.join().unwrap(), Some(PairingDecision::Denied));
    }

    #[test]
    fn an_approval_needs_a_valid_grant() {
        assert!(reply_for(McpPromptAnswer::Pairing { approved: true, grant: None }).is_err());
        let mut bad = grant_input();
        bad.tool_allowlist = vec!["bv_not_a_tool".into()];
        assert!(reply_for(McpPromptAnswer::Pairing { approved: true, grant: Some(bad) }).is_err());
        let mut long = grant_input();
        long.ttl_secs = 10 * MAX_TOKEN_TTL_SECS;
        let Ok(PromptReply::Pairing(PairingDecision::Approved(g))) =
            reply_for(McpPromptAnswer::Pairing { approved: true, grant: Some(long) })
        else {
            panic!("a valid grant is accepted")
        };
        assert_eq!(g.ttl_secs, MAX_TOKEN_TTL_SECS);
    }

    #[test]
    fn the_answer_wire_shape_is_what_the_frontend_sends() {
        let answer: McpPromptAnswer = serde_json::from_value(serde_json::json!({
            "kind": "pairing",
            "approved": true,
            "grant": {
                "tool_allowlist": ["bv_whoami"], "path_scope": ["secret/*"],
                "reveal_allowed": false, "destructive_allowed": false,
                "confirm_reveal": true, "confirm_destructive": true, "ttl_secs": 3600
            }
        }))
        .unwrap();
        assert!(matches!(reply_for(answer), Ok(PromptReply::Pairing(PairingDecision::Approved(_)))));
        let answer: McpPromptAnswer =
            serde_json::from_value(serde_json::json!({ "kind": "confirm", "allow": true })).unwrap();
        assert!(matches!(reply_for(answer), Ok(PromptReply::Confirm(ConfirmReply { allow: true, mfa: None }))));
        let prompt = McpPrompt::Confirm(ConfirmPrompt {
            id: "x".into(),
            client_name: "c".into(),
            tool: "t".into(),
            tool_description: String::new(),
            summary: String::new(),
            reveals: true,
            destructive: false,
            deadline_unix_ms: 1,
            session: None,
            mfa: None,
            fido2_challenge: Some(serde_json::json!({ "publicKey": { "challenge": "c2VjcmV0" } })),
        });
        let wire = serde_json::to_value(&prompt).unwrap();
        assert_eq!(wire["kind"], serde_json::json!("confirm"));
        assert!(wire.get("fido2_challenge").is_none(), "the security-key challenge stays in the host");
        let answer: McpPromptAnswer = serde_json::from_value(serde_json::json!({
            "kind": "confirm", "allow": true, "mfa": { "method": "totp", "code": "123456" }
        }))
        .unwrap();
        assert!(!format!("{answer:?}").contains("123456"), "a typed code never prints");
        assert!(reply_for(answer).is_err(), "a factor is completed by the host, not here");
    }

    // ── brokered sessions ───────────────────────────────────────────────

    fn session_call(command: &str) -> bv_mcp::dispatcher::SessionCall {
        let args = serde_json::json!({ "resource": "web-01", "profile": "p_agent", "command": command });
        bv_mcp::dispatcher::session_call("bv_resource_ssh_exec", args.as_object().unwrap()).unwrap()
    }

    fn session_request<'a>(
        call: &'a bv_mcp::dispatcher::SessionCall,
        detail: &'a str,
        mfa: Option<bv_mcp::local::MfaStep<'a>>,
    ) -> ConfirmRequest<'a> {
        ConfirmRequest {
            client_name: "claude-code",
            tool: "bv_resource_ssh_exec",
            summary: "",
            reveals: false,
            destructive: true,
            detail: Some(detail),
            session: Some(call),
            open_world: true,
            mfa,
        }
    }

    /// Answers the waiting confirmation with a factor, as `mcp_prompt_answer`
    /// does, and returns what the dialog would be told.
    fn answer_with_factor(
        broker: Arc<PromptBroker>,
        code: &'static str,
    ) -> std::thread::JoinHandle<Result<(), String>> {
        std::thread::spawn(move || {
            for _ in 0..500 {
                if let Some(p) = broker.pending() {
                    let (done, result) = mpsc::channel();
                    let factor = totp_factor(Some(code)).unwrap();
                    let reply =
                        PromptReply::Confirm(ConfirmReply { allow: true, mfa: Some(MfaReply { factor, done }) });
                    broker.answer(p.id(), reply).unwrap();
                    return result.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("the prompt was never shown");
        })
    }

    /// The dialog gets the call field by field, escaped; the factors it may
    /// offer; and never the security-key challenge.
    #[test]
    fn a_session_confirmation_shows_the_call_and_the_mfa_step() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        let call = session_call("journalctl -u nginx\n\ttail -n 5");
        let detail = bv_mcp::local::render_session_detail(&call);
        let challenge = bv_mcp::local::MfaChallenge {
            methods: vec!["fido2".into(), "totp".into(), "sms".into()],
            fido2: Some(serde_json::json!({ "publicKey": { "challenge": "abc" } })),
        };
        let verify = |_: MfaFactor| -> Result<(), String> { Ok(()) };
        let step = bv_mcp::local::MfaStep { challenge: &challenge, verify: &verify };
        let answering = answer_with_factor(broker.clone(), "123456");
        assert_eq!(p.confirm(&session_request(&call, &detail, Some(step))), Some(true));
        assert_eq!(answering.join().unwrap(), Ok(()));

        let shown = lock(&sink.shown);
        let McpPrompt::Confirm(prompt) = &shown[0] else { panic!("expected a confirmation") };
        let session = prompt.session.as_ref().expect("a session call");
        assert_eq!(
            (session.resource.as_str(), session.profile.as_str(), session.protocol.as_str()),
            ("web-01", "p_agent", "ssh")
        );
        assert_eq!(
            session.command, "journalctl -u nginx\n\\u{0009}tail -n 5",
            "tabs and the like are shown as escapes"
        );
        assert_eq!(session.command_bytes, call.command.len());
        assert_eq!(prompt.mfa.as_ref().unwrap().methods, vec!["fido2".to_string(), "totp".to_string()]);
        let wire = serde_json::to_value(prompt).unwrap();
        assert!(!wire.to_string().contains("abc"), "the challenge is not sent to the window: {wire}");
    }

    /// A factor the vault refuses denies the call, and the dialog is told
    /// why; a yes without a factor on a gated profile is not an approval.
    #[test]
    fn a_failed_or_missing_factor_denies_the_session_call() {
        let sink = Arc::new(FakeSink::default());
        let (broker, p) = prompter(&sink);
        let call = session_call("uptime");
        let detail = bv_mcp::local::render_session_detail(&call);
        let challenge = bv_mcp::local::MfaChallenge { methods: vec!["totp".into()], fido2: None };
        let verify = |factor: MfaFactor| -> Result<(), String> {
            match factor {
                MfaFactor::Totp(code) if code.as_str() == "123456" => Ok(()),
                _ => Err("invalid TOTP code".to_string()),
            }
        };
        let step = || bv_mcp::local::MfaStep { challenge: &challenge, verify: &verify };

        let answering = answer_with_factor(broker.clone(), "000000");
        assert_eq!(p.confirm(&session_request(&call, &detail, Some(step()))), Some(false));
        assert_eq!(answering.join().unwrap(), Err("invalid TOTP code".to_string()));

        let answering = answer_when_shown(broker.clone(), McpPromptAnswer::Confirm { allow: true, mfa: None });
        assert_eq!(p.confirm(&session_request(&call, &detail, Some(step()))), Some(false));
        answering.join().unwrap();

        // Ungated: a plain yes is a yes.
        let answering = answer_when_shown(broker, McpPromptAnswer::Confirm { allow: true, mfa: None });
        assert_eq!(p.confirm(&session_request(&call, &detail, None)), Some(true));
        answering.join().unwrap();
        assert_eq!(p.mfa_methods(), &["totp", "fido2"]);
    }

    #[test]
    fn a_totp_code_is_checked_for_shape_before_it_goes_anywhere() {
        assert!(totp_factor(Some(" 123456 ")).is_ok());
        for bad in [None, Some(""), Some("12345"), Some("12345a"), Some("12345678901")] {
            assert!(totp_factor(bad).is_err(), "{bad:?}");
        }
    }
}
