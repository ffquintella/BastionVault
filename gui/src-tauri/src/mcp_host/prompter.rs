//! The operator side of the GUI-hosted MCP server: a pairing-consent or a
//! per-call confirmation becomes an event to the main window, and the
//! asking connection waits -- bounded -- for the operator's answer, which
//! arrives through the `mcp_prompt_answer` command.
//!
//! Fail-closed at every step: no main window, no unlocked session, a server
//! that is stopping, a window that never answers -- each is `None` to the
//! gatekeeper, which refuses the pairing or the call. One prompt is shown at
//! a time; a second waits its turn.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex, MutexGuard,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bv_mcp::{
    catalogue,
    local::{normalize_grant, ConfirmRequest, PairingDecision, PairingGrant, PairingRequest, Prompter},
    pairing::{default_tool_allowlist, DEFAULT_TOKEN_TTL_SECS, MAX_TOKEN_TTL_SECS},
    sanitize::sanitize_for_model,
};
use serde::{Deserialize, Serialize};

/// How long a pairing-consent dialog stays open. Long enough to read the
/// request and choose a scope; an assistant that gave up waiting reconnects
/// and finds the pairing recorded.
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a per-call confirmation stays open before the call is refused.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);

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
/// [`normalize_grant`] before it can resolve a prompt.
#[derive(Deserialize, Clone, Debug)]
pub struct McpGrantInput {
    pub tool_allowlist: Vec<String>,
    pub path_scope: Vec<String>,
    pub reveal_allowed: bool,
    pub destructive_allowed: bool,
    pub confirm_reveal: bool,
    pub confirm_destructive: bool,
    pub ttl_secs: u64,
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
    },
}

#[derive(Debug, PartialEq)]
pub enum PromptReply {
    Pairing(PairingDecision),
    Confirm(bool),
}

/// Turns the frontend's answer into the reply the waiting connection gets,
/// refusing (without resolving the prompt) an approval whose grant does not
/// validate, so the operator can correct it.
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
                ttl_secs: g.ttl_secs,
            })?;
            Ok(PromptReply::Pairing(PairingDecision::Approved(grant)))
        }
        McpPromptAnswer::Confirm { allow } => Ok(PromptReply::Confirm(allow)),
    }
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
            })
        };
        match self.broker.ask(self.sink.as_ref(), build, CONFIRM_TIMEOUT)? {
            PromptReply::Confirm(allow) => Some(allow),
            PromptReply::Pairing(_) => Some(false),
        }
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
            ttl_secs: 3600,
        }
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
        };
        let answering = answer_when_shown(broker.clone(), McpPromptAnswer::Confirm { allow: false });
        assert_eq!(p.confirm(&call), Some(false));
        answering.join().unwrap();
        let answering = answer_when_shown(broker, McpPromptAnswer::Confirm { allow: true });
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
        assert!(broker.answer("mcp-prompt-0", PromptReply::Confirm(true)).is_err(), "nothing is waiting");

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
        assert!(broker.answer(&id, PromptReply::Confirm(true)).is_err(), "a yes to a call cannot approve a pairing");
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
        assert!(matches!(reply_for(answer), Ok(PromptReply::Confirm(true))));
        let prompt = McpPrompt::Confirm(ConfirmPrompt {
            id: "x".into(),
            client_name: "c".into(),
            tool: "t".into(),
            tool_description: String::new(),
            summary: String::new(),
            reveals: true,
            destructive: false,
            deadline_unix_ms: 1,
        });
        assert_eq!(serde_json::to_value(&prompt).unwrap()["kind"], serde_json::json!("confirm"));
    }
}
