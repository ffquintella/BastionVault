//! The gatekeeper itself: one JSON-RPC message in, at most one out, after
//! working out who the client is, whether the operator approved it, and
//! whether this particular call needs a human's yes.

use std::{
    collections::HashMap,
    io::{BufRead, Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use serde_json::{json, Map, Value};
use zeroize::{Zeroize, Zeroizing};

use super::{
    link::{ForwardError, McpCallRef, MfaBeginError, MfaPreflight, MintedToken, VaultLink},
    lock,
    operator::{
        build_record, render_session_detail, ConfirmRequest, MfaFactor, MfaStep, PairingDecision, PairingRequest,
        Prompter,
    },
};
use crate::{
    catalogue::{self, ToolMeta},
    dispatcher,
    jsonrpc::{JsonRpcError, JsonRpcResponse, CONNECT_TICKET_META_KEY, OPERATOR_CONFIRMATION_META_KEY},
    pairing::{find_matching, hash_token, now_secs, PairingRecord, PairingStore, Transport, MAX_TOKEN_TTL_SECS},
    sanitize::sanitize_for_model,
};

/// Same ceiling the vault's own `/v2/mcp` applies to a request body.
pub const MAX_MESSAGE_BYTES: u64 = 256 * 1024;
const MAX_CLIENT_NAME_LEN: usize = 128;
/// Most simultaneous connections a socket or HTTP listener serves.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;
/// Re-mint a token this close to expiry rather than forwarding with one the
/// vault is about to refuse.
const TOKEN_REFRESH_MARGIN_SECS: u64 = 30;
/// MCP revisions whose stateful `initialize` handshake the line transports
/// accept, newest first. A client asking for any other revision is offered
/// the newest, as the handshake prescribes; it disconnects if it cannot speak
/// it. Every revision listed here reads the vault's `tools/list` and
/// `tools/call` answers as they are: the 2026-07-28 additions (`resultType`,
/// `ttlMs`, `cacheScope`) are extra fields an older client ignores, and every
/// successful call carries the `structuredContent` the catalogue's
/// `outputSchema` promises.
pub const HANDSHAKE_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
pub(super) const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";

/// Who is on the other end of one connection, as established by the
/// transport before any message is read.
#[derive(Clone)]
pub struct ConnInfo {
    pub transport: Transport,
    pub peer_uid: Option<u32>,
    /// Loopback HTTP authenticates by bearer before the message is seen, so
    /// the pairing is already known.
    pub preauthenticated: Option<PairingRecord>,
}

pub struct LocalServer {
    link: Box<dyn VaultLink>,
    prompter: Box<dyn Prompter>,
    store: PairingStore,
    /// Serialises "look up or create a pairing" so two first requests from
    /// one client produce one prompt, not two.
    pairing_lock: Mutex<()>,
    /// Serialises minting; see `token_for`.
    mint_lock: Mutex<()>,
    tokens: Mutex<HashMap<String, MintedToken>>,
    clock: fn() -> u64,
    /// `major.minor` of the host, reported as `serverInfo.version` at
    /// `initialize`.
    server_version: String,
    /// Where one-line operator notices go (a client initialized). Never
    /// handed a token or a secret value.
    notice: fn(&str),
    /// Set by [`Self::shutdown`]: from then on every message is refused and
    /// nothing is minted.
    closed: AtomicBool,
}

/// What one line-transport connection has established about its client.
///
/// A client on a stateful MCP revision names itself once, in `initialize`,
/// and never again. A stdio connection is the parent process and a Unix-socket
/// connection is one uid-checked peer, so the name given at `initialize` is
/// the name for the rest of the connection. It is exactly as self-asserted as
/// the `_meta` name a stateless client sends on each request: pairing still
/// binds it to the transport and peer uid, and the vault still judges every
/// call. A request that names a *different* client later in the same
/// connection is refused, never silently re-attributed.
#[derive(Default)]
pub struct SessionState {
    handshake: Option<Handshake>,
}

struct Handshake {
    client_name: String,
    client_version: String,
}

struct Refusal {
    code: i64,
    data_code: &'static str,
    message: String,
}

impl Refusal {
    fn new(code: i64, data_code: &'static str, message: impl Into<String>) -> Self {
        Self { code, data_code, message: message.into() }
    }

    fn stopped() -> Self {
        Refusal::new(
            -32001,
            "mcp_server_stopped",
            "the local MCP server has stopped; reconnect once it is running again",
        )
    }

    fn into_response(self, id: Value) -> Value {
        rpc_error(id, self.code, &self.message, self.data_code)
    }
}

pub(super) fn rpc_error(id: Value, code: i64, message: &str, data_code: &str) -> Value {
    serde_json::to_value(JsonRpcResponse::failure(id, JsonRpcError::with_data_code(code, message, data_code)))
        .unwrap_or(Value::Null)
}

fn rpc_success(id: Value, result: Value) -> Value {
    serde_json::to_value(JsonRpcResponse::success(id, result)).unwrap_or(Value::Null)
}

/// The client a stateless request names in `_meta`.
fn client_info(message: &Map<String, Value>) -> Option<(String, String)> {
    parse_client_info(message.get("params")?.get("_meta")?.get(CLIENT_INFO_META_KEY)?)
}

/// The client identity a request is judged by: the one its connection
/// established at `initialize`, if it did, else the request's own `_meta`.
fn request_identity(
    handshake: Option<&Handshake>,
    message: &Map<String, Value>,
) -> Result<Option<(String, String)>, Refusal> {
    let stated = client_info(message);
    let Some(handshake) = handshake else {
        return Ok(stated);
    };
    if stated.as_ref().is_some_and(|(name, _)| *name != handshake.client_name) {
        return Err(Refusal::new(
            -32602,
            "mcp_client_info_mismatch",
            "this request names a different client from the one this connection initialized as",
        ));
    }
    Ok(Some((handshake.client_name.clone(), handshake.client_version.clone())))
}

/// The revision to answer `initialize` with: the one asked for when it is
/// supported, else the newest.
fn negotiate_protocol_version(requested: &str) -> &'static str {
    HANDSHAKE_PROTOCOL_VERSIONS.iter().copied().find(|v| *v == requested).unwrap_or(HANDSHAKE_PROTOCOL_VERSIONS[0])
}

/// The message as the vault must receive it: a 2026-07-28 request names its
/// client in `_meta`. Overwrites only that one key; `request_identity` has
/// already refused a request that named someone else.
fn with_client_info(message: &Map<String, Value>, handshake: &Handshake) -> Value {
    let mut message = message.clone();
    let params = message.entry("params").or_insert(Value::Null);
    if params.is_null() {
        *params = Value::Object(Map::new());
    }
    if let Value::Object(params) = params {
        let meta = params.entry("_meta").or_insert(Value::Null);
        if meta.is_null() {
            *meta = Value::Object(Map::new());
        }
        if let Value::Object(meta) = meta {
            meta.insert(
                CLIENT_INFO_META_KEY.to_string(),
                json!({ "name": handshake.client_name, "version": handshake.client_version }),
            );
        }
    }
    Value::Object(message)
}

/// The `_meta` namespace that belongs to this gatekeeper: the operator's
/// confirmation record and the operator's connect MFA ticket
/// (`features/mcp-brokered-sessions.md` §3 step 3, §9). The vault audits the
/// first as this host's assertion and redeems the second itself.
pub const GATEKEEPER_META_PREFIX: &str = "io.bastionvault/";

/// Remove every `io.bastionvault/*` key a client put in `params._meta`, so
/// a client cannot assert an operator confirmation or carry a ticket on its
/// own. Runs on every relayed message, before [`assert_gatekeeper_meta`]
/// adds this gatekeeper's own.
fn strip_gatekeeper_meta(message: &mut Value) {
    if let Some(meta) = message.get_mut("params").and_then(|p| p.get_mut("_meta")).and_then(Value::as_object_mut) {
        meta.retain(|key, _| !key.starts_with(GATEKEEPER_META_PREFIX));
    }
}

/// What this gatekeeper adds to a call once the operator said yes.
struct Assertion {
    /// Unix seconds of the operator's answer.
    at: u64,
    /// The operator completed the profile's MFA in the same dialog.
    mfa: bool,
    /// The connect MFA ticket bound to this call. Held only here, and in the
    /// relayed message for as long as the relay takes.
    ticket: Option<Zeroizing<String>>,
}

/// The `_meta` the vault reads: `io.bastionvault/confirmation`
/// (`{"by": "operator", "at", "mfa"}`) and, for a gated profile,
/// `io.bastionvault/connect_ticket`. Never in `arguments`: the ticket is
/// bound to their hash.
fn assert_gatekeeper_meta(message: &mut Value, assertion: &Assertion) {
    let Some(object) = message.as_object_mut() else { return };
    let params = object.entry("params").or_insert(Value::Null);
    if params.is_null() {
        *params = Value::Object(Map::new());
    }
    let Some(params) = params.as_object_mut() else { return };
    let meta = params.entry("_meta").or_insert(Value::Null);
    if !meta.is_object() {
        *meta = Value::Object(Map::new());
    }
    let Some(meta) = meta.as_object_mut() else { return };
    meta.insert(
        OPERATOR_CONFIRMATION_META_KEY.to_string(),
        json!({ "by": "operator", "at": assertion.at, "mfa": assertion.mfa }),
    );
    if let Some(ticket) = &assertion.ticket {
        meta.insert(CONNECT_TICKET_META_KEY.to_string(), Value::String(ticket.to_string()));
    }
}

/// Wipes the relayed copy of a ticket once the relay is done with it.
fn wipe_relayed_ticket(message: &mut Value) {
    let ticket =
        message.get_mut("params").and_then(|p| p.get_mut("_meta")).and_then(|m| m.get_mut(CONNECT_TICKET_META_KEY));
    if let Some(Value::String(ticket)) = ticket {
        ticket.zeroize();
    }
}

fn major_minor(version: &str) -> String {
    version.splitn(3, '.').take(2).collect::<Vec<_>>().join(".")
}

fn parse_client_info(info: &Value) -> Option<(String, String)> {
    let name = info.get("name")?.as_str()?.trim();
    if name.is_empty() || name.len() > MAX_CLIENT_NAME_LEN {
        return None;
    }
    let version = info.get("version").and_then(Value::as_str).unwrap_or("").trim();
    Some((name.to_string(), version.chars().take(64).collect()))
}

/// Argument names safe to show an operator: they identify *what* a call
/// touches, never a secret value the call carries.
const SUMMARY_KEYS: &[&str] = &["mount", "path", "key", "name", "role", "serial", "common_name"];

fn call_summary(arguments: &Value) -> String {
    SUMMARY_KEYS
        .iter()
        .filter_map(|k| arguments.get(*k).and_then(Value::as_str).map(|v| format!("{k}={v}")))
        .collect::<Vec<_>>()
        .join(" ")
}

fn default_notice(message: &str) {
    eprintln!("bvault mcp: {message}");
}

impl LocalServer {
    pub fn new(link: Box<dyn VaultLink>, prompter: Box<dyn Prompter>, store: PairingStore) -> Self {
        Self::with_clock(link, prompter, store, now_secs)
    }

    pub fn with_clock(
        link: Box<dyn VaultLink>,
        prompter: Box<dyn Prompter>,
        store: PairingStore,
        clock: fn() -> u64,
    ) -> Self {
        Self {
            link,
            prompter,
            store,
            pairing_lock: Mutex::new(()),
            mint_lock: Mutex::new(()),
            tokens: Mutex::new(HashMap::new()),
            clock,
            server_version: major_minor(env!("CARGO_PKG_VERSION")),
            notice: default_notice,
            closed: AtomicBool::new(false),
        }
    }

    /// The host's version (a full `x.y.z` is fine; only `major.minor` is
    /// reported). Each host passes its own, so `serverInfo.version` names the
    /// product the operator installed rather than this library.
    pub fn with_server_version(mut self, version: &str) -> Self {
        self.server_version = major_minor(version);
        self
    }

    /// Where one-line notices go. The default writes `bvault mcp: …` to
    /// stderr, which on stdio is the only channel that is not the protocol.
    pub fn with_notice(mut self, notice: fn(&str)) -> Self {
        self.notice = notice;
        self
    }

    pub fn store(&self) -> &PairingStore {
        &self.store
    }

    /// The server's clock, for a transport that judges expiry itself.
    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Stops this server for good: every later message is refused with
    /// `mcp_server_stopped`, nothing more is minted, and every token minted
    /// so far is forgotten (and wiped). Returns the vault accessors of those
    /// tokens -- `hex(blake3(token))`, the same handle `sys/mcp/tokens`
    /// lists -- so a host can revoke them on the vault without ever holding a
    /// token outside this server. Never waits on the vault: a mint still in
    /// flight is refused, and its token wiped, when it returns.
    pub fn shutdown(&self) -> Vec<String> {
        self.closed.store(true, Ordering::SeqCst);
        let tokens = std::mem::take(&mut *lock(&self.tokens));
        tokens.values().map(|t| hash_token(&t.token)).collect()
    }

    pub fn is_shut_down(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// One JSON-RPC message in, at most one out. `None` for a notification
    /// (no `id`): there is nothing to answer and, since the vault's endpoint
    /// only takes requests, nothing to forward.
    ///
    /// Stateless: every request must name its client in `_meta`. This is the
    /// loopback-HTTP entry point; the line transports use
    /// [`Self::handle_session_message`].
    pub fn handle_message(&self, conn: &ConnInfo, raw: &[u8]) -> Option<Value> {
        self.handle(conn, None, raw)
    }

    /// [`Self::handle_message`] for a connection that may open with the
    /// stateful `initialize` handshake. `session` lives as long as the
    /// connection does.
    pub fn handle_session_message(&self, conn: &ConnInfo, session: &mut SessionState, raw: &[u8]) -> Option<Value> {
        self.handle(conn, Some(session), raw)
    }

    fn handle(&self, conn: &ConnInfo, session: Option<&mut SessionState>, raw: &[u8]) -> Option<Value> {
        let message: Value = match serde_json::from_slice(raw) {
            Ok(v) => v,
            Err(_) => return Some(rpc_error(Value::Null, -32700, "parse error", "mcp_parse_error")),
        };
        let Some(object) = message.as_object() else {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "batches and non-object messages are not supported",
                "mcp_invalid_request",
            ));
        };
        let id = object.get("id").cloned()?;
        if self.is_shut_down() {
            return Some(Refusal::stopped().into_response(id));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(rpc_error(id, -32600, "missing method", "mcp_invalid_request"));
        };

        let handshake = match session {
            Some(session) => {
                match method {
                    "initialize" => return Some(self.initialize(conn, session, id, object)),
                    // The vault has no `ping`; a stateful client expects one
                    // answered once it has initialized.
                    "ping" if session.handshake.is_some() => return Some(rpc_success(id, json!({}))),
                    _ => {}
                }
                session.handshake.as_ref()
            }
            None => None,
        };

        let identity = match request_identity(handshake, object) {
            Ok(identity) => identity,
            Err(refusal) => return Some(refusal.into_response(id)),
        };
        let record = match self.resolve_pairing(conn, identity) {
            Ok(r) => r,
            Err(refusal) => return Some(refusal.into_response(id)),
        };
        let assertion = match self.confirm_if_needed(&record, object) {
            Ok(assertion) => assertion,
            Err(refusal) => return Some(refusal.into_response(id)),
        };
        let token = match self.token_for(&record) {
            Ok(t) => t,
            Err(refusal) => return Some(refusal.into_response(id)),
        };

        let mut forwarded = match handshake {
            Some(handshake) => with_client_info(object, handshake),
            None => message.clone(),
        };
        strip_gatekeeper_meta(&mut forwarded);
        if let Some(assertion) = &assertion {
            assert_gatekeeper_meta(&mut forwarded, assertion);
        }
        // Last look before the vault: a stop that landed while this call was
        // being resolved refuses it here rather than after it has run.
        if self.is_shut_down() {
            wipe_relayed_ticket(&mut forwarded);
            return Some(Refusal::stopped().into_response(id));
        }
        let relayed = self.link.forward(&token, &forwarded);
        wipe_relayed_ticket(&mut forwarded);
        match relayed {
            Ok(response) => Some(response),
            Err(ForwardError::Refused(status)) => {
                lock(&self.tokens).remove(&record.id);
                Some(rpc_error(
                    id,
                    -32603,
                    &format!("the vault refused this pairing's token (HTTP {status}); it was revoked or expired -- retry to mint a fresh one"),
                    "mcp_token_refused",
                ))
            }
            Err(ForwardError::Other(e)) => Some(rpc_error(id, -32603, &e, "mcp_vault_unavailable")),
        }
    }

    /// Answers a stateful client's `initialize` here: the vault speaks only the
    /// stateless revision and has no such method. The pairing is resolved now
    /// -- prompting the operator if there is one -- so an unapproved client
    /// fails at connect, not at its first tool call. No token is minted and
    /// nothing reaches the vault until the first relayed request.
    fn initialize(
        &self,
        conn: &ConnInfo,
        session: &mut SessionState,
        id: Value,
        message: &Map<String, Value>,
    ) -> Value {
        if session.handshake.is_some() {
            return rpc_error(id, -32600, "initialize may be sent only once per connection", "mcp_already_initialized");
        }
        let params = message.get("params");
        let Some((client_name, client_version)) = params.and_then(|p| p.get("clientInfo")).and_then(parse_client_info)
        else {
            return rpc_error(id, -32602, "initialize must carry clientInfo with a name", "mcp_client_info_required");
        };
        let requested = params.and_then(|p| p.get("protocolVersion")).and_then(Value::as_str).unwrap_or("");
        let negotiated = negotiate_protocol_version(requested);

        if let Err(refusal) = self.resolve_pairing(conn, Some((client_name.clone(), client_version.clone()))) {
            return refusal.into_response(id);
        }
        (self.notice)(&format!(
            "`{}` {} initialized (MCP {negotiated})",
            sanitize_for_model(&client_name),
            sanitize_for_model(&client_version)
        ));
        session.handshake = Some(Handshake { client_name, client_version });
        rpc_success(
            id,
            json!({
                "protocolVersion": negotiated,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "bastionvault", "version": self.server_version },
            }),
        )
    }

    fn resolve_pairing(&self, conn: &ConnInfo, identity: Option<(String, String)>) -> Result<PairingRecord, Refusal> {
        if let Some(record) = &conn.preauthenticated {
            return Ok(record.clone());
        }
        let Some((client_name, client_version)) = identity else {
            return Err(Refusal::new(
                -32602,
                "mcp_client_info_required",
                "request `_meta` must carry io.modelcontextprotocol/clientInfo with a name",
            ));
        };

        let _serialised = lock(&self.pairing_lock);
        let now = (self.clock)();
        let records = self.store.load().map_err(|e| Refusal::new(-32603, "mcp_pairing_store_error", e.to_string()))?;
        if let Some(found) = find_matching(&records, &client_name, conn.peer_uid, conn.transport, now) {
            return Ok(found.clone());
        }
        if conn.transport == Transport::LoopbackHttp {
            // Unreachable through the HTTP transport, which only admits a
            // bearer that already maps to a pairing. Refuse rather than
            // prompt: an HTTP client cannot be handed a bearer inline.
            return Err(Refusal::new(-32001, "mcp_pairing_required", "pair this client with `bvault mcp pair`"));
        }

        let request = PairingRequest {
            client_name: &client_name,
            client_version: &client_version,
            transport: conn.transport,
            peer_uid: conn.peer_uid,
        };
        let decision = self.prompter.approve(&request);
        if self.is_shut_down() {
            // Stopped while the operator was being asked: whatever the
            // answer, this server serves nobody any more.
            return Err(Refusal::stopped());
        }
        match decision {
            None => {
                Err(Refusal::new(-32001, "mcp_pairing_requires_operator", self.prompter.pairing_unavailable_message()))
            }
            Some(PairingDecision::Denied) => {
                Err(Refusal::new(-32001, "mcp_pairing_denied", "the operator declined to pair this client"))
            }
            Some(PairingDecision::Approved(grant)) => {
                let (record, _no_inline_bearer) = build_record(&request, &grant, now);
                self.store
                    .upsert(record.clone())
                    .map_err(|e| Refusal::new(-32603, "mcp_pairing_store_error", e.to_string()))?;
                Ok(record)
            }
        }
    }

    /// Per-call operator confirmation: for a session tool, every call
    /// ([`Self::confirm_session`]); for a reveal or a write, when the grant
    /// allows it and asked to confirm it. A call the grant would refuse
    /// anyway is forwarded without a prompt (the vault will deny it); a call
    /// needing a confirmation nobody can give is refused. `Some` is what the
    /// operator approved, for the relayed `_meta`.
    fn confirm_if_needed(
        &self,
        record: &PairingRecord,
        message: &Map<String, Value>,
    ) -> Result<Option<Assertion>, Refusal> {
        if message.get("method").and_then(Value::as_str) != Some("tools/call") {
            return Ok(None);
        }
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let Some(tool) = params.get("name").and_then(Value::as_str) else {
            return Ok(None);
        };
        let Some(meta) = catalogue::find(tool) else {
            return Ok(None);
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        if meta.open_world {
            return self.confirm_session(record, meta, &arguments);
        }
        let reveal_requested = arguments.get("reveal").and_then(Value::as_bool).unwrap_or(false);

        let reveals = meta.is_reveal && reveal_requested;
        let destructive = meta.destructive;
        if (reveals && !record.reveal_allowed) || (destructive && !record.destructive_allowed) {
            return Ok(None);
        }
        let needs = (reveals && record.confirm_reveal) || (destructive && record.confirm_destructive);
        if !needs {
            return Ok(None);
        }

        let summary = call_summary(&arguments);
        let request = ConfirmRequest {
            client_name: &record.client_name,
            tool,
            summary: &summary,
            reveals,
            destructive,
            detail: None,
            session: None,
            open_world: false,
            mfa: None,
        };
        let answer = self.prompter.confirm(&request);
        self.judge_answer(answer)?;
        Ok(Some(Assertion { at: (self.clock)(), mfa: false, ticket: None }))
    }

    /// The operator's answer, or the refusal it amounts to.
    fn judge_answer(&self, answer: Option<bool>) -> Result<(), Refusal> {
        if self.is_shut_down() {
            return Err(Refusal::stopped());
        }
        match answer {
            Some(true) => Ok(()),
            Some(false) => Err(Refusal::new(-32001, "mcp_confirmation_denied", "the operator declined this call")),
            None => {
                Err(Refusal::new(-32001, "mcp_confirmation_denied", self.prompter.confirmation_unavailable_message()))
            }
        }
    }

    /// A brokered-session call (`features/mcp-brokered-sessions.md` §3 step
    /// 3, §3.1, §9). Every one the vault could run is shown to the operator
    /// -- there is no grant, flag or record field that skips this -- with
    /// the exact command, and, when the profile is gated, completes the
    /// operator's MFA in the same prompt, bound to this one call.
    ///
    /// A call the vault refuses before it runs anything (not in the
    /// allow-list, no `connect_allowed`, malformed, outside the path scope)
    /// is relayed unprompted and unconfirmed, so the vault answers it with
    /// its own code and audit event and nobody is asked about it.
    fn confirm_session(
        &self,
        record: &PairingRecord,
        meta: &ToolMeta,
        arguments: &Value,
    ) -> Result<Option<Assertion>, Refusal> {
        if !record.tool_allowlist.iter().any(|t| t == meta.name) || !record.connect_allowed {
            return Ok(None);
        }
        let empty = Map::new();
        let args = match arguments {
            Value::Object(args) => args,
            Value::Null => &empty,
            _ => return Ok(None),
        };
        let Ok(call) = dispatcher::session_call(meta.name, args) else {
            return Ok(None);
        };
        if !dispatcher::path_scope_covers(&record.path_scope, &call.scope_subject) {
            return Ok(None);
        }

        // Is the profile gated? The vault decides, asked as the operator.
        let challenge = match self.link.connect_mfa_begin(&call.resource, &call.profile) {
            Ok(MfaPreflight::NotRequired) => None,
            Ok(MfaPreflight::Required(challenge)) => Some(challenge),
            Err(MfaBeginError::Unavailable(reason)) => {
                return Err(Refusal::new(-32001, "mcp_session_mfa_unavailable", sanitize_for_model(&reason)))
            }
            Err(MfaBeginError::Other(reason)) => {
                return Err(Refusal::new(
                    -32603,
                    "mcp_session_mfa_check_failed",
                    format!(
                        "could not ask the vault, as the operator, whether this profile requires MFA: {}",
                        sanitize_for_model(&reason)
                    ),
                ))
            }
        };
        if let Some(challenge) = &challenge {
            let collectable = self.prompter.mfa_methods();
            if !challenge.methods.iter().any(|m| collectable.contains(&m.as_str())) {
                return Err(Refusal::new(
                    -32001,
                    "mcp_session_mfa_unavailable",
                    self.prompter.mfa_unavailable_message(),
                ));
            }
        }

        let bound_to = McpCallRef {
            pairing_id: record.id.clone(),
            tool: meta.name.to_string(),
            args_hash: call.args_hash.clone(),
        };
        let ticket: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);
        let verify = |factor: MfaFactor| -> Result<(), String> {
            let minted = self.link.connect_mfa_verify(&call.resource, &call.profile, &factor, &bound_to)?;
            *lock(&ticket) = Some(minted);
            Ok(())
        };
        let detail = render_session_detail(&call);
        let request = ConfirmRequest {
            client_name: &record.client_name,
            tool: meta.name,
            summary: "",
            reveals: false,
            destructive: meta.destructive,
            detail: Some(&detail),
            session: Some(&call),
            open_world: true,
            mfa: challenge.as_ref().map(|challenge| MfaStep { challenge, verify: &verify }),
        };
        let answer = self.prompter.confirm(&request);
        self.judge_answer(answer)?;

        let ticket = lock(&ticket).take();
        if challenge.is_some() && ticket.is_none() {
            return Err(Refusal::new(
                -32001,
                "mcp_confirmation_denied",
                "this profile requires the operator's MFA, which was not completed; the call was not run",
            ));
        }
        Ok(Some(Assertion { at: (self.clock)(), mfa: ticket.is_some(), ticket }))
    }

    fn token_for(&self, record: &PairingRecord) -> Result<Zeroizing<String>, Refusal> {
        let now = (self.clock)();
        // One mint at a time, so two first calls from one client mint once.
        // Held across the vault round trip; `tokens` is not, so a
        // `shutdown` never waits on the network.
        let _minting = lock(&self.mint_lock);
        {
            let tokens = lock(&self.tokens);
            if self.is_shut_down() {
                return Err(Refusal::stopped());
            }
            if let Some(t) = tokens.get(&record.id) {
                if t.expires_at > now + TOKEN_REFRESH_MARGIN_SECS {
                    return Ok(Zeroizing::new(t.token.clone()));
                }
            }
        }
        let ttl = exchange_ttl(record, now);
        let minted = self
            .link
            .exchange_pairing(record, ttl)
            .map_err(|e| Refusal::new(-32603, "mcp_exchange_failed", format!("could not mint an MCP token: {e}")))?;
        let token = {
            let mut tokens = lock(&self.tokens);
            // Judged under the lock `shutdown` drains under: either the drain
            // is still to come and will hand this token's accessor back with
            // the rest, or it has run and the token is wiped here (dropped)
            // rather than cached past it.
            if self.is_shut_down() {
                return Err(Refusal::stopped());
            }
            let token = Zeroizing::new(minted.token.clone());
            tokens.insert(record.id.clone(), minted);
            token
        };
        // Best effort, once per mint rather than per message.
        let _ = self.store.touch(&record.id, now);
        Ok(token)
    }
}

/// The token never outlives the pairing it was minted for.
pub fn exchange_ttl(record: &PairingRecord, now: u64) -> u64 {
    let requested = record.ttl_secs.clamp(1, MAX_TOKEN_TTL_SECS);
    match record.expires_at {
        Some(expiry) => requested.min(expiry.saturating_sub(now)).max(1),
        None => requested,
    }
}

/// Newline-delimited JSON-RPC, the stdio framing. Shared by stdio and the
/// Unix-socket transport.
pub fn run_line_session<R: BufRead, W: Write>(
    server: &LocalServer,
    conn: &ConnInfo,
    mut reader: R,
    mut writer: W,
) -> std::io::Result<()> {
    let mut session = SessionState::default();
    loop {
        let mut line = Vec::new();
        let read = (&mut reader).take(MAX_MESSAGE_BYTES + 1).read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(());
        }
        if line.len() as u64 > MAX_MESSAGE_BYTES {
            let too_big = rpc_error(Value::Null, -32600, "message too large", "mcp_message_too_large");
            serde_json::to_writer(&mut writer, &too_big)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            return Ok(());
        }
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(response) = server.handle_session_message(conn, &mut session, trimmed) {
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
}

/// One of at most [`MAX_CONCURRENT_CONNECTIONS`] connection slots, released
/// on drop.
pub struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    pub fn acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
        if counter.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
            counter.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnectionSlot(counter.clone()))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::local::operator::{MfaChallenge, PairingGrant};
    use crate::pairing::new_pairing_id;

    pub(crate) const MINTED: &str = "SECRET-MCP-TOKEN-0123456789";
    pub(crate) const TICKET: &str = "SECRET-CONNECT-TICKET-abcdef";

    /// One `connect/mfa/verify` the fake vault saw:
    /// `(resource, profile, method, factor, call)`.
    pub(crate) type VerifyCall = (String, String, String, String, McpCallRef);

    #[derive(Default)]
    pub(crate) struct FakeLink {
        pub(crate) exchanges: AtomicUsize,
        pub(crate) forwards: Mutex<Vec<(String, Value)>>,
        pub(crate) refuse_next_forward: Mutex<Option<u16>>,
        pub(crate) minted_ttls: Mutex<Vec<u64>>,
        /// What `connect/mfa/begin` answers; `None` is "not required".
        pub(crate) begin: Mutex<Option<Result<MfaPreflight, MfaBeginError>>>,
        pub(crate) begins: Mutex<Vec<(String, String)>>,
        /// What `connect/mfa/verify` answers; `None` mints [`TICKET`].
        pub(crate) verify: Mutex<Option<Result<String, String>>>,
        /// `(resource, profile, method, factor, call)` per verify.
        pub(crate) verifies: Mutex<Vec<VerifyCall>>,
    }

    impl VaultLink for Arc<FakeLink> {
        fn exchange_pairing(&self, _record: &PairingRecord, ttl_secs: u64) -> Result<MintedToken, String> {
            self.exchanges.fetch_add(1, Ordering::SeqCst);
            lock(&self.minted_ttls).push(ttl_secs);
            Ok(MintedToken { token: MINTED.to_string(), expires_at: now_secs() + ttl_secs })
        }

        fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError> {
            if let Some(status) = lock(&self.refuse_next_forward).take() {
                return Err(ForwardError::Refused(status));
            }
            lock(&self.forwards).push((token.to_string(), message.clone()));
            Ok(json!({ "jsonrpc": "2.0", "id": message["id"], "result": { "relayed": true } }))
        }

        fn connect_mfa_begin(&self, resource: &str, profile_id: &str) -> Result<MfaPreflight, MfaBeginError> {
            lock(&self.begins).push((resource.to_string(), profile_id.to_string()));
            lock(&self.begin).clone().unwrap_or(Ok(MfaPreflight::NotRequired))
        }

        fn connect_mfa_verify(
            &self,
            resource: &str,
            profile_id: &str,
            factor: &MfaFactor,
            call: &McpCallRef,
        ) -> Result<Zeroizing<String>, String> {
            let shown = match factor {
                MfaFactor::Totp(code) => code.to_string(),
                MfaFactor::Fido2(credential) => credential.to_string(),
            };
            lock(&self.verifies).push((
                resource.to_string(),
                profile_id.to_string(),
                factor.method().to_string(),
                shown,
                call.clone(),
            ));
            lock(&self.verify).clone().unwrap_or(Ok(TICKET.to_string())).map(Zeroizing::new)
        }
    }

    /// What a confirmation showed the operator.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct Shown {
        pub(crate) tool: String,
        pub(crate) detail: Option<String>,
        pub(crate) command: Option<String>,
        pub(crate) open_world: bool,
        pub(crate) mfa_methods: Option<Vec<String>>,
        pub(crate) verified: Option<Result<(), String>>,
    }

    #[derive(Default)]
    pub(crate) struct Scripted {
        pub(crate) approve: Mutex<Option<Option<PairingDecision>>>,
        pub(crate) confirm: Mutex<Option<Option<bool>>>,
        /// The TOTP code the operator types when a call asks for MFA.
        pub(crate) totp: Mutex<Option<String>>,
        pub(crate) approvals_asked: AtomicUsize,
        pub(crate) confirms_asked: AtomicUsize,
        pub(crate) shown: Mutex<Vec<Shown>>,
    }

    impl Prompter for Arc<Scripted> {
        fn approve(&self, _request: &PairingRequest<'_>) -> Option<PairingDecision> {
            self.approvals_asked.fetch_add(1, Ordering::SeqCst);
            lock(&self.approve).clone().unwrap_or(None)
        }

        fn confirm(&self, request: &ConfirmRequest<'_>) -> Option<bool> {
            self.confirms_asked.fetch_add(1, Ordering::SeqCst);
            let mut shown = Shown {
                tool: request.tool.to_string(),
                detail: request.detail.map(str::to_string),
                command: request.session.map(|c| c.command.clone()),
                open_world: request.open_world,
                mfa_methods: request.mfa.as_ref().map(|m| m.challenge.methods.clone()),
                verified: None,
            };
            let answer = (*lock(&self.confirm)).unwrap_or(None);
            if let (Some(step), Some(true), Some(code)) = (&request.mfa, answer, lock(&self.totp).clone()) {
                let verified = (step.verify)(MfaFactor::Totp(Zeroizing::new(code)));
                let failed = verified.is_err();
                shown.verified = Some(verified);
                lock(&self.shown).push(shown);
                // A failed factor denies.
                return Some(!failed);
            }
            lock(&self.shown).push(shown);
            answer
        }

        fn mfa_methods(&self) -> &[&'static str] {
            &["totp"]
        }
    }

    pub(crate) fn grant() -> PairingGrant {
        PairingGrant {
            tool_allowlist: vec!["bv_kv_read_metadata".into(), "bv_kv_read".into()],
            path_scope: vec!["secret/*".into()],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            connect_allowed: false,
            confirm_connect: false,
            ttl_secs: 3600,
        }
    }

    pub(crate) struct Rig {
        pub(crate) server: Arc<LocalServer>,
        pub(crate) link: Arc<FakeLink>,
        pub(crate) prompt: Arc<Scripted>,
        pub(crate) dir: std::path::PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    pub(crate) fn rig(name: &str) -> Rig {
        let dir = std::env::temp_dir().join(format!("bv-mcp-local-{name}-{}", new_pairing_id()));
        let link = Arc::new(FakeLink::default());
        let prompt = Arc::new(Scripted::default());
        let server = Arc::new(LocalServer::new(
            Box::new(link.clone()),
            Box::new(prompt.clone()),
            PairingStore::at(dir.join("mcp-pairings.json")),
        ));
        Rig { server, link, prompt, dir }
    }

    pub(crate) fn stdio() -> ConnInfo {
        ConnInfo { transport: Transport::Stdio, peer_uid: None, preauthenticated: None }
    }

    pub(crate) fn request(id: u64, method: &str, params: Value) -> Vec<u8> {
        let mut params = params;
        params["_meta"] =
            json!({ "io.modelcontextprotocol/clientInfo": { "name": "claude-desktop", "version": "9.9" } });
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })).unwrap()
    }

    pub(crate) fn data_code(resp: &Value) -> &str {
        resp["error"]["data"]["code"].as_str().unwrap_or("")
    }

    #[test]
    fn unpaired_client_without_an_operator_fails_closed() {
        let rig = rig("noterminal");
        // Scripted::approve defaults to None: no operator reachable.
        let resp = rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_pairing_requires_operator");
        assert!(resp["error"]["message"].as_str().unwrap().contains("no terminal"), "the CLI wording is the default");
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 0, "no token may be minted for an unpaired client");
        assert!(lock(&rig.link.forwards).is_empty());
        assert!(rig.server.store().load().unwrap().is_empty(), "nothing is recorded without approval");
    }

    #[test]
    fn a_host_can_word_the_no_operator_refusal_for_its_own_channel() {
        struct Gui;
        impl Prompter for Gui {
            fn approve(&self, _: &PairingRequest<'_>) -> Option<PairingDecision> {
                None
            }
            fn confirm(&self, _: &ConfirmRequest<'_>) -> Option<bool> {
                None
            }
            fn pairing_unavailable_message(&self) -> &str {
                "nobody approved it in the app"
            }
        }
        let dir = std::env::temp_dir().join(format!("bv-mcp-local-wording-{}", new_pairing_id()));
        let server = LocalServer::new(
            Box::new(Arc::new(FakeLink::default())),
            Box::new(Gui),
            PairingStore::at(dir.join("p.json")),
        );
        let resp = server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_pairing_requires_operator");
        assert_eq!(resp["error"]["message"], json!("nobody approved it in the app"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn operator_denial_is_respected_and_not_persisted() {
        let rig = rig("denied");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Denied));
        let resp = rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_pairing_denied");
        assert!(rig.server.store().load().unwrap().is_empty());
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn approval_pairs_persists_mints_once_and_relays() {
        let rig = rig("approve");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));

        let first = rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        assert_eq!(first["result"]["relayed"], json!(true));
        let second = rig.server.handle_message(&stdio(), &request(2, "tools/list", json!({}))).unwrap();
        assert_eq!(second["id"], json!(2));

        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 1, "a paired client is not asked again");
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 1, "the minted token is reused while valid");
        let forwards = lock(&rig.link.forwards);
        assert_eq!(forwards.len(), 2);
        assert_eq!(forwards[0].0, MINTED);

        let records = rig.server.store().load().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].client_name, "claude-desktop");
        assert_eq!(records[0].tool_allowlist, grant().tool_allowlist);
    }

    #[test]
    fn the_minted_token_is_never_written_to_disk() {
        let rig = rig("notoken");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        rig.server.handle_message(&stdio(), &request(2, "tools/list", json!({}))).unwrap();

        // Neither the sealed file nor the decrypted records mention it...
        let raw = std::fs::read_to_string(rig.server.store().path()).unwrap();
        assert!(!raw.contains(MINTED));
        let records = serde_json::to_string(&rig.server.store().load().unwrap()).unwrap();
        assert!(!records.contains(MINTED));
        // ...nor does anything else this run left in its directory.
        for entry in std::fs::read_dir(&rig.dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(MINTED));
        }
    }

    #[test]
    fn notifications_get_no_reply_and_are_not_forwarded() {
        let rig = rig("notify");
        let note = serde_json::to_vec(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).unwrap();
        assert!(rig.server.handle_message(&stdio(), &note).is_none());
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 0);
        assert!(lock(&rig.link.forwards).is_empty());
    }

    #[test]
    fn malformed_and_batch_input_is_refused() {
        let rig = rig("malformed");
        let parse = rig.server.handle_message(&stdio(), b"{not json").unwrap();
        assert_eq!(parse["error"]["code"], json!(-32700));
        let batch = rig.server.handle_message(&stdio(), b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"}]").unwrap();
        assert_eq!(data_code(&batch), "mcp_invalid_request");
        let no_method = rig.server.handle_message(&stdio(), b"{\"jsonrpc\":\"2.0\",\"id\":1}").unwrap();
        assert_eq!(data_code(&no_method), "mcp_invalid_request");
        assert!(lock(&rig.link.forwards).is_empty());
    }

    #[test]
    fn a_request_without_client_info_cannot_pair() {
        let rig = rig("noinfo");
        let bare =
            serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} })).unwrap();
        let resp = rig.server.handle_message(&stdio(), &bare).unwrap();
        assert_eq!(data_code(&resp), "mcp_client_info_required");
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 0);
    }

    // ── stateful handshake (MCP 2025-xx clients such as Claude Code) ──────

    /// `initialize` exactly as Claude Code 2.1.277 sends it: the client is
    /// named in `params.clientInfo`, never in `_meta`.
    pub(crate) fn initialize(id: u64, version: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": { "name": "claude-code", "title": "Claude Code", "version": "2.1.277" },
            },
        }))
        .unwrap()
    }

    /// A request with no `_meta`, as a stateful client sends after `initialize`.
    pub(crate) fn bare(id: u64, method: &str, params: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })).unwrap()
    }

    #[test]
    fn handshake_pairs_at_initialize_and_carries_the_identity_onto_relayed_requests() {
        let rig = rig("handshake");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let mut session = SessionState::default();

        let init = rig.server.handle_session_message(&stdio(), &mut session, &initialize(0, "2025-11-25")).unwrap();
        assert_eq!(init["result"]["protocolVersion"], json!("2025-11-25"));
        assert_eq!(init["result"]["capabilities"]["tools"], json!({ "listChanged": false }));
        assert_eq!(init["result"]["serverInfo"]["name"], json!("bastionvault"));
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 1, "pairing is decided at connect");
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 0, "initialize mints nothing");
        assert!(lock(&rig.link.forwards).is_empty(), "initialize never reaches the vault");

        let list =
            rig.server.handle_session_message(&stdio(), &mut session, &bare(1, "tools/list", json!({}))).unwrap();
        assert_eq!(list["result"]["relayed"], json!(true));
        // A request with no params at all is completed the same way.
        let no_params = serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })).unwrap();
        rig.server.handle_session_message(&stdio(), &mut session, &no_params).unwrap();

        let forwards = lock(&rig.link.forwards);
        assert_eq!(forwards.len(), 2);
        for (token, message) in forwards.iter() {
            assert_eq!(token, MINTED);
            assert_eq!(
                message["params"]["_meta"][CLIENT_INFO_META_KEY],
                json!({ "name": "claude-code", "version": "2.1.277" })
            );
        }
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 1, "a paired client is not asked again");
        let records = rig.server.store().load().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].client_name, "claude-code");
        assert_eq!(records[0].transport, "stdio");
    }

    #[test]
    fn handshake_reports_the_host_version_it_was_given() {
        let rig = rig("handshake-version");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let server = LocalServer::new(
            Box::new(rig.link.clone()),
            Box::new(rig.prompt.clone()),
            PairingStore::at(rig.dir.join("mcp-pairings.json")),
        )
        .with_server_version("0.44.32");
        let mut session = SessionState::default();
        let init = server.handle_session_message(&stdio(), &mut session, &initialize(0, "2025-11-25")).unwrap();
        assert_eq!(init["result"]["serverInfo"]["version"], json!("0.44"));
    }

    #[test]
    fn handshake_negotiates_a_supported_revision_or_offers_the_newest() {
        for (asked, answered) in [
            ("2025-11-25", "2025-11-25"),
            ("2025-06-18", "2025-06-18"),
            ("2025-03-26", "2025-03-26"),
            ("2024-11-05", "2025-11-25"),
            ("2026-07-28", "2025-11-25"),
            ("", "2025-11-25"),
        ] {
            let rig = rig("negotiate");
            *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
            let mut session = SessionState::default();
            let init = rig.server.handle_session_message(&stdio(), &mut session, &initialize(0, asked)).unwrap();
            assert_eq!(init["result"]["protocolVersion"], json!(answered), "asked for `{asked}`");
        }
    }

    #[test]
    fn an_unapproved_handshake_fails_closed_and_establishes_nothing() {
        let rig = rig("handshake-noterminal");
        // Scripted::approve defaults to None: no operator reachable.
        let mut session = SessionState::default();
        let init = rig.server.handle_session_message(&stdio(), &mut session, &initialize(0, "2025-11-25")).unwrap();
        assert_eq!(data_code(&init), "mcp_pairing_requires_operator");
        assert!(init.get("result").is_none());

        // The failed handshake did not leave an identity behind to borrow.
        let list =
            rig.server.handle_session_message(&stdio(), &mut session, &bare(1, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&list), "mcp_client_info_required");
        let ping = rig.server.handle_session_message(&stdio(), &mut session, &bare(2, "ping", json!({}))).unwrap();
        assert_eq!(data_code(&ping), "mcp_client_info_required", "no local ping before a handshake");
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 0);
        assert!(lock(&rig.link.forwards).is_empty());
        assert!(rig.server.store().load().unwrap().is_empty());
    }

    #[test]
    fn initialize_without_client_info_is_refused_before_any_prompt() {
        let rig = rig("handshake-noinfo");
        let mut session = SessionState::default();
        for params in [json!({ "protocolVersion": "2025-11-25" }), json!({ "clientInfo": { "name": "  " } })] {
            let init =
                rig.server.handle_session_message(&stdio(), &mut session, &bare(0, "initialize", params)).unwrap();
            assert_eq!(data_code(&init), "mcp_client_info_required");
        }
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_connection_initializes_once_and_cannot_change_who_it_is() {
        let rig = rig("handshake-identity");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let mut session = SessionState::default();
        rig.server.handle_session_message(&stdio(), &mut session, &initialize(0, "2025-11-25")).unwrap();

        let again = rig.server.handle_session_message(&stdio(), &mut session, &initialize(1, "2025-11-25")).unwrap();
        assert_eq!(data_code(&again), "mcp_already_initialized");

        // `request()` names `claude-desktop` in `_meta`: another client.
        let other =
            rig.server.handle_session_message(&stdio(), &mut session, &request(2, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&other), "mcp_client_info_mismatch");
        assert!(lock(&rig.link.forwards).is_empty(), "a mismatched request is never relayed");
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 1, "and never prompts a second pairing");

        // Naming itself consistently in `_meta` is fine.
        let mut same = serde_json::from_slice::<Value>(&bare(3, "tools/list", json!({}))).unwrap();
        same["params"]["_meta"] = json!({ CLIENT_INFO_META_KEY: { "name": "claude-code", "version": "2.1.277" } });
        let resp =
            rig.server.handle_session_message(&stdio(), &mut session, &serde_json::to_vec(&same).unwrap()).unwrap();
        assert_eq!(resp["result"]["relayed"], json!(true));
    }

    #[test]
    fn ping_after_the_handshake_is_answered_here() {
        let rig = rig("handshake-ping");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let mut session = SessionState::default();
        rig.server.handle_session_message(&stdio(), &mut session, &initialize(0, "2025-11-25")).unwrap();
        let pong = rig.server.handle_session_message(&stdio(), &mut session, &bare(7, "ping", json!({}))).unwrap();
        assert_eq!(pong["id"], json!(7));
        assert_eq!(pong["result"], json!({}));
        assert!(lock(&rig.link.forwards).is_empty());
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_stateless_entry_point_does_not_take_the_handshake() {
        let rig = rig("handshake-stateless");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let resp = rig.server.handle_message(&stdio(), &initialize(0, "2025-11-25")).unwrap();
        assert_eq!(data_code(&resp), "mcp_client_info_required");
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_line_session_speaks_the_stateful_handshake_end_to_end() {
        let rig = rig("handshake-lines");
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let input = [
            String::from_utf8(initialize(0, "2025-11-25")).unwrap(),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
            String::from_utf8(bare(1, "tools/list", json!({}))).unwrap(),
        ]
        .join("\n");
        let mut out = Vec::new();
        run_line_session(&rig.server, &stdio(), std::io::Cursor::new(input.into_bytes()), &mut out).unwrap();
        let replies: Vec<Value> =
            out.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect();
        assert_eq!(replies.len(), 2, "the notification gets no reply");
        assert_eq!(replies[0]["result"]["protocolVersion"], json!("2025-11-25"));
        assert_eq!(replies[1]["result"]["relayed"], json!(true));

        // A new connection starts with no identity of its own.
        let mut out = Vec::new();
        let later = String::from_utf8(bare(2, "tools/list", json!({}))).unwrap();
        run_line_session(&rig.server, &stdio(), std::io::Cursor::new(later.into_bytes()), &mut out).unwrap();
        let reply: Value = serde_json::from_slice(out.trim_ascii()).unwrap();
        assert_eq!(data_code(&reply), "mcp_client_info_required");
    }

    fn reveal_call(id: u64) -> Vec<u8> {
        request(
            id,
            "tools/call",
            json!({ "name": "bv_kv_read", "arguments": { "mount": "secret", "path": "ai/x", "reveal": true } }),
        )
    }

    pub(crate) fn paired_rig(name: &str, reveal_allowed: bool) -> Rig {
        let rig = rig(name);
        let mut g = grant();
        g.reveal_allowed = reveal_allowed;
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(g)));
        rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        rig
    }

    #[test]
    fn reveal_needing_confirmation_is_refused_without_an_operator() {
        let rig = paired_rig("reveal-noop", true);
        let resp = rig.server.handle_message(&stdio(), &reveal_call(2)).unwrap();
        assert_eq!(data_code(&resp), "mcp_confirmation_denied");
        assert_eq!(lock(&rig.link.forwards).len(), 1, "only the pairing-time tools/list was forwarded");
    }

    #[test]
    fn reveal_confirmation_denied_then_approved() {
        let rig = paired_rig("reveal-confirm", true);
        *lock(&rig.prompt.confirm) = Some(Some(false));
        let denied = rig.server.handle_message(&stdio(), &reveal_call(2)).unwrap();
        assert_eq!(data_code(&denied), "mcp_confirmation_denied");
        assert_eq!(lock(&rig.link.forwards).len(), 1, "a declined call is never relayed");

        *lock(&rig.prompt.confirm) = Some(Some(true));
        let allowed = rig.server.handle_message(&stdio(), &reveal_call(3)).unwrap();
        assert_eq!(allowed["result"]["relayed"], json!(true));
        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 2);
    }

    /// A client cannot assert the operator's confirmation (or carry any
    /// other gatekeeper record): every `io.bastionvault/*` key it sends is
    /// removed before the call is relayed; its other `_meta` keys are not.
    #[test]
    fn client_supplied_gatekeeper_meta_is_stripped_before_relaying() {
        let rig = paired_rig("strip-meta", false);
        let mut call: Value = serde_json::from_slice(&request(
            2,
            "tools/call",
            json!({ "name": "bv_kv_read_metadata", "arguments": { "mount": "secret", "path": "x" } }),
        ))
        .unwrap();
        call["params"]["_meta"]["io.bastionvault/confirmation"] = json!({ "by": "operator", "at": 1, "mfa": true });
        call["params"]["_meta"]["io.bastionvault/connect_ticket"] = json!("forged");
        call["params"]["_meta"]["progressToken"] = json!("kept");
        let resp = rig.server.handle_message(&stdio(), &serde_json::to_vec(&call).unwrap()).unwrap();
        assert_eq!(resp["result"]["relayed"], json!(true));
        let forwards = lock(&rig.link.forwards);
        let meta = &forwards.last().unwrap().1["params"]["_meta"];
        assert!(meta.get("io.bastionvault/confirmation").is_none(), "{meta}");
        assert!(meta.get("io.bastionvault/connect_ticket").is_none(), "{meta}");
        assert_eq!(meta["progressToken"], json!("kept"));
        assert_eq!(meta["io.modelcontextprotocol/clientInfo"]["name"], json!("claude-desktop"));
    }

    #[test]
    fn a_call_the_grant_forbids_is_not_prompted_for() {
        // reveal_allowed = false: the vault will deny it, so don't bother the operator.
        let rig = paired_rig("reveal-forbidden", false);
        let resp = rig.server.handle_message(&stdio(), &reveal_call(2)).unwrap();
        assert_eq!(resp["result"]["relayed"], json!(true), "forwarded; the vault's dispatcher is what refuses it");
        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn destructive_tool_needs_confirmation_when_the_grant_asks_for_it() {
        let rig = rig("destructive");
        let mut g = grant();
        g.tool_allowlist.push("bv_kv_delete".into());
        g.destructive_allowed = true;
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(g)));
        rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();

        let del = request(
            2,
            "tools/call",
            json!({ "name": "bv_kv_delete", "arguments": { "mount": "secret", "path": "x" } }),
        );
        let resp = rig.server.handle_message(&stdio(), &del).unwrap();
        assert_eq!(data_code(&resp), "mcp_confirmation_denied");
        *lock(&rig.prompt.confirm) = Some(Some(true));
        assert_eq!(rig.server.handle_message(&stdio(), &del).unwrap()["result"]["relayed"], json!(true));
    }

    #[test]
    fn a_token_the_vault_refuses_is_dropped_and_reminted() {
        let rig = paired_rig("refused", false);
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 1);
        *lock(&rig.link.refuse_next_forward) = Some(403);
        let resp = rig.server.handle_message(&stdio(), &request(2, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_token_refused");
        rig.server.handle_message(&stdio(), &request(3, "tools/list", json!({}))).unwrap();
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 2, "the next message mints a fresh token");
    }

    #[test]
    fn shutdown_forgets_every_token_hands_back_only_accessors_and_refuses_from_then_on() {
        let rig = paired_rig("shutdown", false);
        let accessors = rig.server.shutdown();
        assert_eq!(accessors, vec![hash_token(MINTED)], "the vault accessor of the one minted token");
        assert!(accessors.iter().all(|a| !a.contains(MINTED)));
        assert!(rig.server.is_shut_down());

        let forwards_before = lock(&rig.link.forwards).len();
        let resp = rig.server.handle_message(&stdio(), &request(2, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_server_stopped");
        let mut session = SessionState::default();
        let init = rig.server.handle_session_message(&stdio(), &mut session, &initialize(3, "2025-11-25")).unwrap();
        assert_eq!(data_code(&init), "mcp_server_stopped");
        assert_eq!(lock(&rig.link.forwards).len(), forwards_before, "nothing reaches the vault after shutdown");
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 1, "and nothing is minted");
        assert!(rig.server.shutdown().is_empty(), "a second shutdown has nothing left to hand back");
    }

    #[test]
    fn shutdown_does_not_wait_for_a_mint_in_flight_and_that_mint_is_not_kept() {
        use std::sync::mpsc;

        /// Holds every exchange until told to answer.
        struct SlowLink {
            entered: Mutex<mpsc::Sender<()>>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl VaultLink for SlowLink {
            fn exchange_pairing(&self, _record: &PairingRecord, ttl: u64) -> Result<MintedToken, String> {
                lock(&self.entered).send(()).ok();
                lock(&self.release).recv().ok();
                Ok(MintedToken { token: MINTED.to_string(), expires_at: now_secs() + ttl })
            }
            fn forward(&self, _token: &str, _message: &Value) -> Result<Value, ForwardError> {
                panic!("a call refused at shutdown must never be forwarded");
            }
        }

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let dir = std::env::temp_dir().join(format!("bv-mcp-local-inflight-{}", new_pairing_id()));
        let prompt = Arc::new(Scripted::default());
        *lock(&prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
        let server = Arc::new(LocalServer::new(
            Box::new(SlowLink { entered: Mutex::new(entered_tx), release: Mutex::new(release_rx) }),
            Box::new(prompt),
            PairingStore::at(dir.join("p.json")),
        ));

        let calling = server.clone();
        let call = std::thread::spawn(move || calling.handle_message(&stdio(), &request(1, "tools/list", json!({}))));
        entered_rx.recv().unwrap();
        // The vault has not answered; shutdown must not wait for it.
        assert!(server.shutdown().is_empty());
        release_tx.send(()).unwrap();
        let resp = call.join().unwrap().unwrap();
        assert_eq!(data_code(&resp), "mcp_server_stopped");
        assert!(server.shutdown().is_empty(), "the late token was wiped, not cached past the drain");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_approval_that_lands_after_shutdown_is_refused() {
        struct ShutsDownWhileAsking(std::sync::OnceLock<Arc<LocalServer>>);
        impl Prompter for Arc<ShutsDownWhileAsking> {
            fn approve(&self, _: &PairingRequest<'_>) -> Option<PairingDecision> {
                self.0.get().unwrap().shutdown();
                Some(PairingDecision::Approved(grant()))
            }
            fn confirm(&self, _: &ConfirmRequest<'_>) -> Option<bool> {
                Some(true)
            }
        }
        let dir = std::env::temp_dir().join(format!("bv-mcp-local-late-{}", new_pairing_id()));
        let prompter = Arc::new(ShutsDownWhileAsking(std::sync::OnceLock::new()));
        let link = Arc::new(FakeLink::default());
        let server = Arc::new(LocalServer::new(
            Box::new(link.clone()),
            Box::new(prompter.clone()),
            PairingStore::at(dir.join("p.json")),
        ));
        prompter.0.set(server.clone()).ok();
        let resp = server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_server_stopped");
        assert_eq!(link.exchanges.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(dir).ok();
    }

    // ── brokered sessions (features/mcp-brokered-sessions.md §3.1, §9) ────

    const SSH: &str = "bv_resource_ssh_exec";

    fn ssh_args(command: &str) -> Value {
        json!({ "resource": "web-01", "profile": "p_agent", "command": command })
    }

    fn ssh_call(id: u64, arguments: Value) -> Vec<u8> {
        request(id, "tools/call", json!({ "name": SSH, "arguments": arguments }))
    }

    /// A client paired for `bv_resource_ssh_exec` on `web-01`, with
    /// brokered sessions allowed.
    fn session_rig(name: &str) -> Rig {
        let rig = rig(name);
        let mut g = grant();
        g.tool_allowlist.push(SSH.into());
        g.path_scope = vec!["resources/secrets/web-01/".into()];
        g.connect_allowed = true;
        g.confirm_connect = true;
        *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(g)));
        rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        rig
    }

    fn last_meta(rig: &Rig) -> Value {
        lock(&rig.link.forwards).last().unwrap().1["params"]["_meta"].clone()
    }

    fn session_forwards(rig: &Rig) -> usize {
        lock(&rig.link.forwards).iter().filter(|(_, m)| m["method"] == json!("tools/call")).count()
    }

    /// Every session call is shown with its exact command; an approval
    /// relays the call with this gatekeeper's confirmation and nothing else.
    #[test]
    fn a_session_call_is_always_confirmed_and_the_approval_is_asserted() {
        let rig = session_rig("session-confirm");
        *lock(&rig.prompt.confirm) = Some(Some(true));
        let command = "journalctl -u nginx --since -1h | tail -n 200\nuptime";
        for id in [2, 3] {
            let resp = rig.server.handle_message(&stdio(), &ssh_call(id, ssh_args(command))).unwrap();
            assert_eq!(resp["result"]["relayed"], json!(true), "{resp}");
        }
        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 2, "no call skips the operator");
        let shown = lock(&rig.prompt.shown).clone();
        assert_eq!(shown[0].tool, SSH);
        assert!(shown[0].open_world);
        assert_eq!(shown[0].command.as_deref(), Some(command), "the dialog's command is the bytes relayed");
        let detail = shown[0].detail.clone().unwrap();
        assert!(detail.contains("Resource:  web-01") && detail.contains("Profile:   p_agent"), "{detail}");
        assert!(detail.contains("Protocol:  ssh") && detail.contains("  | uptime"), "{detail}");
        assert!(shown[0].mfa_methods.is_none(), "an ungated profile asks for no factor");

        let meta = last_meta(&rig);
        assert_eq!(meta[OPERATOR_CONFIRMATION_META_KEY]["by"], json!("operator"));
        assert_eq!(meta[OPERATOR_CONFIRMATION_META_KEY]["mfa"], json!(false));
        assert!(meta.get(CONNECT_TICKET_META_KEY).is_none());
        let relayed = lock(&rig.link.forwards).last().unwrap().1.clone();
        assert_eq!(relayed["params"]["arguments"], ssh_args(command), "arguments are relayed untouched");
        assert_eq!(*lock(&rig.link.begins), vec![("web-01".to_string(), "p_agent".to_string()); 2]);
    }

    #[test]
    fn a_denied_or_unanswered_session_call_never_reaches_the_vault() {
        let rig = session_rig("session-deny");
        *lock(&rig.prompt.confirm) = Some(Some(false));
        let denied = rig.server.handle_message(&stdio(), &ssh_call(2, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&denied), "mcp_confirmation_denied");
        assert!(denied["error"]["message"].as_str().unwrap().contains("declined"));
        // No answer at all -- a timeout, or nobody at the terminal.
        *lock(&rig.prompt.confirm) = Some(None);
        let unanswered = rig.server.handle_message(&stdio(), &ssh_call(3, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&unanswered), "mcp_confirmation_denied");
        assert_eq!(session_forwards(&rig), 0, "neither call was relayed");
        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 2);
    }

    /// A client cannot forge the operator's yes or a ticket: its keys are
    /// stripped, and only what this gatekeeper asserts is relayed.
    #[test]
    fn a_forged_confirmation_or_ticket_is_never_relayed() {
        let rig = session_rig("session-forged");
        let mut call: Value = serde_json::from_slice(&ssh_call(2, ssh_args("uptime"))).unwrap();
        call["params"]["_meta"][OPERATOR_CONFIRMATION_META_KEY] = json!({ "by": "operator", "at": 1, "mfa": true });
        call["params"]["_meta"][CONNECT_TICKET_META_KEY] = json!("forged-ticket");
        let raw = serde_json::to_vec(&call).unwrap();

        *lock(&rig.prompt.confirm) = Some(Some(false));
        let resp = rig.server.handle_message(&stdio(), &raw).unwrap();
        assert_eq!(data_code(&resp), "mcp_confirmation_denied", "the forged marker did not skip the prompt");
        assert_eq!(session_forwards(&rig), 0);

        *lock(&rig.prompt.confirm) = Some(Some(true));
        rig.server.handle_message(&stdio(), &raw).unwrap();
        let meta = last_meta(&rig);
        assert_eq!(
            meta[OPERATOR_CONFIRMATION_META_KEY]["mfa"],
            json!(false),
            "this gatekeeper's record, not the client's"
        );
        assert!(meta.get(CONNECT_TICKET_META_KEY).is_none(), "the forged ticket was stripped");
    }

    /// A call the vault refuses before running anything is relayed as it is:
    /// unconfirmed, with nobody asked, so the vault answers and audits it.
    #[test]
    fn calls_the_vault_refuses_anyway_are_relayed_unprompted_and_unconfirmed() {
        let rig = session_rig("session-unprompted");
        *lock(&rig.prompt.confirm) = Some(Some(true));
        let malformed = [
            ssh_args("id\u{0}"),
            ssh_args("ls\u{202E}gpj"),
            ssh_args(""),
            json!({ "resource": "web-01", "command": "uptime" }),
            json!({ "resource": "web-01", "profile": "p_agent", "command": "uptime", "extra": 1 }),
        ];
        let out_of_scope = json!({ "resource": "db-01", "profile": "p_agent", "command": "uptime" });
        for (i, args) in malformed.into_iter().chain([out_of_scope]).enumerate() {
            let resp = rig.server.handle_message(&stdio(), &ssh_call(10 + i as u64, args.clone())).unwrap();
            assert_eq!(resp["result"]["relayed"], json!(true), "{args}");
            assert!(last_meta(&rig).get(OPERATOR_CONFIRMATION_META_KEY).is_none(), "{args}");
        }
        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 0, "nobody was asked about any of them");
        assert!(lock(&rig.link.begins).is_empty());

        // A pairing without brokered sessions is not asked either.
        let plain = paired_rig("session-not-allowed", false);
        let resp = plain.server.handle_message(&stdio(), &ssh_call(2, ssh_args("uptime"))).unwrap();
        assert_eq!(resp["result"]["relayed"], json!(true));
        assert_eq!(plain.prompt.confirms_asked.load(Ordering::SeqCst), 0);
        assert!(last_meta(&plain).get(OPERATOR_CONFIRMATION_META_KEY).is_none());
    }

    /// A record on disk claiming `confirm_connect: false` changes nothing.
    #[test]
    fn a_record_cannot_turn_session_confirmation_off() {
        let rig = session_rig("session-record");
        let mut records = rig.server.store().load().unwrap();
        records[0].confirm_connect = false;
        rig.server.store().upsert(records[0].clone()).unwrap();
        *lock(&rig.prompt.confirm) = Some(None);
        let resp = rig.server.handle_message(&stdio(), &ssh_call(2, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&resp), "mcp_confirmation_denied");
        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 1);
    }

    fn gated(methods: &[&str]) -> Option<Result<MfaPreflight, MfaBeginError>> {
        Some(Ok(MfaPreflight::Required(MfaChallenge {
            methods: methods.iter().map(|m| m.to_string()).collect(),
            fido2: None,
        })))
    }

    /// A gated profile: the operator completes MFA in the same prompt, the
    /// ticket is bound to this pairing, tool and argument hash, and it rides
    /// only in the relayed `_meta`.
    #[test]
    fn an_mfa_gated_call_relays_a_ticket_bound_to_the_call() {
        let rig = session_rig("session-mfa");
        *lock(&rig.link.begin) = gated(&["fido2", "totp"]);
        *lock(&rig.prompt.confirm) = Some(Some(true));
        *lock(&rig.prompt.totp) = Some("123456".into());
        let args = ssh_args("systemctl status nginx");
        let resp = rig.server.handle_message(&stdio(), &ssh_call(2, args.clone())).unwrap();
        assert_eq!(resp["result"]["relayed"], json!(true), "{resp}");

        let shown = lock(&rig.prompt.shown).clone();
        assert_eq!(shown[0].mfa_methods, Some(vec!["fido2".to_string(), "totp".to_string()]));
        assert_eq!(shown[0].verified, Some(Ok(())));
        let verifies = lock(&rig.link.verifies).clone();
        assert_eq!(verifies.len(), 1);
        let (resource, profile, method, code, call) = &verifies[0];
        assert_eq!(
            (resource.as_str(), profile.as_str(), method.as_str(), code.as_str()),
            ("web-01", "p_agent", "totp", "123456")
        );
        let pairing_id = rig.server.store().load().unwrap()[0].id.clone();
        assert_eq!(call.pairing_id, pairing_id);
        assert_eq!(call.tool, SSH);
        assert_eq!(call.args_hash, dispatcher::args_hash(args.as_object().unwrap()));

        let meta = last_meta(&rig);
        assert_eq!(meta[OPERATOR_CONFIRMATION_META_KEY]["mfa"], json!(true));
        assert_eq!(meta[CONNECT_TICKET_META_KEY], json!(TICKET));
        let relayed = lock(&rig.link.forwards).last().unwrap().1.clone();
        assert!(!relayed["params"]["arguments"].to_string().contains(TICKET), "never in the hashed arguments");
        // The relayed copy is wiped once the relay is done with it.
        let mut forwarded = relayed.clone();
        wipe_relayed_ticket(&mut forwarded);
        assert_eq!(forwarded["params"]["_meta"][CONNECT_TICKET_META_KEY], json!(""));
        // Nothing the client gets back carries it.
        assert!(!resp.to_string().contains(TICKET));
    }

    #[test]
    fn a_failed_or_skipped_factor_denies_the_call() {
        let rig = session_rig("session-mfa-fail");
        *lock(&rig.link.begin) = gated(&["totp"]);
        *lock(&rig.prompt.confirm) = Some(Some(true));
        *lock(&rig.prompt.totp) = Some("000000".into());
        *lock(&rig.link.verify) = Some(Err("vault answered HTTP 403: invalid TOTP code".into()));
        let resp = rig.server.handle_message(&stdio(), &ssh_call(2, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&resp), "mcp_confirmation_denied");
        assert_eq!(session_forwards(&rig), 0);

        // A prompter that says yes without completing MFA gets no ticket.
        *lock(&rig.prompt.totp) = None;
        *lock(&rig.link.verify) = None;
        let resp = rig.server.handle_message(&stdio(), &ssh_call(3, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&resp), "mcp_confirmation_denied");
        assert!(resp["error"]["message"].as_str().unwrap().contains("MFA"));
        assert_eq!(session_forwards(&rig), 0);
    }

    /// An operator who cannot complete MFA here is refused before anyone
    /// is asked: not a userpass user, no factor, or only factors this
    /// channel cannot collect.
    #[test]
    fn mfa_the_operator_cannot_complete_is_refused_before_any_prompt() {
        let rig = session_rig("session-mfa-unavailable");
        *lock(&rig.prompt.confirm) = Some(Some(true));
        *lock(&rig.link.begin) = Some(Err(MfaBeginError::Unavailable(
            "vault answered HTTP 403: mfa_unavailable: only userpass principals".into(),
        )));
        let resp = rig.server.handle_message(&stdio(), &ssh_call(2, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&resp), "mcp_session_mfa_unavailable");

        *lock(&rig.link.begin) = gated(&["fido2"]);
        let resp = rig.server.handle_message(&stdio(), &ssh_call(3, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&resp), "mcp_session_mfa_unavailable", "a security key this channel cannot use");

        *lock(&rig.link.begin) = Some(Err(MfaBeginError::Other("could not reach the vault".into())));
        let resp = rig.server.handle_message(&stdio(), &ssh_call(4, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&resp), "mcp_session_mfa_check_failed");

        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 0);
        assert_eq!(session_forwards(&rig), 0);
    }

    /// The default `VaultLink` cannot ask about MFA, and the default
    /// `Prompter` collects no factor: a host that built neither refuses.
    #[test]
    fn a_host_without_the_mfa_step_fails_closed() {
        struct Minimal(Arc<FakeLink>);
        impl VaultLink for Minimal {
            fn exchange_pairing(&self, r: &PairingRecord, ttl: u64) -> Result<MintedToken, String> {
                self.0.exchange_pairing(r, ttl)
            }
            fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError> {
                self.0.forward(token, message)
            }
        }
        let dir = std::env::temp_dir().join(format!("bv-mcp-local-minimal-{}", new_pairing_id()));
        let prompt = Arc::new(Scripted::default());
        let mut g = grant();
        g.tool_allowlist = vec![SSH.into()];
        g.path_scope = vec!["resources/secrets/web-01/".into()];
        g.connect_allowed = true;
        *lock(&prompt.approve) = Some(Some(PairingDecision::Approved(g)));
        *lock(&prompt.confirm) = Some(Some(true));
        let link = Arc::new(FakeLink::default());
        let server = LocalServer::new(
            Box::new(Minimal(link.clone())),
            Box::new(prompt.clone()),
            PairingStore::at(dir.join("p.json")),
        );
        let resp = server.handle_message(&stdio(), &ssh_call(1, ssh_args("uptime"))).unwrap();
        assert_eq!(data_code(&resp), "mcp_session_mfa_check_failed");
        assert_eq!(prompt.confirms_asked.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(dir).ok();
    }

    /// A reveal or write the operator confirmed is asserted too, so the
    /// vault's audit says who approved it.
    #[test]
    fn a_confirmed_reveal_is_asserted_to_the_vault() {
        let rig = paired_rig("reveal-asserted", true);
        *lock(&rig.prompt.confirm) = Some(Some(true));
        rig.server.handle_message(&stdio(), &reveal_call(2)).unwrap();
        let meta = last_meta(&rig);
        assert_eq!(meta[OPERATOR_CONFIRMATION_META_KEY]["by"], json!("operator"));
        assert!(meta.get(CONNECT_TICKET_META_KEY).is_none());
        // An unconfirmed call carries no record.
        rig.server.handle_message(&stdio(), &request(3, "tools/list", json!({}))).unwrap();
        assert!(last_meta(&rig).get(OPERATOR_CONFIRMATION_META_KEY).is_none());
    }

    #[test]
    fn exchange_ttl_never_outlives_the_pairing() {
        let mut record = PairingRecord {
            version: 1,
            id: "x".into(),
            client_name: "c".into(),
            client_version: "".into(),
            peer_uid: None,
            transport: "stdio".into(),
            pairing_token_hash: None,
            tool_allowlist: vec![],
            path_scope: vec![],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            connect_allowed: false,
            confirm_connect: false,
            ttl_secs: 8 * 3600,
            approved_at: 0,
            expires_at: Some(1_000 + 600),
            last_used_at: 0,
        };
        assert_eq!(exchange_ttl(&record, 1_000), 600);
        record.expires_at = None;
        assert_eq!(exchange_ttl(&record, 1_000), 8 * 3600);
        record.ttl_secs = 10 * 24 * 3600;
        assert_eq!(exchange_ttl(&record, 1_000), MAX_TOKEN_TTL_SECS);
    }

    #[test]
    fn line_session_frames_messages_and_caps_size() {
        let rig = paired_rig("lines", false);
        let input = [
            String::from_utf8(request(10, "tools/list", json!({}))).unwrap(),
            String::new(),
            String::from_utf8(request(11, "tools/list", json!({}))).unwrap(),
        ]
        .join("\n");
        let mut out = Vec::new();
        run_line_session(&rig.server, &stdio(), std::io::Cursor::new(input.into_bytes()), &mut out).unwrap();
        let replies: Vec<Value> =
            out.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[1]["id"], json!(11));

        let huge = vec![b'a'; (MAX_MESSAGE_BYTES + 10) as usize];
        let mut out = Vec::new();
        run_line_session(&rig.server, &stdio(), std::io::Cursor::new(huge), &mut out).unwrap();
        let reply: Value = serde_json::from_slice(out.trim_ascii()).unwrap();
        assert_eq!(data_code(&reply), "mcp_message_too_large");
    }

    #[test]
    fn connection_slots_are_bounded_and_released() {
        let counter = Arc::new(AtomicUsize::new(0));
        let slots: Vec<_> =
            (0..MAX_CONCURRENT_CONNECTIONS).map(|_| ConnectionSlot::acquire(&counter).unwrap()).collect();
        assert!(ConnectionSlot::acquire(&counter).is_none());
        drop(slots);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(ConnectionSlot::acquire(&counter).is_some());
    }
}
