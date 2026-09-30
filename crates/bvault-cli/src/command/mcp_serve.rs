//! `bvault mcp serve` -- the local MCP server (`features/mcp-access.md` §3, §11).
//!
//! It is a *gatekeeper and proxy*, not a second dispatcher. A local client
//! (Claude Desktop, an IDE...) speaks MCP to it over stdio, a Unix socket or
//! loopback HTTP; for each request it (1) works out which client this is and
//! whether the operator approved it, (2) mints an MCP-bound token for that
//! pairing from the operator's own session, and (3) forwards the JSON-RPC
//! message unchanged to the vault's `POST /v2/mcp`, relaying the answer. The
//! vault's dispatcher therefore remains the single place tool gates, path
//! scope, ACL and audit are enforced -- this process adds only what the vault
//! cannot know: who is on the other end of *this machine's* socket, and
//! whether a human said yes.
//!
//! Fail-closed everywhere: no controlling terminal means no pairing and no
//! per-call confirmation, never a silent approval. The minted token lives in
//! this process's memory for the pairing's TTL and is never written out.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

use bv_mcp::{
    catalogue,
    jsonrpc::{JsonRpcError, JsonRpcResponse},
    sanitize::sanitize_for_model,
};
use serde_json::{json, Map, Value};

use bv_mcp::pairing::{
    self, find_by_token_hash, find_matching, hash_token, new_pairing_id, new_pairing_token, now_secs,
    PairingRecord, PairingStore, Transport, DEFAULT_PAIRING_LIFETIME_SECS, DEFAULT_TOKEN_TTL_SECS,
    MAX_TOKEN_TTL_SECS,
};
use crate::{api::Client, bv_error_string, errors::RvError};

/// Same ceiling the vault's own `/v2/mcp` applies to a request body.
pub const MAX_MESSAGE_BYTES: u64 = 256 * 1024;
const MAX_HEAD_BYTES: usize = 16 * 1024;
const MAX_CLIENT_NAME_LEN: usize = 128;
const MAX_CONCURRENT_CONNECTIONS: usize = 32;
/// Re-mint a token this close to expiry rather than forwarding with one the
/// vault is about to refuse.
const TOKEN_REFRESH_MARGIN_SECS: u64 = 30;
pub const HTTP_PATH: &str = "/mcp";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ── vault side ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MintedToken {
    pub token: String,
    pub expires_at: u64,
}

#[derive(Debug)]
pub enum ForwardError {
    /// The vault answered 401/403: the token was revoked, expired or refused.
    Refused(u16),
    Other(String),
}

/// What the local server needs from the vault. A trait so the gatekeeping
/// logic is testable without a server.
pub trait VaultLink: Send + Sync {
    fn exchange_pairing(&self, record: &PairingRecord, ttl_secs: u64) -> Result<MintedToken, String>;
    fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError>;
}

pub struct HttpVaultLink {
    client: Client,
}

impl HttpVaultLink {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

pub(super) fn vault_error_text(body: &Option<Value>, status: u16) -> String {
    let detail = body
        .as_ref()
        .and_then(|b| b.get("errors").and_then(Value::as_array).and_then(|e| e.first()).and_then(Value::as_str))
        .or_else(|| body.as_ref().and_then(|b| b.get("error")).and_then(Value::as_str));
    match detail {
        Some(d) => format!("vault answered HTTP {status}: {}", sanitize_for_model(d)),
        None => format!("vault answered HTTP {status}"),
    }
}

/// `DELETE <address>/<path>` returning only the HTTP status. For endpoints
/// whose success answer is an empty body: `api::Client::request` parses JSON
/// unconditionally and would report that success as an error.
pub(super) fn delete_status(client: &Client, path: &str) -> Result<u16, String> {
    let request = http::Request::builder()
        .method("DELETE")
        .uri(format!("{}/{}", client.address.trim_end_matches('/'), path))
        .header("Accept", "application/json")
        .header("X-BastionVault-Token", &client.token)
        .body(())
        .map_err(|e| format!("could not build the request: {e}"))?;
    client.http_client.run(request).map(|r| r.status().as_u16()).map_err(|e| e.to_string())
}

impl VaultLink for HttpVaultLink {
    fn exchange_pairing(&self, record: &PairingRecord, ttl_secs: u64) -> Result<MintedToken, String> {
        let mut body = Map::new();
        body.insert(
            "pairing".into(),
            json!({
                "id": record.id,
                "client_name": record.client_name,
                "client_version": record.client_version,
                "tool_allowlist": record.tool_allowlist,
                "path_scope": record.path_scope,
                "reveal_allowed": record.reveal_allowed,
                "destructive_allowed": record.destructive_allowed,
                "ttl_secs": ttl_secs,
            }),
        );
        body.insert("catalogue_hash".into(), Value::String(catalogue::catalogue_hash()));
        body.insert("ttl_secs".into(), json!(ttl_secs));

        let resp = self
            .client
            .request_write("v2/mcp/token", Some(body))
            .map_err(|e| format!("could not reach the vault: {e}"))?;
        if resp.response_status != 200 {
            return Err(vault_error_text(&resp.response_data, resp.response_status));
        }
        let data = resp.response_data.ok_or_else(|| "vault returned an empty exchange response".to_string())?;
        let auth = data.get("auth").or_else(|| data.get("data").and_then(|d| d.get("auth"))).cloned();
        let auth = auth.ok_or_else(|| "vault exchange response carried no auth block".to_string())?;
        let token = auth
            .get("client_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| "vault exchange response carried no token".to_string())?
            .to_string();
        let lease = auth.get("lease_duration").and_then(Value::as_u64).unwrap_or(ttl_secs);
        Ok(MintedToken { token, expires_at: now_secs() + lease })
    }

    fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError> {
        let body = message
            .as_object()
            .cloned()
            .ok_or_else(|| ForwardError::Other("only JSON objects can be forwarded".to_string()))?;
        let mut client = self.client.clone();
        client.token = token.to_string();
        let resp = client
            .request_write("v2/mcp", Some(body))
            .map_err(|e| ForwardError::Other(format!("could not reach the vault: {e}")))?;
        match (resp.response_status, resp.response_data) {
            (200, Some(v)) => Ok(v),
            (s @ (401 | 403), _) => Err(ForwardError::Refused(s)),
            (s, data) => Err(ForwardError::Other(vault_error_text(&data, s))),
        }
    }
}

// ── operator side ────────────────────────────────────────────────────────

pub struct PairingRequest<'a> {
    pub client_name: &'a str,
    pub client_version: &'a str,
    pub transport: Transport,
    pub peer_uid: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingGrant {
    pub tool_allowlist: Vec<String>,
    pub path_scope: Vec<String>,
    pub reveal_allowed: bool,
    pub destructive_allowed: bool,
    pub confirm_reveal: bool,
    pub confirm_destructive: bool,
    pub ttl_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingDecision {
    Approved(PairingGrant),
    Denied,
}

pub struct ConfirmRequest<'a> {
    pub client_name: &'a str,
    pub tool: &'a str,
    pub summary: &'a str,
    pub reveals: bool,
    pub destructive: bool,
}

/// A human. `None` from either method means *no operator is reachable*, which
/// every caller treats as a refusal.
pub trait Prompter: Send + Sync {
    fn approve(&self, request: &PairingRequest<'_>) -> Option<PairingDecision>;
    fn confirm(&self, request: &ConfirmRequest<'_>) -> Option<bool>;
}

/// Prompts on the controlling terminal (`/dev/tty`), *not* stdin/stdout: in
/// stdio transport those two are the MCP channel itself, and a prompt written
/// to either would corrupt it. A process with no controlling terminal -- a
/// GUI-spawned server, cron, CI -- gets `None` and so cannot pair.
#[derive(Default)]
pub struct TtyPrompter {
    one_prompt_at_a_time: Mutex<()>,
}

struct Tty {
    reader: BufReader<File>,
    writer: File,
}

impl Tty {
    fn open() -> Option<Tty> {
        #[cfg(unix)]
        let (input, output) = ("/dev/tty", "/dev/tty");
        #[cfg(not(unix))]
        let (input, output) = ("CONIN$", "CONOUT$");
        let reader = File::open(input).ok()?;
        let writer = OpenOptions::new().write(true).open(output).ok()?;
        Some(Tty { reader: BufReader::new(reader), writer })
    }

    fn say(&mut self, text: &str) {
        let _ = writeln!(self.writer, "{text}");
    }

    /// `None` on EOF or a read error -- the operator went away.
    fn ask(&mut self, prompt: &str) -> Option<String> {
        let _ = write!(self.writer, "{prompt}");
        let _ = self.writer.flush();
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim().to_string()),
        }
    }

    fn yes_no(&mut self, prompt: &str, default_yes: bool) -> Option<bool> {
        let answer = self.ask(&format!("{prompt} [{}] ", if default_yes { "Y/n" } else { "y/N" }))?;
        Some(match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => true,
            "n" | "no" => false,
            _ => default_yes,
        })
    }
}

fn split_list(input: &str) -> Vec<String> {
    input.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

impl Prompter for TtyPrompter {
    fn approve(&self, request: &PairingRequest<'_>) -> Option<PairingDecision> {
        let _one = lock(&self.one_prompt_at_a_time);
        let mut tty = Tty::open()?;
        tty.say("");
        tty.say("A local MCP client is asking for access to your vault.");
        tty.say(&format!("  Client:     {} {}", sanitize_for_model(request.client_name), sanitize_for_model(request.client_version)));
        tty.say(&format!("  Transport:  {}", request.transport.as_str()));
        if let Some(uid) = request.peer_uid {
            tty.say(&format!("  Peer uid:   {uid}"));
        }
        tty.say("  It will act with YOUR permissions, narrowed to the scope you choose below.");
        tty.say("");
        if !tty.yes_no("Approve this client?", false)? {
            return Some(PairingDecision::Denied);
        }

        let path_scope = split_list(&tty.ask("Path scope, comma-separated (e.g. secret/metadata/ai/*; empty denies every path): ")?);
        if path_scope.is_empty() {
            tty.say("  No path scope: every tool call will be refused until you re-pair with one.");
        }

        let defaults = pairing::default_tool_allowlist();
        tty.say(&format!("Default tools (read-only, never reveal a value): {}", defaults.join(", ")));
        let tools_in = tty.ask("Tools, comma-separated (Enter for the default list): ")?;
        let tool_allowlist = if tools_in.is_empty() { defaults } else { split_list(&tools_in) };
        if let Some(unknown) = tool_allowlist.iter().find(|t| catalogue::find(t).is_none()) {
            tty.say(&format!("  `{}` is not a tool in this build's catalogue; denying the pairing.", sanitize_for_model(unknown)));
            return Some(PairingDecision::Denied);
        }

        let reveal_allowed = tty.yes_no("Allow revealing secret values?", false)?;
        let confirm_reveal = reveal_allowed && tty.yes_no("  Ask you to confirm each reveal?", true)?;
        let destructive_allowed = tty.yes_no("Allow destructive tools (write, delete, issue, sign)?", false)?;
        let confirm_destructive = destructive_allowed && tty.yes_no("  Ask you to confirm each one?", true)?;

        let hours = tty.ask(&format!("Token lifetime in hours [{}]: ", DEFAULT_TOKEN_TTL_SECS / 3600))?;
        let ttl_secs = if hours.is_empty() {
            DEFAULT_TOKEN_TTL_SECS
        } else {
            match hours.parse::<u64>() {
                Ok(h) if h >= 1 => (h * 3600).min(MAX_TOKEN_TTL_SECS),
                _ => {
                    tty.say("  Not a whole number of hours; denying the pairing.");
                    return Some(PairingDecision::Denied);
                }
            }
        };

        Some(PairingDecision::Approved(PairingGrant {
            tool_allowlist,
            path_scope,
            reveal_allowed,
            destructive_allowed,
            confirm_reveal,
            confirm_destructive,
            ttl_secs,
        }))
    }

    fn confirm(&self, request: &ConfirmRequest<'_>) -> Option<bool> {
        let _one = lock(&self.one_prompt_at_a_time);
        let mut tty = Tty::open()?;
        tty.say("");
        let what = match (request.reveals, request.destructive) {
            (true, true) => "reveal a secret value AND make a change",
            (true, false) => "reveal a secret value",
            _ => "make a change",
        };
        tty.say(&format!("MCP client `{}` wants to {what}:", sanitize_for_model(request.client_name)));
        tty.say(&format!("  {}  {}", sanitize_for_model(request.tool), sanitize_for_model(request.summary)));
        // Default deny: anything but an explicit yes refuses the call.
        tty.yes_no("Allow this one call?", false)
    }
}

/// Builds the record for an approved pairing. Returns the loopback-HTTP
/// bearer too, which exists only here: the record stores its hash.
pub fn build_record(request: &PairingRequest<'_>, grant: &PairingGrant, now: u64) -> (PairingRecord, Option<String>) {
    let token = (request.transport == Transport::LoopbackHttp).then(new_pairing_token);
    let record = PairingRecord {
        version: 1,
        id: new_pairing_id(),
        client_name: request.client_name.to_string(),
        client_version: request.client_version.to_string(),
        peer_uid: request.peer_uid,
        transport: request.transport.as_str().to_string(),
        pairing_token_hash: token.as_deref().map(hash_token),
        tool_allowlist: grant.tool_allowlist.clone(),
        path_scope: grant.path_scope.clone(),
        reveal_allowed: grant.reveal_allowed,
        destructive_allowed: grant.destructive_allowed,
        confirm_reveal: grant.confirm_reveal,
        confirm_destructive: grant.confirm_destructive,
        ttl_secs: grant.ttl_secs,
        approved_at: now,
        expires_at: Some(now + DEFAULT_PAIRING_LIFETIME_SECS),
        last_used_at: now,
    };
    (record, token)
}

// ── the gatekeeper ───────────────────────────────────────────────────────

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
    tokens: Mutex<HashMap<String, MintedToken>>,
    clock: fn() -> u64,
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

    fn into_response(self, id: Value) -> Value {
        rpc_error(id, self.code, &self.message, self.data_code)
    }
}

fn rpc_error(id: Value, code: i64, message: &str, data_code: &str) -> Value {
    serde_json::to_value(JsonRpcResponse::failure(id, JsonRpcError::with_data_code(code, message, data_code)))
        .unwrap_or(Value::Null)
}

fn client_info(message: &Map<String, Value>) -> Option<(String, String)> {
    let info = message.get("params")?.get("_meta")?.get("io.modelcontextprotocol/clientInfo")?;
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
            tokens: Mutex::new(HashMap::new()),
            clock,
        }
    }

    pub fn store(&self) -> &PairingStore {
        &self.store
    }

    /// One JSON-RPC message in, at most one out. `None` for a notification
    /// (no `id`): there is nothing to answer and, since the vault's endpoint
    /// only takes requests, nothing to forward.
    pub fn handle_message(&self, conn: &ConnInfo, raw: &[u8]) -> Option<Value> {
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
        if object.get("method").and_then(Value::as_str).is_none() {
            return Some(rpc_error(id, -32600, "missing method", "mcp_invalid_request"));
        }

        let record = match self.resolve_pairing(conn, object) {
            Ok(r) => r,
            Err(refusal) => return Some(refusal.into_response(id)),
        };
        if let Err(refusal) = self.confirm_if_needed(&record, object) {
            return Some(refusal.into_response(id));
        }
        let token = match self.token_for(&record) {
            Ok(t) => t,
            Err(refusal) => return Some(refusal.into_response(id)),
        };

        match self.link.forward(&token, &message) {
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

    fn resolve_pairing(&self, conn: &ConnInfo, message: &Map<String, Value>) -> Result<PairingRecord, Refusal> {
        if let Some(record) = &conn.preauthenticated {
            return Ok(record.clone());
        }
        let Some((client_name, client_version)) = client_info(message) else {
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
        match self.prompter.approve(&request) {
            None => Err(Refusal::new(
                -32001,
                "mcp_pairing_requires_operator",
                "this client is not paired and no terminal is available to approve it; run `bvault mcp pair` interactively first",
            )),
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

    /// Per-call operator confirmation for reveal/destructive calls the grant
    /// allows and asked to confirm. A call the grant would refuse anyway is
    /// forwarded without a prompt (the vault will deny it); a call needing a
    /// confirmation nobody can give is refused.
    fn confirm_if_needed(&self, record: &PairingRecord, message: &Map<String, Value>) -> Result<(), Refusal> {
        if message.get("method").and_then(Value::as_str) != Some("tools/call") {
            return Ok(());
        }
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let Some(tool) = params.get("name").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(meta) = catalogue::find(tool) else {
            return Ok(());
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        let reveal_requested = arguments.get("reveal").and_then(Value::as_bool).unwrap_or(false);

        let reveals = meta.is_reveal && reveal_requested;
        let destructive = meta.destructive;
        if (reveals && !record.reveal_allowed) || (destructive && !record.destructive_allowed) {
            return Ok(());
        }
        let needs = (reveals && record.confirm_reveal) || (destructive && record.confirm_destructive);
        if !needs {
            return Ok(());
        }

        let summary = call_summary(&arguments);
        let request = ConfirmRequest {
            client_name: &record.client_name,
            tool,
            summary: &summary,
            reveals,
            destructive,
        };
        match self.prompter.confirm(&request) {
            Some(true) => Ok(()),
            Some(false) => {
                Err(Refusal::new(-32001, "mcp_confirmation_denied", "the operator declined this call"))
            }
            None => Err(Refusal::new(
                -32001,
                "mcp_confirmation_denied",
                "this call needs operator confirmation and no terminal is available to give it",
            )),
        }
    }

    fn token_for(&self, record: &PairingRecord) -> Result<String, Refusal> {
        let now = (self.clock)();
        let mut tokens = lock(&self.tokens);
        if let Some(t) = tokens.get(&record.id) {
            if t.expires_at > now + TOKEN_REFRESH_MARGIN_SECS {
                return Ok(t.token.clone());
            }
        }
        let ttl = exchange_ttl(record, now);
        let minted = self
            .link
            .exchange_pairing(record, ttl)
            .map_err(|e| Refusal::new(-32603, "mcp_exchange_failed", format!("could not mint an MCP token: {e}")))?;
        let token = minted.token.clone();
        tokens.insert(record.id.clone(), minted);
        drop(tokens);
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

// ── transports ───────────────────────────────────────────────────────────

/// Newline-delimited JSON-RPC, the stdio framing. Shared by stdio and the
/// Unix-socket transport.
pub fn run_line_session<R: BufRead, W: Write>(
    server: &LocalServer,
    conn: &ConnInfo,
    mut reader: R,
    mut writer: W,
) -> std::io::Result<()> {
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
        if let Some(response) = server.handle_message(conn, trimmed) {
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
}

pub fn serve_stdio(server: &LocalServer) -> Result<(), RvError> {
    let conn = ConnInfo { transport: Transport::Stdio, peer_uid: None, preauthenticated: None };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_line_session(server, &conn, stdin.lock(), stdout.lock())
        .map_err(|e| bv_error_string!(format!("stdio session ended: {e}")))
}

struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
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

/// Loopback only, by construction: there is no flag to widen this.
pub fn parse_loopback_addr(input: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = input
        .parse()
        .map_err(|_| format!("`{input}` is not an IP:port address (e.g. 127.0.0.1:8250)"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "`{input}` is not a loopback address: the local MCP server only ever binds 127.0.0.1 or [::1]"
        ));
    }
    Ok(addr)
}

#[cfg(unix)]
pub mod uds {
    use std::{
        fs,
        os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        path::Path,
    };

    use super::*;

    /// The uid on the far end of a connected Unix socket, from the kernel.
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
        use std::os::unix::io::AsRawFd;
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `fd` is a live socket owned by `stream`; `uid`/`gid` are
        // valid out-pointers for the duration of the call.
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        (rc == 0).then_some(uid)
    }

    #[cfg(target_os = "linux")]
    pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
        use std::os::unix::io::AsRawFd;
        // SAFETY: zeroed `ucred` is a valid plain-data value; `getsockopt`
        // writes at most `len` bytes into it.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        (rc == 0).then_some(cred.uid)
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "linux"
    )))]
    pub fn peer_uid(_stream: &UnixStream) -> Option<u32> {
        // No way to prove who is connecting: nobody is admitted.
        None
    }

    pub fn current_uid() -> u32 {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// The pre-read gate. A peer whose uid the kernel cannot confirm equals
    /// `expected` is dropped before a single byte is read from it.
    pub fn peer_is(stream: &UnixStream, expected: u32) -> Option<u32> {
        peer_uid(stream).filter(|uid| *uid == expected)
    }

    pub fn serve_connection(server: &LocalServer, stream: UnixStream, expected_uid: u32) {
        let Some(uid) = peer_is(&stream, expected_uid) else {
            return; // dropped: nothing was read
        };
        let conn = ConnInfo { transport: Transport::Uds, peer_uid: Some(uid), preauthenticated: None };
        let Ok(write_half) = stream.try_clone() else { return };
        let _ = run_line_session(server, &conn, BufReader::new(stream), write_half);
    }

    /// Bind a 0600 socket. A stale socket file from a dead server is
    /// replaced; a live one, or a non-socket, is an error.
    pub fn bind_private_socket(path: &Path) -> Result<UnixListener, RvError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            pairing::create_private_dir(dir)?;
        }
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {
                if UnixStream::connect(path).is_ok() {
                    return Err(bv_error_string!(format!("{} is already being served", path.display())));
                }
                fs::remove_file(path)?;
            }
            Ok(_) => {
                return Err(bv_error_string!(format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // No umask games: it is process-global, so tightening it around `bind`
        // races every other thread that creates a file or directory. The
        // socket is narrowed to 0600 immediately after binding instead. The
        // window is harmless in practice -- connecting to a Unix socket needs
        // write permission, which the default umask withholds from other
        // users; a directory we created is 0700; and every connection is
        // uid-checked before a byte is read regardless.
        let listener = UnixListener::bind(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidInput {
                // `sockaddr_un.sun_path` is ~104 bytes on macOS and 108 on
                // Linux; the OS error for overflowing it says nothing useful.
                bv_error_string!(format!(
                    "{} is too long for a Unix socket path (limit is about 100 bytes); choose a shorter --socket path",
                    path.display()
                ))
            } else {
                RvError::from(e)
            }
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    pub fn serve(server: Arc<LocalServer>, path: &Path) -> Result<(), RvError> {
        let listener = bind_private_socket(path)?;
        eprintln!("bvault mcp: serving on {} (owner-only)", path.display());
        run(server, listener, current_uid());
        Ok(())
    }

    pub fn run(server: Arc<LocalServer>, listener: UnixListener, expected_uid: u32) {
        let active = Arc::new(AtomicUsize::new(0));
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let Some(slot) = ConnectionSlot::acquire(&active) else {
                continue;
            };
            let server = server.clone();
            let _ = std::thread::Builder::new().name("mcp-uds".into()).spawn(move || {
                let _slot = slot;
                serve_connection(&server, stream, expected_uid);
            });
        }
    }
}

pub struct HttpConfig {
    pub allowed_origins: Vec<String>,
}

pub struct BoundHttp {
    pub listener: TcpListener,
    pub addr: SocketAddr,
}

pub fn bind_http(addr: SocketAddr) -> Result<BoundHttp, RvError> {
    if !addr.ip().is_loopback() {
        return Err(bv_error_string!("the local MCP server only binds loopback addresses"));
    }
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    Ok(BoundHttp { listener, addr })
}

struct HttpReply {
    status: u16,
    reason: &'static str,
    extra_headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl HttpReply {
    fn status(status: u16, reason: &'static str) -> Self {
        Self { status, reason, extra_headers: Vec::new(), body: Vec::new() }
    }

    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            reason: "OK",
            extra_headers: vec![("Content-Type", "application/json".to_string())],
            body: serde_json::to_vec(value).unwrap_or_default(),
        }
    }

    fn write_to(self, stream: &mut TcpStream) {
        let mut head = format!("HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n", self.status, self.reason, self.body.len());
        for (k, v) in &self.extra_headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&self.body);
        let _ = stream.flush();
    }
}

/// Reads the request head, bounded, and returns it with whatever body bytes
/// arrived in the same reads.
fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, usize)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some((buf, end + 4));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return None;
        }
    }
}

fn header<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Vec<&'a [u8]> {
    headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value).collect()
}

/// Everything decided *before* the vault is contacted or the body is read:
/// method, path, `Host` (DNS rebinding), `Origin` (browser tabs), then the
/// bearer. Returns the rejection to send, or the admitted bearer.
fn admit_http_request(
    req: &httparse::Request<'_, '_>,
    local_port: u16,
    config: &HttpConfig,
) -> Result<String, HttpReply> {
    if req.method != Some("POST") {
        let mut r = HttpReply::status(405, "Method Not Allowed");
        r.extra_headers.push(("Allow", "POST".to_string()));
        return Err(r);
    }
    if req.path.map(|p| p.split('?').next().unwrap_or("")) != Some(HTTP_PATH) {
        return Err(HttpReply::status(404, "Not Found"));
    }
    let headers = &*req.headers;

    let hosts = header(headers, "Host");
    let host_ok = hosts.len() == 1
        && std::str::from_utf8(hosts[0]).is_ok_and(|h| {
            let h = h.trim().to_ascii_lowercase();
            [format!("127.0.0.1:{local_port}"), format!("localhost:{local_port}"), format!("[::1]:{local_port}")]
                .contains(&h)
        });
    if !host_ok {
        return Err(HttpReply::status(403, "Forbidden"));
    }

    let origins = header(headers, "Origin");
    if origins.len() > 1 {
        return Err(HttpReply::status(403, "Forbidden"));
    }
    if let Some(origin) = origins.first() {
        let allowed = std::str::from_utf8(origin)
            .is_ok_and(|o| config.allowed_origins.iter().any(|a| a == o.trim()));
        if !allowed {
            return Err(HttpReply::status(403, "Forbidden"));
        }
    }

    let unauthorized = || {
        let mut r = HttpReply::status(401, "Unauthorized");
        r.extra_headers.push(("WWW-Authenticate", "Bearer".to_string()));
        r
    };
    let auth = header(headers, "Authorization");
    if auth.len() != 1 {
        return Err(unauthorized());
    }
    let bearer = std::str::from_utf8(auth[0])
        .ok()
        .and_then(|a| a.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());
    bearer.map(str::to_string).ok_or_else(unauthorized)
}

fn handle_http_connection(server: &LocalServer, mut stream: TcpStream, local_port: u16, config: &HttpConfig) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let Some((buf, head_len)) = read_head(&mut stream) else {
        HttpReply::status(400, "Bad Request").write_to(&mut stream);
        return;
    };

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(&buf[..head_len]), Ok(httparse::Status::Complete(_))) {
        HttpReply::status(400, "Bad Request").write_to(&mut stream);
        return;
    }

    let bearer = match admit_http_request(&req, local_port, config) {
        Ok(b) => b,
        Err(reply) => return reply.write_to(&mut stream),
    };

    // Framing: a fixed Content-Length or nothing. Chunked bodies and
    // conflicting lengths are how request smuggling starts.
    if !header(&*req.headers, "Transfer-Encoding").is_empty() {
        return HttpReply::status(501, "Not Implemented").write_to(&mut stream);
    }
    let lengths = header(&*req.headers, "Content-Length");
    if lengths.len() != 1 {
        return HttpReply::status(411, "Length Required").write_to(&mut stream);
    }
    let Some(length) = std::str::from_utf8(lengths[0]).ok().and_then(|l| l.trim().parse::<u64>().ok()) else {
        return HttpReply::status(400, "Bad Request").write_to(&mut stream);
    };
    if length > MAX_MESSAGE_BYTES {
        return HttpReply::status(413, "Payload Too Large").write_to(&mut stream);
    }

    let mut body = buf[head_len..].to_vec();
    if (body.len() as u64) > length {
        body.truncate(length as usize);
    }
    let mut remaining = length as usize - body.len();
    let mut chunk = [0u8; 4096];
    while remaining > 0 {
        let want = remaining.min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) | Err(_) => return HttpReply::status(400, "Bad Request").write_to(&mut stream),
            Ok(n) => {
                body.extend_from_slice(&chunk[..n]);
                remaining -= n;
            }
        }
    }

    // Only now does anything touch the pairing store or the vault.
    let now = (server.clock)();
    let Ok(records) = server.store.load() else {
        return HttpReply::status(500, "Internal Server Error").write_to(&mut stream);
    };
    let Some(record) = find_by_token_hash(&records, &hash_token(&bearer), now).cloned() else {
        let mut r = HttpReply::status(401, "Unauthorized");
        r.extra_headers.push(("WWW-Authenticate", "Bearer".to_string()));
        return r.write_to(&mut stream);
    };
    let conn = ConnInfo { transport: Transport::LoopbackHttp, peer_uid: None, preauthenticated: Some(record) };
    match server.handle_message(&conn, &body) {
        Some(response) => HttpReply::json(&response).write_to(&mut stream),
        None => HttpReply::status(202, "Accepted").write_to(&mut stream),
    }
}

impl BoundHttp {
    pub fn run(self, server: Arc<LocalServer>, config: HttpConfig) {
        let config = Arc::new(config);
        let port = self.addr.port();
        let active = Arc::new(AtomicUsize::new(0));
        for conn in self.listener.incoming() {
            let Ok(stream) = conn else { continue };
            let Some(slot) = ConnectionSlot::acquire(&active) else {
                continue;
            };
            let server = server.clone();
            let config = config.clone();
            let _ = std::thread::Builder::new().name("mcp-http".into()).spawn(move || {
                let _slot = slot;
                handle_http_connection(&server, stream, port, &config);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::TcpStream,
        sync::atomic::AtomicUsize,
        thread,
    };

    use super::*;

    const MINTED: &str = "SECRET-MCP-TOKEN-0123456789";

    #[derive(Default)]
    struct FakeLink {
        exchanges: AtomicUsize,
        forwards: Mutex<Vec<(String, Value)>>,
        refuse_next_forward: Mutex<Option<u16>>,
        minted_ttls: Mutex<Vec<u64>>,
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
    }

    #[derive(Default)]
    struct Scripted {
        approve: Mutex<Option<Option<PairingDecision>>>,
        confirm: Mutex<Option<Option<bool>>>,
        approvals_asked: AtomicUsize,
        confirms_asked: AtomicUsize,
    }

    impl Prompter for Arc<Scripted> {
        fn approve(&self, _request: &PairingRequest<'_>) -> Option<PairingDecision> {
            self.approvals_asked.fetch_add(1, Ordering::SeqCst);
            lock(&self.approve).clone().unwrap_or(None)
        }

        fn confirm(&self, _request: &ConfirmRequest<'_>) -> Option<bool> {
            self.confirms_asked.fetch_add(1, Ordering::SeqCst);
            (*lock(&self.confirm)).unwrap_or(None)
        }
    }

    fn grant() -> PairingGrant {
        PairingGrant {
            tool_allowlist: vec!["bv_kv_read_metadata".into(), "bv_kv_read".into()],
            path_scope: vec!["secret/*".into()],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            ttl_secs: 3600,
        }
    }

    struct Rig {
        server: Arc<LocalServer>,
        link: Arc<FakeLink>,
        prompt: Arc<Scripted>,
        dir: std::path::PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn rig(name: &str) -> Rig {
        let dir = std::env::temp_dir().join(format!("bvault-mcp-serve-{name}-{}", new_pairing_id()));
        let link = Arc::new(FakeLink::default());
        let prompt = Arc::new(Scripted::default());
        let server = Arc::new(LocalServer::new(
            Box::new(link.clone()),
            Box::new(prompt.clone()),
            PairingStore::at(dir.join("mcp-pairings.json")),
        ));
        Rig { server, link, prompt, dir }
    }

    fn stdio() -> ConnInfo {
        ConnInfo { transport: Transport::Stdio, peer_uid: None, preauthenticated: None }
    }

    fn request(id: u64, method: &str, params: Value) -> Vec<u8> {
        let mut params = params;
        params["_meta"] = json!({ "io.modelcontextprotocol/clientInfo": { "name": "claude-desktop", "version": "9.9" } });
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })).unwrap()
    }

    fn data_code(resp: &Value) -> &str {
        resp["error"]["data"]["code"].as_str().unwrap_or("")
    }

    #[test]
    fn unpaired_client_without_a_terminal_fails_closed() {
        let rig = rig("noterminal");
        // Scripted::approve defaults to None: no operator reachable.
        let resp = rig.server.handle_message(&stdio(), &request(1, "tools/list", json!({}))).unwrap();
        assert_eq!(data_code(&resp), "mcp_pairing_requires_operator");
        assert_eq!(rig.link.exchanges.load(Ordering::SeqCst), 0, "no token may be minted for an unpaired client");
        assert!(lock(&rig.link.forwards).is_empty());
        assert!(rig.server.store().load().unwrap().is_empty(), "nothing is recorded without approval");
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
    fn approval_pairs_mints_once_and_relays() {
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
        let bare = serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} })).unwrap();
        let resp = rig.server.handle_message(&stdio(), &bare).unwrap();
        assert_eq!(data_code(&resp), "mcp_client_info_required");
        assert_eq!(rig.prompt.approvals_asked.load(Ordering::SeqCst), 0);
    }

    fn reveal_call(id: u64) -> Vec<u8> {
        request(
            id,
            "tools/call",
            json!({ "name": "bv_kv_read", "arguments": { "mount": "secret", "path": "ai/x", "reveal": true } }),
        )
    }

    fn paired_rig(name: &str, reveal_allowed: bool) -> Rig {
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

        *lock(&rig.prompt.confirm) = Some(Some(true));
        let allowed = rig.server.handle_message(&stdio(), &reveal_call(3)).unwrap();
        assert_eq!(allowed["result"]["relayed"], json!(true));
        assert_eq!(rig.prompt.confirms_asked.load(Ordering::SeqCst), 2);
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

        let del = request(2, "tools/call", json!({ "name": "bv_kv_delete", "arguments": { "mount": "secret", "path": "x" } }));
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
        let replies: Vec<Value> = out.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[1]["id"], json!(11));

        let huge = vec![b'a'; (MAX_MESSAGE_BYTES + 10) as usize];
        let mut out = Vec::new();
        run_line_session(&rig.server, &stdio(), std::io::Cursor::new(huge), &mut out).unwrap();
        let reply: Value = serde_json::from_slice(out.trim_ascii()).unwrap();
        assert_eq!(data_code(&reply), "mcp_message_too_large");
    }

    #[test]
    fn listen_address_must_be_loopback() {
        assert!(parse_loopback_addr("127.0.0.1:8250").is_ok());
        assert!(parse_loopback_addr("[::1]:8250").is_ok());
        for bad in ["0.0.0.0:8250", "192.168.1.5:8250", "[::]:8250", "8250", "localhost:8250", "example.com:80"] {
            assert!(parse_loopback_addr(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn binding_a_non_loopback_address_is_refused_even_if_called_directly() {
        assert!(bind_http("0.0.0.0:0".parse().unwrap()).is_err());
    }

    // ── loopback HTTP ────────────────────────────────────────────────────

    struct HttpRig {
        rig: Rig,
        addr: SocketAddr,
        bearer: String,
    }

    fn http_rig(name: &str, allowed_origins: Vec<String>) -> HttpRig {
        let rig = rig(name);
        let bearer = new_pairing_token();
        let mut record = build_record(
            &PairingRequest { client_name: "web-client", client_version: "1", transport: Transport::LoopbackHttp, peer_uid: None },
            &grant(),
            now_secs(),
        )
        .0;
        record.pairing_token_hash = Some(hash_token(&bearer));
        rig.server.store().add(record).unwrap();

        let bound = bind_http("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = bound.addr;
        let server = rig.server.clone();
        thread::spawn(move || bound.run(server, HttpConfig { allowed_origins }));
        HttpRig { rig, addr, bearer }
    }

    fn raw(addr: SocketAddr, request: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        let status = response.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        (status, response)
    }

    fn post(addr: SocketAddr, host: Option<&str>, origin: Option<&str>, bearer: Option<&str>, body: &str) -> (u16, String) {
        let mut req = format!("POST {HTTP_PATH} HTTP/1.1\r\n");
        if let Some(h) = host {
            req.push_str(&format!("Host: {h}\r\n"));
        }
        if let Some(o) = origin {
            req.push_str(&format!("Origin: {o}\r\n"));
        }
        if let Some(b) = bearer {
            req.push_str(&format!("Authorization: Bearer {b}\r\n"));
        }
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
        raw(addr, &req)
    }

    fn list_body() -> String {
        String::from_utf8(request(1, "tools/list", json!({}))).unwrap()
    }

    #[test]
    fn http_happy_path_relays_with_a_paired_bearer() {
        let h = http_rig("http-ok", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        let (status, body) = post(h.addr, Some(&host), None, Some(&h.bearer), &list_body());
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("\"relayed\":true"));
        assert_eq!(lock(&h.rig.link.forwards)[0].0, MINTED);
    }

    #[test]
    fn http_foreign_origin_is_403_and_never_reaches_the_vault() {
        let h = http_rig("http-origin", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        let (status, _) = post(h.addr, Some(&host), Some("https://evil.example.com"), Some(&h.bearer), &list_body());
        assert_eq!(status, 403);
        assert_eq!(h.rig.link.exchanges.load(Ordering::SeqCst), 0);
        assert!(lock(&h.rig.link.forwards).is_empty());
    }

    #[test]
    fn http_allowed_origin_passes_and_others_still_fail() {
        let h = http_rig("http-origin-allow", vec!["https://app.example.com".into()]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        assert_eq!(post(h.addr, Some(&host), Some("https://app.example.com"), Some(&h.bearer), &list_body()).0, 200);
        assert_eq!(post(h.addr, Some(&host), Some("https://app.example.com.evil.test"), Some(&h.bearer), &list_body()).0, 403);
    }

    #[test]
    fn http_rebinding_host_is_403() {
        let h = http_rig("http-host", vec![]);
        for host in [Some("evil.example.com"), Some("evil.example.com:80"), Some("127.0.0.1:1"), None] {
            let (status, _) = post(h.addr, host, None, Some(&h.bearer), &list_body());
            assert_eq!(status, 403, "Host {host:?} must be refused");
        }
        assert!(lock(&h.rig.link.forwards).is_empty());
    }

    #[test]
    fn http_requires_a_known_bearer() {
        let h = http_rig("http-auth", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        assert_eq!(post(h.addr, Some(&host), None, None, &list_body()).0, 401);
        assert_eq!(post(h.addr, Some(&host), None, Some("not-a-paired-token"), &list_body()).0, 401);
        assert_eq!(h.rig.link.exchanges.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn http_rejects_other_methods_paths_and_bad_framing() {
        let h = http_rig("http-shape", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        assert_eq!(raw(h.addr, &format!("GET {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n\r\n")).0, 405);
        assert_eq!(raw(h.addr, &format!("POST /elsewhere HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n")).0, 404);

        let auth = format!("Authorization: Bearer {}\r\n", h.bearer);
        let oversized = format!("POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Length: {}\r\n\r\n", MAX_MESSAGE_BYTES + 1);
        assert_eq!(raw(h.addr, &oversized).0, 413);
        let chunked = format!("POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
        assert_eq!(raw(h.addr, &chunked).0, 501);
        let no_length = format!("POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}\r\n");
        assert_eq!(raw(h.addr, &no_length).0, 411);
        let dup_length = format!("POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}");
        assert_eq!(raw(h.addr, &dup_length).0, 411);
        assert!(lock(&h.rig.link.forwards).is_empty());
    }

    // ── Unix socket ──────────────────────────────────────────────────────

    #[cfg(unix)]
    mod unix_socket {
        use std::os::unix::net::UnixStream;

        use super::*;
        use crate::command::mcp_serve::uds;

        #[test]
        fn peer_uid_of_a_local_pair_is_our_own() {
            let (a, _b) = UnixStream::pair().unwrap();
            assert_eq!(uds::peer_uid(&a), Some(uds::current_uid()));
            assert!(uds::peer_is(&a, uds::current_uid()).is_some());
        }

        #[test]
        fn a_peer_with_a_different_uid_is_dropped_before_any_byte_is_read() {
            let rig = paired_rig("uds-gate", false);
            let forwards_before = lock(&rig.link.forwards).len();
            let (server_end, mut client_end) = UnixStream::pair().unwrap();
            // The client speaks first, as a hostile or confused peer would.
            client_end.write_all(&request(5, "tools/list", json!({}))).unwrap();
            client_end.write_all(b"\n").unwrap();

            let wrong = uds::current_uid().wrapping_add(1);
            uds::serve_connection(&rig.server, server_end, wrong);

            // Dropping a socket with unread data is an orderly EOF on macOS but
            // a connection reset on Linux; either way the peer is cut off and
            // gets no answer.
            let mut reply = String::new();
            match client_end.read_to_string(&mut reply) {
                Ok(_) => assert!(reply.is_empty(), "a rejected peer gets EOF, not an answer: {reply:?}"),
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}"),
            }
            assert!(reply.is_empty(), "nothing was answered: {reply:?}");
            assert_eq!(lock(&rig.link.forwards).len(), forwards_before, "nothing reached the vault");
        }

        #[test]
        fn a_matching_peer_is_served_and_recorded_with_its_uid() {
            let rig = rig("uds-ok");
            *lock(&rig.prompt.approve) = Some(Some(PairingDecision::Approved(grant())));
            let (server_end, mut client_end) = UnixStream::pair().unwrap();
            client_end.write_all(&request(7, "tools/list", json!({}))).unwrap();
            client_end.write_all(b"\n").unwrap();
            client_end.shutdown(std::net::Shutdown::Write).unwrap();

            uds::serve_connection(&rig.server, server_end, uds::current_uid());

            let mut reply = String::new();
            client_end.read_to_string(&mut reply).unwrap();
            assert!(reply.contains("\"relayed\":true"), "{reply}");
            let records = rig.server.store().load().unwrap();
            assert_eq!(records[0].peer_uid, Some(uds::current_uid()));
            assert_eq!(records[0].transport, "uds");
        }

        #[test]
        fn the_socket_is_created_owner_only_and_a_live_one_is_not_replaced() {
            use std::os::unix::fs::PermissionsExt;
            // Short and under /tmp on purpose: a socket path must fit in
            // `sun_path`, and macOS's per-user temp dir alone nearly does not.
            let dir = std::path::PathBuf::from(format!("/tmp/bvmcp-{}", &new_pairing_id()[..8]));
            let path = dir.join("mcp.sock");
            let listener = uds::bind_private_socket(&path).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert!(uds::bind_private_socket(&path).is_err(), "a socket in use must not be stolen");
            drop(listener);
            assert!(uds::bind_private_socket(&path).is_ok(), "a stale socket file is replaced");
            std::fs::remove_dir_all(dir).ok();
        }

        #[test]
        fn an_over_long_socket_path_gets_an_actionable_error() {
            let dir = std::path::PathBuf::from(format!("/tmp/bvmcp-{}", &new_pairing_id()[..8]));
            let path = dir.join("x".repeat(200));
            let err = uds::bind_private_socket(&path).unwrap_err().to_string();
            assert!(err.contains("too long for a Unix socket path"), "{err}");
            std::fs::remove_dir_all(dir).ok();
        }

        #[test]
        fn a_regular_file_is_never_replaced_by_the_socket() {
            let dir = std::env::temp_dir().join(format!("bvault-mcp-sock-file-{}", new_pairing_id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("precious.txt");
            std::fs::write(&path, b"keep me").unwrap();
            assert!(uds::bind_private_socket(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
            std::fs::remove_dir_all(dir).ok();
        }
    }
}
