//! `bvault mcp serve` -- the CLI host of the local MCP server
//! (`features/mcp-access.md` §3, §11).
//!
//! The gatekeeper itself -- pairing, the stateful `initialize` handshake,
//! per-call confirmation, token minting, the line framing and the
//! owner-only Unix socket -- is [`bv_mcp::local`], shared with the desktop
//! app so the two cannot drift. What stays here is what only the CLI has:
//!
//! - [`HttpVaultLink`]: the vault, reached over the CLI's `api::Client`
//!   (`POST /v2/mcp/token` to mint, `POST /v2/mcp` to forward);
//! - [`TtyPrompter`]: the operator, at the controlling terminal;
//! - the stdio and Unix-socket serving loops, which run until killed;
//! - the loopback-HTTP transport, which only the CLI offers.
//!
//! Fail-closed everywhere: no controlling terminal means no pairing and no
//! per-call confirmation, never a silent approval. A per-call confirmation
//! nobody answers within [`CONFIRM_TIMEOUT`] is refused.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{atomic::AtomicUsize, Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use bv_mcp::{
    catalogue,
    local::{
        exchange_request_body, mfa_begin_body, mfa_begin_error, mfa_preflight_from_begin, mfa_verify_body,
        minted_token_from_exchange, normalize_grant, operator_namespace_from_lookup, ticket_from_verify,
        ConfirmRequest, ConnInfo, ConnectionSlot, ForwardError, LocalServer, McpCallRef, MfaBeginError, MfaFactor,
        MfaPreflight, MintedToken, PairingDecision, PairingGrant, PairingRequest, Prompter, VaultLink,
        CONNECT_MFA_BEGIN_PATH, CONNECT_MFA_VERIFY_PATH, MAX_MESSAGE_BYTES, NAMESPACE_HEADER, TOKEN_LOOKUP_SELF_PATH,
    },
    pairing::{
        self, find_by_token_hash, hash_token, now_secs, PairingRecord, Transport, DEFAULT_TOKEN_TTL_SECS,
        MAX_TOKEN_TTL_SECS,
    },
    sanitize::sanitize_for_model,
};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{api::Client, bv_error_string, errors::RvError};

pub use bv_mcp::local::vault_error_text;

const MAX_HEAD_BYTES: usize = 16 * 1024;
pub const HTTP_PATH: &str = "/mcp";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ── vault side ───────────────────────────────────────────────────────────

pub struct HttpVaultLink {
    client: Client,
    /// The namespace the operator's session is bound to, once asked. The
    /// session's token is fixed for the life of the process and its binding
    /// is immutable, so one answer holds; a failed lookup is not cached.
    operator_namespace: Mutex<Option<String>>,
}

impl HttpVaultLink {
    pub fn new(client: Client) -> Self {
        Self { client, operator_namespace: Mutex::new(None) }
    }

    /// The operator session's namespace (`""` = root), from the vault's own
    /// record of the session's token (`auth/token/lookup-self`), never from
    /// the MCP client (`features/mcp-namespace-selection.md` Phase 1).
    fn session_namespace(&self) -> Result<String, String> {
        if let Some(ns) = lock(&self.operator_namespace).clone() {
            return Ok(ns);
        }
        let resp = self
            .client
            .logical()
            .read(TOKEN_LOOKUP_SELF_PATH)
            .map_err(|e| format!("could not ask the vault which namespace your session is in: {e}"))?;
        if resp.response_status != 200 {
            return Err(vault_error_text(&resp.response_data, resp.response_status));
        }
        let ns = operator_namespace_from_lookup(&resp.response_data.unwrap_or(Value::Null))?;
        *lock(&self.operator_namespace) = Some(ns.clone());
        Ok(ns)
    }

    /// The operator's client, aimed at `namespace` -- where the pairing's
    /// token runs, as the exchange reported it -- or, when that is unknown,
    /// at their session's: the MFA ticket must bind where the call runs.
    fn operator_client(&self, namespace: Option<&str>) -> Result<Client, String> {
        let ns = match namespace {
            Some(ns) => ns.to_string(),
            None => self.session_namespace()?,
        };
        Ok(if ns.is_empty() { self.client.clone() } else { self.client.clone().add_header(NAMESPACE_HEADER, &ns) })
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
    fn exchange_pairing(
        &self,
        record: &PairingRecord,
        ttl_secs: u64,
        namespace: Option<&str>,
    ) -> Result<MintedToken, String> {
        let resp = self
            .client
            .request_write("v2/mcp/token", Some(exchange_request_body(record, ttl_secs, namespace)))
            .map_err(|e| format!("could not reach the vault: {e}"))?;
        if resp.response_status != 200 {
            return Err(vault_error_text(&resp.response_data, resp.response_status));
        }
        let data = resp.response_data.ok_or_else(|| "vault returned an empty exchange response".to_string())?;
        minted_token_from_exchange(&data, ttl_secs, now_secs())
    }

    fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError> {
        let body = message
            .as_object()
            .cloned()
            .ok_or_else(|| ForwardError::Other("only JSON objects can be forwarded".to_string()))?;
        let mut client = self.client.clone();
        client.token = token.to_string();
        let resp = client.request_write("v2/mcp", Some(body));
        // The minted token is the gatekeeper's to keep; wipe this copy.
        client.token.zeroize();
        let resp = resp.map_err(|e| ForwardError::Other(format!("could not reach the vault: {e}")))?;
        match (resp.response_status, resp.response_data) {
            (200, Some(v)) => Ok(v),
            (s @ (401 | 403), _) => Err(ForwardError::Refused(s)),
            (s, data) => Err(ForwardError::Other(vault_error_text(&data, s))),
        }
    }

    /// Asked with the operator's own login -- the client this server mints
    /// pairing tokens from -- never with an MCP token.
    fn connect_mfa_begin(
        &self,
        namespace: Option<&str>,
        resource: &str,
        profile_id: &str,
    ) -> Result<MfaPreflight, MfaBeginError> {
        let client = self.operator_client(namespace).map_err(MfaBeginError::Other)?;
        let resp = client
            .logical()
            .write(CONNECT_MFA_BEGIN_PATH, Some(mfa_begin_body(resource, profile_id)))
            .map_err(|e| MfaBeginError::Other(format!("could not reach the vault: {e}")))?;
        if resp.response_status != 200 {
            return Err(mfa_begin_error(vault_error_text(&resp.response_data, resp.response_status)));
        }
        mfa_preflight_from_begin(&resp.response_data.unwrap_or(Value::Null))
    }

    fn connect_mfa_verify(
        &self,
        namespace: Option<&str>,
        resource: &str,
        profile_id: &str,
        factor: &MfaFactor,
        call: &McpCallRef,
    ) -> Result<Zeroizing<String>, String> {
        let client = self.operator_client(namespace)?;
        let resp = client
            .logical()
            .write(CONNECT_MFA_VERIFY_PATH, Some(mfa_verify_body(resource, profile_id, factor, call)))
            .map_err(|e| format!("could not reach the vault: {e}"))?;
        if resp.response_status != 200 {
            return Err(vault_error_text(&resp.response_data, resp.response_status));
        }
        ticket_from_verify(&resp.response_data.unwrap_or(Value::Null))
    }

    fn operator_namespace(&self) -> Option<String> {
        self.session_namespace().ok()
    }
}

// ── operator side ────────────────────────────────────────────────────────

/// How long a per-call confirmation waits at the terminal before the call
/// is refused: the desktop app's dialog waits as long.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);

/// The warning a pairing that may both reveal secrets and open sessions is
/// given (`features/mcp-brokered-sessions.md` §9).
pub const TRIFECTA_WARNING: &str = "This assistant can read secret values AND run commands on servers. A hijacked \
                                    assistant could send a secret to a server. You will approve each command; read them.";

/// Prompts on the controlling terminal (`/dev/tty`), *not* stdin/stdout: in
/// stdio transport those two are the MCP channel itself, and a prompt written
/// to either would corrupt it. A process with no controlling terminal -- a
/// GUI-spawned server, cron, CI -- gets `None` and so cannot pair.
#[derive(Default)]
pub struct TtyPrompter {
    one_prompt_at_a_time: Mutex<()>,
}

/// One conversation with the operator. Generic so the prompts are testable
/// with an in-memory "terminal".
pub(crate) struct Tty<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    /// When unanswered questions are refused. `None`: wait for ever (the
    /// pairing questions, asked of an operator who ran `bvault mcp pair`).
    deadline: Option<Instant>,
    /// Whether a line can be read before `timeout` runs out.
    ready: fn(&R, Duration) -> bool,
}

type RealTty = Tty<BufReader<File>, File>;

impl RealTty {
    fn open() -> Option<RealTty> {
        #[cfg(unix)]
        let (input, output) = ("/dev/tty", "/dev/tty");
        #[cfg(not(unix))]
        let (input, output) = ("CONIN$", "CONOUT$");
        let reader = File::open(input).ok()?;
        let writer = OpenOptions::new().write(true).open(output).ok()?;
        discard_typed_ahead(&reader);
        Some(Tty { reader: BufReader::new(reader), writer, deadline: None, ready: tty_ready })
    }
}

/// Keys typed before a question is asked are not an answer to it: drop
/// them, so a stray `y` (or one typed after an earlier prompt timed out)
/// cannot approve the next call.
#[cfg(unix)]
fn discard_typed_ahead(tty: &File) {
    use std::os::fd::AsRawFd;
    // SAFETY: `tty` is an open file for the whole call; `tcflush` only
    // discards the kernel's pending input queue for that descriptor and
    // touches no memory of ours. A failure (not a terminal) is harmless.
    unsafe {
        libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH);
    }
}

#[cfg(not(unix))]
fn discard_typed_ahead(_tty: &File) {}

/// Waits until the terminal has a line to read, for at most `timeout`.
#[cfg(unix)]
fn tty_ready(reader: &BufReader<File>, timeout: Duration) -> bool {
    use std::os::fd::AsRawFd;
    if !reader.buffer().is_empty() {
        return true;
    }
    let fd = reader.get_ref().as_raw_fd();
    // `FD_SET` on a descriptor at or past `FD_SETSIZE` is undefined; such a
    // terminal is waited on without a timeout rather than risked.
    if fd < 0 || fd as usize >= libc::FD_SETSIZE {
        return true;
    }
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        // SAFETY: `set` is a zeroed `fd_set` on this stack frame, initialised
        // by FD_ZERO/FD_SET for one descriptor below FD_SETSIZE (checked
        // above); `tv` is a valid timeval; `select` reads and writes only
        // those two for the call's duration. `fd` stays open throughout.
        let ready = unsafe {
            let mut set: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut set);
            libc::FD_SET(fd, &mut set);
            let mut tv = libc::timeval {
                tv_sec: left.as_secs() as libc::time_t,
                tv_usec: left.subsec_micros() as libc::suseconds_t,
            };
            libc::select(fd + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv)
        };
        match ready {
            n if n > 0 => return true,
            0 => return false,
            // Interrupted by a signal: wait out the rest.
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => continue,
            _ => return false,
        }
    }
}

/// No `select` on this platform's console: no timeout.
#[cfg(not(unix))]
fn tty_ready(_reader: &BufReader<File>, _timeout: Duration) -> bool {
    true
}

impl<R: BufRead, W: Write> Tty<R, W> {
    fn say(&mut self, text: &str) {
        let _ = writeln!(self.writer, "{text}");
    }

    /// `None` on EOF, a read error, or the deadline passing -- the operator
    /// went away, or did not answer in time.
    fn ask(&mut self, prompt: &str) -> Option<String> {
        let _ = write!(self.writer, "{prompt}");
        let _ = self.writer.flush();
        if let Some(deadline) = self.deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || !(self.ready)(&self.reader, left) {
                self.say("");
                self.say("  No answer in time: refused.");
                return None;
            }
        }
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

    /// The pairing questions (`bvault mcp pair`, or a first contact on
    /// `bvault mcp serve`).
    pub(crate) fn approve(&mut self, request: &PairingRequest<'_>) -> Option<PairingDecision> {
        self.say("");
        self.say("A local MCP client is asking for access to your vault.");
        self.say(&format!(
            "  Client:     {} {}",
            sanitize_for_model(request.client_name),
            sanitize_for_model(request.client_version)
        ));
        self.say(&format!("  Transport:  {}", request.transport.as_str()));
        if let Some(ns) = request.namespace {
            self.say(&format!("  Namespace:  {}", namespace_label(ns)));
        }
        if let Some(uid) = request.peer_uid {
            self.say(&format!("  Peer uid:   {uid}"));
        }
        self.say("  It will act with YOUR permissions, narrowed to the scope you choose below.");
        self.say("");
        if !self.yes_no("Approve this client?", false)? {
            return Some(PairingDecision::Denied);
        }

        let path_scope = split_list(
            &self.ask("Path scope, comma-separated (e.g. secret/metadata/ai/*; empty denies every path): ")?,
        );
        if path_scope.is_empty() {
            self.say("  No path scope: every tool call will be refused until you re-pair with one.");
        }

        let defaults = pairing::default_tool_allowlist();
        self.say(&format!("Default tools (read-only, never reveal a value): {}", defaults.join(", ")));
        let tools_in = self.ask("Tools, comma-separated (Enter for the default list): ")?;
        let mut tool_allowlist = if tools_in.is_empty() { defaults } else { split_list(&tools_in) };
        if let Some(unknown) = tool_allowlist.iter().find(|t| catalogue::find(t).is_none()) {
            self.say(&format!(
                "  `{}` is not a tool in this build's catalogue; denying the pairing.",
                sanitize_for_model(unknown)
            ));
            return Some(PairingDecision::Denied);
        }

        let reveal_allowed = self.yes_no("Allow revealing secret values?", false)?;
        let confirm_reveal = reveal_allowed && self.yes_no("  Ask you to confirm each reveal?", true)?;
        let destructive_allowed = self.yes_no("Allow destructive tools (write, delete, issue, sign)?", false)?;
        let confirm_destructive = destructive_allowed && self.yes_no("  Ask you to confirm each one?", true)?;

        // Brokered sessions: their own question, off by default, with every
        // call confirmed and no way to say otherwise.
        let session_tools: Vec<&str> = catalogue::catalogue().iter().filter(|t| t.open_world).map(|t| t.name).collect();
        self.say("");
        self.say("Brokered sessions let this assistant open connections to your servers through the vault");
        self.say(&format!(
            "({}). The vault holds the credential; every call is shown to you for approval,",
            session_tools.join(", ")
        ));
        self.say("with the exact command, and runs only if you say yes.");
        let connect_allowed = self.yes_no("Allow brokered sessions?", false)?;
        if connect_allowed {
            for tool in &session_tools {
                if !tool_allowlist.iter().any(|t| t == tool) {
                    tool_allowlist.push(tool.to_string());
                }
            }
            if reveal_allowed {
                self.say("");
                self.say(&format!("  WARNING: {TRIFECTA_WARNING}"));
                if !self.yes_no("  Pair it with both anyway?", false)? {
                    return Some(PairingDecision::Denied);
                }
            }
        } else if tool_allowlist.iter().any(|t| session_tools.contains(&t.as_str())) {
            tool_allowlist.retain(|t| !session_tools.contains(&t.as_str()));
            self.say("  Brokered sessions not allowed: the session tools were left out.");
        }

        let hours = self.ask(&format!("Token lifetime in hours [{}]: ", DEFAULT_TOKEN_TTL_SECS / 3600))?;
        let ttl_secs = if hours.is_empty() {
            DEFAULT_TOKEN_TTL_SECS
        } else {
            match hours.parse::<u64>() {
                Ok(h) if h >= 1 => (h * 3600).min(MAX_TOKEN_TTL_SECS),
                _ => {
                    self.say("  Not a whole number of hours; denying the pairing.");
                    return Some(PairingDecision::Denied);
                }
            }
        };

        let grant = PairingGrant {
            tool_allowlist,
            path_scope,
            reveal_allowed,
            destructive_allowed,
            confirm_reveal,
            confirm_destructive,
            connect_allowed,
            confirm_connect: connect_allowed,
            ttl_secs,
            // The terminal narrows with `--namespace`, a server setting; a
            // terminal approval never pins one on the pairing.
            namespace: None,
        };
        match normalize_grant(grant) {
            Ok(grant) => Some(PairingDecision::Approved(grant)),
            Err(reason) => {
                self.say(&format!("  {}; denying the pairing.", sanitize_for_model(&reason)));
                Some(PairingDecision::Denied)
            }
        }
    }

    /// A per-call confirmation. Default deny; for a session call, the
    /// operator sees every field and every line of the command, and on a
    /// gated profile types a TOTP code, which is verified before the answer
    /// is given. A failed factor denies.
    pub(crate) fn confirm(&mut self, request: &ConfirmRequest<'_>) -> Option<bool> {
        let client = sanitize_for_model(request.client_name);
        self.say("");
        if let (true, Some(detail)) = (request.open_world, request.detail) {
            let resource = request.session.map(|c| sanitize_for_model(&c.resource)).unwrap_or_default();
            let web = request.session.is_some_and(|c| c.protocol == "web");
            let what = if web { "fetch a page from" } else { "run a command on" };
            self.say(&format!("MCP client `{client}` wants to {what} `{resource}` ({}):", request.tool));
            if let Some(ns) = request.namespace {
                self.say(&format!("    Namespace: {}", namespace_label(ns)));
            }
            for line in detail.split('\n') {
                self.say(&format!("    {line}"));
            }
            if let Some(step) = &request.mfa {
                let profile = request.session.map(|c| sanitize_for_model(&c.profile)).unwrap_or_default();
                self.say("");
                self.say(&format!(
                    "`{client}` is asking you to complete MFA to access `{resource}` (profile `{profile}`)."
                ));
                if !step.challenge.methods.iter().any(|m| m == "totp") {
                    self.say("  Your only enrolled factor is a security key, which this terminal cannot use;");
                    self.say("  approve this from the BastionVault desktop app. Refused.");
                    return Some(false);
                }
            }
            let question = if web { "Fetch this page once?" } else { "Run this command once?" };
            if !self.yes_no(question, false)? {
                return Some(false);
            }
            if let Some(step) = &request.mfa {
                let code = Zeroizing::new(self.ask("Authenticator (TOTP) code: ")?);
                if code.trim().is_empty() {
                    self.say("  No code: refused.");
                    return Some(false);
                }
                if let Err(reason) = (step.verify)(MfaFactor::Totp(code)) {
                    self.say(&format!("  MFA failed ({}): refused.", sanitize_for_model(&reason)));
                    return Some(false);
                }
                self.say("  MFA verified.");
            }
            return Some(true);
        }
        let what = match (request.reveals, request.destructive) {
            (true, true) => "reveal a secret value AND make a change",
            (true, false) => "reveal a secret value",
            _ => "make a change",
        };
        self.say(&format!("MCP client `{client}` wants to {what}:"));
        self.say(&format!("  {}  {}", sanitize_for_model(request.tool), sanitize_for_model(request.summary)));
        if let Some(ns) = request.namespace {
            self.say(&format!("  in namespace {}", namespace_label(ns)));
        }
        // Default deny: anything but an explicit yes refuses the call.
        self.yes_no("Allow this one call?", false)
    }
}

/// How a namespace is named to the operator: `root` for the root namespace.
fn namespace_label(ns: &str) -> String {
    if ns.is_empty() {
        "root".to_string()
    } else {
        sanitize_for_model(ns)
    }
}

fn split_list(input: &str) -> Vec<String> {
    input.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

impl Prompter for TtyPrompter {
    fn approve(&self, request: &PairingRequest<'_>) -> Option<PairingDecision> {
        let _one = lock(&self.one_prompt_at_a_time);
        RealTty::open()?.approve(request)
    }

    fn confirm(&self, request: &ConfirmRequest<'_>) -> Option<bool> {
        let _one = lock(&self.one_prompt_at_a_time);
        let mut tty = RealTty::open()?;
        tty.deadline = Some(Instant::now() + CONFIRM_TIMEOUT);
        tty.confirm(request)
    }

    fn confirmation_unavailable_message(&self) -> &str {
        "this call needs operator confirmation at the terminal running `bvault mcp serve`, and none was given \
         (no terminal, or no answer within 90 seconds)"
    }

    fn mfa_methods(&self) -> &[&'static str] {
        &["totp"]
    }

    fn mfa_unavailable_message(&self) -> &str {
        "this connection profile requires your MFA, and a terminal can take only a TOTP code, which your account \
         does not have; approve this assistant's session calls from the BastionVault desktop app, which can use \
         your security key"
    }
}

// ── transports ───────────────────────────────────────────────────────────

pub fn serve_stdio(server: &LocalServer) -> Result<(), RvError> {
    let conn = ConnInfo { transport: Transport::Stdio, peer_uid: None, preauthenticated: None };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    bv_mcp::local::run_line_session(server, &conn, stdin.lock(), stdout.lock())
        .map_err(|e| bv_error_string!(format!("stdio session ended: {e}")))
}

/// Loopback only, by construction: there is no flag to widen this.
pub fn parse_loopback_addr(input: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr =
        input.parse().map_err(|_| format!("`{input}` is not an IP:port address (e.g. 127.0.0.1:8250)"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "`{input}` is not a loopback address: the local MCP server only ever binds 127.0.0.1 or [::1]"
        ));
    }
    Ok(addr)
}

/// `bvault mcp serve --socket`: the shared owner-only socket
/// ([`bv_mcp::local::uds`]), served in the foreground until killed.
#[cfg(unix)]
pub mod uds {
    use std::{path::Path, sync::Arc};

    pub use bv_mcp::local::uds::current_uid;
    use bv_mcp::local::{uds, LocalServer};

    use crate::errors::RvError;

    pub fn serve(server: Arc<LocalServer>, path: &Path) -> Result<(), RvError> {
        let listener = uds::bind_private_socket(path)?;
        eprintln!("bvault mcp: serving on {} (owner-only)", path.display());
        uds::run(server, listener, current_uid());
        Ok(())
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
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.body.len()
        );
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
        let allowed = std::str::from_utf8(origin).is_ok_and(|o| config.allowed_origins.iter().any(|a| a == o.trim()));
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
    let now = server.now();
    let Ok(records) = server.store().load() else {
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
    //! The CLI-only parts: the loopback-HTTP transport and its address
    //! rules. The gatekeeper's own tests (pairing, handshake, confirmation,
    //! the Unix socket) live with it in `bv_mcp::local`.

    use std::{
        net::TcpStream,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
    };

    use bv_mcp::local::build_record;
    use bv_mcp::pairing::{new_pairing_id, new_pairing_token, PairingStore};
    use serde_json::json;

    use super::*;

    const MINTED: &str = "SECRET-MCP-TOKEN-0123456789";

    #[derive(Default)]
    struct FakeLink {
        exchanges: AtomicUsize,
        forwards: Mutex<Vec<(String, Value)>>,
    }

    /// The trait is `bv-mcp`'s, so the test double needs a local type.
    struct SharedLink(Arc<FakeLink>);

    impl VaultLink for SharedLink {
        fn exchange_pairing(
            &self,
            _record: &PairingRecord,
            ttl_secs: u64,
            _namespace: Option<&str>,
        ) -> Result<MintedToken, String> {
            self.0.exchanges.fetch_add(1, Ordering::SeqCst);
            Ok(MintedToken { token: MINTED.to_string(), expires_at: now_secs() + ttl_secs, namespace: None })
        }

        fn forward(&self, token: &str, message: &Value) -> Result<Value, ForwardError> {
            lock(&self.0.forwards).push((token.to_string(), message.clone()));
            Ok(json!({ "jsonrpc": "2.0", "id": message["id"], "result": { "relayed": true } }))
        }
    }

    /// Loopback HTTP never prompts: a client is admitted by a bearer that
    /// already maps to a pairing.
    struct NoOperator;

    impl Prompter for NoOperator {
        fn approve(&self, _request: &PairingRequest<'_>) -> Option<PairingDecision> {
            None
        }

        fn confirm(&self, _request: &ConfirmRequest<'_>) -> Option<bool> {
            None
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
            connect_allowed: false,
            confirm_connect: false,
            ttl_secs: 3600,
            namespace: None,
        }
    }

    // ── the terminal prompt ─────────────────────────────────────────────

    /// A terminal whose keyboard is `typed` and whose screen is returned.
    fn tty(typed: &str) -> Tty<std::io::Cursor<Vec<u8>>, Vec<u8>> {
        Tty {
            reader: std::io::Cursor::new(typed.as_bytes().to_vec()),
            writer: Vec::new(),
            deadline: None,
            ready: |_, _| true,
        }
    }

    fn screen(t: &Tty<std::io::Cursor<Vec<u8>>, Vec<u8>>) -> String {
        String::from_utf8(t.writer.clone()).unwrap()
    }

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
            namespace: Some("dti/esi"),
        }
    }

    /// The operator sees every field and every line of the command; Enter
    /// alone, or anything but yes, refuses.
    #[test]
    fn the_session_prompt_shows_the_whole_call_and_defaults_to_deny() {
        let call = session_call("journalctl -u nginx | tail -n 20\nuptime");
        let detail = bv_mcp::local::render_session_detail(&call);
        for (typed, expected) in [("y\n", Some(true)), ("\n", Some(false)), ("n\n", Some(false)), ("", None)] {
            let mut t = tty(typed);
            assert_eq!(t.confirm(&session_request(&call, &detail, None)), expected, "{typed:?}");
            let shown = screen(&t);
            assert!(shown.contains("`claude-code` wants to run a command on `web-01`"), "{shown}");
            assert!(shown.contains("Profile:   p_agent") && shown.contains("Protocol:  ssh"), "{shown}");
            assert!(shown.contains("  | journalctl -u nginx | tail -n 20") && shown.contains("  | uptime"), "{shown}");
            assert!(shown.contains("Run this command once? [y/N]"), "{shown}");
            assert!(shown.contains("Namespace: dti/esi"), "the call names the namespace it runs in: {shown}");
        }
    }

    /// A web fetch is shown as one: the method, the whole path and the
    /// resource, and its own question.
    #[test]
    fn the_web_fetch_prompt_shows_the_method_and_path() {
        let args =
            serde_json::json!({ "resource": "grafana", "profile": "agent-api", "path": "/api/health?verbose=1" });
        let call = bv_mcp::dispatcher::session_call("bv_resource_web_fetch", args.as_object().unwrap()).unwrap();
        let detail = bv_mcp::local::render_session_detail(&call);
        let mut request = session_request(&call, &detail, None);
        request.tool = "bv_resource_web_fetch";
        request.destructive = false;
        let mut t = tty("y\n");
        assert_eq!(t.confirm(&request), Some(true));
        let shown = screen(&t);
        assert!(shown.contains("`claude-code` wants to fetch a page from `grafana`"), "{shown}");
        assert!(shown.contains("Request:   GET /api/health?verbose=1"), "{shown}");
        assert!(shown.contains("Fetch this page once? [y/N]"), "{shown}");
    }

    /// On a gated profile the operator is told who asks for MFA, types a
    /// TOTP code, and the call is allowed only once it verifies.
    #[test]
    fn the_session_prompt_collects_totp_and_a_failed_factor_denies() {
        let call = session_call("uptime");
        let detail = bv_mcp::local::render_session_detail(&call);
        let challenge = bv_mcp::local::MfaChallenge { methods: vec!["fido2".into(), "totp".into()], fido2: None };
        let typed_codes = std::cell::RefCell::new(Vec::new());
        let verify = |factor: MfaFactor| -> Result<(), String> {
            let MfaFactor::Totp(code) = factor else { return Err("not totp".into()) };
            typed_codes.borrow_mut().push(code.to_string());
            if code.as_str() == "123456" {
                Ok(())
            } else {
                Err("invalid TOTP code".into())
            }
        };
        let step = || bv_mcp::local::MfaStep { challenge: &challenge, verify: &verify };

        let mut t = tty("y\n123456\n");
        assert_eq!(t.confirm(&session_request(&call, &detail, Some(step()))), Some(true));
        let shown = screen(&t);
        assert!(
            shown.contains("`claude-code` is asking you to complete MFA to access `web-01` (profile `p_agent`)"),
            "{shown}"
        );
        assert!(shown.contains("Authenticator (TOTP) code:") && shown.contains("MFA verified."), "{shown}");

        let mut t = tty("y\n000000\n");
        assert_eq!(t.confirm(&session_request(&call, &detail, Some(step()))), Some(false));
        assert!(screen(&t).contains("MFA failed (invalid TOTP code): refused."));

        // A denial asks for no factor at all.
        let mut t = tty("n\n");
        assert_eq!(t.confirm(&session_request(&call, &detail, Some(step()))), Some(false));
        assert!(!screen(&t).contains("Authenticator"));
        assert_eq!(*typed_codes.borrow(), vec!["123456".to_string(), "000000".to_string()]);

        // A security key only: the terminal cannot take it, and says where to go.
        let keys_only = bv_mcp::local::MfaChallenge { methods: vec!["fido2".into()], fido2: None };
        let mut t = tty("y\n");
        let request =
            session_request(&call, &detail, Some(bv_mcp::local::MfaStep { challenge: &keys_only, verify: &verify }));
        assert_eq!(t.confirm(&request), Some(false));
        assert!(screen(&t).contains("desktop app"));
        assert_eq!(TtyPrompter::default().mfa_methods(), &["totp"]);
    }

    /// A question nobody answers in time is refused, and says so.
    #[test]
    fn an_unanswered_confirmation_is_refused_at_the_deadline() {
        let call = session_call("uptime");
        let detail = bv_mcp::local::render_session_detail(&call);
        let mut t = tty("y\n");
        t.deadline = Some(Instant::now());
        t.ready = |_, _| false;
        assert_eq!(t.confirm(&session_request(&call, &detail, None)), None);
        assert!(screen(&t).contains("No answer in time: refused."));
    }

    /// `bvault mcp pair` can grant brokered sessions; the session tool comes
    /// with the grant, confirmation is forced on, and reveal plus sessions
    /// shows the warning before it is allowed.
    #[test]
    fn pairing_at_the_terminal_can_grant_brokered_sessions() {
        let request = PairingRequest {
            client_name: "claude-code",
            client_version: "2.1",
            transport: Transport::Stdio,
            peer_uid: None,
            namespace: Some(""),
        };
        // approve, scope, default tools, no reveal, no writes, sessions yes, default TTL.
        let mut t = tty("y\nresources/secrets/web-01/\n\nn\nn\ny\n\n");
        let Some(PairingDecision::Approved(g)) = t.approve(&request) else { panic!("{}", screen(&t)) };
        assert!(g.connect_allowed && g.confirm_connect);
        assert!(g.tool_allowlist.iter().any(|t| t == "bv_resource_ssh_exec"));
        assert!(screen(&t).contains("every call is shown to you for approval"));
        assert!(screen(&t).contains("Namespace:  root"), "the approval names the namespace: {}", screen(&t));

        // Sessions declined: a session tool typed into the list is dropped.
        let mut t = tty("y\nsecret/*\nbv_whoami,bv_resource_ssh_exec\nn\nn\nn\n\n");
        let Some(PairingDecision::Approved(g)) = t.approve(&request) else { panic!("{}", screen(&t)) };
        assert!(!g.connect_allowed && !g.confirm_connect);
        assert_eq!(g.tool_allowlist, vec!["bv_whoami".to_string()]);

        // Reveal and sessions: the warning, and a second yes.
        let mut t = tty("y\nsecret/*\n\ny\ny\nn\ny\ny\n\n");
        let Some(PairingDecision::Approved(g)) = t.approve(&request) else { panic!("{}", screen(&t)) };
        assert!(g.reveal_allowed && g.connect_allowed);
        assert!(screen(&t).contains(TRIFECTA_WARNING));
        let mut t = tty("y\nsecret/*\n\ny\ny\nn\ny\nn\n");
        assert_eq!(t.approve(&request), Some(PairingDecision::Denied), "declining the warning denies");
    }

    struct HttpRig {
        link: Arc<FakeLink>,
        dir: std::path::PathBuf,
        addr: SocketAddr,
        bearer: String,
    }

    impl Drop for HttpRig {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn http_rig(name: &str, allowed_origins: Vec<String>) -> HttpRig {
        let dir = std::env::temp_dir().join(format!("bvault-mcp-serve-{name}-{}", new_pairing_id()));
        let link = Arc::new(FakeLink::default());
        let server = Arc::new(LocalServer::new(
            Box::new(SharedLink(link.clone())),
            Box::new(NoOperator),
            PairingStore::at(dir.join("mcp-pairings.json")),
        ));
        let bearer = new_pairing_token();
        let mut record = build_record(
            &PairingRequest {
                client_name: "web-client",
                client_version: "1",
                transport: Transport::LoopbackHttp,
                peer_uid: None,
                namespace: None,
            },
            &grant(),
            now_secs(),
        )
        .0;
        record.pairing_token_hash = Some(hash_token(&bearer));
        server.store().add(record).unwrap();

        let bound = bind_http("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = bound.addr;
        let serving = server.clone();
        thread::spawn(move || bound.run(serving, HttpConfig { allowed_origins }));
        HttpRig { link, dir, addr, bearer }
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

    fn post(
        addr: SocketAddr,
        host: Option<&str>,
        origin: Option<&str>,
        bearer: Option<&str>,
        body: &str,
    ) -> (u16, String) {
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
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": { "io.modelcontextprotocol/clientInfo": { "name": "web-client", "version": "1" } } },
        })
        .to_string()
    }

    // ── the operator's MFA calls (T457) ──────────────────────────────────

    type Seen = Arc<Mutex<Vec<(String, String, Vec<(String, String)>)>>>;

    /// A stand-in vault on loopback: answers each request with
    /// `answer(method, path)` and records `(method, path, headers)`.
    fn fake_vault(answer: impl Fn(&str, &str, &Value) -> Value + Send + 'static) -> (String, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let log = seen.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some((buf, head_len)) = read_head(&mut stream) else { continue };
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut req = httparse::Request::new(&mut headers);
                if req.parse(&buf[..head_len]).is_err() {
                    continue;
                }
                let (method, path) = (req.method.unwrap_or("").to_string(), req.path.unwrap_or("").to_string());
                let heads: Vec<(String, String)> = req
                    .headers
                    .iter()
                    .map(|h| (h.name.to_ascii_lowercase(), String::from_utf8_lossy(h.value).to_string()))
                    .collect();
                let length = heads
                    .iter()
                    .find(|(k, _)| k == "content-length")
                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let (mut received, mut chunk) = (buf[head_len..].to_vec(), [0u8; 4096]);
                while received.len() < length {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => received.extend_from_slice(&chunk[..n]),
                    }
                }
                let sent: Value = serde_json::from_slice(&received).unwrap_or(Value::Null);
                let body = serde_json::to_vec(&answer(&method, &path, &sent)).unwrap();
                lock(&log).push((method, path, heads));
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        (format!("http://{addr}"), seen)
    }

    /// `namespace: None` answers the lookup as a root token does: no
    /// `namespace_path` in its metadata at all.
    fn vault_answering(namespace: Option<&'static str>) -> impl Fn(&str, &str, &Value) -> Value + Send + 'static {
        move |_method, path, sent| {
            if path.ends_with("/auth/token/lookup-self") {
                let mut meta = json!({ "username": "felipe" });
                if let Some(ns) = namespace {
                    meta["namespace_path"] = json!(ns);
                }
                json!({ "data": { "meta": meta } })
            } else if path.ends_with("/connect/mfa/begin") {
                json!({ "data": { "required": true, "methods": ["totp"] } })
            } else if path.ends_with("/connect/mfa/verify") {
                json!({ "data": { "connect_ticket": "ticket-1" } })
            } else if path.ends_with("/v2/mcp/token") {
                // Bound where it was asked to narrow to, else the session's.
                let bound = sent.get("namespace").cloned().unwrap_or_else(|| json!(namespace.unwrap_or("")));
                json!({ "auth": { "client_token": "minted", "lease_duration": 60, "metadata": { "namespace": bound } } })
            } else {
                json!({})
            }
        }
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn mfa_round(link: &HttpVaultLink) -> Result<String, String> {
        mfa_round_in(link, None)
    }

    /// One begin + verify, in the token's namespace when the server knows it.
    fn mfa_round_in(link: &HttpVaultLink, namespace: Option<&str>) -> Result<String, String> {
        link.connect_mfa_begin(namespace, "web-01", "p_agent").map_err(|e| format!("{e:?}"))?;
        let call =
            McpCallRef { pairing_id: "p1".into(), tool: "bv_resource_ssh_exec".into(), args_hash: "ab".repeat(32) };
        let factor = MfaFactor::Totp(Zeroizing::new("123456".into()));
        link.connect_mfa_verify(namespace, "web-01", "p_agent", &factor, &call).map(|t| t.to_string())
    }

    /// The step-up preflight and verify run as the operator, in the
    /// namespace their own session is bound to (asked of the vault once),
    /// so the ticket binds where the pairing's token runs.
    #[test]
    fn the_operator_mfa_calls_carry_the_sessions_namespace() {
        let (addr, seen) = fake_vault(vault_answering(Some("tenant-a")));
        let client = Client::new().with_addr(&addr).with_token("operator-session-token").build();
        let link = HttpVaultLink::new(client);
        assert_eq!(mfa_round(&link).unwrap(), "ticket-1");
        assert_eq!(mfa_round(&link).unwrap(), "ticket-1");
        assert_eq!(link.operator_namespace().as_deref(), Some("tenant-a"));

        let seen = lock(&seen);
        assert_eq!(seen.iter().filter(|(_, p, _)| p.ends_with("lookup-self")).count(), 1, "asked once: {seen:?}");
        let mfa: Vec<_> = seen.iter().filter(|(_, p, _)| p.contains("/connect/mfa/")).collect();
        assert_eq!(mfa.len(), 4);
        for (_, path, headers) in mfa {
            assert_eq!(header(headers, "x-bastionvault-namespace"), Some("tenant-a"), "{path}");
            assert_eq!(header(headers, "x-bastionvault-token"), Some("operator-session-token"), "{path}");
        }
    }

    /// A root-bound session sends no namespace header, as before.
    #[test]
    fn a_root_session_sends_no_namespace_header() {
        let (addr, seen) = fake_vault(vault_answering(None));
        let link = HttpVaultLink::new(Client::new().with_addr(&addr).with_token("root-session").build());
        assert_eq!(mfa_round(&link).unwrap(), "ticket-1");
        assert_eq!(link.operator_namespace().as_deref(), Some(""));
        for (_, path, headers) in lock(&seen).iter() {
            assert_eq!(header(headers, "x-bastionvault-namespace"), None, "{path}");
        }
    }

    /// A namespace binding that does not normalize stops the step-up before
    /// anything is sent without it: never a silent fall back to root.
    #[test]
    fn a_malformed_session_namespace_refuses_the_step_up() {
        let (addr, seen) = fake_vault(vault_answering(Some("a/../b")));
        let link = HttpVaultLink::new(Client::new().with_addr(&addr).with_token("op").build());
        assert!(matches!(link.connect_mfa_begin(None, "web-01", "p_agent"), Err(MfaBeginError::Other(_))));
        assert_eq!(link.operator_namespace(), None);
        assert!(lock(&seen).iter().all(|(_, p, _)| !p.contains("/connect/mfa/")), "nothing sent without the header");
    }

    /// T457 Phase 2: the exchange asks for the server's narrowing (and only
    /// then names a namespace), the answer's binding is read back, and the
    /// operator's step-up then runs in the token's namespace, not the
    /// session's, without asking the vault where the session is.
    #[test]
    fn a_narrowed_exchange_and_its_step_up_name_the_tokens_namespace() {
        let (addr, seen) = fake_vault(vault_answering(Some("dti")));
        let link = HttpVaultLink::new(Client::new().with_addr(&addr).with_token("operator-session-token").build());
        let record = pairing_record_for_tests();
        let minted = link.exchange_pairing(&record, 60, Some("dti/esi")).unwrap();
        assert_eq!(minted.namespace.as_deref(), Some("dti/esi"));
        let plain = link.exchange_pairing(&record, 60, None).unwrap();
        assert_eq!(plain.namespace.as_deref(), Some("dti"), "no narrowing: the session's namespace");
        assert_eq!(mfa_round_in(&link, minted.namespace.as_deref()).unwrap(), "ticket-1");

        let seen = lock(&seen);
        assert!(seen.iter().all(|(_, p, _)| !p.ends_with("lookup-self")), "the token's namespace was known: {seen:?}");
        for (_, path, headers) in seen.iter().filter(|(_, p, _)| p.contains("/connect/mfa/")) {
            assert_eq!(header(headers, "x-bastionvault-namespace"), Some("dti/esi"), "{path}");
        }
        for (_, path, headers) in seen.iter().filter(|(_, p, _)| p.ends_with("/v2/mcp/token")) {
            assert_eq!(header(headers, "x-bastionvault-namespace"), None, "the exchange is not header-routed: {path}");
        }
    }

    fn pairing_record_for_tests() -> PairingRecord {
        PairingRecord {
            version: 1,
            id: "0123456789abcdef0123456789abcdef".into(),
            client_name: "claude-code".into(),
            client_version: "2.1".into(),
            peer_uid: None,
            transport: "stdio".into(),
            pairing_token_hash: None,
            tool_allowlist: vec!["bv_whoami".into()],
            path_scope: vec!["secret/*".into()],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            connect_allowed: false,
            confirm_connect: false,
            ttl_secs: 60,
            approved_at: 0,
            expires_at: None,
            last_used_at: 0,
            namespace: None,
        }
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

    #[test]
    fn http_happy_path_relays_with_a_paired_bearer() {
        let h = http_rig("http-ok", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        let (status, body) = post(h.addr, Some(&host), None, Some(&h.bearer), &list_body());
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("\"relayed\":true"));
        assert!(!body.contains(MINTED), "the minted token never reaches the client");
        assert_eq!(lock(&h.link.forwards)[0].0, MINTED);
    }

    #[test]
    fn http_foreign_origin_is_403_and_never_reaches_the_vault() {
        let h = http_rig("http-origin", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        let (status, _) = post(h.addr, Some(&host), Some("https://evil.example.com"), Some(&h.bearer), &list_body());
        assert_eq!(status, 403);
        assert_eq!(h.link.exchanges.load(Ordering::SeqCst), 0);
        assert!(lock(&h.link.forwards).is_empty());
    }

    #[test]
    fn http_allowed_origin_passes_and_others_still_fail() {
        let h = http_rig("http-origin-allow", vec!["https://app.example.com".into()]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        assert_eq!(post(h.addr, Some(&host), Some("https://app.example.com"), Some(&h.bearer), &list_body()).0, 200);
        assert_eq!(
            post(h.addr, Some(&host), Some("https://app.example.com.evil.test"), Some(&h.bearer), &list_body()).0,
            403
        );
    }

    #[test]
    fn http_rebinding_host_is_403() {
        let h = http_rig("http-host", vec![]);
        for host in [Some("evil.example.com"), Some("evil.example.com:80"), Some("127.0.0.1:1"), None] {
            let (status, _) = post(h.addr, host, None, Some(&h.bearer), &list_body());
            assert_eq!(status, 403, "Host {host:?} must be refused");
        }
        assert!(lock(&h.link.forwards).is_empty());
    }

    #[test]
    fn http_requires_a_known_bearer() {
        let h = http_rig("http-auth", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        assert_eq!(post(h.addr, Some(&host), None, None, &list_body()).0, 401);
        assert_eq!(post(h.addr, Some(&host), None, Some("not-a-paired-token"), &list_body()).0, 401);
        assert_eq!(h.link.exchanges.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn http_rejects_other_methods_paths_and_bad_framing() {
        let h = http_rig("http-shape", vec![]);
        let host = format!("127.0.0.1:{}", h.addr.port());
        assert_eq!(raw(h.addr, &format!("GET {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n\r\n")).0, 405);
        assert_eq!(
            raw(h.addr, &format!("POST /elsewhere HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n")).0,
            404
        );

        let auth = format!("Authorization: Bearer {}\r\n", h.bearer);
        let oversized = format!(
            "POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Length: {}\r\n\r\n",
            MAX_MESSAGE_BYTES + 1
        );
        assert_eq!(raw(h.addr, &oversized).0, 413);
        let chunked =
            format!("POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
        assert_eq!(raw(h.addr, &chunked).0, 501);
        let no_length = format!("POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}\r\n");
        assert_eq!(raw(h.addr, &no_length).0, 411);
        let dup_length = format!(
            "POST {HTTP_PATH} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert_eq!(raw(h.addr, &dup_length).0, 411);
        assert!(lock(&h.link.forwards).is_empty());
    }
}
