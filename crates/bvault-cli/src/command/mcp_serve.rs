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
//! per-call confirmation, never a silent approval.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{atomic::AtomicUsize, Arc, Mutex, MutexGuard},
    time::Duration,
};

use bv_mcp::{
    catalogue,
    local::{
        exchange_request_body, minted_token_from_exchange, ConfirmRequest, ConnInfo, ConnectionSlot, ForwardError,
        LocalServer, MintedToken, PairingDecision, PairingGrant, PairingRequest, Prompter, VaultLink,
        MAX_MESSAGE_BYTES,
    },
    pairing::{
        self, find_by_token_hash, hash_token, now_secs, PairingRecord, Transport, DEFAULT_TOKEN_TTL_SECS,
        MAX_TOKEN_TTL_SECS,
    },
    sanitize::sanitize_for_model,
};
use serde_json::Value;
use zeroize::Zeroize;

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
}

impl HttpVaultLink {
    pub fn new(client: Client) -> Self {
        Self { client }
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
        let resp = self
            .client
            .request_write("v2/mcp/token", Some(exchange_request_body(record, ttl_secs)))
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
}

// ── operator side ────────────────────────────────────────────────────────

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
        tty.say(&format!(
            "  Client:     {} {}",
            sanitize_for_model(request.client_name),
            sanitize_for_model(request.client_version)
        ));
        tty.say(&format!("  Transport:  {}", request.transport.as_str()));
        if let Some(uid) = request.peer_uid {
            tty.say(&format!("  Peer uid:   {uid}"));
        }
        tty.say("  It will act with YOUR permissions, narrowed to the scope you choose below.");
        tty.say("");
        if !tty.yes_no("Approve this client?", false)? {
            return Some(PairingDecision::Denied);
        }

        let path_scope =
            split_list(&tty.ask("Path scope, comma-separated (e.g. secret/metadata/ai/*; empty denies every path): ")?);
        if path_scope.is_empty() {
            tty.say("  No path scope: every tool call will be refused until you re-pair with one.");
        }

        let defaults = pairing::default_tool_allowlist();
        tty.say(&format!("Default tools (read-only, never reveal a value): {}", defaults.join(", ")));
        let tools_in = tty.ask("Tools, comma-separated (Enter for the default list): ")?;
        let tool_allowlist = if tools_in.is_empty() { defaults } else { split_list(&tools_in) };
        if let Some(unknown) = tool_allowlist.iter().find(|t| catalogue::find(t).is_none()) {
            tty.say(&format!(
                "  `{}` is not a tool in this build's catalogue; denying the pairing.",
                sanitize_for_model(unknown)
            ));
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
        fn exchange_pairing(&self, _record: &PairingRecord, ttl_secs: u64) -> Result<MintedToken, String> {
            self.0.exchanges.fetch_add(1, Ordering::SeqCst);
            Ok(MintedToken { token: MINTED.to_string(), expires_at: now_secs() + ttl_secs })
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
            ttl_secs: 3600,
        }
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
