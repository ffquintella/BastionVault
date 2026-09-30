//! `bvault mcp` -- give AI assistants scoped access to BastionVault over the
//! Model Context Protocol. See `features/mcp-access.md`.
//!
//! - `serve`     -- the local MCP server for this workstation's assistants.
//! - `pair`      -- approve a local client by hand (interactive).
//! - `pairings`  -- list or revoke approved clients.
//! - `token`     -- exchange the current login for an MCP-bound token (apps).
//! - `catalogue` -- print the tool catalogue and its pinnable hash.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use bv_mcp::pairing::{now_secs, PairingStore, Transport};
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use derive_more::Deref;
use serde_json::{json, Map, Value};
use sysexits::ExitCode;

use super::mcp_serve::{
    self, bind_http, build_record, delete_status, parse_loopback_addr, serve_stdio, vault_error_text, HttpConfig,
    HttpVaultLink, LocalServer, PairingDecision, PairingRequest, Prompter, TtyPrompter, HTTP_PATH,
};
use crate::{bv_error_string, command, command::CommandExecutor, errors::RvError, EXIT_CODE_INSUFFICIENT_PARAMS};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Give AI assistants scoped, audited access to BastionVault (MCP)",
    long_about = r#"Expose BastionVault to AI assistants over the Model Context Protocol without
handing them a vault token.

On a workstation, run the local server and point your assistant at it. Each
client is paired once, by you, at a terminal, with an explicit scope:

    $ bvault mcp pair --client-name claude-desktop
    $ bvault mcp serve                       # stdio; the assistant launches this
    $ bvault mcp serve --socket ~/.bvault/mcp.sock
    $ bvault mcp serve --listen 127.0.0.1:8250

An application on a server obtains a short-lived MCP-bound token for a
registered MCP app and calls the vault's /v2/mcp endpoint directly:

    $ bvault mcp token --app ci-secrets-reader --format json

Print the tool catalogue and its hash (to pin in `sys/mcp/config`):

    $ bvault mcp catalogue"#
)]
pub struct Mcp {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the local MCP server for this workstation's AI assistants.
    Serve(Serve),
    /// Approve a local MCP client by hand (needs a terminal).
    Pair(Pair),
    /// List or revoke approved local clients.
    Pairings(Pairings),
    /// Exchange the current login for an MCP-bound token for an MCP app.
    Token(Token),
    /// Print the tool catalogue and its hash.
    Catalogue(Catalogue),
}

impl Mcp {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            Commands::Serve(c) => c.execute(),
            Commands::Pair(c) => c.execute(),
            Commands::Pairings(c) => c.execute(),
            Commands::Token(c) => c.execute(),
            Commands::Catalogue(c) => c.execute(),
        }
    }
}

/// `--transport`'s values. The library's [`Transport`] stays free of clap.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum TransportArg {
    Stdio,
    Uds,
    LoopbackHttp,
}

impl From<TransportArg> for Transport {
    fn from(t: TransportArg) -> Self {
        match t {
            TransportArg::Stdio => Transport::Stdio,
            TransportArg::Uds => Transport::Uds,
            TransportArg::LoopbackHttp => Transport::LoopbackHttp,
        }
    }
}

fn pairing_store(path: &Option<PathBuf>) -> Result<PairingStore, RvError> {
    Ok(PairingStore::at(match path {
        Some(p) => p.clone(),
        None => PairingStore::default_path()?,
    }))
}

#[cfg(unix)]
fn default_peer_uid() -> Option<u32> {
    Some(mcp_serve::uds::current_uid())
}

#[cfg(not(unix))]
fn default_peer_uid() -> Option<u32> {
    None
}

// ── serve ────────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(
    about = "Run the local MCP server for this workstation's AI assistants",
    long_about = r#"Run the local MCP server. It authenticates nothing itself: it works out which
client is connecting, checks you approved it, mints an MCP-bound token from YOUR
login narrowed to the scope you approved, and forwards the request to the
vault's /v2/mcp endpoint. The vault still enforces every tool gate, path scope,
ACL and audit rule.

Transports (pick one; stdio is the default):

  --stdio            MCP over stdin/stdout, for assistants that launch it.
  --socket <PATH>    A Unix socket, created owner-only; a peer with any other
                     uid is dropped before a byte is read.
  --listen <ADDR>    HTTP on a loopback address only (127.0.0.1:PORT or
                     [::1]:PORT). Clients need a pairing token from `bvault mcp
                     pair --transport loopback-http`; foreign Origin and Host
                     headers are refused.

A client that is not yet paired can only be approved at a terminal. With no
terminal (an assistant launching this headlessly), pairing and per-call
confirmations fail closed -- run `bvault mcp pair` first."#
)]
#[command(group(ArgGroup::new("transport").multiple(false).args(["stdio", "socket", "listen"])))]
pub struct Serve {
    /// Speak MCP over stdin/stdout (the default).
    #[arg(long)]
    stdio: bool,

    /// Listen on a Unix socket at this path (owner-only). Unix only.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Listen for HTTP on a loopback address, e.g. 127.0.0.1:8250.
    #[arg(long, value_name = "ADDR", value_parser = parse_loopback_addr)]
    listen: Option<SocketAddr>,

    /// Browser origin allowed to call the loopback HTTP server. Repeatable.
    /// Default: none -- only non-browser clients (no `Origin` header).
    #[arg(long = "allowed-origin", value_name = "ORIGIN")]
    allowed_origins: Vec<String>,

    /// Pairing store location (default: $XDG_CONFIG_HOME/bvault/mcp-pairings.json).
    #[arg(long, value_name = "PATH", env = "BVAULT_MCP_PAIRINGS_FILE")]
    pairings_file: Option<PathBuf>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for Serve {
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        if client.token.is_empty() {
            return Err(bv_error_string!(
                "no vault token: run `bvault login` first, or pass --token / set VAULT_TOKEN"
            ));
        }
        let store = pairing_store(&self.pairings_file)?;
        let server =
            Arc::new(LocalServer::new(Box::new(HttpVaultLink::new(client)), Box::new(TtyPrompter::default()), store));

        if let Some(addr) = self.listen {
            let bound = bind_http(addr)?;
            eprintln!("bvault mcp: serving HTTP on http://{}{HTTP_PATH} (loopback only)", bound.addr);
            bound.run(server, HttpConfig { allowed_origins: self.allowed_origins.clone() });
            return Ok(());
        }
        if let Some(path) = &self.socket {
            #[cfg(unix)]
            return mcp_serve::uds::serve(server, path);
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(bv_error_string!("--socket needs Unix domain sockets, which this platform lacks"));
            }
        }
        // Diagnostics go to stderr: on stdio, stdout *is* the MCP channel.
        eprintln!("bvault mcp: serving on stdio");
        serve_stdio(&server)
    }
}

// ── pair ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    about = "Approve a local MCP client by hand (needs a terminal)",
    long_about = r#"Approve a local MCP client and record what it may do. You are shown who is
asking and choose the scope (path globs, tools, whether it may reveal values or
make changes). Needs an interactive terminal -- a non-interactive environment
cannot pair.

The --client-name must match the name the client sends in its MCP `clientInfo`
(for Claude Desktop, the name shown in its MCP server list).

For --transport loopback-http a pairing token is generated and shown ONCE:
configure it as the client's `Authorization: Bearer` value."#
)]
pub struct Pair {
    /// The client's `clientInfo.name`.
    #[arg(long, value_name = "NAME")]
    client_name: String,

    /// The client's version, shown to you when approving.
    #[arg(long, value_name = "VERSION", default_value = "")]
    client_version: String,

    #[arg(long, value_enum, default_value_t = TransportArg::Stdio)]
    transport: TransportArg,

    /// For --transport uds: the uid of the client process (default: yours).
    #[arg(long, value_name = "UID")]
    peer_uid: Option<u32>,

    /// Pairing store location (default: $XDG_CONFIG_HOME/bvault/mcp-pairings.json).
    #[arg(long, value_name = "PATH", env = "BVAULT_MCP_PAIRINGS_FILE")]
    pairings_file: Option<PathBuf>,
}

impl CommandExecutor for Pair {
    fn main(&self) -> Result<(), RvError> {
        let name = self.client_name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(bv_error_string!("--client-name must be 1 to 128 characters"));
        }
        let transport: Transport = self.transport.into();
        let peer_uid = match transport {
            Transport::Uds => {
                let uid = self.peer_uid.or_else(default_peer_uid);
                if uid.is_none() {
                    return Err(bv_error_string!(
                        "--transport uds needs Unix domain sockets, which this platform lacks"
                    ));
                }
                uid
            }
            _ => None,
        };
        let store = pairing_store(&self.pairings_file)?;
        let request =
            PairingRequest { client_name: name, client_version: self.client_version.trim(), transport, peer_uid };

        let decision = TtyPrompter::default().approve(&request).ok_or_else(|| {
            bv_error_string!("pairing needs an interactive terminal, and none is available; run this from a terminal")
        })?;
        let PairingDecision::Approved(grant) = decision else {
            println!("Not paired.");
            return Ok(());
        };

        let (record, bearer) = build_record(&request, &grant, now_secs());
        let id = record.id.clone();
        store.upsert(record)?;
        println!("Paired `{name}` over {} (pairing id {id}).", transport.as_str());
        if let Some(token) = bearer {
            println!();
            println!("Pairing token (shown once -- it is not stored):");
            println!("  {token}");
            println!("Configure the client to send `Authorization: Bearer <token>` to POST {HTTP_PATH}.");
        }
        Ok(())
    }
}

// ── pairings ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(about = "List or revoke approved local clients")]
pub struct Pairings {
    #[command(subcommand)]
    command: Option<PairingsCommands>,
}

#[derive(Subcommand)]
pub enum PairingsCommands {
    /// List approved clients.
    List(PairingsList),
    /// Revoke one approved client, including its tokens on the vault.
    Revoke(PairingsRevoke),
}

impl Pairings {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            PairingsCommands::List(c) => c.execute(),
            PairingsCommands::Revoke(c) => c.execute(),
        }
    }
}

#[derive(Parser)]
#[command(about = "List approved clients")]
pub struct PairingsList {
    /// Pairing store location (default: $XDG_CONFIG_HOME/bvault/mcp-pairings.json).
    #[arg(long, value_name = "PATH", env = "BVAULT_MCP_PAIRINGS_FILE")]
    pairings_file: Option<PathBuf>,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for PairingsList {
    fn main(&self) -> Result<(), RvError> {
        let records = pairing_store(&self.pairings_file)?.load()?;
        let now = now_secs();
        if !self.output.is_format_table() {
            let rows: Vec<Value> = records
                .iter()
                .map(|r| {
                    let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
                    v["expired"] = json!(r.is_expired(now));
                    v
                })
                .collect();
            return self.output.print_value(&Value::Array(rows), false);
        }
        if records.is_empty() {
            println!("No paired clients.");
            return Ok(());
        }
        println!(
            "{:<34} {:<24} {:<14} {:<6} {:<7} {:<7} STATE",
            "ID", "CLIENT", "TRANSPORT", "UID", "REVEAL", "WRITE"
        );
        for r in &records {
            let uid = r.peer_uid.map(|u| u.to_string()).unwrap_or_else(|| "-".into());
            let state = match r.expires_at {
                Some(t) if t <= now => "expired".to_string(),
                Some(t) => format!("{}d left", (t - now) / 86400),
                None => "no expiry".to_string(),
            };
            println!(
                "{:<34} {:<24} {:<14} {:<6} {:<7} {:<7} {}",
                r.id,
                r.client_name.chars().take(24).collect::<String>(),
                r.transport,
                uid,
                if r.reveal_allowed { "yes" } else { "no" },
                if r.destructive_allowed { "yes" } else { "no" },
                state
            );
        }
        Ok(())
    }
}

#[derive(Parser, Deref)]
#[command(
    about = "Revoke one approved client, including its tokens on the vault",
    long_about = r#"Remove a pairing so the client can no longer connect, and revoke every MCP token
the vault minted for it. The local record is removed first, so no new token can
be minted even if the vault is unreachable; in that case this command says so
and exits non-zero -- the orphaned tokens then expire on their own."#
)]
pub struct PairingsRevoke {
    /// The pairing id (from `bvault mcp pairings list`).
    id: String,

    /// Pairing store location (default: $XDG_CONFIG_HOME/bvault/mcp-pairings.json).
    #[arg(long, value_name = "PATH", env = "BVAULT_MCP_PAIRINGS_FILE")]
    pairings_file: Option<PathBuf>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,
}

impl CommandExecutor for PairingsRevoke {
    fn main(&self) -> Result<(), RvError> {
        let id = self.id.trim();
        let store = pairing_store(&self.pairings_file)?;
        let Some(record) = store.remove(id)? else {
            return Err(bv_error_string!(format!("no pairing with id `{id}`")));
        };
        println!("Removed pairing {id} (`{}`) from this machine.", record.client_name);

        let client = self.client()?;
        match delete_status(&client, &format!("v2/sys/mcp/pairings/{id}")) {
            Ok(status) if (200..300).contains(&status) => {
                println!("Revoked its outstanding tokens on the vault.");
                Ok(())
            }
            Ok(status) => Err(bv_error_string!(format!(
                "the pairing is removed locally, but the vault did not revoke its tokens (HTTP {status}); they expire on their own within {} hours",
                record.ttl_secs / 3600
            ))),
            Err(e) => Err(bv_error_string!(format!(
                "the pairing is removed locally, but the vault could not be reached to revoke its tokens ({e}); they expire on their own within {} hours",
                record.ttl_secs / 3600
            ))),
        }
    }
}

// ── token ────────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(
    about = "Exchange the current login for an MCP-bound token (for MCP apps)",
    long_about = r#"Exchange the login this command runs under for a short-lived MCP-bound token for
a registered MCP app, and print it with its attributes. The token is NEVER
persisted, so this is safe to exec from an application at startup.

The login must be the AppID login for the app's role, made with a live FerroGate
machine token (or under the app's machine-identity waiver). An MCP-bound token
works only against the vault's /v2/mcp endpoint -- every other path refuses it.

    $ bvault mcp token --app ci-secrets-reader --format json
    $ bvault mcp token --app ci-secrets-reader --field client_token"#
)]
pub struct Token {
    /// The MCP app to exchange for (`sys/mcp/apps/<name>`).
    #[arg(long, value_name = "NAME")]
    app: String,

    /// Requested lifetime in seconds (clamped to the app's configured maximum).
    #[arg(long, value_name = "SECONDS")]
    ttl_secs: Option<u64>,

    /// Narrow the token to a subset of the login's policies. Comma-separated.
    #[arg(long, value_delimiter = ',', value_name = "POLICY")]
    policies: Vec<String>,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::LogicalOutputOptions,
}

impl CommandExecutor for Token {
    fn main(&self) -> Result<(), RvError> {
        let mut body = Map::new();
        body.insert("app".into(), Value::String(self.app.trim().to_string()));
        body.insert("catalogue_hash".into(), Value::String(bv_mcp::catalogue::catalogue_hash()));
        if let Some(ttl) = self.ttl_secs {
            body.insert("ttl_secs".into(), json!(ttl));
        }
        if !self.policies.is_empty() {
            body.insert("policies".into(), Value::String(self.policies.join(",")));
        }

        let client = self.client()?;
        let resp = client.request_write("v2/mcp/token", Some(body))?;
        if resp.response_status != 200 {
            return Err(bv_error_string!(vault_error_text(&resp.response_data, resp.response_status)));
        }
        let data = resp.response_data.unwrap_or(Value::Null);
        let auth = data
            .get("auth")
            .or_else(|| data.get("data").and_then(|d| d.get("auth")))
            .and_then(Value::as_object)
            .filter(|a| a.get("client_token").and_then(Value::as_str).is_some_and(|t| !t.is_empty()));
        let Some(auth) = auth else {
            return Err(bv_error_string!("the vault's exchange response carried no token"));
        };

        // Flattened to one level so `--field <name>` and the table formatter
        // both work: metadata is hoisted, auth keys win on collision.
        let mut out = Map::new();
        if let Some(meta) = auth.get("metadata").and_then(Value::as_object) {
            for (k, v) in meta {
                out.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in auth {
            if k != "metadata" && !v.is_null() {
                out.insert(k.clone(), v.clone());
            }
        }
        self.output.print_data(
            &Value::Object(Map::from_iter([("data".to_string(), Value::Object(out))])),
            self.output.field.as_deref(),
        )
    }
}

// ── catalogue ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    about = "Print the tool catalogue and its hash",
    long_about = r#"Print every tool this build offers and the BLAKE3 hash of the catalogue. The hash
is what `sys/mcp/config`'s `catalogue_pin` compares against: a change to any
tool description or schema changes it, so pinning it turns such a change into a
deliberate upgrade step. Computed locally; no vault is contacted."#
)]
pub struct Catalogue {
    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Catalogue {
    fn main(&self) -> Result<(), RvError> {
        let hash = bv_mcp::catalogue::catalogue_hash();
        let list = bv_mcp::catalogue::tools_list_json();
        let tools = list.get("tools").cloned().unwrap_or(Value::Array(vec![]));
        if !self.output.is_format_table() {
            return self.output.print_value(&json!({ "catalogue_hash": hash, "tools": tools }), false);
        }
        println!("catalogue_hash: {hash}");
        println!();
        println!("{:<24} {:<10} DESCRIPTION", "TOOL", "KIND");
        for t in bv_mcp::catalogue::catalogue() {
            let kind = match (t.destructive, t.is_reveal) {
                (true, true) => "write+reveal",
                (true, false) => "write",
                (false, true) => "reveal",
                (false, false) => "read",
            };
            println!("{:<24} {:<10} {}", t.name, kind, t.description);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        command::mcp_serve::{ConfirmRequest, ConnInfo, PairingGrant},
        test_utils::TestHttpServer,
    };

    // ── command line ─────────────────────────────────────────────────────

    #[test]
    fn serve_refuses_a_non_loopback_listen_address() {
        for bad in ["0.0.0.0:8250", "192.168.1.5:8250", "[::]:8250"] {
            let err = Serve::try_parse_from(["serve", "--listen", bad]).err().expect("must be a usage error");
            assert!(err.to_string().contains("loopback"), "{bad}: {err}");
        }
        assert!(Serve::try_parse_from(["serve", "--listen", "127.0.0.1:8250"]).is_ok());
    }

    #[test]
    fn serve_transports_are_mutually_exclusive() {
        assert!(Serve::try_parse_from(["serve", "--stdio", "--socket", "/tmp/x"]).is_err());
        assert!(Serve::try_parse_from(["serve", "--socket", "/tmp/x", "--listen", "127.0.0.1:1"]).is_err());
        assert!(Serve::try_parse_from(["serve"]).is_ok(), "stdio is the default");
    }

    #[test]
    fn catalogue_prints_without_a_vault() {
        for format in ["table", "json"] {
            Catalogue::try_parse_from(["catalogue", "--format", format]).unwrap().main().unwrap();
        }
    }

    // ── against a real vault ─────────────────────────────────────────────

    /// Approves pairings while `allow` is set; once cleared, nobody is
    /// reachable, as with a headless process.
    struct Approves {
        grant: PairingGrant,
        allow: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Prompter for Approves {
        fn approve(&self, _request: &PairingRequest<'_>) -> Option<PairingDecision> {
            self.allow.load(std::sync::atomic::Ordering::SeqCst).then(|| PairingDecision::Approved(self.grant.clone()))
        }

        fn confirm(&self, _request: &ConfirmRequest<'_>) -> Option<bool> {
            None
        }
    }

    fn call(id: u64, tool: &str, arguments: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": { "io.modelcontextprotocol/clientInfo": { "name": "claude-desktop", "version": "1.0" } },
            },
        }))
        .unwrap()
    }

    fn data_code(resp: &Value) -> &str {
        resp["error"]["data"]["code"].as_str().unwrap_or("")
    }

    /// The whole local flow against a real server: an operator logs in, a
    /// client is paired, the exchange mints a pairing-bound token over real
    /// HTTP, `/v2/mcp` answers through the real dispatcher (including its
    /// refusals), and `pairings revoke` cuts the token off on the vault.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn local_pairing_flow_against_a_real_vault() {
        let mut server = TestHttpServer::new("test_cli_mcp_local_flow", false).await;
        server.token = server.root_token.clone();
        let root = server.root_token.clone();

        server.mount_auth("userpass", "userpass").unwrap();
        server.mount("secret", "kv-v2").unwrap();
        let policy = r#"
            path "sys/mcp/token" { capabilities = ["update"] }
            path "sys/mcp/pairings/*" { capabilities = ["delete"] }
            path "secret/metadata/ai/*" { capabilities = ["read"] }
            path "secret/data/ai/*" { capabilities = ["read"] }
        "#;
        server.write("sys/policy/mcp-pairer", json!({ "policy": policy }).as_object().cloned(), Some(&root)).unwrap();
        server
            .write(
                "auth/userpass/users/felipe",
                json!({ "password": "pw", "policies": "mcp-pairer" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        server.write("secret/data/ai/x", json!({ "data": { "k": "v" } }).as_object().cloned(), Some(&root)).unwrap();
        let (_, login) =
            server.login("auth/userpass/login/felipe", json!({ "password": "pw" }).as_object().cloned(), None).unwrap();
        let operator = login["auth"]["client_token"].as_str().expect("operator login token").to_string();

        let mut client = server.client().unwrap();
        client.token = operator.clone();

        let dir = std::env::temp_dir().join(format!("bvault-mcp-e2e-{}", bv_mcp::pairing::new_pairing_id()));
        let store_path = dir.join("mcp-pairings.json");
        let grant = PairingGrant {
            tool_allowlist: vec!["bv_kv_read_metadata".into(), "bv_kv_read".into()],
            path_scope: vec!["secret/metadata/ai/*".into(), "secret/data/ai/*".into()],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            ttl_secs: 3600,
        };
        let operator_present = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let local = LocalServer::new(
            Box::new(HttpVaultLink::new(client)),
            Box::new(Approves { grant, allow: operator_present.clone() }),
            PairingStore::at(store_path.clone()),
        );
        let conn = ConnInfo { transport: Transport::Stdio, peer_uid: None, preauthenticated: None };

        // Pairs on first contact, mints over real HTTP, and the dispatcher answers.
        let ok = local
            .handle_message(&conn, &call(1, "bv_kv_read_metadata", json!({ "mount": "secret", "path": "ai/x" })))
            .unwrap();
        assert_eq!(ok["result"]["structuredContent"]["current_version"], json!(1), "{ok}");

        // The vault's own gates still apply behind the proxy.
        let out_of_scope = local
            .handle_message(&conn, &call(2, "bv_kv_read_metadata", json!({ "mount": "secret", "path": "other/y" })))
            .unwrap();
        assert!(out_of_scope.get("error").is_some(), "{out_of_scope}");
        let not_granted = local
            .handle_message(&conn, &call(3, "bv_transit_encrypt", json!({ "key": "k", "plaintext": "eA==" })))
            .unwrap();
        assert!(not_granted.get("error").is_some(), "a tool outside the allow-list is refused: {not_granted}");
        let redacted =
            local.handle_message(&conn, &call(4, "bv_kv_read", json!({ "mount": "secret", "path": "ai/x" }))).unwrap();
        assert_eq!(redacted["result"]["structuredContent"]["data"], json!("<redacted>"), "{redacted}");
        let denied_reveal = local
            .handle_message(&conn, &call(5, "bv_kv_read", json!({ "mount": "secret", "path": "ai/x", "reveal": true })))
            .unwrap();
        assert_eq!(data_code(&denied_reveal), "mcp_reveal_denied", "{denied_reveal}");

        // One pairing token exists on the vault, tagged as a pairing's.
        let (_, tokens) = server.list("sys/mcp/tokens", Some(&root)).unwrap();
        assert_eq!(tokens["tokens"][0]["kind"], json!("pairing"), "{tokens}");
        let records = PairingStore::at(store_path.clone()).load().unwrap();
        assert_eq!(records.len(), 1);
        let id = records[0].id.clone();

        // `pairings revoke`: local record gone AND the vault token revoked.
        let address = format!("http://{}", server.listen_addr);
        PairingsRevoke::try_parse_from([
            "revoke",
            id.as_str(),
            "--pairings-file",
            store_path.to_str().unwrap(),
            "--address",
            address.as_str(),
            "--token",
            operator.as_str(),
        ])
        .unwrap()
        .main()
        .unwrap();
        assert!(PairingStore::at(store_path.clone()).load().unwrap().is_empty());
        let (_, tokens) = server.list("sys/mcp/tokens", Some(&root)).unwrap();
        assert_eq!(tokens["tokens"], json!([]), "the vault revoked the pairing's tokens: {tokens}");

        // A revoked client cannot quietly come back on the still-running
        // server: with no operator to re-approve it, it is refused.
        operator_present.store(false, std::sync::atomic::Ordering::SeqCst);
        let after = local
            .handle_message(&conn, &call(6, "bv_kv_read_metadata", json!({ "mount": "secret", "path": "ai/x" })))
            .unwrap();
        assert_eq!(data_code(&after), "mcp_pairing_requires_operator", "{after}");
        let (_, tokens) = server.list("sys/mcp/tokens", Some(&root)).unwrap();
        assert_eq!(tokens["tokens"], json!([]), "and nothing new was minted for it: {tokens}");

        // Revoking an unknown pairing is an error, not a silent success.
        let missing = PairingsRevoke::try_parse_from([
            "revoke",
            "no-such-pairing",
            "--pairings-file",
            store_path.to_str().unwrap(),
            "--address",
            address.as_str(),
            "--token",
            operator.as_str(),
        ])
        .unwrap()
        .main();
        assert!(missing.is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
