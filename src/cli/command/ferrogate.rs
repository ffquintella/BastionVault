//! `bvault ferrogate` — authenticate this machine to BastionVault using a
//! FerroGate-issued, DPoP-bound child token obtained from the local MIA.
//!
//! Subcommands:
//! - `login`  — mint a child token from the MIA, prove possession via DPoP, and
//!   exchange it at `auth/<mount>/login` for a BastionVault token.
//! - `token`  — same exchange as `login`, but print the minted token and its
//!   attributes as structured output (`--format json`) and never persist it —
//!   for applications that exec this at startup.
//! - `status` — report this machine's enrolment status without minting a vault
//!   token (verifies the FerroGate token server-side).
//! - `whoami` — print this host's SPIFFE id (read locally from a freshly minted
//!   token; no server call).

use clap::{Parser, Subcommand};
use derive_more::Deref;
use serde_json::{Map, Value};
use sysexits::ExitCode;

use super::ferrogate_mia::{self, DpopKey};
use crate::{
    bv_error_string,
    cli::{command, command::CommandExecutor, util},
    errors::RvError,
    EXIT_CODE_INSUFFICIENT_PARAMS,
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Authenticate this machine to BastionVault via FerroGate",
    long_about = r#"Authenticate a machine to BastionVault using its FerroGate hardware identity.

These commands talk to the local FerroGate Machine Identity Agent (MIA) over its
helper socket to obtain a short-lived, DPoP-bound child token, then exchange it
at the `ferrogate` auth method. A running MIA is required.

Log in (mints and stores a BastionVault token):

    $ bvault ferrogate login --audience https://vault.example.com

Check this machine's enrolment status:

    $ bvault ferrogate status --audience https://vault.example.com

Print this host's SPIFFE id:

    $ bvault ferrogate whoami"#
)]
pub struct Ferrogate {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authenticate and obtain a BastionVault token.
    Login(Login),
    /// Mint a machine token and print it as structured output (for apps; never persisted).
    Token(Token),
    /// Request self-enrolment of this machine (unauthenticated; awaits admin approval).
    Enroll(Enroll),
    /// Report this machine's enrolment status.
    Status(Status),
    /// Print this host's SPIFFE id (local; no server call).
    Whoami(Whoami),
    /// Derive a `ferrogate` mount config from the local MIA (and optionally apply it).
    Autoconfig(Autoconfig),
}

/// Resolve the MIA helper socket: an explicit `--socket` wins; otherwise read
/// the socket the installed MIA wrote for `--environment` (default `mia.toml`).
/// Validates the environment selector before it becomes part of a filename.
fn resolve_socket(socket: Option<&str>, environment: Option<&str>) -> Result<String, RvError> {
    if let Some(s) = socket {
        return Ok(s.to_string());
    }
    if let Some(env) = environment {
        ferrogate_mia::validate_environment(env).map_err(|e| bv_error_string!(e))?;
    }
    Ok(ferrogate_mia::resolve_mia_socket_for(environment))
}

/// Mint a DPoP-bound child token from the local MIA and build the request body
/// (`token` + `dpop` proof) for the mount's `login` / `status` endpoints.
fn mia_login_body(socket: &str, audience: &str, ttl: u32) -> Result<Map<String, Value>, RvError> {
    let dpop = DpopKey::generate();
    let child = ferrogate_mia::request_child_token(socket, audience, &dpop.jkt(), ttl)
        .map_err(|e| bv_error_string!(e))?;
    let proof = dpop.proof("POST", audience);

    let mut body = Map::new();
    body.insert("token".into(), Value::String(child.jws));
    body.insert("dpop".into(), Value::String(proof));
    Ok(body)
}

/// Pull a human-readable error out of a login response that minted no token.
fn login_error(resp: &crate::api::HttpResponse) -> String {
    resp.response_data
        .as_ref()
        .and_then(|d| d.get("data").or(Some(d)))
        .and_then(|d| d.get("error"))
        .and_then(|e| e.as_str())
        .unwrap_or("login failed (no token issued)")
        .to_string()
}

impl Ferrogate {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            Commands::Login(c) => c.execute(),
            Commands::Token(c) => c.execute(),
            Commands::Enroll(c) => c.execute(),
            Commands::Status(c) => c.execute(),
            Commands::Whoami(c) => c.execute(),
            Commands::Autoconfig(c) => c.execute(),
        }
    }
}

// ── login ────────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(about = "Authenticate and obtain a BastionVault token")]
pub struct Login {
    /// Audience the token is minted for; MUST match the mount's
    /// `expected_audience`. Defaults to the resolved server address.
    #[arg(long)]
    audience: Option<String>,

    /// MIA helper socket path. Defaults to the socket the installed MIA is
    /// configured with (`FERROGATE_HELPER_SOCKET`, then `mia.toml`).
    #[arg(long)]
    socket: Option<String>,

    /// MIA environment selector: resolve the socket from `mia-<env>.toml`
    /// instead of `mia.toml`. Mirrors `mia --environment <env>`. Ignored when
    /// `--socket` is given.
    #[arg(long)]
    environment: Option<String>,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    /// Requested child-token lifetime, seconds (MIA clamps to its max).
    #[arg(long, default_value_t = 300)]
    ttl: u32,

    /// Do not persist the issued token to the on-disk token helper.
    #[arg(long)]
    no_store: bool,

    /// Do not print the issued token.
    #[arg(long)]
    no_print: bool,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Login {
    fn main(&self) -> Result<(), RvError> {
        let audience = match &self.audience {
            Some(a) => a.clone(),
            None => self.resolved_address()?,
        };

        let socket = resolve_socket(self.socket.as_deref(), self.environment.as_deref())?;
        let body = mia_login_body(&socket, &audience, self.ttl)?;

        let client = self.client()?;
        let path = format!("auth/{}/login", self.mount.trim_matches('/'));
        let resp = client.logical().write(&path, Some(body))?;

        let token = resp
            .response_data
            .as_ref()
            .and_then(|d| d.get("auth"))
            .and_then(|a| a.get("client_token"))
            .and_then(|t| t.as_str());

        match token {
            Some(tok) => {
                if !self.no_store {
                    if let Err(e) = util::write_persisted_token(tok) {
                        eprintln!("warning: could not persist token: {e}");
                    }
                }
                if !self.no_print {
                    println!("{tok}");
                }
                Ok(())
            }
            None => Err(bv_error_string!(login_error(&resp))),
        }
    }
}

// ── token ────────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(
    about = "Mint a machine token and print it as structured output (for apps)",
    long_about = r#"Authenticate this machine via the local FerroGate MIA and print the minted
BastionVault machine token together with its attributes (policies, TTL,
SPIFFE id, ...). The token is NEVER persisted to the on-disk token helper,
so this is safe to run from applications without disturbing the host's
stored CLI session.

Intended for applications that exec this command at startup:

    $ bvault ferrogate token --format json
    $ bvault ferrogate token --field client_token

The minted token can be sent as `X-Vault-Token` on direct API calls, or
presented as the `machine_token` of an AppID (approle) login."#
)]
pub struct Token {
    /// Audience the token is minted for; MUST match the mount's
    /// `expected_audience`. Defaults to the resolved server address.
    #[arg(long)]
    audience: Option<String>,

    /// MIA helper socket path. Defaults to the socket the installed MIA is
    /// configured with (`FERROGATE_HELPER_SOCKET`, then `mia.toml`).
    #[arg(long)]
    socket: Option<String>,

    /// MIA environment selector: resolve the socket from `mia-<env>.toml`
    /// instead of `mia.toml`. Mirrors `mia --environment <env>`. Ignored when
    /// `--socket` is given.
    #[arg(long)]
    environment: Option<String>,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    /// Requested child-token lifetime, seconds (MIA clamps to its max).
    #[arg(long, default_value_t = 300)]
    ttl: u32,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::LogicalOutputOptions,
}

impl CommandExecutor for Token {
    fn main(&self) -> Result<(), RvError> {
        let audience = match &self.audience {
            Some(a) => a.clone(),
            None => self.resolved_address()?,
        };
        let socket = resolve_socket(self.socket.as_deref(), self.environment.as_deref())?;
        let body = mia_login_body(&socket, &audience, self.ttl)?;

        let client = self.client()?;
        let path = format!("auth/{}/login", self.mount.trim_matches('/'));
        let resp = client.logical().write(&path, Some(body))?;

        let auth = resp
            .response_data
            .as_ref()
            .and_then(|d| d.get("auth"))
            .and_then(|a| a.as_object())
            .filter(|a| a.get("client_token").and_then(Value::as_str).is_some_and(|t| !t.is_empty()));

        let Some(auth) = auth else {
            return Err(bv_error_string!(login_error(&resp)));
        };

        // Flatten to a single level so both `--field <name>` and the table
        // formatter work: metadata entries (spiffe_id, machine_id, ...) are
        // hoisted to top-level keys; auth keys win on collision.
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

        self.output.print_data(&Value::Object(Map::from_iter([("data".to_string(), Value::Object(out))])), self.output.field.as_deref())
    }
}

// ── enroll ───────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(
    about = "Request self-enrolment of this machine (unauthenticated)",
    long_about = r#"Ask a BastionVault server to register this machine's SPIFFE id.

Calls the mount's UNAUTHENTICATED self-enrolment endpoint
(auth/<mount>/enroll). It only creates a *pending* record for an administrator
to approve — it never returns a token and grants no access on its own. After an
administrator approves it, authenticate normally with `bvault ferrogate login`.

The endpoint must be enabled on the mount (`self_enroll_enabled`) and the caller
must satisfy its allow-list / block-list and per-source-IP rate limit.

    $ bvault ferrogate enroll --spiffe-id spiffe://ferrogate.prod/host/abc
    $ bvault ferrogate enroll            # read the id from the local MIA"#
)]
pub struct Enroll {
    /// SPIFFE id to register. When omitted, it is read from the local MIA (a
    /// throwaway token is minted just to read its `iss` claim).
    #[arg(long)]
    spiffe_id: Option<String>,

    /// Optional note shown to the approving administrator.
    #[arg(long)]
    comment: Option<String>,

    /// MIA helper socket path. Used only when `--spiffe-id` is omitted.
    #[arg(long)]
    socket: Option<String>,

    /// MIA environment selector (`mia-<env>.toml`). Used only when
    /// `--spiffe-id` is omitted; ignored when `--socket` is given.
    #[arg(long)]
    environment: Option<String>,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Enroll {
    fn main(&self) -> Result<(), RvError> {
        let spiffe_id = match &self.spiffe_id {
            Some(s) => s.trim().to_string(),
            None => {
                // Derive the identity from the local MIA: mint a throwaway
                // token purely to read its `iss` (SPIFFE id). No server call.
                let socket = resolve_socket(self.socket.as_deref(), self.environment.as_deref())?;
                let dpop = DpopKey::generate();
                let child =
                    ferrogate_mia::request_child_token(&socket, "urn:bvault:ferrogate:enroll", &dpop.jkt(), 60)
                        .map_err(|e| bv_error_string!(e))?;
                ferrogate_mia::jws_claim_str(&child.jws, "iss").ok_or_else(|| {
                    bv_error_string!("could not read SPIFFE id from the local MIA; pass --spiffe-id".to_string())
                })?
            }
        };

        let mut body = Map::new();
        body.insert("spiffe_id".into(), Value::String(spiffe_id));
        if let Some(c) = self.comment.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            body.insert("comment".into(), Value::String(c.to_string()));
        }

        let client = self.client()?;
        let path = format!("auth/{}/enroll", self.mount.trim_matches('/'));
        let resp = client.logical().write(&path, Some(body))?;

        // A gate refusal (disabled, allow/block-list, rate limit) comes back as
        // {"error": "..."} in the data envelope — surface it as a command error.
        if let Some(data) = resp.response_data.as_ref().and_then(|d| d.get("data")) {
            if let Some(err) = data.get("error").and_then(|e| e.as_str()) {
                return Err(bv_error_string!(err.to_string()));
            }
            self.output.print_value(data, true)?;
        } else {
            resp.print_debug_info();
        }
        Ok(())
    }
}

// ── status ───────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(about = "Report this machine's enrolment status")]
pub struct Status {
    #[arg(long)]
    audience: Option<String>,

    /// MIA helper socket path. Defaults to the installed MIA's configured
    /// socket (`FERROGATE_HELPER_SOCKET`, then `mia.toml`).
    #[arg(long)]
    socket: Option<String>,

    /// MIA environment selector: resolve the socket from `mia-<env>.toml`
    /// instead of `mia.toml`. Ignored when `--socket` is given.
    #[arg(long)]
    environment: Option<String>,

    #[arg(long, default_value = "ferrogate")]
    mount: String,

    #[arg(long, default_value_t = 300)]
    ttl: u32,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Status {
    fn main(&self) -> Result<(), RvError> {
        let audience = match &self.audience {
            Some(a) => a.clone(),
            None => self.resolved_address()?,
        };
        let socket = resolve_socket(self.socket.as_deref(), self.environment.as_deref())?;
        let body = mia_login_body(&socket, &audience, self.ttl)?;

        let client = self.client()?;
        let path = format!("auth/{}/status", self.mount.trim_matches('/'));
        let resp = client.logical().write(&path, Some(body))?;
        if let Some(data) = resp.response_data.as_ref().and_then(|d| d.get("data")) {
            self.output.print_value(data, true)?;
        } else {
            resp.print_debug_info();
        }
        Ok(())
    }
}

// ── whoami ───────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(about = "Print this host's SPIFFE id (local; no server call)")]
pub struct Whoami {
    /// MIA helper socket path. Defaults to the installed MIA's configured
    /// socket (`FERROGATE_HELPER_SOCKET`, then `mia.toml`).
    #[arg(long)]
    socket: Option<String>,

    /// MIA environment selector: resolve the socket from `mia-<env>.toml`
    /// instead of `mia.toml`. Ignored when `--socket` is given.
    #[arg(long)]
    environment: Option<String>,

    /// Audience for the throwaway token minted to read the identity.
    #[arg(long, default_value = "urn:bvault:ferrogate:whoami")]
    audience: String,
}

impl CommandExecutor for Whoami {
    fn main(&self) -> Result<(), RvError> {
        let socket = resolve_socket(self.socket.as_deref(), self.environment.as_deref())?;
        let dpop = DpopKey::generate();
        let child = ferrogate_mia::request_child_token(&socket, &self.audience, &dpop.jkt(), 60)
            .map_err(|e| bv_error_string!(e))?;
        let spiffe = ferrogate_mia::jws_claim_str(&child.jws, "iss")
            .ok_or_else(|| bv_error_string!("could not read SPIFFE id from the minted token".to_string()))?;
        println!("{spiffe}");
        Ok(())
    }
}

// ── autoconfig ─────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(
    about = "Derive a ferrogate mount config from the local MIA",
    long_about = r#"Build a ready-to-apply `ferrogate` auth-mount configuration from the FerroGate
MIA installed on this host.

Reads the CMIS endpoint + SPKI pin from mia.toml, the trust domain from the
signed allowlist, and fetches the live composite JWKS from CMIS. By default it
prints the resulting config; pass --apply to write it to `auth/<mount>/config`
on the resolved server (requires an authenticated token).

    $ bvault ferrogate autoconfig
    $ bvault ferrogate autoconfig --apply --audience https://vault.example.com"#
)]
pub struct Autoconfig {
    /// Audience to set as `expected_audience`. Defaults to the resolved server
    /// address (the value `login` would mint for).
    #[arg(long)]
    audience: Option<String>,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    /// MIA environment selector: read `mia-<env>.toml` (CMIS endpoint/pin) and
    /// the matching allowlist instead of `mia.toml`. Mirrors
    /// `mia --environment <env>`.
    #[arg(long)]
    environment: Option<String>,

    /// Write the derived config to `auth/<mount>/config` instead of just
    /// printing it. Requires an authenticated token.
    #[arg(long)]
    apply: bool,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Autoconfig {
    fn main(&self) -> Result<(), RvError> {
        let audience = match &self.audience {
            Some(a) => a.clone(),
            None => self.resolved_address()?,
        };
        if let Some(env) = &self.environment {
            ferrogate_mia::validate_environment(env).map_err(|e| bv_error_string!(e))?;
        }

        // build_autoconfig fetches the JWKS over async gRPC; the CLI has no
        // ambient runtime, so spin a single-threaded one for the call.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| bv_error_string!(format!("could not start async runtime: {e}")))?;
        let cfg = rt
            .block_on(ferrogate_mia::build_autoconfig(audience, self.environment.as_deref()))
            .map_err(|e| bv_error_string!(e))?;

        for w in &cfg.warnings {
            eprintln!("warning: {w}");
        }

        if self.apply {
            let client = self.client()?;
            let mut body = Map::new();
            body.insert("trust_domain".into(), Value::String(cfg.trust_domain.clone()));
            body.insert("expected_audience".into(), Value::String(cfg.expected_audience.clone()));
            body.insert("jwks_source".into(), Value::String(cfg.jwks_source.clone()));
            body.insert("cmis_endpoint".into(), Value::String(cfg.cmis_endpoint.clone()));
            body.insert("cmis_srv".into(), Value::String(cfg.cmis_srv.clone()));
            body.insert("cmis_spki_pins".into(), Value::String(cfg.cmis_spki_pins.join(",")));
            body.insert("cmis_tls_enable".into(), Value::Bool(cfg.cmis_tls_enable));

            let path = format!("auth/{}/config", self.mount.trim_matches('/'));
            client.logical().write(&path, Some(body))?;
            // Report whichever CMIS locator was configured — the SRV name for
            // an HA cluster, otherwise the literal endpoint.
            let cmis = if cfg.cmis_srv.is_empty() {
                format!("cmis_endpoint={}", cfg.cmis_endpoint)
            } else {
                format!("cmis_srv={}", cfg.cmis_srv)
            };
            println!(
                "configured {path}: trust_domain={:?}, {cmis}, {} key(s) {:?}",
                cfg.trust_domain,
                cfg.jwks_kids.len(),
                cfg.jwks_kids
            );
            Ok(())
        } else {
            let value = serde_json::to_value(&cfg).map_err(|e| bv_error_string!(e.to_string()))?;
            self.output.print_value(&value, true)?;
            Ok(())
        }
    }
}
