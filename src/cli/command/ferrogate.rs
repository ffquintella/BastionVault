//! `bvault ferrogate` — authenticate this machine to BastionVault using a
//! FerroGate-issued, DPoP-bound child token obtained from the local MIA.
//!
//! Subcommands:
//! - `login`  — mint a child token from the MIA, prove possession via DPoP, and
//!   exchange it at `auth/<mount>/login` for a BastionVault token.
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
    /// Report this machine's enrolment status.
    Status(Status),
    /// Print this host's SPIFFE id (local; no server call).
    Whoami(Whoami),
}

impl Ferrogate {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            Commands::Login(c) => c.execute(),
            Commands::Status(c) => c.execute(),
            Commands::Whoami(c) => c.execute(),
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

        let socket = self.socket.clone().unwrap_or_else(ferrogate_mia::resolve_mia_socket);
        let dpop = DpopKey::generate();
        let child = ferrogate_mia::request_child_token(&socket, &audience, &dpop.jkt(), self.ttl)
            .map_err(|e| bv_error_string!(e))?;
        let proof = dpop.proof("POST", &audience);

        let client = self.client()?;
        let mut body = Map::new();
        body.insert("token".into(), Value::String(child.jws));
        body.insert("dpop".into(), Value::String(proof));

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
            None => {
                let msg = resp
                    .response_data
                    .as_ref()
                    .and_then(|d| d.get("data").or(Some(d)))
                    .and_then(|d| d.get("error"))
                    .and_then(|e| e.as_str())
                    .unwrap_or("login failed (no token issued)");
                Err(bv_error_string!(msg.to_string()))
            }
        }
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
        let socket = self.socket.clone().unwrap_or_else(ferrogate_mia::resolve_mia_socket);
        let dpop = DpopKey::generate();
        let child = ferrogate_mia::request_child_token(&socket, &audience, &dpop.jkt(), self.ttl)
            .map_err(|e| bv_error_string!(e))?;
        let proof = dpop.proof("POST", &audience);

        let client = self.client()?;
        let mut body = Map::new();
        body.insert("token".into(), Value::String(child.jws));
        body.insert("dpop".into(), Value::String(proof));

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

    /// Audience for the throwaway token minted to read the identity.
    #[arg(long, default_value = "urn:bvault:ferrogate:whoami")]
    audience: String,
}

impl CommandExecutor for Whoami {
    fn main(&self) -> Result<(), RvError> {
        let socket = self.socket.clone().unwrap_or_else(ferrogate_mia::resolve_mia_socket);
        let dpop = DpopKey::generate();
        let child = ferrogate_mia::request_child_token(&socket, &self.audience, &dpop.jkt(), 60)
            .map_err(|e| bv_error_string!(e))?;
        let spiffe = ferrogate_mia::jws_claim_str(&child.jws, "iss")
            .ok_or_else(|| bv_error_string!("could not read SPIFFE id from the minted token".to_string()))?;
        println!("{spiffe}");
        Ok(())
    }
}
