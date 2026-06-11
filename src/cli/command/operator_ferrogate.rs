//! `bvault operator ferrogate` — operator-side administration of the FerroGate
//! machine-identity enrolment queue, run against the server with a privileged
//! (root) token.
//!
//! Unlike `bvault ferrogate` (which authenticates *this* machine via the local
//! MIA), these subcommands manage *other* machines' enrolment: listing the
//! pending queue and approving / rejecting / revoking machines. They are plain
//! admin API calls against `auth/<mount>/machines...`, so they do NOT require
//! the operator's own machine to be approved — they only require a token with
//! the policy to write the ferrogate admin paths (typically root). This is the
//! escape hatch out of the bootstrap deadlock: an operator on the server can
//! authorize the first machine without already holding a machine token.
//!
//! Subcommands:
//! - `list`    — show enrolled machines (optionally filtered by status).
//! - `approve` — approve a machine and attach its policy set + TTL.
//! - `reject`  — reject a pending machine.
//! - `revoke`  — revoke a previously-approved machine.
//!
//! A machine is addressed by its handle (BLAKE3 hex of the SPIFFE ID, as shown
//! by `list`) or by its SPIFFE ID directly (auto-detected and hashed locally).

use clap::{Parser, Subcommand};
use derive_more::Deref;
use serde_json::{Map, Value};
use sysexits::ExitCode;

use crate::{
    cli::{command, command::CommandExecutor},
    errors::RvError,
    modules::credential::ferrogate::machine_id,
    EXIT_CODE_INSUFFICIENT_PARAMS,
};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Administer the FerroGate machine enrolment queue (operator/root)",
    long_about = r#"Operator-side administration of FerroGate machine enrolment.

These commands manage *other* machines' enrolment against the running server and
require a privileged (root) token, NOT an approved machine — so an operator on
the server can authorize the first machine and break the bootstrap deadlock.

List machines awaiting approval:

    $ bvault operator ferrogate list --status pending

Approve a pending machine by handle (from `list`) or by SPIFFE id:

    $ bvault operator ferrogate approve <handle> --policies default,reader
    $ bvault operator ferrogate approve spiffe://ferrogate.prod/host/<uuid> --policies default

Reject or revoke a machine:

    $ bvault operator ferrogate reject <handle> --reason "unrecognised host"
    $ bvault operator ferrogate revoke <handle>"#
)]
pub struct Ferrogate {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List enrolled machines (optionally filtered by status).
    List(List),
    /// Approve a machine and attach its policy set.
    Approve(Approve),
    /// Reject a pending machine.
    Reject(Reject),
    /// Revoke a previously-approved machine.
    Revoke(Revoke),
}

impl Ferrogate {
    #[inline]
    pub fn execute(&mut self) -> ExitCode {
        let Some(cmd) = &mut self.command else {
            return EXIT_CODE_INSUFFICIENT_PARAMS;
        };
        match cmd {
            Commands::List(c) => c.execute(),
            Commands::Approve(c) => c.execute(),
            Commands::Reject(c) => c.execute(),
            Commands::Revoke(c) => c.execute(),
        }
    }
}

/// Resolve an operator-supplied machine reference into its storage handle. A
/// `spiffe://` URI is hashed locally into the BLAKE3 handle the admin paths
/// expect; anything else is assumed to already be a handle and passed through.
fn resolve_handle(machine: &str) -> String {
    if machine.starts_with("spiffe://") {
        machine_id(machine)
    } else {
        machine.trim().to_string()
    }
}

// ── list ─────────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(about = "List enrolled machines")]
pub struct List {
    /// Only show machines in this status (pending|approved|rejected|revoked).
    #[arg(long)]
    status: Option<String>,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for List {
    fn main(&self) -> Result<(), RvError> {
        let client = self.client()?;
        let path = format!("auth/{}/machines", self.mount.trim_matches('/'));
        let resp = client.logical().list(&path)?;

        let machines = resp
            .response_data
            .as_ref()
            .and_then(|d| d.get("machines"))
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();

        let filtered: Vec<Value> = match &self.status {
            Some(want) => machines
                .into_iter()
                .filter(|m| m.get("status").and_then(|s| s.as_str()) == Some(want.as_str()))
                .collect(),
            None => machines,
        };

        if filtered.is_empty() {
            println!("No machines found.");
            return Ok(());
        }
        self.output.print_value(&Value::Array(filtered), true)
    }
}

// ── approve ──────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(about = "Approve a machine and attach its policy set")]
pub struct Approve {
    /// Machine handle (BLAKE3 hex from `list`) or its SPIFFE id (auto-hashed).
    #[arg(value_name = "MACHINE")]
    machine: String,

    /// Policies to grant tokens this machine mints (comma-separated).
    #[arg(long)]
    policies: Option<String>,

    /// Token TTL in seconds; 0 (or omitted) uses the mount's config default.
    #[arg(long)]
    ttl: Option<u64>,

    /// Optional approval note.
    #[arg(long)]
    comment: Option<String>,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Approve {
    fn main(&self) -> Result<(), RvError> {
        let id = resolve_handle(&self.machine);
        let client = self.client()?;

        let mut body = Map::new();
        if let Some(p) = &self.policies {
            body.insert("policies".into(), Value::String(p.clone()));
        }
        if let Some(ttl) = self.ttl {
            body.insert("ttl_seconds".into(), Value::Number(ttl.into()));
        }
        if let Some(c) = &self.comment {
            body.insert("comment".into(), Value::String(c.clone()));
        }

        let path = format!("auth/{}/machines/{}/approve", self.mount.trim_matches('/'), id);
        client.logical().write(&path, Some(body))?;
        println!("approved machine {id}");
        Ok(())
    }
}

// ── reject ───────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(about = "Reject a pending machine")]
pub struct Reject {
    /// Machine handle (BLAKE3 hex from `list`) or its SPIFFE id (auto-hashed).
    #[arg(value_name = "MACHINE")]
    machine: String,

    /// Reason for rejection (recorded on the machine record).
    #[arg(long)]
    reason: Option<String>,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Reject {
    fn main(&self) -> Result<(), RvError> {
        let id = resolve_handle(&self.machine);
        let client = self.client()?;

        let mut body = Map::new();
        if let Some(r) = &self.reason {
            body.insert("reason".into(), Value::String(r.clone()));
        }

        let path = format!("auth/{}/machines/{}/reject", self.mount.trim_matches('/'), id);
        client.logical().write(&path, Some(body))?;
        println!("rejected machine {id}");
        Ok(())
    }
}

// ── revoke ───────────────────────────────────────────────────────────────

#[derive(Parser, Deref)]
#[command(about = "Revoke a previously-approved machine")]
pub struct Revoke {
    /// Machine handle (BLAKE3 hex from `list`) or its SPIFFE id (auto-hashed).
    #[arg(value_name = "MACHINE")]
    machine: String,

    /// Mount path of the ferrogate auth method.
    #[arg(long, default_value = "ferrogate")]
    mount: String,

    #[deref]
    #[command(flatten, next_help_heading = "HTTP Options")]
    http_options: command::HttpOptions,

    #[command(flatten, next_help_heading = "Output Options")]
    output: command::OutputOptions,
}

impl CommandExecutor for Revoke {
    fn main(&self) -> Result<(), RvError> {
        let id = resolve_handle(&self.machine);
        let client = self.client()?;
        let path = format!("auth/{}/machines/{}/revoke", self.mount.trim_matches('/'), id);
        client.logical().write(&path, None)?;
        println!("revoked machine {id}");
        Ok(())
    }
}
