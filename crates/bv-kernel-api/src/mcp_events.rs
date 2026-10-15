//! The MCP brokered-session audit events (`features/mcp-brokered-sessions.md`
//! §10): `connect.agent.*` for what an agent's session did or was refused, and
//! `mcp.transcript.accessed` for every read of a transcript.
//!
//! In the kernel contract because three places emit them: the MCP endpoint in
//! the facade (refusals before anything is routed), the resource engine (the
//! session handler, which cannot see the facade) and `bv-kernel` (transcript
//! reads).
//!
//! **The discipline is in the types.** Each event is a struct with no field
//! for credential material, certificates, tickets, command text, URL paths,
//! page text or images; a command or a path can only appear as its HMAC under
//! the audit HMAC key ([`audit_hmac`]). The fields are then written in the
//! clear — an event entry is not HMAC-redacted the way a request body is —
//! so an operator can read who, what and why.
//!
//! **Where they go.** Every event is one `security` log line, always, and one
//! `event` entry on the audit broker when an audit device is enabled
//! (`bv_audit::AuditEntry::event`). A broker failure is returned: the caller
//! decides whether to fail closed.

use bv_audit::{entry::hmac_redact, AuditEntry};
use bv_errors::RvError;
use bv_logical::{McpOperatorRef, Request};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::ctx::VaultCtx;

/// `connect.agent.ssh.exec`: one SSH session ran (Phase 1).
pub const CONNECT_AGENT_SSH_EXEC: &str = "connect.agent.ssh.exec";
/// `connect.agent.web.fetch` (Phase 2).
pub const CONNECT_AGENT_WEB_FETCH: &str = "connect.agent.web.fetch";
/// `connect.agent.rdp.act` (Phase 3).
pub const CONNECT_AGENT_RDP_ACT: &str = "connect.agent.rdp.act";
/// `connect.agent.refused`: a session call was refused before or instead of
/// dialing.
pub const CONNECT_AGENT_REFUSED: &str = "connect.agent.refused";
/// `connect.agent.aborted`: a running session was cut short.
pub const CONNECT_AGENT_ABORTED: &str = "connect.agent.aborted";
/// `mcp.transcript.accessed`: a transcript, or the list of them, was read.
pub const MCP_TRANSCRIPT_ACCESSED: &str = "mcp.transcript.accessed";

/// Longest string an event carries for a value that may have come from a
/// model (a refused call's resource or profile argument). Longer values are
/// cut, and say so, rather than letting a client fill the log.
pub const MAX_EVENT_ARG_LEN: usize = 128;

/// An event's audit name and its fields.
pub trait McpAuditEvent: Serialize {
    const NAME: &'static str;
}

/// `connect.agent.refused`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentRefused {
    /// The stable refusal code (`data.code`), e.g. `mcp_connect_not_allowed`.
    pub reason: String,
    pub tool: String,
    /// `ssh`, `web` or `rdp`.
    pub protocol: String,
    /// The resource the call named, when it named one ([`bounded_arg`]).
    pub resource: Option<String>,
    pub profile_id: Option<String>,
    pub operator: Option<McpOperatorRef>,
    pub pairing_id: Option<String>,
    pub client_name: String,
}

impl McpAuditEvent for AgentRefused {
    const NAME: &'static str = CONNECT_AGENT_REFUSED;
}

/// Why a session was cut short.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortCause {
    TokenRevoked,
    KillSwitch,
    Timeout,
    ExecutorError,
}

/// `connect.agent.aborted`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentAborted {
    pub session_id: String,
    pub cause: AbortCause,
    pub protocol: String,
    pub resource: String,
    pub profile_id: String,
    pub operator: Option<McpOperatorRef>,
    pub pairing_id: Option<String>,
}

impl McpAuditEvent for AgentAborted {
    const NAME: &'static str = CONNECT_AGENT_ABORTED;
}

/// `connect.agent.ssh.exec`, with the spec's fields. The command is present
/// only as `command_hmac` and its length.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SshExecEvent {
    pub session_id: String,
    pub operator: Option<McpOperatorRef>,
    pub pairing_id: Option<String>,
    pub client_name: String,
    pub binding_reveal_allowed: bool,
    pub resource: String,
    pub profile_id: String,
    /// The `host:port` dialed.
    pub target: String,
    pub host_key_fingerprint: String,
    /// `certificate`, `password` or `stored-key`.
    pub login: String,
    pub cert_serial: Option<String>,
    pub mfa_method: Option<String>,
    /// [`audit_hmac`] of the command bytes; `None` without an audit device.
    pub command_hmac: Option<String>,
    pub command_bytes: u64,
    pub exit_status: Option<u32>,
    pub exit_signal: Option<String>,
    pub timed_out: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub truncated: bool,
    pub credential_echo_redacted: bool,
    pub duration_ms: u64,
    /// The transcript the session was recorded under; `None` when recording
    /// it failed (the failure is in the log).
    pub transcript_id: Option<String>,
    pub operator_confirmation: Option<String>,
}

impl McpAuditEvent for SshExecEvent {
    const NAME: &'static str = CONNECT_AGENT_SSH_EXEC;
}

/// `connect.agent.web.fetch` (Phase 2), with the spec's fields. The path is
/// present only as `path_hmac` and its length; the page text never.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WebFetchEvent {
    pub session_id: String,
    pub operator: Option<McpOperatorRef>,
    pub pairing_id: Option<String>,
    pub client_name: String,
    pub binding_reveal_allowed: bool,
    pub resource: String,
    pub profile_id: String,
    /// `GET` or `HEAD`.
    pub method: String,
    /// [`audit_hmac`] of the requested path (with its query); `None` without
    /// an audit device.
    pub path_hmac: Option<String>,
    pub path_bytes: u64,
    /// The profile's start origin, `https://host[:port]` (configuration, not
    /// model input).
    pub origin: String,
    /// The `ip:port` the first request dialed.
    pub target: String,
    /// `open` or `http-auth`.
    pub login: String,
    /// How the last certificate was trusted: `platform`, `pinned-leaf`,
    /// `pinned-issuer`.
    pub tls: Option<String>,
    pub mfa_method: Option<String>,
    /// The final response's status.
    pub status: Option<u16>,
    /// Redirects followed.
    pub redirects: u32,
    /// Whether the profile's credential answered a challenge.
    pub credential_sent: bool,
    pub body_bytes: u64,
    pub truncated: bool,
    pub binary_output: bool,
    pub credential_echo_redacted: bool,
    pub duration_ms: u64,
    pub transcript_id: Option<String>,
    pub operator_confirmation: Option<String>,
}

impl McpAuditEvent for WebFetchEvent {
    const NAME: &'static str = CONNECT_AGENT_WEB_FETCH;
}

/// `mcp.transcript.accessed`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TranscriptAccessed {
    /// `read` (one transcript) or `list`.
    pub operation: String,
    /// The transcript read; `None` for a list.
    pub transcript_id: Option<String>,
    /// How many ids a list returned.
    pub listed: Option<u64>,
    /// Whether the transcript existed and was returned.
    pub found: bool,
}

impl McpAuditEvent for TranscriptAccessed {
    const NAME: &'static str = MCP_TRANSCRIPT_ACCESSED;
}

/// `"hmac:<hex>"` of `data` under the audit HMAC key, the form every audit
/// device already uses for a redacted value. `None` when no audit broker is
/// installed (there is then no device for the HMAC to correlate with).
pub fn audit_hmac(ctx: &dyn VaultCtx, data: &[u8]) -> Option<String> {
    ctx.audit_broker().map(|b| format!("hmac:{}", hmac_redact(b.hmac_key(), data)))
}

/// A value a model may have supplied, made safe to carry in an event: cut to
/// [`MAX_EVENT_ARG_LEN`] characters with a `…` marker. It is never
/// interpolated into anything but a JSON string, which escapes it.
pub fn bounded_arg(value: &str) -> String {
    if value.chars().count() <= MAX_EVENT_ARG_LEN {
        return value.to_string();
    }
    let mut cut: String = value.chars().take(MAX_EVENT_ARG_LEN).collect();
    cut.push('…');
    cut
}

/// The event's fields, as written.
pub fn event_fields<E: McpAuditEvent>(event: &E) -> Map<String, Value> {
    match serde_json::to_value(event) {
        Ok(Value::Object(map)) => map,
        // Every event is a struct of plain fields; anything else is a bug in
        // this module, and an empty record still names the event.
        _ => Map::new(),
    }
}

/// Emit `event`: one `security` log line, and one `event` entry on the audit
/// broker when a device is enabled. `req`, when given, is the request that
/// caused it (who and from where; its body is not recorded). The broker's
/// error is returned so the caller can fail closed.
#[maybe_async::maybe_async]
pub async fn emit<E: McpAuditEvent + Sync>(
    ctx: &dyn VaultCtx,
    event: &E,
    req: Option<&Request>,
) -> Result<(), RvError> {
    let fields = event_fields(event);
    // `Value`'s `Display` is compact JSON, so no field can break the line.
    log::info!(target: "security", "{} {}", E::NAME, Value::Object(fields.clone()));
    let Some(broker) = ctx.audit_broker() else {
        return Ok(());
    };
    if !broker.has_devices() {
        return Ok(());
    }
    let mut entry = AuditEntry::event(E::NAME, fields, req, broker.hmac_key());
    broker.log(&mut entry).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_carry_their_name_and_no_free_text() {
        let refused = AgentRefused {
            reason: "mcp_connect_not_allowed".into(),
            tool: "bv_resource_ssh_exec".into(),
            protocol: "ssh".into(),
            resource: Some("web-01".into()),
            ..Default::default()
        };
        let fields = event_fields(&refused);
        assert_eq!(AgentRefused::NAME, "connect.agent.refused");
        assert_eq!(fields["reason"], "mcp_connect_not_allowed");
        assert_eq!(fields["resource"], "web-01");

        let exec = SshExecEvent { command_hmac: Some("hmac:ab".into()), command_bytes: 9, ..Default::default() };
        let fields = event_fields(&exec);
        assert_eq!(SshExecEvent::NAME, "connect.agent.ssh.exec");
        assert!(!fields.contains_key("command"), "the command is never a field");
        assert_eq!(fields["command_hmac"], "hmac:ab");

        let aborted = AgentAborted {
            session_id: "s".into(),
            cause: AbortCause::TokenRevoked,
            protocol: "ssh".into(),
            resource: "r".into(),
            profile_id: "p".into(),
            operator: None,
            pairing_id: None,
        };
        assert_eq!(event_fields(&aborted)["cause"], "token_revoked");

        let fetch = WebFetchEvent { path_hmac: Some("hmac:cd".into()), path_bytes: 11, ..Default::default() };
        let fields = event_fields(&fetch);
        assert_eq!(WebFetchEvent::NAME, "connect.agent.web.fetch");
        assert!(!fields.contains_key("path") && !fields.contains_key("body_text"), "never the path or the page");
        assert_eq!(fields["path_hmac"], "hmac:cd");
        assert_eq!(TranscriptAccessed::NAME, "mcp.transcript.accessed");
    }

    #[test]
    fn model_supplied_values_are_bounded() {
        assert_eq!(bounded_arg("web-01"), "web-01");
        let long = "é".repeat(MAX_EVENT_ARG_LEN + 5);
        let cut = bounded_arg(&long);
        assert_eq!(cut.chars().count(), MAX_EVENT_ARG_LEN + 1);
        assert!(cut.ends_with('…'));
    }
}
