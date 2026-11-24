//! The bastion leg of `resources/v2/connect/agent/ssh/exec`
//! (`features/rustion-agent-exec.md`, phase 2): the credential is resolved
//! here, `rustion/v2/session/open` (through the router: an engine never
//! depends on another engine) seals it with the confirmed command into an
//! exec ticket, and the vault redeems the ticket at the bastion's pinned
//! SSH listener with one `exec` of the same bytes. No failure here ever
//! falls back to a direct dial.

use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
use bv_kernel_api::{
    mcp_events::{self, McpAuditEvent, SshExecEvent},
    ssh_credentials::{self, BrokeredCertRequest, SecretResolution},
    VaultCtx,
};
use bv_mcp::untrusted::CredentialScrubber;
use serde::Serialize;
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use super::{session::LoginPlan, CallError, Gated, SessionRefusal, CERT_VALIDITY_SECS};
use crate::{
    agent_session::{refused, BastionRoute},
    connect_mfa::{attach_agent_mfa_grant, ConnectMfaTicket},
    errors::RvError,
    logical::{Operation, Request},
};

/// The exec form of the Rustion engine's connect-only open.
pub(crate) const RUSTION_OPEN_PATH: &str = "rustion/v2/session/open";

/// The Rustion engine's control-plane kill.
const RUSTION_KILL_PATH: &str = "rustion/session/kill";

/// What is sealed for the bastion to log in to the target with. The
/// material is base64, as the open's `credential_material` field takes it,
/// and wiped on drop.
pub(crate) struct SealedCredential {
    /// `ssh-password`, `ssh-key` or `ssh-cert`: the envelope's kind.
    pub kind: &'static str,
    pub username: String,
    pub material_b64: Zeroizing<String>,
    /// For `ssh-cert`: the signed certificate text.
    pub cert: Option<String>,
    /// For `ssh-cert`: its serial, for the audit join with `ssh/sign`.
    pub serial: Option<String>,
}

impl SealedCredential {
    /// The `login` field of results, events and transcripts: what the
    /// bastion logs in to the target with, in the direct path's words.
    pub fn login_kind(&self) -> &'static str {
        match self.kind {
            "ssh-key" => "stored-key",
            "ssh-cert" => "certificate",
            _ => "password",
        }
    }
}

/// Resolve or mint the credential for the bastion to seal, under the
/// server's authority, with the functions the direct path uses, so this
/// route's scrubber knows it. Runs after every refusal.
pub(crate) async fn resolve_sealed_credential(
    ctx: &dyn VaultCtx,
    ns_prefix: &str,
    resource: &str,
    plan: LoginPlan,
    gated: &Gated,
    target_host: &str,
    actor: &str,
) -> Result<(SealedCredential, CredentialScrubber), CallError> {
    let failed = |m: String| refused("mcp_session_failed", 422, m);
    let unsupported = |m: &str| refused("mcp_session_login_class_unsupported", 422, m.to_string());
    let b64 = |bytes: &[u8]| Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes));
    match plan {
        LoginPlan::Secret { secret_id, profile_username } => {
            let resolved = ssh_credentials::resolve_secret_credential(
                ctx,
                ns_prefix,
                resource,
                &secret_id,
                &SecretResolution { audit_label: "mcp-agent-ssh-resolve", actor },
            )
            .await
            .map_err(|e| failed(format!("the profile's stored credential could not be resolved: {e}")))?;
            let username =
                resolved.username.clone().or(profile_username).filter(|u| !u.is_empty()).ok_or_else(|| {
                    refused(
                        "mcp_session_login_class_unsupported",
                        403,
                        "neither the stored secret nor the profile names the login (`username`)",
                    )
                })?;
            let mut scrubber = CredentialScrubber::none();
            if let Some(pem) = resolved.private_key.as_ref() {
                scrubber.add_private_key_pem(pem);
                if resolved.passphrase.is_some() {
                    return Err(unsupported(
                        "the stored private key is passphrase-protected, which cannot be sealed for a bastion (the \
                         envelope has no passphrase channel); store an unencrypted OpenSSH key",
                    ));
                }
                let parsed = russh::keys::PrivateKey::from_openssh(pem.as_bytes())
                    .map_err(|_| unsupported("the stored private key is not an OpenSSH private key"))?;
                if parsed.is_encrypted() {
                    return Err(unsupported(
                        "the stored private key is encrypted, which cannot be sealed for a bastion; store an \
                         unencrypted OpenSSH key",
                    ));
                }
                drop(parsed);
                let material_b64 = b64(pem.as_bytes());
                return Ok((
                    SealedCredential { kind: "ssh-key", username, material_b64, cert: None, serial: None },
                    scrubber,
                ));
            }
            let Some(password) = resolved.password else {
                return Err(failed("the stored secret carries no password and no private key".into()));
            };
            scrubber.add_password(&username, &password);
            let material_b64 = b64(password.as_bytes());
            Ok((SealedCredential { kind: "ssh-password", username, material_b64, cert: None, serial: None }, scrubber))
        }
        LoginPlan::Certificate { ssh_mount, ssh_role, username } => {
            // `force-command` and a minute of validity, as on the direct
            // path. No `source-address`: the bastion, not this vault, dials
            // the target, from an address the vault does not know.
            let mut critical_options = std::collections::BTreeMap::new();
            critical_options.insert("force-command".to_string(), gated.command.clone());
            let request = BrokeredCertRequest {
                principal: Some(&username),
                critical_options,
                ttl_secs: Some(CERT_VALIDITY_SECS),
                target_host: Some(target_host),
            };
            let minted = ssh_credentials::mint_brokered_ssh_cert(ctx, ns_prefix, &ssh_mount, &ssh_role, &request)
                .await
                .map_err(|e| {
                    failed(format!("SSH role `{ssh_role}` on `{ssh_mount}` did not sign the session certificate: {e}"))
                })?;
            let facts =
                ssh_credentials::inspect_ssh_certificate(&minted.certificate).map_err(|e| failed(e.to_string()))?;
            super::session::verify_certificate(&facts, &gated.command, "", &username, &ssh_role, now_secs())?;
            let material_b64 = b64(minted.private_key_openssh.as_bytes());
            let serial = Some(format!("{:016x}", facts.serial));
            Ok((
                SealedCredential {
                    kind: "ssh-cert",
                    username,
                    material_b64,
                    cert: Some(minted.certificate.trim().to_string()),
                    serial,
                },
                CredentialScrubber::none(),
            ))
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What the exec open asks for.
pub(crate) struct OpenParams<'a> {
    pub resource: &'a str,
    pub profile_id: &'a str,
    pub command: &'a str,
    /// The target, from the stored records, as the bastion will dial it.
    pub target_host: &'a str,
    pub target_port: u16,
    /// The profile's pin, which the bastion enforces on the target.
    pub target_pin: &'a str,
    pub credential: &'a SealedCredential,
    pub route: &'a BastionRoute,
    /// How long the bastion session may live: the call's own budget.
    pub ttl_secs: u64,
}

/// The body of the exec open. The command is the confirmed bytes, unchanged:
/// what the bastion seals and later compares the `exec` request against.
pub(crate) fn open_body(p: &OpenParams<'_>) -> Map<String, Value> {
    let mut body = Map::new();
    let mut put = |k: &str, v: Value| {
        body.insert(k.to_string(), v);
    };
    put("resource_name", Value::String(p.resource.to_string()));
    put("profile_id", Value::String(p.profile_id.to_string()));
    put("resource_id", Value::String(p.resource.to_string()));
    if let Some(t) = &p.route.resource_type {
        put("resource_type", Value::String(t.clone()));
    }
    if !p.route.asset_group_ids.is_empty() {
        put("asset_group_ids", Value::String(p.route.asset_group_ids.join(",")));
    }
    put("kind", Value::String("exec".into()));
    put("command", Value::String(p.command.to_string()));
    put("target_host", Value::String(p.target_host.to_string()));
    put("target_port", Value::from(p.target_port));
    put("target_protocol", Value::String("ssh".into()));
    put("target_hostkey_pin", Value::String(p.target_pin.to_string()));
    put("credential_kind", Value::String(p.credential.kind.to_string()));
    put("credential_username", Value::String(p.credential.username.clone()));
    put("credential_material", Value::String(p.credential.material_b64.to_string()));
    if let Some(cert) = &p.credential.cert {
        put("credential_cert", Value::String(cert.clone()));
    }
    if let Some(serial) = &p.credential.serial {
        put("credential_serial", Value::String(serial.clone()));
    }
    put("ttl_secs", Value::from(p.ttl_secs));
    put("max_renewals", Value::from(0u64));
    put("recording", Value::String("always".into()));
    body
}

/// An exec ticket the bastion granted, and where to redeem it.
pub(crate) struct BastionTicket {
    pub session_id: String,
    pub correlation_id: String,
    pub bastion_id: String,
    pub bastion_name: String,
    pub recording_id: String,
    pub dial_host: String,
    pub dial_port: u16,
    /// SHA-256 of the listener's pinned host key.
    pub host_key_sha256: [u8; 32],
    /// The single-use password, wiped on drop.
    pub ticket: Zeroizing<String>,
}

impl std::fmt::Debug for BastionTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BastionTicket")
            .field("session_id", &self.session_id)
            .field("bastion_name", &self.bastion_name)
            .field("dial", &format_args!("{}:{}", self.dial_host, self.dial_port))
            .field("ticket", &"<redacted>")
            .finish()
    }
}

/// Read the exec open's answer. Refused unless the bastion echoed
/// `kind: "exec"` (checked again here, where the ticket is used), and
/// unless it names a listener and a well-formed host-key pin. The ticket is
/// moved out of the map, never copied.
pub(crate) fn ticket_from_response(mut data: Map<String, Value>) -> Result<BastionTicket, SessionRefusal> {
    let bastion = |m: &str| SessionRefusal::new("mcp_session_requires_bastion", 403, m);
    let ticket = match data.remove("ticket") {
        Some(Value::String(t)) => Zeroizing::new(t),
        _ => return Err(bastion("the bastion's exec open carries no ticket")),
    };
    if data.get("kind").and_then(Value::as_str) != Some("exec") {
        return Err(bastion("the bastion did not confirm an exec session; its ticket is not used"));
    }
    let text = |k: &str| data.get(k).and_then(Value::as_str).unwrap_or_default().trim().to_string();
    let pin = text("ssh_host_key_pin");
    let host_key_sha256 = pin
        .strip_prefix("SHA256:")
        .and_then(|b| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b.trim_end_matches('=')).ok())
        .and_then(|d| <[u8; 32]>::try_from(d).ok())
        .ok_or_else(|| {
            bastion("the bastion's SSH listener has no well-formed host-key pin; it is never dialed unpinned")
        })?;
    let dial_host = text("ssh_dial_host");
    let dial_port = data.get("ssh_dial_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).unwrap_or(0);
    if dial_host.is_empty() || dial_port == 0 || ticket.is_empty() {
        return Err(bastion("the bastion's exec open names no SSH listener to redeem its ticket at"));
    }
    Ok(BastionTicket {
        session_id: text("session_id"),
        correlation_id: text("correlation_id"),
        bastion_id: text("bastion_id"),
        bastion_name: text("bastion_name"),
        recording_id: text("recording_id"),
        dial_host,
        dial_port,
        host_key_sha256,
        ticket,
    })
}

/// The open's error, as this route answers it. Nothing ran on the target in
/// any of these, and none of them is a reason to dial direct.
pub(crate) fn refusal_for_open_error(error: RvError) -> CallError {
    let text = error.to_string();
    let detail = |m: &str| format!("{m} ({}); nothing ran and the target was not dialed direct", bounded(&text));
    if matches!(error, RvError::ErrPermissionDenied) {
        return CallError::Vault { reason: "permission_denied", error };
    }
    if text.contains("envelope_too_large: ") {
        return refused(
            "mcp_invalid_argument",
            400,
            "envelope_too_large: the command and the profile's credential do not fit the bastion's 16384-byte \
             envelope; shorten the command",
        );
    }
    if text.contains("exec_unsupported: ") {
        return refused(
            "mcp_session_requires_bastion",
            403,
            detail(
                "no bastion serving this resource can run an agent command: it needs an update to Rustion 0.20.0 \
                 or later with ssh_exec enabled",
            ),
        );
    }
    if text.contains("exec_kind_not_echoed: ") {
        return refused(
            "mcp_session_requires_bastion",
            403,
            detail("the bastion opened an interactive session instead of an exec (an older Rustion?); it was ended"),
        );
    }
    if text.contains("mfa_required: ") || text.contains("mfa_unavailable: ") {
        return refused("mcp_session_mfa_ticket_refused", 403, detail("the bastion open refused the operator's MFA"));
    }
    if text.contains("bastion_rejected: ") {
        return refused("mcp_session_failed", 502, detail("the bastion refused the exec open"));
    }
    refused("mcp_session_requires_bastion", 403, detail("the bastion route could not be opened"))
}

/// An error's text, cut to keep a refusal readable.
fn bounded(text: &str) -> String {
    const MAX: usize = 512;
    if text.len() <= MAX {
        return text.to_string();
    }
    let mut end = MAX;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// A sub-request to the Rustion engine, as the caller: its token's policies
/// and namespace, through the router (the engine runs its own gate).
fn sub_request(req: &Request, path: &str, body: Map<String, Value>) -> Request {
    let mut sub = Request::new_write_request(path, Some(body));
    sub.operation = Operation::Write;
    sub.auth = req.auth.clone();
    sub.namespace_path = req.namespace_path.clone();
    sub
}

/// Ask the Rustion engine for an exec ticket. `mfa` is the operator's
/// ticket this route already redeemed for a gated profile; it rides
/// in-process to the open's gate, which would otherwise ask for it again.
pub(crate) async fn open(
    ctx: &dyn VaultCtx,
    req: &Request,
    body: Map<String, Value>,
    mfa: Option<ConnectMfaTicket>,
) -> Result<BastionTicket, CallError> {
    let mut sub = sub_request(req, RUSTION_OPEN_PATH, body);
    if let Some(record) = mfa {
        attach_agent_mfa_grant(&sub, record);
    }
    let answer = ctx.router().handle_request(&mut sub).await;
    // The sealed credential's base64 is in the body; wipe it now.
    if let Some(Value::String(material)) = sub.body.as_mut().and_then(|b| b.get_mut("credential_material")) {
        material.zeroize();
    }
    let data = answer.map_err(refusal_for_open_error)?.and_then(|r| r.data).unwrap_or_default();
    ticket_from_response(data).map_err(CallError::Refused)
}

/// End the bastion session through its control plane (timeout, abort, no
/// result, or a ticket never redeemed). Best effort: the bastion also ends
/// an exec session when its channel closes, and a ticket expires in 30 s.
pub(crate) async fn kill(ctx: &dyn VaultCtx, who: &Request, session: &BastionSessionRef) {
    let mut body = Map::new();
    body.insert("bastion_id".into(), Value::String(session.bastion_id.clone()));
    body.insert("session_id".into(), Value::String(session.session_id.clone()));
    body.insert("correlation_id".into(), Value::String(session.correlation_id.clone()));
    let mut sub = sub_request(who, RUSTION_KILL_PATH, body);
    match ctx.router().handle_request(&mut sub).await {
        Ok(_) => log::info!(
            target: "security",
            "connect.agent.ssh bastion session ended: bastion={} session_id={}",
            session.bastion_name,
            session.session_id
        ),
        Err(e) => log::warn!(
            target: "security",
            "connect.agent.ssh bastion session {} on {} could not be ended through the control plane ({e}); it \
             expires on its own",
            session.session_id,
            session.bastion_name
        ),
    }
}

/// Resolve the bastion listener's host once; an IP literal is used as is.
/// Not held to the agents' destination allow-list, which governs where a
/// command lands (the target, checked): the bastion is enrolled
/// infrastructure, authenticated by its pinned key before the ticket goes.
pub(crate) async fn resolve_listener(host: &str, port: u16) -> Result<Vec<SocketAddr>, SessionRefusal> {
    let literal = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let unreachable = |m: String| SessionRefusal::new("mcp_session_requires_bastion", 403, m);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| unreachable(format!("the bastion's SSH listener `{host}` does not resolve ({e}); nothing ran")))?
        .collect();
    if addrs.is_empty() {
        return Err(unreachable(format!("the bastion's SSH listener `{host}` resolves to no address; nothing ran")));
    }
    Ok(addrs)
}

/// What identifies the bastion session once the ticket is spent: the
/// control plane's kill handle and the audit join keys.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct BastionSessionRef {
    pub bastion_id: String,
    pub bastion_name: String,
    /// The bastion's own session id.
    pub session_id: String,
    pub correlation_id: String,
    /// Where the bastion keeps the recording (`rustion/recordings/<id>`).
    pub recording_id: String,
    /// Why it went through the bastion: `profile`, `rustion-required` or
    /// `rustion-preferred`.
    pub route: &'static str,
    /// The SSH listener dialed, `host:port`.
    pub listener: String,
}

impl BastionSessionRef {
    pub fn new(ticket: &BastionTicket, route: &'static str) -> Self {
        Self {
            bastion_id: ticket.bastion_id.clone(),
            bastion_name: ticket.bastion_name.clone(),
            session_id: ticket.session_id.clone(),
            correlation_id: ticket.correlation_id.clone(),
            recording_id: ticket.recording_id.clone(),
            route,
            listener: format!("{}:{}", ticket.dial_host, ticket.dial_port),
        }
    }
}

/// The bastion block of the call's one `connect.agent.ssh.exec` record.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BastionRecord {
    #[serde(flatten)]
    pub session: BastionSessionRef,
    /// `SHA256:<base64>` of the listener key the vault checked.
    pub listener_host_key_fingerprint: String,
    /// `completed` (exit status or signal), `failed` (no result after it
    /// started), `refused` (nothing ran), `timed_out`, `aborted`, or
    /// `not_run` (the listener was not reached, or refused the ticket).
    pub outcome: &'static str,
    /// The bastion's reason code, or its hint for a missing result.
    pub reason: Option<String>,
}

/// `connect.agent.ssh.exec` for a call that went through a bastion: the
/// direct path's record plus its `bastion` block. One record per call, as
/// on the direct path; the command is only an HMAC.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BastionSshExecEvent {
    #[serde(flatten)]
    pub exec: SshExecEvent,
    pub bastion: BastionRecord,
}

impl McpAuditEvent for BastionSshExecEvent {
    const NAME: &'static str = mcp_events::CONNECT_AGENT_SSH_EXEC;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PIN: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    fn route() -> BastionRoute {
        BastionRoute {
            why: "rustion-required",
            resource_type: Some("server".into()),
            asset_group_ids: vec!["ag-1".into(), "ag-2".into()],
        }
    }

    fn credential() -> SealedCredential {
        SealedCredential {
            kind: "ssh-password",
            username: "ops".into(),
            material_b64: Zeroizing::new("aHVudGVyMg==".into()),
            cert: None,
            serial: None,
        }
    }

    /// The bytes the operator confirmed are the bytes the open seals: the
    /// body carries the command unchanged, with the exec kind, an SSH
    /// target and the profile's pin (decision 3).
    #[test]
    fn the_open_body_carries_the_confirmed_bytes() {
        let command = "df -h / ; echo \"ação\" | tr a-z A-Z\t# ✓";
        let (cred, route) = (credential(), route());
        let body = open_body(&OpenParams {
            resource: "web-01",
            profile_id: "p_agent",
            command,
            target_host: "10.0.0.7",
            target_port: 2222,
            target_pin: PIN,
            credential: &cred,
            route: &route,
            ttl_secs: 40,
        });
        assert_eq!(body["command"].as_str().unwrap().as_bytes(), command.as_bytes());
        assert_eq!(body["kind"], json!("exec"));
        assert_eq!(body["target_protocol"], json!("ssh"));
        assert_eq!(body["target_hostkey_pin"], json!(PIN));
        assert_eq!(body["target_port"], json!(2222));
        assert_eq!(body["asset_group_ids"], json!("ag-1,ag-2"));
        assert_eq!(body["max_renewals"], json!(0));
        assert_eq!(body["recording"], json!("always"));
        assert!(body.get("credential_source").is_none(), "the credential is sealed as material, never re-resolved");
    }

    fn granted() -> Map<String, Value> {
        json!({
            "kind": "exec", "ticket": "tkt-1", "session_id": "s-1", "correlation_id": "c-1",
            "bastion_id": "rt_1", "bastion_name": "bastion-1", "recording_id": "rec_1",
            "ssh_dial_host": "127.0.0.1", "ssh_dial_port": 2222, "ssh_host_key_pin": PIN,
        })
        .as_object()
        .cloned()
        .unwrap()
    }

    #[test]
    fn a_ticket_is_used_only_from_a_confirmed_exec_open() {
        let t = ticket_from_response(granted()).unwrap();
        assert_eq!((t.dial_host.as_str(), t.dial_port, t.ticket.as_str()), ("127.0.0.1", 2222, "tkt-1"));
        assert_eq!(super::super::exec::sha256_fingerprint(&t.host_key_sha256), PIN);
        assert!(!format!("{t:?}").contains("tkt-1"), "Debug never prints the ticket");

        // No `kind: "exec"`: an interactive ticket is never redeemed.
        for kind in [Value::Null, json!("interactive")] {
            let mut d = granted();
            d.insert("kind".into(), kind);
            assert_eq!(ticket_from_response(d).unwrap_err().code, "mcp_session_requires_bastion");
        }
        // No pin, a malformed one, or no listener: never dialed.
        for (k, v) in [
            ("ssh_host_key_pin", json!("")),
            ("ssh_host_key_pin", json!("SHA256:AAAA")),
            ("ssh_host_key_pin", json!("MD5:aa")),
            ("ssh_dial_host", json!("")),
            ("ssh_dial_port", json!(0)),
            ("ticket", json!("")),
        ] {
            let mut d = granted();
            d.insert(k.into(), v.clone());
            assert!(ticket_from_response(d).is_err(), "{k}={v}");
        }
    }

    fn code(e: CallError) -> &'static str {
        match e {
            CallError::Refused(r) => r.code,
            CallError::Vault { reason, .. } => reason,
            CallError::Ended(r) => r.code,
        }
    }

    /// Every way the open fails is a refusal or a failure with a stable
    /// code; none of them dials direct. An older Rustion is named.
    #[test]
    fn open_errors_map_to_stable_codes() {
        let status = |s: u16, m: &str| RvError::ErrResponseStatus(s, m.to_string());
        match refusal_for_open_error(status(409, "exec_unsupported: no candidate (b: exec_unsupported)")) {
            CallError::Refused(r) => {
                assert_eq!(r.code, "mcp_session_requires_bastion");
                assert!(r.message.contains("update to Rustion 0.20.0"), "{}", r.message);
            }
            _ => panic!("a refusal"),
        }
        assert_eq!(
            code(refusal_for_open_error(status(400, "envelope_too_large: the sealed open envelope"))),
            "mcp_invalid_argument"
        );
        assert_eq!(
            code(refusal_for_open_error(status(502, "exec_kind_not_echoed: bastion `b` answered"))),
            "mcp_session_requires_bastion"
        );
        assert_eq!(
            code(refusal_for_open_error(status(503, "bastion_unavailable: no candidate Rustion targets"))),
            "mcp_session_requires_bastion"
        );
        assert_eq!(code(refusal_for_open_error(status(502, "bastion_rejected: b: http 409"))), "mcp_session_failed");
        assert_eq!(code(refusal_for_open_error(status(403, "mfa_required: no"))), "mcp_session_mfa_ticket_refused");
        assert_eq!(code(refusal_for_open_error(RvError::ErrPermissionDenied)), "permission_denied");
    }

    #[test]
    fn the_bastion_record_flattens_into_the_exec_event() {
        let event = BastionSshExecEvent {
            exec: SshExecEvent { session_id: "as_1".into(), command_bytes: 6, ..Default::default() },
            bastion: BastionRecord {
                session: BastionSessionRef {
                    bastion_id: "rt_1".into(),
                    bastion_name: "bastion-1".into(),
                    session_id: "s-1".into(),
                    correlation_id: "c-1".into(),
                    recording_id: "rec_1".into(),
                    route: "rustion-required",
                    listener: "127.0.0.1:2222".into(),
                },
                listener_host_key_fingerprint: PIN.into(),
                outcome: "completed",
                reason: None,
            },
        };
        let fields = mcp_events::event_fields(&event);
        assert_eq!(fields["session_id"], json!("as_1"));
        assert_eq!(fields["bastion"]["session_id"], json!("s-1"));
        assert_eq!(fields["bastion"]["recording_id"], json!("rec_1"));
        assert_eq!(fields["bastion"]["outcome"], json!("completed"));
        assert_eq!(BastionSshExecEvent::NAME, "connect.agent.ssh.exec");
    }
}
