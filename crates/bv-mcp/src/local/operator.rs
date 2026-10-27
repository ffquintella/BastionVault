//! The operator side of the local gatekeeper: what a human is asked, what
//! they can answer, and the pairing record an approval becomes.

use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    catalogue,
    dispatcher::SessionCall,
    pairing::{
        hash_token, new_pairing_id, new_pairing_token, PairingRecord, Transport, DEFAULT_PAIRING_LIFETIME_SECS,
        MAX_TOKEN_TTL_SECS,
    },
    sanitize::{escape_for_display, sanitize_for_model},
};

pub struct PairingRequest<'a> {
    pub client_name: &'a str,
    pub client_version: &'a str,
    pub transport: Transport,
    pub peer_uid: Option<u32>,
    /// The namespace the client's tokens will be bound to (`""` = root): the
    /// host's narrowing request (`bvault mcp serve --namespace`), else the
    /// operator session's own. `None` when the host cannot tell.
    pub namespace: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingGrant {
    pub tool_allowlist: Vec<String>,
    pub path_scope: Vec<String>,
    pub reveal_allowed: bool,
    pub destructive_allowed: bool,
    pub confirm_reveal: bool,
    pub confirm_destructive: bool,
    /// May open brokered sessions (`features/mcp-brokered-sessions.md` §9):
    /// required for any session tool in `tool_allowlist`.
    pub connect_allowed: bool,
    /// Forced to `connect_allowed` by [`normalize_grant`]: there is no grant
    /// that allows sessions without confirming each one, and no channel can
    /// turn it off.
    pub confirm_connect: bool,
    pub ttl_secs: u64,
    /// The operator chose to narrow this pairing's tokens to a namespace
    /// (T457 Phase 2; the desktop dialog's selector). `None` follows the
    /// operator's session. The vault decides whether it is permitted.
    pub namespace: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingDecision {
    Approved(PairingGrant),
    Denied,
}

/// What `resources/v2/connect/mfa/begin` reported for a gated profile: the
/// factors the operator holds, server-ordered, and the WebAuthn request
/// options when a security key is among them.
#[derive(Clone, Debug, PartialEq)]
pub struct MfaChallenge {
    pub methods: Vec<String>,
    /// Opaque; handed to the platform authenticator by a host that can run
    /// the assertion. Never shown to the MCP client.
    pub fido2: Option<Value>,
}

/// One second factor the operator presented.
pub enum MfaFactor {
    /// The current code from the operator's authenticator app.
    Totp(Zeroizing<String>),
    /// A JSON-encoded WebAuthn assertion over [`MfaChallenge::fido2`].
    Fido2(Zeroizing<String>),
}

impl MfaFactor {
    /// The `method` the vault's verify expects.
    pub fn method(&self) -> &'static str {
        match self {
            MfaFactor::Totp(_) => "totp",
            MfaFactor::Fido2(_) => "fido2",
        }
    }
}

impl std::fmt::Debug for MfaFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MfaFactor::{}(<redacted>)", self.method())
    }
}

/// The MFA step of a session call's confirmation
/// (`features/mcp-brokered-sessions.md` §3.1 steps 2-3). The prompter
/// collects one factor and hands it to `verify`, which proves it to the vault
/// as the operator, bound to this one call. On `Ok` the gatekeeper holds the
/// resulting ticket; the prompter never sees it. On `Err` the call must be
/// denied: a failed factor denies, it is not retried into an approval.
pub struct MfaStep<'a> {
    pub challenge: &'a MfaChallenge,
    pub verify: &'a dyn Fn(MfaFactor) -> Result<(), String>,
}

pub struct ConfirmRequest<'a> {
    pub client_name: &'a str,
    pub tool: &'a str,
    /// Reveal and write tools: what the call touches (mount, path, key),
    /// never a value. Empty for a session tool, which uses `detail`.
    pub summary: &'a str,
    pub reveals: bool,
    pub destructive: bool,
    /// Session tools (§9): the whole call as the operator must read it --
    /// resource, profile, protocol and the exact command, escaped for
    /// display ([`render_session_detail`]). `None` for every other tool.
    pub detail: Option<&'a str>,
    /// The same call, field by field, for a host that lays it out itself.
    /// Its `command` is the raw bytes that will run; display it only through
    /// [`escape_for_display`].
    pub session: Option<&'a SessionCall>,
    /// The tool opens a network session to a resource (`openWorldHint`).
    /// Confirmation of these is mandatory and has no off switch.
    pub open_world: bool,
    /// Present when the profile requires the operator's MFA.
    pub mfa: Option<MfaStep<'a>>,
    /// The namespace the call runs in: the one the pairing's token is bound
    /// to (`""` = root). `None` when the host cannot tell.
    pub namespace: Option<&'a str>,
}

/// A human. `None` from either method means *no operator is reachable*, which
/// every caller treats as a refusal -- never as an approval.
pub trait Prompter: Send + Sync {
    fn approve(&self, request: &PairingRequest<'_>) -> Option<PairingDecision>;
    fn confirm(&self, request: &ConfirmRequest<'_>) -> Option<bool>;

    /// What an unpaired client is told when [`Self::approve`] returned `None`.
    /// The default names the terminal, which is the CLI's operator channel.
    fn pairing_unavailable_message(&self) -> &str {
        "this client is not paired and no terminal is available to approve it; run `bvault mcp pair` interactively first"
    }

    /// What a client is told when [`Self::confirm`] returned `None`.
    fn confirmation_unavailable_message(&self) -> &str {
        "this call needs operator confirmation and no terminal is available to give it"
    }

    /// The second factors this operator channel can collect for a session
    /// call's MFA step: `"totp"`, `"fido2"`. None by default, so a host that
    /// has not built the step refuses MFA-gated profiles before prompting
    /// rather than prompting without it.
    fn mfa_methods(&self) -> &[&'static str] {
        &[]
    }

    /// What a client is told when a gated profile needs a factor this
    /// channel cannot collect.
    fn mfa_unavailable_message(&self) -> &str {
        "this connection profile requires your MFA, and none of the factors enrolled on your account can be completed here"
    }
}

/// The text a confirmation shows for a session call (§9): every field the
/// call carries, and the command in a gutter so each of its lines -- and so
/// each line break -- is visible, never truncated, with its byte length.
/// For a web fetch, the method and the path with its query, whole. Everything
/// is escaped for display; nothing here is a secret.
pub fn render_session_detail(call: &SessionCall) -> String {
    if call.protocol == "web" {
        let mut out = format!(
            "Resource:  {}\nProfile:   {}\nProtocol:  web\nRequest:   {} {}\nPath:      {} bytes, with its query",
            escape_for_display(&call.resource),
            escape_for_display(&call.profile),
            escape_for_display(&call.method),
            escape_for_display(&call.path),
            call.path.len(),
        );
        if let Some(timeout) = call.timeout_secs {
            out.push_str(&format!("\nTimeout:   {timeout} s"));
        }
        return out;
    }
    let command = escape_for_display(&call.command);
    let lines = command.split('\n').count();
    let mut out = format!(
        "Resource:  {}\nProfile:   {}\nProtocol:  {}\nCommand:   {} bytes, {} line{}",
        escape_for_display(&call.resource),
        escape_for_display(&call.profile),
        call.protocol,
        call.command.len(),
        lines,
        if lines == 1 { "" } else { "s" },
    );
    if let Some(timeout) = call.timeout_secs {
        out.push_str(&format!("\nTimeout:   {timeout} s"));
    }
    for line in command.split('\n') {
        out.push_str("\n  | ");
        out.push_str(line);
    }
    out
}

/// Most entries a grant's path scope may carry. Far beyond any real scope;
/// it bounds what an operator channel (a GUI form) can hand the store.
pub const MAX_PATH_SCOPE_ENTRIES: usize = 64;
/// Longest single path-scope glob a grant may carry.
pub const MAX_PATH_SCOPE_LEN: usize = 512;

/// Checks and tidies a grant an operator channel produced before it becomes
/// a pairing: every tool must exist in this build's catalogue, the scope is
/// bounded, a confirmation flag cannot outlive the permission it confirms,
/// and the token TTL is clamped to the ceiling. The vault re-checks all of
/// this at exchange time; this is so an operator is told at approval rather
/// than at the first refused call.
pub fn normalize_grant(grant: PairingGrant) -> Result<PairingGrant, String> {
    let mut tool_allowlist: Vec<String> = Vec::new();
    for tool in grant.tool_allowlist.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        if catalogue::find(tool).is_none() {
            return Err(format!("`{}` is not a tool in this build's catalogue", sanitize_for_model(tool)));
        }
        if !tool_allowlist.iter().any(|t| t == tool) {
            tool_allowlist.push(tool.to_string());
        }
    }
    if tool_allowlist.is_empty() {
        return Err("a pairing needs at least one tool".to_string());
    }
    if let Some(session_tool) = tool_allowlist.iter().find(|t| catalogue::find(t).is_some_and(|m| m.open_world)) {
        if !grant.connect_allowed {
            return Err(format!(
                "`{session_tool}` opens brokered sessions to your servers; allow brokered sessions (connect_allowed) \
                 to grant it, or leave it out"
            ));
        }
    }

    let mut path_scope: Vec<String> = Vec::new();
    for glob in grant.path_scope.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
        if glob.len() > MAX_PATH_SCOPE_LEN {
            return Err(format!("a path scope entry is longer than {MAX_PATH_SCOPE_LEN} characters"));
        }
        if !path_scope.iter().any(|p| p == glob) {
            path_scope.push(glob.to_string());
        }
    }
    if path_scope.len() > MAX_PATH_SCOPE_ENTRIES {
        return Err(format!("a path scope may have at most {MAX_PATH_SCOPE_ENTRIES} entries"));
    }

    if grant.ttl_secs == 0 {
        return Err("the token lifetime must be at least one second".to_string());
    }
    let namespace = grant.namespace.as_deref().map(super::link::normalize_namespace).transpose()?;

    Ok(PairingGrant {
        tool_allowlist,
        path_scope,
        reveal_allowed: grant.reveal_allowed,
        destructive_allowed: grant.destructive_allowed,
        confirm_reveal: grant.reveal_allowed && grant.confirm_reveal,
        confirm_destructive: grant.destructive_allowed && grant.confirm_destructive,
        connect_allowed: grant.connect_allowed,
        // Never what the channel asked for: on whenever sessions are.
        confirm_connect: grant.connect_allowed,
        ttl_secs: grant.ttl_secs.min(MAX_TOKEN_TTL_SECS),
        namespace,
    })
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
        connect_allowed: grant.connect_allowed,
        confirm_connect: grant.connect_allowed,
        ttl_secs: grant.ttl_secs,
        approved_at: now,
        expires_at: Some(now + DEFAULT_PAIRING_LIFETIME_SECS),
        last_used_at: now,
        namespace: grant.namespace.clone(),
    };
    (record, token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::default_tool_allowlist;

    fn grant() -> PairingGrant {
        PairingGrant {
            tool_allowlist: default_tool_allowlist(),
            path_scope: vec!["secret/metadata/ai/*".into()],
            reveal_allowed: false,
            destructive_allowed: false,
            confirm_reveal: true,
            confirm_destructive: true,
            connect_allowed: false,
            confirm_connect: false,
            ttl_secs: 8 * 3600,
            namespace: None,
        }
    }

    /// T457 Phase 2: a narrowing chosen at approval is canonicalized, refused
    /// when malformed, and recorded on the pairing.
    #[test]
    fn a_narrowing_is_normalized_and_recorded() {
        let mut g = grant();
        g.namespace = Some("/dti/esi/".into());
        let normalized = normalize_grant(g.clone()).unwrap();
        assert_eq!(normalized.namespace.as_deref(), Some("dti/esi"));
        let request = PairingRequest {
            client_name: "c",
            client_version: "1",
            transport: Transport::Stdio,
            peer_uid: None,
            namespace: Some("dti"),
        };
        let (record, _) = build_record(&request, &normalized, 1);
        assert_eq!(record.namespace.as_deref(), Some("dti/esi"), "the grant's choice, not the dialog's default");
        let (record, _) = build_record(&request, &normalize_grant(grant()).unwrap(), 1);
        assert_eq!(record.namespace, None, "no choice: the tokens follow the session");

        g.namespace = Some("dti/../root".into());
        assert!(normalize_grant(g).unwrap_err().contains("not a well-formed namespace path"));
    }

    #[test]
    fn a_session_tool_needs_connect_allowed_and_connect_is_always_confirmed() {
        let mut g = grant();
        g.tool_allowlist.push("bv_resource_ssh_exec".into());
        let err = normalize_grant(g.clone()).unwrap_err();
        assert!(err.contains("bv_resource_ssh_exec") && err.contains("connect_allowed"), "{err}");

        // A channel asking for sessions without confirmation gets them confirmed.
        g.connect_allowed = true;
        g.confirm_connect = false;
        let normalized = normalize_grant(g).unwrap();
        assert!(normalized.connect_allowed && normalized.confirm_connect);

        // Reveal and sessions together are allowed (the owner's decision).
        let mut both = grant();
        both.tool_allowlist.push("bv_resource_ssh_exec".into());
        both.reveal_allowed = true;
        both.connect_allowed = true;
        let both = normalize_grant(both).unwrap();
        assert!(both.reveal_allowed && both.connect_allowed && both.confirm_connect);

        // No sessions, nothing to confirm; and the record follows the grant.
        let none = normalize_grant(grant()).unwrap();
        assert!(!none.connect_allowed && !none.confirm_connect);
        let request = PairingRequest {
            client_name: "c",
            client_version: "1",
            transport: Transport::Stdio,
            peer_uid: None,
            namespace: None,
        };
        let (record, _) = build_record(&request, &both, 1);
        assert!(record.connect_allowed && record.confirm_connect);
    }

    #[test]
    fn the_session_detail_shows_every_field_and_every_line_escaped() {
        let call = SessionCall {
            tool: "bv_resource_ssh_exec",
            protocol: "ssh",
            resource: "web-01".into(),
            profile: "agent-ops".into(),
            command: "journalctl -u nginx\n\tuptime\u{00A0}x".into(),
            method: String::new(),
            path: String::new(),
            timeout_secs: Some(15),
            args_hash: "h".into(),
            scope_subject: "resources/secrets/web-01/".into(),
        };
        let detail = render_session_detail(&call);
        assert_eq!(
            detail,
            "Resource:  web-01\nProfile:   agent-ops\nProtocol:  ssh\nCommand:   30 bytes, 2 lines\n\
             Timeout:   15 s\n  | journalctl -u nginx\n  | \\u{0009}uptime\\u{00A0}x"
        );
        assert!(detail.chars().all(|c| c == '\n' || !c.is_control()));
    }

    /// A web fetch shows the method and the whole path with its query.
    #[test]
    fn the_web_detail_shows_the_method_and_the_whole_path() {
        let path = format!("/api/search?q={}&verbose=1", "a".repeat(300));
        let call = SessionCall {
            tool: "bv_resource_web_fetch",
            protocol: "web",
            resource: "grafana".into(),
            profile: "agent-api".into(),
            command: String::new(),
            method: "HEAD".into(),
            path: path.clone(),
            timeout_secs: None,
            args_hash: "h".into(),
            scope_subject: "resources/secrets/grafana/".into(),
        };
        let detail = render_session_detail(&call);
        assert_eq!(
            detail,
            format!(
                "Resource:  grafana\nProfile:   agent-api\nProtocol:  web\nRequest:   HEAD {path}\nPath:      {} bytes, with its query",
                path.len()
            )
        );
    }

    #[test]
    fn a_default_grant_is_kept_and_unpermitted_confirmations_are_dropped() {
        let g = normalize_grant(grant()).unwrap();
        assert_eq!(g.tool_allowlist, default_tool_allowlist());
        assert!(!g.confirm_reveal && !g.confirm_destructive, "nothing to confirm when nothing is permitted");
        assert_eq!(g.ttl_secs, 8 * 3600);
    }

    #[test]
    fn confirmations_stay_on_for_permitted_reveals_and_writes() {
        let mut g = grant();
        g.reveal_allowed = true;
        g.destructive_allowed = true;
        let g = normalize_grant(g).unwrap();
        assert!(g.confirm_reveal && g.confirm_destructive);
    }

    #[test]
    fn unknown_tools_and_empty_tool_lists_are_refused() {
        let mut g = grant();
        g.tool_allowlist = vec!["bv_kv_read".into(), "bv_format_disk".into()];
        assert!(normalize_grant(g).unwrap_err().contains("bv_format_disk"));
        let mut g = grant();
        g.tool_allowlist = vec!["  ".into()];
        assert!(normalize_grant(g).is_err());
    }

    #[test]
    fn scope_and_tools_are_trimmed_and_deduplicated() {
        let mut g = grant();
        g.tool_allowlist = vec![" bv_kv_read ".into(), "bv_kv_read".into()];
        g.path_scope = vec![" secret/* ".into(), "".into(), "secret/*".into()];
        let g = normalize_grant(g).unwrap();
        assert_eq!(g.tool_allowlist, vec!["bv_kv_read".to_string()]);
        assert_eq!(g.path_scope, vec!["secret/*".to_string()]);
    }

    #[test]
    fn oversized_scopes_and_zero_ttl_are_refused_and_long_ttls_clamped() {
        let mut g = grant();
        g.path_scope = (0..=MAX_PATH_SCOPE_ENTRIES).map(|i| format!("p{i}/*")).collect();
        assert!(normalize_grant(g).is_err());
        let mut g = grant();
        g.path_scope = vec!["x".repeat(MAX_PATH_SCOPE_LEN + 1)];
        assert!(normalize_grant(g).is_err());
        let mut g = grant();
        g.ttl_secs = 0;
        assert!(normalize_grant(g).is_err());
        let mut g = grant();
        g.ttl_secs = 10 * MAX_TOKEN_TTL_SECS;
        assert_eq!(normalize_grant(g).unwrap().ttl_secs, MAX_TOKEN_TTL_SECS);
    }

    #[test]
    fn only_a_loopback_http_pairing_gets_a_bearer_and_only_its_hash_is_recorded() {
        let request = PairingRequest {
            client_name: "c",
            client_version: "1",
            transport: Transport::Uds,
            peer_uid: Some(7),
            namespace: None,
        };
        let (record, bearer) = build_record(&request, &grant(), 100);
        assert!(bearer.is_none() && record.pairing_token_hash.is_none());
        assert_eq!((record.peer_uid, record.transport.as_str()), (Some(7), "uds"));
        assert_eq!(record.expires_at, Some(100 + DEFAULT_PAIRING_LIFETIME_SECS));

        let request = PairingRequest {
            client_name: "c",
            client_version: "1",
            transport: Transport::LoopbackHttp,
            peer_uid: None,
            namespace: None,
        };
        let (record, bearer) = build_record(&request, &grant(), 100);
        let bearer = bearer.expect("loopback HTTP needs a bearer");
        assert_eq!(record.pairing_token_hash, Some(hash_token(&bearer)));
    }
}
