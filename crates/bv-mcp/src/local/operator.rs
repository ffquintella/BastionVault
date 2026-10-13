//! The operator side of the local gatekeeper: what a human is asked, what
//! they can answer, and the pairing record an approval becomes.

use crate::{
    catalogue,
    pairing::{
        hash_token, new_pairing_id, new_pairing_token, PairingRecord, Transport, DEFAULT_PAIRING_LIFETIME_SECS,
        MAX_TOKEN_TTL_SECS,
    },
    sanitize::sanitize_for_model,
};

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

    Ok(PairingGrant {
        tool_allowlist,
        path_scope,
        reveal_allowed: grant.reveal_allowed,
        destructive_allowed: grant.destructive_allowed,
        confirm_reveal: grant.reveal_allowed && grant.confirm_reveal,
        confirm_destructive: grant.destructive_allowed && grant.confirm_destructive,
        ttl_secs: grant.ttl_secs.min(MAX_TOKEN_TTL_SECS),
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
        ttl_secs: grant.ttl_secs,
        approved_at: now,
        expires_at: Some(now + DEFAULT_PAIRING_LIFETIME_SECS),
        last_used_at: now,
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
            ttl_secs: 8 * 3600,
        }
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
        let request =
            PairingRequest { client_name: "c", client_version: "1", transport: Transport::Uds, peer_uid: Some(7) };
        let (record, bearer) = build_record(&request, &grant(), 100);
        assert!(bearer.is_none() && record.pairing_token_hash.is_none());
        assert_eq!((record.peer_uid, record.transport.as_str()), (Some(7), "uds"));
        assert_eq!(record.expires_at, Some(100 + DEFAULT_PAIRING_LIFETIME_SECS));

        let request = PairingRequest {
            client_name: "c",
            client_version: "1",
            transport: Transport::LoopbackHttp,
            peer_uid: None,
        };
        let (record, bearer) = build_record(&request, &grant(), 100);
        let bearer = bearer.expect("loopback HTTP needs a bearer");
        assert_eq!(record.pairing_token_hash, Some(hash_token(&bearer)));
    }
}
