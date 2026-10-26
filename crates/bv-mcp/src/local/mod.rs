//! The local MCP server's gatekeeper (`features/mcp-access.md` §3, §11),
//! shared by `bvault mcp serve` and the desktop app.
//!
//! It is a *gatekeeper and proxy*, not a second dispatcher. A local client
//! (Claude Desktop, Claude Code, an IDE...) speaks MCP to it over stdio, a
//! Unix socket or loopback HTTP; for each request it (1) works out which
//! client this is and whether the operator approved it, (2) mints an
//! MCP-bound token for that pairing from the operator's own session, and (3)
//! forwards the JSON-RPC message unchanged to the vault's MCP endpoint,
//! relaying the answer. The vault's dispatcher therefore remains the single
//! place tool gates, path scope, ACL and audit are enforced -- this code adds
//! only what the vault cannot know: who is on the other end of *this
//! machine's* socket, and whether a human said yes.
//!
//! Transport-agnostic by construction. A host supplies a [`VaultLink`] (how
//! it reaches the vault: the CLI over HTTP, the desktop app over its own
//! connection, embedded or remote) and a [`Prompter`] (how it reaches the
//! operator: the CLI's terminal, the desktop app's dialogs). Neither is
//! implemented here.
//!
//! Fail-closed everywhere: a prompter that cannot reach a human returns
//! `None`, which refuses the pairing or the call -- never a silent approval.
//! The minted token lives in this server's memory for the pairing's TTL and
//! is never written out; [`LocalServer::shutdown`] forgets it.
//!
//! The vault speaks the stateless MCP 2026-07-28 revision, in which every
//! request names its client in `_meta`. Clients on the earlier, stateful
//! revisions (Claude Code among them) open with `initialize` and name
//! themselves only there. On the line transports -- stdio and the Unix
//! socket, where one connection is one client for its whole life -- this
//! server answers that handshake itself and carries the identity it was given
//! onto every request it relays (see [`SessionState`]). Loopback HTTP is
//! stateless and does not take the handshake.

use std::{
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use bv_errors::RvError;

mod link;
mod operator;
mod server;
#[cfg(unix)]
pub mod uds;

pub use link::{
    exchange_request_body, mfa_begin_body, mfa_begin_error, mfa_preflight_from_begin, mfa_verify_body,
    minted_token_from_exchange, normalize_namespace, operator_namespace_from_lookup, ticket_from_verify,
    vault_error_text, ForwardError, McpCallRef, MfaBeginError, MfaPreflight, MintedToken, VaultLink,
    CONNECT_MFA_BEGIN_PATH, CONNECT_MFA_VERIFY_PATH, NAMESPACE_HEADER, TOKEN_LOOKUP_SELF_PATH,
};
pub use operator::{
    build_record, normalize_grant, render_session_detail, ConfirmRequest, MfaChallenge, MfaFactor, MfaStep,
    PairingDecision, PairingGrant, PairingRequest, Prompter, MAX_PATH_SCOPE_ENTRIES, MAX_PATH_SCOPE_LEN,
};
pub use server::{
    exchange_ttl, run_line_session, ConnInfo, ConnectionSlot, LocalServer, SessionState, GATEKEEPER_META_PREFIX,
    HANDSHAKE_PROTOCOL_VERSIONS, MAX_CONCURRENT_CONNECTIONS, MAX_MESSAGE_BYTES,
};

use crate::pairing::PairingStore;

/// The file name of the desktop app's socket, beside the pairing store.
pub const GUI_SOCKET_FILE_NAME: &str = "mcp-gui.sock";

/// Where the desktop app serves MCP and where its `--mcp-stdio` relay looks
/// for it: beside the pairing store, in the same owner-only directory, so
/// both ends derive one path from one rule and no path has to be configured.
pub fn default_gui_socket_path() -> Result<PathBuf, RvError> {
    Ok(PairingStore::default_path()?.with_file_name(GUI_SOCKET_FILE_NAME))
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_gui_socket_sits_beside_the_pairing_store() {
        let store = super::PairingStore::default_path().unwrap();
        let socket = super::default_gui_socket_path().unwrap();
        assert_eq!(socket.parent(), store.parent());
        assert_eq!(socket.file_name().unwrap(), super::GUI_SOCKET_FILE_NAME);
    }
}
