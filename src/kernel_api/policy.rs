//! Authorization questions an engine is allowed to ask.
//!
//! Not an ACL handle. The policy engine's `ACL`, `Policy`, `PermissionsEntry`
//! and `Capability` types are the evaluator's internals; an engine that could
//! name them could also build one, and a second place that decides what a
//! caller may do is a second place to get it wrong. So this trait exposes the
//! three *questions* the engines actually ask, each answered by the same
//! evaluator the request pipeline uses:
//!
//! | question | asked by |
//! |---|---|
//! | may this caller open a session to this target? | rustion, resource connect-MFA |
//! | which of these objects may this caller see? | rustion, resource listing |
//! | does this caller hold `sudo` here? | rustion raw `session/open` |
//!
//! All three take the caller's own `Request` rather than a synthesized one.
//! That is load-bearing and was a real bug once: the identity-less
//! `Request::default()` probe reports "denied" for every share-grantee,
//! because scope-gated rules resolve owner and share qualifiers off the
//! request. See `PolicyStore::may_connect_target`.

use crate::{errors::RvError, logical::Request};

#[maybe_async::maybe_async]
pub trait PolicyGate: Send + Sync {
    /// May the caller behind `req` open a session to `target_prefix`?
    ///
    /// Asks for the `connect` capability explicitly, and resolves owner and
    /// share qualifiers off `req` — so an owner or a `connect`-share grantee
    /// passes, and a read-only share does not.
    ///
    /// Fails closed: any evaluation error is `false`.
    async fn may_connect_target(&self, req: &Request, target_prefix: &str) -> bool;

    /// Which of `targets` may the caller behind `req` read?
    ///
    /// Returns one verdict per target, in order. Share- and owner-aware.
    async fn readable_targets(&self, req: &Request, targets: &[String]) -> Vec<bool>;

    /// Does the caller behind `req` hold `sudo` on `path` (or root)?
    ///
    /// `Err` when no ACL can be built for the caller — the caller should treat
    /// that as a refusal, never as a pass.
    async fn caller_has_sudo(&self, req: &Request, path: &str) -> Result<bool, RvError>;
}
