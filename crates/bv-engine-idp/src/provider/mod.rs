//! Downstream providers (features/identity-provider.md §3). Each calls the
//! issue gate before it issues anything; Phase 3 ships SSH, Phase 4 RADIUS,
//! Phase 5 the SAML IdP and the OIDC OP (sharing `federation`).

pub mod federation;
pub mod oidc_op;
pub mod radius;
pub mod saml_idp;
pub mod ssh;

use crate::{
    entitlement::gate::{IssueDenied, IssueGate, IssueGrant, IssueRequest},
    logical::Request,
};

/// The decision an issue waits on. Implemented by [`IssueGate`] only; the
/// seam exists for the tests that prove each provider depends on the gate.
// Same macro-generated `double_must_use` as the gate's traits.
#[allow(clippy::double_must_use)]
#[maybe_async::maybe_async]
pub(crate) trait Authorizer: Send + Sync {
    async fn check(&self, req: &IssueRequest, http: Option<&Request>) -> Result<IssueGrant, IssueDenied>;
}

#[maybe_async::maybe_async]
impl Authorizer for IssueGate {
    async fn check(&self, req: &IssueRequest, http: Option<&Request>) -> Result<IssueGrant, IssueDenied> {
        self.authorize(req, http).await
    }
}
