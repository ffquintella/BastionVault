//! `ResourceModule` as the vault's [`ConnectMfaGate`].
//!
//! The connect-MFA gate belongs to the resource engine — the flag lives on a
//! connection profile, the ticket is bound to a resource — but it has to be
//! enforced by whatever transport opens the session. Rustion was doing that by
//! calling `crate::modules::resource::connect_mfa::enforce` directly, which is
//! an engine naming another engine and the last edge in the
//! `resource → ssh_broker → rustion → resource` chain the roadmap flagged as
//! having no valid extraction order.
//!
//! Both methods forward into `connect_mfa`, which is where the logic stays.

use std::sync::Arc;

use crate::{
    errors::RvError,
    kernel_api::engines::{ConnectMfaGate, ConnectMfaGrant},
    logical::Request,
};

use super::{connect_mfa, ResourceModule};

#[maybe_async::maybe_async]
impl ConnectMfaGate for ResourceModule {
    async fn enforce(
        &self,
        req: &Request,
        ns_prefix: &str,
        resource: &str,
        profile_id: &str,
        ticket: Option<&str>,
    ) -> Result<Option<ConnectMfaGrant>, RvError> {
        let redeemed = connect_mfa::enforce(
            self.backend.core.as_ref(),
            req,
            ns_prefix,
            resource,
            profile_id,
            ticket,
        )
        .await?;
        Ok(redeemed
            .map(|t| ConnectMfaGrant { principal: t.principal, method: t.method }))
    }

    async fn resource_has_gated_profile(
        &self,
        ns_prefix: &str,
        resource: &str,
    ) -> Result<bool, RvError> {
        connect_mfa::resource_has_gated_profile(self.backend.core.as_ref(), ns_prefix, resource)
            .await
    }
}

/// Publish the resource module as the vault's connect-MFA gate.
pub fn register(module: Arc<ResourceModule>, services: &crate::kernel_api::KernelServices) {
    services.set_connect_mfa(module);
}
