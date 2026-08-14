//! `SshBrokerModule` as the vault's [`LoginClassPolicy`].
//!
//! The one thing another engine asks of the SSH broker: is this resource
//! pinned to brokered logins? The resource engine needs it to refuse attaching
//! a static SSH credential to a brokered resource, and it used to get it by
//! naming `SshBrokerModule`, `EffectiveLoginClass` and `LoginClass` directly.
//!
//! The full tier resolution — lock state, per-tier chain, lock violations —
//! stays inside this engine. The resource engine reads two of its six fields.
//!
//! A deployment that never configures brokering has no policy store yet, and
//! [`LoginClassVerdict::default`] is exactly the "shared credential, decided
//! by nothing" answer the caller's own fallback produced.

use std::sync::Arc;

use crate::{
    errors::RvError,
    kernel_api::engines::{LoginClassPolicy, LoginClassVerdict},
};

use super::{policy::LoginClass, SshBrokerModule};

#[maybe_async::maybe_async]
impl LoginClassPolicy for SshBrokerModule {
    async fn resolve_for(
        &self,
        resource_type: &str,
        asset_group_ids: &[String],
        resource_id: &str,
    ) -> Result<LoginClassVerdict, RvError> {
        let Some(store) = self.policy_store() else {
            return Ok(LoginClassVerdict::default());
        };
        let eff = store.resolve_for(resource_type, asset_group_ids, resource_id).await?;
        Ok(LoginClassVerdict {
            brokered: eff.login_class == LoginClass::Brokered,
            source: eff.login_class_source.to_string(),
        })
    }
}

/// Publish the ssh-broker module as the vault's login-class policy.
pub fn register(module: Arc<SshBrokerModule>, services: &crate::kernel_api::KernelServices) {
    services.set_login_class(module);
}
