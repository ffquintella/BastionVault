//! `PolicyModule` as the vault's [`PolicyGate`].
//!
//! Three questions, one evaluator. The point of the narrow surface is that an
//! engine cannot obtain an `ACL` and decide for itself: every verdict here
//! comes from `PolicyStore`, the same object the request pipeline uses.
//!
//! [`PolicyGate::caller_has_sudo`] is the one that does more than forward, and
//! only because `explain_capability` returns a two-field verdict the caller
//! always collapsed the same way (`allowed || is_root`).

use std::sync::Arc;

use crate::{
    errors::RvError,
    kernel_api::policy::PolicyGate,
    logical::Request,
};

use super::{policy::Capability, policy_store::PolicyStore, PolicyModule};

/// An owned handle to the live policy store.
///
/// `ArcSwap::load()` would do, but its `Guard` would then be held across the
/// `.await` in every method below. `load_full()` costs one refcount bump and
/// keeps this file out of the `await_holding_lock` category the repo has been
/// bitten by before.
trait LivePolicyStore {
    fn store(&self) -> std::sync::Arc<PolicyStore>;
}

impl LivePolicyStore for PolicyModule {
    fn store(&self) -> std::sync::Arc<PolicyStore> {
        self.policy_store.load_full()
    }
}

#[maybe_async::maybe_async]
impl PolicyGate for PolicyModule {
    async fn may_connect_target(&self, req: &Request, target_prefix: &str) -> bool {
        self.store().may_connect_target(req, target_prefix).await
    }

    async fn readable_targets(&self, req: &Request, targets: &[String]) -> Vec<bool> {
        self.store().readable_targets(req, targets).await
    }

    async fn caller_has_sudo(&self, req: &Request, path: &str) -> Result<bool, RvError> {
        let auth = req
            .auth
            .clone()
            .ok_or_else(|| crate::bv_error_response_status!(401, "no authenticated caller"))?;
        let acl = self
            .store()
            .new_acl_for_request(&auth.policies, None, &auth, req.namespace_path.as_deref())
            .await?;
        let verdict = acl.explain_capability(path, Capability::Sudo);
        Ok(verdict.allowed || verdict.is_root)
    }
}

/// Publish the policy module as the vault's policy gate.
pub fn register(module: Arc<PolicyModule>, services: &crate::kernel_api::KernelServices) {
    services.set_policy(module);
}
