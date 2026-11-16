//! Outbound identity provider (features/identity-provider.md, T52). Phase 1:
//! one record per workforce identity, keyed by `entity_id`, with an immutable
//! `(login, uid, primary_gid)` allocated once and never reused, plus the
//! `active -> disabled -> removed` lifecycle. Phase 2: environments,
//! entitlements and the fail-closed issue gate. Phase 3: identity-bound SSH
//! certificates, the KRL and the signed deny feed. Phase 4: the RADIUS
//! provider (RadSec, opt-in UDP). Phase 5: the SAML IdP and the OIDC OP.
//! Served under `v2/idp/` only and from the root namespace only.

#![deny(unsafe_code)]

use bv_context as context;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;
use bv_storage as storage;

use std::{any::Any, sync::Arc};

use crate::{
    entitlement::{
        gate::{BrokerIssueAudit, CtxNamespaceLookup, IssueGate},
        store::EntitlementStore,
        EntitlementStoreSlot,
    },
    errors::RvError,
    kernel_api::{Module, VaultCtx},
    logical::Backend,
    posix::store::PosixStore,
    provider::{
        oidc_op::store::OidcStore,
        radius::{store::RadiusStore, RadiusRuntime},
        saml_idp::store::SamlStore,
        ssh::store::SshStore,
    },
    revoke::store::FeedStore,
    storage::Storage,
};

pub mod backend;
pub mod entitlement;
pub mod host;
pub mod posix;
pub mod provider;
pub mod revoke;
#[cfg(test)]
mod test_support;

/// The mount type an operator enables (`sys/mounts/idp type=idp`).
pub const IDP_LOGICAL_TYPE: &str = "idp";

/// Sub-view of the root system view that holds the POSIX identity store. Not
/// a mount's own view: there is one uid/gid space however many `idp` mounts
/// exist.
const POSIX_SUBVIEW: &str = "idp/posix/";

/// Sub-view holding environments and entitlements, shared the same way.
const AUTHZ_SUBVIEW: &str = "idp/authz/";

/// Phase 3: SSH provider configuration and the issued-certificate registry.
const SSH_SUBVIEW: &str = "idp/ssh/";

/// Phase 3: the deny feed's version state and signing key.
const REVOKE_SUBVIEW: &str = "idp/revoke/";

/// Phase 4: RADIUS configuration, NAS clients, profiles and passcodes.
const RADIUS_SUBVIEW: &str = "idp/radius/";

/// Phase 5: OIDC OP configuration, clients, codes and signing keys.
const OIDC_SUBVIEW: &str = "idp/oidc/";

/// Phase 5: SAML IdP configuration, service providers, replay cache, keys.
const SAML_SUBVIEW: &str = "idp/saml/";

/// Late-bound handle to the store: the backend is built at mount time, the
/// store only once the barrier is unsealed.
pub type PosixStoreSlot = arc_swap::ArcSwap<Option<Arc<PosixStore>>>;

/// The Phase 3, 4 and 5 stores, set together at unseal.
pub struct IssuanceStores {
    pub ssh: SshStore,
    pub feed: FeedStore,
    pub radius: RadiusStore,
    pub oidc: OidcStore,
    pub saml: SamlStore,
}

pub type IssuanceSlot = arc_swap::ArcSwap<Option<Arc<IssuanceStores>>>;

pub struct IdpModule {
    pub name: String,
    pub core: Arc<dyn VaultCtx>,
    pub store: Arc<PosixStoreSlot>,
    pub authz: Arc<EntitlementStoreSlot>,
    pub issuance: Arc<IssuanceSlot>,
    /// Phase 4: the RADIUS listeners' supervisor handle.
    pub radius: Arc<RadiusRuntime>,
}

impl IdpModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "idp".to_string(),
            core,
            store: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            authz: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            issuance: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
            radius: Arc::new(RadiusRuntime::default()),
        }
    }

    pub fn store(&self) -> Option<Arc<PosixStore>> {
        self.store.load().as_ref().clone()
    }

    pub fn entitlements(&self) -> Option<Arc<EntitlementStore>> {
        self.authz.load().as_ref().clone()
    }

    /// The issue gate over the current stores, the vault's namespace registry
    /// and its audit broker. Sealed, it denies everything.
    pub fn issue_gate(&self) -> IssueGate {
        issue_gate(&self.core, &self.store, &self.authz)
    }
}

/// Shared by the module and the backend so both build the same gate.
pub(crate) fn issue_gate(core: &Arc<dyn VaultCtx>, posix: &PosixStoreSlot, authz: &EntitlementStoreSlot) -> IssueGate {
    IssueGate::new(
        posix.load().as_ref().clone(),
        authz.load().as_ref().clone(),
        Arc::new(CtxNamespaceLookup { ctx: core.clone() }),
        Arc::new(BrokerIssueAudit { ctx: core.clone() }),
    )
}

#[maybe_async::maybe_async]
impl Module for IdpModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let store = self.store.clone();
        let authz = self.authz.clone();
        let issuance = self.issuance.clone();
        let radius = self.radius.clone();
        let backend_new_func = move |ctx: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let b = backend::IdpBackend::new(ctx, store.clone(), authz.clone(), issuance.clone(), radius.clone());
            let mut b = b.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend(IDP_LOGICAL_TYPE, Arc::new(backend_new_func))
    }

    async fn init(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        let Some(system_view) = self.core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let view: Arc<dyn Storage> = Arc::new(system_view.new_sub_view(POSIX_SUBVIEW));
        self.store.store(Arc::new(Some(Arc::new(PosixStore::new(view)))));
        let authz_view: Arc<dyn Storage> = Arc::new(system_view.new_sub_view(AUTHZ_SUBVIEW));
        self.authz.store(Arc::new(Some(Arc::new(EntitlementStore::new(authz_view)))));
        let ssh_view: Arc<dyn Storage> = Arc::new(system_view.new_sub_view(SSH_SUBVIEW));
        let revoke_view: Arc<dyn Storage> = Arc::new(system_view.new_sub_view(REVOKE_SUBVIEW));
        let radius_view: Arc<dyn Storage> = Arc::new(system_view.new_sub_view(RADIUS_SUBVIEW));
        let oidc_view: Arc<dyn Storage> = Arc::new(system_view.new_sub_view(OIDC_SUBVIEW));
        let saml_view: Arc<dyn Storage> = Arc::new(system_view.new_sub_view(SAML_SUBVIEW));
        let issuance = IssuanceStores {
            ssh: SshStore::new(ssh_view),
            feed: FeedStore::new(revoke_view),
            radius: RadiusStore::new(radius_view),
            oidc: OidcStore::new(oidc_view),
            saml: SamlStore::new(saml_view),
        };
        self.issuance.store(Arc::new(Some(Arc::new(issuance))));
        Ok(())
    }

    /// The RADIUS supervisor: started once, it binds only what
    /// `idp/radius/config` asks for (nothing until an operator writes it).
    fn start_background(&self, core: Arc<dyn VaultCtx>) {
        #[cfg(not(feature = "sync_handler"))]
        self.radius.start(Arc::new(provider::radius::server::VaultSource {
            ctx: Arc::downgrade(&core),
            posix: self.store.clone(),
            authz: self.authz.clone(),
            issuance: self.issuance.clone(),
        }));
        #[cfg(feature = "sync_handler")]
        drop(core);
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        self.store.store(Arc::new(None));
        self.authz.store(Arc::new(None));
        self.issuance.store(Arc::new(None));
        // Sealed: the supervisor stops the listeners now, not at its tick.
        self.radius.reconcile_soon();
        core.delete_logical_backend(IDP_LOGICAL_TYPE)
    }
}
