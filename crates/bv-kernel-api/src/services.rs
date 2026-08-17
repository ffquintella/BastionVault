//! The service registry — typed accessors in place of `Arc::downcast`.
//!
//! Before this, a module reached a sibling with
//! `core.module_manager().get_module::<IdentityModule>("identity")`: a
//! name-keyed lookup followed by a downcast to a concrete type. Three things
//! were wrong with it, in ascending order of how much they cost:
//!
//! 1. It is a stringly-typed lookup that can silently return `None` when the
//!    name and the type disagree.
//! 2. It requires `ModuleManager`, which is Tier 2 — so an engine that used it
//!    dragged the kernel's module machinery into its compile unit.
//! 3. It requires *naming the concrete sibling type*, which is what actually
//!    pinned all 14 engines and the plugin runtime into one crate.
//!
//! Here, each provider registers itself as a trait object once, at module
//! construction, and consumers ask [`VaultCtx`](super::VaultCtx) for the
//! capability rather than for the module. No name, no downcast, no concrete
//! type.
//!
//! ## Registration and the empty-slot contract
//!
//! [`crate::module::Module::register`] is the hook: `ModuleManager` calls it
//! on every module as it installs the set, handing over this registry. A
//! module that provides nothing does nothing.
//!
//! Every accessor returns `Option`, and that is a real state rather than
//! defensive coding: a vault can legitimately run without an identity module
//! (minimal embedded builds do), and *every* consumer already handled `None` —
//! `get_module` returned `Option` too. The `Option` is deliberately **not**
//! collapsed into a no-op default implementation: "no identity module" and "an
//! identity module that found nothing" are different answers, and a silent
//! default would let a misconfigured build issue tokens with no `entity_id`
//! and log nothing. Callers log at WARN on the `None` arm; that discipline is
//! preserved from the code this replaced.
//!
//! ## Why `ArcSwap` and not `OnceLock`
//!
//! Registration happens once today, but a module can be added at runtime
//! (`ModuleManager::add_module`, which the credential backends use), and the
//! GUI's embedded vault builds and tears down cores in-process. `ArcSwap`
//! makes the read path — which is on every login and every connect — a plain
//! atomic load with no lock, and keeps replacement legal.
//!
//! The slots are `ArcSwap<Option<Arc<dyn _>>>` rather than the tidier
//! `ArcSwapOption<dyn _>`, because arc-swap's `RefCnt` is implemented only for
//! `Arc<T: Sized>` — an unsized trait object needs the extra indirection. Same
//! shape the identity module already uses for its own stores.

use arc_swap::ArcSwap;

use super::{
    auth::{AuthMountRegistry, TokenService},
    engines::{ConnectMfaGate, LoginClassPolicy, NotificationSink, PluginHost, TotpMfa},
    identity::IdentityService,
    namespace::NamespaceRegistry,
    pipeline::{DenialAudit, NsScopeDatafix, RequestPipeline, RerootActivation, UnsealHook},
    policy::PolicyGate,
    resource_group::ResourceGroupIndex,
};

use std::sync::Arc;

/// Capabilities the modules of a vault publish to each other.
///
/// One instance per `Core`. Cheap to read (an atomic load per accessor),
/// written only during module installation.
#[derive(Default)]
pub struct KernelServices {
    identity: ArcSwap<Option<Arc<dyn IdentityService>>>,
    tokens: ArcSwap<Option<Arc<dyn TokenService>>>,
    auth_mounts: ArcSwap<Option<Arc<dyn AuthMountRegistry>>>,
    policy: ArcSwap<Option<Arc<dyn PolicyGate>>>,
    namespaces: ArcSwap<Option<Arc<dyn NamespaceRegistry>>>,
    resource_groups: ArcSwap<Option<Arc<dyn ResourceGroupIndex>>>,
    notifications: ArcSwap<Option<Arc<dyn NotificationSink>>>,
    login_class: ArcSwap<Option<Arc<dyn LoginClassPolicy>>>,
    connect_mfa: ArcSwap<Option<Arc<dyn ConnectMfaGate>>>,
    totp_mfa: ArcSwap<Option<Arc<dyn TotpMfa>>>,
    plugin_host: ArcSwap<Option<Arc<dyn PluginHost>>>,
    // The Tier 2 slots: what `Core::handle_request` and `Core::post_unseal`
    // delegate to the kernel tier instead of calling by name. See
    // `crate::pipeline`.
    request_pipeline: ArcSwap<Option<Arc<dyn RequestPipeline>>>,
    denial_audit: ArcSwap<Option<Arc<dyn DenialAudit>>>,
    reroot: ArcSwap<Option<Arc<dyn RerootActivation>>>,
    ns_scope_datafix: ArcSwap<Option<Arc<dyn NsScopeDatafix>>>,
    unseal_hooks: ArcSwap<Vec<Arc<dyn UnsealHook>>>,
}

/// Generates the paired setter/getter for one slot.
///
/// A macro rather than ten hand-written pairs: the bodies are identical, and
/// the only thing worth reviewing per-slot is the trait name.
macro_rules! service_slot {
    ($set:ident, $get:ident, $field:ident, $trait:ident, $what:literal) => {
        #[doc = concat!("Publish the ", $what, " for this vault.")]
        pub fn $set(&self, service: Arc<dyn $trait>) {
            self.$field.store(Arc::new(Some(service)));
        }

        #[doc = concat!("The ", $what, ", or `None` when no module provides it.")]
        pub fn $get(&self) -> Option<Arc<dyn $trait>> {
            self.$field.load().as_ref().clone()
        }
    };
}

impl KernelServices {
    pub fn new() -> Self {
        Self::default()
    }

    service_slot!(set_identity, identity, identity, IdentityService, "identity service");
    service_slot!(set_tokens, tokens, tokens, TokenService, "token service");
    service_slot!(
        set_auth_mounts,
        auth_mounts,
        auth_mounts,
        AuthMountRegistry,
        "auth mount registry"
    );
    service_slot!(set_policy, policy, policy, PolicyGate, "policy gate");
    service_slot!(
        set_namespaces,
        namespaces,
        namespaces,
        NamespaceRegistry,
        "namespace registry"
    );
    service_slot!(
        set_resource_groups,
        resource_groups,
        resource_groups,
        ResourceGroupIndex,
        "asset-group index"
    );
    service_slot!(
        set_notifications,
        notifications,
        notifications,
        NotificationSink,
        "notification sink"
    );
    service_slot!(
        set_login_class,
        login_class,
        login_class,
        LoginClassPolicy,
        "login-class policy"
    );
    service_slot!(
        set_connect_mfa,
        connect_mfa,
        connect_mfa,
        ConnectMfaGate,
        "connect-MFA gate"
    );
    service_slot!(set_totp_mfa, totp_mfa, totp_mfa, TotpMfa, "TOTP verifier");
    // Registered by the assembly layer, not by a `Module`: the plugin runtime
    // is not one.
    service_slot!(set_plugin_host, plugin_host, plugin_host, PluginHost, "plugin runtime");

    // ── Tier 2: the request pipeline and the unseal path ──────────────
    service_slot!(
        set_request_pipeline,
        request_pipeline,
        request_pipeline,
        RequestPipeline,
        "per-request multi-tenancy pipeline"
    );
    service_slot!(
        set_denial_audit,
        denial_audit,
        denial_audit,
        DenialAudit,
        "permission-denial audit sink"
    );
    // Registered by the assembly layer, like the plugin host: it runs before
    // any module is installed, so no module could have published it.
    service_slot!(
        set_reroot,
        reroot,
        reroot,
        RerootActivation,
        "namespace re-root migration"
    );
    service_slot!(
        set_ns_scope_datafix,
        ns_scope_datafix,
        ns_scope_datafix,
        NsScopeDatafix,
        "owner/share namespace-scope datafix"
    );

    /// Add a hook to run once per unseal, after the module set is initialised.
    ///
    /// A list rather than a single slot: unlike every other capability here,
    /// there is no reason two subsystems could not both want one, and the
    /// registration order is the run order. Appends rather than replaces, so a
    /// second registration cannot silently drop the first.
    pub fn add_unseal_hook(&self, hook: Arc<dyn UnsealHook>) {
        let mut next = self.unseal_hooks.load().as_ref().clone();
        next.push(hook);
        self.unseal_hooks.store(Arc::new(next));
    }

    /// The unseal hooks, in registration order.
    pub fn unseal_hooks(&self) -> Vec<Arc<dyn UnsealHook>> {
        self.unseal_hooks.load().as_ref().clone()
    }
}
