//! The steps `Core::handle_request` and `Core::post_unseal` delegate to the
//! kernel tier.
//!
//! These are the last edges pointing *down* out of `Core` into a module —
//! the ones Phase 2 measured, named as "the `bv-core` ↔ `bv-kernel`
//! entanglement the target graph already predicts", and deliberately left
//! alone because resolving them is a Tier 2 question. This module is that
//! resolution.
//!
//! ## Why the traits carry no context argument
//!
//! Every provider here is a kernel module that already holds an `Arc<Core>`
//! for its own work, so passing one back in would be handing an object its
//! own handle. `PolicyGate` and its siblings in this crate are shaped the
//! same way, for the same reason: the traits carry *operations*, not handles.
//!
//! [`RerootActivation`] is the exception and takes a `&dyn VaultCtx`,
//! because of when it runs — see below.
//!
//! ## Ordering, which is load-bearing
//!
//! [`RerootActivation::resolve`] runs **before** `ModuleManager::setup`, so at
//! that moment no module is registered and no module could have published
//! itself. It is registered by the assembly layer instead, next to the plugin
//! host, which is the same arrangement and for the same reason. It must also
//! run before any system view or root mount table is built, so the root
//! tenant's first read lands at the active prefix — that is why it cannot
//! simply be deferred until modules exist.
//!
//! [`NsScopeDatafix`] runs *after* `ModuleManager::init`, because it needs
//! both the identity stores and the loaded root mount table, so it is an
//! ordinary registered service.

use std::sync::Arc;

use bv_errors::RvError;
use bv_logical::Request;

use crate::VaultCtx;

/// The per-request multi-tenancy steps, in the order `handle_request` runs
/// them.
///
/// Provided by the namespace module. Every method is a no-op for a vault with
/// no namespaces configured, which is why an absent provider and a provider
/// that does nothing are equivalent here — unlike the identity slots, where
/// the distinction is a security property.
#[maybe_async::maybe_async]
pub trait RequestPipeline: Send + Sync {
    /// Converge the `X-BastionVault-Namespace` header onto the path-prefix
    /// form so the shared router dispatches namespace mounts uniformly.
    ///
    /// Runs before the pre-route phase, and mutates the request.
    async fn rewrite_request(&self, req: &mut Request) -> Result<(), RvError>;

    /// Reject a token used outside its namespace.
    ///
    /// Runs once auth is resolved and before any backend dispatch. A
    /// `child_visible` token may reach a descendant namespace; nothing else
    /// crosses.
    async fn enforce_token_binding(&self, req: &Request) -> Result<(), RvError>;

    /// Per-namespace request-rate quota. `Err` becomes a 429.
    async fn enforce_request_rate(&self, req: &Request) -> Result<(), RvError>;

    /// Per-namespace storage-bytes quota. `Err` becomes a 507. A no-op for
    /// non-writes and for root or unlimited namespaces.
    async fn enforce_write_storage_quota(&self, req: &Request) -> Result<(), RvError>;
}

/// Persistence for permission denials.
///
/// Provided by the system module. `Core` counts denials in memory for the
/// dashboard; this is what makes them survive a restart and show up on the
/// Audit page. Best-effort by contract — the 403 is returned unchanged
/// whether or not the append succeeds, so the method cannot fail.
#[maybe_async::maybe_async]
pub trait DenialAudit: Send + Sync {
    async fn record_denial(&self, req: &Request);
}

/// The namespace re-root migration, run at the very top of `post_unseal`.
///
/// Takes a `&dyn VaultCtx` rather than relying on a stored handle because it
/// runs before module registration — there is no module yet to hold one. The
/// assembly layer publishes it directly.
///
/// Returns the root namespace uuid when the caller should activate re-root,
/// or `None` to leave the legacy layout authoritative for this boot. Fails
/// safe: an unverifiable copy returns `None` rather than an error.
#[maybe_async::maybe_async]
pub trait RerootActivation: Send + Sync {
    async fn resolve(&self, ctx: &dyn VaultCtx) -> Result<Option<String>, RvError>;
}

/// The one-shot datafix that re-keys legacy bare owner/share records to their
/// namespace-scoped form.
///
/// Provided by the identity module. Marker-guarded, so it is a no-op on every
/// boot after the first.
///
/// Returns `None` when the marker says it has already run — the common case —
/// and otherwise a human-readable summary for the migration log. A summary
/// string rather than the module's own report type: `bv-kernel-api` cannot
/// name a type that lives in the kernel it is the contract for, so what
/// crosses is owned data. Same rule as `IdentityService::rename_object`.
#[maybe_async::maybe_async]
pub trait NsScopeDatafix: Send + Sync {
    async fn run_if_needed(&self) -> Result<Option<String>, RvError>;
}

/// A background scheduler the assembly layer owns, started at unseal.
///
/// `Core::post_unseal` used to call `scheduled_exports::start_scheduler` by
/// name, which is an edge from Tier 2 straight into a facade subsystem. The
/// engines' schedulers stopped being called that way in Phase 2
/// (`Module::start_background`); this is the same inversion for the one
/// scheduler that is not a module's.
pub trait UnsealHook: Send + Sync {
    /// Called once per unseal, after the module set is initialised. Detached
    /// by contract: implementations spawn and return.
    fn on_unseal(&self, ctx: Arc<dyn VaultCtx>);
}
