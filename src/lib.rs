//! This crate is the 'library' part of BastionVault, a Rust and real free replica of Hashicorp Vault.
//! BastionVault is focused on identity-based secrets management and works in two ways independently:
//!
//! 1. A standalone application serving secrets management via RESTful API;
//! 2. A Rust crate that provides same features for other application to integrate.
//!
//! This document is only about the crate part of BastionVault. For the first working mode,
//! please go to BastionVault's [RESTful API documentation], which documents all BastionVault's RESTful API.
//! Users can use an HTTP client tool (curl, e.g.) to send commands to a running BastionVault server and
//! then have relevant secret management features.
//!
//! BastionVault is a fork of RustyVault. The rebrand reflects that this fork is taking a different
//! approach in the library while staying in the same secret-management domain.
//!
//! The second working mode, which works as a typical Rust crate called `bastion_vault`, allows Rust
//! application developers to integrate BastionVault easily into their own applications to have the
//! ability of secrets management such as secure key/vaule storage, public key cryptography, data
//! encryption and so forth.
//!
//! This is the official documentation of crate `bastion_vault`, and it's mainly for developers.
//! Once again, if you are looking for how to use the BastionVault server via a set of RESTful API,
//! then you may prefer the BastionVault's [RESTful API documentation].
//!
//! [Hashicorp Vault]: https://www.hashicorp.com/products/vault
//! [RESTful API documentation]: https://github.com/ffquintella/BastionVault

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::kernel_api::VaultCtx;
use crate::{
    config::Config,
    core::Core,
    errors::RvError,
    logical::{Request, Response},
    modules::{
        auth::AuthModule,
        credential::{
            approle::AppRoleModule, ferrogate::FerroGateModule, oidc::OidcModule, saml::SamlModule,
            userpass::UserPassModule,
        },
        policy::PolicyModule,
    },
    mount::MountsMonitor,
    storage::{Backend, BarrierType},
};

pub mod api;
pub mod audit;
pub mod backup;
pub mod exchange;
pub mod plugins;
pub mod scheduled_exports;
/// The read caches, now a module of the Tier 0 `bv-storage` crate — they and
/// `storage` reference each other, so they are one compilation unit either
/// way. Re-exported here so `bastion_vault::cache::*` paths are unchanged.
pub use bv_storage::cache;
/// The command-line client moved to the `bvault-cli` crate in Phase 4, which
/// sits above this one and above `bv-server`. It carried 111 of the last 300
/// commits' churn inside this compilation unit.
///
/// The server configuration model it used to own is [`config`] now — it was
/// never CLI code. It travelled into `bv-core` in Phase 4.5, next to the
/// `Core` that takes one.
pub use bv_core::config;
/// Moved to the Tier 0 `bv-context` crate. Not in the roadmap's Tier 0 list,
/// but it belongs there and `bv-logical` needs it.
pub use bv_context as context;
/// The vault kernel — `Core`, the mount table, the module registry, the seal
/// path and the server config model — now the Tier 2 `bv-core` crate. It sits
/// *below* the kernel tier, which is what makes the split work: `Core` does
/// not name a module. See roadmaps/workspace-decomposition.md § Phase 4.5.
pub use bv_core::core;
pub mod dos;
/// `RvError` now lives in the Tier 0 `bv-errors` crate. Re-exported here so
/// `crate::errors::RvError` and `bastion_vault::errors::RvError` keep
/// resolving unchanged. See roadmaps/workspace-decomposition.md § Phase 1.
pub use bv_errors as errors;
/// The three `RvError` constructor macros are `#[macro_export]`ed by
/// `bv-errors`, which places them at *that* crate's root. Re-exporting them
/// here restores the crate-root macro namespace the ~490 bare
/// `bv_error_string!(...)` call sites resolve through, and keeps the
/// `crate::bv_error_string!(...)` form working too.
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};
/// The request-pipeline hook traits, now in `bv-logical` alongside the
/// `Request` that carries an `Arc<dyn Handler>`.
pub use bv_logical::handler;
/// HSM backends for the seal path — a module of `bv-core`.
pub use bv_core::hsm;
/// The kernel contract modules depend on instead of `Core` — the Tier 1
/// `bv-kernel-api` crate. `impl VaultCtx for Core` travelled into `bv-core`
/// with the `Core` it implements for; the orphan rule allows it there and
/// nowhere else.
pub use bv_kernel_api as kernel_api;
/// The HTTP(S) API surface moved to the `bv-server` crate in Phase 4, which
/// sits *above* this one — it is the assembly layer, and it is what took
/// `actix-web` and `actix-tls` out of this crate's dependency graph. There is
/// deliberately no re-export: a shim here would put the web framework back.
/// Structured logging setup — a module of `bv-core`, which needs
/// `default_audit_options` when it bootstraps the audit device at unseal.
pub use bv_core::logging;
/// Request/Response/Backend/Path/Field — the Tier 0 `bv-logical` crate.
pub use bv_logical as logical;
/// The eight backend-definition macros are `#[macro_export]`ed by
/// `bv-logical`, which places them at *that* crate's root. Re-exporting them
/// here restores the crate-root macro namespace every engine's
/// `new_logical_backend!` / `new_path!` call site resolves through. Same
/// arrangement as `bv_error_string!` above; the `_internal` halves are the
/// recursive arms the public macros expand into and must travel with them.
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
};
pub mod metrics;
/// The module registry — a module of `bv-core`.
pub use bv_core::module_manager;
pub mod modules;
/// The mount table's management operations — a module of `bv-core`. The
/// engine-facing view is `bv_kernel_api::mount`, which this re-exports.
pub use bv_core::mount;
/// The request router, moved into `bv-kernel-api`: engines reach it through
/// [`kernel_api::VaultCtx::router`], so it sits below them.
pub use bv_kernel_api::router;
/// Diesel's generated table definition, moved into `bv-storage` alongside its
/// only reader (the MySQL backend).
#[cfg(feature = "storage_mysql")]
pub use bv_storage::schema;
/// Seal/unseal and the KEK providers — a module of `bv-core`.
pub use bv_core::seal;
/// Process-level server facts (version, uptime, listen address) — a module of
/// `bv-core`.
pub use bv_core::server_info;
/// Moved to the Tier 0 `bv-shamir` crate — the one directory in the original
/// Phase 1 list that really did reference nothing but `crate::errors`.
pub use bv_shamir as shamir;
/// Dashboard counters, moved into `bv-kernel-api` alongside
/// [`kernel_api::VaultCtx::stats`], which hands them out.
pub use bv_kernel_api::stats;
/// Barriers, physical backends and the read caches — the Tier 0 `bv-storage`
/// crate, and the extraction that takes hiqlite, diesel and rusty-s3 out of
/// the monolith's compilation unit.
pub use bv_storage as storage;
/// Shared helpers — the Tier 1 `bv-utils` crate.
pub use bv_utils as utils;

/// Shared test fixtures. Also reachable behind the `test-support` feature,
/// which `bv-server` turns on to build its HTTP harness on top of them.
#[cfg(any(test, feature = "test-support"))]
pub mod test_utils;

/// The two backend tests that need a second vault process; see the module
/// docs for why they are not next to the backends in `bv-storage`.
#[cfg(test)]
mod storage_backend_tests;

/// Engine tests that need `test_utils`, and so could not travel into the
/// engine crates. See the module docs.
#[cfg(test)]
mod engine_tests;

/// `Core`'s own tests, which could not travel into `bv-core`. See the module
/// docs.
#[cfg(test)]
mod core_tests;

/// When the test binary is spawned as a plugin subprocess (the
/// `ProcessRuntime` does this — same exe acts as runner *and* plugin
/// in the test suite), this constructor catches the env var the
/// runtime sets and dispatches into the subprocess plugin handler
/// before the test runner's `main` ever gets a chance. The handler
/// reads stdin, drives the JSON-RPC dance, exits.
///
/// Production builds don't run tests so this code is never reached
/// in a real deployment — gated on `cfg(test)` to keep it out of the
/// shipping crate.
#[cfg(test)]
#[ctor::ctor(unsafe)]
fn maybe_act_as_test_subprocess_plugin() {
    if std::env::var("BV_PLUGIN_MODE").ok().as_deref() == Some("1") {
        crate::plugins::process_runtime::run_test_subprocess_plugin();
    }
}

/// Exit ok
pub const EXIT_CODE_OK: sysexits::ExitCode = sysexits::ExitCode::Ok;
/// Exit code when server exits unexpectedly
pub const EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when server aborted
pub const EXIT_CODE_SERVER_ABORTED: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when loading configuration from file fails
pub const EXIT_CODE_LOAD_CONFIG_FAILURE: sysexits::ExitCode = sysexits::ExitCode::Config;
/// Exit code when insufficient params are passed via CLI
pub const EXIT_CODE_INSUFFICIENT_PARAMS: sysexits::ExitCode = sysexits::ExitCode::Usage;

/// Build timestamp in UTC
pub const BUILD_TIME: &str = build_time::build_time_utc!();

/// bastion_vault version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The module set a default BastionVault server mounts.
///
/// This list lives here, at the assembly point, and not in
/// `module_manager.rs`: naming the 17 concrete engine types is exactly the
/// dependency that would stop `bv-core` from being a crate independent of the
/// engines. See roadmaps/workspace-decomposition.md Phase 2 step 4.
///
/// **Order is load-bearing.** The namespace module is the multi-tenancy
/// registry and must initialise before the system module's request handlers
/// reference its store.
pub fn default_modules() -> Vec<Box<dyn crate::module_manager::ModuleFactory>> {
    use crate::modules::{
        cert_lifecycle::CertLifecycleModule, files::FilesModule, identity::IdentityModule,
        kv::KvModule, kv_v2::KvV2Module, ldap::LdapModule, namespace::NamespaceModule,
        notifications::NotificationsModule, pki::PkiModule, resource::ResourceModule,
        resource_group::ResourceGroupModule, rustion::RustionModule, ssh::SshModule,
        ssh_broker::SshBrokerModule, system::SystemModule, totp::TotpModule,
        transit::TransitModule, Module,
    };

    // One `Box::new(...)` per engine. The closure shape is what the blanket
    // `ModuleFactory` impl accepts.
    macro_rules! factory {
        ($ty:ident) => {
            Box::new(|c: Arc<Core>| Arc::new($ty::new(c)) as Arc<dyn Module>)
                as Box<dyn crate::module_manager::ModuleFactory>
        };
    }

    vec![
        factory!(KvModule),
        factory!(KvV2Module),
        factory!(PkiModule),
        factory!(ResourceModule),
        factory!(FilesModule),
        factory!(IdentityModule),
        factory!(NotificationsModule),
        factory!(ResourceGroupModule),
        factory!(RustionModule),
        factory!(SshModule),
        factory!(SshBrokerModule),
        factory!(TotpModule),
        factory!(TransitModule),
        factory!(LdapModule),
        factory!(CertLifecycleModule),
        // Namespace before system: see the note above.
        factory!(NamespaceModule),
        factory!(SystemModule),
    ]
}

pub struct BastionVault {
    pub core: ArcSwap<Core>,
    pub token: ArcSwap<String>,
}

#[maybe_async::maybe_async]
impl BastionVault {
    pub fn new(backend: Arc<dyn Backend>, config: Option<&Config>) -> Result<Self, RvError> {
        let barrier_type = config.map(|conf| conf.barrier_type).unwrap_or(BarrierType::Chacha20Poly1305);
        let cache_config = config.map(|c| c.cache.clone()).unwrap_or_default();
        // Apply process-level memory protections (`mlockall`,
        // `PR_SET_DUMPABLE`) before any cache allocation happens. Returns
        // `Err` when the operator has requested a guarantee we cannot
        // provide (e.g. `memlock = true` on Windows, or `mlockall` with
        // `RLIMIT_MEMLOCK` too low).
        crate::cache::guardrails::apply(&cache_config)?;
        // Wrap the physical backend in the ciphertext-only read cache
        // when enabled. No-op when `secret_cache_ttl_secs == 0` (default),
        // so existing deployments see zero overhead.
        let backend = crate::storage::wrap_with_cache(backend, &cache_config)?;
        // The mount table cannot name the plugin runtime (it sits below it in
        // the crate graph), so the runtime registers its `plugin:<name>`
        // resolver here, at the assembly point, before any mount can be built.
        crate::plugins::register_mount_resolver();
        let mut core = Core::new_with_barrier(backend, barrier_type);
        if let Some(conf) = config {
            core.mount_entry_hmac_level = conf.mount_entry_hmac_level;
            core.mounts_monitor_interval = conf.mounts_monitor_interval;
            core.cache_config = conf.cache.clone();
            // Seed the DoS guard from the optional `dos { ... }` config block.
            // The barrier-persisted value (if any) overrides this at unseal.
            if let Some(dos) = conf.dos.clone() {
                core.dos_guard.set_config(dos);
            }
        }

        let core = core.wrap();

        if core.mounts_monitor_interval > 0 {
            core.mounts_monitor.store(Some(Arc::new(MountsMonitor::new(core.clone(), core.mounts_monitor_interval))));
        }

        // The plugin runtime publishes itself as a `PluginHost` capability so
        // the notifications engine can dispatch a plugin channel without
        // naming `crate::plugins`. Not a `Module::register`, because the
        // runtime is not a module. See src/plugins/kernel_service.rs.
        core.kernel_services.set_plugin_host(crate::plugins::PluginRuntimeHost::new(core.clone()));

        // The namespace re-root migration runs at the very top of
        // `post_unseal` — before `ModuleManager::setup`, so before any module
        // exists to have published it, and deliberately before any system view
        // or root mount table is built. Registered here for the same reason
        // the plugin host is: this is the assembly point.
        core.kernel_services
            .set_reroot(Arc::new(crate::modules::namespace::kernel_service::NamespaceReroot));

        // The scheduled-export tick loop, which `Core::post_unseal` used to
        // start by name. A `Weak` handle, so registering it does not keep the
        // vault alive through the registry that lives on it.
        core.kernel_services.add_unseal_hook(Arc::new(
            crate::scheduled_exports::runner::ScheduledExportsHook::new(Arc::downgrade(&core)),
        ));

        core.module_manager().set_modules(default_modules(), core.clone())?;

        // add auth_module
        let auth_module = AuthModule::new(core.clone())?;
        core.module_manager().add_module(Arc::new(auth_module), &core.kernel_services)?;

        // add policy_module
        let policy_module = PolicyModule::new(core.clone());
        core.module_manager().add_module(Arc::new(policy_module), &core.kernel_services)?;

        // add credential module: userpass
        let userpass_module = UserPassModule::new(core.clone());
        core.module_manager().add_module(Arc::new(userpass_module), &core.kernel_services)?;

        // add credential module: approle
        let approle_module = AppRoleModule::new(core.clone());
        core.module_manager().add_module(Arc::new(approle_module), &core.kernel_services)?;

        // add credential module: fido2
        let fido2_module = modules::credential::fido2::Fido2Module::new(core.clone());
        core.module_manager().add_module(Arc::new(fido2_module), &core.kernel_services)?;

        // add credential module: oidc
        let oidc_module = OidcModule::new(core.clone());
        core.module_manager().add_module(Arc::new(oidc_module), &core.kernel_services)?;

        // add credential module: saml (Phase 1+2 — config + roles only)
        let saml_module = SamlModule::new(core.clone());
        core.module_manager().add_module(Arc::new(saml_module), &core.kernel_services)?;

        // add credential module: ferrogate (Phase 1 — config + admin lifecycle; login stubbed)
        let ferrogate_module = FerroGateModule::new(core.clone());
        core.module_manager().add_module(Arc::new(ferrogate_module), &core.kernel_services)?;

        Ok(Self { core: ArcSwap::new(core), token: ArcSwap::new(Arc::new(String::new())) })
    }

    pub async fn init(&self, seal_config: &core::SealConfig) -> Result<core::InitResult, RvError> {
        self.core.load().init(seal_config).await
    }

    pub async fn inited(&self) -> Result<bool, RvError> {
        self.core.load().inited().await
    }

    pub async fn unseal(&self, keys: &[&[u8]]) -> Result<bool, RvError> {
        for key in keys.iter() {
            if self.core.load().unseal(key).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Unseals the vault once and immediately generates new unseal keys.
    ///
    /// This is a high-level wrapper around the core's unseal_once method that provides
    /// one-time unseal functionality with automatic key rotation for enhanced security.
    ///
    /// # Arguments
    /// - `key`: The unseal key to use for the unseal operation
    ///
    /// # Returns
    /// A `Result` containing new unseal keys if successful, or an error if the operation fails.
    ///
    /// # Security
    /// - Prevents replay attacks by invalidating used keys
    /// - Automatically generates fresh keys for future use
    /// - Provides forward secrecy through key rotation
    pub async fn unseal_once(&self, key: &[u8]) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        self.core.load().unseal_once(key).await
    }

    /// Generates new unseal keys using the current Key Encryption Key (KEK).
    ///
    /// This is a high-level wrapper around the core's generate_unseal_keys method
    /// that creates a fresh set of unseal keys for future vault operations.
    ///
    /// # Returns
    /// A `Result` containing new unseal key shares, or an error if generation fails.
    ///
    /// # Requirements
    /// - The vault must be currently unsealed
    /// - A valid KEK must exist in the current state
    ///
    /// # Security
    /// - Uses Shamir's Secret Sharing for key distribution
    /// - Generated keys are cryptographically independent
    /// - Returns zeroizing vector for secure memory cleanup
    pub async fn generate_unseal_keys(&self) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        self.core.load().generate_unseal_keys().await
    }

    pub async fn seal(&self) -> Result<(), RvError> {
        self.core.load().seal().await
    }

    pub fn set_token<S: Into<String>>(&self, token: S) {
        self.token.store(Arc::new(token.into()));
    }

    pub async fn mount<S: Into<String>>(
        &self,
        token: Option<S>,
        path: S,
        mount_type: S,
    ) -> Result<Option<Response>, RvError> {
        let data = serde_json::json!({
            "type": mount_type.into(),
        })
        .as_object()
        .cloned();

        self.write::<String>(token.map(|t| t.into()), format!("sys/mounts/{}", path.into()), data).await
    }

    pub async fn unmount<S: Into<String>>(&self, token: Option<S>, path: S) -> Result<Option<Response>, RvError> {
        self.delete::<String>(token.map(|t| t.into()), format!("sys/mounts/{}", path.into()), None).await
    }

    pub async fn remount<S: Into<String>>(
        &self,
        token: Option<S>,
        from: S,
        to: S,
    ) -> Result<Option<Response>, RvError> {
        let data = serde_json::json!({
            "from": from.into(),
            "to": to.into(),
        })
        .as_object()
        .cloned();

        self.write::<String>(token.map(|t| t.into()), "sys/remount".to_string(), data).await
    }

    pub async fn enable_auth<S: Into<String>>(
        &self,
        token: Option<S>,
        path: S,
        auth_type: S,
    ) -> Result<Option<Response>, RvError> {
        let data = serde_json::json!({
            "type": auth_type.into(),
        })
        .as_object()
        .cloned();

        self.write::<String>(token.map(|t| t.into()), format!("sys/auth/{}", path.into()), data).await
    }

    pub async fn disable_auth<S: Into<String>>(&self, token: Option<S>, path: S) -> Result<Option<Response>, RvError> {
        self.delete::<String>(token.map(|t| t.into()), format!("sys/auth/{}", path.into()), None).await
    }

    pub async fn login<S: Into<String>>(
        &self,
        path: S,
        data: Option<Map<String, Value>>,
    ) -> Result<(Option<Response>, bool), RvError> {
        let mut login_success = false;
        let mut req = Request::new_write_request(path, data);
        let resp = self.core.load().handle_request(&mut req).await?;
        if let Some(response) = resp.as_ref() {
            if let Some(auth) = response.auth.as_ref() {
                self.token.store(Arc::new(auth.client_token.clone()));
                login_success = true;
            }
        }

        Ok((resp, login_success))
    }

    pub async fn request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        self.core.load().handle_request(req).await
    }

    pub async fn read<S: Into<String>>(&self, token: Option<S>, path: &str) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_read_request(path);
        req.client_token = token.map(Into::into).unwrap_or_else(|| self.token.load().as_ref().clone());
        self.request(&mut req).await
    }

    pub async fn write<S: Into<String>>(
        &self,
        token: Option<S>,
        path: S,
        data: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_write_request(path, data);
        req.client_token = token.map(Into::into).unwrap_or_else(|| self.token.load().as_ref().clone());
        self.request(&mut req).await
    }

    pub async fn delete<S: Into<String>>(
        &self,
        token: Option<S>,
        path: S,
        data: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_delete_request(path, data);
        req.client_token = token.map(Into::into).unwrap_or_else(|| self.token.load().as_ref().clone());
        self.request(&mut req).await
    }

    pub async fn list<S: Into<String>>(&self, token: Option<S>, path: S) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_list_request(path);
        req.client_token = token.map(Into::into).unwrap_or_else(|| self.token.load().as_ref().clone());
        self.request(&mut req).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{
        core::SealConfig,
        storage::{barrier_chacha20_poly1305::BARRIER_CHACHA20_POLY1305_VERSION, BarrierType, StorageEntry},
        test_utils::new_test_backend,
    };

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_bastion_vault_uses_chacha_barrier_when_configured() {
        let test_name = format!(
            "test_bastion_vault_uses_chacha_barrier_when_configured_{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        );
        let backend = new_test_backend(&test_name);
        let config = Config { barrier_type: BarrierType::Chacha20Poly1305, ..Default::default() };
        let bvault = BastionVault::new(backend.clone(), Some(&config)).unwrap();

        let seal_config = SealConfig { secret_shares: 1, secret_threshold: 1 };
        let init_result = bvault.init(&seal_config).await.unwrap();
        let unseal_key = init_result.secret_shares[0].clone();

        assert!(bvault.unseal(&[unseal_key.as_slice()]).await.unwrap());

        let entry = StorageEntry { key: "test/chacha".to_string(), value: b"payload".to_vec() };
        bvault.core.load().barrier.put(&entry).await.unwrap();

        let raw = backend.get(&entry.key).await.unwrap().unwrap();
        assert_eq!(raw.value[4], BARRIER_CHACHA20_POLY1305_VERSION);
    }
}
