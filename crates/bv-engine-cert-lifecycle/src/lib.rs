//! Cert-lifecycle module — Phase L5 of the PKI key-management +
//! lifecycle initiative. See
//! [features/pki-key-management-and-lifecycle.md].
//!
//! Mounts at the global path `cert-lifecycle/`. Holds an inventory of
//! renewal targets and exposes a manual renew endpoint. The module
//! consumes the PKI engine — it never holds a CA key of its own. The
//! renewer dispatches `pki/issue/<role>` calls into the configured
//! PKI mount via [`Core::handle_request`] so the same role / issuer /
//! emission policies that gate any other caller apply here.
//!
//! Phase L5 surface:
//! - `LIST   /v1/cert-lifecycle/targets`
//! - `READ`/`WRITE`/`DELETE  /v1/cert-lifecycle/targets/<name>`
//! - `READ   /v1/cert-lifecycle/state/<name>`
//! - `WRITE  /v1/cert-lifecycle/renew/<name>` — manual renew
//!
//! L6 wires a periodic scheduler around the same `renew_target`
//! handler. L7 introduces a `CertDeliveryPlugin` trait so non-`file`
//! kinds can deliver via plugin-ext.

// The substrate, under the names the cert-lifecycle engine has always spelled it. Private:
// `crate::errors::RvError` and `crate::logical::Path` keep resolving inside
// the crate, and none of it leaks into the public API, so the extraction
// stayed a file move rather than an import rewrite.
// See roadmaps/workspace-decomposition.md § Phase 3.
use bv_context as context;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;

// The eight backend-definition macros are `#[macro_export]`ed by `bv-logical`,
// which places them at *that* crate's root; the call sites import them as
// `crate::new_path` and friends. The `_internal` halves are the recursive arms
// the public macros expand into, so they must travel with them.
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
};
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};

use std::{any::Any, collections::HashMap, sync::Arc};

use derive_more::Deref;
use serde_json::{json, Map, Value};

use bv_kernel_api::{Module, VaultCtx};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, LogicalBackend, Operation, Path, PathOperation, Request, Response},
};

pub mod delivery;
pub mod path_renew;
pub mod path_scheduler_config;
pub mod path_state;
pub mod path_targets;
pub mod scheduler;
pub mod storage;

const CERT_LIFECYCLE_BACKEND_HELP: &str = r#"
The cert-lifecycle engine renews and distributes certificates issued
by a PKI mount to consumer endpoints. Phase L5 supports a manual renew
endpoint that delivers the cert + key + chain into a filesystem
directory; the periodic scheduler (L6) and plugin-driven delivery (L7)
land in follow-ups.
"#;

pub struct CertLifecycleBackendInner {
    pub core: Arc<dyn VaultCtx>,
    /// Phase L7: lookup table for [`delivery::CertDeliveryPlugin`]
    /// implementations keyed by [`storage::TargetKind::as_str`].
    /// Built once at module construction with the engine's built-in
    /// `file` + `http-push` deliverers; an L7 follow-up will extend
    /// it from `plugin-ext` discovery at unseal time.
    pub deliverers: delivery::DelivererRegistry,
}

#[derive(Deref)]
pub struct CertLifecycleBackend {
    #[deref]
    pub inner: Arc<CertLifecycleBackendInner>,
}

impl CertLifecycleBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            inner: Arc::new(CertLifecycleBackendInner {
                core,
                deliverers: delivery::DelivererRegistry::with_builtins(),
            }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let paths: Vec<Path> = vec![
            self.targets_list_path(),
            self.target_path(),
            self.target_state_path(),
            self.renew_path(),
            self.scheduler_config_path(),
            self.sys_deliverers_path(),
        ];
        let mut backend = LogicalBackend::new();
        for p in paths {
            backend.paths.push(Arc::new(p));
        }
        backend.help = CERT_LIFECYCLE_BACKEND_HELP.to_string();
        backend
    }

    pub fn sys_deliverers_path(&self) -> Path {
        let r = self.inner.clone();
        new_path!({
            pattern: r"sys/deliverers$",
            operations: [{op: Operation::Read, handler: r.list_deliverers}],
            help: "List the cert-delivery plugins this engine knows about (Phase L7)."
        })
    }
}

#[maybe_async::maybe_async]
impl CertLifecycleBackendInner {
    pub async fn list_deliverers(
        &self,
        _b: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let names = self.deliverers.names();
        let mut data: Map<String, Value> = Map::new();
        data.insert("deliverers".into(), json!(names));
        Ok(Some(Response::data_response(Some(data))))
    }
}

pub struct CertLifecycleModule {
    pub name: String,
    pub backend: Arc<CertLifecycleBackend>,
}

impl CertLifecycleModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "cert-lifecycle".to_string(),
            backend: Arc::new(CertLifecycleBackend::new(core)),
        }
    }
}

impl Module for CertLifecycleModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    /// Boot the renewal scheduler (Phase L6). Each mount opts in via
    /// `cert-lifecycle/scheduler/config`; un-configured mounts are skipped on
    /// every tick. The renewal goes through the request pipeline with the
    /// operator-supplied `client_token`, so the PKI ACL boundary still
    /// applies.
    fn start_background(&self, core: Arc<dyn VaultCtx>) {
        // Detached on purpose: dropping the handle does not stop the task.
        drop(scheduler::start_cert_lifecycle_scheduler(core));
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let backend = self.backend.clone();
        let new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = backend.new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("cert-lifecycle", Arc::new(new_func))
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_logical_backend("cert-lifecycle")
    }
}
