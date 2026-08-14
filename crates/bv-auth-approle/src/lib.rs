//! The approle auth method allows machines or apps to authenticate with BastionVault-defined roles.
//! The open design of AppRole enables a varied set of workflows and configurations to handle
//! large numbers of apps. This auth method is oriented to automated workflows (machines and
//! services), and is less useful for human operators. We recommend using batch tokens with
//! the AppRole auth method.
//!
//! An "AppRole" represents a set of Vault policies and login constraints that must be met to
//! receive a token with those policies. The scope can be as narrow or broad as desired.
//! An AppRole can be created for a particular machine, or even a particular user on that
//! machine, or a service spread across machines. The credentials required for successful
//! login depend upon the constraints set on the AppRole associated with the credentials.
//!
//! ## Credentials/Constraints
//!
//! ### RoleID
//!
//! RoleID is an identifier that selects the AppRole against which the other credentials are
//! evaluated. When authenticating against this auth method's login endpoint, the RoleID is
//! a required argument (via `role_id`) at all times. By default, RoleIDs are unique UUIDs,
//! which allow them to serve as secondary secrets to the other credential information.
//! However, they can be set to particular values to match introspected information by the
//! client (for instance, the client's domain name).
//!
//! ### SecretID
//!
//! SecretID is a credential that is required by default for any login (via `secret_id`) and
//! is intended to always be secret. (For advanced usage, requiring a SecretID can be disabled
//! via an AppRole's `bind_secret_id` parameter, allowing machines with only knowledge of the
//! RoleID, or matching other set constraints, to fetch a token). SecretIDs can be created
//! against an AppRole either via generation of a 128-bit purely random UUID by the role
//! itself (`Pull` mode) or via specific, custom values (`Push` mode).
//! Similarly to tokens, SecretIDs have properties like usage-limit, TTLs and expirations.
//!
//! ### Further constraints
//!
//! `role_id` is a required credential at the login endpoint. AppRole pointed to by the `role_id`
//! will have constraints set on it. This dictates other `required` credentials for login.
//! The `bind_secret_id` constraint requires `secret_id` to be presented at the login endpoint.
//! Going forward, this auth method can support more constraint parameters to support varied set
//! of Apps.  Some constraints will not require a credential, but still enforce constraints for login.
//! For example, `secret_id_bound_cidrs` will only allow logins coming from IP addresses belonging
//! to configured CIDR blocks on the AppRole.

// The substrate, under the names this backend has always spelled it. Private:
// `crate::errors::RvError` and `crate::logical::Path` keep resolving inside
// the crate, and none of it leaks into the public API, so the extraction
// stayed a file move rather than an import rewrite.
// See roadmaps/workspace-decomposition.md § Phase 3.
use bv_context as context;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;
use bv_storage as storage;
use bv_utils as utils;

// The eight backend-definition macros are `#[macro_export]`ed by `bv-logical`,
// which places them at *that* crate's root; the call sites import them as
// `crate::new_path` and friends. The `_internal` halves are the recursive arms
// the public macros expand into, so they must travel with them.
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
};
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};

use std::{
    any::Any,
    collections::HashMap,
    sync::{atomic::AtomicU32, Arc},
};

use arc_swap::ArcSwapOption;
use derive_more::Deref;

use bv_kernel_api::{Module, VaultCtx};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation},
    utils::{locks::Locks, salt::Salt},
};

pub mod path_login;
pub mod path_role;
pub mod path_tidy_secret_id;
pub mod validation;

const HMAC_INPUT_LEN_MAX: usize = 4096;

/// `pub` so the relocated tests can address the same storage prefix they
/// assert against. A second hard-coded copy is how a test stops testing the
/// layout it names.
pub const SECRET_ID_PREFIX: &str = "secret_id/";
const SECRET_ID_LOCAL_PREFIX: &str = "secret_id_local/";
const SECRET_ID_ACCESSOR_PREFIX: &str = "accessor/";
const SECRET_ID_ACCESSOR_LOCAL_PREFIX: &str = "accessor_local/";

static APPROLE_BACKEND_HELP: &str = r#"
Any registered Role can authenticate itself with BastionVault. The credentials
depends on the constraints that are set on the Role. One common required
credential is the 'role_id' which is a unique identifier of the Role.
It can be retrieved from the 'role/<appname>/role-id' endpoint.

The default constraint configuration is 'bind_secret_id', which requires
the credential 'secret_id' to be presented during login. Refer to the
documentation for other types of constraints.`
"#;

#[derive(Deref)]
pub struct AppRoleModule {
    pub name: String,
    #[deref]
    pub backend: Arc<AppRoleBackend>,
}

pub struct AppRoleBackendInner {
    pub core: Arc<dyn VaultCtx>,
    pub salt: ArcSwapOption<Salt>,
    pub role_locks: Locks,
    pub role_id_locks: Locks,
    pub secret_id_locks: Locks,
    pub secret_id_accessor_locks: Locks,
    pub tidy_secret_id_cas_guard: AtomicU32,
}

#[derive(Deref)]
pub struct AppRoleBackend {
    #[deref]
    pub inner: Arc<AppRoleBackendInner>,
}

impl AppRoleBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { inner: Arc::new(AppRoleBackendInner::new(core)) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let approle_backend_ref = self.inner.clone();

        let mut backend = new_logical_backend!({
            unauth_paths: ["login"],
            auth_renew_handler: approle_backend_ref.login_renew,
            help: APPROLE_BACKEND_HELP,
        });

        let role_paths = self.role_paths();
        backend.paths.extend(role_paths.into_iter().map(Arc::new));
        backend.paths.push(Arc::new(self.login_path()));
        backend.paths.push(Arc::new(self.config_path()));

        backend.paths.push(Arc::new(self.role_path()));
        backend.paths.push(Arc::new(self.tidy_secret_id_path()));

        backend
    }

    // config - Read/set the server-wide mandatory-machine gate.
    pub fn config_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        new_path!({
            pattern: r"config$",
            fields: {
                "require_machine": {
                    field_type: FieldType::Bool,
                    description: "When true (default), every AppID login must present a FerroGate machine token bound to the role."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_config},
                {op: Operation::Write, handler: approle_backend_ref2.write_config}
            ],
            help: "AppID backend configuration: mandatory machine-binding gate."
        })
    }
}

impl AppRoleBackendInner {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            core,
            salt: ArcSwapOption::new(None),
            role_locks: Locks::new(),
            role_id_locks: Locks::new(),
            secret_id_locks: Locks::new(),
            secret_id_accessor_locks: Locks::new(),
            tidy_secret_id_cas_guard: AtomicU32::new(0),
        }
    }
}

impl AppRoleModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { name: "approle".to_string(), backend: Arc::new(AppRoleBackend::new(core)) }
    }
}

#[maybe_async::maybe_async]
impl Module for AppRoleModule {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let approle = self.backend.clone();
        let approle_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut approle_backend = approle.new_backend();
            approle_backend.init()?;
            Ok(Arc::new(approle_backend))
        };

        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.add_auth_backend("approle", Arc::new(approle_backend_new_func));
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }

    async fn init(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if core.system_view().is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let system_view = core.system_view().unwrap();
        let salt = Salt::new(Some(system_view.as_storage()), None).await?;

        self.backend.inner.salt.store(Some(Arc::new(salt)));

        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.delete_auth_backend("approle");
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }
}

