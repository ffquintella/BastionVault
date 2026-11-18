// The substrate, under the names this engine already spells it by. Private:
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
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    new_secret, new_secret_internal,
};

use std::{
    any::Any,
    sync::{Arc, Mutex},
};

use derive_more::Deref;

use crate::{
    errors::RvError,
    logical::{Backend, LogicalBackend},
};
use bv_kernel_api::{Module, VaultCtx};

pub mod path_config;
pub mod path_fido2_config;
pub mod path_fido2_credentials;
pub mod path_fido2_login;
pub mod path_fido2_register;
pub mod path_login;
pub mod path_step_up;
pub mod path_users;
pub mod username_mounts;

static USERPASS_BACKEND_HELP: &str = r#"
The "userpass" credential provider allows authentication using a combination of
a username and password, optionally reinforced with a TOTP second factor.

The username/password combination is configured using the "users/" endpoints by
a user with root access. Authentication is then done by supplying the username
and password (plus a "totp_code" when MFA is enabled) for "login".

Accounts can be enabled/disabled by an admin, temporarily locked out after
repeated failed password attempts (see "config/lockout"), and required to
present a TOTP code (see "config/mfa" and the per-user "totp_mfa_enabled" flag).
"#;

pub struct UserPassModule {
    pub name: String,
    pub backend: Arc<UserPassBackend>,
    /// What the last unseal's duplicate-username scan found (T500); `None`
    /// until one completes. Read with [`Self::take_last_duplicate_scan`].
    last_duplicate_scan: Arc<Mutex<Option<Vec<username_mounts::DuplicateUsername>>>>,
}

pub struct UserPassBackendInner {
    pub core: Arc<dyn VaultCtx>,
}

#[derive(Deref)]
pub struct UserPassBackend {
    #[deref]
    pub inner: Arc<UserPassBackendInner>,
}

impl UserPassBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self { inner: Arc::new(UserPassBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let userpass_backend_ref = self.inner.clone();

        let mut backend = new_logical_backend!({
            unauth_paths: ["login/*", "fido2/login/*", "fido2/config"],
            auth_renew_handler: userpass_backend_ref.login_renew,
            help: USERPASS_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.users_path()));
        backend.paths.push(Arc::new(self.user_list_path()));
        backend.paths.push(Arc::new(self.user_list_info_path()));
        backend.paths.push(Arc::new(self.user_password_path()));
        backend.paths.push(Arc::new(self.user_unlock_path()));
        backend.paths.push(Arc::new(self.lockout_config_path()));
        backend.paths.push(Arc::new(self.mfa_config_path()));
        backend.paths.push(Arc::new(self.login_path()));
        // FIDO2 paths
        backend.paths.push(Arc::new(self.fido2_config_path()));
        backend.paths.push(Arc::new(self.fido2_register_begin_path()));
        backend.paths.push(Arc::new(self.fido2_register_complete_path()));
        backend.paths.push(Arc::new(self.fido2_login_begin_path()));
        backend.paths.push(Arc::new(self.fido2_login_complete_path()));
        backend.paths.push(Arc::new(self.fido2_credentials_path()));
        // Verify-only second-factor re-validation. Authenticated callers
        // only — deliberately absent from `unauth_paths` above.
        backend.paths.push(Arc::new(self.step_up_begin_path()));
        backend.paths.push(Arc::new(self.step_up_verify_path()));

        backend
    }
}

impl UserPassModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            name: "userpass".to_string(),
            backend: Arc::new(UserPassBackend::new(core)),
            last_duplicate_scan: Arc::new(Mutex::new(None)),
        }
    }

    /// Take what the last unseal's duplicate-username scan found, leaving
    /// `None`: lets a test see that an unseal ran the scan.
    pub fn take_last_duplicate_scan(&self) -> Option<Vec<username_mounts::DuplicateUsername>> {
        self.last_duplicate_scan.lock().ok().and_then(|mut slot| slot.take())
    }
}

fn record_duplicate_scan(
    slot: &Mutex<Option<Vec<username_mounts::DuplicateUsername>>>,
    found: Option<Vec<username_mounts::DuplicateUsername>>,
) {
    if let (Some(found), Ok(mut slot)) = (found, slot.lock()) {
        *slot = Some(found);
    }
}

impl Module for UserPassModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let userpass = self.backend.clone();
        let userpass_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut userpass_backend = userpass.new_backend();
            userpass_backend.init()?;
            Ok(Arc::new(userpass_backend))
        };

        if let Some(auth_mounts) = core.auth_mounts() {
            auth_mounts.add_auth_backend("userpass", Arc::new(userpass_backend_new_func))?;
            // Disabling a userpass mount forgets its users' entity aliases (T522).
            let principals = Arc::new(username_mounts::UserPassPrincipals);
            if let Err(e) = auth_mounts.set_auth_mount_principals(username_mounts::USERPASS, Some(principals)) {
                log::warn!(target: "security", "userpass: disabling a mount will not forget its users' entity aliases: {e}");
            }
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }

    /// Report the usernames more than one userpass mount holds (T500), once
    /// per unseal, detached so a slow storage listing never holds it up. The
    /// `sync_handler` arm (off by default, built by no CI target) uses a thread.
    fn start_background(&self, core: Arc<dyn VaultCtx>) {
        let slot = self.last_duplicate_scan.clone();
        #[cfg(not(feature = "sync_handler"))]
        drop(tokio::task::spawn(async move {
            let found = username_mounts::report_duplicate_usernames(core.as_ref()).await;
            record_duplicate_scan(&slot, found);
        }));
        #[cfg(feature = "sync_handler")]
        drop(std::thread::spawn(move || {
            let found = username_mounts::report_duplicate_usernames(core.as_ref());
            record_duplicate_scan(&slot, found);
        }));
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if let Some(auth_mounts) = core.auth_mounts() {
            // A registry that refused the registration at setup refuses this too.
            let _ = auth_mounts.set_auth_mount_principals(username_mounts::USERPASS, None);
            return auth_mounts.delete_auth_backend("userpass");
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }
}
