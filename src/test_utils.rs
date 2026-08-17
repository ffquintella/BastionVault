//! Shared test fixtures.
//!
//! Available to this crate's own tests, and — behind the `test-support`
//! feature — to `bv-server`, which needs `new_test_bastion_vault` and the seal
//! helpers to build its own harness.
//!
//! The in-process HTTP harness ([`TestHttpServer`] and friends) went the other
//! way in Phase 4: it configures an actix `App` from `bv_server::init_service`,
//! so it had to travel up into that crate. It is re-exported below under its
//! original name, so the ~50 call sites in this crate that say
//! `crate::test_utils::TestHttpServer` did not change.

use std::{
    default::Default,
    env, fs,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use serde_json::{json, Map, Value};

use crate::kernel_api::VaultCtx;
use crate::{
    bv_error_string,
    core::{Core, InitResult, SealConfig},
    errors::RvError,
    logical::{self, Operation, Request, Response},
    BastionVault,
};

/// Used only by `test_multi_routine`, which is `cfg(test)` because it drives
/// a `TestHttpServer` from the dev-dependency.
#[cfg(test)]
use std::{str::FromStr, thread::sleep};
#[cfg(test)]
use crate::storage::Backend;

/// The backend fixtures now live in `bv-storage`, next to the barrier and
/// backend tests that use them; a test in that crate cannot import from this
/// one. Re-exported under their original names so every call site here and in
/// `tests/` is unchanged. See roadmaps/workspace-decomposition.md § Phase 1.
pub use bv_storage::test_support::{new_test_backend, new_test_file_backend, new_test_temp_dir, TEST_DIR};

/// The in-process HTTP harness, which moved to `bv-server` in Phase 4 — it
/// builds an actix `App` out of that crate's routes, so it belongs on that
/// side of the split. `bv-server` is a **dev**-dependency here (cargo permits
/// dev-dependency cycles), which is why this re-export is `cfg(test)` and not
/// available under the `test-support` feature: a consumer that turns the
/// feature on gets the fixtures below, not a web server.
#[cfg(test)]
pub use bv_server::test_support::{TestHttpServer, TestTlsClientAuth, TestTlsConfig};


/// Process-wide fixture setup, run before any test's `main`.
///
/// **This deliberately travels with the `test-support` feature and is not
/// `#[cfg(test)]`.** `bv-server` and `bvault-cli` stand up TLS listeners in
/// their harnesses, and a `cfg(test)` gate here would not fire for them —
/// `test` is per-crate, and they consume this module through the feature. So
/// the provider install and the `TEST_DIR` creation have to be part of what
/// the feature provides, or those two crates' suites would fault on the first
/// rustls handshake.
///
/// The consequence to be aware of: enabling `test-support` on a *non-test*
/// build installs a process-default crypto provider as a side effect. That is
/// why the feature is off by default and declared only in dev-dependencies.
/// `install_default` returns `Err` if a provider is already set, which is the
/// normal case when a real binary has already chosen one — hence `let _`, not
/// an unwrap: this must never override a deliberate choice made by the host.
mod fixture_init {
    use super::*;

    #[ctor::ctor(unsafe)]
    fn init() {
        let dir = env::temp_dir().join(TEST_DIR);
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(fs::create_dir_all(&dir).is_ok());
    }
}

pub fn new_test_cert(
    _is_ca: bool,
    _client_auth: bool,
    _server_auth: bool,
    _common_name: &str,
    _dns_sans: Option<&str>,
    _ip_sans: Option<&str>,
    _uri_sans: Option<&str>,
    _ttl: Option<&str>,
    _ca_cert_pem: Option<String>,
    _ca_key_pem: Option<String>,
) -> Result<(String, String), RvError> {
    Err(bv_error_string!("OpenSSL-based test certificate generation has been removed"))
}

pub fn new_test_cert_ext(
    _is_ca: bool,
    _client_auth: bool,
    _server_auth: bool,
    _common_name: &str,
    _dns_sans: Option<&str>,
    _ip_sans: Option<&str>,
    _uri_sans: Option<&str>,
    _ttl: Option<&str>,
    _ca_cert_pem: Option<String>,
    _ca_key_pem: Option<String>,
) -> Result<(String, String), RvError> {
    Err(bv_error_string!("OpenSSL-based test certificate generation has been removed"))
}

pub fn cert_to_x509(
    _cert: &(),
    _client_auth: bool,
    _server_auth: bool,
    _ca_cert: Option<&()>,
    _ca_key: Option<&()>,
    _private_key: &(),
) -> Result<(), RvError> {
    Err(bv_error_string!("OpenSSL-based X.509 test conversion has been removed"))
}

/// # Safety
///
/// This is a vestigial `unsafe` stub kept only for signature
/// compatibility after the OpenSSL-based test CRL generation was
/// removed. It performs no unsafe operations and always returns an
/// error, so callers have no invariant to uphold; the `unsafe` marker
/// is retained solely so existing call sites continue to type-check.
pub unsafe fn new_test_crl(_revoked_cert_pem: &str, _ca_cert_pem: &str, _ca_key_pem: &str) -> Result<String, RvError> {
    Err(bv_error_string!("OpenSSL-based test CRL generation has been removed"))
}

pub fn new_test_bastion_vault(name: &str) -> BastionVault {
    BastionVault::new(new_test_backend(name), None).unwrap()
}

#[maybe_async::maybe_async]
pub async fn init_test_bastion_vault(bvault: &BastionVault, seal_config: &SealConfig) -> InitResult {
    let result = bvault.init(seal_config).await;
    assert!(result.is_ok());

    result.unwrap()
}

#[maybe_async::maybe_async]
pub async fn unseal_test_bastion_vault(bvault: &BastionVault, keys: &[&[u8]]) -> bool {
    unseal_test_bastion_vault_core(bvault.core.load().as_ref(), keys).await
}

#[maybe_async::maybe_async]
pub async fn unseal_test_bastion_vault_core(core: &Core, keys: &[&[u8]]) -> bool {
    let mut unsealed = false;
    for key in keys.iter() {
        let unseal = core.unseal(key).await;
        assert!(unseal.is_ok());
        unsealed = unseal.unwrap();
    }

    unsealed
}

#[maybe_async::maybe_async]
pub async fn new_unseal_test_bastion_vault(name: &str) -> (BastionVault, Arc<Core>, String) {
    let seal_config = SealConfig { secret_shares: 9, secret_threshold: 5 };
    

    let bvault = new_test_bastion_vault(name);
    let init_result = init_test_bastion_vault(&bvault, &seal_config).await;

    println!("init_result: {:?}", init_result);

    let mut keys: Vec<Vec<u8>> = Vec::new();

    for i in 0..seal_config.secret_threshold {
        keys.push(init_result.secret_shares[i as usize].clone());
    }

    let k: Vec<&[u8]> = keys.iter().map(|v| v.as_slice()).collect();

    let result = unseal_test_bastion_vault(&bvault, &k).await;
    assert!(result);

    let root_token = init_result.root_token.clone();
    println!("root_token: {:?}", root_token);

    let core = bvault.core.load().clone();

    (bvault, core, root_token)
}


#[maybe_async::maybe_async]
pub async fn test_list_api(core: &dyn VaultCtx, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    println!("list path: {}, resp: {:?}", path, resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

/// Drives a real `TestHttpServer`, which lives in `bv-server` — a
/// dev-dependency here. So this helper, unlike the rest of the module, is not
/// available under the `test-support` feature.
#[cfg(test)]
pub fn test_multi_routine(backend: Arc<dyn Backend>) {
    let mut test_http_server1 = TestHttpServer::new_with_backend(backend.clone(), false);

    let ret = test_http_server1.cli(&["operator", "init"], &["--format=raw", "--key-shares=3", "--key-threshold=2"]);
    assert!(ret.is_ok());
    let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
    let init_result = ret.as_object().unwrap();

    let keys = &init_result["keys"];
    let _ret = test_http_server1.cli(&["operator", "unseal"], &["--format=raw", keys[0].as_str().unwrap()]);
    let ret = test_http_server1.cli(&["operator", "unseal"], &["--format=raw", keys[1].as_str().unwrap()]);
    let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
    let unseal_result = ret.as_object().unwrap();
    assert_eq!(unseal_result["sealed"], false);
    test_http_server1.root_token = init_result["root_token"].as_str().unwrap().to_string();
    test_http_server1.token = test_http_server1.root_token.clone();

    let mut test_http_server2 = TestHttpServer::new_with_backend(backend, false);

    let _ret = test_http_server2.cli(&["operator", "unseal"], &["--format=raw", keys[0].as_str().unwrap()]);
    let ret = test_http_server2.cli(&["operator", "unseal"], &["--format=raw", keys[1].as_str().unwrap()]);
    let ret = Value::from_str(ret.unwrap().as_str()).unwrap();
    let unseal_result = ret.as_object().unwrap();
    assert_eq!(unseal_result["sealed"], false);
    test_http_server2.root_token = init_result["root_token"].as_str().unwrap().to_string();
    test_http_server2.token = test_http_server2.root_token.clone();

    // test mount kv
    let ret = test_http_server1.mount("kv", "kv");
    println!("ret: {:?}", ret);
    assert!(ret.is_ok());

    let ret = test_http_server1.cli(&["write"], &["kv/foo", "aa=bb", "cc=dd"]);
    println!("ret: {:?}", ret);
    assert_eq!(ret, Ok("Success! Data written to: kv/foo\n".into()));

    let ret = test_http_server1.cli(&["read"], &["--format=json", "kv/foo"]);
    assert_eq!(ret, Ok("{\n  \"aa\": \"bb\",\n  \"cc\": \"dd\"\n}\n".into()));

    let ret = test_http_server2.cli(&["read"], &["--format=json", "kv/foo"]);
    assert_ne!(ret, Ok("{\n  \"aa\": \"bb\",\n  \"cc\": \"dd\"\n}\n".into()));

    sleep(Duration::from_secs(6));

    let ret = test_http_server2.cli(&["read"], &["--format=json", "kv/foo"]);
    assert_eq!(ret, Ok("{\n  \"aa\": \"bb\",\n  \"cc\": \"dd\"\n}\n".into()));

    // test mount auth
    // mount usepass auth to path: pass
    let mount = "pass";
    let ret = test_http_server1.mount_auth(mount, "userpass");
    assert!(ret.is_ok());

    // add user
    let username = "jinjiu";
    let password = "123123";
    let ret = test_http_server1.cli(
        &["write"],
        &[&format!("auth/{}/users/{}", mount, username), &format!("password={}", password), "ttl=600"],
    );
    assert!(ret.is_ok());

    sleep(Duration::from_secs(6));

    // clear token
    test_http_server2.token.clear();

    // test login
    let ret = test_http_server2.cli(
        &["login"],
        &[
            "--method=userpass",
            &format!("--path={}", mount),
            &format!("username={}", username),
            &format!("password={}", password),
        ],
    );
    println!("login ret: {:?}", ret);
    assert!(ret.is_ok());
}

#[maybe_async::maybe_async]
pub async fn test_read_api(core: &dyn VaultCtx, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req).await;
    println!("read path: {}, resp: {:?}", path, resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

#[maybe_async::maybe_async]
pub async fn test_write_api(
    core: &dyn VaultCtx,
    token: &str,
    path: &str,
    is_ok: bool,
    data: Option<Map<String, Value>>,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = data;

    let resp = core.handle_request(&mut req).await;
    println!("write path: {}, resp: {:?}", path, resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

#[maybe_async::maybe_async]
pub async fn test_delete_api(
    core: &dyn VaultCtx,
    token: &str,
    path: &str,
    is_ok: bool,
    data: Option<Map<String, Value>>,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    req.body = data;
    let resp = core.handle_request(&mut req).await;
    println!("delete path: {}, resp: {:?}", path, resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

#[maybe_async::maybe_async]
pub async fn test_mount_api(core: &dyn VaultCtx, token: &str, mtype: &str, path: &str) {
    let data = json!({
        "type": mtype,
    })
    .as_object()
    .cloned();

    let resp = test_write_api(core, token, format!("sys/mounts/{}", path).as_str(), true, data).await;
    assert!(resp.is_ok());
}

#[maybe_async::maybe_async]
pub async fn test_mount_auth_api(core: &dyn VaultCtx, token: &str, atype: &str, path: &str) {
    let auth_data = json!({
        "type": atype,
    })
    .as_object()
    .cloned();

    let resp = test_write_api(core, token, format!("sys/auth/{}", path).as_str(), true, auth_data).await;
    assert!(resp.is_ok());
}

pub fn get_project_binary_path() -> String {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Every `TestHttpServer::cli(...)` invocation in the suite drives
    // the server CLI, so this is hard-wired to `bvault`. We *don't*
    // honour `CARGO_BIN_NAME` here: cargo populates that env var when
    // building any `[[bin]]` target in the workspace, and with the
    // `bv-ssh-helper` bin in the same crate it has been observed
    // bleeding into the lib-test runtime — pointing this path at the
    // SSH helper, which knows nothing about the `auth`/`policy`/etc.
    // subcommands the tests exercise. Hard-coding the name keeps the
    // resolution stable across cargo + platform variations.
    let bin_name = "bvault";

    // Preferred: derive it from the running test executable, which cargo puts
    // at `<target>/<profile>/deps/<name>-<hash>` — so its grandparent is the
    // profile directory `bvault` is built into.
    //
    // `CARGO_MANIFEST_DIR` (the fallback below) stopped being sufficient in
    // Phase 4: this fixture is now used from three packages — `bastion_vault`,
    // `bv-server` and `bvault-cli` — and cargo sets that variable to the
    // manifest dir of whichever one is under test, while the target directory
    // is shared and lives at the workspace root. Deriving from `current_exe`
    // also honours `CARGO_TARGET_DIR`, which the plugin targets set.
    if let Ok(exe) = env::current_exe() {
        if let Some(profile_dir) = exe.parent().and_then(|deps| deps.parent()) {
            let candidate = profile_dir.join(bin_name);
            if candidate.exists() {
                return candidate.into_os_string().into_string().unwrap_or_default();
            }
        }
    }

    let build_profile = env::var("CARGO_PROFILE_RELEASE_DEBUG").unwrap_or("debug".into());
    let mut binary_path = PathBuf::from(manifest_dir);
    if build_profile == "release" {
        binary_path.push("target/release/");
    } else {
        binary_path.push("target/debug/");
    }
    binary_path.push(bin_name);

    binary_path.into_os_string().into_string().unwrap_or_default()
}

type BackendTestRequestHandler = dyn Fn(&mut Request) -> Result<Option<Response>, RvError> + Send + Sync;

#[derive(Default)]
pub struct NoopBackend {
    pub root: Vec<String>,
    pub login: Vec<String>,
    pub paths: RwLock<Vec<String>>,
    pub requests: RwLock<Vec<Request>>,
    pub response: Option<Response>,
    pub request_handler: Option<Arc<BackendTestRequestHandler>>,
    pub invalidations: Vec<String>,
    pub default_lease_ttl: Duration,
    pub max_lease_ttl: Duration,
    pub rollback_errs: bool,
}

impl Clone for NoopBackend {
    fn clone(&self) -> Self {
        NoopBackend {
            root: self.root.clone(),
            login: self.login.clone(),
            paths: RwLock::new(self.paths.read().unwrap().clone()),
            requests: RwLock::new(self.requests.read().unwrap().clone()),
            response: self.response.clone(),
            request_handler: self.request_handler.clone(),
            invalidations: self.invalidations.clone(),
            default_lease_ttl: self.default_lease_ttl,
            max_lease_ttl: self.max_lease_ttl,
            rollback_errs: self.rollback_errs,
        }
    }
}

#[maybe_async::maybe_async]
impl logical::Backend for NoopBackend {
    async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        if self.rollback_errs && req.operation == Operation::Rollback {
            return Err(bv_error_string!("no-op backend rollback has erred out"));
        }

        let resp = self.request_handler.as_ref().map_or(Ok(None), |handler| handler(req))?;

        let mut requests = self.requests.write()?;
        requests.push(req.clone());

        let mut path = self.paths.write()?;
        path.push(req.path.clone());

        if req.storage.is_none() {
            return Err(bv_error_string!("missing view"));
        }

        if req.path == "panic" {
            panic!("as you command");
        }

        if resp.is_some() {
            return Ok(resp);
        }

        Ok(self.response.clone())
    }

    fn cleanup(&self) -> Result<(), RvError> {
        Ok(())
    }

    fn get_ctx(&self) -> Option<Arc<crate::context::Context>> {
        None
    }

    fn get_root_paths(&self) -> Option<Arc<Vec<String>>> {
        Some(Arc::new(self.root.clone()))
    }

    fn get_unauth_paths(&self) -> Option<Arc<Vec<String>>> {
        Some(Arc::new(self.login.clone()))
    }

    fn init(&mut self) -> Result<(), RvError> {
        Ok(())
    }

    fn setup(&self, _key: &str) -> Result<(), RvError> {
        Ok(())
    }

    fn secret(&self, _key: &str) -> Option<&Arc<logical::secret::Secret>> {
        None
    }
}
