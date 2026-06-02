//! FerroGate machine-authentication backend (Phase 1 — skeleton).
//!
//! Admits only machines whose hardware-attested identity has been issued by
//! [FerroGate](../../../../../FerroGate) (a TPM 2.0-attested, post-quantum SPIFFE
//! machine-identity system) **and** explicitly authorized by a BastionVault
//! administrator. FerroGate answers *"is this a real, attested machine?"*;
//! this backend answers *"is this machine allowed to use this vault?"* via an
//! admin-approval gate keyed on the machine's stable SPIFFE ID.
//!
//! See [`features/machine-authentication.md`](../../../../features/machine-authentication.md)
//! for the full design.
//!
//! ## Phase status
//!
//! - **Phase 1 (this file):** mount at `auth/ferrogate/`, trust-anchor config
//!   read/write, the machine-record storage layout, and the admin lifecycle
//!   routes (`register` / `list` / `show` / `approve` / `reject` / `revoke` /
//!   delete). `login` is deliberately stubbed to a not-implemented error until
//!   Phase 2 wires the FerroGate reference verifiers.
//! - **Phase 2+:** child-token + DPoP verification, the enrolment state machine,
//!   the root-token bootstrap, the CMIS gRPC JWKS source, the client CLI, and
//!   the admin GUI page.

use std::{any::Any, sync::Arc, time::SystemTime};

use derive_more::Deref;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
};

pub mod path_config;
pub mod path_machines;

static FERROGATE_BACKEND_HELP: &str = r#"
The "ferrogate" credential provider admits only machines whose identity has
been hardware-attested by FerroGate and explicitly authorized by an
administrator. A machine presents a FerroGate-issued, composite-signed token;
BastionVault verifies it against FerroGate's published keys and then checks
its own admin-approval gate. An unknown but attested machine is held "pending"
until an administrator approves it from the GUI or the CLI.
"#;

/// Lifecycle state of an enrolled machine.
pub mod status {
    /// Seen / pre-registered, awaiting administrator approval. No vault access.
    pub const PENDING: &str = "pending";
    /// Administrator-approved; logins mint a token bound to `policies`.
    pub const APPROVED: &str = "approved";
    /// Administrator-rejected; the enrolment is denied.
    pub const REJECTED: &str = "rejected";
    /// Previously approved, now administratively revoked.
    pub const REVOKED: &str = "revoked";
}

/// How BastionVault obtains FerroGate's composite verification keys + CRL.
pub mod jwks_source {
    /// Operator-pasted static JWK set (air-gapped / tests).
    pub const STATIC: &str = "static_jwks";
    /// Periodic SPKI-pinned fetch from the CMIS `JWKS` gRPC RPC.
    pub const CMIS_GRPC: &str = "cmis_grpc";
}

/// Trust-anchor configuration for the mount. All fields are public key material
/// or non-secret policy knobs — nothing here is a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FerroGateConfig {
    /// FerroGate trust domain, e.g. `ferrogate.prod`. Matched against the
    /// SPIFFE-ID authority of presented tokens.
    #[serde(default)]
    pub trust_domain: String,
    /// This vault's audience string, matched against a child token's `aud`.
    #[serde(default)]
    pub expected_audience: String,
    /// One of [`jwks_source`].
    #[serde(default)]
    pub jwks_source: String,
    /// CMIS gRPC endpoint (when `jwks_source == cmis_grpc`).
    #[serde(default)]
    pub cmis_endpoint: String,
    /// SHA-384 SPKI pins for the CMIS server certificate (hex), used for the
    /// hybrid-PQC TLS fetch.
    #[serde(default)]
    pub cmis_spki_pins: Vec<String>,
    /// Pinned JWK set JSON (when `jwks_source == static_jwks`).
    #[serde(default)]
    pub static_jwks: String,
    /// Accept a host SVID presented directly (no per-request DPoP). Weaker;
    /// opt-in. Default is child-token-only.
    #[serde(default)]
    pub accept_svid: bool,
    /// Clock leeway, in seconds, applied to token `nbf`/`exp` checks.
    #[serde(default = "default_clock_leeway")]
    pub clock_leeway_secs: i64,
    /// Default TTL (seconds) for minted tokens when an approval sets none.
    #[serde(default)]
    pub default_token_ttl: u64,
    /// Auto-approve the first machine that logs in with a root token while no
    /// machine is yet approved (one-shot bootstrap).
    #[serde(default = "default_true")]
    pub bootstrap_root_auto_approve: bool,
    /// Policies granted to the auto-approved first machine.
    #[serde(default = "default_bootstrap_policies")]
    pub bootstrap_policies: Vec<String>,
}

fn default_clock_leeway() -> i64 {
    60
}

fn default_true() -> bool {
    true
}

fn default_bootstrap_policies() -> Vec<String> {
    vec!["default".to_string()]
}

impl Default for FerroGateConfig {
    fn default() -> Self {
        Self {
            trust_domain: String::new(),
            expected_audience: String::new(),
            jwks_source: jwks_source::STATIC.to_string(),
            cmis_endpoint: String::new(),
            cmis_spki_pins: Vec::new(),
            static_jwks: String::new(),
            accept_svid: false,
            clock_leeway_secs: default_clock_leeway(),
            default_token_ttl: 0,
            bootstrap_root_auto_approve: true,
            bootstrap_policies: default_bootstrap_policies(),
        }
    }
}

/// A persisted machine enrolment record, keyed by [`machine_id`] of its SPIFFE ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MachineEntry {
    /// Stable SPIFFE ID, e.g. `spiffe://ferrogate.prod/host/<uuid>`.
    pub spiffe_id: String,
    /// One of [`status`].
    pub status: String,
    /// Policies attached at approval; granted to tokens this machine mints.
    #[serde(default)]
    pub policies: Vec<String>,
    /// Token TTL (seconds) granted at approval; `0` means use the config default.
    #[serde(default)]
    pub ttl_seconds: u64,
    /// `SHA-384(ek_cert)` hex from the verified token's attestation block, when known.
    #[serde(default)]
    pub ek_cert_sha384: String,
    /// RIM policy generation from the attestation block, when known.
    #[serde(default)]
    pub policy_id: String,
    /// Unix seconds the machine was first seen / registered.
    #[serde(default)]
    pub first_seen_at: i64,
    /// Unix seconds of approval, when approved.
    #[serde(default)]
    pub approved_at: i64,
    /// Display name of the approving administrator, when approved.
    #[serde(default)]
    pub approver: String,
    /// Unix seconds of last successful login.
    #[serde(default)]
    pub last_login_at: i64,
    /// Source IP of last successful login.
    #[serde(default)]
    pub last_login_ip: String,
    /// Reason recorded on rejection.
    #[serde(default)]
    pub reject_reason: String,
    /// Free-text note recorded at registration / approval.
    #[serde(default)]
    pub comment: String,
}

/// Stable, path-safe handle for a SPIFFE ID (BLAKE3 hex). Used as the storage
/// key suffix and as the `{id}` admin-route parameter, since a raw SPIFFE ID
/// contains `/` and `:` and can't be a single path segment.
#[must_use]
pub fn machine_id(spiffe_id: &str) -> String {
    blake3::hash(spiffe_id.as_bytes()).to_hex().to_string()
}

/// Current wall-clock as Unix seconds (best-effort; pre-epoch clocks yield 0).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct FerroGateBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct FerroGateBackend {
    #[deref]
    pub inner: Arc<FerroGateBackendInner>,
}

impl FerroGateBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(FerroGateBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let mut backend = new_logical_backend!({
            unauth_paths: ["login"],
            root_paths: ["config", "register", "machines", "machines/*"],
            help: FERROGATE_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.register_path()));
        backend.paths.push(Arc::new(self.machines_list_path()));
        backend.paths.push(Arc::new(self.machine_path()));
        backend.paths.push(Arc::new(self.machine_approve_path()));
        backend.paths.push(Arc::new(self.machine_reject_path()));
        backend.paths.push(Arc::new(self.machine_revoke_path()));
        backend.paths.push(Arc::new(self.login_path()));

        backend
    }
}

pub struct FerroGateModule {
    pub name: String,
    pub backend: Arc<FerroGateBackend>,
}

impl FerroGateModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self { name: "ferrogate".to_string(), backend: Arc::new(FerroGateBackend::new(core)) }
    }
}

impl Module for FerroGateModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let ferrogate = self.backend.clone();
        let ferrogate_backend_new_func = move |_c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut ferrogate_backend = ferrogate.new_backend();
            ferrogate_backend.init()?;
            Ok(Arc::new(ferrogate_backend))
        };

        if let Some(auth_module) = core.module_manager.get_module::<AuthModule>("auth") {
            return auth_module.add_auth_backend("ferrogate", Arc::new(ferrogate_backend_new_func));
        }

        log::error!("get auth module failed!");
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        if let Some(auth_module) = core.module_manager.get_module::<AuthModule>("auth") {
            return auth_module.delete_auth_backend("ferrogate");
        }

        log::error!("get auth module failed!");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{
        core::Core,
        logical::{Operation, Request, Response},
        modules::credential::ferrogate::{machine_id, status},
        test_utils::{new_unseal_test_bastion_vault, test_mount_auth_api, test_read_api, test_write_api},
    };

    const SPIFFE: &str = "spiffe://ferrogate.test/host/11111111-1111-1111-1111-111111111111";

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ferrogate_admin_lifecycle() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_ferrogate_admin_lifecycle").await;

        // mount ferrogate at auth/ferrogate
        test_mount_auth_api(&core, &root_token, "ferrogate", "ferrogate").await;

        // write + read config
        let cfg = json!({
            "trust_domain": "ferrogate.test",
            "expected_audience": "https://vault.example.com",
            "jwks_source": "static_jwks",
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &root_token, "auth/ferrogate/config", true, cfg).await;
        assert!(resp.is_ok());
        let resp = test_read_api(&core, &root_token, "auth/ferrogate/config", true).await.unwrap().unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["trust_domain"], "ferrogate.test");
        assert_eq!(data["bootstrap_root_auto_approve"], true);

        // register a machine (admin pre-registration / Phase-1 seed)
        let reg = json!({ "spiffe_id": SPIFFE }).as_object().cloned();
        let resp = test_write_api(&core, &root_token, "auth/ferrogate/register", true, reg)
            .await
            .unwrap()
            .unwrap();
        let id = resp.data.unwrap()["id"].as_str().unwrap().to_string();
        assert_eq!(id, machine_id(SPIFFE));

        // show → pending
        let resp = test_read_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}"), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["status"], status::PENDING);

        // approve with policies + ttl
        let appr = json!({ "policies": "default,reader", "ttl_seconds": 3600 }).as_object().cloned();
        let resp = test_write_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}/approve"), true, appr).await;
        assert!(resp.is_ok());
        let resp = test_read_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}"), true)
            .await
            .unwrap()
            .unwrap();
        let data = resp.data.unwrap();
        assert_eq!(data["status"], status::APPROVED);
        assert_eq!(data["ttl_seconds"], 3600);

        // revoke
        let resp =
            test_write_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}/revoke"), true, None).await;
        assert!(resp.is_ok());
        let resp = test_read_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}"), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.data.unwrap()["status"], status::REVOKED);

        // login is stubbed in Phase 1
        let mut req = Request::new("auth/ferrogate/login");
        req.operation = Operation::Write;
        req.body = json!({ "token": "x" }).as_object().cloned();
        let resp = core.handle_request(&mut req).await;
        assert!(resp.is_err() || matches!(resp, Ok(Some(Response { auth: None, .. }))));
    }
}
