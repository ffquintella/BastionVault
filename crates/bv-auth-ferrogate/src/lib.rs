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

// The eight backend-definition macros are `#[macro_export]`ed by `bv-logical`,
// which places them at *that* crate's root; the call sites import them as
// `crate::new_path` and friends. The `_internal` halves are the recursive arms
// the public macros expand into, so they must travel with them.
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
};
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};

use std::{any::Any, sync::Arc, time::SystemTime};

use arc_swap::ArcSwapOption;
use derive_more::Deref;
use serde::{Deserialize, Serialize};

use bv_kernel_api::{Module, VaultCtx};
use crate::{
    errors::RvError,
    logical::{Backend, LogicalBackend},
};

pub mod cmis;
pub mod path_config;
pub mod path_machines;
pub mod verify;

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
    /// CMIS gRPC endpoint (when `jwks_source == cmis_grpc`). A single literal
    /// `host:port`. Ignored when `cmis_srv` is set.
    #[serde(default)]
    pub cmis_endpoint: String,
    /// DNS SRV owner name advertising a CMIS HA cluster, e.g.
    /// `_ferrogate-prod._tcp.example.com`. When set, the mount resolves it at
    /// each JWKS fetch and tries every advertised node in RFC 2782 order
    /// (ascending priority, then descending weight) until one connects and
    /// verifies its SPKI pin — mirroring the MIA's own SRV failover, so a node
    /// whose cert has diverged from the cluster pin is skipped rather than
    /// failing the whole fetch. The shared SPKI pin authenticates whichever
    /// node answers. Takes precedence over `cmis_endpoint`; when set,
    /// `cmis_same_host` host-local aliasing does not apply. Empty = dial the
    /// single literal `cmis_endpoint`.
    #[serde(default)]
    pub cmis_srv: String,
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
    /// Use hybrid post-quantum TLS to reach CMIS (`cmis_grpc` source). When
    /// `false`, connect over plaintext gRPC — for a dev/loopback CMIS only.
    #[serde(default = "default_true")]
    pub cmis_tls_enable: bool,
    /// CMIS runs on the same machine as this BastionVault server. The
    /// configured `cmis_endpoint` (typically the host's public name, correct
    /// for external clients) may not be reachable from the server's own
    /// vantage point — e.g. from inside a rootless-podman container the
    /// host's own address hairpins into the container's empty namespace. When
    /// set, host-local aliases (`host.containers.internal`, loopback) are
    /// tried first, falling back to the configured endpoint. Safe because the
    /// SPKI pin authenticates the peer regardless of the name dialled.
    #[serde(default)]
    pub cmis_same_host: bool,
    /// How long (seconds) a fetched JWKS is cached before a refresh is attempted.
    #[serde(default = "default_jwks_refresh")]
    pub jwks_refresh_secs: i64,
    /// Per-source-IP `login` rate limit (attempts per minute); `0` = unlimited.
    #[serde(default = "default_login_rate")]
    pub login_rate_limit_per_min: u32,
    /// Auto-approve the first machine that logs in with a root token while no
    /// machine is yet approved (one-shot bootstrap).
    #[serde(default = "default_true")]
    pub bootstrap_root_auto_approve: bool,
    /// Policies granted to the auto-approved first machine.
    #[serde(default = "default_bootstrap_policies")]
    pub bootstrap_policies: Vec<String>,
    /// Enforce combined machine+user auth server-side: when `true`, a `login`
    /// must also carry a valid `user_token`, and the minted token's policies
    /// are the INTERSECTION of the machine's approved policies and the user
    /// token's policies (the intermediate user token is revoked). A login
    /// without a `user_token` is denied. Default `false` keeps machine-only
    /// logins working for deployments that don't require a user factor.
    #[serde(default)]
    pub require_user_token: bool,
    /// Server-enforced machine-identity requirement. When `true`, EVERY
    /// authenticated request to this server must present a FerroGate
    /// machine-bound token (or a root token); a plain user/token/approle
    /// session is rejected at the token layer. This is the server's
    /// declaration that machine identity is mandatory — clients discover it
    /// via the unauthenticated `auth/ferrogate/requirement` endpoint and can
    /// neither opt out of nor bypass it. Independent of `require_user_token`
    /// (which governs the ferrogate login itself); set both for full combined
    /// machine+user enforcement. Default `false`.
    #[serde(default)]
    pub require_machine_identity: bool,
    /// MIA environment selector this deployment belongs to (e.g. `hml`,
    /// `prod`): clients should read `mia-<env>.toml` rather than the default
    /// `mia.toml` when minting child tokens for this server. Advertised on the
    /// unauthenticated `requirement` endpoint so the connect flow dials the
    /// right local MIA without operator input. Informational for the server
    /// itself — verification is governed by the trust anchor above. Empty =
    /// the default environment (`mia.toml`).
    #[serde(default)]
    pub mia_environment: String,
    /// Enable the unauthenticated machine self-enrolment endpoint
    /// (`auth/<mount>/enroll`). When `false` (the default) the endpoint refuses
    /// every request. Self-enrolment only records a `pending` machine for an
    /// administrator to approve — it NEVER mints a token or grants access; a
    /// machine still authenticates through the attested `login` flow. Pre-
    /// approving a self-enrolled (self-asserted, therefore untrusted) SPIFFE ID
    /// grants nothing unless that machine can also attest as the same identity.
    #[serde(default)]
    pub self_enroll_enabled: bool,
    /// Allow-list gating which callers may self-enrol. Each entry is matched
    /// against BOTH the request source IP and the caller's claimed identity: an
    /// entry that parses as an IP or CIDR matches the source IP; any other entry
    /// matches the claimed `spiffe_id` (exact, or as a prefix when it ends with
    /// `*`) or the 64-hex machine id. When the list is non-empty a caller must
    /// match at least one entry; an empty list admits any caller (still subject
    /// to `self_enroll_blocklist` and the rate limit).
    #[serde(default)]
    pub self_enroll_allowlist: Vec<String>,
    /// Block-list of callers refused self-enrolment, matched exactly as
    /// `self_enroll_allowlist`. A block-list match always wins over the
    /// allow-list.
    #[serde(default)]
    pub self_enroll_blocklist: Vec<String>,
    /// Per-source-IP self-enrolment rate limit (requests per minute);
    /// `0` = unlimited. Defaults to a low value to blunt pending-queue flooding
    /// of the unauthenticated endpoint.
    #[serde(default = "default_self_enroll_rate")]
    pub self_enroll_rate_limit_per_min: u32,
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

fn default_jwks_refresh() -> i64 {
    60
}

fn default_login_rate() -> u32 {
    10
}

fn default_self_enroll_rate() -> u32 {
    5
}

impl Default for FerroGateConfig {
    fn default() -> Self {
        Self {
            trust_domain: String::new(),
            expected_audience: String::new(),
            jwks_source: jwks_source::STATIC.to_string(),
            cmis_endpoint: String::new(),
            cmis_srv: String::new(),
            cmis_spki_pins: Vec::new(),
            static_jwks: String::new(),
            accept_svid: false,
            clock_leeway_secs: default_clock_leeway(),
            default_token_ttl: 0,
            cmis_tls_enable: true,
            cmis_same_host: false,
            jwks_refresh_secs: default_jwks_refresh(),
            login_rate_limit_per_min: default_login_rate(),
            bootstrap_root_auto_approve: true,
            bootstrap_policies: default_bootstrap_policies(),
            require_user_token: false,
            require_machine_identity: false,
            mia_environment: String::new(),
            self_enroll_enabled: false,
            self_enroll_allowlist: Vec::new(),
            self_enroll_blocklist: Vec::new(),
            self_enroll_rate_limit_per_min: default_self_enroll_rate(),
        }
    }
}

/// In-memory cache of the JWKS fetched from CMIS (`cmis_grpc` source).
#[derive(Debug, Clone)]
pub struct CachedJwks {
    /// The `jwks_json` returned by the CMIS `JWKS` RPC.
    pub json: String,
    /// Unix seconds the JWKS was fetched.
    pub fetched_at: i64,
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
    /// `SHA-384(ek_cert)` hex from the verified token's attestation block, when
    /// known. Only the host SVID carries this; child-token logins leave it empty.
    #[serde(default)]
    pub ek_cert_sha384: String,
    /// RIM policy generation from the attestation block, when known (SVID only).
    #[serde(default)]
    pub policy_id: String,
    /// Hex `SHA-384` of the parent host SVID, from a child token's `ferrogate`
    /// provenance block. Recorded for audit/traceability.
    #[serde(default)]
    pub parent_svid: String,
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
    /// True when this record was created by the unauthenticated self-enrolment
    /// endpoint (a machine requesting its own registration) rather than by an
    /// administrator `register` call or an attested `login` first-sighting.
    /// Lets operators tell self-requested pending machines apart in the queue.
    #[serde(default)]
    pub self_enrolled: bool,
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
    pub core: Arc<dyn VaultCtx>,
    /// Last JWKS fetched from CMIS (`cmis_grpc` source). Singleton per mount.
    pub jwks_cache: ArcSwapOption<CachedJwks>,
    /// Per-source-IP login counters keyed by `ip` → `(minute_window, count)`.
    pub login_attempts: dashmap::DashMap<String, (i64, u32)>,
    /// Per-source-IP self-enrolment counters, kept separate from `login_attempts`
    /// so the two unauthenticated endpoints do not share a rate budget.
    pub enroll_attempts: dashmap::DashMap<String, (i64, u32)>,
}

#[derive(Deref)]
pub struct FerroGateBackend {
    #[deref]
    pub inner: Arc<FerroGateBackendInner>,
}

impl FerroGateBackend {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
        Self {
            inner: Arc::new(FerroGateBackendInner {
                core,
                jwks_cache: ArcSwapOption::empty(),
                login_attempts: dashmap::DashMap::new(),
                enroll_attempts: dashmap::DashMap::new(),
            }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let mut backend = new_logical_backend!({
            unauth_paths: ["login", "status", "requirement", "enroll"],
            root_paths: ["config", "register", "machines", "machines/*"],
            help: FERROGATE_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.requirement_path()));
        backend.paths.push(Arc::new(self.register_path()));
        backend.paths.push(Arc::new(self.enroll_path()));
        backend.paths.push(Arc::new(self.machines_list_path()));
        backend.paths.push(Arc::new(self.machine_path()));
        backend.paths.push(Arc::new(self.machine_approve_path()));
        backend.paths.push(Arc::new(self.machine_reject_path()));
        backend.paths.push(Arc::new(self.machine_revoke_path()));
        backend.paths.push(Arc::new(self.login_path()));
        backend.paths.push(Arc::new(self.status_path()));

        backend
    }
}

pub struct FerroGateModule {
    pub name: String,
    pub backend: Arc<FerroGateBackend>,
}

impl FerroGateModule {
    pub fn new(core: Arc<dyn VaultCtx>) -> Self {
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

    fn setup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let ferrogate = self.backend.clone();
        let ferrogate_backend_new_func = move |_c: Arc<dyn VaultCtx>| -> Result<Arc<dyn Backend>, RvError> {
            let mut ferrogate_backend = ferrogate.new_backend();
            ferrogate_backend.init()?;
            Ok(Arc::new(ferrogate_backend))
        };

        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.add_auth_backend("ferrogate", Arc::new(ferrogate_backend_new_func));
        }

        log::error!("get auth module failed!");
        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        if let Some(auth_mounts) = core.auth_mounts() {
            return auth_mounts.delete_auth_backend("ferrogate");
        }

        log::error!("get auth module failed!");
        Ok(())
    }
}

