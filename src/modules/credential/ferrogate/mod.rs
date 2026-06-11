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

use arc_swap::ArcSwapOption;
use derive_more::Deref;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
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
            cmis_tls_enable: true,
            cmis_same_host: false,
            jwks_refresh_secs: default_jwks_refresh(),
            login_rate_limit_per_min: default_login_rate(),
            bootstrap_root_auto_approve: true,
            bootstrap_policies: default_bootstrap_policies(),
            require_user_token: false,
            require_machine_identity: false,
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
    /// Last JWKS fetched from CMIS (`cmis_grpc` source). Singleton per mount.
    pub jwks_cache: ArcSwapOption<CachedJwks>,
    /// Per-source-IP login counters keyed by `ip` → `(minute_window, count)`.
    pub login_attempts: dashmap::DashMap<String, (i64, u32)>,
}

#[derive(Deref)]
pub struct FerroGateBackend {
    #[deref]
    pub inner: Arc<FerroGateBackendInner>,
}

impl FerroGateBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            inner: Arc::new(FerroGateBackendInner {
                core,
                jwks_cache: ArcSwapOption::empty(),
                login_attempts: dashmap::DashMap::new(),
            }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let mut backend = new_logical_backend!({
            unauth_paths: ["login", "status", "requirement"],
            root_paths: ["config", "register", "machines", "machines/*"],
            help: FERROGATE_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.config_path()));
        backend.paths.push(Arc::new(self.requirement_path()));
        backend.paths.push(Arc::new(self.register_path()));
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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use ferro_child_verify::{jwk_thumbprint_ed25519, CHILD_ALG, CHILD_SIGNING_CONTEXT, CHILD_TYP};
    use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey};
    use serde_json::json;

    use crate::{
        core::Core,
        logical::{Operation, Request, Response},
        modules::credential::ferrogate::{machine_id, status},
        test_utils::{new_unseal_test_bastion_vault, test_mount_auth_api, test_read_api, test_write_api},
    };

    const SPIFFE: &str = "spiffe://ferrogate.test/host/11111111-1111-1111-1111-111111111111";

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Mint a composite-signed child token, replicating the MIA wire format.
    fn mint_child(
        sk: &CompositeSecretKey,
        kid: &str,
        iss: &str,
        aud: &str,
        jkt: &str,
        iat: i64,
        exp: i64,
    ) -> String {
        let header = json!({ "alg": CHILD_ALG, "typ": CHILD_TYP, "kid": kid });
        let claims = json!({
            "iss": iss,
            "sub": format!("{iss}#app:abababababababab"),
            "aud": aud,
            "exp": exp,
            "iat": iat,
            "jti": "0123456789abcdef0123456789abcdef",
            "cnf": { "jkt": jkt },
            "ferrogate": {
                "parent_svid": "33".repeat(48),
                "actor_pid": 1234u32,
                "actor_uid": 1001u32,
                "actor_bin": "ab".repeat(48),
            },
        });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = sk.sign(CHILD_SIGNING_CONTEXT, signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", b64(&sig.to_concat_bytes()))
    }

    /// Build a DPoP proof for `(htm, htu, iat)`; return `(proof_jws, jkt)`.
    fn mint_dpop(ed_sk: &SigningKey, htm: &str, htu: &str, iat: i64) -> (String, String) {
        let x = b64(ed_sk.verifying_key().as_bytes());
        let jkt = jwk_thumbprint_ed25519(&x);
        let header = json!({ "typ": "dpop+jwt", "alg": "EdDSA", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x } });
        let claims = json!({ "jti": "dpop-jti-0001", "htm": htm, "htu": htu, "iat": iat });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = ed_sk.sign(signing_input.as_bytes());
        (format!("{signing_input}.{}", b64(&sig.to_bytes())), jkt)
    }

    fn jwks_json(kid: &str, pk: &CompositePublicKey) -> String {
        json!({ "keys": [ { "kty": "FERROGATE-COMPOSITE", "kid": kid, "pub": b64(&pk.to_concat_bytes()) } ] })
            .to_string()
    }

    #[maybe_async::maybe_async]
    async fn do_login(core: &Core, token: &str, dpop: Option<&str>) -> Option<Response> {
        do_request(core, "auth/ferrogate/login", token, dpop, "").await
    }

    #[maybe_async::maybe_async]
    async fn do_request(core: &Core, path: &str, token: &str, dpop: Option<&str>, client_token: &str) -> Option<Response> {
        let mut req = Request::new(path);
        req.operation = Operation::Write;
        if !client_token.is_empty() {
            req.client_token = client_token.to_string();
        }
        let mut body = serde_json::Map::new();
        body.insert("token".to_string(), json!(token));
        if let Some(d) = dpop {
            body.insert("dpop".to_string(), json!(d));
        }
        req.body = Some(body);
        core.handle_request(&mut req).await.unwrap()
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ferrogate_login_child_token() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_ferrogate_login_child_token").await;
        test_mount_auth_api(&core, &root_token, "ferrogate", "ferrogate").await;

        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let kid = "host-test-1";
        let aud = "https://vault.example.com";
        let iss = "spiffe://ferrogate.test/host/abc";
        let now = now_secs();
        let ed_sk = SigningKey::from_bytes(&[7u8; 32]);
        let (proof, jkt) = mint_dpop(&ed_sk, "POST", aud, now);
        let jws = mint_child(&sk, kid, iss, aud, &jkt, now, now + 3600);

        // configure the trust anchor (static JWKS)
        let cfg = json!({
            "trust_domain": "ferrogate.test",
            "expected_audience": aud,
            "jwks_source": "static_jwks",
            "static_jwks": jwks_json(kid, &pk),
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, cfg).await.unwrap();

        // 1) unknown but attested machine → denied + recorded pending
        let r = do_login(&core, &jws, Some(&proof)).await.unwrap();
        assert!(r.auth.is_none(), "unknown machine must be denied");
        let id = machine_id(iss);
        let show = test_read_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}"), true)
            .await
            .unwrap()
            .unwrap();
        let data = show.data.unwrap();
        assert_eq!(data["status"], status::PENDING);
        assert_eq!(data["spiffe_id"], iss);
        assert_eq!(data["parent_svid"], "33".repeat(48));

        // 2) admin approves with a policy + ttl
        let appr = json!({ "policies": "default", "ttl_seconds": 600 }).as_object().cloned();
        test_write_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}/approve"), true, appr)
            .await
            .unwrap();

        // 3) login again → token minted with the approved policies
        let r = do_login(&core, &jws, Some(&proof)).await.unwrap();
        let auth = r.auth.expect("approved machine mints a token");
        // The token store prefixes display_name with the mount type ("ferrogate-").
        assert!(auth.display_name.ends_with(iss), "display_name = {}", auth.display_name);
        assert!(auth.policies.contains(&"default".to_string()));
        assert_eq!(auth.lease.ttl.as_secs(), 600);
        assert_eq!(auth.metadata.get("spiffe_id").map(String::as_str), Some(iss));

        // 4) a captured token replayed WITHOUT a DPoP proof is rejected
        let r = do_login(&core, &jws, None).await.unwrap();
        assert!(r.auth.is_none(), "bare bearer token (no DPoP) must be rejected");

        // 5) wrong audience is rejected even with a valid signature
        let (proof2, jkt2) = mint_dpop(&ed_sk, "POST", "https://evil.example.com", now);
        let jws2 = mint_child(&sk, kid, iss, "https://evil.example.com", &jkt2, now, now + 3600);
        let r = do_login(&core, &jws2, Some(&proof2)).await.unwrap();
        assert!(r.auth.is_none(), "audience mismatch must be rejected");
    }

    /// Mint a userpass user with `policies` and log in, returning its token.
    #[maybe_async::maybe_async]
    async fn make_user_token(core: &Core, root_token: &str, user: &str, policies: &str) -> String {
        let body = json!({ "password": "pw", "policies": policies }).as_object().cloned();
        test_write_api(core, root_token, &format!("auth/userpass/users/{user}"), true, body)
            .await
            .unwrap();
        let mut req = Request::new(&format!("auth/userpass/login/{user}"));
        req.operation = Operation::Write;
        req.body = Some(json!({ "password": "pw" }).as_object().cloned().unwrap());
        let resp = core.handle_request(&mut req).await.unwrap().expect("userpass login response");
        resp.auth.expect("userpass login mints a token").client_token
    }

    /// Combined machine+user auth: binding a user token intersects policies,
    /// revokes the user token, and `require_user_token` denies a bare machine
    /// login.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ferrogate_combined_user_binding() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_ferrogate_combined_user_binding").await;
        test_mount_auth_api(&core, &root_token, "ferrogate", "ferrogate").await;
        test_mount_auth_api(&core, &root_token, "userpass", "userpass").await;

        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let kid = "host-test-combined";
        let aud = "https://vault.example.com";
        let iss = "spiffe://ferrogate.test/host/combined";
        let now = now_secs();
        let ed_sk = SigningKey::from_bytes(&[9u8; 32]);
        let (proof, jkt) = mint_dpop(&ed_sk, "POST", aud, now);
        let jws = mint_child(&sk, kid, iss, aud, &jkt, now, now + 3600);

        let cfg = json!({
            "trust_domain": "ferrogate.test",
            "expected_audience": aud,
            "jwks_source": "static_jwks",
            "static_jwks": jwks_json(kid, &pk),
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, cfg).await.unwrap();

        // Record (pending) then approve the machine with two named policies.
        do_login(&core, &jws, Some(&proof)).await.unwrap();
        let id = machine_id(iss);
        let appr = json!({ "policies": "shared,machineonly", "ttl_seconds": 600 }).as_object().cloned();
        test_write_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}/approve"), true, appr)
            .await
            .unwrap();

        // A user whose policies overlap the machine's only on "shared".
        let user_token = make_user_token(&core, &root_token, "alice", "shared,useronly").await;

        // Bind: the minted token's named policies = intersection ("shared"),
        // never the machine-only or user-only ones. "default" is baseline.
        let mut req = Request::new("auth/ferrogate/login");
        req.operation = Operation::Write;
        req.body = Some(
            json!({ "token": jws, "dpop": proof, "user_token": user_token })
                .as_object()
                .cloned()
                .unwrap(),
        );
        let resp = core.handle_request(&mut req).await.unwrap().unwrap();
        let auth = resp.auth.expect("combined login mints a token");
        assert!(auth.policies.contains(&"shared".to_string()), "policies = {:?}", auth.policies);
        assert!(!auth.policies.contains(&"machineonly".to_string()), "machine-only must be dropped");
        assert!(!auth.policies.contains(&"useronly".to_string()), "user-only must be dropped");

        // The intermediate user token is revoked — a self-lookup with it fails.
        let mut lk = Request::new("auth/token/lookup-self");
        lk.operation = Operation::Read;
        lk.client_token = user_token.clone();
        assert!(
            core.handle_request(&mut lk).await.is_err()
                || core.handle_request(&mut lk).await.ok().flatten().is_none(),
            "bound user token must be revoked after binding"
        );

        // Enforce server-side: require_user_token denies a bare machine login.
        let cfg2 = json!({ "require_user_token": true }).as_object().cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, cfg2).await.unwrap();
        let r = do_login(&core, &jws, Some(&proof)).await.unwrap();
        assert!(r.auth.is_none(), "require_user_token must deny a login with no user_token");
    }

    /// Server-enforced machine identity: with `require_machine_identity` set,
    /// the unauthenticated `requirement` endpoint advertises it, a plain user
    /// token is rejected on a protected path, a root token is exempt, and a
    /// FerroGate machine-bound token is accepted.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ferrogate_require_machine_identity_enforced() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_ferrogate_require_machine_identity_enforced").await;
        test_mount_auth_api(&core, &root_token, "ferrogate", "ferrogate").await;
        test_mount_auth_api(&core, &root_token, "userpass", "userpass").await;

        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let kid = "host-test-rmi";
        let aud = "https://vault.example.com";
        let iss = "spiffe://ferrogate.test/host/rmi";
        let now = now_secs();
        let ed_sk = SigningKey::from_bytes(&[5u8; 32]);
        let (proof, jkt) = mint_dpop(&ed_sk, "POST", aud, now);
        let jws = mint_child(&sk, kid, iss, aud, &jkt, now, now + 3600);

        // Configure the trust anchor AND turn on server-enforced machine identity.
        let cfg = json!({
            "trust_domain": "ferrogate.test",
            "expected_audience": aud,
            "jwks_source": "static_jwks",
            "static_jwks": jwks_json(kid, &pk),
            "require_machine_identity": true,
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, cfg).await.unwrap();

        // The flag round-trips through read_config.
        let rc = test_read_api(&core, &root_token, "auth/ferrogate/config", true).await.unwrap().unwrap();
        assert_eq!(rc.data.unwrap()["require_machine_identity"], true);

        // The unauthenticated requirement endpoint advertises it (no token).
        let mut rq = Request::new("auth/ferrogate/requirement");
        rq.operation = Operation::Read;
        let resp = core.handle_request(&mut rq).await.unwrap().expect("requirement response");
        let data = resp.data.unwrap();
        assert_eq!(data["require_machine_identity"], true);
        assert_eq!(data["expected_audience"], aud);

        // A plain userpass token is now rejected on a protected (non-unauth,
        // non-root) path.
        let user_token = make_user_token(&core, &root_token, "bob", "default").await;
        let mut lk = Request::new("auth/token/lookup-self");
        lk.operation = Operation::Read;
        lk.client_token = user_token.clone();
        assert!(
            core.handle_request(&mut lk).await.is_err(),
            "plain user token must be denied when the server requires machine identity"
        );

        // A root token stays exempt (bootstrap / break-glass).
        let mut lkr = Request::new("auth/token/lookup-self");
        lkr.operation = Operation::Read;
        lkr.client_token = root_token.clone();
        assert!(
            core.handle_request(&mut lkr).await.is_ok(),
            "root token must remain exempt from the machine-identity gate"
        );

        // A FerroGate machine-bound token is accepted. Record (pending) → approve
        // with root → combined login mints a token carrying `spiffe_id`.
        do_login(&core, &jws, Some(&proof)).await.unwrap();
        let id = machine_id(iss);
        let appr = json!({ "policies": "default", "ttl_seconds": 600 }).as_object().cloned();
        test_write_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}/approve"), true, appr)
            .await
            .unwrap();
        let machine_token = {
            let mut req = Request::new("auth/ferrogate/login");
            req.operation = Operation::Write;
            req.body = Some(
                json!({ "token": jws, "dpop": proof, "user_token": user_token })
                    .as_object()
                    .cloned()
                    .unwrap(),
            );
            let resp = core.handle_request(&mut req).await.unwrap().unwrap();
            resp.auth.expect("combined login mints a machine-bound token").client_token
        };
        let mut lkm = Request::new("auth/token/lookup-self");
        lkm.operation = Operation::Read;
        lkm.client_token = machine_token;
        assert!(
            core.handle_request(&mut lkm).await.is_ok(),
            "a FerroGate machine-bound token must be accepted"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ferrogate_root_bootstrap() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_ferrogate_root_bootstrap").await;
        test_mount_auth_api(&core, &root_token, "ferrogate", "ferrogate").await;

        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let kid = "host-test-1";
        let aud = "https://vault.example.com";
        let now = now_secs();
        let ed_sk = SigningKey::from_bytes(&[7u8; 32]);
        let (proof, jkt) = mint_dpop(&ed_sk, "POST", aud, now);

        let cfg = json!({
            "trust_domain": "ferrogate.test",
            "expected_audience": aud,
            "jwks_source": "static_jwks",
            "static_jwks": jwks_json(kid, &pk),
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, cfg).await.unwrap();

        let iss1 = "spiffe://ferrogate.test/host/first";
        let jws1 = mint_child(&sk, kid, iss1, aud, &jkt, now, now + 3600);

        // First machine logs in WITH the root token while none are approved →
        // auto-approved and a token is minted immediately (bootstrap_policies).
        let r = do_request(&core, "auth/ferrogate/login", &jws1, Some(&proof), &root_token).await.unwrap();
        let auth = r.auth.expect("first machine is bootstrap-approved and minted");
        assert!(auth.policies.contains(&"default".to_string()));
        let id1 = machine_id(iss1);
        let show = test_read_api(&core, &root_token, &format!("auth/ferrogate/machines/{id1}"), true)
            .await
            .unwrap()
            .unwrap();
        let data = show.data.unwrap();
        assert_eq!(data["status"], status::APPROVED);
        assert_eq!(data["approver"], "bootstrap(root)");

        // Second machine, same conditions (root token presented) → NOT
        // auto-approved, because one machine is already approved. Goes pending.
        let iss2 = "spiffe://ferrogate.test/host/second";
        let jws2 = mint_child(&sk, kid, iss2, aud, &jkt, now, now + 3600);
        let r = do_request(&core, "auth/ferrogate/login", &jws2, Some(&proof), &root_token).await.unwrap();
        assert!(r.auth.is_none(), "second machine must not bootstrap");
        let id2 = machine_id(iss2);
        let show = test_read_api(&core, &root_token, &format!("auth/ferrogate/machines/{id2}"), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(show.data.unwrap()["status"], status::PENDING);

        // Self-poll status endpoint: first machine is approved, an unseen one is unknown.
        let r = do_request(&core, "auth/ferrogate/status", &jws1, Some(&proof), "").await.unwrap();
        assert_eq!(r.data.unwrap()["status"], status::APPROVED);

        let iss3 = "spiffe://ferrogate.test/host/never";
        let jws3 = mint_child(&sk, kid, iss3, aud, &jkt, now, now + 3600);
        let r = do_request(&core, "auth/ferrogate/status", &jws3, Some(&proof), "").await.unwrap();
        assert_eq!(r.data.unwrap()["status"], "unknown");
    }

    /// The verifier must consume the *real* JWKS served by the live dev CMIS
    /// (captured from `ferrogate.v1.MachineIdentity/JWKS` on segdc1vds0005,
    /// CMIS 0.13.1). Proves BastionVault's vendored `ferro-child-verify` parses
    /// production CMIS output — including the `x-ferrogate-crl` extension it
    /// ignores — and that the composite public key decodes.
    #[test]
    fn test_real_cmis_jwks_parses() {
        use ferro_child_verify::JwkSet;
        use ferro_crypto::composite::CompositePublicKey;

        let raw = include_str!("testdata/cmis_dev_jwks.json");
        let jwks = JwkSet::from_json(raw).expect("real CMIS JWKS parses");
        assert_eq!(jwks.keys.len(), 1);
        let k = &jwks.keys[0];
        assert_eq!(k.kty, "FERROGATE-COMPOSITE");
        assert_eq!(k.kid, "cmis-dev-1");
        let pk_bytes = URL_SAFE_NO_PAD.decode(k.public.as_bytes()).expect("pub is base64url");
        CompositePublicKey::from_concat_bytes(&pk_bytes).expect("composite public key decodes");
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_ferrogate_login_svid_accept() {
        use ferro_svid_verify::{CRL_SIGNING_CONTEXT, SVID_SIGNING_CONTEXT, SVID_TYP};

        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_ferrogate_login_svid_accept").await;
        test_mount_auth_api(&core, &root_token, "ferrogate", "ferrogate").await;

        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let kid = "cmis-dev-1";
        let now = now_secs();
        let iss = "spiffe://ferrogate.test/cmis";
        let sub = "spiffe://ferrogate.test/host/svidhost";

        // Mint a host SVID (typ ferrogate-svid+jwt) signed by the composite key.
        let header = json!({ "alg": CHILD_ALG, "typ": SVID_TYP, "kid": kid });
        let claims = json!({
            "iss": iss, "sub": sub, "iat": now, "nbf": now - 60, "exp": now + 3600,
            "cnf": { "jkt": "x" },
            "attest": { "ek_cert_sha384": "ab".repeat(48), "pcr_digest_sha384": "cd".repeat(48), "policy_id": "1" },
        });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let si = format!("{h}.{p}");
        let svid_sig = sk.sign(SVID_SIGNING_CONTEXT, si.as_bytes()).unwrap();
        let svid = format!("{si}.{}", b64(&svid_sig.to_concat_bytes()));

        // Mint a fresh, signed, empty CRL. The signed payload is the struct-
        // ordered compact JSON of CrlBody (issued_at, number, entries).
        let crl_body = format!("{{\"issued_at\":{now},\"number\":1,\"entries\":[]}}");
        let crl_sig = sk.sign(CRL_SIGNING_CONTEXT, crl_body.as_bytes()).unwrap();
        let jwks = format!(
            "{{\"keys\":[{{\"kty\":\"FERROGATE-COMPOSITE\",\"kid\":\"{kid}\",\"pub\":\"{}\"}}],\
             \"x-ferrogate-crl\":{{\"body\":{crl_body},\"signer_kid\":\"{kid}\",\"signature_b64\":\"{}\"}}}}",
            b64(&pk.to_concat_bytes()),
            b64(&crl_sig.to_concat_bytes()),
        );

        // Configure with accept_svid OFF first.
        let cfg = json!({
            "trust_domain": "ferrogate.test",
            "expected_audience": "https://vault.example.com",
            "jwks_source": "static_jwks",
            "static_jwks": jwks,
            "accept_svid": false,
        })
        .as_object()
        .cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, cfg).await.unwrap();

        // 1) SVID presented while accept_svid is off → denied.
        let r = do_login(&core, &svid, None).await.unwrap();
        assert!(r.auth.is_none(), "direct SVID must be denied when accept_svid is off");

        // 2) Enable accept_svid → unknown SVID host recorded pending.
        let on = json!({ "accept_svid": true }).as_object().cloned();
        test_write_api(&core, &root_token, "auth/ferrogate/config", true, on).await.unwrap();
        let r = do_login(&core, &svid, None).await.unwrap();
        assert!(r.auth.is_none(), "unknown SVID host must be pending");

        // 3) Approve, then the SVID login mints a token (CRL checked, host not revoked).
        let id = machine_id(sub);
        let appr = json!({ "policies": "default", "ttl_seconds": 600 }).as_object().cloned();
        test_write_api(&core, &root_token, &format!("auth/ferrogate/machines/{id}/approve"), true, appr)
            .await
            .unwrap();
        let r = do_login(&core, &svid, None).await.unwrap();
        let auth = r.auth.expect("approved SVID host mints a token");
        assert!(auth.policies.contains(&"default".to_string()));
    }

    /// Live end-to-end fetch of the JWKS from a real CMIS over the `cmis_grpc`
    /// source (plaintext — the dev CMIS speaks cleartext gRPC). Ignored by
    /// default; run against the dev CMIS with an SSH tunnel:
    ///
    /// ```text
    /// ssh -f -N -L 18443:127.0.0.1:8443 felipe@segdc1vds0005.fgv.br
    /// FERROGATE_CMIS_ENDPOINT=127.0.0.1:18443 \
    ///   cargo test --lib ferrogate::test::test_cmis_grpc_live_fetch -- --ignored --nocapture
    /// ```
    #[cfg(not(feature = "sync_handler"))]
    #[tokio::test]
    #[ignore = "requires a live CMIS at $FERROGATE_CMIS_ENDPOINT (e.g. an SSH tunnel to segdc1vds0005:8443)"]
    async fn test_cmis_grpc_live_fetch() {
        use ferro_child_verify::JwkSet;

        let endpoint = std::env::var("FERROGATE_CMIS_ENDPOINT").expect("set FERROGATE_CMIS_ENDPOINT");
        // If FERROGATE_CMIS_SPKI_PIN (hex SHA-384) is set, exercise the hybrid
        // PQ-TLS path; otherwise plaintext. CMIS >= 0.15.0 is TLS-only.
        let pin = std::env::var("FERROGATE_CMIS_SPKI_PIN").ok();
        let cfg = super::FerroGateConfig {
            jwks_source: super::jwks_source::CMIS_GRPC.to_string(),
            cmis_endpoint: endpoint,
            cmis_tls_enable: pin.is_some(),
            cmis_spki_pins: pin.into_iter().collect(),
            // With FERROGATE_CMIS_SAME_HOST set, exercises the host-local
            // candidate fallback (host.containers.internal → loopback →
            // configured) — from a dev laptop the first two fail and the
            // configured endpoint must still win.
            cmis_same_host: std::env::var("FERROGATE_CMIS_SAME_HOST").is_ok(),
            ..Default::default()
        };

        let json = super::cmis::fetch_jwks_json(&cfg).await.expect("fetch JWKS from live CMIS");
        let jwks = JwkSet::from_json(&json).expect("live JWKS parses");
        assert!(jwks.keys.iter().any(|k| k.kty == "FERROGATE-COMPOSITE"), "expected a composite key");
        eprintln!(
            "live CMIS JWKS: {} key(s), kids={:?}",
            jwks.keys.len(),
            jwks.keys.iter().map(|k| k.kid.clone()).collect::<Vec<_>>()
        );
    }

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
