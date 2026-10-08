//! Live HTTP probe + background pinger for the Rustion target registry.
//!
//! Each tick walks every **enabled** target, sends `GET /v1/health`
//! against its control-plane endpoint, feeds the outcome through the
//! state machine in `health.rs`, and persists the new health record.
//! Status transitions (`up` → `down` and back, etc.) emit
//! `rustion.target.health.changed` log events; stable verdicts only
//! refresh the timestamp / latency.
//!
//! Probe authentication: `GET /v1/health` accepts a **lightweight
//! master-signed nonce**, not a full BVRG-v1 envelope. A probe is
//! exactly one of two shapes, never anything in between:
//!
//! - **Signed** — `X-Rustion-Authority`, `X-Rustion-Nonce` and
//!   `X-Rustion-Sig`. The nonce is 16 fresh bytes from the OS CSPRNG;
//!   the signature is the framed hybrid Ed25519 + ML-DSA-65 signature
//!   (`bvrg::sign_detached_hybrid`, 3377 bytes) over the raw bytes
//!   `nonce || authority_name`, with no pre-hash. Both headers are
//!   RFC 4648 standard base64 with padding. Rustion answers with real
//!   `uptime_secs` and this authority's `active_sessions`.
//! - **Anonymous** — `X-Rustion-Authority` only, sent while this
//!   deployment has no master keypair (or it cannot be loaded).
//!   Rustion answers with its public shape (`uptime_secs` and
//!   `active_sessions` are `0`).
//!
//! Rustion ≥ 0.16 refuses any probe carrying either nonce or signature
//! that does not authenticate, and never falls back to the anonymous
//! answer — so a nonce without a signature, or an empty or placeholder
//! signature, takes every target out of `up`. `ProbeAuth` makes those
//! shapes unrepresentable. The signing key is read without being
//! created: a health tick never mints a master keypair.
//!
//! Lifecycle: a single tokio task is spawned at unseal time. It
//! self-skips while the barrier is sealed and detaches naturally on
//! process shutdown. Same shape as `pki::scheduler::start_pki_tidy_scheduler`.

use std::{
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bv_crypto::{bvrg, BvrgMasterSigningKey};
use chrono::Utc;
use rand::TryRng;
use serde::Deserialize;

use crate::kernel_api::VaultCtx;
use crate::errors::RvError;

use super::{
    audit, apply_probe,
    config::RustionTarget,
    health::ProbeOutcome,
    master::MasterStore,
    RustionStore,
};

/// Default tick. Surfaced as a constant so a test can drive the
/// state machine without waiting 30s for real wallclock progress.
pub const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Per-probe HTTP timeout. A bastion that takes more than 5 seconds
/// to answer a health probe is effectively `Down` for any operator
/// trying to open a session against it.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Length of the raw probe nonce, before base64. Fixed by Rustion's
/// wire contract.
pub const PROBE_NONCE_LEN: usize = 16;

const HEADER_AUTHORITY: &str = "X-Rustion-Authority";
const HEADER_NONCE: &str = "X-Rustion-Nonce";
const HEADER_SIG: &str = "X-Rustion-Sig";

/// Cap on how much of a refusal body is read to find its `error`
/// code. A bastion's error JSON is a few dozen bytes; a hostile or
/// broken one must not make a probe buffer an unbounded body.
const MAX_ERROR_BODY_BYTES: usize = 4096;

/// Authority name the pinger announces itself as. Rustion's authority
/// store maps this name to the master pubkey BastionVault enrolled.
/// Now operator-settable per deployment via `authority_name` on
/// `rustion/master/config`; this constant is only the fallback for the
/// paths that have no master store to read (see `probe_target_now`).
pub const PROBE_AUTHORITY: &str = crate::master::DEFAULT_AUTHORITY_NAME;

/// Spawn the background pinger. Returns the JoinHandle so the caller
/// can hold it; dropping the handle does not stop the task (tokio
/// detaches when the parent crate-level futures terminate). Mirrors
/// `pki::scheduler::start_pki_tidy_scheduler`.
pub fn start_pinger(
    core: Arc<dyn VaultCtx>,
    stores: Arc<super::RustionStores>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        log::info!(
            "rustion/pinger: started (tick every {}s, probe timeout {}s)",
            TICK_INTERVAL.as_secs(),
            PROBE_TIMEOUT.as_secs()
        );
        let mut interval = tokio::time::interval(TICK_INTERVAL);
        // Skip the first immediate tick to avoid hammering Rustion
        // before the operator has had a chance to enrol any targets.
        interval.tick().await;
        loop {
            interval.tick().await;
            if core.sealed() {
                continue;
            }
            if let Err(e) = tick(&stores).await {
                log::warn!("rustion/pinger: tick failed: {e}");
            }
        }
    })
}

/// Run a single probe round. Exposed so an integration test (or a
/// future admin endpoint) can force a sweep without waiting for the
/// background interval.
pub async fn run_probe_pass(stores: &super::RustionStores) -> Result<(), RvError> {
    tick(stores).await
}

/// Probe one specific target and persist the fresh health record.
/// Used by the synchronous "test connection" admin endpoint so the
/// GUI / CLI can surface a verdict without waiting for the next tick.
///
/// `signer` is the current master signing key from `load_probe_signer`;
/// `None` sends the anonymous probe.
pub async fn probe_target_now(
    store: &Arc<RustionStore>,
    authority: &str,
    signer: Option<&BvrgMasterSigningKey>,
    target: &RustionTarget,
) {
    let client = match build_client_for(target) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("rustion/pinger: build http client: {e}");
            return;
        }
    };
    probe_one(&client, store, authority, signer, target).await;
}

/// How the last probe round authenticated, so the signed/anonymous
/// switch is logged once when it changes instead of on every tick.
static LAST_PROBE_AUTH_MODE: AtomicU8 = AtomicU8::new(AUTH_MODE_UNSET);
const AUTH_MODE_UNSET: u8 = 0;
const AUTH_MODE_SIGNED: u8 = 1;
const AUTH_MODE_NO_KEY: u8 = 2;
const AUTH_MODE_LOAD_FAILED: u8 = 3;

/// Record the auth mode; `true` when it differs from the previous one.
fn auth_mode_changed(mode: u8) -> bool {
    LAST_PROBE_AUTH_MODE.swap(mode, Ordering::Relaxed) != mode
}

/// Load the current master signing key for health probes, read-only.
///
/// Returns `None` — and the probes go out anonymous — when there is no
/// master store yet, no keypair has been initialised, or the record
/// cannot be loaded. Never creates a keypair: that is
/// `rustion/master/issue`'s job, not a background tick's.
pub async fn load_probe_signer(master: Option<&MasterStore>) -> Option<BvrgMasterSigningKey> {
    let loaded = match master {
        Some(m) => m.read_current_signing_key().await,
        None => Ok(None),
    };
    match loaded {
        Ok(Some(key)) => {
            if auth_mode_changed(AUTH_MODE_SIGNED) {
                log::info!("rustion/pinger: health probes are signed with the current master key");
            }
            Some(key)
        }
        Ok(None) => {
            if auth_mode_changed(AUTH_MODE_NO_KEY) {
                log::info!(
                    "rustion/pinger: no master keypair is initialised; health probes are sent \
                     anonymous (no X-Rustion-Nonce / X-Rustion-Sig) until `rustion/master/issue` runs"
                );
            }
            None
        }
        Err(e) => {
            if auth_mode_changed(AUTH_MODE_LOAD_FAILED) {
                log::warn!(
                    "rustion/pinger: the master signing key could not be loaded ({e}); health \
                     probes are sent anonymous until it can"
                );
            }
            None
        }
    }
}

async fn tick(stores: &super::RustionStores) -> Result<(), RvError> {
    let Some(store) = stores.store() else {
        return Ok(());
    };
    // Deployment-global, so resolved once per pass. A missing master
    // store means the engine is still initialising; the default keeps
    // the pinger running rather than blanking every health record.
    let authority = match stores.master() {
        Some(m) => m.authority_name().await?,
        None => PROBE_AUTHORITY.to_string(),
    };

    let ids = store.list_target_ids().await?;
    if ids.is_empty() {
        return Ok(());
    }
    // Loaded once per pass and shared by every target's probe.
    let master = stores.master();
    let signer = load_probe_signer(master.as_deref()).await;

    // Per-target client: each target may carry its own pinned TLS
    // leaf cert, so we can't share a single client across the fleet
    // without losing the pin scope. Connection reuse is per-host
    // anyway (each target is a distinct endpoint) so the only thing
    // sacrificed is the cost of constructing the client struct —
    // negligible against a 30s probe cadence.
    for id in ids {
        let Some(target) = store.get_target(&id).await? else {
            continue;
        };
        if !target.enabled {
            // Disabled targets aren't probed — their last cached
            // verdict stands. Operators staging a drain rely on this
            // so flipping `enabled=false` doesn't churn audit events.
            continue;
        }
        let client = match build_client_for(&target) {
            Ok(c) => c,
            Err(e) => {
                log::warn!(
                    "rustion/pinger: build http client for {} ({}): {e}",
                    target.id,
                    target.name
                );
                continue;
            }
        };
        probe_one(&client, &store, &authority, signer.as_ref(), &target).await;
    }
    Ok(())
}

async fn probe_one(
    client: &reqwest::Client,
    store: &Arc<RustionStore>,
    authority: &str,
    signer: Option<&BvrgMasterSigningKey>,
    target: &RustionTarget,
) {
    let prev = store
        .get_health(&target.id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let outcome = run_single_probe(client, authority, signer, target).await;
    let now = Utc::now();
    let (next, changed) = apply_probe(&prev, outcome, now);

    if changed {
        log::info!(
            "{}: id={} name={} status={}→{} consecutive_failures={}",
            audit::TARGET_HEALTH_CHANGED,
            target.id,
            target.name,
            prev.status.as_str(),
            next.status.as_str(),
            next.consecutive_failures
        );
    }

    if let Err(e) = store.put_health(&target.id, &next).await {
        log::warn!(
            "rustion/pinger: persist health for {} failed: {e}",
            target.id
        );
    }
}

async fn run_single_probe(
    client: &reqwest::Client,
    authority: &str,
    signer: Option<&BvrgMasterSigningKey>,
    target: &RustionTarget,
) -> ProbeOutcome {
    let request = match build_probe_request(client, target, authority, signer) {
        Ok(r) => r,
        Err(error) => return ProbeOutcome::Failure { error },
    };

    let start = std::time::Instant::now();
    let resp = client.execute(request).await;
    let elapsed = start.elapsed();
    let latency_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            // Walk the `source()` chain so the operator sees the real
            // cause (TLS handshake, DNS, connect refused, …) instead
            // of the generic reqwest top-level "error sending request".
            let mut detail = format!("{e}");
            let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
            while let Some(s) = src {
                detail.push_str(" -> ");
                detail.push_str(&format!("{s}"));
                src = std::error::Error::source(s);
            }
            return ProbeOutcome::Failure {
                error: format!("transport: {detail}"),
            };
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let code = read_error_code(resp).await;
        if let Some(c @ ("nonce_replay" | "health_auth_malformed" | "missing_authority_header")) =
            code.as_deref()
        {
            // Every probe carries a fresh nonce and a well-formed header
            // set, so these refusals mean BastionVault built a bad probe.
            log::warn!(
                "rustion/pinger: target {} ({}) refused the health probe with `{c}` — this is a \
                 BastionVault bug, not a bastion misconfiguration",
                target.id,
                target.name
            );
        }
        return ProbeOutcome::Failure {
            error: describe_refusal(status, code.as_deref(), authority),
        };
    }

    let body: HealthBody = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            return ProbeOutcome::Failure {
                error: format!("decode body: {e}"),
            };
        }
    };

    ProbeOutcome::Success {
        latency_ms,
        version: body.version.unwrap_or_default(),
        active_sessions: body.active_sessions.unwrap_or(0),
    }
}

/// Shape of the JSON Rustion's `GET /v1/health` returns. Fields are
/// all optional so a Rustion that ships a slimmer payload (e.g. an
/// air-gapped build) still resolves to a Success outcome.
#[derive(Debug, Deserialize)]
struct HealthBody {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    active_sessions: Option<u64>,
    #[allow(dead_code)]
    #[serde(default)]
    build_sha: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    uptime_secs: Option<u64>,
    #[allow(dead_code)]
    #[serde(default)]
    now: Option<String>,
}

fn build_client_for(target: &RustionTarget) -> Result<reqwest::Client, RvError> {
    super::http::build_client_for(target, PROBE_TIMEOUT)
}

/// The authentication a probe carries. Exactly two shapes: a real
/// signature with its nonce, or neither header. A nonce without a
/// signature, or an empty or placeholder signature, has no variant.
#[derive(Debug)]
enum ProbeAuth {
    Signed { nonce_b64: String, sig_b64: String },
    Anonymous,
}

fn probe_auth(authority: &str, signer: Option<&BvrgMasterSigningKey>) -> Result<ProbeAuth, String> {
    let Some(master) = signer else {
        return Ok(ProbeAuth::Anonymous);
    };
    let nonce = mint_nonce()?;
    let sig = bvrg::sign_detached_hybrid(master, &probe_signed_message(&nonce, authority))
        .map_err(|e| format!("sign health probe: {e}"))?;
    Ok(ProbeAuth::Signed {
        nonce_b64: STANDARD.encode(nonce),
        sig_b64: STANDARD.encode(sig),
    })
}

/// The bytes a signed probe signs: the raw nonce followed by the
/// authority name exactly as sent in `X-Rustion-Authority`.
fn probe_signed_message(nonce: &[u8; PROBE_NONCE_LEN], authority: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(PROBE_NONCE_LEN + authority.len());
    message.extend_from_slice(nonce);
    message.extend_from_slice(authority.as_bytes());
    message
}

/// Build the `GET /v1/health` request for one target. A signing
/// failure is returned as an error, never downgraded to an anonymous
/// probe: the anonymous shape is reserved for "no key", not "key that
/// did not work".
fn build_probe_request(
    client: &reqwest::Client,
    target: &RustionTarget,
    authority: &str,
    signer: Option<&BvrgMasterSigningKey>,
) -> Result<reqwest::Request, String> {
    let url = format!("https://{}/v1/health", target.endpoint.trim_end_matches('/'));
    let mut builder = client
        .get(&url)
        .header(HEADER_AUTHORITY, authority)
        .timeout(PROBE_TIMEOUT);
    match probe_auth(authority, signer)? {
        ProbeAuth::Signed { nonce_b64, sig_b64 } => {
            builder = builder.header(HEADER_NONCE, nonce_b64).header(HEADER_SIG, sig_b64);
        }
        ProbeAuth::Anonymous => {}
    }
    builder.build().map_err(|e| format!("build health probe request: {e}"))
}

/// 16 fresh bytes straight from the OS CSPRNG. A fresh nonce per
/// probe — retries included — because Rustion's nonce cache refuses a
/// repeat with `409 nonce_replay`.
fn mint_nonce() -> Result<[u8; PROBE_NONCE_LEN], String> {
    let mut nonce = [0u8; PROBE_NONCE_LEN];
    rand::rngs::SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| format!("health probe nonce: OS random source failed: {e}"))?;
    Ok(nonce)
}

/// Read at most `MAX_ERROR_BODY_BYTES` of a refusal and pull out its
/// `error` code.
async fn read_error_code(mut resp: reqwest::Response) -> Option<String> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        let room = MAX_ERROR_BODY_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if body.len() >= MAX_ERROR_BODY_BYTES {
            break;
        }
    }
    parse_error_code(&body)
}

/// The `error` field of a Rustion refusal body. Only a plain
/// identifier is accepted: the code ends up in the health record, the
/// GUI and the logs, and comes from a remote peer.
fn parse_error_code(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    let code = serde_json::from_slice::<ErrorBody>(body).ok()?.error;
    let plain = !code.is_empty()
        && code.len() <= 64
        && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    plain.then_some(code)
}

/// The `ProbeOutcome::Failure` message for a non-2xx answer:
/// `http <status> <code>` plus an operator hint where the code has one,
/// or `http <status>: <reason>` when the bastion sent no usable code.
fn describe_refusal(status: reqwest::StatusCode, code: Option<&str>, authority: &str) -> String {
    let Some(code) = code else {
        return format!("http {}: {}", status.as_u16(), status.canonical_reason().unwrap_or(""));
    };
    let mut message = format!("http {} {code}", status.as_u16());
    let hint = match code {
        "signature_invalid" => Some(format!(
            "the probe is correctly signed, but the bastion has a different master pubkey pinned \
             for authority `{authority}` than this deployment's current master key — a master-key \
             identity mismatch, not a permission or namespace problem. Compare the bastion's \
             `GET /v1/authorities/self` with `GET rustion/master/pubkey`; if they differ, \
             re-approve the current pubkey on that bastion (or re-run attestation)"
        )),
        "unknown_authority" => Some(format!(
            "the bastion holds no authority record named `{authority}`; this deployment was never \
             enrolled on it under that name. `GET rustion/master/pubkey` shows the name and key \
             to approve there"
        )),
        _ => None,
    };
    if let Some(hint) = hint {
        message.push_str(": ");
        message.push_str(&hint);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HealthStatus,
        storage::{barrier::SecurityBarrier, barrier_aes_gcm, barrier_view::BarrierView},
        RustionStores,
    };
    use bv_crypto::bvrg::{verify_detached_hybrid, HYBRID_SIG_LEN};
    use bv_storage::test_support::new_test_backend;
    use rand::Rng;
    use sha2::{Digest, Sha256};

    const AUTHORITY: &str = "bastion-vault";

    fn target(endpoint: &str) -> RustionTarget {
        RustionTarget {
            id: "probe-test".into(),
            name: "probe-test".into(),
            endpoint: endpoint.into(),
            enabled: true,
            ..Default::default()
        }
    }

    /// The request the pinger would put on the wire, captured before it
    /// is sent: built by the same `build_probe_request` the tick uses,
    /// on the same per-target client.
    fn probe_request(authority: &str, signer: Option<&BvrgMasterSigningKey>) -> reqwest::Request {
        let target = target("bastion.example:9443");
        let client = build_client_for(&target).expect("client");
        build_probe_request(&client, &target, authority, signer).expect("probe request")
    }

    /// The single value of `name`, refusing a repeated header.
    fn header(req: &reqwest::Request, name: &str) -> Option<String> {
        let values: Vec<_> = req.headers().get_all(name).iter().collect();
        assert!(values.len() <= 1, "{name} sent {} times", values.len());
        values
            .first()
            .map(|v| v.to_str().expect("header is visible ASCII").to_string())
    }

    /// `(nonce, sig_blob)` decoded from a signed request.
    fn signed_parts(req: &reqwest::Request) -> ([u8; PROBE_NONCE_LEN], Vec<u8>) {
        let nonce = STANDARD
            .decode(header(req, HEADER_NONCE).expect("nonce header"))
            .expect("nonce is standard base64");
        let sig = STANDARD
            .decode(header(req, HEADER_SIG).expect("sig header"))
            .expect("sig is standard base64");
        (nonce.try_into().expect("nonce is 16 bytes"), sig)
    }

    async fn unsealed_system_view(test_name: &str) -> BarrierView {
        let backend = new_test_backend(&format!("test_rustion_probe_{test_name}"));
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(key.as_mut_slice());
        let barrier = barrier_aes_gcm::AESGCMBarrier::new(backend);
        barrier.init(key.as_slice()).await.expect("barrier init");
        barrier.unseal(key.as_slice()).await.expect("barrier unseal");
        BarrierView::new(Arc::new(barrier), "sys/")
    }

    fn master_store(system_view: &BarrierView) -> Arc<MasterStore> {
        MasterStore::from_view(Arc::new(system_view.new_sub_view("rustion/master/")))
    }

    #[test]
    fn signed_probe_headers_match_the_wire_contract() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let req = probe_request(AUTHORITY, Some(&master));

        assert_eq!(req.method(), reqwest::Method::GET);
        assert_eq!(req.url().as_str(), "https://bastion.example:9443/v1/health");
        assert_eq!(header(&req, HEADER_AUTHORITY).as_deref(), Some(AUTHORITY));

        let nonce_b64 = header(&req, HEADER_NONCE).unwrap();
        let sig_b64 = header(&req, HEADER_SIG).unwrap();
        assert_eq!(nonce_b64.len(), 24, "16 bytes, padded standard base64");
        assert_eq!(sig_b64.len(), 4504, "3377 bytes, padded standard base64");

        let (nonce, sig) = signed_parts(&req);
        assert_eq!(nonce.len(), 16);
        assert_eq!(sig.len(), HYBRID_SIG_LEN);
        assert_eq!(sig.len(), 3377);
        assert_eq!(&sig[0..2], &[0x00, 0x40], "ed_len = 64");
        assert_eq!(&sig[66..68], &[0x0C, 0xED], "ml_len = 3309");
    }

    #[test]
    fn signed_probe_verifies_over_nonce_then_authority_and_rejects_any_flipped_bit() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let pubkey = master.public_key();
        let req = probe_request(AUTHORITY, Some(&master));
        let (nonce, sig) = signed_parts(&req);

        let mut message = nonce.to_vec();
        message.extend_from_slice(AUTHORITY.as_bytes());
        verify_detached_hybrid(&message, &sig, &pubkey).expect("probe signature verifies");

        // One bit in the nonce, then one in the authority name.
        for flip_at in [0, PROBE_NONCE_LEN + 3] {
            let mut tampered = message.clone();
            tampered[flip_at] ^= 0x01;
            assert!(
                verify_detached_hybrid(&tampered, &sig, &pubkey).is_err(),
                "message bit flipped at {flip_at} still verified"
            );
        }

        // One bit in each of: ed_len, the Ed25519 half, ml_len, the ML-DSA-65 half.
        for flip_at in [1, 2 + 20, 2 + 64 + 1, 2 + 64 + 2 + 2000] {
            let mut tampered = sig.clone();
            tampered[flip_at] ^= 0x01;
            assert!(
                verify_detached_hybrid(&message, &tampered, &pubkey).is_err(),
                "signature bit flipped at {flip_at} still verified"
            );
        }
    }

    #[test]
    fn signed_probe_is_not_signed_over_a_hash() {
        // Guards against routing the probe through the envelope's TBS path.
        let master = BvrgMasterSigningKey::generate().unwrap();
        let req = probe_request(AUTHORITY, Some(&master));
        let (nonce, sig) = signed_parts(&req);

        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(AUTHORITY.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        assert!(verify_detached_hybrid(&digest, &sig, &master.public_key()).is_err());
    }

    #[test]
    fn signed_message_uses_the_authority_header_byte_for_byte() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let authority = "BV-Prod.eu_1";
        let req = probe_request(authority, Some(&master));
        assert_eq!(header(&req, HEADER_AUTHORITY).as_deref(), Some(authority));

        let (nonce, sig) = signed_parts(&req);
        let pubkey = master.public_key();
        verify_detached_hybrid(&probe_signed_message(&nonce, authority), &sig, &pubkey)
            .expect("signed over the exact header value");
        assert!(
            verify_detached_hybrid(&probe_signed_message(&nonce, "bv-prod.eu_1"), &sig, &pubkey)
                .is_err(),
            "authority must not be re-cased"
        );
    }

    #[test]
    fn anonymous_probe_sends_neither_nonce_nor_signature() {
        let req = probe_request(AUTHORITY, None);
        assert_eq!(header(&req, HEADER_AUTHORITY).as_deref(), Some(AUTHORITY));
        assert!(req.headers().get(HEADER_NONCE).is_none());
        assert!(req.headers().get(HEADER_SIG).is_none());
    }

    #[test]
    fn a_probe_never_carries_one_header_alone_or_an_empty_value() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        for signer in [None, Some(&master)] {
            for _ in 0..8 {
                let req = probe_request(AUTHORITY, signer);
                let nonce = header(&req, HEADER_NONCE);
                let sig = header(&req, HEADER_SIG);
                assert_eq!(nonce.is_some(), sig.is_some(), "exactly one of nonce/sig sent");
                assert_eq!(nonce.is_some(), signer.is_some());
                for value in [nonce, sig].into_iter().flatten() {
                    assert!(!value.is_empty(), "empty probe auth header");
                }
            }
        }
    }

    #[test]
    fn consecutive_probes_use_fresh_standard_alphabet_nonces() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let first = header(&probe_request(AUTHORITY, Some(&master)), HEADER_NONCE).unwrap();
        let second = header(&probe_request(AUTHORITY, Some(&master)), HEADER_NONCE).unwrap();
        assert_ne!(first, second);

        // URL-safe base64 would emit `-` / `_` for roughly half of all
        // 16-byte nonces; over 256 nonces at least one would show it.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let nonce = mint_nonce().unwrap();
            let encoded = STANDARD.encode(nonce);
            assert!(!encoded.contains(['-', '_']), "URL-safe alphabet leaked: {encoded}");
            assert!(seen.insert(nonce), "nonce repeated");
        }
    }

    #[test]
    fn refusal_codes_are_parsed_strictly() {
        assert_eq!(
            parse_error_code(br#"{"error":"signature_invalid","detail":"x"}"#).as_deref(),
            Some("signature_invalid")
        );
        assert_eq!(parse_error_code(b"<html>bad gateway</html>"), None);
        assert_eq!(parse_error_code(br#"{"error":""}"#), None);
        assert_eq!(parse_error_code(br#"{"error":"a\nforged log line"}"#), None);
        assert_eq!(parse_error_code(br#"{"detail":"no code"}"#), None);
    }

    #[test]
    fn refusal_messages_carry_the_code_and_point_at_the_pinned_key() {
        let msg = describe_refusal(
            reqwest::StatusCode::UNAUTHORIZED,
            Some("signature_invalid"),
            AUTHORITY,
        );
        assert!(msg.starts_with("http 401 signature_invalid: "), "{msg}");
        assert!(msg.contains("GET /v1/authorities/self"), "{msg}");
        assert!(msg.contains("`bastion-vault`"), "{msg}");

        let msg = describe_refusal(reqwest::StatusCode::CONFLICT, Some("nonce_replay"), AUTHORITY);
        assert_eq!(msg, "http 409 nonce_replay");

        let msg = describe_refusal(reqwest::StatusCode::UNAUTHORIZED, None, AUTHORITY);
        assert_eq!(msg, "http 401: Unauthorized");
    }

    #[tokio::test]
    async fn loading_the_probe_signer_never_creates_a_master_key() {
        let view = unsealed_system_view("signer_load").await;
        let master = master_store(&view);

        assert!(load_probe_signer(Some(&master)).await.is_none());
        assert!(load_probe_signer(None).await.is_none());
        assert!(
            master.read_signing_record().await.unwrap().is_none(),
            "loading the probe signer minted a master key"
        );

        // Once a key exists, the probe signs with it.
        master.get_or_init_signing_key().await.unwrap();
        let signer = load_probe_signer(Some(&master)).await.expect("current key");
        let (_, current_pub) = master.load_active_keys().await.unwrap().remove(0);
        let req = probe_request(AUTHORITY, Some(&signer));
        let (nonce, sig) = signed_parts(&req);
        verify_detached_hybrid(&probe_signed_message(&nonce, AUTHORITY), &sig, &current_pub)
            .expect("probe signed with the current master key");
    }

    #[tokio::test]
    async fn a_tick_without_a_master_key_probes_anonymously_and_creates_none() {
        let view = unsealed_system_view("tick_no_key").await;
        let master = master_store(&view);
        let store = RustionStore::from_system_view(&view);
        // Port 1 on loopback: refused at once, so the probe fails fast
        // at the transport and the tick still runs end to end.
        let target = target("127.0.0.1:1");
        store.put_target_for_test(&target).await.unwrap();

        let stores = RustionStores::default();
        stores.store.store(Arc::new(Some(store.clone())));
        stores.master.store(Arc::new(Some(master.clone())));

        run_probe_pass(&stores).await.expect("probe pass");

        assert!(
            master.read_signing_record().await.unwrap().is_none(),
            "a health tick minted a master key"
        );
        let health = store.get_health(&target.id).await.unwrap().expect("health persisted");
        assert_ne!(health.status, HealthStatus::Up);
        assert_eq!(health.consecutive_failures, 1);
        assert!(health.last_error.starts_with("transport: "), "{}", health.last_error);
    }
}
