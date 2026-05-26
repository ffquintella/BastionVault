//! Live HTTP probe + background pinger for the Rustion target registry.
//!
//! Each tick walks every **enabled** target, sends `GET /v1/health`
//! against its control-plane endpoint, feeds the outcome through the
//! state machine in `health.rs`, and persists the new health record.
//! Status transitions (`up` → `down` and back, etc.) emit
//! `rustion.target.health.changed` log events; stable verdicts only
//! refresh the timestamp / latency.
//!
//! Probe authentication: per the spec, `GET /v1/health` accepts a
//! **lightweight master-signed nonce** (`X-Rustion-Authority`,
//! `X-Rustion-Nonce`, `X-Rustion-Sig`) — not a full BVRG-v1 envelope.
//! Until the master signing keypair is wired through Phase 2's
//! envelope crate, this module is signature-aware-but-tolerant: the
//! nonce header is always sent (so an authority record can be matched
//! on the Rustion side), and the `X-Rustion-Sig` header is sent as an
//! empty string. The signature header is upgraded to a real
//! hybrid sign once Phase 2 lands.
//!
//! Lifecycle: a single tokio task is spawned at unseal time. It
//! self-skips while the barrier is sealed and detaches naturally on
//! process shutdown. Same shape as `pki::scheduler::start_pki_tidy_scheduler`.

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::Rng;
use serde::Deserialize;

use crate::{core::Core, errors::RvError};

use super::{
    audit, apply_probe,
    config::RustionTarget,
    health::ProbeOutcome,
    RustionModule, RustionStore,
};

/// Default tick. Surfaced as a constant so a test can drive the
/// state machine without waiting 30s for real wallclock progress.
pub const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Per-probe HTTP timeout. A bastion that takes more than 5 seconds
/// to answer a health probe is effectively `Down` for any operator
/// trying to open a session against it.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Authority name the pinger announces itself as. Rustion's authority
/// store maps this name to the master pubkey BastionVault enrolled.
/// Phase 2+ will let operators override this per-deployment; today
/// the value is a fixed default that matches the spec.
pub const PROBE_AUTHORITY: &str = "bastion-vault";

/// Spawn the background pinger. Returns the JoinHandle so the caller
/// can hold it; dropping the handle does not stop the task (tokio
/// detaches when the parent crate-level futures terminate). Mirrors
/// `pki::scheduler::start_pki_tidy_scheduler`.
pub fn start_pinger(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
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
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core).await {
                log::warn!("rustion/pinger: tick failed: {e}");
            }
        }
    })
}

/// Run a single probe round. Exposed so an integration test (or a
/// future admin endpoint) can force a sweep without waiting for the
/// background interval.
pub async fn run_probe_pass(core: &Arc<Core>) -> Result<(), RvError> {
    tick(core).await
}

/// Probe one specific target and persist the fresh health record.
/// Used by the synchronous "test connection" admin endpoint so the
/// GUI / CLI can surface a verdict without waiting for the next tick.
pub async fn probe_target_now(store: &Arc<RustionStore>, target: &RustionTarget) {
    let client = match build_client_for(target) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("rustion/pinger: build http client: {e}");
            return;
        }
    };
    probe_one(&client, store, target).await;
}

async fn tick(core: &Arc<Core>) -> Result<(), RvError> {
    let Some(module) = core
        .module_manager
        .get_module::<RustionModule>("rustion")
    else {
        return Ok(());
    };
    let Some(store) = module.store() else {
        return Ok(());
    };

    let ids = store.list_target_ids().await?;
    if ids.is_empty() {
        return Ok(());
    }

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
        probe_one(&client, &store, &target).await;
    }
    Ok(())
}

async fn probe_one(client: &reqwest::Client, store: &Arc<RustionStore>, target: &RustionTarget) {
    let prev = store
        .get_health(&target.id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let outcome = run_single_probe(client, target).await;
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

async fn run_single_probe(client: &reqwest::Client, target: &RustionTarget) -> ProbeOutcome {
    let url = format!("https://{}/v1/health", target.endpoint.trim_end_matches('/'));
    let nonce_b64 = mint_nonce();

    let start = std::time::Instant::now();
    let resp = client
        .get(&url)
        .header("X-Rustion-Authority", PROBE_AUTHORITY)
        .header("X-Rustion-Nonce", &nonce_b64)
        // Signature header reserved for Phase 2's hybrid signer.
        // Sending it empty makes the header presence stable for
        // Rustion-side parsers; signatures land alongside the master
        // cert wiring.
        .header("X-Rustion-Sig", "")
        .timeout(PROBE_TIMEOUT)
        .send()
        .await;
    let elapsed = start.elapsed();
    let latency_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            return ProbeOutcome::Failure {
                error: format!("transport: {e}"),
            };
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return ProbeOutcome::Failure {
            error: format!("http {}: {}", status.as_u16(), status.canonical_reason().unwrap_or("")),
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

fn mint_nonce() -> String {
    // rand 0.10 ships ThreadRng (CSPRNG, lazily seeded from the OS).
    // 16 random bytes is enough for the nonce — Rustion's replay
    // window keys an LRU on the nonce value, not on its entropy.
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    URL_SAFE_NO_PAD.encode(nonce)
}
