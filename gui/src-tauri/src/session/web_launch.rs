//! The server half of a form-mode web session, host side
//! (features/web-application-connect.md §3, docs/api.md "Web Connect (`form`
//! mode)"; T96 Phase 2).
//!
//! Call order: `connect/mfa/*` (the GUI, before the host is called) →
//! `launch` → `totp`* → `result` → `close`.
//!
//! * [`launch`] calls `resources/v2/connect/web/launch` **instead of**
//!   `connect/authorize` — it burns the MFA ticket itself — and returns the
//!   bundle with the credential in `Zeroizing` buffers.
//! * [`WebLaunch`] owns the `launch_id` and the per-launch call state.
//!   [`LaunchCalls`] is the pure state machine behind it: `result` is sent at
//!   most once with one outcome, `close` is sent exactly once, and a teardown
//!   that comes before the engine's outcome records `aborted:<reason>` first
//!   (the server only takes `result` on an open launch).
//! * Every call goes through a [`LaunchChannel`] captured at launch: the
//!   backend, token and namespace the launch was bound to, so a later vault
//!   switch or logout cannot send `result` / `close` to the wrong place.
//!
//! Never logged: the credential, a TOTP code, the `launch_id` (only its
//! SHA-256, the same `launch_id_hash` the server audits), the vault token.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bv_client::{Backend, Operation};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{watch, Mutex};
use zeroize::Zeroizing;

use super::web_engine::LaunchOps;
use super::web_recipe::{self, LaunchBundle, Outcome, RefreshedTotp, TotpCode};
use crate::state::AppState;

/// The four endpoints live under the resource mount, v2 only.
const WEB_CONNECT_PREFIX: &str = "resources/v2/connect/web/";

/// How long to wait before the one retry of a `close` whose LDAP check-in
/// failed (the server's documented remedy is "call close again").
const CHECKIN_RETRY_DELAY: Duration = Duration::from_secs(1);

/// The backend, token and namespace one launch is bound to.
pub struct LaunchChannel {
    backend: Arc<dyn Backend>,
    token: Zeroizing<String>,
    namespace: Option<String>,
}

impl LaunchChannel {
    /// Capture the session's current backend, token and namespace — the
    /// same three `make_request` would use for this call.
    pub async fn capture(state: &AppState) -> Result<Self, String> {
        let backend =
            state.backend.lock().await.clone().ok_or_else(|| "No vault open or remote server connected".to_string())?;
        let token = Zeroizing::new(state.token.lock().await.clone().unwrap_or_default());
        let namespace = state.active_namespace.lock().await.clone();
        Ok(Self { backend, token, namespace })
    }

    async fn write(&self, op: &str, body: Map<String, Value>) -> Result<Map<String, Value>, String> {
        let path = format!("{WEB_CONNECT_PREFIX}{op}");
        let resp = self
            .backend
            .handle_with_namespace(Operation::Write, &path, Some(body), &self.token, self.namespace.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        Ok(resp.and_then(|r| r.data).unwrap_or_default())
    }
}

/// Hex SHA-256 of a `launch_id` — what the server's audit lines carry, so
/// host and server lines can be joined without either logging the handle.
pub fn launch_id_hash(launch_id: &str) -> String {
    hex::encode(Sha256::digest(launch_id.trim().as_bytes()))
}

/// The stable refusal code in a server error (`<code>: …`), when it is one
/// the host acts on or reports. Never the message text, which the host does
/// not control.
pub fn refusal_code(message: &str) -> &'static str {
    const CODES: &[&str] = &[
        "ldap_checkin_failed",
        "launch_unknown",
        "launch_binding_mismatch",
        "launch_expired",
        "launch_closed",
        "launch_busy",
        "totp_not_configured",
        "totp_step_used",
        "totp_step_invalid",
        "result_conflict",
        "invalid_request",
    ];
    CODES.iter().copied().find(|c| message.contains(c)).unwrap_or("request_failed")
}

// ── The call-state machine ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResultState {
    Pending,
    /// Sent (or being sent, under the launch's lock) and delivered.
    Sent,
    /// Sent but not delivered; `close` sends the same outcome once more
    /// (the server takes a repeat of the same outcome idempotently).
    Failed(ResultCall),
}

/// One `result` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultCall {
    pub outcome: String,
    pub step: Option<u32>,
}

/// What a teardown has to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseCalls {
    pub result: Option<ResultCall>,
    pub close: bool,
}

/// Per-launch call state. Pure: the caller performs the calls it returns,
/// holding the launch's lock, so a `result` in flight always lands before
/// the `close` that follows it.
#[derive(Debug)]
pub struct LaunchCalls {
    result: ResultState,
    closed: bool,
}

impl Default for LaunchCalls {
    fn default() -> Self {
        Self::new()
    }
}

impl LaunchCalls {
    pub fn new() -> Self {
        Self { result: ResultState::Pending, closed: false }
    }

    /// The engine's outcome. `Some` the first time only and never after
    /// `close`: a launch records one outcome.
    pub fn claim_result(&mut self, outcome: &Outcome, step: Option<u32>) -> Option<ResultCall> {
        if self.closed || self.result != ResultState::Pending {
            return None;
        }
        self.result = ResultState::Sent;
        Some(ResultCall { outcome: outcome.wire(), step })
    }

    /// Record whether a claimed `result` reached the server.
    pub fn settle_result(&mut self, call: ResultCall, delivered: bool) {
        if !delivered {
            self.result = ResultState::Failed(call);
        }
    }

    /// Teardown. The first call returns `close: true`, plus the `result`
    /// still owed: `aborted:<abort_check>` when no outcome was claimed, or
    /// the undelivered outcome again. Every later call returns nothing.
    pub fn claim_close(&mut self, abort_check: &'static str) -> CloseCalls {
        if self.closed {
            return CloseCalls { result: None, close: false };
        }
        self.closed = true;
        let result = match std::mem::replace(&mut self.result, ResultState::Sent) {
            ResultState::Pending => Some(ResultCall { outcome: Outcome::Aborted(abort_check).wire(), step: None }),
            ResultState::Failed(call) => Some(call),
            ResultState::Sent => None,
        };
        CloseCalls { result, close: true }
    }

    #[cfg(test)]
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

// ── One launch ─────────────────────────────────────────────────────

/// A live `launch_id` and everything needed to finish it.
pub struct WebLaunch {
    channel: LaunchChannel,
    launch_id: Zeroizing<String>,
    launch_id_hash: String,
    resource: String,
    /// The host session token, for audit correlation with `session.open`.
    session_token: String,
    launched_at: Instant,
    calls: Mutex<LaunchCalls>,
    cancel: watch::Sender<Option<&'static str>>,
}

impl WebLaunch {
    fn new(channel: LaunchChannel, launch_id: Zeroizing<String>, resource: &str, session_token: &str) -> Self {
        let launch_id_hash = launch_id_hash(&launch_id);
        Self {
            channel,
            launch_id,
            launch_id_hash,
            resource: resource.to_string(),
            session_token: session_token.to_string(),
            launched_at: Instant::now(),
            calls: Mutex::new(LaunchCalls::new()),
            cancel: watch::channel(None).0,
        }
    }

    pub fn launch_id_hash(&self) -> &str {
        &self.launch_id_hash
    }

    /// Stop the recipe engine (it reports its own `aborted:<check>`, which
    /// is a no-op once teardown has claimed the result).
    pub fn cancel(&self, check: &'static str) {
        self.cancel.send_if_modified(|v| {
            if v.is_none() {
                *v = Some(check);
                true
            } else {
                false
            }
        });
    }

    pub fn cancel_rx(&self) -> watch::Receiver<Option<&'static str>> {
        self.cancel.subscribe()
    }

    fn body(&self) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert("launch_id".into(), Value::String(self.launch_id.to_string()));
        body
    }

    /// Report the engine's outcome — at most once per launch.
    pub async fn report(&self, outcome: &Outcome, step: Option<u32>) {
        let mut calls = self.calls.lock().await;
        let Some(call) = calls.claim_result(outcome, step) else {
            return;
        };
        let delivered = self.post_result(&call).await;
        calls.settle_result(call, delivered);
    }

    async fn post_result(&self, call: &ResultCall) -> bool {
        let mut body = self.body();
        body.insert("outcome".into(), Value::String(call.outcome.clone()));
        if let Some(step) = call.step {
            body.insert("step".into(), Value::from(step));
        }
        let step = call.step.map(|s| s.to_string()).unwrap_or_else(|| "none".into());
        match self.channel.write("result", body).await {
            Ok(data) => {
                log::info!(
                    target: "audit",
                    "connect.web.result: resource={} token={} launch_id_hash={} outcome={} step={step} \
                     already_recorded={}",
                    self.resource,
                    self.session_token,
                    self.launch_id_hash,
                    call.outcome,
                    data.get("already_recorded").and_then(Value::as_bool).unwrap_or(false),
                );
                true
            }
            Err(e) => {
                log::warn!(
                    target: "audit",
                    "connect.web.result_failed: resource={} token={} launch_id_hash={} outcome={} step={step} \
                     code={}",
                    self.resource,
                    self.session_token,
                    self.launch_id_hash,
                    call.outcome,
                    refusal_code(&e),
                );
                false
            }
        }
    }

    /// Teardown: send the `result` still owed, then `close`. Idempotent —
    /// only the first call sends anything. Failures are logged (code only)
    /// and never block the window's teardown.
    pub async fn finish(&self, abort_check: &'static str) {
        let mut calls = self.calls.lock().await;
        let plan = calls.claim_close(abort_check);
        if !plan.close {
            return;
        }
        if let Some(r) = &plan.result {
            self.post_result(r).await;
        }
        for attempt in 1..=2 {
            match self.channel.write("close", self.body()).await {
                Ok(data) => {
                    log::info!(
                        target: "audit",
                        "connect.web.close: resource={} token={} launch_id_hash={} ldap_checkin={} \
                         already_closed={} duration_ms={}",
                        self.resource,
                        self.session_token,
                        self.launch_id_hash,
                        data.get("ldap_checkin").and_then(Value::as_str).unwrap_or("unknown"),
                        data.get("already_closed").and_then(Value::as_bool).unwrap_or(false),
                        self.launched_at.elapsed().as_millis(),
                    );
                    return;
                }
                Err(e) if refusal_code(&e) == "ldap_checkin_failed" => {
                    log::warn!(
                        target: "audit",
                        "connect.web.close: resource={} token={} launch_id_hash={} ldap_checkin=failed \
                         attempt={attempt} — the session is closed; {}",
                        self.resource,
                        self.session_token,
                        self.launch_id_hash,
                        if attempt == 1 {
                            "retrying the check-in once"
                        } else {
                            "the LDAP account stays checked out until its lease expires"
                        },
                    );
                    if attempt == 1 {
                        tokio::time::sleep(CHECKIN_RETRY_DELAY).await;
                    }
                }
                Err(e) => {
                    log::warn!(
                        target: "audit",
                        "connect.web.close_failed: resource={} token={} launch_id_hash={} code={} — the server \
                         reaps the launch record; an LDAP account is released when its lease expires",
                        self.resource,
                        self.session_token,
                        self.launch_id_hash,
                        refusal_code(&e),
                    );
                    return;
                }
            }
        }
    }
}

impl LaunchOps for WebLaunch {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }

    async fn refresh_totp(&self, step: u32) -> Result<RefreshedTotp, String> {
        let mut body = self.body();
        body.insert("step".into(), Value::from(step));
        let mut data = match self.channel.write("totp", body).await {
            Ok(d) => d,
            Err(e) => {
                log::warn!(
                    target: "audit",
                    "connect.web.totp_refresh_failed: resource={} token={} launch_id_hash={} step={step} code={}",
                    self.resource,
                    self.session_token,
                    self.launch_id_hash,
                    refusal_code(&e),
                );
                return Err(e);
            }
        };
        let parsed = parse_refreshed_totp(&mut data);
        web_recipe::scrub_map(&mut data);
        if parsed.is_ok() {
            log::info!(
                target: "audit",
                "connect.web.totp_refresh: resource={} token={} launch_id_hash={} step={step}",
                self.resource,
                self.session_token,
                self.launch_id_hash,
            );
        }
        parsed
    }
}

/// Parse a `v2/connect/web/totp` response, moving the code into a
/// `Zeroizing` buffer.
pub fn parse_refreshed_totp(data: &mut Map<String, Value>) -> Result<RefreshedTotp, String> {
    let code = match data.remove("totp") {
        Some(Value::String(s)) => Zeroizing::new(s),
        _ => return Err("the TOTP refresh carried no code".into()),
    };
    let valid_until = data
        .get("totp_valid_until")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .ok_or_else(|| "the TOTP refresh carried no validity window".to_string())?
        .with_timezone(&Utc);
    let remaining_steps = data
        .get("totp_refresh_steps")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok())).collect::<Option<Vec<_>>>())
        .ok_or_else(|| "the TOTP refresh carried no step list".to_string())?;
    Ok(RefreshedTotp { code: TotpCode { code, valid_until }, remaining_steps })
}

/// What [`launch`] needs from the caller.
pub struct LaunchRequest<'a> {
    pub resource: &'a str,
    pub profile_id: &'a str,
    pub recipe_hash: &'a str,
    pub connect_ticket: Option<&'a str>,
    pub session_token: &'a str,
}

/// `POST resources/v2/connect/web/launch`. A refusal is returned as the
/// server's error. A response that carries a `launch_id` but fails to parse
/// is reported (`aborted:bundle_invalid`) and closed before the error
/// returns, so the server never holds an orphaned launch the host knows of.
pub async fn launch(channel: LaunchChannel, req: &LaunchRequest<'_>) -> Result<(Arc<WebLaunch>, LaunchBundle), String> {
    let mut body = Map::new();
    body.insert("resource".into(), Value::String(req.resource.to_string()));
    body.insert("profile_id".into(), Value::String(req.profile_id.to_string()));
    body.insert("recipe_hash".into(), Value::String(req.recipe_hash.to_string()));
    if let Some(t) = req.connect_ticket.map(str::trim).filter(|t| !t.is_empty()) {
        body.insert("connect_ticket".into(), Value::String(t.to_string()));
    }
    let mut data = channel.write("launch", body).await?;
    let launch_id = match web_recipe::take_launch_id(&mut data) {
        Ok(id) => id,
        Err(e) => {
            web_recipe::scrub_map(&mut data);
            return Err(format!("the launch response is malformed ({e}); nothing was opened"));
        }
    };
    let launch = Arc::new(WebLaunch::new(channel, launch_id, req.resource, req.session_token));
    match web_recipe::parse_bundle(data) {
        Ok(bundle) => Ok((launch, bundle)),
        Err(e) => {
            launch.finish("bundle_invalid").await;
            Err(format!("the launch bundle is malformed ({e}); the launch was reported and closed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn result_is_claimed_once_and_close_follows() {
        let mut c = LaunchCalls::new();
        let r = c.claim_result(&Outcome::Success, Some(1)).unwrap();
        assert_eq!(r, ResultCall { outcome: "success".into(), step: Some(1) });
        c.settle_result(r, true);
        assert_eq!(c.claim_result(&Outcome::Failure, Some(1)), None, "a second outcome is never sent");
        assert_eq!(c.claim_close("window_closed"), CloseCalls { result: None, close: true });
        assert!(c.is_closed());
    }

    #[test]
    fn teardown_before_an_outcome_reports_the_abort_first() {
        let mut c = LaunchCalls::new();
        assert_eq!(
            c.claim_close("window_build"),
            CloseCalls { result: Some(ResultCall { outcome: "aborted:window_build".into(), step: None }), close: true }
        );
        // The engine's late outcome is dropped.
        assert_eq!(c.claim_result(&Outcome::Success, Some(0)), None);
    }

    #[test]
    fn every_teardown_path_closes_exactly_once() {
        for reason in ["window_closed", "session_closed", "window_build", "app_exit", "session_dropped"] {
            let mut c = LaunchCalls::new();
            let first = c.claim_close(reason);
            assert!(first.close, "{reason}");
            assert_eq!(first.result.unwrap().outcome, format!("aborted:{reason}"));
            for again in ["window_closed", "session_closed", "app_exit"] {
                assert_eq!(c.claim_close(again), CloseCalls { result: None, close: false }, "{reason} then {again}");
            }
        }
    }

    #[test]
    fn an_undelivered_result_is_resent_unchanged_on_close() {
        let mut c = LaunchCalls::new();
        let r = c.claim_result(&Outcome::Aborted("form_action"), Some(0)).unwrap();
        c.settle_result(r.clone(), false);
        assert_eq!(c.claim_result(&Outcome::Success, None), None);
        assert_eq!(c.claim_close("window_closed"), CloseCalls { result: Some(r), close: true });
    }

    #[test]
    fn refusal_codes_are_extracted_never_the_message() {
        assert_eq!(refusal_code("HTTP 502: ldap_checkin_failed: the session is closed, but …"), "ldap_checkin_failed");
        assert_eq!(refusal_code("launch_expired: the launch's 60-second login window has passed"), "launch_expired");
        assert_eq!(refusal_code("connection refused (os error 61)"), "request_failed");
    }

    #[test]
    fn launch_id_hash_matches_the_server() {
        let id = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";
        assert_eq!(launch_id_hash(id), bastion_vault::modules::resource::connect_web::launch_store::launch_id_hash(id));
        assert_eq!(launch_id_hash(id).len(), 64);
    }

    #[test]
    fn a_totp_refresh_parses_and_moves_the_code() {
        let mut d = json!({ "totp": "654321", "totp_valid_until": "2026-10-05T12:01:00Z", "step": 1,
                            "totp_refresh_steps": [3] })
        .as_object()
        .unwrap()
        .clone();
        let r = parse_refreshed_totp(&mut d).unwrap();
        assert_eq!(r.code.code.as_str(), "654321");
        assert_eq!(r.remaining_steps, vec![3]);
        assert!(!d.contains_key("totp"), "the code was moved, not copied");
        let mut bad = json!({ "totp": "1", "totp_refresh_steps": [] }).as_object().unwrap().clone();
        assert!(parse_refreshed_totp(&mut bad).is_err());
    }
}
