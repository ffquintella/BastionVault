//! The form-mode recipe engine (features/web-application-connect.md §5,
//! T96 Phase 2), written against two small traits so it runs — and is
//! tested — without a webview:
//!
//! * [`RecipePage`]: the host-observed page (top-frame URL and load state,
//!   from the webview's own navigation events and URL, never from the page)
//!   and one way in, [`RecipePage::eval`], which runs the fixed routine with
//!   a [`ScriptCall`] and returns its reply. The real implementation uses the
//!   webview's native script evaluation, whose only channel back is the
//!   script's return value — the window keeps no IPC.
//! * [`LaunchOps`]: the clock and `v2/connect/web/totp`.
//!
//! [`run_fill`] runs a recipe with the launch's credential; [`run_check`] is
//! the dry run behind `web_recipe_test`, and has no credential parameter at
//! all — it can only ever send check-mode calls.
//!
//! Rules the engine keeps, whatever the page replies:
//! * A step runs only when the host-observed URL matches its `when_url`, and
//!   only on an origin of the fill scope; every action re-checks the origin
//!   (host side) and the routine checks it again (page side).
//! * A failed safety check aborts; a transient one (not rendered yet, fading
//!   in, covered by a spinner) is retried with the *same* check until the
//!   deadline — never with a looser selector, never as heuristics.
//! * One outcome, then the password fields are cleared and the credential is
//!   dropped with the engine.

use std::borrow::Cow;
use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tauri::Url;
use tokio::sync::watch;
use tokio::time::Instant;

use bastion_vault::modules::resource::connect_web::recipe::FillValue;

use super::web::WebOrigin;
use super::web_recipe::{
    deadline_outcome, judge, plan_heuristic, select_step, totp_decision, value_kind, CredentialHas, EffectiveScope,
    LaunchCredential, Outcome, PlanAction, PlanSteps, RecipePlan, RefreshedTotp, TotpDecision,
};
use super::web_script::{ActionKind, ActionStatus, FieldExpect, ScanCounts, ScriptCall, ScriptMode, ScriptReply};

/// Delay between polls of the page.
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How long a dry run keeps re-checking an action whose check is transient
/// before it reports the state it saw.
pub const CHECK_SETTLE: Duration = Duration::from_secs(5);

/// The host-observed top frame.
#[derive(Debug, Clone, Default)]
pub struct PageSnapshot {
    pub url: Option<Url>,
    /// A top-frame load has started and not finished.
    pub loading: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalError {
    /// The evaluation produced no value (it threw, or was dropped).
    NoResult,
    /// The evaluation did not complete in time.
    Timeout,
    /// The window is gone.
    WindowGone,
    /// A value came back that is not a routine reply.
    Invalid,
}

pub trait RecipePage: Send + Sync {
    fn snapshot(&self) -> PageSnapshot;
    /// The session was torn down (window closed, `session_close`, exit).
    fn closed(&self) -> bool;
    fn eval(&self, call: &ScriptCall<'_>) -> impl Future<Output = Result<ScriptReply, EvalError>> + Send;
    /// Show the login state in the host-owned title.
    fn show(&self, text: &str);
}

pub trait LaunchOps: Send + Sync {
    fn now_utc(&self) -> DateTime<Utc>;
    fn refresh_totp(&self, step: u32) -> impl Future<Output = Result<RefreshedTotp, String>> + Send;
}

#[derive(Debug, Clone, Copy)]
pub struct EngineTiming {
    pub poll: Duration,
    /// The recipe's `timeout_secs`, from engine start.
    pub deadline: Duration,
    /// Dry run only, see [`CHECK_SETTLE`].
    pub settle: Duration,
}

impl EngineTiming {
    pub fn for_plan(plan: &RecipePlan) -> Self {
        Self { poll: POLL_INTERVAL, deadline: plan.timeout, settle: CHECK_SETTLE }
    }
}

/// Audit context for the engine's own lines. Names and hashes only.
#[derive(Debug, Clone, Copy)]
pub struct AuditTag<'a> {
    pub resource: &'a str,
    pub token: &'a str,
    pub launch_id_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillReport {
    pub outcome: Outcome,
    /// The last step the engine started (`result.step`).
    pub step: Option<u32>,
    /// Successful fills.
    pub fills: u32,
}

/// The origin of a ready URL, judged against the fill scope.
enum ScopeVerdict {
    In(WebOrigin),
    /// Not an http(s) document (`about:blank` between navigations): wait.
    NotWeb,
    /// An http(s) origin outside the fill scope.
    Out,
}

fn scope_verdict(scope: &EffectiveScope, url: &Url) -> ScopeVerdict {
    match url.scheme() {
        "http" | "https" => match WebOrigin::of_url(url) {
            Some(o) if scope.origins.contains(&o) => ScopeVerdict::In(o),
            _ => ScopeVerdict::Out,
        },
        _ => ScopeVerdict::NotWeb,
    }
}

fn ready_url<P: RecipePage>(page: &P) -> Option<Url> {
    let s = page.snapshot();
    if s.loading {
        None
    } else {
        s.url
    }
}

/// Sleep one poll, waking early on cancellation. Returns the cancel reason.
async fn pause(cancel: &mut watch::Receiver<Option<&'static str>>, poll: Duration) -> Option<&'static str> {
    if let Some(r) = *cancel.borrow() {
        return Some(r);
    }
    tokio::select! {
        _ = tokio::time::sleep(poll) => {}
        changed = cancel.changed() => {
            // A dropped sender cannot cancel any more; finish the poll.
            if changed.is_err() {
                tokio::time::sleep(poll).await;
            }
        }
    }
    *cancel.borrow()
}

struct FillRun<'a, P, L> {
    plan: &'a RecipePlan,
    scope: &'a EffectiveScope,
    page: &'a P,
    launch: &'a L,
    cancel: watch::Receiver<Option<&'static str>>,
    timing: EngineTiming,
    deadline: Instant,
    audit: AuditTag<'a>,
    credential: LaunchCredential,
    refresh_steps: Vec<u32>,
    fills: u32,
}

/// Run a recipe with the launch's credential. Consumes the credential: it is
/// dropped (zeroized) when this returns, whatever the outcome.
#[allow(clippy::too_many_arguments)]
pub async fn run_fill<P: RecipePage, L: LaunchOps>(
    plan: &RecipePlan,
    scope: &EffectiveScope,
    credential: LaunchCredential,
    refresh_steps: Vec<u32>,
    page: &P,
    launch: &L,
    cancel: watch::Receiver<Option<&'static str>>,
    timing: EngineTiming,
    audit: AuditTag<'_>,
) -> FillReport {
    let run = FillRun {
        plan,
        scope,
        page,
        launch,
        cancel,
        timing,
        deadline: Instant::now() + timing.deadline,
        audit,
        credential,
        refresh_steps,
        fills: 0,
    };
    run.run().await
}

impl<P: RecipePage, L: LaunchOps> FillRun<'_, P, L> {
    fn cancelled(&self) -> Option<&'static str> {
        *self.cancel.borrow()
    }

    async fn pause(&mut self) -> Option<&'static str> {
        pause(&mut self.cancel, self.timing.poll).await
    }

    async fn run(mut self) -> FillReport {
        let plan = self.plan;
        let mut next = 0usize;
        let mut last_step: Option<u32> = None;
        let mut attempted = false;
        self.page.show("signing in…");
        let outcome = loop {
            if let Some(r) = self.cancelled() {
                break Outcome::Aborted(r);
            }
            if self.page.closed() {
                break Outcome::Aborted("window_closed");
            }
            if Instant::now() >= self.deadline {
                break Outcome::Timeout;
            }
            let Some(url) = ready_url(self.page) else {
                if let Some(r) = self.pause().await {
                    break Outcome::Aborted(r);
                }
                continue;
            };
            let origin = match scope_verdict(self.scope, &url) {
                ScopeVerdict::In(o) => o,
                // The navigation allow-list is the fill scope, so this is a
                // policy failure, not a page to wait out.
                ScopeVerdict::Out => break Outcome::Aborted("origin"),
                ScopeVerdict::NotWeb => {
                    if let Some(r) = self.pause().await {
                        break Outcome::Aborted(r);
                    }
                    continue;
                }
            };
            let key = origin.to_string();

            // An outcome is a verdict on a login attempt, so it is judged
            // only once a step has run; a selector that also exists on the
            // login page cannot short-circuit the fill.
            if attempted {
                match self.judge_now(&url, &key).await {
                    Ok(Some(o)) => break o,
                    Ok(None) => {}
                    Err(o) => break o,
                }
            }

            let to_run: Option<(u32, Cow<'_, [PlanAction]>)> = match &plan.steps {
                PlanSteps::Explicit(steps) => {
                    select_step(steps, next, &url).map(|i| (i as u32, Cow::Borrowed(steps[i].actions.as_slice())))
                }
                PlanSteps::Heuristic if !attempted => match self.heuristic_actions(&key).await {
                    Ok(Some(actions)) => Some((0, Cow::Owned(actions))),
                    Ok(None) => None,
                    Err(o) => break o,
                },
                PlanSteps::Heuristic => None,
            };
            if let Some((i, actions)) = to_run {
                last_step = Some(i);
                if let Err(o) = self.run_actions(i, &actions, &origin).await {
                    break o;
                }
                next = i as usize + 1;
                attempted = true;
                self.page.show(plan.waiting_text());
            }
            if let Some(r) = self.pause().await {
                break Outcome::Aborted(r);
            }
        };
        self.clear_passwords().await;
        self.page.show(&outcome.title_text());
        FillReport { outcome, step: last_step, fills: self.fills }
    }

    async fn judge_now(&mut self, url: &Url, key: &str) -> Result<Option<Outcome>, Outcome> {
        let plan = self.plan;
        let (success, failure) = if plan.has_selector_condition() {
            let reply = {
                let call =
                    ScriptCall::probe(key, &self.scope.origin_keys, plan.success_selector(), plan.failure_selector());
                self.page.eval(&call).await
            };
            match reply {
                Ok(r) if r.status == ActionStatus::Ok && r.origin == key => (r.success, r.failure),
                Ok(r) if r.status.is_transient() => return Ok(None),
                Ok(r) if r.status == ActionStatus::Ok => return Err(Outcome::Aborted("probe_invalid")),
                Ok(r) => return Err(Outcome::Aborted(r.status.abort_check())),
                Err(EvalError::WindowGone) => return Err(Outcome::Aborted("window_closed")),
                Err(EvalError::Invalid) => return Err(Outcome::Aborted("probe_invalid")),
                Err(EvalError::NoResult | EvalError::Timeout) => return Ok(None),
            }
        } else {
            (None, None)
        };
        Ok(judge(plan, url, success, failure))
    }

    async fn heuristic_actions(&mut self, key: &str) -> Result<Option<Vec<PlanAction>>, Outcome> {
        let reply = {
            let call = ScriptCall::scan(key, &self.scope.origin_keys);
            self.page.eval(&call).await
        };
        match reply {
            Ok(r) if r.status == ActionStatus::Ok && r.origin == key => {
                let scan: ScanCounts = r.scan.ok_or(Outcome::Aborted("probe_invalid"))?;
                plan_heuristic(&scan, CredentialHas::of(&self.credential)).map_err(Outcome::Aborted)
            }
            Ok(r) if r.status.is_transient() => Ok(None),
            Ok(r) if r.status == ActionStatus::Ok => Err(Outcome::Aborted("probe_invalid")),
            Ok(r) => Err(Outcome::Aborted(r.status.abort_check())),
            Err(EvalError::WindowGone) => Err(Outcome::Aborted("window_closed")),
            Err(EvalError::Invalid) => Err(Outcome::Aborted("probe_invalid")),
            Err(EvalError::NoResult | EvalError::Timeout) => Ok(None),
        }
    }

    /// Whether a `totp` fill at `step` needs a fresh code: `Ok(Some(step))`
    /// when the code expired and the step still has its one refresh,
    /// `Ok(None)` when the current code is usable.
    fn totp_refresh_needed(&self, step: u32) -> Result<Option<u32>, Outcome> {
        let Some(totp) = &self.credential.totp else {
            return Err(Outcome::Aborted("credential_missing"));
        };
        match totp_decision(self.launch.now_utc(), totp.valid_until, step, &self.refresh_steps) {
            TotpDecision::UseCurrent => Ok(None),
            TotpDecision::Refresh(s) => Ok(Some(s)),
            TotpDecision::Expired => Err(Outcome::Aborted("totp_expired")),
        }
    }

    /// Spend `step`'s one refresh through `v2/connect/web/totp`.
    async fn refresh_totp(&mut self, step: u32) -> Result<(), Outcome> {
        match self.launch.refresh_totp(step).await {
            Ok(fresh) => {
                self.credential.totp = Some(fresh.code);
                self.refresh_steps = fresh.remaining_steps;
                Ok(())
            }
            Err(_) => Err(Outcome::Aborted("totp_refresh")),
        }
    }

    async fn run_actions(&mut self, step: u32, actions: &[PlanAction], step_origin: &WebOrigin) -> Result<(), Outcome> {
        let key = step_origin.to_string();
        for (j, action) in actions.iter().enumerate() {
            let mut last: Option<ActionStatus> = None;
            loop {
                if let Some(r) = self.cancelled() {
                    return Err(Outcome::Aborted(r));
                }
                if Instant::now() >= self.deadline {
                    return Err(deadline_outcome(action.kind, last));
                }
                let ready = ready_url(self.page);
                let current = ready.as_ref().map(|u| scope_verdict(self.scope, u));
                match current {
                    Some(ScopeVerdict::In(o)) if &o == step_origin => {}
                    Some(ScopeVerdict::In(_)) => return Err(Outcome::Aborted("navigated")),
                    Some(ScopeVerdict::Out) => return Err(Outcome::Aborted("origin")),
                    Some(ScopeVerdict::NotWeb) | None => {
                        if let Some(r) = self.pause().await {
                            return Err(Outcome::Aborted(r));
                        }
                        continue;
                    }
                }
                if matches!(action.value, Some(FillValue::Totp)) {
                    if let Some(refresh_step) = self.totp_refresh_needed(step)? {
                        // A step has one refresh: spend it only on a field
                        // the routine's checks pass right now, so a field
                        // that fails them never costs it.
                        let probe = {
                            let call = ScriptCall::check_fill(
                                &key,
                                &self.scope.origin_keys,
                                &action.selector,
                                FieldExpect::Totp,
                            );
                            self.page.eval(&call).await
                        };
                        match probe {
                            Ok(r) if r.status == ActionStatus::Ok && r.origin == key => {
                                self.refresh_totp(refresh_step).await?;
                            }
                            Ok(r) if r.status == ActionStatus::Ok => return Err(Outcome::Aborted("probe_invalid")),
                            Ok(r) if !r.status.is_transient() => return Err(Outcome::Aborted(r.status.abort_check())),
                            Err(EvalError::WindowGone) => return Err(Outcome::Aborted("window_closed")),
                            Err(EvalError::Invalid) => return Err(Outcome::Aborted("probe_invalid")),
                            transient => {
                                if let Ok(r) = transient {
                                    last = Some(r.status);
                                }
                                if let Some(r) = self.pause().await {
                                    return Err(Outcome::Aborted(r));
                                }
                                continue;
                            }
                        }
                    }
                }
                let reply = {
                    let origins = &self.scope.origin_keys;
                    let call = match (&action.value, action.expect()) {
                        (Some(v), Some(expect)) => {
                            let Some(value) = self.credential.value(v) else {
                                return Err(Outcome::Aborted("credential_missing"));
                            };
                            ScriptCall::fill(&key, origins, &action.selector, expect, value)
                        }
                        _ => ScriptCall::non_fill(action.kind, ScriptMode::Act, &key, origins, &action.selector),
                    };
                    self.page.eval(&call).await
                };
                match reply {
                    Ok(r) if r.status == ActionStatus::Ok => {
                        if r.origin != key {
                            return Err(Outcome::Aborted("probe_invalid"));
                        }
                        self.audit_action(step, j, action, &key);
                        break;
                    }
                    Ok(r) if r.status.is_transient() => last = Some(r.status),
                    Ok(r) => return Err(Outcome::Aborted(r.status.abort_check())),
                    Err(EvalError::WindowGone) => return Err(Outcome::Aborted("window_closed")),
                    Err(EvalError::Invalid) => return Err(Outcome::Aborted("probe_invalid")),
                    // A click or submit may have run: never repeat it.
                    Err(EvalError::NoResult | EvalError::Timeout)
                        if matches!(action.kind, ActionKind::Click | ActionKind::Submit) =>
                    {
                        return Err(Outcome::Aborted("script_no_result"))
                    }
                    Err(EvalError::NoResult | EvalError::Timeout) => {}
                }
                if let Some(r) = self.pause().await {
                    return Err(Outcome::Aborted(r));
                }
            }
        }
        Ok(())
    }

    fn audit_action(&mut self, step: u32, index: usize, action: &PlanAction, origin: &str) {
        let a = self.audit;
        match &action.value {
            Some(v) => {
                self.fills += 1;
                log::info!(
                    target: "audit",
                    "connect.web.fill: resource={} token={} launch_id_hash={} step={step} action={index} value={} \
                     origin={origin}",
                    a.resource,
                    a.token,
                    a.launch_id_hash,
                    value_kind(v),
                );
            }
            None => log::info!(
                target: "audit",
                "connect.web.action: resource={} token={} launch_id_hash={} step={step} action={index} kind={} \
                 origin={origin}",
                a.resource,
                a.token,
                a.launch_id_hash,
                action.kind.as_str(),
            ),
        }
    }

    /// Spec §5 "After submit": empty password fields still in the document.
    /// Best effort, on an in-scope page only.
    async fn clear_passwords(&mut self) {
        if self.fills == 0 {
            return;
        }
        let Some(url) = ready_url(self.page) else { return };
        let ScopeVerdict::In(origin) = scope_verdict(self.scope, &url) else { return };
        let key = origin.to_string();
        let call = ScriptCall::clear(&key, &self.scope.origin_keys);
        let _ = self.page.eval(&call).await;
    }
}

// ── Dry run ────────────────────────────────────────────────────────

/// One action as the dry run saw it. Selectors are the caller's own and are
/// not echoed; values are named, never present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionCheck {
    pub index: u32,
    pub kind: &'static str,
    /// `username` / `password` / `totp` / `literal` for a fill.
    pub value: Option<&'static str>,
    /// The routine's status (`ok`, `no_match`, `not_visible`, …), or
    /// `not_reached` when no page matched the step.
    pub status: &'static str,
    pub matches: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepCheck {
    pub index: u32,
    pub reached: bool,
    /// The origin the step was checked on (never a path or query).
    pub origin: Option<String>,
    pub actions: Vec<ActionCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeuristicCheck {
    pub scan: ScanCounts,
    /// The values heuristic mode would fill on that page, or an
    /// `aborted:<check>` it would stop with.
    pub would_fill: Vec<&'static str>,
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    /// `complete` (every step reached), `timeout`, or `aborted:<check>`.
    pub outcome: String,
    pub heuristic: bool,
    pub steps: Vec<StepCheck>,
    pub heuristic_check: Option<HeuristicCheck>,
    /// Origins of the pages the dry run looked at, in order.
    pub origins_seen: Vec<String>,
    pub success_seen: bool,
    pub failure_seen: bool,
}

fn not_reached(plan: &RecipePlan) -> Vec<StepCheck> {
    let PlanSteps::Explicit(steps) = &plan.steps else { return Vec::new() };
    steps
        .iter()
        .enumerate()
        .map(|(i, s)| StepCheck {
            index: i as u32,
            reached: false,
            origin: None,
            actions: s
                .actions
                .iter()
                .enumerate()
                .map(|(j, a)| ActionCheck {
                    index: j as u32,
                    kind: a.kind.as_str(),
                    value: a.value.as_ref().map(value_kind),
                    status: "not_reached",
                    matches: None,
                })
                .collect(),
        })
        .collect()
}

/// Dry-run a recipe: for every page the window reaches, check each step whose
/// `when_url` matches with check-mode calls (every safety check, no value,
/// no click, no submit), and probe the outcome selectors. Nothing here can
/// hold a credential, ask for a TOTP code or touch a launch.
pub async fn run_check<P: RecipePage>(
    plan: &RecipePlan,
    scope: &EffectiveScope,
    page: &P,
    timing: EngineTiming,
) -> CheckReport {
    let deadline = Instant::now() + timing.deadline;
    let mut report = CheckReport {
        outcome: "timeout".into(),
        heuristic: plan.is_heuristic(),
        steps: not_reached(plan),
        heuristic_check: None,
        origins_seen: Vec::new(),
        success_seen: false,
        failure_seen: false,
    };
    // A dry run is never cancelled from outside; the window closing ends it.
    let (_keep, mut cancel) = watch::channel::<Option<&'static str>>(None);
    let mut last_url: Option<String> = None;
    page.show("checking the recipe — nothing is filled");
    loop {
        if page.closed() {
            report.outcome = Outcome::Aborted("window_closed").wire();
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        let Some(url) = ready_url(page) else {
            pause(&mut cancel, timing.poll).await;
            continue;
        };
        let origin = match scope_verdict(scope, &url) {
            ScopeVerdict::In(o) => o,
            ScopeVerdict::Out => {
                report.outcome = Outcome::Aborted("origin").wire();
                break;
            }
            ScopeVerdict::NotWeb => {
                pause(&mut cancel, timing.poll).await;
                continue;
            }
        };
        if last_url.as_deref() != Some(url.as_str()) {
            last_url = Some(url.as_str().to_string());
            let key = origin.to_string();
            if !report.origins_seen.contains(&key) {
                report.origins_seen.push(key.clone());
            }
            match check_page(plan, scope, page, &url, &key, &mut report, deadline, timing).await {
                Ok(()) => {}
                Err(o) => {
                    report.outcome = o.wire();
                    break;
                }
            }
            let done = match &plan.steps {
                PlanSteps::Explicit(_) => report.steps.iter().all(|s| s.reached),
                PlanSteps::Heuristic => report.heuristic_check.is_some(),
            };
            if done {
                report.outcome = "complete".into();
                break;
            }
        }
        pause(&mut cancel, timing.poll).await;
    }
    page.show(&format!("recipe check: {}", report.outcome));
    report
}

#[allow(clippy::too_many_arguments)]
async fn check_page<P: RecipePage>(
    plan: &RecipePlan,
    scope: &EffectiveScope,
    page: &P,
    url: &Url,
    key: &str,
    report: &mut CheckReport,
    deadline: Instant,
    timing: EngineTiming,
) -> Result<(), Outcome> {
    let origins = &scope.origin_keys;
    if plan.has_selector_condition() || plan.success.url.is_some() || plan.failure.is_some() {
        let probed = if plan.has_selector_condition() {
            let call = ScriptCall::probe(key, origins, plan.success_selector(), plan.failure_selector());
            match page.eval(&call).await {
                Ok(r) if r.status == ActionStatus::Ok => Some((r.success, r.failure)),
                Ok(r) if r.status == ActionStatus::BadSelector => return Err(Outcome::Aborted("bad_selector")),
                Err(EvalError::WindowGone) => return Err(Outcome::Aborted("window_closed")),
                _ => None,
            }
        } else {
            Some((None, None))
        };
        if let Some((s, f)) = probed {
            report.success_seen |= plan.success.met(url, s);
            report.failure_seen |= plan.failure.as_ref().is_some_and(|c| c.met(url, f));
        }
    }
    match &plan.steps {
        PlanSteps::Heuristic => {
            if report.heuristic_check.is_some() {
                return Ok(());
            }
            let call = ScriptCall::scan(key, origins);
            match page.eval(&call).await {
                Ok(r) if r.status == ActionStatus::Ok => {
                    let scan = r.scan.ok_or(Outcome::Aborted("probe_invalid"))?;
                    let all = CredentialHas { username: true, password: true, totp: true };
                    let (would_fill, verdict) = match plan_heuristic(&scan, all) {
                        Ok(Some(actions)) => {
                            (actions.iter().filter_map(|a| a.value.as_ref().map(value_kind)).collect(), "ok".into())
                        }
                        Ok(None) => (Vec::new(), "no_candidates".into()),
                        Err(check) => (Vec::new(), Outcome::Aborted(check).wire()),
                    };
                    // A page with no candidates is not the login page yet.
                    if verdict != "no_candidates" {
                        report.heuristic_check = Some(HeuristicCheck { scan, would_fill, verdict });
                    }
                }
                Err(EvalError::WindowGone) => return Err(Outcome::Aborted("window_closed")),
                _ => {}
            }
        }
        PlanSteps::Explicit(steps) => {
            for (i, step) in steps.iter().enumerate() {
                if report.steps[i].reached || !step.when_url.matches(url) {
                    continue;
                }
                for (j, action) in step.actions.iter().enumerate() {
                    let (status, matches) = check_action(page, action, key, origins, deadline, timing).await?;
                    report.steps[i].actions[j].status = status.as_str();
                    report.steps[i].actions[j].matches = matches;
                }
                report.steps[i].reached = true;
                report.steps[i].origin = Some(key.to_string());
            }
        }
    }
    Ok(())
}

async fn check_action<P: RecipePage>(
    page: &P,
    action: &PlanAction,
    key: &str,
    origins: &[String],
    deadline: Instant,
    timing: EngineTiming,
) -> Result<(ActionStatus, Option<u32>), Outcome> {
    let settle_until = (Instant::now() + timing.settle).min(deadline);
    let (_keep, mut cancel) = watch::channel::<Option<&'static str>>(None);
    loop {
        let call = match action.expect() {
            Some(expect) => ScriptCall::check_fill(key, origins, &action.selector, expect),
            None => ScriptCall::non_fill(action.kind, ScriptMode::Check, key, origins, &action.selector),
        };
        let seen = match page.eval(&call).await {
            Ok(r) => Some((r.status, r.matches)),
            Err(EvalError::WindowGone) => return Err(Outcome::Aborted("window_closed")),
            Err(EvalError::Invalid) => Some((ActionStatus::ScriptError, None)),
            Err(EvalError::NoResult | EvalError::Timeout) => None,
        };
        let settled = Instant::now() >= settle_until;
        match seen {
            Some((status, matches)) if !status.is_transient() || settled => return Ok((status, matches)),
            None if settled => return Ok((ActionStatus::ScriptError, None)),
            _ => {}
        }
        pause(&mut cancel, timing.poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::web::{OriginSet, WebOrigin};
    use crate::session::web_recipe::TotpCode;
    use crate::session::web_script::{ScriptOp, HEURISTIC_SELECTORS};
    use bastion_vault::modules::resource::connect_web::recipe::WebLoginRecipe;
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    const FW: &str = "https://fw01.example.com";

    /// One recorded routine call, values included so tests can prove where
    /// they went.
    #[derive(Debug, Clone)]
    struct Seen {
        op: ScriptOp,
        mode: ScriptMode,
        kind: Option<ActionKind>,
        selector: Option<String>,
        expect: Option<FieldExpect>,
        value: Option<String>,
        origin: String,
        url: String,
    }

    type Responder = Box<dyn FnMut(&Seen, &mut PageState) -> Result<ScriptReply, EvalError> + Send>;

    struct PageState {
        url: Url,
        loading: bool,
        closed: bool,
    }

    struct FakePage {
        state: Mutex<PageState>,
        seen: Mutex<Vec<Seen>>,
        titles: Mutex<Vec<String>>,
        responder: Mutex<Responder>,
    }

    impl FakePage {
        fn new(url: &str, responder: Responder) -> Self {
            Self {
                state: Mutex::new(PageState { url: Url::parse(url).unwrap(), loading: false, closed: false }),
                seen: Mutex::new(Vec::new()),
                titles: Mutex::new(Vec::new()),
                responder: Mutex::new(responder),
            }
        }
        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
        fn actions(&self) -> Vec<Seen> {
            self.seen().into_iter().filter(|s| s.op == ScriptOp::Action).collect()
        }
    }

    impl RecipePage for FakePage {
        fn snapshot(&self) -> PageSnapshot {
            let s = self.state.lock().unwrap();
            PageSnapshot { url: Some(s.url.clone()), loading: s.loading }
        }
        fn closed(&self) -> bool {
            self.state.lock().unwrap().closed
        }
        fn eval(&self, call: &ScriptCall<'_>) -> impl Future<Output = Result<ScriptReply, EvalError>> + Send {
            let mut state = self.state.lock().unwrap();
            let seen = Seen {
                op: call.op(),
                mode: call.mode(),
                kind: call.kind(),
                selector: call.selector().map(str::to_string),
                expect: call.expect(),
                value: call.value().map(str::to_string),
                origin: call.origin().to_string(),
                url: state.url.to_string(),
            };
            self.seen.lock().unwrap().push(seen.clone());
            let reply = (self.responder.lock().unwrap())(&seen, &mut state);
            async move { reply }
        }
        fn show(&self, text: &str) {
            self.titles.lock().unwrap().push(text.to_string());
        }
    }

    fn ok(origin: &str) -> Result<ScriptReply, EvalError> {
        status(origin, ActionStatus::Ok)
    }

    fn status(origin: &str, status: ActionStatus) -> Result<ScriptReply, EvalError> {
        Ok(ScriptReply { origin: origin.into(), status, matches: Some(1), success: None, failure: None, scan: None })
    }

    fn probe(origin: &str, failure: u32) -> Result<ScriptReply, EvalError> {
        Ok(ScriptReply {
            origin: origin.into(),
            status: ActionStatus::Ok,
            matches: None,
            success: None,
            failure: Some(failure),
            scan: None,
        })
    }

    struct FakeLaunch {
        now: DateTime<Utc>,
        refreshes: Mutex<Vec<u32>>,
        fail: bool,
    }

    impl LaunchOps for FakeLaunch {
        fn now_utc(&self) -> DateTime<Utc> {
            self.now
        }
        fn refresh_totp(&self, step: u32) -> impl Future<Output = Result<RefreshedTotp, String>> + Send {
            self.refreshes.lock().unwrap().push(step);
            let r = if self.fail {
                Err("launch_expired".to_string())
            } else {
                Ok(RefreshedTotp {
                    code: TotpCode {
                        code: Zeroizing::new("999999".into()),
                        valid_until: self.now + chrono::Duration::seconds(30),
                    },
                    remaining_steps: vec![],
                })
            };
            async move { r }
        }
    }

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-05T12:00:00Z").unwrap().with_timezone(&Utc)
    }

    fn launch_at(now: DateTime<Utc>) -> FakeLaunch {
        FakeLaunch { now, refreshes: Mutex::new(Vec::new()), fail: false }
    }

    fn plan(v: Value) -> RecipePlan {
        RecipePlan::from_recipe(&WebLoginRecipe::parse(&v).unwrap()).unwrap()
    }

    fn two_page() -> RecipePlan {
        plan(json!({
            "version": 1,
            "steps": [
                { "when_url": "https://fw01.example.com/login", "actions": [
                    { "fill": "#u", "value": "username" },
                    { "fill": "#p", "value": "password" },
                    { "click": "#go" } ] },
                { "when_url": "https://fw01.example.com/2fa*", "actions": [
                    { "fill": "#otp", "value": "totp" },
                    { "submit": "form" } ] }
            ],
            "success_when": { "url": "https://fw01.example.com/ng/*" },
            "failure_when": { "selector": ".error" },
            "timeout_secs": 30
        }))
    }

    fn scope(origins: &[&str]) -> EffectiveScope {
        let set = OriginSet::new(origins.iter().map(|o| WebOrigin::parse_config(o, false).unwrap()).collect());
        EffectiveScope::local(Url::parse(&format!("{}/login", origins[0])).unwrap(), set, false)
    }

    fn credential(totp_valid_until: DateTime<Utc>) -> LaunchCredential {
        LaunchCredential {
            username: Some(Zeroizing::new("admin".into())),
            password: Some(Zeroizing::new("hunter2\"</script>".into())),
            totp: Some(TotpCode { code: Zeroizing::new("123456".into()), valid_until: totp_valid_until }),
        }
    }

    fn fast(deadline_ms: u64) -> EngineTiming {
        EngineTiming {
            poll: Duration::from_millis(1),
            deadline: Duration::from_millis(deadline_ms),
            settle: Duration::from_millis(20),
        }
    }

    const AUDIT: AuditTag<'static> = AuditTag { resource: "fw01", token: "sess_t", launch_id_hash: "h" };

    async fn fill(
        plan: &RecipePlan,
        scope: &EffectiveScope,
        page: &FakePage,
        launch: &FakeLaunch,
        deadline_ms: u64,
    ) -> FillReport {
        let (_tx, rx) = watch::channel(None);
        run_fill(
            plan,
            scope,
            credential(t0() + chrono::Duration::seconds(30)),
            vec![1],
            page,
            launch,
            rx,
            fast(deadline_ms),
            AUDIT,
        )
        .await
    }

    /// A well-behaved two-page login: the click moves to the 2FA page, the
    /// submit to the console.
    fn happy_responder() -> Responder {
        Box::new(|seen, st| match (seen.op, seen.kind) {
            (ScriptOp::Action, Some(ActionKind::Click)) => {
                st.url = Url::parse("https://fw01.example.com/2fa?x=1").unwrap();
                ok(FW)
            }
            (ScriptOp::Action, Some(ActionKind::Submit)) => {
                st.url = Url::parse("https://fw01.example.com/ng/home").unwrap();
                ok(FW)
            }
            (ScriptOp::Probe, _) => probe(FW, 0),
            _ => ok(FW),
        })
    }

    #[tokio::test]
    async fn a_two_page_login_fills_in_order_and_succeeds() {
        let page = FakePage::new("https://fw01.example.com/login", happy_responder());
        let launch = launch_at(t0());
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch, 5_000).await;
        assert_eq!(r.outcome, Outcome::Success);
        assert_eq!(r.step, Some(1));
        assert_eq!(r.fills, 3);
        let fills: Vec<(String, String)> = page
            .actions()
            .into_iter()
            .filter(|s| s.kind == Some(ActionKind::Fill))
            .map(|s| (s.selector.unwrap(), s.value.unwrap()))
            .collect();
        assert_eq!(
            fills,
            [
                ("#u".to_string(), "admin".to_string()),
                ("#p".into(), "hunter2\"</script>".into()),
                ("#otp".into(), "123456".into())
            ]
        );
        // Every call ran on the fill scope's origin, and named it.
        assert!(page.seen().iter().all(|s| s.origin == FW && s.url.starts_with(FW)));
        // The password fields were cleared after the outcome.
        assert_eq!(page.seen().last().unwrap().op, ScriptOp::Clear);
        assert!(launch.refreshes.lock().unwrap().is_empty(), "a valid code is not refreshed");
        assert_eq!(page.titles.lock().unwrap().last().unwrap(), "signed in");
    }

    #[tokio::test]
    async fn the_failure_selector_wins() {
        let page = FakePage::new(
            "https://fw01.example.com/login",
            Box::new(|seen, _| match seen.op {
                ScriptOp::Probe => probe(FW, 1),
                _ => ok(FW),
            }),
        );
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 5_000).await;
        assert_eq!(r.outcome, Outcome::Failure);
        assert_eq!(r.step, Some(0));
    }

    #[tokio::test]
    async fn nothing_is_filled_outside_the_fill_scope() {
        // The profile also allowed sso.example.com, but the server's scope
        // narrowed it out: the window lands there, nothing is filled.
        let page = FakePage::new("https://sso.example.com/login", Box::new(|_, _| ok("https://sso.example.com")));
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 2_000).await;
        assert_eq!(r.outcome, Outcome::Aborted("origin"));
        assert!(page.seen().is_empty(), "no script ran: {:?}", page.seen());
    }

    #[tokio::test]
    async fn a_navigation_mid_step_aborts_before_the_next_fill() {
        let page = FakePage::new(
            "https://fw01.example.com/login",
            Box::new(|seen, st| {
                if seen.selector.as_deref() == Some("#u") {
                    st.url = Url::parse("https://sso.example.com/").unwrap();
                }
                ok(FW)
            }),
        );
        let r = fill(&two_page(), &scope(&[FW, "https://sso.example.com"]), &page, &launch_at(t0()), 2_000).await;
        assert_eq!(r.outcome, Outcome::Aborted("navigated"));
        let actions = page.actions();
        assert_eq!(actions.len(), 1, "the password was never sent: {actions:?}");
        assert_eq!(actions[0].value.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn the_page_saying_origin_never_gets_a_fill_elsewhere() {
        // The page is mid-navigation: the routine refuses every attempt.
        let page = FakePage::new("https://fw01.example.com/login", Box::new(|_, _| status(FW, ActionStatus::Origin)));
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 100).await;
        assert_eq!(r.outcome, Outcome::Timeout);
        assert!(page.actions().iter().all(|s| s.origin == FW && s.selector.as_deref() == Some("#u")));
    }

    #[tokio::test]
    async fn a_failed_safety_check_aborts_at_once() {
        for (st, check) in [
            (ActionStatus::FormAction, "form_action"),
            (ActionStatus::Ambiguous, "ambiguous_match"),
            (ActionStatus::WrongType, "field_type"),
            (ActionStatus::NotTop, "frame"),
        ] {
            let page = FakePage::new("https://fw01.example.com/login", Box::new(move |_, _| status(FW, st)));
            let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 2_000).await;
            assert_eq!(r.outcome, Outcome::Aborted(check));
            assert_eq!(page.actions().len(), 1, "{check}: never retried");
        }
    }

    #[tokio::test]
    async fn a_transient_check_is_retried_unchanged_until_the_deadline() {
        let page =
            FakePage::new("https://fw01.example.com/login", Box::new(|_, _| status(FW, ActionStatus::NotVisible)));
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 150).await;
        assert_eq!(r.outcome, Outcome::Aborted("not_visible"));
        let actions = page.actions();
        assert!(actions.len() > 1);
        assert!(actions.iter().all(|s| s.selector.as_deref() == Some("#u") && s.expect == Some(FieldExpect::Username)));
    }

    #[tokio::test]
    async fn an_expired_code_is_refreshed_for_its_step() {
        let page = FakePage::new("https://fw01.example.com/login", happy_responder());
        // The bundle's code expired before the 2FA page was reached.
        let launch = launch_at(t0() + chrono::Duration::seconds(45));
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch, 5_000).await;
        assert_eq!(r.outcome, Outcome::Success);
        assert_eq!(*launch.refreshes.lock().unwrap(), vec![1]);
        let otp: Vec<Seen> = page.actions().into_iter().filter(|s| s.selector.as_deref() == Some("#otp")).collect();
        // First a value-less check that the field is fillable, then the fill.
        assert_eq!(otp.len(), 2);
        assert_eq!((otp[0].mode, otp[0].value.as_deref()), (ScriptMode::Check, None));
        assert_eq!(
            (otp[1].mode, otp[1].value.as_deref()),
            (ScriptMode::Act, Some("999999")),
            "the fresh code is filled"
        );
    }

    #[tokio::test]
    async fn the_one_refresh_is_not_spent_on_a_field_that_fails_its_checks() {
        let page = FakePage::new(
            "https://fw01.example.com/login",
            Box::new(|seen, st| match (seen.op, seen.kind, seen.selector.as_deref()) {
                (ScriptOp::Action, Some(ActionKind::Click), _) => {
                    st.url = Url::parse("https://fw01.example.com/2fa").unwrap();
                    ok(FW)
                }
                (ScriptOp::Action, _, Some("#otp")) => status(FW, ActionStatus::FormAction),
                (ScriptOp::Probe, _, _) => probe(FW, 0),
                _ => ok(FW),
            }),
        );
        let launch = launch_at(t0() + chrono::Duration::seconds(45));
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch, 5_000).await;
        assert_eq!(r.outcome, Outcome::Aborted("form_action"));
        assert!(launch.refreshes.lock().unwrap().is_empty(), "the refresh was kept");
        let otp: Vec<Seen> = page.actions().into_iter().filter(|s| s.selector.as_deref() == Some("#otp")).collect();
        assert_eq!(otp.len(), 1);
        assert_eq!(otp[0].mode, ScriptMode::Check);
        assert!(otp[0].value.is_none(), "no code was sent to a field that failed");
    }

    #[tokio::test]
    async fn an_expired_code_with_no_refresh_left_is_never_filled() {
        let page = FakePage::new("https://fw01.example.com/login", happy_responder());
        let launch = launch_at(t0() + chrono::Duration::seconds(45));
        let (_tx, rx) = watch::channel(None);
        let r = run_fill(
            &two_page(),
            &scope(&[FW]),
            credential(t0() + chrono::Duration::seconds(30)),
            vec![],
            &page,
            &launch,
            rx,
            fast(5_000),
            AUDIT,
        )
        .await;
        assert_eq!(r.outcome, Outcome::Aborted("totp_expired"));
        assert!(page.actions().iter().all(|s| s.selector.as_deref() != Some("#otp")));
        assert!(launch.refreshes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_failed_refresh_aborts() {
        let page = FakePage::new("https://fw01.example.com/login", happy_responder());
        let launch = FakeLaunch { fail: true, ..launch_at(t0() + chrono::Duration::seconds(45)) };
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch, 5_000).await;
        assert_eq!(r.outcome, Outcome::Aborted("totp_refresh"));
    }

    #[tokio::test]
    async fn a_click_that_returns_nothing_is_never_repeated() {
        let page = FakePage::new(
            "https://fw01.example.com/login",
            Box::new(|seen, _| match seen.kind {
                Some(ActionKind::Click) => Err(EvalError::NoResult),
                _ => ok(FW),
            }),
        );
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 2_000).await;
        assert_eq!(r.outcome, Outcome::Aborted("script_no_result"));
        assert_eq!(page.actions().iter().filter(|s| s.kind == Some(ActionKind::Click)).count(), 1);
    }

    #[tokio::test]
    async fn a_closed_window_ends_the_run() {
        let page = FakePage::new("https://fw01.example.com/login", Box::new(|_, _| Err(EvalError::WindowGone)));
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 2_000).await;
        assert_eq!(r.outcome, Outcome::Aborted("window_closed"));
    }

    #[tokio::test]
    async fn cancellation_stops_the_engine_with_its_reason() {
        let page = FakePage::new("https://fw01.example.com/elsewhere", Box::new(|_, _| ok(FW)));
        let (tx, rx) = watch::channel(None);
        let plan = two_page();
        let sc = scope(&[FW]);
        let launch = launch_at(t0());
        let run = run_fill(&plan, &sc, credential(t0()), vec![], &page, &launch, rx, fast(10_000), AUDIT);
        let cancel = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tx.send(Some("window_closed")).unwrap();
        };
        let (r, ()) = tokio::join!(run, cancel);
        assert_eq!(r.outcome, Outcome::Aborted("window_closed"));
    }

    #[tokio::test]
    async fn loading_pages_are_waited_out() {
        let page = FakePage::new("https://fw01.example.com/login", Box::new(|_, _| ok(FW)));
        page.state.lock().unwrap().loading = true;
        let r = fill(&two_page(), &scope(&[FW]), &page, &launch_at(t0()), 60).await;
        assert_eq!(r.outcome, Outcome::Timeout);
        assert!(page.seen().is_empty(), "nothing runs on a page still loading");
    }

    #[tokio::test]
    async fn heuristic_mode_scans_fills_and_submits() {
        let plan =
            plan(json!({ "version": 1, "steps": "auto", "success_when": { "url": "https://fw01.example.com/home*" } }));
        let page = FakePage::new(
            "https://fw01.example.com/login",
            Box::new(|seen, st| match (seen.op, seen.kind) {
                (ScriptOp::Scan, _) => Ok(ScriptReply {
                    origin: FW.into(),
                    status: ActionStatus::Ok,
                    matches: None,
                    success: None,
                    failure: None,
                    scan: Some(ScanCounts { username: 1, current_password: 1, password: 1, otp: 0 }),
                }),
                (ScriptOp::Action, Some(ActionKind::Submit)) => {
                    st.url = Url::parse("https://fw01.example.com/home").unwrap();
                    ok(FW)
                }
                _ => ok(FW),
            }),
        );
        let (_tx, rx) = watch::channel(None);
        let r =
            run_fill(&plan, &scope(&[FW]), credential(t0()), vec![0], &page, &launch_at(t0()), rx, fast(5_000), AUDIT)
                .await;
        assert_eq!(r.outcome, Outcome::Success);
        let a = page.actions();
        assert_eq!(a[0].selector.as_deref(), Some(HEURISTIC_SELECTORS.username));
        assert_eq!(a[1].selector.as_deref(), Some(HEURISTIC_SELECTORS.current_password));
        assert_eq!(a[1].value.as_deref(), Some("hunter2\"</script>"));
        assert_eq!(a[2].kind, Some(ActionKind::Submit));
    }

    #[tokio::test]
    async fn the_dry_run_never_carries_a_value_or_acts() {
        let page = FakePage::new(
            "https://fw01.example.com/login",
            Box::new(|seen, _| match (seen.op, seen.selector.as_deref()) {
                (ScriptOp::Probe, _) => probe(FW, 0),
                (_, Some("#p")) => status(FW, ActionStatus::NotVisible),
                _ => ok(FW),
            }),
        );
        let r = run_check(&two_page(), &scope(&[FW]), &page, fast(200)).await;
        let seen = page.seen();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|s| s.value.is_none() && s.mode == ScriptMode::Check), "{seen:?}");
        assert!(seen.iter().all(|s| s.op != ScriptOp::Clear));
        assert_eq!(r.steps[0].actions[0].status, "ok");
        assert_eq!(r.steps[0].actions[1].status, "not_visible");
        assert_eq!(r.steps[0].actions[1].value, Some("password"));
        assert!(r.steps[0].reached);
        assert!(!r.steps[1].reached);
        assert_eq!(r.steps[1].actions[0].status, "not_reached");
        assert_eq!(r.outcome, "timeout");
        assert_eq!(r.origins_seen, vec![FW.to_string()]);
    }

    #[tokio::test]
    async fn a_dry_run_stops_when_its_window_closes() {
        let page = FakePage::new("https://fw01.example.com/elsewhere", Box::new(|_, _| ok(FW)));
        page.state.lock().unwrap().closed = true;
        let r = run_check(&two_page(), &scope(&[FW]), &page, fast(10_000)).await;
        assert_eq!(r.outcome, "aborted:window_closed");
    }

    #[tokio::test]
    async fn the_dry_run_completes_when_every_step_was_seen() {
        let plan = plan(json!({
            "version": 1,
            "steps": [ { "when_url": "https://fw01.example.com/login", "actions": [ { "wait": "form" } ] } ],
            "success_when": { "url": "https://fw01.example.com/ng/*" }
        }));
        let page = FakePage::new("https://fw01.example.com/login", Box::new(|_, _| ok(FW)));
        let r = run_check(&plan, &scope(&[FW]), &page, fast(2_000)).await;
        assert_eq!(r.outcome, "complete");
        assert!(!r.success_seen);
    }
}
