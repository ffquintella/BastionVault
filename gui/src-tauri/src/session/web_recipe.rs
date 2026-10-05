//! Form-mode recipe planning — the parts of the host recipe engine that need
//! no webview (features/web-application-connect.md §2, §3, §5; T96 Phase 2).
//!
//! * [`RecipePlan`]: a recipe the server's own strict parser accepted
//!   (`bastion_vault::modules::resource::connect_web::recipe`), with its URL
//!   patterns compiled into [`UrlGlob`]s.
//! * Step selection, outcome judging and the `aborted:<check>` vocabulary.
//! * The TOTP refresh decision.
//! * The launch bundle: strict parsing, the credential held in `Zeroizing`
//!   buffers, and the bundle-vs-profile cross-checks.
//! * [`reconcile_fill_scope`]: the server's `fill_scope` is authoritative and
//!   may only *narrow* what the host's copy of the profile allows.
//! * Heuristic (`"steps": "auto"`) planning from candidate counts.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map, Value};
use tauri::Url;
use zeroize::{Zeroize, Zeroizing};

use bastion_vault::modules::resource::connect_web::recipe::{
    FillValue, PauseReason, RecipeAction, RecipeCondition, RecipeSteps, WebLoginRecipe,
};

use super::web::{OriginSet, WebOrigin};
use super::web_script::{ActionKind, FieldExpect, ScanCounts, HEURISTIC_SELECTORS};

// ── URL patterns ───────────────────────────────────────────────────

/// A recipe URL pattern: an exact origin plus a glob over everything after
/// it (path, query, fragment). Only `*` is special, and never in the origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlGlob {
    origin: WebOrigin,
    tail: String,
}

impl UrlGlob {
    pub fn compile(pattern: &str) -> Result<Self, String> {
        if pattern.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
            return Err(format!("URL pattern `{pattern}` contains whitespace, a control character or a backslash"));
        }
        let (scheme, rest) =
            pattern.split_once("://").ok_or_else(|| format!("URL pattern `{pattern}` is not an absolute URL"))?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty() || authority.contains(['*', '@']) {
            return Err(format!("URL pattern `{pattern}` must name a literal origin"));
        }
        let base = Url::parse(&format!("{scheme}://{authority}/"))
            .map_err(|e| format!("URL pattern `{pattern}` has an invalid origin: {e}"))?;
        let origin =
            WebOrigin::of_url(&base).ok_or_else(|| format!("URL pattern `{pattern}` is not an http(s) origin"))?;
        // `https://a` and `https://a?x` address the path `/`.
        let tail = if tail.starts_with('/') { tail.to_string() } else { format!("/{tail}") };
        Ok(Self { origin, tail })
    }

    pub fn origin(&self) -> &WebOrigin {
        &self.origin
    }

    /// Match the host-observed URL: the origin exactly, the rest by glob.
    pub fn matches(&self, url: &Url) -> bool {
        WebOrigin::of_url(url).as_ref() == Some(&self.origin) && glob_match(&self.tail, &url_tail(url))
    }
}

/// Everything after the origin: path, `?query`, `#fragment`, as serialised.
fn url_tail(url: &Url) -> String {
    let mut s = url.path().to_string();
    if let Some(q) = url.query() {
        s.push('?');
        s.push_str(q);
    }
    if let Some(f) = url.fragment() {
        s.push('#');
        s.push_str(f);
    }
    s
}

/// `*` matches any run of characters (including `/`); everything else is
/// literal. Iterative with single-star backtracking, so a hostile URL cannot
/// make it exponential.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

// ── The plan ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanAction {
    pub kind: ActionKind,
    pub selector: String,
    /// `Some` exactly for `fill`.
    pub value: Option<FillValue>,
}

impl PlanAction {
    /// The field type a fill expects, from its value.
    pub fn expect(&self) -> Option<FieldExpect> {
        self.value.as_ref().map(|v| match v {
            FillValue::Username => FieldExpect::Username,
            FillValue::Password => FieldExpect::Password,
            FillValue::Totp => FieldExpect::Totp,
            FillValue::Literal(_) => FieldExpect::Literal,
        })
    }
}

/// The audit / report name of a fill value — never the value.
pub fn value_kind(v: &FillValue) -> &'static str {
    match v {
        FillValue::Username => "username",
        FillValue::Password => "password",
        FillValue::Totp => "totp",
        FillValue::Literal(_) => "literal",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub when_url: UrlGlob,
    pub actions: Vec<PlanAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanCondition {
    pub url: Option<UrlGlob>,
    pub selector: Option<String>,
}

impl PlanCondition {
    fn compile(c: &RecipeCondition) -> Result<Self, String> {
        Ok(Self { url: c.url.as_deref().map(UrlGlob::compile).transpose()?, selector: c.selector.clone() })
    }

    /// Both halves that are set must hold. `selector_count` is `None` when
    /// the selector was not probed, which never satisfies a selector half.
    pub fn met(&self, url: &Url, selector_count: Option<u32>) -> bool {
        let url_ok = self.url.as_ref().is_none_or(|g| g.matches(url));
        let selector_ok = self.selector.is_none() || selector_count.is_some_and(|n| n > 0);
        url_ok && selector_ok
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanSteps {
    Explicit(Vec<PlanStep>),
    Heuristic,
}

/// A recipe ready to run. Built only from a recipe the shared strict parser
/// accepted, so every rule the server checked holds here too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipePlan {
    pub steps: PlanSteps,
    pub success: PlanCondition,
    pub failure: Option<PlanCondition>,
    pub timeout: Duration,
    pub pause_for_operator: Vec<PauseReason>,
    /// Which credential parts an explicit recipe must receive.
    pub needs_username: bool,
    pub needs_password: bool,
    pub needs_totp: bool,
}

impl RecipePlan {
    pub fn from_recipe(recipe: &WebLoginRecipe) -> Result<Self, String> {
        let needs = recipe.needs();
        let steps = match &recipe.steps {
            RecipeSteps::Heuristic => PlanSteps::Heuristic,
            RecipeSteps::Explicit(list) => PlanSteps::Explicit(
                list.iter()
                    .map(|s| {
                        Ok(PlanStep {
                            when_url: UrlGlob::compile(&s.when_url)?,
                            actions: s
                                .actions
                                .iter()
                                .map(|a| match a {
                                    RecipeAction::Fill { selector, value } => PlanAction {
                                        kind: ActionKind::Fill,
                                        selector: selector.clone(),
                                        value: Some(value.clone()),
                                    },
                                    RecipeAction::Click { selector } => {
                                        PlanAction { kind: ActionKind::Click, selector: selector.clone(), value: None }
                                    }
                                    RecipeAction::Submit { selector } => {
                                        PlanAction { kind: ActionKind::Submit, selector: selector.clone(), value: None }
                                    }
                                    RecipeAction::Wait { selector } => {
                                        PlanAction { kind: ActionKind::Wait, selector: selector.clone(), value: None }
                                    }
                                })
                                .collect(),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            ),
        };
        Ok(Self {
            steps,
            success: PlanCondition::compile(&recipe.success_when)?,
            failure: recipe.failure_when.as_ref().map(PlanCondition::compile).transpose()?,
            timeout: Duration::from_secs(recipe.timeout_secs),
            pause_for_operator: recipe.pause_for_operator.clone(),
            needs_username: !needs.heuristic && needs.username,
            needs_password: !needs.heuristic && needs.password,
            needs_totp: !needs.heuristic && needs.totp,
        })
    }

    pub fn is_heuristic(&self) -> bool {
        matches!(self.steps, PlanSteps::Heuristic)
    }

    pub fn step_count(&self) -> usize {
        match &self.steps {
            PlanSteps::Explicit(s) => s.len(),
            PlanSteps::Heuristic => 1,
        }
    }

    /// Whether the outcome judges from more than the URL — then the engine
    /// has to probe the page.
    pub fn has_selector_condition(&self) -> bool {
        self.success.selector.is_some() || self.failure.as_ref().is_some_and(|f| f.selector.is_some())
    }

    pub fn success_selector(&self) -> Option<&str> {
        self.success.selector.as_deref()
    }

    pub fn failure_selector(&self) -> Option<&str> {
        self.failure.as_ref().and_then(|f| f.selector.as_deref())
    }

    /// Operator-facing wait text for the title while the recipe waits on a
    /// page it has no step for.
    pub fn waiting_text(&self) -> &'static str {
        let captcha = self.pause_for_operator.contains(&PauseReason::Captcha);
        let push = self.pause_for_operator.contains(&PauseReason::PushMfa);
        match (captcha, push) {
            (true, true) => "waiting for you: solve the CAPTCHA or approve the sign-in",
            (true, false) => "waiting for you: solve the CAPTCHA",
            (false, true) => "waiting for you: approve the sign-in on your device",
            (false, false) => "signing in…",
        }
    }
}

/// The step to run on `url`: the lowest-numbered step not yet run whose
/// `when_url` matches. A step runs at most once, steps run in order, and a
/// later step may be reached without an earlier optional one — but never a
/// step behind `next`, so a login that bounces back to its first page is not
/// refilled.
pub fn select_step(steps: &[PlanStep], next: usize, url: &Url) -> Option<usize> {
    (next..steps.len()).find(|&i| steps[i].when_url.matches(url))
}

// ── Outcomes ───────────────────────────────────────────────────────

/// What `v2/connect/web/result` records. `Aborted` carries a fixed check name
/// (`[a-z0-9_]{1,32}`; every name the host can produce is a `&'static str`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Timeout,
    Aborted(&'static str),
}

impl Outcome {
    pub fn wire(&self) -> String {
        match self {
            Self::Success => "success".into(),
            Self::Failure => "failure".into(),
            Self::Timeout => "timeout".into(),
            Self::Aborted(check) => format!("aborted:{check}"),
        }
    }

    /// The window-title text for this outcome.
    pub fn title_text(&self) -> String {
        match self {
            Self::Success => "signed in".into(),
            Self::Failure => "sign-in failed".into(),
            Self::Timeout => "sign-in timed out".into(),
            Self::Aborted(check) => format!("sign-in stopped ({})", check.replace('_', " ")),
        }
    }
}

/// Every `aborted:<check>` name the host emits that is not an
/// [`ActionStatus`](super::web_script::ActionStatus) mapping — kept so a
/// test can hold each to the server's `[a-z0-9_]{1,32}` rule.
#[cfg(test)]
pub const HOST_ABORT_CHECKS: &[&str] = &[
    "origin",
    "navigated",
    "credential_missing",
    "totp_expired",
    "totp_refresh",
    "script_no_result",
    "probe_invalid",
    "window_closed",
    "window_build",
    "session_closed",
    "session_dropped",
    "app_exit",
    "policy_violation",
    "bundle_invalid",
    "bundle_mismatch",
    "fill_scope",
    "heuristic_mismatch",
    "registry_conflict",
];

/// The outcome once failure / success conditions have been probed. Failure is
/// checked first, so a page matching both is a failure.
pub fn judge(plan: &RecipePlan, url: &Url, success_count: Option<u32>, failure_count: Option<u32>) -> Option<Outcome> {
    if plan.failure.as_ref().is_some_and(|f| f.met(url, failure_count)) {
        return Some(Outcome::Failure);
    }
    if plan.success.met(url, success_count) {
        return Some(Outcome::Success);
    }
    None
}

/// The outcome when the deadline passes in the middle of an action: the last
/// transient check that kept it from running (`aborted:not_visible` for a
/// field that never became visible), or a plain timeout for a `wait` or for
/// a page that was still navigating.
pub fn deadline_outcome(kind: ActionKind, last: Option<super::web_script::ActionStatus>) -> Outcome {
    use super::web_script::ActionStatus;
    match (kind, last) {
        (ActionKind::Wait, _) | (_, None) | (_, Some(ActionStatus::Origin)) => Outcome::Timeout,
        (_, Some(s)) => Outcome::Aborted(s.abort_check()),
    }
}

// ── TOTP ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpDecision {
    /// The bundle's code is still inside its window.
    UseCurrent,
    /// Ask `v2/connect/web/totp` for a fresh code for this step.
    Refresh(u32),
    /// The code has expired and this step has no refresh left; filling it
    /// would only spend a login attempt.
    Expired,
}

/// Decide what a `totp` fill at `step` uses. `refreshable` is the server's
/// `totp_refresh_steps` (the steps that still have their one refresh).
pub fn totp_decision(now: DateTime<Utc>, valid_until: DateTime<Utc>, step: u32, refreshable: &[u32]) -> TotpDecision {
    if now < valid_until {
        TotpDecision::UseCurrent
    } else if refreshable.contains(&step) {
        TotpDecision::Refresh(step)
    } else {
        TotpDecision::Expired
    }
}

// ── The launch bundle ──────────────────────────────────────────────

/// A TOTP code and the end of its validity window (server clock).
pub struct TotpCode {
    pub code: Zeroizing<String>,
    pub valid_until: DateTime<Utc>,
}

/// A `v2/connect/web/totp` answer: the fresh code and the steps that still
/// have their one refresh.
pub struct RefreshedTotp {
    pub code: TotpCode,
    pub remaining_steps: Vec<u32>,
}

/// The released credential, only the parts the recipe fills. Every value is
/// in a `Zeroizing` buffer and dropped with this struct.
#[derive(Default)]
pub struct LaunchCredential {
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
    pub totp: Option<TotpCode>,
}

impl fmt::Debug for LaunchCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchCredential")
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("totp", &self.totp.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl LaunchCredential {
    /// The value a fill writes: a credential part, or a recipe literal.
    pub fn value<'a>(&'a self, v: &'a FillValue) -> Option<&'a str> {
        match v {
            FillValue::Username => self.username.as_deref().map(String::as_str),
            FillValue::Password => self.password.as_deref().map(String::as_str),
            FillValue::Totp => self.totp.as_ref().map(|t| t.code.as_str()),
            FillValue::Literal(text) => Some(text.as_str()),
        }
    }
}

/// `fill_scope` as the server returned it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFillScope {
    pub start_url: String,
    pub origins: Vec<String>,
    pub allow_insecure_http: bool,
}

/// The parsed `v2/connect/web/launch` response, minus the `launch_id`
/// (which the caller takes first, so even a bundle that fails to parse can
/// be reported and closed).
pub struct LaunchBundle {
    pub resource: String,
    pub profile_id: String,
    pub login_mode: String,
    pub exposure: String,
    pub recipe_hash: String,
    pub heuristic: bool,
    pub fill_scope: ServerFillScope,
    pub credential_source: String,
    pub credential: LaunchCredential,
    pub totp_refresh_steps: Vec<u32>,
    pub mfa_method: Option<String>,
}

fn scrub(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::Object(m) => m.values_mut().for_each(scrub),
        _ => {}
    }
}

/// Scrub every string left in a response map (credential leftovers on an
/// error path).
pub fn scrub_map(m: &mut Map<String, Value>) {
    m.values_mut().for_each(scrub);
}

fn take_string(m: &mut Map<String, Value>, key: &str) -> Result<String, String> {
    match m.remove(key) {
        Some(Value::String(s)) => Ok(s),
        Some(mut other) => {
            scrub(&mut other);
            Err(format!("`{key}` is not a string"))
        }
        None => Err(format!("`{key}` is missing")),
    }
}

/// Take the `launch_id` out of the response. Checked for shape only; it is a
/// bearer handle and is never logged.
pub fn take_launch_id(data: &mut Map<String, Value>) -> Result<Zeroizing<String>, String> {
    let id = Zeroizing::new(take_string(data, "launch_id")?);
    let ok = (16..=256).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return Err("`launch_id` is not a base64url handle".into());
    }
    Ok(id)
}

fn parse_credential(v: Option<Value>) -> Result<LaunchCredential, String> {
    let mut m = match v {
        Some(Value::Object(m)) => m,
        Some(mut other) => {
            scrub(&mut other);
            return Err("`credential` is not an object".into());
        }
        None => return Err("`credential` is missing".into()),
    };
    let mut cred = LaunchCredential::default();
    let result = (|| {
        for key in m.keys() {
            if !matches!(key.as_str(), "username" | "password" | "totp" | "totp_valid_until") {
                return Err(format!("`credential.{key}` is not a field this host fills"));
            }
        }
        if m.contains_key("username") {
            cred.username = Some(Zeroizing::new(take_string(&mut m, "username")?));
        }
        if m.contains_key("password") {
            cred.password = Some(Zeroizing::new(take_string(&mut m, "password")?));
        }
        match (m.contains_key("totp"), m.contains_key("totp_valid_until")) {
            (false, false) => {}
            (true, true) => {
                let code = Zeroizing::new(take_string(&mut m, "totp")?);
                let until = take_string(&mut m, "totp_valid_until")?;
                let valid_until = DateTime::parse_from_rfc3339(&until)
                    .map_err(|_| "`credential.totp_valid_until` is not an RFC 3339 time".to_string())?
                    .with_timezone(&Utc);
                cred.totp = Some(TotpCode { code, valid_until });
            }
            _ => return Err("`credential.totp` and `totp_valid_until` come together".into()),
        }
        Ok(())
    })();
    scrub_map(&mut m);
    result.map(|()| cred)
}

/// Strictly parse a launch bundle (after [`take_launch_id`]). Takes the map by
/// value so credential strings move into `Zeroizing` buffers rather than
/// being copied; anything left over is scrubbed.
pub fn parse_bundle(mut data: Map<String, Value>) -> Result<LaunchBundle, String> {
    let result = (|| {
        let credential = parse_credential(data.remove("credential"))?;
        let fill_scope: ServerFillScope = serde_json::from_value(data.remove("fill_scope").unwrap_or(Value::Null))
            .map_err(|e| format!("`fill_scope`: {e}"))?;
        let heuristic = data.get("heuristic").and_then(Value::as_bool).ok_or("`heuristic` is not a boolean")?;
        let totp_refresh_steps = match data.remove("totp_refresh_steps") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()))
                .collect::<Option<Vec<u32>>>()
                .ok_or("`totp_refresh_steps` must list step indexes")?,
            _ => return Err("`totp_refresh_steps` is not a list".to_string()),
        };
        let mfa_method = match data.remove("mfa_method") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s),
            Some(_) => return Err("`mfa_method` is not a string".into()),
        };
        Ok(LaunchBundle {
            resource: take_string(&mut data, "resource")?,
            profile_id: take_string(&mut data, "profile_id")?,
            login_mode: take_string(&mut data, "login_mode")?,
            exposure: take_string(&mut data, "exposure")?,
            recipe_hash: take_string(&mut data, "recipe_hash")?,
            heuristic,
            fill_scope,
            credential_source: take_string(&mut data, "credential_source")?,
            credential,
            totp_refresh_steps,
            mfa_method,
        })
    })();
    scrub_map(&mut data);
    result
}

/// What the host expects of the bundle, from its own parse of the profile.
pub struct BundleExpectation<'a> {
    pub resource: &'a str,
    pub profile_id: &'a str,
    pub recipe_hash: &'a str,
    pub plan: &'a RecipePlan,
}

/// Cross-check the bundle against the profile the host is about to run.
/// `Err` carries the `aborted:<check>` name the launch is closed with.
pub fn check_bundle(bundle: &LaunchBundle, expect: &BundleExpectation<'_>) -> Result<(), &'static str> {
    if bundle.resource != expect.resource
        || bundle.profile_id != expect.profile_id
        || bundle.login_mode != "form"
        || bundle.exposure != "dom"
        || bundle.recipe_hash != expect.recipe_hash
    {
        return Err("bundle_mismatch");
    }
    // Heuristic filling runs only when the server says policy allows it for
    // this launch, and only for a recipe that asks for it.
    if bundle.heuristic != expect.plan.is_heuristic() {
        return Err("heuristic_mismatch");
    }
    let c = &bundle.credential;
    let p = expect.plan;
    if (p.needs_username && c.username.is_none())
        || (p.needs_password && c.password.is_none())
        || (p.needs_totp && c.totp.is_none())
    {
        return Err("credential_missing");
    }
    Ok(())
}

// ── Fill scope ─────────────────────────────────────────────────────

/// The scope the window navigates and fills in.
#[derive(Debug, Clone)]
pub struct EffectiveScope {
    pub start_url: Url,
    pub origins: OriginSet,
    /// `origins` as `scheme://host[:port]` strings — the routine's
    /// form-action allow-list. Same format as `location.origin`.
    pub origin_keys: Vec<String>,
    pub allow_insecure_http: bool,
    /// Origins the host's copy of the profile allowed that the server's
    /// scope does not (logged; never used).
    pub narrowed_out: Vec<String>,
}

impl EffectiveScope {
    /// An `open`-mode session or a dry run: the scope is the profile's own.
    pub fn local(start_url: Url, origins: OriginSet, allow_insecure_http: bool) -> Self {
        let origin_keys = origins.iter().map(ToString::to_string).collect();
        Self { start_url, origins, origin_keys, allow_insecure_http, narrowed_out: Vec::new() }
    }
}

/// Reconcile the server's `fill_scope` with the host's parse of the profile.
///
/// The server's scope is authoritative: the window starts at its
/// `start_url` and navigates / fills only on its `origins`. It may only
/// *narrow* the host's view — an origin the host's copy does not allow, or
/// `allow_insecure_http` the host's copy does not set, means the two
/// disagree about the profile in a way that would widen what this window
/// does, and the launch is refused rather than resolved either way.
pub fn reconcile_fill_scope(
    local: &OriginSet,
    local_allow_insecure_http: bool,
    scope: &ServerFillScope,
) -> Result<EffectiveScope, String> {
    if scope.allow_insecure_http && !local_allow_insecure_http {
        return Err("the server's fill scope allows plain http, which this profile does not".into());
    }
    let http = scope.allow_insecure_http;
    if scope.origins.is_empty() {
        return Err("the server's fill scope names no origin".into());
    }
    let mut parsed = Vec::with_capacity(scope.origins.len());
    for raw in &scope.origins {
        let o = WebOrigin::parse_config(raw, http).map_err(|e| format!("fill scope origin: {e}"))?;
        if !local.contains(&o) {
            return Err(format!("the server's fill scope includes {o}, which this profile does not allow"));
        }
        parsed.push(o);
    }
    let start_url = Url::parse(scope.start_url.trim()).map_err(|e| format!("fill scope start_url: {e}"))?;
    if !start_url.username().is_empty() || start_url.password().is_some() {
        return Err("fill scope start_url carries userinfo".into());
    }
    let start_origin = WebOrigin::validated(&start_url, http).map_err(|e| format!("fill scope start_url: {e}"))?;
    if parsed.first() != Some(&start_origin) {
        return Err("the fill scope's start URL is not on its first origin".into());
    }
    let origins = OriginSet::new(parsed);
    let narrowed_out = local.iter().filter(|o| !origins.contains(o)).map(ToString::to_string).collect();
    let origin_keys = origins.iter().map(ToString::to_string).collect();
    Ok(EffectiveScope { start_url, origins, origin_keys, allow_insecure_http: http, narrowed_out })
}

// ── Heuristic mode ─────────────────────────────────────────────────

/// Which values the bundle carries (heuristic mode fills whichever it has).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CredentialHas {
    pub username: bool,
    pub password: bool,
    pub totp: bool,
}

impl CredentialHas {
    pub fn of(c: &LaunchCredential) -> Self {
        Self { username: c.username.is_some(), password: c.password.is_some(), totp: c.totp.is_some() }
    }
}

/// Plan heuristic step 0 from the candidate counts.
///
/// `Ok(None)` while there is nothing to fill yet (keep waiting). More than
/// one candidate for a value aborts (`ambiguous_match`): heuristics never
/// guess between fields. `current-password` wins over `type=password`. The
/// form of the last filled field is submitted.
pub fn plan_heuristic(scan: &ScanCounts, has: CredentialHas) -> Result<Option<Vec<PlanAction>>, &'static str> {
    let mut fills: Vec<(&'static str, FillValue)> = Vec::new();
    let pick = |n: u32| -> Result<bool, &'static str> {
        match n {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("ambiguous_match"),
        }
    };
    if has.username && pick(scan.username)? {
        fills.push((HEURISTIC_SELECTORS.username, FillValue::Username));
    }
    if has.password {
        if scan.current_password > 0 {
            if pick(scan.current_password)? {
                fills.push((HEURISTIC_SELECTORS.current_password, FillValue::Password));
            }
        } else if pick(scan.password)? {
            fills.push((HEURISTIC_SELECTORS.password, FillValue::Password));
        }
    }
    if has.totp && pick(scan.otp)? {
        fills.push((HEURISTIC_SELECTORS.otp, FillValue::Totp));
    }
    let Some(&(last_selector, _)) = fills.last() else {
        return Ok(None);
    };
    let mut actions: Vec<PlanAction> = fills
        .into_iter()
        .map(|(selector, value)| PlanAction { kind: ActionKind::Fill, selector: selector.into(), value: Some(value) })
        .collect();
    actions.push(PlanAction { kind: ActionKind::Submit, selector: last_selector.into(), value: None });
    Ok(Some(actions))
}

// ── Outcome event ──────────────────────────────────────────────────

/// Name of the event the host sends the main window when a form session's
/// sign-in ends.
pub const WEB_SESSION_OUTCOME_EVENT: &str = "web-session-outcome";

/// The payload of [`WEB_SESSION_OUTCOME_EVENT`]: names, the session token
/// and the outcome only — never a credential, a TOTP code, the `launch_id`
/// or any URL.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WebSessionOutcomeEvent {
    pub token: String,
    pub resource: String,
    pub profile_id: String,
    /// `success` | `failure` | `timeout` | `aborted:<check>`.
    pub outcome: String,
    pub step: Option<u32>,
}

pub fn outcome_event(
    token: &str,
    resource: &str,
    profile_id: &str,
    outcome: &Outcome,
    step: Option<u32>,
) -> WebSessionOutcomeEvent {
    WebSessionOutcomeEvent {
        token: token.to_string(),
        resource: resource.to_string(),
        profile_id: profile_id.to_string(),
        outcome: outcome.wire(),
        step,
    }
}

// ── Title ──────────────────────────────────────────────────────────

/// The host-owned window title: `<resource> — <origin>`, then an optional
/// navigation notice and the login state. Built only from host-observed
/// origins and host-chosen text, never from the page.
pub fn session_title(resource: &str, origin: &str, notice: Option<&str>, login: Option<&str>) -> String {
    let mut t = format!("{resource} — {origin}");
    for part in [notice, login].into_iter().flatten() {
        t.push_str(" — ");
        t.push_str(part);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::web_script::ActionStatus;
    use bastion_vault::modules::resource::connect_web::recipe::recipe_hash;
    use serde_json::json;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn origin(s: &str) -> WebOrigin {
        WebOrigin::parse_config(s, true).unwrap()
    }

    fn recipe(v: Value) -> RecipePlan {
        RecipePlan::from_recipe(&WebLoginRecipe::parse(&v).unwrap()).unwrap()
    }

    fn two_page() -> Value {
        json!({
            "version": 1,
            "steps": [
                { "when_url": "https://fw01.example.com/login*", "actions": [
                    { "fill": "input[name=username]", "value": "username" },
                    { "fill": "input[name=secretkey]", "value": "password" },
                    { "click": "button#login_button" } ] },
                { "when_url": "https://fw01.example.com/login/2fa*", "actions": [
                    { "fill": "input[autocomplete=one-time-code]", "value": "totp" },
                    { "submit": "form" } ] }
            ],
            "success_when": { "url": "https://fw01.example.com/ng/*" },
            "failure_when": { "selector": ".error-message" },
            "timeout_secs": 30,
            "pause_for_operator": ["captcha"]
        })
    }

    // ── Globs ──────────────────────────────────────────────────────

    #[test]
    fn glob_semantics() {
        assert!(glob_match("/login*", "/login"));
        assert!(glob_match("/login*", "/login?next=%2F"));
        assert!(glob_match("/login*", "/login/2fa"));
        assert!(!glob_match("/login", "/login?x=1"));
        assert!(glob_match("/*/admin", "/a/b/admin"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("/a*b", "/acd"));
        // Pathological input stays fast.
        let long = "a".repeat(5000);
        assert!(!glob_match("*a*a*a*a*a*b", &long));
    }

    #[test]
    fn url_globs_match_the_origin_exactly() {
        let g = UrlGlob::compile("https://fw01.example.com/login*").unwrap();
        assert!(g.matches(&url("https://fw01.example.com/login")));
        assert!(g.matches(&url("https://FW01.example.com:443/login?x")));
        assert!(!g.matches(&url("http://fw01.example.com/login")));
        assert!(!g.matches(&url("https://fw01.example.com:8443/login")));
        assert!(!g.matches(&url("https://evil.example/https://fw01.example.com/login")));
        assert!(!g.matches(&url("https://fw01.example.com.evil.example/login")));
        assert!(!g.matches(&url("https://fw01.example.com@evil.example/login")));
        // A bare origin addresses `/` only.
        let root = UrlGlob::compile("https://a.example").unwrap();
        assert!(root.matches(&url("https://a.example/")));
        assert!(!root.matches(&url("https://a.example/x")));
        for bad in ["https://*.example.com/", "https://u@a.example/", "fw01/login", "https://a.example/ x"] {
            assert!(UrlGlob::compile(bad).is_err(), "{bad}");
        }
    }

    // ── Planning ───────────────────────────────────────────────────

    #[test]
    fn a_recipe_plans_into_ordered_steps() {
        let plan = recipe(two_page());
        let PlanSteps::Explicit(steps) = &plan.steps else { panic!() };
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].actions[0].expect(), Some(FieldExpect::Username));
        assert_eq!(steps[0].actions[2].kind, ActionKind::Click);
        assert_eq!(steps[1].actions[1].kind, ActionKind::Submit);
        assert!(plan.needs_username && plan.needs_password && plan.needs_totp);
        assert_eq!(plan.timeout, Duration::from_secs(30));
        assert_eq!(plan.waiting_text(), "waiting for you: solve the CAPTCHA");
        assert!(plan.has_selector_condition());
    }

    #[test]
    fn step_selection_runs_each_step_once_in_order() {
        let plan = recipe(two_page());
        let PlanSteps::Explicit(steps) = &plan.steps else { panic!() };
        let login = url("https://fw01.example.com/login");
        let twofa = url("https://fw01.example.com/login/2fa");
        assert_eq!(select_step(steps, 0, &login), Some(0));
        // Step 0's glob also matches the 2FA page; before it ran, it wins.
        assert_eq!(select_step(steps, 0, &twofa), Some(0));
        assert_eq!(select_step(steps, 1, &twofa), Some(1));
        // Bounced back to the first page after step 0: never refilled.
        assert_eq!(select_step(steps, 1, &login), None);
        assert_eq!(select_step(steps, 2, &twofa), None);
        assert_eq!(select_step(steps, 0, &url("https://other.example/login")), None);
    }

    #[test]
    fn heuristic_recipes_plan_as_heuristic() {
        let plan =
            recipe(json!({ "version": 1, "steps": "auto", "success_when": { "url": "https://a.example/home*" } }));
        assert!(plan.is_heuristic());
        assert_eq!(plan.step_count(), 1);
        // Heuristic mode takes whichever values the source has.
        assert!(!plan.needs_username && !plan.needs_password && !plan.needs_totp);
    }

    // ── Outcomes ───────────────────────────────────────────────────

    #[test]
    fn outcomes_judge_failure_before_success() {
        let plan = recipe(two_page());
        let ng = url("https://fw01.example.com/ng/dashboard");
        let login = url("https://fw01.example.com/login");
        assert_eq!(judge(&plan, &ng, None, Some(0)), Some(Outcome::Success));
        assert_eq!(judge(&plan, &ng, None, Some(1)), Some(Outcome::Failure));
        assert_eq!(judge(&plan, &login, None, Some(1)), Some(Outcome::Failure));
        assert_eq!(judge(&plan, &login, None, Some(0)), None);
        // An unprobed selector never counts as present.
        assert_eq!(judge(&plan, &login, None, None), None);
    }

    #[test]
    fn a_condition_with_url_and_selector_needs_both() {
        let c = PlanCondition {
            url: Some(UrlGlob::compile("https://a.example/home*").unwrap()),
            selector: Some("#menu".into()),
        };
        assert!(c.met(&url("https://a.example/home"), Some(1)));
        assert!(!c.met(&url("https://a.example/home"), Some(0)));
        assert!(!c.met(&url("https://a.example/login"), Some(1)));
    }

    #[test]
    fn outcome_wire_strings_and_check_names_are_what_the_server_accepts() {
        assert_eq!(Outcome::Success.wire(), "success");
        assert_eq!(Outcome::Failure.wire(), "failure");
        assert_eq!(Outcome::Timeout.wire(), "timeout");
        assert_eq!(Outcome::Aborted("form_action").wire(), "aborted:form_action");
        for check in HOST_ABORT_CHECKS {
            assert!(
                (1..=32).contains(&check.len())
                    && check.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{check}"
            );
        }
    }

    #[test]
    fn the_deadline_reports_the_check_that_kept_an_action_from_running() {
        assert_eq!(deadline_outcome(ActionKind::Fill, None), Outcome::Timeout);
        assert_eq!(deadline_outcome(ActionKind::Fill, Some(ActionStatus::NotVisible)), Outcome::Aborted("not_visible"));
        assert_eq!(deadline_outcome(ActionKind::Click, Some(ActionStatus::Occluded)), Outcome::Aborted("occluded"));
        assert_eq!(deadline_outcome(ActionKind::Fill, Some(ActionStatus::NoMatch)), Outcome::Aborted("no_match"));
        assert_eq!(deadline_outcome(ActionKind::Wait, Some(ActionStatus::NoMatch)), Outcome::Timeout);
        assert_eq!(deadline_outcome(ActionKind::Fill, Some(ActionStatus::Origin)), Outcome::Timeout);
    }

    // ── TOTP ───────────────────────────────────────────────────────

    #[test]
    fn totp_refresh_step_selection() {
        let t0 = DateTime::parse_from_rfc3339("2026-10-05T12:00:00Z").unwrap().with_timezone(&Utc);
        let until = t0 + chrono::Duration::seconds(30);
        assert_eq!(totp_decision(t0, until, 1, &[1]), TotpDecision::UseCurrent);
        assert_eq!(totp_decision(until, until, 1, &[1]), TotpDecision::Refresh(1));
        assert_eq!(totp_decision(until + chrono::Duration::seconds(5), until, 1, &[1, 3]), TotpDecision::Refresh(1));
        // Already refreshed (the server no longer lists it), or not a TOTP step.
        assert_eq!(totp_decision(until, until, 1, &[]), TotpDecision::Expired);
        assert_eq!(totp_decision(until, until, 2, &[1]), TotpDecision::Expired);
    }

    // ── Bundle ─────────────────────────────────────────────────────

    fn bundle_json() -> Map<String, Value> {
        let v = json!({
            "launch_id": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde",
            "expires_at": "2026-10-05T12:01:00Z",
            "resource": "fw01", "profile_id": "p_web",
            "login_mode": "form", "exposure": "dom", "exposure_cap": "dom",
            "recipe_hash": "sha256:abc", "heuristic": false,
            "fill_scope": { "start_url": "https://fw01.example.com/login",
                            "origins": ["https://fw01.example.com"], "allow_insecure_http": false },
            "credential_source": "secret",
            "credential": { "username": "admin", "password": "pw\"</script>", "totp": "123456",
                            "totp_valid_until": "2026-10-05T12:00:30Z" },
            "totp_refresh_steps": [1],
            "mfa_method": "totp"
        });
        v.as_object().unwrap().clone()
    }

    #[test]
    fn a_bundle_parses_and_holds_the_credential() {
        let mut data = bundle_json();
        let id = take_launch_id(&mut data).unwrap();
        assert_eq!(id.len(), 43);
        let b = parse_bundle(data).unwrap();
        assert_eq!(b.credential.username.as_deref().map(String::as_str), Some("admin"));
        assert_eq!(b.credential.password.as_deref().map(String::as_str), Some("pw\"</script>"));
        assert_eq!(b.credential.totp.as_ref().unwrap().code.as_str(), "123456");
        assert_eq!(b.totp_refresh_steps, vec![1]);
        assert_eq!(b.fill_scope.origins, vec!["https://fw01.example.com".to_string()]);
        // Debug never prints a value.
        let dbg = format!("{:?}", b.credential);
        assert!(!dbg.contains("admin") && !dbg.contains("123456") && dbg.contains("redacted"), "{dbg}");
    }

    #[test]
    fn malformed_bundles_are_refused() {
        let mut d = bundle_json();
        d.insert("launch_id".into(), json!("short"));
        assert!(take_launch_id(&mut d).is_err());
        let mut d = bundle_json();
        d.insert("launch_id".into(), json!("has spaces in it which is not base64url at all"));
        assert!(take_launch_id(&mut d).is_err());

        let cases: Vec<Box<dyn Fn(&mut Map<String, Value>)>> = vec![
            Box::new(|d| {
                d["credential"]["pin"] = json!("1234");
            }),
            Box::new(|d| {
                d["credential"].as_object_mut().unwrap().remove("totp_valid_until");
            }),
            Box::new(|d| {
                d["credential"]["totp_valid_until"] = json!("soon");
            }),
            Box::new(|d| {
                d["fill_scope"]["frame_origin"] = json!("https://x.example");
            }),
            Box::new(|d| {
                d.remove("fill_scope");
            }),
            Box::new(|d| {
                d["heuristic"] = json!("false");
            }),
            Box::new(|d| {
                d["totp_refresh_steps"] = json!([-1]);
            }),
            Box::new(|d| {
                d["credential"]["password"] = json!(5);
            }),
        ];
        for (i, mutate) in cases.iter().enumerate() {
            let mut d = bundle_json();
            take_launch_id(&mut d).unwrap();
            mutate(&mut d);
            assert!(parse_bundle(d).is_err(), "case {i}");
        }
    }

    #[test]
    fn bundle_checks_against_the_profile() {
        let plan = recipe(two_page());
        let hash = recipe_hash(&two_page()).unwrap();
        let mut d = bundle_json();
        take_launch_id(&mut d).unwrap();
        d["recipe_hash"] = json!(hash);
        let b = parse_bundle(d).unwrap();
        let expect = BundleExpectation { resource: "fw01", profile_id: "p_web", recipe_hash: &hash, plan: &plan };
        assert_eq!(check_bundle(&b, &expect), Ok(()));
        let other = BundleExpectation { recipe_hash: "sha256:other", ..expect };
        assert_eq!(check_bundle(&b, &other), Err("bundle_mismatch"));
        let other = BundleExpectation { resource: "fw02", ..expect };
        assert_eq!(check_bundle(&b, &other), Err("bundle_mismatch"));

        // The server saying "heuristic" for an explicit recipe (or the
        // reverse) is never run.
        let mut d = bundle_json();
        take_launch_id(&mut d).unwrap();
        d["recipe_hash"] = json!(hash);
        d["heuristic"] = json!(true);
        assert_eq!(check_bundle(&parse_bundle(d).unwrap(), &expect), Err("heuristic_mismatch"));

        // A recipe that fills TOTP needs the code.
        let mut d = bundle_json();
        take_launch_id(&mut d).unwrap();
        d["recipe_hash"] = json!(hash);
        let c = d["credential"].as_object_mut().unwrap();
        c.remove("totp");
        c.remove("totp_valid_until");
        assert_eq!(check_bundle(&parse_bundle(d).unwrap(), &expect), Err("credential_missing"));
    }

    // ── Fill scope ─────────────────────────────────────────────────

    fn local_set() -> OriginSet {
        OriginSet::new(vec![origin("https://fw01.example.com"), origin("https://sso.example.com")])
    }

    fn scope(start: &str, origins: &[&str], http: bool) -> ServerFillScope {
        ServerFillScope {
            start_url: start.into(),
            origins: origins.iter().map(|s| s.to_string()).collect(),
            allow_insecure_http: http,
        }
    }

    #[test]
    fn the_server_scope_may_narrow() {
        let s = reconcile_fill_scope(
            &local_set(),
            false,
            &scope("https://fw01.example.com/login", &["https://fw01.example.com"], false),
        )
        .unwrap();
        assert_eq!(s.origin_keys, vec!["https://fw01.example.com".to_string()]);
        assert!(!s.origins.contains(&origin("https://sso.example.com")));
        assert_eq!(s.narrowed_out, vec!["https://sso.example.com".to_string()]);
        assert_eq!(s.start_url.as_str(), "https://fw01.example.com/login");
        // The server's start URL wins when it is on the scope.
        let s = reconcile_fill_scope(
            &local_set(),
            false,
            &scope("https://fw01.example.com/other", &["https://fw01.example.com"], false),
        )
        .unwrap();
        assert_eq!(s.start_url.path(), "/other");
        // Insecure http: the server may turn it off, never on.
        let s = reconcile_fill_scope(
            &OriginSet::new(vec![origin("https://fw01.example.com")]),
            true,
            &scope("https://fw01.example.com/", &["https://fw01.example.com"], false),
        )
        .unwrap();
        assert!(!s.allow_insecure_http);
    }

    #[test]
    fn the_server_scope_may_never_widen() {
        let local = local_set();
        for (sc, why) in [
            (scope("https://evil.example/", &["https://evil.example"], false), "foreign origin"),
            (
                scope("https://fw01.example.com/", &["https://fw01.example.com", "https://evil.example"], false),
                "extra origin",
            ),
            (scope("http://fw01.example.com/", &["http://fw01.example.com"], true), "insecure http"),
            (scope("https://fw01.example.com/", &[], false), "empty set"),
            (
                scope("https://sso.example.com/", &["https://fw01.example.com", "https://sso.example.com"], false),
                "start not first",
            ),
            (scope("https://u:p@fw01.example.com/", &["https://fw01.example.com"], false), "userinfo"),
            (scope("https://fw01.example.com/", &["https://fw01.example.com/path"], false), "not an origin"),
            (scope("https://localhost/", &["https://localhost"], false), "vault-local host"),
        ] {
            assert!(reconcile_fill_scope(&local, false, &sc).is_err(), "{why}");
        }
    }

    // ── Heuristics ─────────────────────────────────────────────────

    fn scan(username: u32, current_password: u32, password: u32, otp: u32) -> ScanCounts {
        ScanCounts { username, current_password, password, otp }
    }

    const ALL: CredentialHas = CredentialHas { username: true, password: true, totp: true };

    #[test]
    fn heuristics_fill_what_they_find_and_submit_the_last_form() {
        let a = plan_heuristic(&scan(1, 1, 1, 0), ALL).unwrap().unwrap();
        let sels: Vec<&str> = a.iter().map(|x| x.selector.as_str()).collect();
        assert_eq!(
            sels,
            [HEURISTIC_SELECTORS.username, HEURISTIC_SELECTORS.current_password, HEURISTIC_SELECTORS.current_password]
        );
        assert_eq!(a[2].kind, ActionKind::Submit);
        // `type=password` only when there is no current-password field.
        let a = plan_heuristic(&scan(0, 0, 1, 0), ALL).unwrap().unwrap();
        assert_eq!(a[0].selector, HEURISTIC_SELECTORS.password);
        // Nothing yet: keep waiting.
        assert_eq!(plan_heuristic(&scan(0, 0, 0, 0), ALL), Ok(None));
        // A value the source does not carry is never planned.
        let a =
            plan_heuristic(&scan(1, 0, 1, 1), CredentialHas { username: true, ..Default::default() }).unwrap().unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].value, Some(FillValue::Username));
    }

    #[test]
    fn heuristics_never_guess_between_fields() {
        assert_eq!(plan_heuristic(&scan(2, 0, 1, 0), ALL), Err("ambiguous_match"));
        assert_eq!(plan_heuristic(&scan(0, 0, 2, 0), ALL), Err("ambiguous_match"));
        assert_eq!(plan_heuristic(&scan(0, 2, 1, 0), ALL), Err("ambiguous_match"));
        assert_eq!(plan_heuristic(&scan(0, 0, 0, 3), ALL), Err("ambiguous_match"));
    }

    #[test]
    fn the_outcome_event_carries_names_and_the_outcome_only() {
        let ev = outcome_event("sess_t", "fw01", "p_web", &Outcome::Aborted("form_action"), Some(1));
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            v,
            json!({ "token": "sess_t", "resource": "fw01", "profile_id": "p_web",
                    "outcome": "aborted:form_action", "step": 1 })
        );
        let ev = outcome_event("sess_t", "fw01", "p_web", &Outcome::Success, None);
        assert_eq!(serde_json::to_value(&ev).unwrap()["step"], Value::Null);
        assert_eq!(WEB_SESSION_OUTCOME_EVENT, "web-session-outcome");
    }

    #[test]
    fn the_title_is_host_text_only() {
        assert_eq!(session_title("fw01", "https://fw01.example.com", None, None), "fw01 — https://fw01.example.com");
        assert_eq!(
            session_title("fw01", "https://a.example", Some("blocked: https://evil.example"), Some("signed in")),
            "fw01 — https://a.example — blocked: https://evil.example — signed in"
        );
        assert_eq!(Outcome::Aborted("form_action").title_text(), "sign-in stopped (form action)");
    }
}
