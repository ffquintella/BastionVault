//! The host side of the fixed fill routine
//! (features/web-application-connect.md §5, T96 Phase 2).
//!
//! The routine itself is [`FILL_ROUTINE`] (`web_fill_routine.js`), compiled
//! into the binary. Every call is `(<routine>)(<args>)`, where `<args>` is a
//! [`ScriptCall`] serialised by `serde_json` with [`JsLiteralFormatter`]. No
//! value, selector or URL is ever concatenated into script text: they are
//! string literals inside a JSON object, and JSON is a syntactic subset of
//! JavaScript. The formatter additionally escapes `<`, `>`, `&`, U+2028 and
//! U+2029 so the literal stays inert in any embedding and in engines that
//! predate ES2019's line-terminator change.
//!
//! The routine's reply is the page's word, not the host's: a page that
//! patches DOM prototypes can make it say anything. [`parse_reply`] is
//! therefore strict (unknown fields, versions and statuses are errors), and
//! the engine trusts a reply only to *refuse* or to *proceed with the next
//! host-decided step* — never to widen where a value goes.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The fixed fill routine. A function expression, never evaluated on its own.
pub const FILL_ROUTINE: &str = include_str!("web_fill_routine.js");

/// Which part of the routine runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptOp {
    /// One recipe action (`fill` / `click` / `submit` / `wait`).
    Action,
    /// Presence counts for the success / failure selectors.
    Probe,
    /// Heuristic-mode candidate counts.
    Scan,
    /// Empty every password field (after the outcome).
    Clear,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Fill,
    Click,
    Submit,
    Wait,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fill => "fill",
            Self::Click => "click",
            Self::Submit => "submit",
            Self::Wait => "wait",
        }
    }
}

/// `act` performs the action; `check` runs every check and changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptMode {
    Act,
    Check,
}

/// Which field types a fill may target (the routine's `TYPES` table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldExpect {
    Username,
    Password,
    Totp,
    Literal,
}

/// The fixed heuristic-mode selectors (spec §2: `autocomplete` first, then
/// `type=password`). Host constants, passed to the routine as data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ScanSelectors {
    pub username: &'static str,
    pub current_password: &'static str,
    pub password: &'static str,
    pub otp: &'static str,
}

pub const HEURISTIC_SELECTORS: ScanSelectors = ScanSelectors {
    username: r#"input[autocomplete~="username" i]"#,
    current_password: r#"input[autocomplete~="current-password" i]"#,
    password: r#"input[type="password" i]"#,
    otp: r#"input[autocomplete~="one-time-code" i]"#,
};

/// One call of the fixed routine.
///
/// Deliberately not `Debug` and not `Clone`: `value` can be a credential.
/// Built only through the constructors below, which keep the invariant that
/// a value is present exactly on an `act`-mode `fill`.
#[derive(Serialize)]
pub struct ScriptCall<'a> {
    op: ScriptOp,
    mode: ScriptMode,
    /// The top-frame origin the host observed and checked; the routine
    /// refuses to run anywhere else.
    origin: &'a str,
    /// The fill scope's origins, for the form-action check.
    fill_origins: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<ActionKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect: Option<FieldExpect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    success_selector: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_selector: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan: Option<ScanSelectors>,
}

impl<'a> ScriptCall<'a> {
    fn base(op: ScriptOp, mode: ScriptMode, origin: &'a str, fill_origins: &'a [String]) -> Self {
        Self {
            op,
            mode,
            origin,
            fill_origins,
            kind: None,
            selector: None,
            expect: None,
            value: None,
            success_selector: None,
            failure_selector: None,
            scan: None,
        }
    }

    /// Fill `value` into the single field `selector` names.
    pub fn fill(
        origin: &'a str,
        fill_origins: &'a [String],
        selector: &'a str,
        expect: FieldExpect,
        value: &'a str,
    ) -> Self {
        Self {
            kind: Some(ActionKind::Fill),
            selector: Some(selector),
            expect: Some(expect),
            value: Some(value),
            ..Self::base(ScriptOp::Action, ScriptMode::Act, origin, fill_origins)
        }
    }

    /// Run a fill's checks without a value (the recipe dry run).
    pub fn check_fill(origin: &'a str, fill_origins: &'a [String], selector: &'a str, expect: FieldExpect) -> Self {
        Self {
            kind: Some(ActionKind::Fill),
            selector: Some(selector),
            expect: Some(expect),
            ..Self::base(ScriptOp::Action, ScriptMode::Check, origin, fill_origins)
        }
    }

    /// `click`, `submit` or `wait`. A fill must go through [`Self::fill`]
    /// or [`Self::check_fill`].
    pub fn non_fill(
        kind: ActionKind,
        mode: ScriptMode,
        origin: &'a str,
        fill_origins: &'a [String],
        selector: &'a str,
    ) -> Self {
        debug_assert_ne!(kind, ActionKind::Fill, "fills carry an expectation");
        Self { kind: Some(kind), selector: Some(selector), ..Self::base(ScriptOp::Action, mode, origin, fill_origins) }
    }

    pub fn probe(
        origin: &'a str,
        fill_origins: &'a [String],
        success_selector: Option<&'a str>,
        failure_selector: Option<&'a str>,
    ) -> Self {
        Self {
            success_selector,
            failure_selector,
            ..Self::base(ScriptOp::Probe, ScriptMode::Check, origin, fill_origins)
        }
    }

    pub fn scan(origin: &'a str, fill_origins: &'a [String]) -> Self {
        Self { scan: Some(HEURISTIC_SELECTORS), ..Self::base(ScriptOp::Scan, ScriptMode::Check, origin, fill_origins) }
    }

    pub fn clear(origin: &'a str, fill_origins: &'a [String]) -> Self {
        Self::base(ScriptOp::Clear, ScriptMode::Act, origin, fill_origins)
    }

    // Read-only views for the engine tests' fake page, which records every
    // call to prove where values went.
    #[cfg(test)]
    pub fn op(&self) -> ScriptOp {
        self.op
    }
    #[cfg(test)]
    pub fn mode(&self) -> ScriptMode {
        self.mode
    }
    #[cfg(test)]
    pub fn kind(&self) -> Option<ActionKind> {
        self.kind
    }
    #[cfg(test)]
    pub fn selector(&self) -> Option<&str> {
        self.selector
    }
    #[cfg(test)]
    pub fn expect(&self) -> Option<FieldExpect> {
        self.expect
    }
    #[cfg(test)]
    pub fn origin(&self) -> &str {
        self.origin
    }
    #[cfg(test)]
    pub fn has_value(&self) -> bool {
        self.value.is_some()
    }
    #[cfg(test)]
    pub fn value(&self) -> Option<&str> {
        self.value
    }
}

/// `serde_json`'s compact output, with `<`, `>`, `&`, U+2028 and U+2029
/// written as `\uXXXX` escapes inside strings. Those characters can only
/// occur inside a JSON string, so escaping fragments is enough.
pub struct JsLiteralFormatter;

impl serde_json::ser::Formatter for JsLiteralFormatter {
    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let escape = match c {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            writer.write_all(&fragment.as_bytes()[start..i])?;
            writer.write_all(escape.as_bytes())?;
            start = i + c.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

/// The script text for one call: `(<routine>)(<args>)`.
///
/// Built in one pre-sized, zeroizing buffer so a value is not left behind in
/// a reallocated copy. The webview API takes the `String` by value; what it
/// and the platform do with their copy is outside the host's control.
pub fn render(call: &ScriptCall<'_>) -> Zeroizing<String> {
    let value_len = call.value.map_or(0, str::len);
    let selector_len =
        [call.selector, call.success_selector, call.failure_selector].iter().flatten().map(|s| s.len()).sum::<usize>();
    let origins_len: usize = call.fill_origins.iter().map(|o| o.len() + 3).sum();
    // Worst case every character becomes a six-byte `\uXXXX` escape.
    let capacity = FILL_ROUTINE.len() + 512 + 6 * (value_len + selector_len + origins_len + call.origin.len());
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(capacity));
    buf.push(b'(');
    buf.extend_from_slice(FILL_ROUTINE.trim_end().as_bytes());
    buf.extend_from_slice(b")(");
    {
        let mut ser = serde_json::Serializer::with_formatter(&mut *buf, JsLiteralFormatter);
        // Writing string-keyed structs into a Vec cannot fail.
        call.serialize(&mut ser).expect("serialising a ScriptCall into memory cannot fail");
    }
    buf.push(b')');
    let bytes = std::mem::take(&mut *buf);
    // Every byte came from a `&str` or an ASCII literal.
    Zeroizing::new(String::from_utf8(bytes).expect("rendered script is UTF-8"))
}

/// What the routine says happened to one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionStatus {
    Ok,
    NoMatch,
    Ambiguous,
    NotInput,
    WrongType,
    NotVisible,
    Occluded,
    Disabled,
    FormAction,
    NoForm,
    Unsupported,
    BadSelector,
    /// The top frame is on another origin than the host expected (a
    /// navigation in flight).
    Origin,
    NotTop,
    ScriptError,
}

impl ActionStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "ok" => Self::Ok,
            "no_match" => Self::NoMatch,
            "ambiguous" => Self::Ambiguous,
            "not_input" => Self::NotInput,
            "wrong_type" => Self::WrongType,
            "not_visible" => Self::NotVisible,
            "occluded" => Self::Occluded,
            "disabled" => Self::Disabled,
            "form_action" => Self::FormAction,
            "no_form" => Self::NoForm,
            "unsupported" => Self::Unsupported,
            "bad_selector" => Self::BadSelector,
            "origin" => Self::Origin,
            "not_top" => Self::NotTop,
            "script_error" => Self::ScriptError,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoMatch => "no_match",
            Self::Ambiguous => "ambiguous",
            Self::NotInput => "not_input",
            Self::WrongType => "wrong_type",
            Self::NotVisible => "not_visible",
            Self::Occluded => "occluded",
            Self::Disabled => "disabled",
            Self::FormAction => "form_action",
            Self::NoForm => "no_form",
            Self::Unsupported => "unsupported",
            Self::BadSelector => "bad_selector",
            Self::Origin => "origin",
            Self::NotTop => "not_top",
            Self::ScriptError => "script_error",
        }
    }

    /// A state the page can leave by itself — a form still rendering, a fade
    /// in, a loading overlay, a navigation in flight. The engine re-runs the
    /// *same* check until the recipe's deadline; it never loosens it.
    /// Everything else aborts at once.
    pub fn is_transient(self) -> bool {
        matches!(self, Self::NoMatch | Self::NotVisible | Self::Occluded | Self::Disabled | Self::Origin)
    }

    /// The `aborted:<check>` name for this status.
    pub fn abort_check(self) -> &'static str {
        match self {
            Self::Ok => "internal",
            Self::NoMatch => "no_match",
            Self::Ambiguous => "ambiguous_match",
            Self::NotInput => "not_input",
            Self::WrongType => "field_type",
            Self::NotVisible => "not_visible",
            Self::Occluded => "occluded",
            Self::Disabled => "field_disabled",
            Self::FormAction => "form_action",
            Self::NoForm => "no_form",
            Self::Unsupported => "submit_unsupported",
            Self::BadSelector => "bad_selector",
            Self::Origin => "origin",
            Self::NotTop => "frame",
            Self::ScriptError => "script_error",
        }
    }
}

/// Heuristic candidate counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCounts {
    pub username: u32,
    pub current_password: u32,
    pub password: u32,
    pub otp: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyWire {
    v: u32,
    origin: String,
    status: String,
    #[serde(default)]
    matches: Option<u32>,
    #[serde(default)]
    success: Option<u32>,
    #[serde(default)]
    failure: Option<u32>,
    #[serde(default)]
    scan: Option<ScanCounts>,
}

/// A parsed routine reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptReply {
    pub origin: String,
    pub status: ActionStatus,
    pub matches: Option<u32>,
    pub success: Option<u32>,
    pub failure: Option<u32>,
    pub scan: Option<ScanCounts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// No value came back: the script threw, the page went away, or the
    /// webview dropped the evaluation.
    NoResult,
    /// Something came back that is not a routine reply.
    Invalid,
}

/// Parse what `eval_with_callback` delivered: the JSON encoding of the
/// routine's return value, which is itself a JSON string.
pub fn parse_reply(raw: &str) -> Result<ScriptReply, ReplyError> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "null" || raw == "undefined" {
        return Err(ReplyError::NoResult);
    }
    let inner: String = serde_json::from_str(raw).map_err(|_| ReplyError::Invalid)?;
    let wire: ReplyWire = serde_json::from_str(&inner).map_err(|_| ReplyError::Invalid)?;
    if wire.v != 1 {
        return Err(ReplyError::Invalid);
    }
    let status = ActionStatus::parse(&wire.status).ok_or(ReplyError::Invalid)?;
    Ok(ScriptReply {
        origin: wire.origin,
        status,
        matches: wire.matches,
        success: wire.success,
        failure: wire.failure,
        scan: wire.scan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const ORIGIN: &str = "https://fw01.example.com";

    fn origins() -> Vec<String> {
        vec![ORIGIN.to_string()]
    }

    /// The args half of a rendered script, parsed back.
    fn args_of(script: &str) -> Value {
        let prefix = format!("({})(", FILL_ROUTINE.trim_end());
        let body = script.strip_prefix(&prefix).expect("routine prefix");
        let args = body.strip_suffix(')').expect("closing paren");
        serde_json::from_str(args).expect("args are JSON")
    }

    const HOSTILE: &[&str] = &[
        "\"; alert(1); //",
        "'); alert(1); //",
        "</script><script>alert(1)</script>",
        "back\\slash\\\\ and \\u0041",
        "line\u{2028}sep\u{2029}para",
        "`${alert(1)}`",
        "\n\r\t\u{0}\u{1f}",
        "})(); alert(1); ((function(){",
        "<!-- -->&amp;",
    ];

    #[test]
    fn hostile_values_round_trip_as_inert_literals() {
        let fo = origins();
        for value in HOSTILE {
            let call = ScriptCall::fill(ORIGIN, &fo, "input[name=\"u\"]", FieldExpect::Password, value);
            let script = render(&call);
            let args = args_of(&script);
            assert_eq!(args["value"], Value::String((*value).to_string()), "{value:?}");
            // Nothing a hostile value contains survives raw in the args.
            let raw_args = &script[FILL_ROUTINE.trim_end().len() + 3..];
            for needle in ["</script", "<!--", "\u{2028}", "\u{2029}", "&amp;", "\n"] {
                assert!(!raw_args.contains(needle), "{value:?} leaked {needle:?}");
            }
        }
    }

    #[test]
    fn hostile_selectors_round_trip_too() {
        let fo = origins();
        for sel in HOSTILE {
            let call = ScriptCall::check_fill(ORIGIN, &fo, sel, FieldExpect::Username);
            let args = args_of(&render(&call));
            assert_eq!(args["selector"], Value::String((*sel).to_string()));
        }
    }

    #[test]
    fn the_value_appears_once_and_only_on_an_act_mode_fill() {
        let fo = origins();
        let secret = "s3cr3t-Pa55";
        let script = render(&ScriptCall::fill(ORIGIN, &fo, "#p", FieldExpect::Password, secret));
        assert_eq!(script.matches(secret).count(), 1);
        let args = args_of(&script);
        assert_eq!(args["mode"], "act");
        assert_eq!(args["kind"], "fill");
        assert_eq!(args["expect"], "password");
        assert_eq!(args["origin"], ORIGIN);
        assert_eq!(args["fill_origins"], serde_json::json!([ORIGIN]));

        let check = ScriptCall::check_fill(ORIGIN, &fo, "#p", FieldExpect::Password);
        assert!(!check.has_value());
        let args = args_of(&render(&check));
        assert_eq!(args["mode"], "check");
        assert!(args.get("value").is_none());

        for call in [
            ScriptCall::non_fill(ActionKind::Click, ScriptMode::Act, ORIGIN, &fo, "#b"),
            ScriptCall::probe(ORIGIN, &fo, Some(".ok"), Some(".err")),
            ScriptCall::scan(ORIGIN, &fo),
            ScriptCall::clear(ORIGIN, &fo),
        ] {
            assert!(!call.has_value());
            assert!(args_of(&render(&call)).get("value").is_none());
        }
    }

    #[test]
    fn scan_carries_the_fixed_heuristic_selectors() {
        let fo = origins();
        let args = args_of(&render(&ScriptCall::scan(ORIGIN, &fo)));
        assert_eq!(args["op"], "scan");
        assert_eq!(args["scan"]["username"], HEURISTIC_SELECTORS.username);
        assert_eq!(args["scan"]["password"], HEURISTIC_SELECTORS.password);
    }

    fn reply(inner: &str) -> String {
        serde_json::to_string(inner).unwrap()
    }

    #[test]
    fn replies_parse_strictly() {
        let ok = parse_reply(&reply(r#"{"v":1,"origin":"https://a.example","status":"ok","matches":1}"#)).unwrap();
        assert_eq!(ok.status, ActionStatus::Ok);
        assert_eq!(ok.matches, Some(1));
        let scan = parse_reply(&reply(
            r#"{"v":1,"origin":"https://a.example","status":"ok","scan":{"username":1,"current_password":0,"password":1,"otp":0}}"#,
        ))
        .unwrap();
        assert_eq!(scan.scan.unwrap().password, 1);

        for raw in ["", "null", "undefined", "  "] {
            assert_eq!(parse_reply(raw), Err(ReplyError::NoResult), "{raw:?}");
        }
        for bad in [
            // not a JSON string
            r#"{"v":1}"#.to_string(),
            reply("not json"),
            reply(r#"{"v":2,"origin":"https://a.example","status":"ok"}"#),
            reply(r#"{"v":1,"origin":"https://a.example","status":"pwned"}"#),
            // A reply may never carry a value back.
            reply(r#"{"v":1,"origin":"https://a.example","status":"ok","value":"x"}"#),
            reply(r#"{"v":1,"origin":"https://a.example","status":"ok","matches":-1}"#),
        ] {
            assert_eq!(parse_reply(&bad), Err(ReplyError::Invalid), "{bad}");
        }
    }

    #[test]
    fn every_status_round_trips_and_maps_to_a_valid_check_name() {
        for s in [
            "ok",
            "no_match",
            "ambiguous",
            "not_input",
            "wrong_type",
            "not_visible",
            "occluded",
            "disabled",
            "form_action",
            "no_form",
            "unsupported",
            "bad_selector",
            "origin",
            "not_top",
            "script_error",
        ] {
            let st = ActionStatus::parse(s).unwrap();
            assert_eq!(st.as_str(), s);
            let check = st.abort_check();
            assert!(
                (1..=32).contains(&check.len())
                    && check.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{check}"
            );
        }
        // The safety checks are never retried.
        for permanent in ["ambiguous", "wrong_type", "form_action", "not_top", "bad_selector"] {
            assert!(!ActionStatus::parse(permanent).unwrap().is_transient(), "{permanent}");
        }
    }

    #[test]
    fn the_routine_is_a_function_expression_with_no_ipc() {
        let r = FILL_ROUTINE.trim();
        let body: String = r.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        assert!(body.trim_start().starts_with("function (A) {"), "{}", &body[..40]);
        // The window has no IPC, and the routine must never look for one.
        for forbidden in ["__TAURI", "invoke", "ipc", "postMessage", "eval(", "Function(", "fetch(", "XMLHttpRequest"] {
            assert!(!body.contains(forbidden), "routine mentions {forbidden}");
        }
    }
}
