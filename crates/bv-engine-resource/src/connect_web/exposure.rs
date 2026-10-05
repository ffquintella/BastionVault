//! Exposure levels and their policy (`features/web-application-connect.md` §6).
//!
//! `web_exposure_max` and `allow_heuristic_fill` can be set on the resource
//! *type* (`config/types[<type>].connect`) and on the *resource* record
//! itself (top-level keys). The most restrictive tier wins, matching the
//! Rustion transport tier rule. The profile editor checks the same thing as a
//! convenience; this module is the control.
//!
//! Every value is parsed strictly. A tier carrying a value this server does
//! not recognise refuses the launch instead of being read as "unset", so a
//! typo can never widen what a resource allows.

use std::fmt;

use serde_json::{Map, Value};

/// How far a login mode lets the credential travel, least to most exposed.
/// The derive order *is* the policy order: `None < Isolated < Handler < Proxy
/// < Dom`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WebExposure {
    /// `open`, `sso`: no shared secret is released.
    None,
    /// Phase 8: the credential reaches a Rustion browser worker, never the
    /// operator's endpoint.
    Isolated,
    /// `http-auth`: a native challenge handler, never the DOM.
    Handler,
    /// Phase 6: a placeholder in the DOM, the secret only on the wire.
    Proxy,
    /// `form`: the credential is in the page's DOM between fill and submit.
    Dom,
}

impl WebExposure {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "isolated" => Self::Isolated,
            "handler" => Self::Handler,
            "proxy" => Self::Proxy,
            "dom" => Self::Dom,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Isolated => "isolated",
            Self::Handler => "handler",
            Self::Proxy => "proxy",
            Self::Dom => "dom",
        }
    }
}

/// Where a policy value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Type,
    Resource,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Resource => "resource",
        }
    }
}

/// The two tiers' settings, as read. `None` means the tier expresses no
/// opinion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposurePolicy {
    pub type_cap: Option<WebExposure>,
    pub resource_cap: Option<WebExposure>,
    pub type_heuristic: Option<bool>,
    pub resource_heuristic: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposureRefusal {
    /// A tier carries a value of the wrong type or outside the enum.
    InvalidPolicy { tier: Tier, field: &'static str },
    /// The login mode needs more exposure than the effective cap allows.
    CapExceeded { required: WebExposure, cap: WebExposure, set_by: Tier },
    /// Heuristic mode without `allow_heuristic_fill`. `blocked_by` names the
    /// tier that set it `false`; `None` means no tier enabled it.
    HeuristicNotAllowed { blocked_by: Option<Tier> },
    /// `allow_insecure_http` while the effective cap is below `dom`.
    InsecureHttpBelowDom { cap: WebExposure },
}

impl ExposureRefusal {
    /// Stable machine-readable code, used as the refusal's error prefix and in
    /// the `connect.web.refused` audit line.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy { .. } => "exposure_policy_invalid",
            Self::CapExceeded { .. } => "exposure_cap_exceeded",
            Self::HeuristicNotAllowed { .. } => "heuristic_not_allowed",
            Self::InsecureHttpBelowDom { .. } => "insecure_http_not_allowed",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidPolicy { .. } => 422,
            _ => 403,
        }
    }
}

impl fmt::Display for ExposureRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy { tier, field } => write!(
                f,
                "the {} tier's `{field}` is not a value this server understands; fix it rather \
                 than relying on a default",
                tier.as_str()
            ),
            Self::CapExceeded { required, cap, set_by } => write!(
                f,
                "this login mode needs exposure `{}` but the {} tier caps web exposure at `{}`",
                required.as_str(),
                set_by.as_str(),
                cap.as_str()
            ),
            Self::HeuristicNotAllowed { blocked_by: Some(t) } => write!(
                f,
                "the recipe uses heuristic fill (`\"steps\": \"auto\"`), which the {} tier \
                 forbids (`allow_heuristic_fill: false`)",
                t.as_str()
            ),
            Self::HeuristicNotAllowed { blocked_by: None } => write!(
                f,
                "the recipe uses heuristic fill (`\"steps\": \"auto\"`), which needs \
                 `allow_heuristic_fill: true` on the resource or its type"
            ),
            Self::InsecureHttpBelowDom { cap } => write!(
                f,
                "allow_insecure_http is refused while the effective exposure cap is `{}`: a \
                 credential sent over plain http is DOM-level exposure",
                cap.as_str()
            ),
        }
    }
}

fn read_cap(v: Option<&Value>, tier: Tier) -> Result<Option<WebExposure>, ExposureRefusal> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            WebExposure::parse(s).map(Some).ok_or(ExposureRefusal::InvalidPolicy { tier, field: "web_exposure_max" })
        }
        Some(_) => Err(ExposureRefusal::InvalidPolicy { tier, field: "web_exposure_max" }),
    }
}

fn read_flag(v: Option<&Value>, tier: Tier) -> Result<Option<bool>, ExposureRefusal> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(ExposureRefusal::InvalidPolicy { tier, field: "allow_heuristic_fill" }),
    }
}

impl ExposurePolicy {
    /// Read both tiers. `type_def` is the resource's entry in `config/types`
    /// (absent when the type was never saved, which leaves the builtin
    /// defaults — no cap); `resource_meta` is the resource record.
    pub fn from_tiers(type_def: Option<&Value>, resource_meta: &Map<String, Value>) -> Result<Self, ExposureRefusal> {
        let type_connect = match type_def {
            None | Some(Value::Null) => None,
            Some(Value::Object(def)) => match def.get("connect") {
                None | Some(Value::Null) => None,
                Some(Value::Object(c)) => Some(c),
                Some(_) => return Err(ExposureRefusal::InvalidPolicy { tier: Tier::Type, field: "connect" }),
            },
            Some(_) => return Err(ExposureRefusal::InvalidPolicy { tier: Tier::Type, field: "connect" }),
        };
        Ok(Self {
            type_cap: read_cap(type_connect.and_then(|c| c.get("web_exposure_max")), Tier::Type)?,
            type_heuristic: read_flag(type_connect.and_then(|c| c.get("allow_heuristic_fill")), Tier::Type)?,
            resource_cap: read_cap(resource_meta.get("web_exposure_max"), Tier::Resource)?,
            resource_heuristic: read_flag(resource_meta.get("allow_heuristic_fill"), Tier::Resource)?,
        })
    }

    /// The effective cap and the tier that set it. With no cap at either tier
    /// every exposure level is allowed (`dom`).
    pub fn effective_cap(&self) -> (WebExposure, Option<Tier>) {
        match (self.type_cap, self.resource_cap) {
            (None, None) => (WebExposure::Dom, None),
            (Some(t), None) => (t, Some(Tier::Type)),
            (None, Some(r)) => (r, Some(Tier::Resource)),
            (Some(t), Some(r)) if r <= t => (r, Some(Tier::Resource)),
            (Some(t), Some(_)) => (t, Some(Tier::Type)),
        }
    }

    /// Heuristic fill is allowed when no tier forbids it and at least one
    /// enables it. The default, with neither tier set, is refusal.
    pub fn heuristic_allowed(&self) -> Result<(), ExposureRefusal> {
        if self.type_heuristic == Some(false) {
            return Err(ExposureRefusal::HeuristicNotAllowed { blocked_by: Some(Tier::Type) });
        }
        if self.resource_heuristic == Some(false) {
            return Err(ExposureRefusal::HeuristicNotAllowed { blocked_by: Some(Tier::Resource) });
        }
        if self.type_heuristic == Some(true) || self.resource_heuristic == Some(true) {
            return Ok(());
        }
        Err(ExposureRefusal::HeuristicNotAllowed { blocked_by: None })
    }

    /// Every §6 check a launch must pass. Returns the effective cap.
    pub fn check(
        &self,
        required: WebExposure,
        heuristic: bool,
        allow_insecure_http: bool,
    ) -> Result<WebExposure, ExposureRefusal> {
        let (cap, set_by) = self.effective_cap();
        if required > cap {
            // `set_by` is always Some here: with no tier set the cap is `dom`,
            // which nothing exceeds.
            return Err(ExposureRefusal::CapExceeded { required, cap, set_by: set_by.unwrap_or(Tier::Resource) });
        }
        if allow_insecure_http && cap < WebExposure::Dom {
            return Err(ExposureRefusal::InsecureHttpBelowDom { cap });
        }
        if heuristic {
            self.heuristic_allowed()?;
        }
        Ok(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn order_is_the_policy_order() {
        use WebExposure::*;
        assert!(None < Isolated && Isolated < Handler && Handler < Proxy && Proxy < Dom);
        for s in ["none", "isolated", "handler", "proxy", "dom"] {
            assert_eq!(WebExposure::parse(s).unwrap().as_str(), s);
        }
        assert!(WebExposure::parse("DOM").is_none());
    }

    #[test]
    fn no_tier_set_means_dom_is_allowed_and_heuristics_are_not() {
        let p = ExposurePolicy::from_tiers(None, &Map::new()).unwrap();
        assert_eq!(p.check(WebExposure::Dom, false, false), Ok(WebExposure::Dom));
        assert_eq!(
            p.check(WebExposure::Dom, true, false),
            Err(ExposureRefusal::HeuristicNotAllowed { blocked_by: None })
        );
    }

    #[test]
    fn the_stricter_tier_wins_and_is_named() {
        let type_def = json!({ "connect": { "web_exposure_max": "handler" } });
        let p = ExposurePolicy::from_tiers(Some(&type_def), &Map::new()).unwrap();
        assert_eq!(
            p.check(WebExposure::Dom, false, false),
            Err(ExposureRefusal::CapExceeded {
                required: WebExposure::Dom,
                cap: WebExposure::Handler,
                set_by: Tier::Type
            })
        );

        let p = ExposurePolicy::from_tiers(None, &meta(json!({ "web_exposure_max": "isolated" }))).unwrap();
        assert!(matches!(
            p.check(WebExposure::Dom, false, false),
            Err(ExposureRefusal::CapExceeded { set_by: Tier::Resource, cap: WebExposure::Isolated, .. })
        ));

        // A resource cannot loosen its type's cap …
        let p = ExposurePolicy::from_tiers(Some(&type_def), &meta(json!({ "web_exposure_max": "dom" }))).unwrap();
        assert_eq!(p.effective_cap(), (WebExposure::Handler, Some(Tier::Type)));
        // … but can tighten it.
        let p = ExposurePolicy::from_tiers(Some(&type_def), &meta(json!({ "web_exposure_max": "none" }))).unwrap();
        assert_eq!(p.effective_cap(), (WebExposure::None, Some(Tier::Resource)));

        // A cap at `dom` on both tiers lets form mode through.
        let dom = json!({ "connect": { "web_exposure_max": "dom" } });
        let p = ExposurePolicy::from_tiers(Some(&dom), &meta(json!({ "web_exposure_max": "dom" }))).unwrap();
        assert_eq!(p.check(WebExposure::Dom, false, false), Ok(WebExposure::Dom));
    }

    #[test]
    fn unrecognised_policy_values_fail_closed() {
        let cases: Vec<(Option<Value>, Value, Tier, &str)> = vec![
            (
                Some(json!({ "connect": { "web_exposure_max": "everything" } })),
                json!({}),
                Tier::Type,
                "web_exposure_max",
            ),
            (Some(json!({ "connect": { "web_exposure_max": 4 } })), json!({}), Tier::Type, "web_exposure_max"),
            (Some(json!({ "connect": "yes" })), json!({}), Tier::Type, "connect"),
            (Some(json!("server")), json!({}), Tier::Type, "connect"),
            (
                Some(json!({ "connect": { "allow_heuristic_fill": "true" } })),
                json!({}),
                Tier::Type,
                "allow_heuristic_fill",
            ),
            (None, json!({ "web_exposure_max": "Dom" }), Tier::Resource, "web_exposure_max"),
            (None, json!({ "allow_heuristic_fill": 1 }), Tier::Resource, "allow_heuristic_fill"),
        ];
        for (type_def, res, tier, field) in cases {
            assert_eq!(
                ExposurePolicy::from_tiers(type_def.as_ref(), &meta(res)),
                Err(ExposureRefusal::InvalidPolicy { tier, field })
            );
        }
    }

    #[test]
    fn heuristic_fill_needs_an_enabling_tier_and_no_forbidding_one() {
        let on = json!({ "connect": { "allow_heuristic_fill": true } });
        let off = json!({ "connect": { "allow_heuristic_fill": false } });

        let p = ExposurePolicy::from_tiers(Some(&on), &Map::new()).unwrap();
        assert!(p.check(WebExposure::Dom, true, false).is_ok());
        let p = ExposurePolicy::from_tiers(None, &meta(json!({ "allow_heuristic_fill": true }))).unwrap();
        assert!(p.check(WebExposure::Dom, true, false).is_ok());

        // An explicit `false` at either tier beats a `true` at the other.
        let p = ExposurePolicy::from_tiers(Some(&off), &meta(json!({ "allow_heuristic_fill": true }))).unwrap();
        assert_eq!(
            p.check(WebExposure::Dom, true, false),
            Err(ExposureRefusal::HeuristicNotAllowed { blocked_by: Some(Tier::Type) })
        );
        let p = ExposurePolicy::from_tiers(Some(&on), &meta(json!({ "allow_heuristic_fill": false }))).unwrap();
        assert_eq!(
            p.check(WebExposure::Dom, true, false),
            Err(ExposureRefusal::HeuristicNotAllowed { blocked_by: Some(Tier::Resource) })
        );
        // Explicit steps never consult the flag.
        assert!(p.check(WebExposure::Dom, false, false).is_ok());
    }

    #[test]
    fn insecure_http_is_refused_below_dom() {
        let p = ExposurePolicy::from_tiers(None, &meta(json!({ "web_exposure_max": "handler" }))).unwrap();
        assert_eq!(
            p.check(WebExposure::Handler, false, true),
            Err(ExposureRefusal::InsecureHttpBelowDom { cap: WebExposure::Handler })
        );
        assert!(p.check(WebExposure::Handler, false, false).is_ok());
        let p = ExposurePolicy::from_tiers(None, &Map::new()).unwrap();
        assert!(p.check(WebExposure::Dom, false, true).is_ok());
    }
}
