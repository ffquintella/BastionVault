//! `assert_*` matchers and snapshot serialization for [`TestInvocation`].
//!
//! Matchers panic with the invocation's response/log context in the
//! message, so a failing plugin test explains itself without a debugger.
//! They return `&Self` so checks chain.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::TestInvocation;

impl TestInvocation {
    fn context(&self) -> String {
        format!(
            "status={} response={:?} logs={:?}",
            self.status(),
            String::from_utf8_lossy(&self.response),
            self.logs.iter().map(|l| l.line.as_str()).collect::<Vec<_>>(),
        )
    }

    /// Panics unless `bv_run` returned 0.
    #[track_caller]
    pub fn assert_success(&self) -> &Self {
        assert!(self.is_success(), "expected success; {}", self.context());
        self
    }

    /// Panics unless `bv_run` returned exactly `code`.
    #[track_caller]
    pub fn assert_plugin_error(&self, code: i32) -> &Self {
        assert!(!self.is_success() && self.status() == code, "expected plugin error {code}; {}", self.context());
        self
    }

    /// Panics unless the response's `data` member equals `expected`.
    #[track_caller]
    pub fn assert_data_eq(&self, expected: Value) -> &Self {
        assert_eq!(self.data(), Some(expected), "data mismatch; {}", self.context());
        self
    }

    /// Panics unless `data` is a JSON object containing `key == value`.
    #[track_caller]
    pub fn assert_data_field(&self, key: &str, value: Value) -> &Self {
        let data = self.data();
        assert_eq!(data.as_ref().and_then(|d| d.get(key)), Some(&value), "data.{key} mismatch; {}", self.context());
        self
    }

    /// Panics unless some captured log line contains `needle`.
    #[track_caller]
    pub fn assert_logged(&self, needle: &str) -> &Self {
        assert!(
            self.logs.iter().any(|l| l.line.contains(needle)),
            "no log line contains {needle:?}; {}",
            self.context()
        );
        self
    }

    /// Panics unless exactly `n` audit events were accepted.
    #[track_caller]
    pub fn assert_audit_count(&self, n: usize) -> &Self {
        assert_eq!(self.audit_events.len(), n, "audit event count; {}", self.context());
        self
    }

    /// Stable, diff-friendly representation for snapshot tests
    /// (`insta`, `expect_test`, or a plain `assert_eq!` on a checked-in
    /// JSON file). `fuel_consumed` is deliberately omitted — it moves
    /// with every compiler/plugin change and would make snapshots
    /// churn. A non-JSON response is carried as `response_b64`.
    pub fn to_snapshot(&self) -> Value {
        let (response_key, response) = match self.response_json() {
            Some(v) => ("response", v),
            None if self.response.is_empty() => ("response", Value::Null),
            None => ("response_b64", Value::String(B64.encode(&self.response))),
        };
        json!({
            "status": self.status(),
            response_key: response,
            "logs": self.logs.iter()
                .map(|l| json!({"level": l.level, "line": l.line}))
                .collect::<Vec<_>>(),
            "audit_events": self.audit_events,
        })
    }
}
