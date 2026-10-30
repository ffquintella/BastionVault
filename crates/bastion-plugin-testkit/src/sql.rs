//! Mock of the ABI 1.4 caller-bound host calls (features/sql-browser.md
//! §9.2): `resource_sql_target`, `resource_sql_authorize`,
//! `resource_sql_credential`, `connect_ticket_redeem`, and the actor-stamped
//! `audit_emit`. Same check order, error codes and release rules as
//! `src/plugins/sql_host.rs`; `tests/test_plugin_testkit_parity.rs` compares.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::{TestCaller, TestHost, TestHostBuilder};

/// The SQL capability names, in policy-language order.
pub const SQL_CAPABILITIES: [&str; 11] = [
    "sql_select",
    "sql_insert",
    "sql_update",
    "sql_delete",
    "sql_alter",
    "sql_create",
    "sql_drop",
    "sql_execute",
    "sql_admin",
    "sql_export",
    "sql_script",
];

/// What the mocked resource engine knows about one `sql` profile.
#[derive(Debug, Clone)]
pub struct MockRelease {
    pub protocol: String,
    /// The endpoint the plugin would dial, `host:port`.
    pub endpoint: String,
    /// `direct`, `rustion-preferred` or `rustion-required`.
    pub transport: String,
    pub secret_id: String,
    /// The secret's `sql_endpoint`, as stored (`None` = unbound).
    pub sql_endpoint: Option<Value>,
    pub username: String,
    pub password: String,
    /// The profile's `sql.require_mfa`: the release needs a ticket the same
    /// caller redeemed for this profile, spent once.
    pub require_mfa: bool,
}

impl MockRelease {
    /// A releasable profile bound to `endpoint`.
    pub fn bound(endpoint: &str, username: &str, password: &str) -> Self {
        Self {
            protocol: "sql".into(),
            endpoint: endpoint.into(),
            transport: "direct".into(),
            secret_id: format!("{username}-secret"),
            sql_endpoint: Some(json!(endpoint)),
            username: username.into(),
            password: password.into(),
            require_mfa: false,
        }
    }
}

/// Mocked SQL substrate state.
#[derive(Debug, Clone, Default)]
pub(crate) struct SqlMock {
    pub sql_gate: bool,
    pub resource_credentials: bool,
    pub sql_gate_granted: bool,
    pub resource_credentials_granted: bool,
    /// resource → SQL capabilities the caller holds on it (resource-wide).
    pub privileges: BTreeMap<String, BTreeSet<String>>,
    pub targets: BTreeMap<String, Value>,
    pub releases: BTreeMap<(String, String), MockRelease>,
    /// (resource, profile) → tickets that redeem once.
    pub tickets: BTreeMap<(String, String), BTreeSet<String>>,
    /// (resource, profile, canonical action) → step-up tickets that redeem
    /// once, only for exactly that action (§8.3, T126).
    pub action_tickets: BTreeMap<(String, String, String), BTreeSet<String>>,
    /// Redemptions not yet spent by a release: (entity, namespace,
    /// resource, profile). The host scopes them to one invocation.
    pub redeemed: BTreeSet<(String, String, String, String)>,
}

impl TestHostBuilder {
    /// Declare `sql_gate = true`; `granted` is the admin `sql-gate` grant.
    pub fn sql_gate(mut self, granted: bool) -> Self {
        self.sql.sql_gate = true;
        self.sql.sql_gate_granted = granted;
        self
    }

    /// Declare `resource_credentials = ["sql"]`; `granted` is the admin
    /// `resource-credentials` grant.
    pub fn resource_credentials(mut self, granted: bool) -> Self {
        self.sql.resource_credentials = true;
        self.sql.resource_credentials_granted = granted;
        self
    }

    /// The caller of [`TestHost::invoke_process_as`] holds `caps` on
    /// `resource` (resource-wide).
    pub fn sql_privileges(mut self, resource: &str, caps: &[&str]) -> Self {
        self.sql.privileges.insert(canonical(resource), caps.iter().map(|c| c.to_string()).collect());
        self
    }

    /// What `resource_sql_target` returns for `resource`.
    pub fn sql_target(mut self, resource: &str, target: Value) -> Self {
        self.sql.targets.insert(canonical(resource), target);
        self
    }

    /// What the resource engine holds for `(resource, profile)`.
    pub fn sql_release(mut self, resource: &str, profile: &str, release: MockRelease) -> Self {
        self.sql.releases.insert((canonical(resource), profile.to_string()), release);
        self
    }

    /// A connect-MFA ticket that `connect_ticket_redeem` accepts once.
    pub fn connect_ticket(mut self, resource: &str, profile: &str, ticket: &str) -> Self {
        self.sql.tickets.entry((canonical(resource), profile.to_string())).or_default().insert(ticket.into());
        self
    }

    /// A step-up ticket bound to `action` (one or more `sql_*` names,
    /// comma-separated; stored canonical) that `connect_ticket_redeem`
    /// accepts once, for exactly that action.
    pub fn connect_action_ticket(mut self, resource: &str, profile: &str, action: &str, ticket: &str) -> Self {
        let action = canonical_action(action).expect("a well-formed step-up action");
        self.sql.action_tickets.entry((canonical(resource), profile.to_string(), action)).or_default().insert(ticket.into());
        self
    }

    /// `abi_version` minor and `caller_identity` of the mocked manifest:
    /// together they decide whether `audit_emit` is actor-stamped.
    pub fn abi_minor(mut self, minor: u32) -> Self {
        self.abi_minor = minor;
        self
    }

    pub fn caller_identity(mut self, on: bool) -> Self {
        self.caller_identity = on;
        self
    }
}

fn canonical(resource: &str) -> String {
    resource.trim().to_lowercase()
}

fn err(code: &str, detail: impl std::fmt::Display) -> String {
    format!("{code}: {detail}")
}

/// Mirror of `connect_mfa::canonical_sql_action`: one or more known `sql_*`
/// names, comma-separated, each once, rewritten in policy-language order.
pub fn canonical_action(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.len() > 160 {
        return Err("`action` must name 1-11 sql_* capabilities, comma-separated".into());
    }
    let mut seen: Vec<&str> = Vec::new();
    for part in raw.split(',') {
        let cap = SQL_CAPABILITIES
            .iter()
            .copied()
            .find(|c| *c == part)
            .ok_or("`action` may name only the eleven sql_* capabilities, comma-separated")?;
        if seen.contains(&cap) {
            return Err(format!("`action` names `{cap}` twice"));
        }
        seen.push(cap);
    }
    Ok(SQL_CAPABILITIES.iter().filter(|c| seen.contains(c)).copied().collect::<Vec<_>>().join(","))
}

/// Mirror of `sql_host::SqlEndpoint::parse`: `(host lower-cased, port)`.
pub fn parse_endpoint(s: &str) -> Option<(String, u16)> {
    if s.is_empty() || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        rest.split_once("]:")?
    } else {
        let (h, p) = s.rsplit_once(':')?;
        if h.contains(':') {
            return None;
        }
        (h, p)
    };
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    if host.is_empty() || host.contains(['[', ']', '/']) {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

/// Mirror of `sql_host::check_release`: `Ok` or the refusal reason.
pub fn check_release(m: &MockRelease) -> Result<(), &'static str> {
    if m.protocol != "sql" {
        return Err("profile_not_sql");
    }
    match m.transport.as_str() {
        "direct" | "rustion-preferred" => {}
        "rustion-required" => return Err("rustion_required"),
        _ => return Err("transport_unknown"),
    }
    let entries: Vec<&Value> = match &m.sql_endpoint {
        None | Some(Value::Null) => return Err("endpoint_unbound"),
        Some(v @ Value::String(_)) => vec![v],
        Some(Value::Array(a)) => a.iter().collect(),
        Some(_) => return Err("endpoint_invalid"),
    };
    if entries.is_empty() {
        return Err("endpoint_unbound");
    }
    let bound: Vec<(String, u16)> = entries
        .into_iter()
        .map(|v| v.as_str().and_then(parse_endpoint).ok_or("endpoint_invalid"))
        .collect::<Result<_, _>>()?;
    let target = parse_endpoint(&m.endpoint).ok_or("endpoint_invalid")?;
    if bound.contains(&target) {
        Ok(())
    } else {
        Err("endpoint_mismatch")
    }
}

impl TestHost {
    /// The four SQL host calls, in the host's check order.
    pub(crate) fn sql_call(&self, method: &str, params: &Value) -> Result<Value, String> {
        let mut st = self.state.lock().unwrap();
        let caller = st.invocation_caller.clone();
        let sql = &mut st.sql;
        let credentials = method == "resource_sql_credential";
        let (declared, granted) = if credentials {
            (sql.resource_credentials, sql.resource_credentials_granted)
        } else {
            (sql.sql_gate, sql.sql_gate_granted)
        };
        if !declared {
            return Err("forbidden".into());
        }
        let Some(caller) = caller else { return Err("no_invocation".into()) };
        if !granted {
            let grant = if credentials { "resource-credentials" } else { "sql-gate" };
            let e = err("not_granted", format!("the `{grant}` grant is absent or voided"));
            drop(st);
            if credentials {
                self.record_release(&caller, params, "", Err(&e));
            }
            return Err(e);
        }
        let text = |k: &str| params.get(k).and_then(Value::as_str).map(str::to_string);
        let resource = text("resource").map(|r| canonical(&r)).filter(|r| !r.is_empty() && !r.contains('/'));
        let Some(resource) = resource else { return Err(err("bad_request", "invalid resource name")) };
        // Parameters are checked before privileges, as on the host.
        let profile = text("profile").unwrap_or_default();
        if credentials && (profile.is_empty() || text("session_ref").unwrap_or_default().is_empty()) {
            return Err(err("bad_request", "`profile` and `session_ref` are required"));
        }
        if method == "connect_ticket_redeem" && (profile.is_empty() || text("ticket").unwrap_or_default().is_empty()) {
            return Err(err("bad_request", "`profile` and `ticket` are required"));
        }
        // The step-up action is parsed with the parameters, as on the host.
        let action = match params.get("action") {
            None | Some(Value::Null) if method == "connect_ticket_redeem" => None,
            Some(Value::String(a)) if method == "connect_ticket_redeem" => {
                Some(canonical_action(a).map_err(|m| err("bad_request", m))?)
            }
            Some(_) if method == "connect_ticket_redeem" => return Err(err("bad_request", "`action` must be a string")),
            _ => None,
        };
        let held: Vec<String> = sql.privileges.get(&resource).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        match method {
            "resource_sql_authorize" => {
                let checks = params.get("checks").and_then(Value::as_array).ok_or_else(|| err("bad_request", "checks"))?;
                let mut verdicts = Vec::new();
                for c in checks {
                    let cap = c.get("capability").and_then(Value::as_str).unwrap_or("");
                    if !SQL_CAPABILITIES.contains(&cap) {
                        return Err(err("bad_request", "unknown SQL capability"));
                    }
                    let allowed = held.iter().any(|h| h == cap);
                    verdicts.push(json!({"capability": cap, "target": c["target"], "allowed": allowed,
                        "denied_by_deny": false, "path": format!("resources/resources/{resource}/sql/")}));
                }
                Ok(json!({"resource": resource, "verdicts": verdicts}))
            }
            _ if held.is_empty() => {
                let e = err("no_sql_privilege", "the caller holds no SQL privilege on this resource");
                drop(st);
                if credentials {
                    self.record_release(&caller, params, "", Err(&e));
                }
                Err(e)
            }
            "resource_sql_target" => match sql.targets.get(&resource) {
                Some(t) => Ok(json!({"namespace": caller.namespace, "resource": resource, "privileges": held, "target": t})),
                None => Err(err("not_found", "resource_not_found: no SQL target for this resource")),
            },
            "connect_ticket_redeem" if action.is_some() => {
                // Always demands a ticket bound to exactly this action, and
                // records no connect redemption (a release still needs one).
                let ticket = text("ticket").unwrap_or_default();
                let action = action.unwrap_or_default();
                let key = (resource.clone(), profile.clone(), action.clone());
                if sql.action_tickets.get_mut(&key).is_some_and(|t| t.remove(&ticket)) {
                    Ok(json!({"redeemed": true, "method": "totp", "action": action}))
                } else {
                    Err(err("refused", "mfa_required: the step-up ticket is unknown, used, expired or bound to another action"))
                }
            }
            "connect_ticket_redeem" => {
                let ticket = text("ticket").unwrap_or_default();
                match sql.tickets.get_mut(&(resource.clone(), profile.clone())) {
                    None => Ok(json!({"redeemed": false})),
                    Some(t) => {
                        if t.remove(&ticket) {
                            let key = (caller.entity_id.clone(), caller.namespace.clone(), resource, profile);
                            sql.redeemed.insert(key);
                            Ok(json!({"redeemed": true, "method": "totp"}))
                        } else {
                            Err(err("refused", "mfa_required: the ticket is unknown, used or expired"))
                        }
                    }
                }
            }
            "resource_sql_credential" => {
                let release = sql.releases.get(&(resource.clone(), profile.clone())).cloned();
                let Some(release) = release else {
                    drop(st);
                    let e = err("not_found", "profile_not_found: no such sql profile");
                    self.record_release(&caller, params, "", Err(&e));
                    return Err(e);
                };
                // Last, as on the host: a fixable refusal does not spend it.
                let key = (caller.entity_id.clone(), caller.namespace.clone(), resource.clone(), profile);
                let checked = check_release(&release).and_then(|()| {
                    if release.require_mfa && !sql.redeemed.remove(&key) {
                        Err("mfa_required")
                    } else {
                        Ok(())
                    }
                });
                drop(st);
                let result = checked
                    .map(|()| {
                        json!({"resource": resource, "profile": text("profile"), "secret_id": release.secret_id,
                            "endpoint": release.endpoint, "username": release.username, "password": release.password})
                    })
                    .map_err(|reason| err("refused", reason));
                self.record_release(&caller, params, &release.secret_id, result.as_ref().map(|_| ()));
                result
            }
            _ => Err("unknown_method".into()),
        }
    }

    /// The host's `resource-credential-release` audit event. Never the value.
    fn record_release(&self, caller: &TestCaller, params: &Value, secret_id: &str, result: Result<(), &String>) {
        let s = |k: &str| params.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let mut data = json!({"plugin": self.name, "resource": s("resource"), "profile": s("profile"),
            "session_ref": s("session_ref"), "secret_id": secret_id});
        match result {
            Ok(()) => data["outcome"] = json!("released"),
            Err(e) => {
                data["outcome"] = json!("refused");
                // As on the host: a stable second code when there is one.
                let mut parts = e.splitn(3, ": ");
                let first = parts.next().unwrap_or("");
                let reason = match parts.next() {
                    Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => s,
                    _ => first,
                };
                data["reason"] = json!(reason);
            }
        }
        self.state.lock().unwrap().audit.push(json!({
            "path": "resource-credential-release",
            "actor": caller.json(),
            "data": data,
        }));
    }

    /// Whether `audit_emit` is stamped with the invocation's caller.
    pub(crate) fn stamps_actor(&self) -> bool {
        self.abi_minor >= 4 && self.caller_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ana() -> TestCaller {
        TestCaller::new("ent-ana")
    }

    fn code(r: Result<Value, String>) -> String {
        r.unwrap_err().split(':').next().unwrap_or("").to_string()
    }

    const METHODS: [&str; 4] =
        ["resource_sql_target", "resource_sql_authorize", "resource_sql_credential", "connect_ticket_redeem"];

    fn params(method: &str) -> Value {
        match method {
            "resource_sql_authorize" => json!({"resource": "db", "checks": [{"capability": "sql_select", "target": "server"}]}),
            "resource_sql_credential" => json!({"resource": "db", "profile": "ro", "session_ref": "s-1"}),
            "connect_ticket_redeem" => json!({"resource": "db", "profile": "ro", "ticket": "t-1"}),
            _ => json!({"resource": "db"}),
        }
    }

    #[test]
    fn refusal_order_matches_the_host() {
        let bare = TestHost::builder("dbms").build();
        let ungranted = TestHost::builder("dbms").sql_gate(false).resource_credentials(false).build();
        let granted = TestHost::builder("dbms").sql_gate(true).resource_credentials(true).build();
        for m in METHODS {
            assert_eq!(code(bare.process_host_call(Some(&ana()), m, &params(m))), "forbidden", "{m}");
            assert_eq!(code(granted.process_host_call(None, m, &params(m))), "no_invocation", "{m}");
            assert_eq!(code(ungranted.process_host_call(Some(&ana()), m, &params(m))), "not_granted", "{m}");
        }
        for m in ["resource_sql_target", "resource_sql_credential", "connect_ticket_redeem"] {
            assert_eq!(code(granted.process_host_call(Some(&ana()), m, &params(m))), "no_sql_privilege", "{m}");
        }
    }

    #[test]
    fn credential_release_follows_the_host_rules_and_is_audited() {
        let host = TestHost::builder("dbms")
            .resource_credentials(true)
            .sql_privileges("DB", &["sql_select"])
            .sql_release("db", "ro", MockRelease::bound("db1:5432", "svc", "pw"))
            .sql_release("db", "moved", MockRelease { endpoint: "evil:5432".into(), ..MockRelease::bound("db1:5432", "svc", "pw") })
            .build();
        let ok = host.process_host_call(Some(&ana()), "resource_sql_credential", &params("resource_sql_credential"));
        assert_eq!(ok.unwrap()["password"], "pw");
        let moved = json!({"resource": "db", "profile": "moved", "session_ref": "s-2"});
        let e = host.process_host_call(Some(&ana()), "resource_sql_credential", &moved).unwrap_err();
        assert_eq!(e, "refused: endpoint_mismatch");
        let audit = host.audit_events();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0]["data"]["outcome"], "released");
        assert_eq!(audit[1]["data"]["reason"], "endpoint_mismatch");
        assert_eq!(audit[0]["actor"]["entity_id"], "ent-ana");
        assert!(!serde_json::to_string(&audit).unwrap().contains("\"pw\""));
    }

    #[test]
    fn release_rules_refuse_each_violation() {
        let base = MockRelease::bound("db1.example:5432", "u", "p");
        assert_eq!(check_release(&base), Ok(()));
        let cases: [(MockRelease, &str); 5] = [
            (MockRelease { protocol: "ssh".into(), ..base.clone() }, "profile_not_sql"),
            (MockRelease { transport: "rustion-required".into(), ..base.clone() }, "rustion_required"),
            (MockRelease { sql_endpoint: None, ..base.clone() }, "endpoint_unbound"),
            (MockRelease { sql_endpoint: Some(json!(5)), ..base.clone() }, "endpoint_invalid"),
            (MockRelease { sql_endpoint: Some(json!(["other:5432"])), ..base.clone() }, "endpoint_mismatch"),
        ];
        for (m, reason) in cases {
            assert_eq!(check_release(&m), Err(reason));
        }
    }

    /// `sql.require_mfa`: released only after this caller redeemed a ticket
    /// for the profile; one redemption, one release.
    #[test]
    fn an_mfa_gated_release_needs_a_redemption() {
        let gated = MockRelease { require_mfa: true, ..MockRelease::bound("db1:5432", "svc", "pw") };
        let host = TestHost::builder("dbms")
            .sql_gate(true)
            .resource_credentials(true)
            .sql_privileges("db", &["sql_select"])
            .sql_release("db", "ro", gated)
            .connect_ticket("db", "ro", "t-1")
            .build();
        let release = params("resource_sql_credential");
        let e = host.process_host_call(Some(&ana()), "resource_sql_credential", &release).unwrap_err();
        assert_eq!(e, "refused: mfa_required");
        let redeem = params("connect_ticket_redeem");
        assert_eq!(host.process_host_call(Some(&ana()), "connect_ticket_redeem", &redeem).unwrap()["redeemed"], true);
        let other = TestCaller::new("ent-bob");
        assert!(host.process_host_call(Some(&other), "resource_sql_credential", &release).is_err());
        assert_eq!(host.process_host_call(Some(&ana()), "resource_sql_credential", &release).unwrap()["password"], "pw");
        assert!(host.process_host_call(Some(&ana()), "resource_sql_credential", &release).is_err(), "spent");
        let reasons: Vec<Value> = host.audit_events().iter().map(|e| e["data"]["reason"].clone()).collect();
        assert_eq!(reasons[0], "mfa_required");
    }

    #[test]
    fn tickets_redeem_once_and_are_bound_to_their_action() {
        let host = TestHost::builder("dbms")
            .sql_gate(true)
            .resource_credentials(true)
            .sql_privileges("db", &["sql_select"])
            .sql_release("db", "ro", MockRelease { require_mfa: true, ..MockRelease::bound("db1:5432", "svc", "pw") })
            .connect_ticket("db", "ro", "t-1")
            .connect_action_ticket("db", "ro", "sql_script,sql_drop", "a-1")
            .build();
        let p = params("connect_ticket_redeem");
        let with = |ticket: &str, action: Value| {
            let mut a = json!({"resource": "db", "profile": "ro", "ticket": ticket});
            a["action"] = action;
            a
        };
        // A connect ticket is never accepted for an action.
        assert_eq!(code(host.process_host_call(Some(&ana()), "connect_ticket_redeem", &with("t-1", json!("sql_drop"))) ), "refused");
        assert_eq!(host.process_host_call(Some(&ana()), "connect_ticket_redeem", &p).unwrap()["redeemed"], true);
        assert_eq!(code(host.process_host_call(Some(&ana()), "connect_ticket_redeem", &p)), "refused");
        for bad in [json!(""), json!("drop"), json!("sql_drop,sql_drop"), json!(["sql_drop"])] {
            assert_eq!(code(host.process_host_call(Some(&ana()), "connect_ticket_redeem", &with("a-1", bad))), "bad_request");
        }
        // Another action, then the action in any order (once).
        assert_eq!(code(host.process_host_call(Some(&ana()), "connect_ticket_redeem", &with("a-1", json!("sql_drop")))), "refused");
        let ok = host.process_host_call(Some(&ana()), "connect_ticket_redeem", &with("a-1", json!("sql_drop,sql_script"))).unwrap();
        assert_eq!((ok["redeemed"].clone(), ok["action"].clone()), (json!(true), json!("sql_drop,sql_script")));
        assert_eq!(code(host.process_host_call(Some(&ana()), "connect_ticket_redeem", &with("a-1", json!("sql_drop,sql_script")))), "refused");
        // The connect redemption above was spent by nothing yet; the action
        // redemption added none: one release, then mfa_required.
        let release = params("resource_sql_credential");
        assert!(host.process_host_call(Some(&ana()), "resource_sql_credential", &release).is_ok());
        assert_eq!(host.process_host_call(Some(&ana()), "resource_sql_credential", &release).unwrap_err(), "refused: mfa_required");
    }

    #[test]
    fn step_up_actions_are_canonical() {
        assert_eq!(canonical_action("sql_script,sql_drop").unwrap(), "sql_drop,sql_script");
        for bad in ["", "sql_drop,", "sql_drop, sql_script", "SQL_DROP", "sql_nope"] {
            assert!(canonical_action(bad).is_err(), "{bad:?}");
        }
    }

    /// The actor is stamped by the host on ABI 1.4 with caller_identity, and
    /// a payload cannot set it.
    #[test]
    fn audit_emit_actor_is_host_stamped() {
        let forged = json!({"payload": {"actor": {"entity_id": "attacker"}}});
        let stamped = TestHost::builder("dbms").audit_emit(true).abi_minor(4).caller_identity(true).build();
        stamped.process_host_call(Some(&ana()), "audit_emit", &forged).unwrap();
        let ev = &stamped.audit_events()[0];
        assert_eq!(ev["actor"]["entity_id"], "ent-ana");
        assert_eq!(ev["data"]["plugin_event"]["actor"]["entity_id"], "attacker");

        let legacy = TestHost::builder("dbms").audit_emit(true).abi_minor(3).caller_identity(true).build();
        legacy.process_host_call(Some(&ana()), "audit_emit", &forged).unwrap();
        assert!(legacy.audit_events()[0].get("actor").is_none());
    }
}
