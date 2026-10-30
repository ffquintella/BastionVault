//! The resource engine's `sql` protocol end to end (T124 Phase 1, subsystem
//! 5; features/sql-browser.md §5, §9.5, Testing Plan): the privileges read,
//! the host calls against the real resource engine, connect MFA for `sql`
//! profiles, the transport and type gates, and a grep of every response,
//! refusal, log line and audit entry for the planted database password.

mod resource_sql_tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use serde_json::{json, Map, Value};

    use crate::core::Core;
    use crate::errors::RvError;
    use crate::kernel_api::VaultCtx;
    use crate::logical::{Operation, Request};
    use crate::modules::resource::connect_mfa::{ConnectMfaTicketStore, TicketBinding};
    use crate::modules::system::denial_audit_store::{DenialAuditStore, SQL_PRIVILEGE_REASON};
    use crate::plugins::{
        invocation::InvocationCaller,
        manifest::PluginManifest,
        sql_grants::{self, tests_support::sql_manifest, SqlGrantKind},
        sql_host,
    };
    use crate::test_utils::{new_unseal_test_bastion_vault, test_write_api};

    const LOGIN_PASSWORD: &str = "hunter22XX!";
    /// The database password stored on the resource. Searched for in every
    /// output except the one host-call reply that releases it.
    const PLANTED: &str = "Pl4nted-db-S3cret-5e1f";
    const RESOURCE: &str = "netrisk-db";
    const PRIVILEGES: &str = "resources/v2/sql/privileges/netrisk-db";

    /// A process-wide `log` sink (nextest runs each test in its own process).
    mod capture {
        use std::sync::{Mutex, OnceLock};

        static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
        static INSTALLED: OnceLock<bool> = OnceLock::new();
        struct Capture;
        impl log::Log for Capture {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, r: &log::Record<'_>) {
                LINES.get_or_init(Default::default).lock().unwrap().push(format!("{} {}", r.target(), r.args()));
            }
            fn flush(&self) {}
        }
        static LOGGER: Capture = Capture;

        pub fn install() -> bool {
            *INSTALLED.get_or_init(|| {
                let ok = log::set_logger(&LOGGER).is_ok();
                if ok {
                    log::set_max_level(log::LevelFilter::Debug);
                }
                ok
            })
        }

        pub fn lines() -> Vec<String> {
            LINES.get_or_init(Default::default).lock().unwrap().clone()
        }
    }

    // ── fixture ─────────────────────────────────────────────────────

    struct Fixture {
        core: Arc<Core>,
        root: String,
        audit_dir: PathBuf,
        /// Every response and refusal text the test saw, for the final grep.
        seen: std::sync::Mutex<Vec<String>>,
        _vault: crate::BastionVault,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.audit_dir);
        }
    }

    fn obj(v: Value) -> Option<Map<String, Value>> {
        v.as_object().cloned()
    }

    impl Fixture {
        fn note(&self, s: impl Into<String>) {
            self.seen.lock().unwrap().push(s.into());
        }

        async fn root_write(&self, path: &str, body: Value) {
            test_write_api(self.core.as_ref(), &self.root, path, true, obj(body)).await.unwrap();
        }

        /// One request through the full pipeline; errors as `(status, text)`.
        async fn request(
            &self,
            token: &str,
            op: Operation,
            path: &str,
            data: Option<Value>,
        ) -> Result<Value, (u16, String)> {
            let mut req = Request::new(path);
            req.operation = op;
            req.client_token = token.to_string();
            match op {
                Operation::Read => req.data = data.and_then(obj),
                _ => req.body = data.and_then(obj),
            }
            let out = match self.core.handle_request(&mut req).await {
                Ok(resp) => Ok(Value::Object(resp.and_then(|r| r.data).unwrap_or_default())),
                Err(RvError::ErrResponseStatus(s, m)) => Err((s, m)),
                Err(RvError::ErrPermissionDenied) => Err((403, "permission denied".into())),
                Err(e) => Err((0, e.to_string())),
            };
            self.note(format!("{out:?}"));
            out
        }

        async fn privileges(&self, token: &str, objects: Option<&str>) -> Result<Value, (u16, String)> {
            self.request(token, Operation::Read, PRIVILEGES, objects.map(|o| json!({ "objects": o }))).await
        }

        /// A userpass user at `userpass/` carrying `policy_hcl` (plus
        /// `default`): its token and the caller a plugin invocation would see.
        async fn user(&self, name: &str, policy_hcl: &str) -> (String, InvocationCaller) {
            self.root_write(&format!("sys/policy/p-{name}"), json!({ "policy": policy_hcl })).await;
            self.root_write(
                &format!("auth/userpass/users/{name}"),
                json!({ "password": LOGIN_PASSWORD, "token_policies": format!("p-{name}"), "ttl": 0 }),
            )
            .await;
            let mut req = Request::new(format!("auth/userpass/login/{name}"));
            req.operation = Operation::Write;
            req.body = obj(json!({ "password": LOGIN_PASSWORD }));
            let mut auth = self.core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap();
            if !auth.policies.iter().any(|p| p == "default") {
                auth.policies.push("default".into());
            }
            let token = auth.client_token.clone();
            let mut caller = Request::new("dbms/v2/sessions");
            caller.client_token = token.clone();
            caller.auth = Some(auth);
            (token, InvocationCaller::from_request(&caller).unwrap())
        }

        /// One SQL host call by the granted plugin, as `caller`.
        async fn host(
            &self,
            m: &PluginManifest,
            caller: &InvocationCaller,
            method: &str,
            params: Value,
        ) -> Result<Value, String> {
            let core: Arc<dyn VaultCtx> = self.core.clone();
            let out = sql_host::handle(m, Some(&core), method, &params, Some(caller)).await;
            if method != "resource_sql_credential" || out.is_err() {
                self.note(format!("{out:?}"));
            }
            out
        }
    }

    fn sql_profile(id: &str, sql: Value, source: Value) -> Value {
        json!({ "id": id, "name": id, "protocol": "sql", "sql": sql, "credential_source": source })
    }

    fn secret(id: &str) -> Value {
        json!({ "kind": "secret", "secret_id": id })
    }

    fn profiles() -> Value {
        let ro = json!({ "catalog": "netrisk", "ceiling": ["sql_select"] });
        json!([
            sql_profile("ro", ro.clone(), secret("svc_ro")),
            sql_profile("gated", json!({ "ceiling": ["sql_select"], "require_mfa": true }), secret("svc_ro")),
            {
                "id": "moved", "protocol": "sql", "target": { "host": "attacker.example" },
                "sql": ro.clone(), "credential_source": secret("svc_ro")
            },
            sql_profile("unbound", ro.clone(), secret("svc_unbound")),
            sql_profile("missing", ro.clone(), secret("svc_nope")),
            sql_profile("dyn", ro.clone(), json!({ "kind": "dynamic", "mount": "db-mysql/", "role": "netrisk-ro" })),
            sql_profile("broken", json!({ "ceiling": "sql_select" }), secret("svc_ro")),
            { "id": "shell", "name": "shell", "protocol": "ssh", "credential_source": secret("svc_ro") },
            sql_profile(
                "stepup",
                json!({ "catalog": "netrisk", "ceiling": ["sql_select"], "step_up": ["sql_drop", "sql_export", "sql_script"] }),
                secret("svc_ro")
            )
        ])
    }

    async fn fixture(name: &str) -> Fixture {
        capture::install();
        let (vault, core, root) = new_unseal_test_bastion_vault(name).await;
        let audit_dir = std::env::temp_dir().join(format!(
            "bv-resource-sql-{name}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&audit_dir).unwrap();
        let f = Fixture { core, root, audit_dir, seen: Default::default(), _vault: vault };
        let log = f.audit_dir.join("audit.log");
        f.root_write(
            "sys/audit/primary",
            json!({ "type": "file", "options": { "file_path": log.display().to_string() } }),
        )
        .await;
        f.root_write("sys/auth/userpass", json!({ "type": "userpass" })).await;
        f.root_write(
            &format!("resources/resources/{RESOURCE}"),
            json!({
                "name": RESOURCE, "type": "database", "engine": "mysql",
                "hostname": "db1.example.net", "connection_profiles": profiles()
            }),
        )
        .await;
        f.root_write(
            &format!("resources/secrets/{RESOURCE}/svc_ro"),
            json!({ "username": "svc_netrisk_ro", "password": PLANTED, "sql_endpoint": "DB1.example.net:3306" }),
        )
        .await;
        f.root_write(
            &format!("resources/secrets/{RESOURCE}/svc_unbound"),
            json!({ "username": "svc_netrisk_ro", "password": PLANTED }),
        )
        .await;
        f
    }

    async fn granted_plugin(f: &Fixture) -> PluginManifest {
        let m = sql_manifest();
        for k in SqlGrantKind::ALL {
            sql_grants::put(f.core.barrier().as_storage(), k, &m, "admin", "t".into()).await.unwrap();
        }
        m
    }

    const READER: &str = r#"path "resources/resources/netrisk-db/sql/*" { capabilities = ["sql_select"] }"#;
    /// A policy that grants nothing this test touches.
    const NOTHING: &str = r#"path "secret/data/unrelated" { capabilities = ["read"] }"#;

    fn code(e: &str) -> (&str, &str) {
        let mut parts = e.splitn(3, ": ");
        (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
    }

    /// The final grep (Testing Plan, "Security regressions"): no response,
    /// refusal, log line or audit entry carries the planted password.
    fn assert_never_leaked(f: &Fixture) {
        for s in f.seen.lock().unwrap().iter() {
            assert!(!s.contains(PLANTED), "a response or refusal carries the password: {s}");
        }
        let lines = capture::lines();
        // Under nextest the sink is this process's logger; make sure it saw
        // the run, or the grep below would pass vacuously.
        assert!(!capture::install() || !lines.is_empty(), "the log sink captured nothing");
        for l in lines {
            assert!(!l.contains(PLANTED), "a log line carries the password: {l}");
        }
        let audit = std::fs::read_to_string(f.audit_dir.join("audit.log")).unwrap_or_default();
        assert!(!audit.is_empty(), "the audit device recorded nothing");
        assert!(!audit.contains(PLANTED), "the audit log carries the password");
    }

    // ── privileges ──────────────────────────────────────────────────

    /// `v2/sql/privileges/<resource>` reports the caller's own capabilities
    /// on `sql/server`, resource-wide and per object, through every arm the
    /// gate resolves (policy, object scope, share via the baseline), and
    /// records no denial.
    #[tokio::test]
    async fn the_privileges_read_reports_the_callers_own_capabilities() {
        let f = fixture("sql_privileges").await;
        let (ana, _) = f.user("ana", READER).await;
        let scoped = r#"
            path "resources/resources/netrisk-db/sql/server" { capabilities = ["sql_select"] }
            path "resources/resources/netrisk-db/sql/objects/netrisk/public/*" { capabilities = ["sql_update", "sql_select"] }
        "#;
        let (dana, _) = f.user("dana", scoped).await;
        let (bob, _) = f.user("bob", NOTHING).await;

        let a = f.privileges(&ana, Some("netrisk/public/users")).await.unwrap();
        assert_eq!(a["server"], json!(["sql_select"]));
        assert_eq!(a["resource_wide"], json!(["sql_select"]));
        assert_eq!(a["objects"][0]["capabilities"], json!(["sql_select"]));
        assert_eq!(a["objects"][0]["addressable"], json!(true));

        let d = f.privileges(&dana, Some("netrisk/public/users,netrisk/pci/cards,a%2Fb/s/o")).await.unwrap();
        assert_eq!(d["server"], json!(["sql_select"]));
        assert_eq!(d["resource_wide"], json!([]), "an object-scoped grant is not resource-wide");
        assert_eq!(d["objects"][0]["capabilities"], json!(["sql_select", "sql_update"]));
        assert_eq!(d["objects"][1]["capabilities"], json!([]));
        assert_eq!(d["objects"][2]["addressable"], json!(false), "a `/` in a name cannot be addressed");
        assert_eq!(d["objects"][2]["capabilities"], json!([]));

        let b = f.privileges(&bob, None).await.unwrap();
        assert_eq!((b["server"].clone(), b["resource_wide"].clone()), (json!([]), json!([])));

        // A share naming `sql_select` reaches bob through `default`'s rule.
        let bob_entity = crate::modules::identity::EntityStore::new(&f.core)
            .await
            .unwrap()
            .get_by_alias_ns("userpass/", "bob", "")
            .await
            .unwrap()
            .unwrap()
            .id;
        let target = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, RESOURCE);
        f.root_write(
            &format!("identity/sharing/by-target/resource/{target}/{bob_entity}"),
            json!({ "target_kind": "resource", "target_path": RESOURCE, "capabilities": "sql_select" }),
        )
        .await;
        let b = f.privileges(&bob, None).await.unwrap();
        assert_eq!(b["server"], json!(["sql_select"]));

        for bad in ["a/b", "a/b/%zz"] {
            let e = f.privileges(&ana, Some(bad)).await.unwrap_err();
            assert_eq!(e.0, 400, "{bad}: {e:?}");
        }

        let denials = DenialAuditStore::from_core(f.core.as_ref()).unwrap().list_all().await.unwrap();
        assert!(denials.iter().all(|e| e.reason != SQL_PRIVILEGE_REASON), "a display read records nothing");
        assert_never_leaked(&f);
    }

    // ── host calls ──────────────────────────────────────────────────

    /// `resource_sql_target` and `resource_sql_credential` against the real
    /// engine: the strictly parsed view, every §5.4 refusal, the one release,
    /// and the password nowhere else.
    #[tokio::test]
    async fn the_host_calls_read_the_resource_engine_and_refuse_closed() {
        let f = fixture("sql_host_engine").await;
        let m = granted_plugin(&f).await;
        let (_, ana) = f.user("ana", READER).await;
        let (_, bob) = f.user("bob", NOTHING).await;

        let t = f.host(&m, &ana, "resource_sql_target", json!({ "resource": "NetRisk-DB" })).await.unwrap();
        let target = &t["target"];
        assert_eq!(t["privileges"], json!(["sql_select"]));
        assert_eq!((target["engine"].clone(), target["default_port"].clone()), (json!("mysql"), json!(3306)));
        assert_eq!(target["enforcement"], "database-first");
        assert_eq!(
            (target["transport"].clone(), target["transport_source"].clone()),
            (json!("direct"), json!("default"))
        );
        let ids: Vec<&str> = target["profiles"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["ro", "gated", "moved", "unbound", "missing", "dyn", "stepup"]);
        let ro = &target["profiles"][0];
        assert_eq!(ro["endpoint"], "db1.example.net:3306");
        assert_eq!(ro["tls"]["mode"], "verify-full");
        assert_eq!(ro["credential_source"], json!({ "kind": "secret", "secret_id": "svc_ro" }));
        assert_eq!(target["profiles"][2]["endpoint"], "attacker.example:3306");
        assert_eq!(target["invalid_profiles"][0]["id"], "broken");
        assert_eq!(target["invalid_profiles"][0]["reason"], "invalid_profile");

        let release = |profile: &str| json!({ "resource": RESOURCE, "profile": profile, "session_ref": "s-1" });
        let ok = f.host(&m, &ana, "resource_sql_credential", release("ro")).await.unwrap();
        assert_eq!((ok["username"].as_str(), ok["password"].as_str()), (Some("svc_netrisk_ro"), Some(PLANTED)));
        assert_eq!(ok["endpoint"], "db1.example.net:3306");

        for (profile, expected) in [
            ("moved", ("refused", "endpoint_mismatch")),
            ("unbound", ("refused", "endpoint_unbound")),
            ("missing", ("refused", "credential_missing")),
            ("dyn", ("refused", "dynamic_not_available")),
            ("broken", ("refused", "invalid_profile")),
            ("shell", ("refused", "profile_not_sql")),
            ("gated", ("refused", "mfa_required")),
            ("nope", ("not_found", "profile_not_found")),
        ] {
            let e = f.host(&m, &ana, "resource_sql_credential", release(profile)).await.unwrap_err();
            assert_eq!(code(&e), expected, "{profile}: {e}");
        }
        let e = f.host(&m, &bob, "resource_sql_credential", release("ro")).await.unwrap_err();
        assert_eq!(code(&e).0, "no_sql_privilege", "{e}");
        let e = f.host(&m, &bob, "resource_sql_target", json!({ "resource": RESOURCE })).await.unwrap_err();
        assert_eq!(code(&e).0, "no_sql_privilege", "{e}");

        let audit = std::fs::read_to_string(f.audit_dir.join("audit.log")).unwrap();
        let reasons: Vec<String> = audit
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|e| e["request"]["path"] == sql_host::RELEASE_EVENT)
            .map(|e| e["request"]["data"]["reason"].as_str().unwrap_or("released").to_string())
            .collect();
        for r in ["released", "endpoint_mismatch", "credential_missing", "dynamic_not_available", "mfa_required"] {
            assert!(reasons.iter().any(|x| x == r), "{r} missing from the release audit: {reasons:?}");
        }
        assert_never_leaked(&f);
    }

    /// `rustion-required` at any tier refuses the release (§6.6), naming the
    /// tier; the target still reports the transport.
    #[tokio::test]
    async fn a_rustion_required_resource_is_refused() {
        use bv_engine_rustion::policy::{PolicyStore, PolicyTier, ResourcePolicy, Transport};
        let f = fixture("sql_rustion_required").await;
        let m = granted_plugin(&f).await;
        let (_, ana) = f.user("ana", READER).await;
        let store = PolicyStore::new(f.core.as_ref()).await.unwrap();
        let tier = PolicyTier { transport: Some(Transport::RustionRequired), ..Default::default() };
        store.put_resource(&ResourcePolicy { resource_id: RESOURCE.into(), tier, ..Default::default() }).await.unwrap();

        let t = f.host(&m, &ana, "resource_sql_target", json!({ "resource": RESOURCE })).await.unwrap();
        assert_eq!(t["target"]["transport"], "rustion-required");
        assert_eq!(t["target"]["transport_source"], "resource");
        let params = json!({ "resource": RESOURCE, "profile": "ro", "session_ref": "s-1" });
        let e = f.host(&m, &ana, "resource_sql_credential", params).await.unwrap_err();
        assert_eq!(code(&e), ("refused", "rustion_required"), "{e}");
        assert!(e.contains("resource"), "the refusal names the tier: {e}");
        assert_never_leaked(&f);
    }

    /// Only `database` resources of the five engines, and only while the
    /// type configuration offers `sql`.
    #[tokio::test]
    async fn the_type_and_engine_gates_refuse() {
        let f = fixture("sql_type_gates").await;
        let m = granted_plugin(&f).await;
        let any = r#"path "resources/resources/+/sql/*" { capabilities = ["sql_select"] }"#;
        let (_, ana) = f.user("ana", any).await;
        let p = profiles();
        f.root_write(
            "resources/resources/web01",
            json!({ "type": "server", "hostname": "web01", "connection_profiles": p }),
        )
        .await;
        f.root_write(
            "resources/resources/cache01",
            json!({ "type": "database", "engine": "redis", "hostname": "cache01", "connection_profiles": p }),
        )
        .await;
        let target = |r: &str| json!({ "resource": r });
        let e = f.host(&m, &ana, "resource_sql_target", target("web01")).await.unwrap_err();
        assert_eq!(code(&e), ("refused", "not_a_database"), "{e}");
        let e = f.host(&m, &ana, "resource_sql_target", target("cache01")).await.unwrap_err();
        assert_eq!(code(&e), ("refused", "engine_unsupported"), "{e}");
        let e = f.host(&m, &ana, "resource_sql_target", target("ghost")).await.unwrap_err();
        assert_eq!(code(&e), ("not_found", "resource_not_found"), "{e}");

        f.root_write(
            "resources/config/types",
            json!({ "database": { "id": "database", "connect": { "protocols": ["ssh"] } } }),
        )
        .await;
        let e = f.host(&m, &ana, "resource_sql_target", target(RESOURCE)).await.unwrap_err();
        assert_eq!(code(&e), ("refused", "sql_disabled_for_type"), "{e}");
        let params = json!({ "resource": RESOURCE, "profile": "ro", "session_ref": "s-1" });
        let e = f.host(&m, &ana, "resource_sql_credential", params).await.unwrap_err();
        assert_eq!(code(&e), ("refused", "sql_disabled_for_type"), "{e}");
        f.root_write("resources/config/types", json!({ "database": { "connect": { "protocols": ["sql"] } } })).await;
        assert!(f.host(&m, &ana, "resource_sql_target", target(RESOURCE)).await.is_ok());
        assert_never_leaked(&f);
    }

    // ── connect MFA ─────────────────────────────────────────────────

    /// `connect/mfa/begin|verify` accept `sql` profiles for a SQL-only
    /// caller (no `connect`), refuse a broken one before any factor, and a
    /// ticket the plugin redeems unlocks exactly one release.
    #[tokio::test]
    async fn connect_mfa_accepts_sql_profiles_and_gates_the_release() {
        let f = fixture("sql_connect_mfa").await;
        let m = granted_plugin(&f).await;
        let (ana_token, ana) = f.user("ana", READER).await;
        let (bob_token, _) = f.user("bob", NOTHING).await;
        let begin = |profile: &str| json!({ "resource": RESOURCE, "profile_id": profile });

        let r =
            f.request(&ana_token, Operation::Write, "resources/v2/connect/mfa/begin", Some(begin("ro"))).await.unwrap();
        assert_eq!(r["required"], json!(false));
        let e = f.request(&ana_token, Operation::Write, "resources/v2/connect/mfa/begin", Some(begin("gated"))).await;
        let (status, text) = e.unwrap_err();
        assert_eq!(status, 403);
        assert!(text.starts_with("mfa_unavailable: "), "the gate applies; ana has no factor enrolled: {text}");
        let e = f.request(&ana_token, Operation::Write, "resources/v2/connect/mfa/begin", Some(begin("broken"))).await;
        let (status, text) = e.unwrap_err();
        assert_eq!(status, 422, "{text}");
        assert!(text.starts_with("invalid_profile: "), "{text}");
        let verify = json!({ "resource": RESOURCE, "profile_id": "ro", "method": "totp", "totp_code": "000000" });
        let e = f.request(&ana_token, Operation::Write, "resources/v2/connect/mfa/verify", Some(verify)).await;
        assert_eq!(e.unwrap_err().0, 400, "an ungated profile needs no ticket");
        let e = f.request(&bob_token, Operation::Write, "resources/v2/connect/mfa/begin", Some(begin("gated"))).await;
        assert_eq!(e.unwrap_err().0, 403, "neither an SQL capability nor `connect`");

        // `connect/authorize` never touches an sql profile's ticket.
        let e = f.request(&f.root, Operation::Write, "resources/v2/connect/authorize", Some(begin("gated"))).await;
        let (status, text) = e.unwrap_err();
        assert_eq!(status, 400);
        assert!(text.starts_with("sql_profile_not_direct: "), "{text}");

        // A ticket as `verify` mints it, redeemed by the plugin.
        let binding = TicketBinding {
            mount: "userpass/".into(),
            principal: "ana".into(),
            namespace: String::new(),
            resource: RESOURCE.into(),
            profile_id: "gated".into(),
            mcp_call: None,
            action: None,
        };
        let store = ConnectMfaTicketStore::new(f.core.as_ref()).unwrap();
        let (ticket, _) = store.mint(&binding, "totp").await.unwrap();
        let release = json!({ "resource": RESOURCE, "profile": "gated", "session_ref": "s-1" });
        let redeem = json!({ "resource": RESOURCE, "profile": "gated", "ticket": ticket });
        let r = f.host(&m, &ana, "connect_ticket_redeem", redeem.clone()).await.unwrap();
        assert_eq!(r["redeemed"], json!(true));
        let ok = f.host(&m, &ana, "resource_sql_credential", release.clone()).await.unwrap();
        assert_eq!(ok["password"], PLANTED);
        let e = f.host(&m, &ana, "resource_sql_credential", release).await.unwrap_err();
        assert_eq!(code(&e), ("refused", "mfa_required"), "one ticket, one release: {e}");
        let e = f.host(&m, &ana, "connect_ticket_redeem", redeem).await.unwrap_err();
        assert_eq!(code(&e).0, "refused", "the ticket is spent: {e}");
        assert_never_leaked(&f);
    }

    /// T126, §8.3: a step-up ticket is bound to its canonical action. A
    /// ticket without an action (a connect ticket, or one written before
    /// T126) is never accepted for an action; an action ticket never opens a
    /// connect nor unlocks a `require_mfa` release; `begin` / `verify` refuse
    /// an action the stored profile does not gate before any factor.
    #[tokio::test]
    async fn step_up_tickets_are_bound_to_their_action() {
        let f = fixture("sql_step_up_action").await;
        let m = granted_plugin(&f).await;
        let (ana_token, ana) = f.user("ana", READER).await;
        let begin = |profile: &str, action: Value| json!({ "resource": RESOURCE, "profile_id": profile, "action": action });
        let path = "resources/v2/connect/mfa/begin";

        // Before any factor: an action the profile does not gate, a
        // malformed one, and an action on a profile that is not `sql`.
        let e = f.request(&ana_token, Operation::Write, path, Some(begin("ro", json!("sql_drop")))).await.unwrap_err();
        assert_eq!(e.0, 400, "{e:?}");
        assert!(e.1.starts_with("step_up_not_required: "), "{e:?}");
        let e = f.request(&ana_token, Operation::Write, path, Some(begin("stepup", json!("sql_drop,sql_admin")))).await;
        assert!(e.unwrap_err().1.contains("`sql_admin`"), "sql_admin is not in this profile's step_up");
        for bad in [json!("sql_nope"), json!(""), json!(5), json!(["sql_drop", 1]), json!("sql_drop,sql_drop")] {
            let e = f.request(&ana_token, Operation::Write, path, Some(begin("stepup", bad.clone()))).await;
            assert_eq!(e.unwrap_err().0, 400, "{bad}");
        }
        let e = f.request(&f.root, Operation::Write, path, Some(begin("shell", json!("sql_drop")))).await.unwrap_err();
        assert_eq!(e.0, 400, "an ssh profile has no SQL actions: {e:?}");
        let verify = json!({ "resource": RESOURCE, "profile_id": "ro", "method": "totp", "totp_code": "000000",
            "action": "sql_drop" });
        let e = f.request(&ana_token, Operation::Write, "resources/v2/connect/mfa/verify", Some(verify)).await;
        assert!(e.unwrap_err().1.starts_with("step_up_not_required: "), "refused before the ceremony");
        // A gated action reaches the factor check (ana has none enrolled),
        // in any order and as a list.
        let e = f.request(&ana_token, Operation::Write, path, Some(begin("stepup", json!(["sql_script", "sql_drop"]))));
        let (status, text) = e.await.unwrap_err();
        assert_eq!(status, 403);
        assert!(text.starts_with("mfa_unavailable: "), "the step-up applies: {text}");

        let store = ConnectMfaTicketStore::new(f.core.as_ref()).unwrap();
        let bind = |profile: &str, action: Option<&str>| TicketBinding {
            mount: "userpass/".into(),
            principal: "ana".into(),
            namespace: String::new(),
            resource: RESOURCE.into(),
            profile_id: profile.into(),
            mcp_call: None,
            action: action.map(str::to_string),
        };
        let redeem = |profile: &str, ticket: &str, action: Option<&str>| {
            let mut p = json!({ "resource": RESOURCE, "profile": profile, "ticket": ticket });
            if let Some(a) = action {
                p["action"] = json!(a);
            }
            p
        };

        // The action ticket redeems once, for its action in any order.
        let (t, _) = store.mint(&bind("stepup", Some("sql_drop,sql_script")), "totp").await.unwrap();
        let r = f.host(&m, &ana, "connect_ticket_redeem", redeem("stepup", &t, Some("sql_script,sql_drop"))).await;
        let r = r.unwrap();
        assert_eq!((r["redeemed"].clone(), r["action"].clone()), (json!(true), json!("sql_drop,sql_script")));
        let e = f.host(&m, &ana, "connect_ticket_redeem", redeem("stepup", &t, Some("sql_drop,sql_script"))).await;
        assert_eq!(code(&e.unwrap_err()).0, "refused", "spent");

        // Regression: a ticket without an action is not accepted for one.
        let (t, _) = store.mint(&bind("stepup", None), "totp").await.unwrap();
        let e = f.host(&m, &ana, "connect_ticket_redeem", redeem("stepup", &t, Some("sql_drop"))).await.unwrap_err();
        assert_eq!(code(&e).0, "refused", "{e}");
        assert!(e.contains("issued for a connect"), "{e}");
        // Nor is one bound to another action, or to a subset.
        let (t, _) = store.mint(&bind("stepup", Some("sql_drop")), "totp").await.unwrap();
        let e = f.host(&m, &ana, "connect_ticket_redeem", redeem("stepup", &t, Some("sql_drop,sql_script"))).await;
        assert_eq!(code(&e.unwrap_err()).0, "refused");
        let (t, _) = store.mint(&bind("stepup", Some("sql_export")), "totp").await.unwrap();
        let e = f.host(&m, &ana, "connect_ticket_redeem", redeem("stepup", &t, Some("sql_drop"))).await;
        assert_eq!(code(&e.unwrap_err()).0, "refused");

        // An action ticket never opens a gated session, and redeeming it
        // for its action records no connect redemption.
        let release = json!({ "resource": RESOURCE, "profile": "gated", "session_ref": "s-1" });
        let (t, _) = store.mint(&bind("gated", Some("sql_drop")), "totp").await.unwrap();
        let e = f.host(&m, &ana, "connect_ticket_redeem", redeem("gated", &t, None)).await.unwrap_err();
        assert!(e.contains("issued for a SQL step-up action"), "{e}");
        let (t, _) = store.mint(&bind("gated", Some("sql_drop")), "totp").await.unwrap();
        let r = f.host(&m, &ana, "connect_ticket_redeem", redeem("gated", &t, Some("sql_drop"))).await.unwrap();
        assert_eq!(r["redeemed"], json!(true));
        let e = f.host(&m, &ana, "resource_sql_credential", release).await.unwrap_err();
        assert_eq!(code(&e), ("refused", "mfa_required"), "an action ticket is not a connect: {e}");
        assert_never_leaked(&f);
    }

    /// `sql_endpoint` is reserved on resource secrets: a malformed binding
    /// is refused at write time; a well-formed one and an unbinding are not.
    #[tokio::test]
    async fn the_sql_endpoint_key_is_reserved_on_secret_writes() {
        let f = fixture("sql_endpoint_reserved").await;
        let path = format!("resources/secrets/{RESOURCE}/svc_rw");
        for bad in [json!("db1.example.net"), json!(3306), json!(["db1:3306", "nope"])] {
            let body = json!({ "username": "rw", "password": PLANTED, "sql_endpoint": bad });
            let e = f.request(&f.root, Operation::Write, &path, Some(body)).await.unwrap_err();
            assert_eq!(e.0, 400, "{bad}: {e:?}");
        }
        for good in [json!("db1:3306"), json!(["db1:3306", "[fd00::1]:3306"]), json!(null), json!([])] {
            let body = json!({ "username": "rw", "password": PLANTED, "sql_endpoint": good });
            assert!(f.request(&f.root, Operation::Write, &path, Some(body)).await.is_ok(), "{good}");
        }
    }
}
