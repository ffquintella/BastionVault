//! Connect with a credential provider, end to end: the real host, the real
//! resource and Rustion engines, and the real `bastion-plugin-self-accounts`
//! wasm (features/self-accounts.md, T103 Phase 3).
//!
//! Drives `resources/v2/connect/provider/candidates`, the `provider` arm of
//! `resources/v2/connect/authorize`, `resources/v2/connect/web/launch` and
//! `rustion/v2/session/open` through the full request pipeline (token, ACL,
//! audit), and checks that the released password appears in no audit device
//! entry, no log line, no refusal text and no candidates response.
//!
//! `#[ignore]`d for the reason `self_accounts_host` is: it needs the
//! `wasm32-unknown-unknown` build of the plugin. `make plugins-test` builds it
//! and runs both with `--run-ignored only`.

mod self_accounts_connect_tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use serde_json::{json, Map, Value};

    use crate::core::Core;
    use crate::errors::RvError;
    use crate::kernel_api::VaultCtx;
    use crate::logical::{Operation, Request};
    use crate::modules::resource::connect_mfa::{ConnectMfaTicketStore, TicketBinding};
    use crate::modules::resource::connect_web::recipe::recipe_hash;
    use crate::plugins::{provider as grants, PluginCatalog};
    use crate::test_utils::{new_unseal_test_bastion_vault, test_mount_api, test_write_api};

    use super::super::self_accounts_host::self_accounts_host_tests::{manifest, wasm};

    const LOGIN_PASSWORD: &str = "hunter22XX!";
    /// The self-account secrets. Searched for in every output the server
    /// produces to prove none of them carries a released credential.
    const RDP_PASSWORD: &str = "S3lf-acct-RDP-pw-91c2";
    const WEB_PASSWORD: &str = "S3lf-acct-WEB-pw-4be7";

    const CANDIDATES: &str = "resources/v2/connect/provider/candidates";
    const PROVIDERS: &str = "resources/v2/connect/providers";
    const AUTHORIZE: &str = "resources/v2/connect/authorize";
    const LAUNCH: &str = "resources/v2/connect/web/launch";
    const OPEN: &str = "rustion/v2/session/open";

    // ── log capture ─────────────────────────────────────────────────

    /// A process-wide `log` sink. nextest runs each test in its own process,
    /// so the first `install` wins and sees every line the server writes.
    mod capture {
        use std::sync::{Mutex, OnceLock};

        static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
        static INSTALLED: OnceLock<bool> = OnceLock::new();

        struct Capture;

        /// The wasm compiler's own debug output is large and not ours.
        const QUIET: [&str; 4] = ["cranelift", "wasmtime", "regalloc", "wasmparser"];

        impl log::Log for Capture {
            fn enabled(&self, m: &log::Metadata<'_>) -> bool {
                !QUIET.iter().any(|q| m.target().starts_with(q))
            }
            fn log(&self, r: &log::Record<'_>) {
                if self.enabled(r.metadata()) {
                    let line = format!("{} {}", r.target(), r.args());
                    LINES.get_or_init(Default::default).lock().unwrap().push(line);
                }
            }
            fn flush(&self) {}
        }

        static LOGGER: Capture = Capture;

        /// `true` when this module's sink is the process logger.
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
        alice: String,
        bob: String,
        mallory: String,
        audit_log: PathBuf,
        /// Owns `audit_log` and the sidecars the audit reconciler writes next
        /// to it (`<log>.reconcile-cursor`).
        audit_dir: PathBuf,
        _vault: crate::BastionVault,
    }

    /// The audit device writes into a per-fixture directory under the system
    /// temp dir; remove it with the fixture so a run leaves nothing behind
    /// (the device's open handle keeps writing to the unlinked file until the
    /// vault drops).
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.audit_dir);
        }
    }

    fn obj(v: Value) -> Option<Map<String, Value>> {
        v.as_object().cloned()
    }

    /// Write through the full pipeline without printing the response (it may
    /// carry a credential). Errors come back as `(status, message)`.
    async fn call(core: &dyn VaultCtx, token: &str, path: &str, body: Value) -> Result<Map<String, Value>, (u16, String)> {
        let mut req = Request::new(path);
        req.operation = Operation::Write;
        req.client_token = token.to_string();
        req.body = body.as_object().cloned();
        match core.handle_request(&mut req).await {
            Ok(resp) => Ok(resp.and_then(|r| r.data).unwrap_or_default()),
            Err(RvError::ErrResponseStatus(s, m)) => Err((s, m)),
            Err(RvError::ErrPermissionDenied) => Err((403, "permission denied".into())),
            Err(e) => Err((0, e.to_string())),
        }
    }

    /// Read through the full pipeline; panics on a refusal.
    async fn read(core: &dyn VaultCtx, token: &str, path: &str) -> Map<String, Value> {
        let mut req = Request::new(path);
        req.operation = Operation::Read;
        req.client_token = token.to_string();
        core.handle_request(&mut req)
            .await
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .and_then(|r| r.data)
            .unwrap_or_default()
    }

    /// Assert a refusal by status and message prefix, and return its text.
    fn refused(r: Result<Map<String, Value>, (u16, String)>, status: u16, prefix: &str) -> String {
        match r {
            Ok(d) => panic!("expected {status} {prefix}, got success with keys {:?}", d.keys().collect::<Vec<_>>()),
            Err((s, m)) => {
                assert_eq!(s, status, "status for `{prefix}`: {m}");
                assert!(m.starts_with(prefix), "expected `{prefix}…`, got `{m}`");
                m
            }
        }
    }

    async fn root_write(f: &Fixture, path: &str, body: Value) {
        test_write_api(f.core.as_ref(), &f.root, path, true, obj(body)).await.unwrap();
    }

    /// A userpass user at `userpass/` (the mount the connect-MFA ticket binds)
    /// carrying `policy_hcl`; returns its token, which carries an entity.
    async fn user(core: &Arc<Core>, root: &str, name: &str, policy_hcl: &str) -> String {
        let _ = call(core.as_ref(), root, "sys/auth/userpass", json!({ "type": "userpass" })).await;
        test_write_api(core.as_ref(), root, &format!("sys/policy/p-{name}"), true, obj(json!({ "policy": policy_hcl })))
            .await
            .unwrap();
        test_write_api(
            core.as_ref(),
            root,
            &format!("auth/userpass/users/{name}"),
            true,
            obj(json!({ "password": LOGIN_PASSWORD, "token_policies": format!("p-{name}"), "ttl": 0 })),
        )
        .await
        .unwrap();
        let mut req = Request::new(format!("auth/userpass/login/{name}"));
        req.operation = Operation::Write;
        req.body = obj(json!({ "password": LOGIN_PASSWORD }));
        let auth = core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap();
        assert!(!auth.metadata.get("entity_id").cloned().unwrap_or_default().is_empty(), "login must stamp an entity");
        auth.client_token
    }

    fn policy(connect_to: &[&str]) -> String {
        let mut p = String::from(
            r#"
            path "self-accounts/*" { capabilities = ["create","read","update","delete","list"] }
            path "resources/v2/connect/*" { capabilities = ["update"] }
            path "rustion/v2/session/open" { capabilities = ["update"] }
            "#,
        );
        for r in connect_to {
            p.push_str(&format!("path \"resources/secrets/{r}/*\" {{ capabilities = [\"connect\"] }}\n"));
        }
        p
    }

    fn provider_source() -> Value {
        json!({ "kind": "provider", "provider": "self-accounts" })
    }

    fn dc01(hostname: &str) -> Value {
        json!({
            "name": "dc01", "type": "server", "os_type": "windows", "hostname": hostname,
            "connection_profiles": [
                { "id": "p_rdp", "name": "Self-account", "protocol": "rdp", "require_mfa": true,
                  "credential_source": provider_source() },
                { "id": "p_rdp_open", "name": "Self-account, no MFA", "protocol": "rdp",
                  "credential_source": provider_source() },
                { "id": "p_secret", "name": "Shared", "protocol": "rdp",
                  "credential_source": { "kind": "secret", "secret_id": "admin" } },
                { "id": "p_other", "name": "Unknown provider", "protocol": "rdp", "require_mfa": true,
                  "credential_source": { "kind": "provider", "provider": "not-a-provider" } }
            ]
        })
    }

    fn web_recipe() -> Value {
        json!({ "version": 1, "steps": [ { "when_url": "https://fw01.example.com/login*", "actions": [
            { "fill": "#user", "value": "username" }, { "fill": "#pass", "value": "password" }, { "submit": "form" }
        ] } ], "success_when": { "url": "https://fw01.example.com/ng/*" } })
    }

    fn fw01() -> Value {
        let web = |allowed: Value| {
            json!({ "start_url": "https://fw01.example.com/login", "allowed_origins": allowed,
                    "login_mode": "form", "recipe": web_recipe() })
        };
        json!({
            "name": "fw01", "type": "web_application",
            "connection_profiles": [
                { "id": "p_web", "name": "Self-account", "protocol": "web", "require_mfa": true,
                  "credential_source": provider_source(), "web": web(json!([])) },
                // A second origin the account is not bound to: every fill
                // origin must match, so this one releases nothing.
                { "id": "p_web_wide", "name": "Wide", "protocol": "web", "require_mfa": true,
                  "credential_source": provider_source(), "web": web(json!(["https://sso.other.example"])) }
            ]
        })
    }

    async fn setup(name: &str) -> Fixture {
        let installed = capture::install();
        let (vault, core, root) = new_unseal_test_bastion_vault(name).await;

        // The provider: registered, mounted and approved.
        let bin = wasm();
        let m = manifest(&bin);
        crate::plugins::verifier::write_accept_unsigned(core.barrier.as_storage(), true).await.unwrap();
        PluginCatalog::new().put(core.barrier.as_storage(), &m, &bin).await.expect("register plugin");
        test_mount_api(core.as_ref(), &root, "plugin:self-accounts", "self-accounts/").await;
        grants::put_grant(core.barrier.as_storage(), &m, "admin", "2026-10-07T00:00:00Z".into()).await.unwrap();

        // An audit device, so the response entries can be searched.
        let audit_dir = std::env::temp_dir().join(format!(
            "bv-sa-connect-{name}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&audit_dir).unwrap();
        let audit_log = audit_dir.join("audit.log");
        let broker = core.audit_broker.load().as_ref().cloned().expect("broker installed at unseal");
        let mut options = HashMap::new();
        options.insert("file_path".to_string(), audit_log.display().to_string());
        broker
            .enable_device(crate::audit::AuditDeviceConfig {
                path: "sa-connect".into(),
                device_type: "file".into(),
                description: String::new(),
                options,
                namespace: String::new(),
                mirror: false,
            })
            .await
            .unwrap();

        let alice = user(&core, &root, "alice", &policy(&["dc01", "fw01"])).await;
        let bob = user(&core, &root, "bob", &policy(&["dc01"])).await;
        let mallory = user(&core, &root, "mallory", &policy(&[])).await;
        let f = Fixture { core, root, alice, bob, mallory, audit_log, audit_dir, _vault: vault };

        root_write(&f, "resources/resources/dc01", dc01("dc01.corp.example.com")).await;
        root_write(&f, "resources/secrets/dc01/admin", json!({ "username": "Administrator", "password": "shared" })).await;
        root_write(
            &f,
            "resources/config/types",
            json!({ "web_application": { "id": "web_application", "fields": [],
                    "connect": { "web_exposure_max": "dom" } } }),
        )
        .await;
        root_write(&f, "resources/resources/fw01", fw01()).await;
        assert!(installed, "the log capture must be the process logger (run under nextest)");
        f
    }

    /// Alice's RDP account, bound to `*.corp.example.com`.
    async fn rdp_account(f: &Fixture) -> String {
        let r = call(
            f.core.as_ref(),
            &f.alice,
            "self-accounts/v2/accounts",
            json!({
                "label": "Domain admin", "username": "felipe.adm", "domain": "CORP",
                "secret_kind": "password", "password": RDP_PASSWORD,
                "resource_types": ["server"], "os_types": ["windows"], "protocols": ["rdp"],
                "targets": "*.corp.example.com",
            }),
        )
        .await
        .expect("create the RDP account");
        r["id"].as_str().unwrap().to_string()
    }

    /// Alice's web account, bound to `https://fw01.example.com` only.
    async fn web_account(f: &Fixture) -> String {
        let r = call(
            f.core.as_ref(),
            &f.alice,
            "self-accounts/v2/accounts",
            json!({
                "label": "Firewall", "username": "fwadmin",
                "secret_kind": "password", "password": WEB_PASSWORD,
                "resource_types": ["web_application"], "protocols": ["web"],
                "targets": "https://fw01.example.com",
            }),
        )
        .await
        .expect("create the web account");
        r["id"].as_str().unwrap().to_string()
    }

    /// A connect MFA ticket, as `connect/mfa/verify` would mint it after a
    /// factor ceremony (the ceremony itself is tested in `resource::gate_tests`).
    async fn ticket(f: &Fixture, principal: &str, resource: &str, profile_id: &str) -> String {
        let binding = TicketBinding {
            mount: "userpass/".into(),
            principal: principal.into(),
            namespace: String::new(),
            resource: resource.into(),
            profile_id: profile_id.into(),
        };
        ConnectMfaTicketStore::new(f.core.as_ref()).unwrap().mint(&binding, "totp").await.unwrap().0
    }

    fn body(resource: &str, profile_id: &str, extra: Value) -> Value {
        let mut b = json!({ "resource": resource, "profile_id": profile_id });
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            b[k] = v;
        }
        b
    }

    /// The released passwords appear in no audit device entry, no log line
    /// and no error text collected during the test.
    fn assert_no_secret_anywhere(f: &Fixture, errors: &[String]) {
        let audit = std::fs::read_to_string(&f.audit_log).unwrap_or_default();
        assert!(!audit.is_empty(), "the audit device recorded nothing");
        let logs = capture::lines().join("\n");
        for secret in [RDP_PASSWORD, WEB_PASSWORD] {
            assert!(!audit.contains(secret), "the audit device holds a released password");
            assert!(!logs.contains(secret), "a log line holds a released password");
            for e in errors {
                assert!(!e.contains(secret), "a refusal echoes a released password: {e}");
            }
        }
    }

    fn audit_lines(prefix: &str) -> Vec<String> {
        capture::lines().into_iter().filter(|l| l.starts_with(&format!("audit {prefix}"))).collect()
    }

    // ── candidates ──────────────────────────────────────────────────

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn candidates_need_the_connect_grant_and_read_only_stored_metadata() {
        let f = setup("sa_conn_candidates").await;
        let id = rdp_account(&f).await;
        let core = f.core.as_ref();
        let mut errors = Vec::new();

        let c = call(core, &f.alice, CANDIDATES, body("dc01", "p_rdp", json!({}))).await.unwrap();
        assert_eq!(c["provider"], "self-accounts");
        assert_eq!(c["display_name"], "Self-account");
        assert_eq!(c["protocol"], "rdp");
        assert_eq!(c["resource_type"], "server");
        assert_eq!(c["os_type"], "windows");
        assert_eq!(c["target"], json!({ "host": "dc01.corp.example.com", "port": 3389 }));
        let list = c["candidates"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], id.as_str());
        assert_eq!(list[0]["username"], "felipe.adm");
        assert_eq!(list[0]["domain"], "CORP");
        assert!(!Value::Object(c.clone()).to_string().contains(RDP_PASSWORD), "metadata only");

        // The body cannot steer the query: type, OS, protocol, target and
        // provider are never read off it.
        let lying = call(
            core,
            &f.alice,
            CANDIDATES,
            body(
                "dc01",
                "p_rdp",
                json!({ "type": "workstation", "resource_type": "workstation", "os_type": "linux",
                        "protocol": "ssh", "provider": "evil", "target_host": "evil.example.org",
                        "target": { "host": "evil.example.org", "port": 22 } }),
            ),
        )
        .await
        .unwrap();
        assert_eq!(lying, c, "extra body fields must be ignored");

        // Bob may connect to dc01 but sees none of Alice's accounts.
        let b = call(core, &f.bob, CANDIDATES, body("dc01", "p_rdp", json!({}))).await.unwrap();
        assert!(b["candidates"].as_array().unwrap().is_empty());

        // Mallory has no `connect` on dc01.
        errors.push(refused(call(core, &f.mallory, CANDIDATES, body("dc01", "p_rdp", json!({}))).await, 403, "permission denied"));
        // The root token has no identity entity: refused before the plugin runs.
        errors.push(refused(call(core, &f.root, CANDIDATES, body("dc01", "p_rdp", json!({}))).await, 403, "no_entity"));
        // A profile that is not a provider profile.
        errors.push(refused(call(core, &f.alice, CANDIDATES, body("dc01", "p_secret", json!({}))).await, 400, "invalid_profile"));
        // A provider that is not approved here.
        errors.push(refused(call(core, &f.alice, CANDIDATES, body("dc01", "p_other", json!({}))).await, 403, "not_granted"));

        // The audit trail names every call; success lines count candidates.
        let lines = audit_lines("connect.provider.candidates");
        assert!(lines.iter().any(|l| l.contains("outcome=success") && l.contains("candidates=1")), "{lines:#?}");
        for reason in ["connect_denied", "no_entity", "invalid_profile", "not_granted"] {
            assert!(
                lines.iter().any(|l| l.contains("outcome=denied") && l.contains(&format!("reason={reason} "))),
                "no denied line with reason={reason}: {lines:#?}"
            );
        }
        assert_no_secret_anywhere(&f, &errors);

        // The profile editor's provider list (Phase 4): the approved provider,
        // and nothing once the grant is revoked.
        let l = read(core, &f.bob, PROVIDERS).await;
        let providers = l["providers"].as_array().expect("a providers list");
        assert_eq!(providers.len(), 1, "{l:?}");
        assert_eq!(providers[0]["name"], "self-accounts");
        assert_eq!(providers[0]["display_name"], "Self-account");
        assert!(providers[0]["protocols"].as_array().unwrap().iter().any(|p| p == "rdp"));
        grants::delete_grant(f.core.barrier.as_storage(), "self-accounts").await.unwrap();
        assert_eq!(read(core, &f.bob, PROVIDERS).await["providers"], json!([]), "a revoked provider is not offered");
    }

    // ── authorize (direct) ──────────────────────────────────────────

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn authorize_burns_the_ticket_before_releasing_and_only_for_provider_profiles() {
        let f = setup("sa_conn_authorize").await;
        let id = rdp_account(&f).await;
        let core = f.core.as_ref();
        let mut errors = Vec::new();
        let with = |extra: Value| body("dc01", "p_rdp", extra);

        // A provider profile needs the account id …
        errors.push(refused(call(core, &f.alice, AUTHORIZE, with(json!({}))).await, 400, "invalid_request"));
        errors.push(refused(
            call(core, &f.alice, AUTHORIZE, with(json!({ "provider_account_id": ["x"] }))).await,
            400,
            "invalid_request",
        ));
        // … and, gated, a ticket.
        errors.push(refused(
            call(core, &f.alice, AUTHORIZE, with(json!({ "provider_account_id": id }))).await,
            403,
            "mfa_required",
        ));

        // Never released here yet: the picker's first-use hint (Phase 5).
        let c = call(core, &f.alice, CANDIDATES, body("dc01", "p_rdp", json!({}))).await.unwrap();
        assert_eq!(c["candidates"][0]["first_use_on_target"], true);
        assert!(c["candidates"][0].get("last_used_on_target").is_none());

        // A forged id with a good ticket: the ticket is redeemed first, so it
        // is spent even though nothing is released.
        let t = ticket(&f, "alice", "dc01", "p_rdp").await;
        errors.push(refused(
            call(core, &f.alice, AUTHORIZE, with(json!({ "provider_account_id": "sa_forged", "connect_ticket": t })))
                .await,
            404,
            "no_match",
        ));
        errors.push(refused(
            call(core, &f.alice, AUTHORIZE, with(json!({ "provider_account_id": id, "connect_ticket": t }))).await,
            403,
            "connect MFA ticket is unknown or has already been used",
        ));

        // The release.
        let t = ticket(&f, "alice", "dc01", "p_rdp").await;
        let ok = call(core, &f.alice, AUTHORIZE, with(json!({ "provider_account_id": id, "connect_ticket": t })))
            .await
            .unwrap();
        assert_eq!(ok["authorized"], true);
        assert_eq!(ok["mfa_required"], true);
        assert_eq!(ok["credential_source"], "provider");
        assert_eq!(ok["provider"], "self-accounts");
        assert_eq!(ok["target"], json!({ "host": "dc01.corp.example.com", "port": 3389 }));
        assert_eq!(ok["credential"]["username"], "felipe.adm");
        assert_eq!(ok["credential"]["domain"], "CORP");
        assert_eq!(ok["credential"]["secret"]["kind"], "password");
        assert_eq!(ok["credential"]["secret"]["password"], RDP_PASSWORD);
        assert!(ok["credential"]["secret"].get("totp_seed").is_none());

        // The release stamped `last_used_at`, which the candidates now show,
        // and this target is no longer a first use; the refusals above did
        // not count as one.
        let c = call(core, &f.alice, CANDIDATES, body("dc01", "p_rdp", json!({}))).await.unwrap();
        assert!(c["candidates"][0]["last_used_at"].is_string());
        assert_eq!(c["candidates"][0]["first_use_on_target"], false);
        assert!(c["candidates"][0]["last_used_on_target"].is_string());
        assert!(!Value::Object(c.clone()).to_string().contains(RDP_PASSWORD));

        // Bob cannot release Alice's account, even with his own good ticket.
        let tb = ticket(&f, "bob", "dc01", "p_rdp").await;
        errors.push(refused(
            call(core, &f.bob, AUTHORIZE, with(json!({ "provider_account_id": id, "connect_ticket": tb }))).await,
            404,
            "no_match",
        ));

        // A non-provider profile refuses the field, and never carries a credential.
        errors.push(refused(
            call(core, &f.alice, AUTHORIZE, body("dc01", "p_secret", json!({ "provider_account_id": id }))).await,
            400,
            "invalid_request",
        ));
        let plain = call(core, &f.alice, AUTHORIZE, body("dc01", "p_secret", json!({}))).await.unwrap();
        assert!(!plain.contains_key("credential") && !plain.contains_key("target"));

        // An ungated provider profile: the plugin's default
        // `require_connect_mfa` refuses, and says how to fix it.
        let m = refused(
            call(core, &f.alice, AUTHORIZE, body("dc01", "p_rdp_open", json!({ "provider_account_id": id }))).await,
            403,
            "mfa_required",
        );
        assert!(m.contains("require_mfa") && m.contains("require_connect_mfa"), "{m}");
        errors.push(m);

        // Point the resource at an attacker's host. The target is computed
        // from the stored record, so the account bound to *.corp.example.com
        // is neither offered nor released.
        root_write(&f, "resources/resources/dc01", dc01("dc01.evil.example.org")).await;
        let c = call(core, &f.alice, CANDIDATES, body("dc01", "p_rdp", json!({}))).await.unwrap();
        assert_eq!(c["target"]["host"], "dc01.evil.example.org");
        assert!(c["candidates"].as_array().unwrap().is_empty());
        let t = ticket(&f, "alice", "dc01", "p_rdp").await;
        errors.push(refused(
            call(core, &f.alice, AUTHORIZE, with(json!({ "provider_account_id": id, "connect_ticket": t }))).await,
            404,
            "no_match",
        ));

        // Audit: one success with the login name, and the refusals by reason.
        let lines = audit_lines("connect.provider.release");
        let success: Vec<_> = lines.iter().filter(|l| l.contains("outcome=success")).collect();
        assert_eq!(success.len(), 1, "{lines:#?}");
        assert!(success[0].contains(r#"login_name="felipe.adm""#) && success[0].contains("transport=direct"));
        assert!(success[0].contains(&format!("account_id={id:?}")));
        for reason in ["invalid_request", "mfa_required", "no_match"] {
            assert!(
                lines.iter().any(|l| l.contains("outcome=denied") && l.contains(&format!("reason={reason} "))),
                "no denied line with reason={reason}: {lines:#?}"
            );
        }

        // The audit device recorded the authorize response with the
        // credential HMAC-redacted, never in the clear.
        let audit = std::fs::read_to_string(&f.audit_log).unwrap();
        let redacted = audit.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).any(|e| {
            e["request"]["path"] == AUTHORIZE
                && e["response"]["data"]["credential"]["secret"]["password"]
                    .as_str()
                    .is_some_and(|p| p.starts_with("hmac:"))
        });
        assert!(redacted, "the authorize response must reach the audit device HMAC-redacted");
        assert_no_secret_anywhere(&f, &errors);
    }

    // ── web launch ──────────────────────────────────────────────────

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn web_launch_releases_the_picked_account_into_the_bundle() {
        let f = setup("sa_conn_web").await;
        let id = web_account(&f).await;
        let core = f.core.as_ref();
        let mut errors = Vec::new();
        let hash = recipe_hash(&web_recipe()).unwrap();

        // Candidates for a web profile are matched on the fill origins.
        let c = call(core, &f.alice, CANDIDATES, body("fw01", "p_web", json!({}))).await.unwrap();
        assert_eq!(c["target"], json!({ "origins": ["https://fw01.example.com"] }));
        assert_eq!(c["candidates"].as_array().unwrap().len(), 1);
        let wide = call(core, &f.alice, CANDIDATES, body("fw01", "p_web_wide", json!({}))).await.unwrap();
        assert!(wide["candidates"].as_array().unwrap().is_empty(), "every fill origin must match");

        // The account id is required, before any ticket is spent.
        errors.push(refused(
            call(core, &f.alice, LAUNCH, body("fw01", "p_web", json!({ "recipe_hash": hash }))).await,
            400,
            "invalid_request",
        ));

        let t = ticket(&f, "alice", "fw01", "p_web").await;
        let b = call(
            core,
            &f.alice,
            LAUNCH,
            body("fw01", "p_web", json!({ "recipe_hash": hash, "provider_account_id": id, "connect_ticket": t })),
        )
        .await
        .unwrap();
        assert_eq!(b["credential_source"], "provider");
        assert_eq!(b["credential"]["username"], "fwadmin");
        assert_eq!(b["credential"]["password"], WEB_PASSWORD);
        assert!(b["credential"].get("totp").is_none());
        assert_eq!(b["totp_refresh_steps"], json!([]));

        // An origin the account is not bound to releases nothing.
        let t = ticket(&f, "alice", "fw01", "p_web_wide").await;
        errors.push(refused(
            call(
                core,
                &f.alice,
                LAUNCH,
                body("fw01", "p_web_wide", json!({ "recipe_hash": hash, "provider_account_id": id, "connect_ticket": t })),
            )
            .await,
            404,
            "no_match",
        ));

        let launch = capture::lines()
            .into_iter()
            .find(|l| l.starts_with("audit connect.web.launch "))
            .expect("a connect.web.launch line");
        assert!(launch.contains(r#"credential_source=provider provider="self-accounts""#), "{launch}");
        let lines = audit_lines("connect.provider.release");
        assert!(lines.iter().any(|l| l.contains("outcome=success") && l.contains("transport=web")), "{lines:#?}");
        assert!(lines.iter().any(|l| l.contains("outcome=denied") && l.contains("reason=no_match ")), "{lines:#?}");
        assert_no_secret_anywhere(&f, &errors);
    }

    // ── the SSH login class ─────────────────────────────────────────

    /// A provider account is a static credential: on a resource whose SSH
    /// login class is `brokered` it is neither offered nor released for SSH —
    /// on the direct route or the Rustion route — and the refusal comes
    /// before the MFA gate. RDP on the same resource is unaffected.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn a_brokered_resource_never_releases_an_account_for_ssh() {
        let f = setup("sa_conn_brokered").await;
        let rdp_id = rdp_account(&f).await;
        let core = f.core.as_ref();
        let mut errors = Vec::new();

        // An SSH provider profile on dc01, and an SSH account that matches it.
        let mut record = dc01("dc01.corp.example.com");
        record["connection_profiles"].as_array_mut().unwrap().push(json!({
            "id": "p_ssh", "name": "Self-account SSH", "protocol": "ssh", "require_mfa": true,
            "credential_source": provider_source()
        }));
        root_write(&f, "resources/resources/dc01", record).await;
        let ssh_id = call(
            core,
            &f.alice,
            "self-accounts/v2/accounts",
            json!({
                "label": "Shell", "username": "felipe", "secret_kind": "password", "password": RDP_PASSWORD,
                "resource_types": ["server"], "os_types": ["windows"], "protocols": ["ssh"],
                "targets": "*.corp.example.com",
            }),
        )
        .await
        .expect("create the SSH account")["id"]
            .as_str()
            .unwrap()
            .to_string();
        let ssh_candidates = call(core, &f.alice, CANDIDATES, body("dc01", "p_ssh", json!({}))).await.unwrap();
        assert_eq!(
            ssh_candidates["candidates"].as_array().unwrap().len(),
            1,
            "matches before the resource is brokered"
        );

        // Every SSH login to `server` resources is now minted by the SSH engine.
        root_write(&f, "ssh-broker/policy/type/server", json!({ "login_class": "brokered" })).await;

        // Candidates: not offered for SSH; RDP still is.
        errors.push(refused(
            call(core, &f.alice, CANDIDATES, body("dc01", "p_ssh", json!({}))).await,
            403,
            "brokered_requires_ssh_engine",
        ));
        let rdp = call(core, &f.alice, CANDIDATES, body("dc01", "p_rdp", json!({}))).await.unwrap();
        assert_eq!(rdp["candidates"].as_array().unwrap().len(), 1, "RDP is not governed by the SSH login class");

        // Direct: refused before the ticket is redeemed (it is spent below).
        let t = ticket(&f, "alice", "dc01", "p_ssh").await;
        let m = refused(
            call(
                core,
                &f.alice,
                AUTHORIZE,
                body("dc01", "p_ssh", json!({ "provider_account_id": ssh_id, "connect_ticket": t })),
            )
            .await,
            403,
            "brokered_requires_ssh_engine",
        );
        assert!(m.contains("ssh-engine"), "the refusal says what to use instead: {m}");
        errors.push(m);

        // Rustion: refused in the pre-flight, before the MFA gate.
        let t2 = ticket(&f, "alice", "dc01", "p_ssh").await;
        let open_ssh = json!({
            "resource_name": "dc01", "profile_id": "p_ssh", "credential_source": provider_source(),
            "target_protocol": "ssh", "credential_kind": "ssh-password",
            "provider_account_id": ssh_id, "connect_ticket": t2,
        });
        errors.push(refused(call(core, &f.alice, OPEN, open_ssh.clone()).await, 403, "brokered_requires_ssh_engine"));

        // RDP on the same brokered resource still releases, on both routes.
        let tr = ticket(&f, "alice", "dc01", "p_rdp").await;
        let ok = call(
            core,
            &f.alice,
            AUTHORIZE,
            body("dc01", "p_rdp", json!({ "provider_account_id": rdp_id, "connect_ticket": tr })),
        )
        .await
        .expect("RDP is released on a brokered resource");
        assert_eq!(ok["credential"]["username"], "felipe.adm");
        let tr2 = ticket(&f, "alice", "dc01", "p_rdp").await;
        match call(
            core,
            &f.alice,
            OPEN,
            json!({ "resource_name": "dc01", "profile_id": "p_rdp", "credential_source": provider_source(),
                    "target_protocol": "rdp", "credential_kind": "rdp-password",
                    "provider_account_id": rdp_id, "connect_ticket": tr2 }),
        )
        .await
        {
            Err((s, m)) => {
                assert!(s == 502 || s == 503, "RDP must reach dispatch (no bastion enrolled), got {s}: {m}");
                errors.push(m);
            }
            Ok(_) => panic!("no bastion is enrolled; the open cannot succeed"),
        }

        // Neither SSH ticket was spent by its refusal: back on a
        // shared-credential class, both release with them.
        root_write(&f, "ssh-broker/policy/type/server", json!({ "login_class": "shared-credential" })).await;
        let released = call(
            core,
            &f.alice,
            AUTHORIZE,
            body("dc01", "p_ssh", json!({ "provider_account_id": ssh_id, "connect_ticket": t })),
        )
        .await
        .expect("the direct refusal must not have spent the ticket");
        assert_eq!(released["credential"]["username"], "felipe");
        match call(core, &f.alice, OPEN, open_ssh).await {
            Err((s, m)) => {
                assert!(s == 502 || s == 503, "the Rustion refusal must not have spent the ticket, got {s}: {m}");
                errors.push(m);
            }
            Ok(_) => panic!("no bastion is enrolled; the open cannot succeed"),
        }

        // Audited as denied, with the reason, on every refused route.
        let release = audit_lines("connect.provider.release");
        for transport in ["direct", "rustion"] {
            assert!(
                release.iter().any(|l| l.contains("outcome=denied")
                    && l.contains("reason=brokered_requires_ssh_engine ")
                    && l.contains(&format!("transport={transport} "))),
                "no brokered denial for transport={transport}: {release:#?}"
            );
        }
        assert!(
            audit_lines("connect.provider.candidates")
                .iter()
                .any(|l| l.contains("outcome=denied") && l.contains("reason=brokered_requires_ssh_engine ")),
            "the candidates refusal is audited"
        );
        assert_no_secret_anywhere(&f, &errors);
    }

    // ── rustion ─────────────────────────────────────────────────────

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn rustion_open_releases_server_side_for_the_stored_target_only() {
        let f = setup("sa_conn_rustion").await;
        let id = rdp_account(&f).await;
        let core = f.core.as_ref();
        let mut errors = Vec::new();
        let open = |extra: Value| {
            let mut b = json!({
                "resource_name": "dc01", "profile_id": "p_rdp",
                "credential_source": provider_source(),
                "target_protocol": "rdp", "credential_kind": "rdp-password",
            });
            for (k, v) in extra.as_object().cloned().unwrap_or_default() {
                b[k] = v;
            }
            b
        };

        // Refused before the MFA gate, so none of these costs a ticket.
        let t = ticket(&f, "alice", "dc01", "p_rdp").await;
        errors.push(refused(call(core, &f.alice, OPEN, open(json!({ "connect_ticket": t }))).await, 400, "invalid_request"));
        errors.push(refused(
            call(
                core,
                &f.alice,
                OPEN,
                open(json!({ "connect_ticket": t, "provider_account_id": id, "target_host": "evil.example.org" })),
            )
            .await,
            400,
            "invalid_request",
        ));
        errors.push(refused(
            call(core, &f.alice, OPEN, open(json!({ "connect_ticket": t, "provider_account_id": id, "target_port": 22 })))
                .await,
            400,
            "invalid_request",
        ));
        errors.push(refused(
            call(
                core,
                &f.alice,
                OPEN,
                open(json!({ "connect_ticket": t, "provider_account_id": id,
                             "credential_source": { "kind": "provider", "provider": "other" } })),
            )
            .await,
            400,
            "invalid_request",
        ));
        errors.push(refused(
            call(
                core,
                &f.alice,
                OPEN,
                open(json!({ "connect_ticket": t, "provider_account_id": id, "credential_material": "aGk=" })),
            )
            .await,
            400,
            "invalid_request",
        ));
        // A non-provider source refuses the account id.
        errors.push(refused(
            call(
                core,
                &f.alice,
                OPEN,
                open(json!({ "profile_id": "p_secret", "provider_account_id": id,
                             "credential_source": { "kind": "secret", "secret_id": "admin" } })),
            )
            .await,
            400,
            "invalid_request",
        ));

        // The ticket survived all of that. Released server-side and sealed;
        // with no bastion enrolled the open then fails at dispatch.
        let r = call(core, &f.alice, OPEN, open(json!({ "connect_ticket": t, "provider_account_id": id }))).await;
        match &r {
            Err((s, m)) => {
                assert!(*s == 502 || *s == 503, "expected a dispatch failure after the release, got {s}: {m}");
                errors.push(m.clone());
            }
            Ok(_) => panic!("no bastion is enrolled; the open cannot succeed"),
        }
        let lines = audit_lines("connect.provider.release");
        let success: Vec<_> = lines.iter().filter(|l| l.contains("outcome=success")).collect();
        assert_eq!(success.len(), 1, "{lines:#?}");
        assert!(success[0].contains("transport=rustion") && success[0].contains(r#"login_name="felipe.adm""#));

        // Repointed at an attacker's host: nothing is released.
        root_write(&f, "resources/resources/dc01", dc01("dc01.evil.example.org")).await;
        let t = ticket(&f, "alice", "dc01", "p_rdp").await;
        errors.push(refused(
            call(core, &f.alice, OPEN, open(json!({ "connect_ticket": t, "provider_account_id": id }))).await,
            404,
            "no_match",
        ));
        assert_eq!(
            audit_lines("connect.provider.release").iter().filter(|l| l.contains("outcome=success")).count(),
            1,
            "the repointed resource must not release"
        );
        assert_no_secret_anywhere(&f, &errors);
    }
}
