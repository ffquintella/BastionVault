//! End-to-end tests of `bv_resource_ssh_exec` (`features/mcp-brokered-sessions.md`
//! Phase 1): a real vault, the in-process `/v2/mcp` handling, the resource
//! engine's session handler, and an in-process SSH server on loopback that
//! records every request it receives.
//!
//! Loopback is always denied in production. These tests reach it through
//! the destination policy's test seam (`permit_loopback_for_tests`, compiled
//! only for tests), installed by replacing the vault's brokered-session
//! environment with one that wraps the real one and also turns the server
//! config's switch on. Nothing else is replaced: the runtime switch, the
//! destination allow-list, the opt-ins, the connect gate and the limits are
//! the vault's own.

#[cfg(all(feature = "mcp_sessions_ssh", not(feature = "sync_handler")))]
mod mod_test {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use bv_engine_resource::agent_ssh::test_server::{
        unrelated_host_key_fingerprint, ScriptedReply, TestServerConfig, TestSshServer,
    };
    use bv_mcp::request_state::SingleUseGuard;
    use bv_utils::destination_policy::{DestinationPolicy, TargetCidrs};
    use serde_json::{json, Map, Value};

    use crate::{
        core::Core,
        errors::RvError,
        kernel_api::{
            mcp_sessions::{BrokeredSessionEnv, BrokeredSessionRuntime, BrokeredSessionSettings},
            mcp_transcripts::{TranscriptBody, TranscriptStore},
        },
        mcp_endpoint::{handle_jsonrpc, McpEndpoint, McpEndpointOutcome},
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_mount_api, test_mount_auth_api, test_write_api,
        },
        BastionVault,
    };

    const PASSWORD: &str = "hunter2-Qx7";
    const TOOL: &str = "bv_resource_ssh_exec";
    /// Requests the vault's SSH client must never make.
    const FORBIDDEN: &[&str] = &[
        "pty_request",
        "shell_request",
        "env_request",
        "x11_request",
        "agent_request",
        "subsystem_request",
        "tcpip_forward",
        "direct_tcpip",
    ];

    /// The vault's own environment, with the server config's switch on and,
    /// when `loopback` is set, the destination policy's test seam open.
    struct TestEnv {
        inner: Arc<dyn BrokeredSessionEnv>,
        settings: BrokeredSessionSettings,
        loopback: bool,
    }

    #[maybe_async::maybe_async]
    impl BrokeredSessionEnv for TestEnv {
        fn settings(&self) -> BrokeredSessionSettings {
            self.settings.clone()
        }

        async fn runtime(&self) -> Result<BrokeredSessionRuntime, RvError> {
            self.inner.runtime().await
        }

        fn destination_policy(&self, allowed: TargetCidrs) -> DestinationPolicy {
            let policy = self.inner.destination_policy(allowed);
            if self.loopback {
                policy.permit_loopback_for_tests()
            } else {
                policy
            }
        }
    }

    fn enabled_settings() -> BrokeredSessionSettings {
        BrokeredSessionSettings { enabled: true, protocols: vec!["ssh".into()], ..Default::default() }
    }

    fn obj(v: Value) -> Option<Map<String, Value>> {
        v.as_object().cloned()
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    /// The scripted target: what each command prints.
    fn target_config() -> TestServerConfig {
        let mut config = TestServerConfig::new(|command| match command {
            "uptime" => {
                ScriptedReply { stdout: b" 10:00 up 3 days\n".to_vec(), exit_status: Some(0), ..Default::default() }
            }
            "echo-secret" => {
                use base64::Engine as _;
                let basic = base64::engine::general_purpose::STANDARD.encode(format!("ops:{PASSWORD}"));
                ScriptedReply {
                    stdout: format!("password={PASSWORD}\nauthorization: Basic {basic}\n").into_bytes(),
                    stderr: format!("sudo: {PASSWORD}\n").into_bytes(),
                    exit_status: Some(0),
                    ..Default::default()
                }
            }
            "big" => ScriptedReply { stdout: vec![b'x'; 100_000], exit_status: Some(0), ..Default::default() },
            "sleep" => {
                ScriptedReply { delay: Some(Duration::from_secs(60)), exit_status: Some(0), ..Default::default() }
            }
            "hidden-output" => ScriptedReply {
                stdout: "ok\u{E0049}\u{E0047}\u{200B} \u{1b}[31mred\u{1b}[0m\n".as_bytes().to_vec(),
                exit_status: Some(3),
                ..Default::default()
            },
            other => ScriptedReply {
                stdout: format!("ran: {}\n", other.len()).into_bytes(),
                exit_status: Some(0),
                ..Default::default()
            },
        });
        config.passwords.push(("ops".into(), PASSWORD.into()));
        config
    }

    struct Rig {
        _bvault: BastionVault,
        core: Arc<Core>,
        root: String,
        op: String,
        token: String,
        server: TestSshServer,
        audit_dir: PathBuf,
        audit_log: PathBuf,
        guard: SingleUseGuard,
        real_env: Arc<dyn BrokeredSessionEnv>,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.audit_dir);
        }
    }

    async fn audit_file(core: &Core, name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir()
            .join(format!("bv-mcp-ssh-{name}-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        let broker = core.audit_broker.load().as_ref().cloned().expect("broker installed at unseal");
        let mut options = std::collections::HashMap::new();
        options.insert("file_path".to_string(), log.display().to_string());
        broker
            .enable_device(crate::audit::AuditDeviceConfig {
                path: format!("ssh-{name}"),
                device_type: "file".into(),
                description: String::new(),
                options,
                namespace: String::new(),
                mirror: false,
            })
            .await
            .unwrap();
        (dir, log)
    }

    fn audit_lines(log: &Path) -> Vec<Value> {
        std::fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    fn events(log: &Path, name: &str) -> Vec<Value> {
        audit_lines(log)
            .into_iter()
            .filter(|e| e["type"] == "event" && e["request"]["path"] == name)
            .map(|e| e["request"]["data"].clone())
            .collect()
    }

    fn profile(pin: &str, port: u16) -> Value {
        json!({
            "id": "p_agent",
            "name": "agent",
            "protocol": "ssh",
            "target_port": port,
            "username": "ops",
            "credential_source": { "kind": "secret", "secret_id": "login" },
            "host_key_pin": pin,
            "agent_access": "allow",
        })
    }

    impl Rig {
        async fn new(name: &str) -> Self {
            Self::with_target(name, target_config()).await
        }

        async fn with_target(name: &str, target: TestServerConfig) -> Self {
            let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
            let (audit_dir, audit_log) = audit_file(&core, name).await;
            let server = TestSshServer::start(target).await;
            let real_env = core.kernel_services.brokered_sessions().expect("the assembly registers the environment");

            // Runtime switch on (the vault's own record).
            let _ = test_write_api(
                core.as_ref(),
                &root,
                "sys/mcp/config",
                true,
                obj(json!({ "brokered_sessions_enabled": true })),
            )
            .await;
            // The type opts in; the resource and its profile; the stored login.
            let types = json!({ "server": { "connect": { "agent_sessions_max": "allow" } } });
            let _ = test_write_api(core.as_ref(), &root, "resources/config/types", true, obj(types)).await;
            let resource = json!({
                "type": "server",
                "ip_address": "127.0.0.1",
                "connection_profiles": [profile(&server.host_key_fingerprint(), server.addr().port())],
            });
            let _ = test_write_api(core.as_ref(), &root, "resources/resources/web-01", true, obj(resource)).await;
            let login = json!({ "username": "ops", "password": PASSWORD });
            let _ = test_write_api(core.as_ref(), &root, "resources/secrets/web-01/login", true, obj(login)).await;

            // The operator: may pair, may call the agent route, may connect
            // to web-01 (a policy grant: an MCP token has no entity).
            test_mount_auth_api(core.as_ref(), &root, "userpass", "userpass").await;
            let policy = r#"
                path "sys/mcp/token"                        { capabilities = ["update"] }
                path "sys/mcp/pairings/*"                   { capabilities = ["delete"] }
                path "resources/v2/connect/agent/ssh/exec"  { capabilities = ["update"] }
                path "resources/secrets/web-01/*"           { capabilities = ["connect"] }
            "#;
            let _ = test_write_api(
                core.as_ref(),
                &root,
                "sys/policy/agent-operator",
                true,
                obj(json!({ "policy": policy })),
            )
            .await;
            let user = json!({ "password": "pw", "policies": "agent-operator" });
            let _ = test_write_api(core.as_ref(), &root, "auth/userpass/users/felipe", true, obj(user)).await;
            let mut req = crate::logical::Request::new("auth/userpass/login/felipe");
            req.operation = crate::logical::Operation::Write;
            req.body = obj(json!({ "password": "pw" }));
            let op = core.handle_request(&mut req).await.unwrap().unwrap().auth.unwrap().client_token;

            let mut rig = Rig {
                _bvault: bvault,
                core,
                root,
                op,
                token: String::new(),
                server,
                audit_dir,
                audit_log,
                guard: SingleUseGuard::new(),
                real_env,
            };
            rig.install_env(enabled_settings(), true);
            rig.token = rig.pair("agent-1", json!(["resources/secrets/web-01/"])).await;
            rig
        }

        fn install_env(&self, settings: BrokeredSessionSettings, loopback: bool) {
            self.core.kernel_services.set_brokered_sessions(Arc::new(TestEnv {
                inner: self.real_env.clone(),
                settings,
                loopback,
            }));
        }

        async fn pair(&self, id: &str, scope: Value) -> String {
            let body = json!({
                "pairing": {
                    "id": id,
                    "client_name": "claude-code",
                    "client_version": "2.1",
                    "tool_allowlist": [TOOL],
                    "path_scope": scope,
                    "connect_allowed": true,
                    "confirm_connect": true,
                },
            });
            let resp = test_write_api(self.core.as_ref(), &self.op, "sys/mcp/token", true, obj(body)).await;
            resp.unwrap().unwrap().data.unwrap()["auth"]["client_token"].as_str().unwrap().to_string()
        }

        /// Replace web-01's only profile; `ok` is whether the write must
        /// succeed.
        async fn write_profile(&self, profile: Value, ok: bool) -> Result<Option<crate::logical::Response>, RvError> {
            let resource = json!({ "type": "server", "ip_address": "127.0.0.1", "connection_profiles": [profile] });
            test_write_api(self.core.as_ref(), &self.root, "resources/resources/web-01", ok, obj(resource)).await
        }

        fn default_profile(&self) -> Value {
            profile(&self.server.host_key_fingerprint(), self.server.addr().port())
        }

        async fn call_with(&self, token: &str, arguments: Value, confirmed: bool) -> Value {
            let meta = if confirmed {
                json!({ "io.bastionvault/confirmation": { "by": "operator", "at": now_secs(), "mfa": false } })
            } else {
                json!({})
            };
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": TOOL, "arguments": arguments, "_meta": meta },
            }))
            .unwrap();
            let ep = McpEndpoint {
                core: &self.core,
                client_ip: "",
                tool_timeout: Duration::from_secs(30),
                server_version: "9.9",
                request_state_key: b"ssh-exec-test-key",
                single_use_guard: &self.guard,
            };
            match handle_jsonrpc(&ep, token, &body).await.unwrap() {
                McpEndpointOutcome::Answer(r) => serde_json::to_value(r).unwrap(),
                other => panic!("expected a JSON-RPC answer, got {other:?}"),
            }
        }

        async fn call(&self, command: &str) -> Value {
            self.call_with(&self.token, json!({ "resource": "web-01", "profile": "p_agent", "command": command }), true)
                .await
        }

        async fn transcripts(&self) -> Vec<crate::kernel_api::mcp_transcripts::McpSessionTranscript> {
            let store = TranscriptStore::from_ctx(self.core.as_ref()).unwrap();
            let mut out = Vec::new();
            for id in store.list().await.unwrap() {
                out.push(store.read(&id).await.unwrap().unwrap());
            }
            out
        }
    }

    fn code(answer: &Value) -> &str {
        answer["error"]["data"]["code"].as_str().unwrap_or_else(|| panic!("expected an error, got {answer}"))
    }

    fn structured(answer: &Value) -> &Value {
        assert!(answer["error"].is_null(), "expected a result, got {answer}");
        &answer["result"]["structuredContent"]
    }

    fn count(events: &[String], prefix: &str) -> usize {
        events.iter().filter(|e| e.starts_with(prefix)).count()
    }

    /// A confirmed call runs one command over one exec channel, returns the
    /// output in the untrusted envelope, and leaves one transcript, one
    /// `connect.agent.ssh.exec` event and an audit trail with the command
    /// only as an HMAC.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_runs_one_command_and_records_it() {
        let rig = Rig::new("ssh_exec_runs").await;
        let answer = rig.call("uptime").await;
        let sc = structured(&answer);
        assert_eq!(sc["exit_status"], json!(0));
        assert_eq!(sc["stdout"], json!(" 10:00 up 3 days\n"));
        assert_eq!(sc["login"], json!("password"));
        assert_eq!(sc["timed_out"], json!(false));
        assert_eq!(sc["host_key_fingerprint"], json!(rig.server.host_key_fingerprint()));
        assert_eq!(sc["untrusted"]["protocol"], json!("ssh"));
        assert_eq!(sc["untrusted"]["resource"], json!("web-01"));
        let text = answer["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(bv_mcp::untrusted::UNTRUSTED_PREAMBLE), "{text}");
        let session_id = sc["session_id"].as_str().unwrap().to_string();

        // The target saw one channel, one exec with the confirmed bytes, and
        // nothing else.
        let seen = rig.server.events();
        assert_eq!(count(&seen, "channel_open_session"), 1, "{seen:?}");
        assert_eq!(seen.iter().filter(|e| e.starts_with("exec:")).collect::<Vec<_>>(), vec!["exec:uptime"]);
        for forbidden in FORBIDDEN {
            assert_eq!(count(&seen, forbidden), 0, "{forbidden}: {seen:?}");
        }

        // One transcript, with the command, the output and who approved.
        let transcripts = rig.transcripts().await;
        assert_eq!(transcripts.len(), 1);
        let t = &transcripts[0];
        assert_eq!(t.summary.session_id, session_id);
        assert_eq!(t.summary.pairing_id, "agent-1");
        assert_eq!(t.summary.operator.as_ref().unwrap().username, "felipe");
        assert_eq!(t.summary.operator_confirmation.as_deref(), Some("asserted-by-local-host"));
        let TranscriptBody::Ssh(ssh) = &t.body;
        assert_eq!(ssh.command, "uptime");
        assert_eq!(ssh.stdout.text, " 10:00 up 3 days\n");
        assert_eq!(ssh.login, "password");
        assert_eq!(ssh.exit_status, Some(0));

        // One exec event: the command as an HMAC, the transcript linked.
        let exec = events(&rig.audit_log, "connect.agent.ssh.exec");
        assert_eq!(exec.len(), 1, "{exec:?}");
        let e = &exec[0];
        assert_eq!(e["session_id"], json!(session_id));
        assert!(e["command_hmac"].as_str().unwrap().starts_with("hmac:"));
        assert_eq!(e["command_bytes"], json!(6));
        assert_eq!(e["pairing_id"], json!("agent-1"));
        assert_eq!(e["binding_reveal_allowed"], json!(false));
        assert_eq!(e["operator_confirmation"], json!("asserted-by-local-host"));
        assert!(e["transcript_id"].as_str().unwrap().ends_with(&session_id));
        assert!(e.get("command").is_none());
        let raw = std::fs::read_to_string(&rig.audit_log).unwrap();
        assert!(!raw.contains("\"uptime\""), "the command is in the audit log only as an HMAC");
        assert!(!raw.contains(PASSWORD), "the credential is never in the audit log");
        assert!(!raw.contains(&rig.token), "the MCP token is never in the audit log");
        // The routed request carries the `mcp` block for this tool.
        assert!(audit_lines(&rig.audit_log).iter().any(|l| l["request"]["mcp"]["tool"] == json!(TOOL)));
    }

    /// The session's own password is scrubbed from what the model gets and
    /// from the transcript, in every encoding the vault produces; control,
    /// bidi, zero-width and tag characters are stripped from output.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_scrubs_the_credential_and_sanitizes_output() {
        let rig = Rig::new("ssh_exec_scrub").await;
        let answer = rig.call("echo-secret").await;
        let sc = structured(&answer);
        let stdout = sc["stdout"].as_str().unwrap();
        assert!(!stdout.contains(PASSWORD) && stdout.contains("<redacted:credential>"), "{stdout}");
        assert!(!stdout.contains("b3BzOm"), "the Basic form is scrubbed too: {stdout}");
        assert!(!sc["stderr"].as_str().unwrap().contains(PASSWORD));
        assert_eq!(sc["credential_echo_redacted"], json!(true));
        let t = rig.transcripts().await;
        let TranscriptBody::Ssh(ssh) = &t[0].body;
        assert!(!ssh.stdout.text.contains(PASSWORD) && !ssh.stderr.text.contains(PASSWORD));
        assert!(t[0].summary.credential_echo_redacted);
        assert!(!std::fs::read_to_string(&rig.audit_log).unwrap().contains(PASSWORD));

        let answer = rig.call("hidden-output").await;
        let sc = structured(&answer);
        assert_eq!(sc["stdout"], json!("ok red\n"), "tags, zero-width and ANSI are stripped");
        assert_eq!(sc["exit_status"], json!(3));
        // The transcript keeps the ANSI bytes for forensics.
        let t = rig.transcripts().await;
        let newest = t.iter().find(|t| t.summary.session_id == sc["session_id"].as_str().unwrap()).unwrap();
        let TranscriptBody::Ssh(ssh) = &newest.body;
        assert!(ssh.stdout.text.contains("\u{1b}[31m"));
    }

    /// Output past `max_output_bytes` is cut with exact counts; the
    /// transcript keeps more, and says where the model's copy stopped.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_caps_output() {
        let rig = Rig::new("ssh_exec_cap").await;
        rig.install_env(BrokeredSessionSettings { max_output_bytes: 1024, ..enabled_settings() }, true);
        let answer = rig.call("big").await;
        let sc = structured(&answer);
        assert_eq!(sc["stdout"].as_str().unwrap().len(), 1024);
        assert_eq!(sc["stdout_truncated"], json!(true));
        assert_eq!(sc["stdout_bytes"], json!(100_000));
        let t = rig.transcripts().await;
        let TranscriptBody::Ssh(ssh) = &t[0].body;
        assert_eq!(ssh.stdout.text.len(), 100_000);
        assert_eq!(ssh.stdout.model_truncated_at, Some(1024));
        let exec = events(&rig.audit_log, "connect.agent.ssh.exec");
        assert_eq!(exec[0]["truncated"], json!(true));
    }

    /// Every refusal of §3 step 5 happens before anything is dialed, carries
    /// its stable code, and yields `connect.agent.refused`.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_refusals_before_dialing() {
        let rig = Rig::new("ssh_exec_refusals").await;
        let args = json!({ "resource": "web-01", "profile": "p_agent", "command": "uptime" });

        // No confirmation from the gatekeeper: fail closed.
        assert_eq!(code(&rig.call_with(&rig.token, args.clone(), false).await), "mcp_confirmation_required");

        // The server config's switch off, then SSH not listed.
        rig.install_env(BrokeredSessionSettings { enabled: false, ..enabled_settings() }, true);
        assert_eq!(code(&rig.call("uptime").await), "mcp_brokered_sessions_disabled");
        rig.install_env(BrokeredSessionSettings { protocols: vec!["web".into()], ..enabled_settings() }, true);
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_protocol_disabled");
        rig.install_env(enabled_settings(), true);

        // The runtime switch off.
        let off = obj(json!({ "brokered_sessions_enabled": false }));
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "sys/mcp/config", true, off).await;
        assert_eq!(code(&rig.call("uptime").await), "mcp_brokered_sessions_disabled");
        let on = obj(json!({ "brokered_sessions_enabled": true }));
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "sys/mcp/config", true, on).await;

        // Malformed input never reaches the handler.
        for command in ["id\u{0}", "ls\u{202E}gpj", "r\u{200B}m", "id\u{E0041}", "a\u{2028}b"] {
            let a = json!({ "resource": "web-01", "profile": "p_agent", "command": command });
            assert_eq!(code(&rig.call_with(&rig.token, a, true).await), "mcp_invalid_argument", "{command:?}");
        }
        // Outside the pairing's scope.
        let a = json!({ "resource": "db-01", "profile": "p_agent", "command": "uptime" });
        assert_eq!(code(&rig.call_with(&rig.token, a, true).await), "mcp_path_out_of_scope");

        // The profile has not opted in; then the type has not.
        let mut p = rig.default_profile();
        p["agent_access"] = json!("deny");
        rig.write_profile(p, true).await.unwrap();
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_profile_not_agent_enabled");
        rig.write_profile(rig.default_profile(), true).await.unwrap();
        let deny = obj(json!({ "server": { "connect": { "agent_sessions_max": "deny" } } }));
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "resources/config/types", true, deny).await;
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_profile_not_agent_enabled");
        let allow = obj(json!({ "server": { "connect": { "agent_sessions_max": "allow" } } }));
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "resources/config/types", true, allow).await;

        // An unpinned profile cannot even be saved with agent access.
        let mut p = rig.default_profile();
        p.as_object_mut().unwrap().remove("host_key_pin");
        let err = rig.write_profile(p, false).await.unwrap_err();
        assert!(err.to_string().contains("mcp_session_host_key_unpinned"), "{err}");

        // MFA-gated profiles fail closed until the gatekeeper runs the step-up.
        let mut p = rig.default_profile();
        p["require_mfa"] = json!(true);
        rig.write_profile(p, true).await.unwrap();
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_mfa_required");

        // A bastion route is never bypassed.
        let mut p = rig.default_profile();
        p["kind"] = json!("rustion");
        rig.write_profile(p, true).await.unwrap();
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_requires_bastion");
        rig.write_profile(rig.default_profile(), true).await.unwrap();

        // Destinations: link-local (the metadata address), loopback without
        // the test seam even when listed, and outside the allow-list.
        let mut p = rig.default_profile();
        p["target_host"] = json!("169.254.169.254");
        rig.write_profile(p, true).await.unwrap();
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_destination_refused");
        rig.write_profile(rig.default_profile(), true).await.unwrap();
        rig.install_env(enabled_settings(), false);
        let listed = obj(json!({ "brokered_sessions_allowed_target_cidrs": ["127.0.0.0/8", "10.0.0.0/8"] }));
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "sys/mcp/config", true, listed).await;
        let refused = rig.call("uptime").await;
        assert_eq!(code(&refused), "mcp_session_destination_refused");
        assert!(refused["error"]["message"].as_str().unwrap().contains("loopback"), "{refused}");
        let mut p = rig.default_profile();
        p["target_host"] = json!("192.168.10.5");
        rig.write_profile(p, true).await.unwrap();
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_destination_refused");
        rig.install_env(enabled_settings(), true);

        // No connect grant on the resource: the vault's own permission denial.
        let other =
            json!({ "type": "server", "ip_address": "127.0.0.1", "connection_profiles": [rig.default_profile()] });
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "resources/resources/web-02", true, obj(other)).await;
        let wide = rig.pair("agent-2", json!(["resources/secrets/*"])).await;
        let a = json!({ "resource": "web-02", "profile": "p_agent", "command": "uptime" });
        assert_eq!(code(&rig.call_with(&wide, a, true).await), "mcp_backend_error");

        // Nothing above reached the target.
        assert!(rig.server.events().is_empty(), "{:?}", rig.server.events());
        assert!(rig.transcripts().await.is_empty());
        let reasons: Vec<String> = events(&rig.audit_log, "connect.agent.refused")
            .iter()
            .map(|e| e["reason"].as_str().unwrap().to_string())
            .collect();
        for expected in [
            "mcp_confirmation_required",
            "mcp_brokered_sessions_disabled",
            "mcp_session_protocol_disabled",
            "mcp_invalid_argument",
            "mcp_path_out_of_scope",
            "mcp_session_profile_not_agent_enabled",
            "mcp_session_mfa_required",
            "mcp_session_requires_bastion",
            "mcp_session_destination_refused",
            "permission_denied",
        ] {
            assert!(reasons.iter().any(|r| r == expected), "{expected} not in {reasons:?}");
        }
    }

    /// The pin is checked before authentication: a mismatch is refused and
    /// the password never reaches the host.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_refuses_a_host_key_mismatch_before_sending_the_password() {
        let rig = Rig::new("ssh_exec_hostkey").await;
        let mut p = rig.default_profile();
        p["host_key_pin"] = json!(unrelated_host_key_fingerprint());
        rig.write_profile(p, true).await.unwrap();
        assert_eq!(code(&rig.call("uptime").await), "mcp_session_host_key_mismatch");
        let seen = rig.server.events();
        assert_eq!(count(&seen, "auth_"), 0, "{seen:?}");
        let refused = events(&rig.audit_log, "connect.agent.refused");
        assert!(refused.iter().any(|e| e["reason"] == "mcp_session_host_key_mismatch"));
    }

    /// At the call timeout the command is killed, `timed_out` is returned,
    /// and the transcript and an `aborted` event are written.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_times_out() {
        let rig = Rig::new("ssh_exec_timeout").await;
        rig.install_env(BrokeredSessionSettings { call_timeout_secs: 2, ..enabled_settings() }, true);
        let started = Instant::now();
        let answer = rig.call("sleep").await;
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
        let sc = structured(&answer);
        assert_eq!(sc["timed_out"], json!(true));
        assert_eq!(sc["exit_status"], Value::Null);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(count(&rig.server.events(), "signal:KILL"), 1, "{:?}", rig.server.events());
        let t = rig.transcripts().await;
        let TranscriptBody::Ssh(ssh) = &t[0].body;
        assert!(ssh.timed_out);
        let aborted = events(&rig.audit_log, "connect.agent.aborted");
        assert!(aborted.iter().any(|e| e["cause"] == "timeout"), "{aborted:?}");
        // A per-call budget above the server's is refused.
        let a = json!({ "resource": "web-01", "profile": "p_agent", "command": "uptime", "timeout_secs": 3 });
        assert_eq!(code(&rig.call_with(&rig.token, a, true).await), "mcp_invalid_argument");
    }

    /// Revoking the pairing, or turning the runtime switch off, ends a
    /// running session within two seconds.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_ends_on_revocation_and_on_the_kill_switch() {
        let rig = Rig::new("ssh_exec_revoke").await;
        let revoked_at = std::sync::Mutex::new(None);
        let (answer, ()) = tokio::join!(rig.call("sleep"), async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let _ = test_delete_api(rig.core.as_ref(), &rig.op, "sys/mcp/pairings/agent-1", true, None).await;
            *revoked_at.lock().unwrap() = Some(Instant::now());
        });
        let after = revoked_at.lock().unwrap().unwrap().elapsed();
        assert!(after < Duration::from_secs(2) + Duration::from_millis(500), "ended {after:?} after the revocation");
        assert_eq!(code(&answer), "mcp_session_aborted");
        let aborted = events(&rig.audit_log, "connect.agent.aborted");
        assert!(aborted.iter().any(|e| e["cause"] == "token_revoked"), "{aborted:?}");

        // The kill switch, on a fresh pairing.
        let token = rig.pair("agent-3", json!(["resources/secrets/web-01/"])).await;
        let switched_at = std::sync::Mutex::new(None);
        let args = json!({ "resource": "web-01", "profile": "p_agent", "command": "sleep" });
        let (answer, ()) = tokio::join!(rig.call_with(&token, args.clone(), true), async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let off = obj(json!({ "brokered_sessions_enabled": false }));
            let _ = test_write_api(rig.core.as_ref(), &rig.root, "sys/mcp/config", true, off).await;
            *switched_at.lock().unwrap() = Some(Instant::now());
        });
        let after = switched_at.lock().unwrap().unwrap().elapsed();
        assert!(after < Duration::from_secs(2) + Duration::from_millis(500), "ended {after:?} after the switch");
        assert_eq!(code(&answer), "mcp_session_aborted");
        let aborted = events(&rig.audit_log, "connect.agent.aborted");
        assert!(aborted.iter().any(|e| e["cause"] == "kill_switch"), "{aborted:?}");

        // Signing out revokes the operator's token and, with it, every MCP
        // token minted from it.
        let on = obj(json!({ "brokered_sessions_enabled": true }));
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "sys/mcp/config", true, on).await;
        let token = rig.pair("agent-4", json!(["resources/secrets/web-01/"])).await;
        let signed_out_at = std::sync::Mutex::new(None);
        let (answer, ()) = tokio::join!(rig.call_with(&token, args, true), async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let _ = test_write_api(rig.core.as_ref(), &rig.op, "auth/token/revoke-self", true, None).await;
            *signed_out_at.lock().unwrap() = Some(Instant::now());
        });
        let after = signed_out_at.lock().unwrap().unwrap().elapsed();
        assert!(after < Duration::from_secs(2) + Duration::from_millis(500), "ended {after:?} after the sign-out");
        assert_eq!(code(&answer), "mcp_session_aborted");
        let revoked = events(&rig.audit_log, "connect.agent.aborted")
            .iter()
            .filter(|e| e["cause"] == "token_revoked")
            .count();
        assert_eq!(revoked, 2, "the pairing delete and the sign-out");
        // Both sessions left a transcript saying why they ended.
        let causes: Vec<Option<String>> = rig
            .transcripts()
            .await
            .into_iter()
            .map(|t| match t.body {
                TranscriptBody::Ssh(ssh) => ssh.aborted,
            })
            .collect();
        assert!(
            causes.contains(&Some("token_revoked".into())) && causes.contains(&Some("kill_switch".into())),
            "{causes:?}"
        );
    }

    /// A stored private key is used server-side, and its body lines are
    /// scrubbed if a command echoes them.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_with_a_stored_key() {
        let mut target = target_config();
        let pem = target.new_authorized_key("deploy");
        let body_line = pem.lines().nth(1).unwrap().to_string();
        let echoed = pem.clone();
        let fallback = target.responder.clone();
        target.responder = Arc::new(move |command| {
            if command == "cat-key" {
                ScriptedReply { stdout: echoed.clone().into_bytes(), exit_status: Some(0), ..Default::default() }
            } else {
                fallback(command)
            }
        });
        let rig = Rig::with_target("ssh_exec_key", target).await;
        let secret = json!({ "username": "deploy", "private_key": pem });
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "resources/secrets/web-01/login", true, obj(secret)).await;
        let answer = rig.call("cat-key").await;
        let sc = structured(&answer);
        assert_eq!(sc["login"], json!("stored-key"));
        let stdout = sc["stdout"].as_str().unwrap();
        assert!(!stdout.contains(&body_line) && stdout.contains("<redacted:credential>"), "{stdout}");
        assert!(stdout.contains("-----BEGIN OPENSSH PRIVATE KEY-----"), "armor is not secret");
        assert!(rig.server.events().iter().any(|e| e == "auth_publickey:deploy"), "{:?}", rig.server.events());
        let t = rig.transcripts().await;
        let TranscriptBody::Ssh(ssh) = &t[0].body;
        assert!(!ssh.stdout.text.contains(&body_line));
    }

    /// The preferred login: a certificate minted per call by the SSH engine,
    /// bound to the confirmed command, with no extension and a validity of a
    /// minute. A role that cannot bind the command is refused by name.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssh_exec_with_a_minted_certificate() {
        let rig = Rig::new("ssh_exec_cert").await;
        // The vault's SSH engine and its CA; a target that trusts that CA.
        test_mount_api(rig.core.as_ref(), &rig.root, "ssh", "ssh").await;
        let ca = test_write_api(
            rig.core.as_ref(),
            &rig.root,
            "ssh/config/ca",
            true,
            obj(json!({ "generate_signing_key": true })),
        )
        .await;
        let ca_public = ca.unwrap().unwrap().data.unwrap()["public_key"].as_str().unwrap().to_string();
        let mut target = target_config();
        target.trust_ca_openssh(&ca_public);
        let server = TestSshServer::start(target).await;
        let role = json!({
            "key_type": "ca",
            "allowed_users": "ops",
            "default_user": "ops",
            "allowed_critical_options": "force-command,source-address",
            "ttl": "60s",
            "max_ttl": "60s",
        });
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "ssh/roles/agent", true, obj(role)).await;
        let cert_profile = |port: u16, pin: &str, role: &str| {
            json!({
                "id": "p_agent", "name": "agent", "protocol": "ssh", "target_port": port, "username": "ops",
                "credential_source": { "kind": "ssh-engine", "mode": "ca", "ssh_mount": "ssh", "ssh_role": role },
                "host_key_pin": pin, "agent_access": "allow",
            })
        };
        let (port, pin) = (server.addr().port(), server.host_key_fingerprint());
        rig.write_profile(cert_profile(port, &pin, "agent"), true).await.unwrap();

        let answer = rig.call("uptime").await;
        let sc = structured(&answer);
        assert_eq!(sc["login"], json!("certificate"));
        assert_eq!(sc["exit_status"], json!(0));
        let seen = server.events();
        let cert_line = seen.iter().find(|e| e.starts_with("auth_cert:ops:")).unwrap_or_else(|| panic!("{seen:?}"));
        assert!(cert_line.contains("options[force-command=uptime]"), "{cert_line}");
        assert!(cert_line.contains(":extensions[]:"), "{cert_line}");
        let validity: u64 = cert_line.rsplit("validity=").next().unwrap().parse().unwrap();
        assert!(validity <= 60 + 30, "validity {validity} s");
        let exec = events(&rig.audit_log, "connect.agent.ssh.exec");
        assert!(exec[0]["cert_serial"].as_str().is_some_and(|s| s.len() == 16), "{exec:?}");

        // A role that does not allow force-command, and one that adds a
        // default extension, are refused by name before anything is dialed.
        let plain =
            json!({ "key_type": "ca", "allowed_users": "ops", "default_user": "ops", "ttl": "60s", "max_ttl": "60s" });
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "ssh/roles/agent-plain", true, obj(plain)).await;
        rig.write_profile(cert_profile(port, &pin, "agent-plain"), true).await.unwrap();
        let refused = rig.call("uptime").await;
        assert_eq!(code(&refused), "mcp_session_login_class_unsupported");
        assert!(refused["error"]["message"].as_str().unwrap().contains("`agent-plain`"), "{refused}");
        let pty = json!({
            "key_type": "ca", "allowed_users": "ops", "default_user": "ops", "ttl": "60s", "max_ttl": "60s",
            "allowed_critical_options": "force-command", "default_extensions": { "permit-pty": "" },
        });
        let _ = test_write_api(rig.core.as_ref(), &rig.root, "ssh/roles/agent-pty", true, obj(pty)).await;
        rig.write_profile(cert_profile(port, &pin, "agent-pty"), true).await.unwrap();
        let refused = rig.call("uptime").await;
        assert_eq!(code(&refused), "mcp_session_login_class_unsupported");
        assert!(refused["error"]["message"].as_str().unwrap().contains("permit-pty"), "{refused}");
        assert_eq!(count(&server.events(), "exec:"), 1, "the refused calls dialed nothing");
    }
}
