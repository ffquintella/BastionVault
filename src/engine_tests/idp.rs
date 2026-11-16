//! Tests for the identity-provider engine (`crates/bv-engine-idp`) through a
//! whole vault: the mount, v2-only routing, the entity check and the
//! root-namespace guard, none of which the crate's own tests can reach.

mod idp_tests {
    use std::collections::HashMap;

    use serde_json::{json, Map, Value};

    use crate::{
        errors::RvError,
        kernel_api::VaultCtx,
        logical::{Operation, Request, Response},
        test_utils::{new_unseal_test_bastion_vault, test_mount_api, test_write_api},
    };

    async fn call(
        core: &dyn VaultCtx,
        token: &str,
        op: Operation,
        path: &str,
        body: Option<Value>,
        api_version: u8,
        namespace: Option<&str>,
    ) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = op;
        req.client_token = token.to_string();
        req.api_version = api_version;
        req.body = body.and_then(|b| b.as_object().cloned());
        if let Some(ns) = namespace {
            req.headers = Some(HashMap::from([("x-bastionvault-namespace".to_string(), ns.to_string())]));
        }
        core.handle_request(&mut req).await
    }

    async fn v2(
        core: &dyn VaultCtx,
        token: &str,
        op: Operation,
        path: &str,
        body: Option<Value>,
    ) -> Result<Option<Response>, RvError> {
        call(core, token, op, path, body, 2, None).await
    }

    fn data(r: Result<Option<Response>, RvError>) -> Map<String, Value> {
        r.expect("request failed").expect("no response").data.expect("no data")
    }

    fn status(r: Result<Option<Response>, RvError>) -> u16 {
        match r {
            Ok(_) => 200,
            Err(RvError::ErrResponseStatus(s, _)) => s,
            Err(RvError::ErrPermissionDenied) => 403,
            Err(RvError::ErrRequestClientTokenMissing) => 401,
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn idp_identity_lifecycle_through_the_logical_backend() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("idp_identity_lifecycle").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        test_mount_api(ctx, &root, "idp", "idp").await;
        let identity = ctx.identity().expect("identity service");
        let alice = identity.ensure_entity_id("userpass/", "alice", "").await.unwrap();
        let bob = identity.ensure_entity_id("userpass/", "bob", "").await.unwrap();
        let carol = identity.ensure_entity_id("userpass/", "carol", "").await.unwrap();

        // v1 is frozen: the engine answers under /v2 only.
        assert_eq!(status(call(ctx, &root, Operation::Read, "idp/config", None, 1, None).await), 400);
        let cfg = data(v2(ctx, &root, Operation::Read, "idp/config", None).await);
        assert_eq!((cfg["uid_min"].as_u64(), cfg["pinned"].as_bool()), (Some(80_000), Some(false)));

        // Only an existing entity gets an identity.
        let ghost = v2(ctx, &root, Operation::Write, "idp/identities/no-such-entity", Some(json!({"login": "ghost"})));
        assert_eq!(status(ghost.await), 404);

        let path_a = format!("idp/identities/{alice}");
        let path_b = format!("idp/identities/{bob}");
        let path_c = format!("idp/identities/{carol}");
        let a = data(
            v2(
                ctx,
                &root,
                Operation::Write,
                &path_a,
                Some(json!({"login": "alice", "display_name": "Alice", "gids": [4]})),
            )
            .await,
        );
        assert_eq!((a["uid"].as_u64(), a["primary_gid"].as_u64()), (Some(80_000), Some(80_000)));
        assert_eq!((a["state"].as_str(), a["created"].as_bool()), (Some("active"), Some(true)));
        let read = data(v2(ctx, &root, Operation::Read, &path_a, None).await);
        assert_eq!((read["login"].as_str(), read["gids"].clone()), (Some("alice"), json!([4])));

        // Immutable fields and malformed input.
        assert_eq!(status(v2(ctx, &root, Operation::Write, &path_a, Some(json!({"login": "alice2"}))).await), 400);
        assert_eq!(status(v2(ctx, &root, Operation::Write, &path_a, Some(json!({"uid": 1}))).await), 400);
        assert_eq!(status(v2(ctx, &root, Operation::Write, &path_a, Some(json!({"gids": "4,5"}))).await), 400);
        assert_eq!(status(v2(ctx, &root, Operation::Write, &path_b, Some(json!({"login": "Root"}))).await), 400);

        let list = data(v2(ctx, &root, Operation::List, "idp/identities/", None).await);
        assert_eq!(list["keys"], json!([alice.clone()]));
        assert_eq!(list["key_info"][&alice]["uid"].as_u64(), Some(80_000));

        // Lifecycle: DELETE needs a disabled identity, removal is terminal.
        assert_eq!(status(v2(ctx, &root, Operation::Delete, &path_a, None).await), 409);
        let state_a = format!("{path_a}/state");
        let disabled = data(v2(ctx, &root, Operation::Write, &state_a, Some(json!({"state": "disabled"}))).await);
        assert_eq!(disabled["state"].as_str(), Some("disabled"));
        assert_eq!(status(v2(ctx, &root, Operation::Write, &state_a, Some(json!({"state": "gone"}))).await), 400);
        let removed = data(v2(ctx, &root, Operation::Delete, &path_a, None).await);
        assert_eq!(removed["state"].as_str(), Some("removed"));
        assert_eq!(status(v2(ctx, &root, Operation::Write, &state_a, Some(json!({"state": "active"}))).await), 409);

        // The removed uid and login are never handed out again.
        let b = data(v2(ctx, &root, Operation::Write, &path_b, Some(json!({"login": "bob"}))).await);
        assert_eq!(b["uid"].as_u64(), Some(80_001));
        assert_eq!(status(v2(ctx, &root, Operation::Write, &path_c, Some(json!({"login": "alice"}))).await), 409);
        let reuse_uid = json!({"login": "carol", "uid_source": "imported", "uid": 80_000, "primary_gid": 95_000});
        assert_eq!(status(v2(ctx, &root, Operation::Write, &path_c, Some(reuse_uid)).await), 409);
        let seeded = json!({"login": "carol", "uid_source": "imported", "uid": 5000});
        let c = data(v2(ctx, &root, Operation::Write, &path_c, Some(seeded)).await);
        assert_eq!((c["uid"].as_u64(), c["uid_source"].as_str()), (Some(5000), Some("imported")));

        let cfg = data(v2(ctx, &root, Operation::Read, "idp/config", None).await);
        assert_eq!((cfg["pinned"].as_bool(), cfg["uid_high_water"].as_u64()), (Some(true), Some(80_001)));
        assert_eq!(cfg["uid_retired"].as_u64(), Some(1));
        assert_eq!(status(v2(ctx, &root, Operation::Write, "idp/config", Some(json!({"uid_min": 10}))).await), 400);
        let moved = data(
            v2(ctx, &root, Operation::Write, "idp/config", Some(json!({"uid_min": 200_000, "uid_max": 300_000}))).await,
        );
        assert_eq!(moved["uid_min"].as_u64(), Some(200_000));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn idp_is_root_namespace_only() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("idp_root_namespace_only").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        test_mount_api(ctx, &root, "idp", "idp").await;
        test_write_api(ctx, &root, "sys/namespaces/tenant", true, json!({}).as_object().cloned()).await.unwrap();
        // A tenant mounting the `idp` type must not reach the deployment-wide store.
        call(ctx, &root, Operation::Write, "sys/mounts/idp/", Some(json!({"type": "idp"})), 1, Some("tenant"))
            .await
            .unwrap();

        // Header form: rewritten into the tenant's own mount, then refused.
        let header = call(ctx, &root, Operation::Read, "idp/config", None, 2, Some("tenant")).await;
        assert_eq!(status(header), 403);
        // Path-prefix form, no header: refused by the root-mount check.
        let prefixed = call(ctx, &root, Operation::Read, "tenant/idp/config", None, 2, None).await;
        assert_eq!(status(prefixed), 403);
        let write = json!({"login": "mallory"});
        let prefixed_write = call(ctx, &root, Operation::Write, "tenant/idp/identities/x", Some(write), 2, None).await;
        assert_eq!(status(prefixed_write), 403);

        // The root mount still serves.
        assert_eq!(status(v2(ctx, &root, Operation::Read, "idp/config", None).await), 200);
    }

    /// A file audit device in a fresh directory, so the test can read back
    /// the `idp.issue` / `idp.issue-denied` events. Returns (dir, log path).
    async fn enable_audit_file(ctx: &dyn VaultCtx, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "bv-idp-{name}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log");
        let broker = ctx.audit_broker().expect("broker installed at unseal");
        let options = HashMap::from([("file_path".to_string(), log.display().to_string())]);
        broker
            .enable_device(crate::audit::AuditDeviceConfig {
                path: format!("idp-{name}"),
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

    /// The `data` of every audit event entry named `name`, in order.
    fn audit_events(log: &std::path::Path, name: &str) -> Vec<Value> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|e| e["type"] == "event" && e["request"]["path"] == name)
            .map(|e| e["request"]["data"].clone())
            .collect()
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn idp_entitlements_and_the_issue_gate_through_the_vault() {
        use crate::modules::idp::{
            entitlement::gate::{DenyReason, IssueRequest},
            IdpModule,
        };
        use crate::test_utils::test_delete_api;

        let (_bvault, core, root) = new_unseal_test_bastion_vault("idp_entitlements_gate").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        test_mount_api(ctx, &root, "idp", "idp").await;
        for ns in ["prod", "dev", "stage"] {
            let path = format!("sys/namespaces/{ns}");
            test_write_api(ctx, &root, &path, true, json!({}).as_object().cloned()).await.unwrap();
        }
        let (audit_dir, audit_log) = enable_audit_file(ctx, "gate").await;
        let identity = ctx.identity().expect("identity service");
        let alice = identity.ensure_entity_id("userpass/", "alice", "").await.unwrap();
        let bob = identity.ensure_entity_id("userpass/", "bob", "").await.unwrap();
        let carol = identity.ensure_entity_id("userpass/", "carol", "").await.unwrap();
        for (id, login) in [(&alice, "alice"), (&bob, "bob")] {
            let path = format!("idp/identities/{id}");
            data(v2(ctx, &root, Operation::Write, &path, Some(json!({"login": login}))).await);
        }

        // Environments: v2 only, bound to an existing namespace by uuid, one
        // per namespace, the binding immutable, `root` never a role policy.
        let env = |name: &str| format!("idp/environments/{name}");
        assert_eq!(status(call(ctx, &root, Operation::Read, &env("prod"), None, 1, None).await), 400);
        let prod_body = json!({"namespace": "prod", "roles": {"sysadmin": ["prod-admin"], "dba": ["prod-dba"]}});
        let prod = data(v2(ctx, &root, Operation::Write, &env("prod"), Some(prod_body)).await);
        assert_eq!((prod["namespace"].as_str(), prod["created"].as_bool()), (Some("prod"), Some(true)));
        assert!(!prod["namespace_uuid"].as_str().unwrap().is_empty());
        let dev_body = json!({"namespace": "dev", "roles": {"sysadmin": ["dev-admin"]}});
        data(v2(ctx, &root, Operation::Write, &env("dev"), Some(dev_body)).await);
        let stage_body = json!({"namespace": "stage", "roles": {"ops": ["stage-ops"]}});
        data(v2(ctx, &root, Operation::Write, &env("stage"), Some(stage_body)).await);
        let core_env = data(v2(ctx, &root, Operation::Write, &env("core"), Some(json!({"namespace": ""}))).await);
        assert_eq!(core_env["namespace"].as_str(), Some(""));
        for (name, body, code) in [
            ("prod2", json!({"namespace": "prod"}), 409),
            ("qa", json!({"namespace": "no-such-ns"}), 404),
            ("qa", json!({"roles": {}}), 400),
            ("prod", json!({"namespace": "dev"}), 400),
            ("evil", json!({"namespace": "prod", "roles": {"sysadmin": ["root"]}}), 400),
            ("Prod", json!({"namespace": "prod"}), 400),
        ] {
            assert_eq!(status(v2(ctx, &root, Operation::Write, &env(name), Some(body)).await), code, "{name}");
        }
        let list = data(v2(ctx, &root, Operation::List, "idp/environments/", None).await);
        assert_eq!(list["keys"], json!(["core", "dev", "prod", "stage"]));

        // Entitlements: the identity and every role must exist, not_after
        // must be in the future, `group` is not writable yet.
        let ent = |id: &str, e: &str| format!("idp/entitlements/{id}/{e}");
        let granted =
            data(v2(ctx, &root, Operation::Write, &ent(&alice, "prod"), Some(json!({"roles": ["sysadmin"]}))).await);
        assert_eq!((granted["roles"].clone(), granted["created"].as_bool()), (json!(["sysadmin"]), Some(true)));
        assert!(!granted["granted_by"].as_str().unwrap().is_empty());
        data(v2(ctx, &root, Operation::Write, &ent(&alice, "stage"), Some(json!({"roles": ["ops"]}))).await);
        for (path, body, code) in [
            (ent(&alice, "prod"), json!({"roles": ["ghost"]}), 400),
            (ent(&alice, "prod"), json!({"roles": "sysadmin"}), 400),
            (ent(&alice, "prod"), json!({}), 400),
            (ent(&alice, "prod"), json!({"roles": ["dba"], "not_after": "2001-01-01T00:00:00Z"}), 400),
            (ent(&alice, "prod"), json!({"roles": ["dba"], "source": "group"}), 400),
            (ent(&carol, "prod"), json!({"roles": ["dba"]}), 404),
            (ent(&alice, "qa"), json!({"roles": ["dba"]}), 404),
        ] {
            assert_eq!(
                status(v2(ctx, &root, Operation::Write, &path, Some(body.clone())).await),
                code,
                "{path} {body}"
            );
        }
        let all = data(v2(ctx, &root, Operation::Read, &format!("idp/entitlements/{alice}"), None).await);
        assert_eq!(all["entitlements"]["prod"]["roles"], json!(["sysadmin"]));
        let one = data(v2(ctx, &root, Operation::Read, &ent(&alice, "prod"), None).await);
        assert_eq!(one["environment"].as_str(), Some("prod"));

        // A tenant that mounts the type reaches none of it, in either form.
        call(ctx, &root, Operation::Write, "sys/mounts/idp/", Some(json!({"type": "idp"})), 1, Some("dev"))
            .await
            .unwrap();
        let grant_body = json!({"roles": ["sysadmin"]});
        let (bob_dev, prefixed_bob_dev, prefixed_prod) =
            (ent(&bob, "dev"), format!("dev/{}", ent(&bob, "dev")), format!("dev/{}", env("prod")));
        let header = call(ctx, &root, Operation::Write, &bob_dev, Some(grant_body.clone()), 2, Some("dev"));
        assert_eq!(status(header.await), 403);
        let prefixed = call(ctx, &root, Operation::Write, &prefixed_bob_dev, Some(grant_body), 2, None);
        assert_eq!(status(prefixed.await), 403);
        let prefixed_env = call(ctx, &root, Operation::Read, &prefixed_prod, None, 2, None);
        assert_eq!(status(prefixed_env.await), 403);

        // The gate, as a provider calls it.
        let module = core.module_manager().get_module::<IdpModule>("idp").expect("idp module");
        let gate = module.issue_gate();
        let ask = |id: &str, e: &str, caller_ns: &str| IssueRequest {
            entity_id: id.to_string(),
            environment: e.to_string(),
            roles: None,
            caller_namespace: caller_ns.to_string(),
            provider: "test".to_string(),
        };
        let grant = gate.authorize(&ask(&alice, "prod", ""), None).await.unwrap();
        assert_eq!((grant.login.as_str(), grant.namespace.as_str()), ("alice", "prod"));
        assert_eq!(
            (grant.roles.clone(), grant.policies.clone()),
            (vec!["sysadmin".to_string()], vec!["prod-admin".to_string()])
        );
        let reason = |r: Result<_, crate::modules::idp::entitlement::gate::IssueDenied>| r.unwrap_err().reason;
        assert_eq!(reason(gate.authorize(&ask(&alice, "dev", ""), None).await), DenyReason::NotEntitled);
        assert_eq!(reason(gate.authorize(&ask(&bob, "prod", ""), None).await), DenyReason::NotEntitled);
        assert_eq!(reason(gate.authorize(&ask(&carol, "prod", ""), None).await), DenyReason::NoIdentity);
        assert_eq!(reason(gate.authorize(&ask(&alice, "prod", "dev"), None).await), DenyReason::NamespaceMismatch);

        // Disable, reinstate, revoke: each applies at the next evaluation.
        let state = format!("idp/identities/{alice}/state");
        data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "disabled"}))).await);
        assert_eq!(reason(gate.authorize(&ask(&alice, "prod", ""), None).await), DenyReason::IdentityDisabled);
        data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "active"}))).await);
        gate.authorize(&ask(&alice, "prod", "prod"), None).await.unwrap();
        let revoked = data(v2(ctx, &root, Operation::Delete, &ent(&alice, "prod"), None).await);
        assert_eq!(revoked["revoked"].as_bool(), Some(true));
        assert_eq!(reason(gate.authorize(&ask(&alice, "prod", ""), None).await), DenyReason::NotEntitled);

        // A namespace deleted, then recreated under the same path, does not
        // carry the environment's entitlements across.
        gate.authorize(&ask(&alice, "stage", ""), None).await.unwrap();
        test_delete_api(ctx, &root, "sys/namespaces/stage", true, None).await.unwrap();
        assert_eq!(reason(gate.authorize(&ask(&alice, "stage", ""), None).await), DenyReason::NamespaceMissing);
        test_write_api(ctx, &root, "sys/namespaces/stage", true, json!({}).as_object().cloned()).await.unwrap();
        assert_eq!(reason(gate.authorize(&ask(&alice, "stage", ""), None).await), DenyReason::NamespaceReplaced);

        // A retired environment denies and its name is never reused.
        data(v2(ctx, &root, Operation::Delete, &env("stage"), None).await);
        assert_eq!(reason(gate.authorize(&ask(&alice, "stage", ""), None).await), DenyReason::EnvironmentRetired);
        let stage = env("stage");
        let reuse = v2(ctx, &root, Operation::Write, &stage, Some(json!({"namespace": "stage"})));
        assert_eq!(status(reuse.await), 409);

        // Every decision reached the audit device, with its fields.
        let issued = audit_events(&audit_log, "idp.issue");
        assert_eq!(issued.len(), 3, "{issued:?}");
        let first = &issued[0];
        assert_eq!((first["decision"].as_str(), first["entity_id"].as_str()), (Some("allow"), Some(alice.as_str())));
        assert_eq!((first["login"].as_str(), first["uid"].as_u64()), (Some("alice"), Some(80_000)));
        assert_eq!((first["environment"].as_str(), first["namespace"].as_str()), (Some("prod"), Some("prod")));
        assert_eq!((first["roles"].clone(), first["policies"].clone()), (json!(["sysadmin"]), json!(["prod-admin"])));
        let denied: Vec<String> = audit_events(&audit_log, "idp.issue-denied")
            .iter()
            .map(|d| {
                assert_eq!(d["decision"].as_str(), Some("deny"));
                d["reason"].as_str().unwrap().to_string()
            })
            .collect();
        let expected = [
            "not_entitled",
            "not_entitled",
            "no_identity",
            "namespace_mismatch",
            "identity_disabled",
            "not_entitled",
            "namespace_missing",
            "namespace_replaced",
            "environment_retired",
        ];
        assert_eq!(denied, expected);
        let _ = std::fs::remove_dir_all(audit_dir);
    }

    /// Phase 3 end to end: self-service sign through the real SSH engine
    /// of each environment's namespace, then disable, KRL, signed deny feed,
    /// reinstate and removal.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn idp_ssh_identity_certificates_and_revocation_through_the_vault() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use ssh_key::{rand_core::OsRng, Algorithm, Certificate, PrivateKey};

        use crate::{
            modules::idp::revoke::{
                feed::{verify_feed, FeedError, FeedPublicKey},
                krl::parse_krl,
            },
            test_utils::test_mount_auth_api,
        };

        let (_bvault, core, root) = new_unseal_test_bastion_vault("idp_ssh_identity").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        test_mount_api(ctx, &root, "idp", "idp").await;
        let (audit_dir, audit_log) = enable_audit_file(ctx, "ssh").await;

        // An SSH engine with its own CA in root and in `prod`. The role lets
        // through any principal: the IdP's gate is the authority, and no
        // token is granted this SSH path.
        test_write_api(ctx, &root, "sys/namespaces/prod", true, json!({}).as_object().cloned()).await.unwrap();
        let role = json!({
            "key_type": "ca",
            "allowed_users": "*",
            "allowed_extensions": "uid@bastionvault,gid@bastionvault,env@bastionvault,roles@bastionvault",
            "default_extensions": {"permit-pty": ""},
            "ttl": "30m",
            "max_ttl": "2h"
        });
        for ns in [None, Some("prod")] {
            call(ctx, &root, Operation::Write, "sys/mounts/ssh/", Some(json!({"type": "ssh"})), 1, ns).await.unwrap();
            let ca = json!({"generate_signing_key": true});
            call(ctx, &root, Operation::Write, "ssh/config/ca", Some(ca), 1, ns).await.unwrap();
            call(ctx, &root, Operation::Write, "ssh/roles/idp", Some(role.clone()), 1, ns).await.unwrap();
        }

        // alice logs in through userpass; her policy allows the sign path only.
        test_mount_auth_api(ctx, &root, "userpass", "userpass").await;
        let policy = r#"path "idp/ssh/sign/*" { capabilities = ["create", "update"] }"#;
        test_write_api(ctx, &root, "sys/policy/idp-ssh", true, json!({"policy": policy}).as_object().cloned())
            .await
            .unwrap();
        let user = json!({"password": "pw-123456", "policies": "idp-ssh"});
        test_write_api(ctx, &root, "auth/userpass/users/alice", true, user.as_object().cloned()).await.unwrap();
        let mut login = Request::new("auth/userpass/login/alice");
        login.operation = Operation::Write;
        login.body = json!({"password": "pw-123456"}).as_object().cloned();
        let auth = ctx.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap();
        let (token, alice) = (auth.client_token.clone(), auth.metadata["entity_id"].clone());

        data(
            v2(ctx, &root, Operation::Write, &format!("idp/identities/{alice}"), Some(json!({"login": "alice"}))).await,
        );
        let core_env = json!({"namespace": "", "roles": {"ops": ["ops"]}});
        data(v2(ctx, &root, Operation::Write, "idp/environments/core", Some(core_env)).await);
        let prod_env = json!({"namespace": "prod", "roles": {"ops": ["prod-ops"]}});
        data(v2(ctx, &root, Operation::Write, "idp/environments/prod", Some(prod_env)).await);
        for env in ["core", "prod"] {
            let path = format!("idp/entitlements/{alice}/{env}");
            data(v2(ctx, &root, Operation::Write, &path, Some(json!({"roles": ["ops"]}))).await);
        }

        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap().public_key().to_openssh().unwrap();
        let body = json!({"public_key": key});
        let sign = |env: &str| format!("idp/ssh/sign/{env}");

        // Off until configured; v2 only; self-service only.
        assert_eq!(status(v2(ctx, &token, Operation::Write, &sign("core"), Some(body.clone())).await), 400);
        let cfg = json!({"default_ttl": "10m", "max_ttl": "1h"});
        let cfg = data(v2(ctx, &root, Operation::Write, "idp/ssh/config", Some(cfg)).await);
        assert_eq!(
            (cfg["mount"].as_str(), cfg["role"].as_str(), cfg["max_ttl"].as_u64()),
            (Some("ssh"), Some("idp"), Some(3600))
        );
        let v1 = call(ctx, &token, Operation::Write, &sign("core"), Some(body.clone()), 1, None).await;
        assert_eq!(status(v1), 400);
        assert_eq!(status(v2(ctx, &root, Operation::Write, &sign("core"), Some(body.clone())).await), 403);
        let too_long = json!({"public_key": key, "ttl": "2h"});
        assert_eq!(status(v2(ctx, &token, Operation::Write, &sign("core"), Some(too_long)).await), 400);
        // Her token reaches nothing else here.
        assert_eq!(status(v2(ctx, &token, Operation::Read, "idp/ssh/krl", None).await), 403);
        assert_eq!(status(v2(ctx, &token, Operation::Write, "idp/ssh/config", Some(json!({}))).await), 403);

        // Signed by each environment's own CA, with the same identity.
        let issued_core = data(v2(ctx, &token, Operation::Write, &sign("core"), Some(body.clone())).await);
        let issued_prod = data(v2(ctx, &token, Operation::Write, &sign("prod"), Some(body.clone())).await);
        let core_cert = Certificate::from_openssh(issued_core["signed_key"].as_str().unwrap()).unwrap();
        let prod_cert = Certificate::from_openssh(issued_prod["signed_key"].as_str().unwrap()).unwrap();
        assert_eq!(core_cert.valid_principals(), ["alice".to_string()]);
        assert_eq!(core_cert.key_id(), format!("bv:{alice}:alice:uid=80000:env=core"));
        for (cert, env) in [(&core_cert, "core"), (&prod_cert, "prod")] {
            let ext = |k: &str| cert.extensions().get(k).cloned();
            assert_eq!(ext("uid@bastionvault").as_deref(), Some("80000"), "{env}");
            assert_eq!(ext("gid@bastionvault").as_deref(), Some("80000"), "{env}");
            assert_eq!(ext("env@bastionvault").as_deref(), Some(env));
            assert_eq!(ext("roles@bastionvault").as_deref(), Some("ops"));
            assert!(cert.extensions().contains_key("permit-pty"), "the role's default extension");
            assert!(
                cert.valid_before() - cert.valid_after() <= 600 + 60,
                "{env}: 10m default plus the role's backdating"
            );
        }
        assert_ne!(core_cert.signature_key(), prod_cert.signature_key(), "one CA per environment namespace");

        // Nothing revoked yet.
        let feed_key = FeedPublicKey::from_value(&Value::Object(data(
            v2(ctx, &root, Operation::Read, "idp/deny-feed/key", None).await,
        )))
        .unwrap();
        let read_feed = |d: &Map<String, Value>, accepted: u64| {
            verify_feed(d["feed"].as_str().unwrap(), d["signature"].as_str().unwrap(), &feed_key, accepted)
        };
        assert_eq!(data(v2(ctx, &root, Operation::Read, "idp/ssh/krl", None).await)["revoked_serials"], json!([]));
        let served0 = data(v2(ctx, &root, Operation::Read, "idp/deny-feed", None).await);
        let feed0 = read_feed(&served0, 0).unwrap();
        assert!(feed0.identities.is_empty() && feed0.revoked_serials.is_empty());

        // Disable: both certificates revoked at once, the next sign denied.
        let state = format!("idp/identities/{alice}/state");
        let disabled = data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "disabled"}))).await);
        assert_eq!(disabled["revoked_certificates"].as_u64(), Some(2));
        assert!(disabled["deny_feed_version"].as_u64().unwrap() > feed0.feed_version);
        assert_eq!(status(v2(ctx, &token, Operation::Write, &sign("core"), Some(body.clone())).await), 403);
        let mut serials = vec![issued_core["serial_number"].clone(), issued_prod["serial_number"].clone()];
        serials.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        let krl = data(v2(ctx, &root, Operation::Read, "idp/ssh/krl", None).await);
        assert_eq!(krl["revoked_serials"], json!(serials));
        let parsed = parse_krl(&B64.decode(krl["krl"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(parsed.serials.len(), 2, "one certificate section per CA");
        assert!(parsed.serials.values().all(|s| s.len() == 1));
        let served1 = data(v2(ctx, &root, Operation::Read, "idp/deny-feed", None).await);
        let feed1 = read_feed(&served1, feed0.feed_version).unwrap();
        assert_eq!(feed1.feed_version, krl["krl_version"].as_u64().unwrap());
        assert_eq!((feed1.identities[0].login.as_str(), feed1.identities[0].state.as_str()), ("alice", "disabled"));
        assert_eq!(json!(feed1.revoked_serials), json!(serials));
        // A host that saw the new feed refuses the old one.
        assert!(matches!(read_feed(&served0, feed1.feed_version), Err(FeedError::Rollback { .. })));

        // Reinstate: the old certificates stay revoked, a new one is good.
        data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "active"}))).await);
        let fresh = data(v2(ctx, &token, Operation::Write, &sign("core"), Some(body.clone())).await);
        let krl = data(v2(ctx, &root, Operation::Read, "idp/ssh/krl", None).await);
        assert_eq!(krl["revoked_serials"], json!(serials));
        // Disable and remove: the new one joins them.
        data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "disabled"}))).await);
        let removed = data(v2(ctx, &root, Operation::Delete, &format!("idp/identities/{alice}"), None).await);
        assert_eq!(removed["state"].as_str(), Some("removed"));
        let krl = data(v2(ctx, &root, Operation::Read, "idp/ssh/krl", None).await);
        assert!(krl["revoked_serials"].as_array().unwrap().contains(&fresh["serial_number"]));
        let feed2 =
            read_feed(&data(v2(ctx, &root, Operation::Read, "idp/deny-feed", None).await), feed1.feed_version).unwrap();
        assert_eq!(feed2.identities[0].state, "removed");

        // The gate's events are the issuance record: three allows, one deny.
        let allows = audit_events(&audit_log, "idp.issue");
        assert_eq!(allows.len(), 3, "{allows:?}");
        assert!(allows.iter().all(|e| e["provider"] == "ssh" && e["entity_id"] == alice.as_str()));
        let denies: Vec<Value> =
            audit_events(&audit_log, "idp.issue-denied").iter().map(|e| e["reason"].clone()).collect();
        assert_eq!(denies, [json!("identity_disabled")]);
        let _ = std::fs::remove_dir_all(audit_dir);
    }

    /// Phase 4 end to end: a passcode minted through v2 by a userpass login,
    /// sent by a NAS over the vault's own UDP listener, then a disable.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn idp_radius_access_requests_through_the_vault() {
        use std::time::Duration;

        use crate::modules::idp::provider::radius::packet::{
            attr, code, encode_request, hide_password, parse, verify_response,
        };

        const SECRET: &str = "fortigate-shared-secret-01";
        let (_bvault, core, root) = new_unseal_test_bastion_vault("idp_radius").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        test_mount_api(ctx, &root, "idp", "idp").await;
        let (audit_dir, audit_log) = enable_audit_file(ctx, "radius").await;

        test_mount_auth_api_for_radius(ctx, &root).await;
        let mut login = Request::new("auth/userpass/login/alice");
        login.operation = Operation::Write;
        login.body = json!({"password": "pw-123456"}).as_object().cloned();
        let auth = ctx.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap();
        let (token, alice) = (auth.client_token.clone(), auth.metadata["entity_id"].clone());
        data(
            v2(ctx, &root, Operation::Write, &format!("idp/identities/{alice}"), Some(json!({"login": "alice"}))).await,
        );
        let env = json!({"namespace": "", "roles": {"netadmin": ["net-admin"], "readonly": ["net-ro"]}});
        data(v2(ctx, &root, Operation::Write, "idp/environments/net", Some(env)).await);
        let grant = json!({"roles": ["netadmin"]});
        data(v2(ctx, &root, Operation::Write, &format!("idp/entitlements/{alice}/net"), Some(grant)).await);

        // Off by default: no passcode, nothing listening.
        let passcode = |body: Value| v2(ctx, &token, Operation::Write, "idp/radius/passcode/net", Some(body));
        assert_eq!(status(passcode(json!({})).await), 400);
        let cfg = data(v2(ctx, &root, Operation::Read, "idp/radius/config", None).await);
        assert_eq!((cfg["enabled"].as_bool(), cfg["listening"]["udp"].clone()), (Some(false), Value::Null));

        let profile = json!({"environment": "net", "roles": {
            "netadmin": [{"attribute": "fortinet-group-name", "value": "bv-super"}]}});
        data(v2(ctx, &root, Operation::Write, "idp/radius/profiles/fgt", Some(profile)).await);
        let bad = json!({"environment": "net", "roles": {"dba": [{"attribute": "fortinet-group-name", "value": "x"}]}});
        assert_eq!(status(v2(ctx, &root, Operation::Write, "idp/radius/profiles/bad", Some(bad)).await), 400);
        let nas = json!({"transport": "udp", "environment": "net", "profile": "fgt",
            "address": "127.0.0.1", "secret": SECRET});
        let client = data(v2(ctx, &root, Operation::Write, "idp/radius/clients/fgt1", Some(nas)).await);
        assert_eq!((client["secret_set"].as_bool(), client.get("secret")), (Some(true), None));
        let read = data(v2(ctx, &root, Operation::Read, "idp/radius/clients/fgt1", None).await);
        assert!(!Value::Object(read).to_string().contains(SECRET));

        // UDP must be asked for explicitly; then the listener comes up.
        let half = json!({"enabled": true, "udp_listen": "127.0.0.1:0"});
        assert_eq!(status(v2(ctx, &root, Operation::Write, "idp/radius/config", Some(half)).await), 400);
        let on = json!({"enabled": true, "udp_enabled": true, "udp_listen": "127.0.0.1:0"});
        data(v2(ctx, &root, Operation::Write, "idp/radius/config", Some(on)).await);
        let mut listening = None;
        for _ in 0..250 {
            let cfg = data(v2(ctx, &root, Operation::Read, "idp/radius/config", None).await);
            if let Some(addr) = cfg["listening"]["udp"].as_str() {
                listening = Some(addr.parse::<std::net::SocketAddr>().unwrap());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let server = listening.expect("the UDP listener never came up");

        // v2 only; self-service only (the root token has no entity).
        assert_eq!(status(call(ctx, &token, Operation::Write, "idp/radius/passcode/net", None, 1, None).await), 400);
        assert_eq!(status(v2(ctx, &root, Operation::Write, "idp/radius/passcode/net", Some(json!({}))).await), 403);
        let minted = data(passcode(json!({"ttl": "1m"})).await);
        let code_a = minted["passcode"].as_str().unwrap().to_string();
        assert_eq!((minted["login"].as_str(), minted["ttl"].as_u64()), (Some("alice"), Some(60)));
        assert_eq!(status(passcode(json!({"roles": ["readonly"]})).await), 403, "not entitled to readonly");
        let code_b = data(passcode(json!({})).await)["passcode"].as_str().unwrap().to_string();

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exchange = |id: u8, user: &str, password: &str| {
            let auth = [id; 16];
            let hidden = hide_password(password.as_bytes(), SECRET.as_bytes(), &auth).unwrap();
            let attrs = vec![(attr::USER_NAME, user.as_bytes().to_vec()), (attr::USER_PASSWORD, hidden)];
            (encode_request(id, &auth, &attrs, SECRET.as_bytes()).unwrap(), auth)
        };
        let send = |pkt: Vec<u8>| {
            let sock = &sock;
            async move {
                sock.send_to(&pkt, server).await.unwrap();
                let mut buf = vec![0u8; 4096];
                let got = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await;
                let (n, _) = got.expect("no reply").unwrap();
                buf.truncate(n);
                buf
            }
        };
        let (pkt, auth) = exchange(1, "alice", &code_a);
        let reply = send(pkt).await;
        assert_eq!(reply[0], code::ACCESS_ACCEPT);
        assert!(verify_response(&reply, &auth, SECRET.as_bytes()));
        let p = parse(&reply).unwrap();
        let vsa = p.attributes.iter().find(|a| a.kind == attr::VENDOR_SPECIFIC).unwrap();
        assert_eq!(vsa.value, [&[0, 0, 0x30, 0x44, 1, 10][..], b"bv-super"].concat(), "Fortinet-Group-Name");

        // Disabled after the passcode was minted: rejected at once.
        let state = format!("idp/identities/{alice}/state");
        data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "disabled"}))).await);
        let (pkt, auth) = exchange(2, "alice", &code_b);
        let reply = send(pkt).await;
        assert_eq!(reply[0], code::ACCESS_REJECT);
        assert!(verify_response(&reply, &auth, SECRET.as_bytes()));

        // The gate's events and the RADIUS events, with no secret in them.
        let issued: Vec<Value> = audit_events(&audit_log, "idp.issue").iter().map(|e| e["provider"].clone()).collect();
        assert_eq!(issued, [json!("radius-passcode"), json!("radius-passcode"), json!("radius")]);
        let denied = audit_events(&audit_log, "idp.issue-denied");
        let reasons: Vec<(Value, Value)> =
            denied.iter().map(|e| (e["provider"].clone(), e["reason"].clone())).collect();
        assert_eq!(
            reasons,
            [(json!("radius-passcode"), json!("role_not_entitled")), (json!("radius"), json!("identity_disabled"))]
        );
        let accepted = audit_events(&audit_log, "idp.radius.accept");
        assert_eq!(accepted.len(), 1);
        assert_eq!((accepted[0]["client"].as_str(), accepted[0]["user_name"].as_str()), (Some("fgt1"), Some("alice")));
        let rejected = audit_events(&audit_log, "idp.radius.reject");
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["gate_reason"].as_str(), Some("identity_disabled"));
        let log = std::fs::read_to_string(&audit_log).unwrap();
        for secret in [SECRET, code_a.as_str(), code_b.as_str()] {
            assert!(!log.contains(secret), "the audit log never holds a secret or a passcode");
        }
        data(v2(ctx, &root, Operation::Write, "idp/radius/config", Some(json!({"enabled": false}))).await);
        let _ = std::fs::remove_dir_all(audit_dir);
    }

    /// Phase 5 end to end: the OIDC code flow and SAML SSO through the
    /// logical backend, with the relying-party endpoints called without a
    /// vault token, then a disable.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn idp_oidc_and_saml_through_the_vault() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        use crate::modules::idp::provider::oidc_op::{jwt::verify_rs256, s256};

        const ISSUER: &str = "https://vault.example.com/v2/idp/oidc";
        const REDIRECT: &str = "https://app.example.com/cb";
        const SP: &str = "https://sp.example.com/metadata";
        const ACS: &str = "https://sp.example.com/acs";
        const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let (_bvault, core, root) = new_unseal_test_bastion_vault("idp_federation").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        test_mount_api(ctx, &root, "idp", "idp").await;
        let (audit_dir, audit_log) = enable_audit_file(ctx, "federation").await;

        crate::test_utils::test_mount_auth_api(ctx, &root, "userpass", "userpass").await;
        let policy = r#"
            path "idp/oidc/authorize" { capabilities = ["create", "update"] }
            path "idp/saml/sso" { capabilities = ["create", "update"] }
        "#;
        test_write_api(ctx, &root, "sys/policy/idp-sso", true, json!({"policy": policy}).as_object().cloned())
            .await
            .unwrap();
        let user = json!({"password": "pw-123456", "policies": "idp-sso"});
        test_write_api(ctx, &root, "auth/userpass/users/alice", true, user.as_object().cloned()).await.unwrap();
        let mut login = Request::new("auth/userpass/login/alice");
        login.operation = Operation::Write;
        login.body = json!({"password": "pw-123456"}).as_object().cloned();
        let auth = ctx.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap();
        let (token, alice) = (auth.client_token.clone(), auth.metadata["entity_id"].clone());
        data(
            v2(ctx, &root, Operation::Write, &format!("idp/identities/{alice}"), Some(json!({"login": "alice"}))).await,
        );
        let env = json!({"namespace": "", "roles": {"ops": ["ops"], "audit": ["audit"]}});
        data(v2(ctx, &root, Operation::Write, "idp/environments/apps", Some(env)).await);
        let grant = json!({"roles": ["ops"]});
        data(v2(ctx, &root, Operation::Write, &format!("idp/entitlements/{alice}/apps"), Some(grant)).await);
        // Relying-party calls carry no vault token.
        let anon = |op: Operation, path: &'static str, body: Option<Value>| v2(ctx, "", op, path, body);

        // ── OIDC ──
        assert_eq!(status(anon(Operation::Read, "idp/oidc/.well-known/openid-configuration", None).await), 404);
        assert_eq!(status(anon(Operation::Read, "idp/oidc/config", None).await), 401, "admin paths need a token");
        let cfg = json!({"enabled": true, "issuer": ISSUER});
        data(v2(ctx, &root, Operation::Write, "idp/oidc/config", Some(cfg)).await);
        let client = json!({"environment": "apps", "redirect_uris": [REDIRECT]});
        let created = data(v2(ctx, &root, Operation::Write, "idp/oidc/clients/app", Some(client)).await);
        let secret = created["client_secret"].as_str().unwrap().to_string();
        let read = data(v2(ctx, &root, Operation::Read, "idp/oidc/clients/app", None).await);
        assert!(read.get("client_secret").is_none() && !Value::Object(read).to_string().contains(&secret));

        let disco = data(anon(Operation::Read, "idp/oidc/.well-known/openid-configuration", None).await);
        assert_eq!(
            (disco["issuer"].as_str(), disco["jwks_uri"].as_str()),
            (Some(ISSUER), Some(&*format!("{ISSUER}/jwks")))
        );
        let jwks = Value::Object(data(anon(Operation::Read, "idp/oidc/jwks", None).await));
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);

        let authorize = json!({"client_id": "app", "redirect_uri": REDIRECT, "response_type": "code",
            "scope": "openid", "state": "s1", "nonce": "n1",
            "code_challenge": s256(VERIFIER), "code_challenge_method": "S256"});
        assert_eq!(
            status(v2(ctx, &root, Operation::Write, "idp/oidc/authorize", Some(authorize.clone())).await),
            403,
            "self-service: root has no entity"
        );
        let v1 = call(ctx, &token, Operation::Write, "idp/oidc/authorize", Some(authorize.clone()), 1, None);
        assert_eq!(status(v1.await), 400);
        let mut bad = authorize.clone();
        bad["redirect_uri"] = json!("https://evil.example.com/cb");
        assert_eq!(status(v2(ctx, &token, Operation::Write, "idp/oidc/authorize", Some(bad)).await), 400);
        let minted = data(v2(ctx, &token, Operation::Write, "idp/oidc/authorize", Some(authorize.clone())).await);
        let code = minted["code"].as_str().unwrap().to_string();
        assert!(minted["redirect_to"].as_str().unwrap().starts_with(&format!("{REDIRECT}?code=")));

        let redeem = |code: &str, secret: &str| {
            json!({"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                "client_id": "app", "client_secret": secret, "code_verifier": VERIFIER})
        };
        assert_eq!(status(anon(Operation::Write, "idp/oidc/token", Some(redeem(&code, "wrong"))).await), 401);
        let issued = data(anon(Operation::Write, "idp/oidc/token", Some(redeem(&code, &secret))).await);
        let id_token = issued["id_token"].as_str().unwrap().to_string();
        let (_, claims) = verify_rs256(&id_token, &jwks).unwrap();
        assert_eq!(
            (claims["sub"].as_str(), claims["preferred_username"].as_str()),
            (Some(alice.as_str()), Some("alice"))
        );
        assert_eq!((claims["uid"].as_u64(), claims["roles"].clone()), (Some(80_000), json!(["ops"])));
        assert_eq!(
            (claims["iss"].as_str(), claims["aud"].as_str(), claims["nonce"].as_str()),
            (Some(ISSUER), Some("app"), Some("n1"))
        );
        assert_eq!(status(anon(Operation::Write, "idp/oidc/token", Some(redeem(&code, &secret))).await), 400, "replay");

        // ── SAML ──
        let cfg = json!({"enabled": true, "entity_id": "https://vault.example.com/saml", "sso_url": "https://vault.example.com/ui/sso"});
        data(v2(ctx, &root, Operation::Write, "idp/saml/config", Some(cfg)).await);
        let sp = json!({"entity_id": SP, "acs_urls": [ACS], "environment": "apps"});
        data(v2(ctx, &root, Operation::Write, "idp/saml/sps/app", Some(sp)).await);
        let md = data(anon(Operation::Read, "idp/saml/metadata", None).await);
        assert!(md["metadata"].as_str().unwrap().contains("<md:IDPSSODescriptor"));
        let cert = md["certificate"].as_str().unwrap().to_string();
        let request = |id: &str| {
            let xml = format!(
                r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{}" AssertionConsumerServiceURL="{ACS}"><saml:Issuer>{SP}</saml:Issuer></samlp:AuthnRequest>"#,
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
            );
            json!({"saml_request": B64.encode(xml), "binding": "post", "relay_state": "rs"})
        };
        assert_eq!(
            status(v2(ctx, &root, Operation::Write, "idp/saml/sso", Some(request("_r0"))).await),
            403,
            "self-service: root has no entity"
        );
        let resp = data(v2(ctx, &token, Operation::Write, "idp/saml/sso", Some(request("_r1"))).await);
        assert_eq!((resp["acs_url"].as_str(), resp["relay_state"].as_str()), (Some(ACS), Some("rs")));
        let xml = B64.decode(resp["saml_response"].as_str().unwrap()).unwrap();
        let parsed = bv_auth_saml::response::parse_response(&xml).unwrap();
        let key = bv_auth_saml::verify::parse_rsa_public_key_from_pem(&cert).unwrap();
        bv_auth_saml::verify::verify_signed_assertion(&parsed, &key).unwrap();
        let assertion = parsed.assertion.as_ref().unwrap();
        assert_eq!(
            (assertion.name_id.as_str(), assertion.attributes["uid"].clone()),
            ("alice", vec!["80000".to_string()])
        );
        assert_eq!(parsed.in_response_to, "_r1");
        assert_eq!(
            status(v2(ctx, &token, Operation::Write, "idp/saml/sso", Some(request("_r1"))).await),
            400,
            "replayed AuthnRequest"
        );

        // A tenant cannot reach the unauthenticated endpoints either.
        test_write_api(ctx, &root, "sys/namespaces/tenant", true, json!({}).as_object().cloned()).await.unwrap();
        call(ctx, &root, Operation::Write, "sys/mounts/idp/", Some(json!({"type": "idp"})), 1, Some("tenant"))
            .await
            .unwrap();
        assert_eq!(status(v2(ctx, "", Operation::Read, "tenant/idp/oidc/jwks", None).await), 403);
        assert_eq!(status(call(ctx, "", Operation::Read, "idp/saml/metadata", None, 2, Some("tenant")).await), 403);

        // Disable: both providers refuse at once.
        let state = format!("idp/identities/{alice}/state");
        data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "disabled"}))).await);
        assert_eq!(status(v2(ctx, &token, Operation::Write, "idp/oidc/authorize", Some(authorize.clone())).await), 403);
        assert_eq!(status(v2(ctx, &token, Operation::Write, "idp/saml/sso", Some(request("_r2"))).await), 403);

        let providers: Vec<Value> =
            audit_events(&audit_log, "idp.issue").iter().map(|e| e["provider"].clone()).collect();
        assert_eq!(providers, [json!("oidc-authorize"), json!("oidc"), json!("saml")]);
        let denied: Vec<(Value, Value)> = audit_events(&audit_log, "idp.issue-denied")
            .iter()
            .map(|e| (e["provider"].clone(), e["reason"].clone()))
            .collect();
        assert_eq!(
            denied,
            [(json!("oidc-authorize"), json!("identity_disabled")), (json!("saml"), json!("identity_disabled"))]
        );
        assert_eq!(audit_events(&audit_log, "idp.oidc.token").len(), 1);
        assert_eq!(audit_events(&audit_log, "idp.saml.response").len(), 1);
        let refused: Vec<Value> =
            audit_events(&audit_log, "idp.oidc.refused").iter().map(|e| e["reason"].clone()).collect();
        assert!(refused.contains(&json!("redirect_uri_mismatch")) && refused.contains(&json!("invalid_client")));
        let log = std::fs::read_to_string(&audit_log).unwrap();
        for secret in [secret.as_str(), id_token.as_str(), code.as_str(), resp["saml_response"].as_str().unwrap()] {
            assert!(!log.contains(secret), "the audit log never holds a secret, code, token or assertion");
        }
        let _ = std::fs::remove_dir_all(audit_dir);
    }

    /// Phase 6 end to end: a client registered through v2, a bind passcode
    /// minted by a userpass login, a bind and searches over the vault's own
    /// (opted-in cleartext) listener, a refused write, then a disable.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn idp_ldap_directory_through_the_vault() {
        use std::time::Duration;

        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpStream,
        };

        use crate::modules::idp::provider::ldap_dir::{
            ber::pdu_len,
            filter::Filter,
            proto::{client, tag, Scope, WriteOp},
        };

        let (_bvault, core, root) = new_unseal_test_bastion_vault("idp_ldap").await;
        let ctx: &dyn VaultCtx = core.as_ref();
        test_mount_api(ctx, &root, "idp", "idp").await;
        let (audit_dir, audit_log) = enable_audit_file(ctx, "ldap").await;
        test_mount_auth_api_with(
            ctx,
            &root,
            "idp-ldap",
            r#"path "idp/ldap/passcode/*" { capabilities = ["create", "update"] }"#,
        )
        .await;
        let mut login = Request::new("auth/userpass/login/alice");
        login.operation = Operation::Write;
        login.body = json!({"password": "pw-123456"}).as_object().cloned();
        let auth = ctx.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap();
        let (token, alice) = (auth.client_token.clone(), auth.metadata["entity_id"].clone());
        let ident = data(
            v2(ctx, &root, Operation::Write, &format!("idp/identities/{alice}"), Some(json!({"login": "alice"}))).await,
        );
        let uid = ident["uid"].as_u64().unwrap();
        let env = json!({"namespace": "", "roles": {"ops": ["ops-policy"]}});
        data(v2(ctx, &root, Operation::Write, "idp/environments/hosts", Some(env)).await);
        let grant = json!({"roles": ["ops"]});
        data(v2(ctx, &root, Operation::Write, &format!("idp/entitlements/{alice}/hosts"), Some(grant)).await);

        // Off by default: no passcode, nothing listening.
        let passcode = || v2(ctx, &token, Operation::Write, "idp/ldap/passcode/hosts", Some(json!({})));
        assert_eq!(status(passcode().await), 400);
        let cfg = data(v2(ctx, &root, Operation::Read, "idp/ldap/config", None).await);
        assert_eq!(cfg["enabled"].as_bool(), Some(false));
        assert_eq!(cfg["listening"]["ldap"], Value::Null);

        let host = json!({"transport": "plain", "environment": "hosts", "address": "127.0.0.1"});
        let c = data(v2(ctx, &root, Operation::Write, "idp/ldap/clients/host1", Some(host)).await);
        assert_eq!((c["transport"].as_str(), c["environment"].as_str()), (Some("plain"), Some("hosts")));
        let fixed = json!({"environment": "other"});
        assert_eq!(status(v2(ctx, &root, Operation::Write, "idp/ldap/clients/host1", Some(fixed)).await), 400);

        // Cleartext must be asked for explicitly; then the listener comes up.
        let half = json!({"enabled": true, "ldap_listen": "127.0.0.1:0"});
        assert_eq!(status(v2(ctx, &root, Operation::Write, "idp/ldap/config", Some(half)).await), 400);
        let on =
            json!({"enabled": true, "ldap_listen": "127.0.0.1:0", "plaintext_enabled": true, "base_dn": "dc=corp"});
        let written = v2(ctx, &root, Operation::Write, "idp/ldap/config", Some(on)).await.unwrap().unwrap();
        assert!(written.warnings.iter().any(|w| w.contains("cleartext")));
        let mut listening = None;
        for _ in 0..250 {
            let cfg = data(v2(ctx, &root, Operation::Read, "idp/ldap/config", None).await);
            if let Some(addr) = cfg["listening"]["ldap"].as_str() {
                listening = Some(addr.parse::<std::net::SocketAddr>().unwrap());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let server = listening.expect("the LDAP listener never came up");

        // v2 only; self-service only (the root token has no entity).
        assert_eq!(status(call(ctx, &token, Operation::Write, "idp/ldap/passcode/hosts", None, 1, None).await), 400);
        assert_eq!(status(v2(ctx, &root, Operation::Write, "idp/ldap/passcode/hosts", Some(json!({}))).await), 403);
        let minted = data(passcode().await);
        let (code_a, bind_dn) = (minted["passcode"].as_str().unwrap().to_string(), minted["bind_dn"].as_str().unwrap());
        assert_eq!(bind_dn, "uid=alice,ou=people,dc=corp");
        let code_b = data(passcode().await)["passcode"].as_str().unwrap().to_string();

        let mut tcp = TcpStream::connect(server).await.unwrap();
        async fn exchange(tcp: &mut TcpStream, pdu: Vec<u8>) -> Vec<client::Reply> {
            tcp.write_all(&pdu).await.unwrap();
            let mut replies = Vec::new();
            loop {
                let mut head = Vec::new();
                let total = loop {
                    if let Some(n) = pdu_len(&head).unwrap() {
                        break n;
                    }
                    let mut b = [0u8; 1];
                    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut b)).await.unwrap().unwrap();
                    head.push(b[0]);
                };
                let mut body = vec![0u8; total];
                body[..head.len()].copy_from_slice(&head);
                tcp.read_exact(&mut body[head.len()..]).await.unwrap();
                let reply = client::read_reply(&body).unwrap();
                let done = reply.tag != tag::SEARCH_RESULT_ENTRY;
                replies.push(reply);
                if done {
                    return replies;
                }
            }
        }
        let search = |f: Filter| client::search(2, "dc=corp", Scope::Sub, 0, &f, &["uid", "uidNumber"]);
        let found = exchange(&mut tcp, search(Filter::eq("uid", "alice"))).await;
        assert_eq!((found.len(), found[0].dn.as_str()), (2, bind_dn));
        assert_eq!(found[0].values("uidNumber"), [uid.to_string()]);
        assert_eq!(exchange(&mut tcp, client::bind_simple(3, bind_dn, &code_a)).await[0].code, Some(0));
        assert_eq!(exchange(&mut tcp, client::bind_simple(4, bind_dn, &code_a)).await[0].code, Some(49), "single use");
        assert_eq!(exchange(&mut tcp, client::bind_simple(5, bind_dn, "")).await[0].code, Some(53), "unauthenticated");
        assert_eq!(exchange(&mut tcp, client::write(6, WriteOp::Add, bind_dn)).await[0].code, Some(53), "read-only");

        // Disabled after the passcode was minted: refused at once, and gone
        // from the directory.
        let state = format!("idp/identities/{alice}/state");
        data(v2(ctx, &root, Operation::Write, &state, Some(json!({"state": "disabled"}))).await);
        assert_eq!(exchange(&mut tcp, client::bind_simple(7, bind_dn, &code_b)).await[0].code, Some(49));
        assert_eq!(exchange(&mut tcp, search(Filter::eq("uid", "alice"))).await.len(), 1, "only the done");

        // The gate's events and the directory's, with no passcode in them.
        let issued: Vec<Value> = audit_events(&audit_log, "idp.issue").iter().map(|e| e["provider"].clone()).collect();
        assert_eq!(issued, [json!("ldap-passcode"), json!("ldap-passcode"), json!("ldap")]);
        let denied = audit_events(&audit_log, "idp.issue-denied");
        let reasons: Vec<(Value, Value)> =
            denied.iter().map(|e| (e["provider"].clone(), e["reason"].clone())).collect();
        assert_eq!(reasons, [(json!("ldap"), json!("identity_disabled"))]);
        let binds: Vec<(Value, Value)> = audit_events(&audit_log, "idp.ldap.bind")
            .iter()
            .map(|e| (e["decision"].clone(), e["reason"].clone()))
            .collect();
        assert_eq!(
            binds,
            [
                (json!("success"), Value::Null),
                (json!("refused"), json!("bad_passcode")),
                (json!("refused"), json!("unauthenticated_bind")),
                (json!("refused"), json!("issue_denied")),
            ]
        );
        let searches = audit_events(&audit_log, "idp.ldap.search");
        let entries: Vec<Value> = searches.iter().map(|e| e["entries"].clone()).collect();
        assert_eq!(entries, [json!(1), json!(0)]);
        assert_eq!(searches[0]["client"].as_str(), Some("host1"));
        let refused = audit_events(&audit_log, "idp.ldap.refused");
        assert_eq!(refused[0]["reason"].as_str(), Some("write_refused"));
        let log = std::fs::read_to_string(&audit_log).unwrap();
        for secret in [code_a.as_str(), code_b.as_str()] {
            assert!(!log.contains(secret), "the audit log never holds a passcode");
        }
        data(v2(ctx, &root, Operation::Write, "idp/ldap/config", Some(json!({"enabled": false}))).await);
        let _ = std::fs::remove_dir_all(audit_dir);
    }

    /// userpass with alice, whose policy allows one path only.
    async fn test_mount_auth_api_with(ctx: &dyn VaultCtx, root: &str, name: &str, policy: &str) {
        crate::test_utils::test_mount_auth_api(ctx, root, "userpass", "userpass").await;
        let body = json!({"policy": policy}).as_object().cloned();
        test_write_api(ctx, root, &format!("sys/policy/{name}"), true, body).await.unwrap();
        let user = json!({"password": "pw-123456", "policies": name});
        test_write_api(ctx, root, "auth/userpass/users/alice", true, user.as_object().cloned()).await.unwrap();
    }

    /// userpass with alice, whose policy allows the passcode path only.
    async fn test_mount_auth_api_for_radius(ctx: &dyn VaultCtx, root: &str) {
        crate::test_utils::test_mount_auth_api(ctx, root, "userpass", "userpass").await;
        let policy = r#"path "idp/radius/passcode/*" { capabilities = ["create", "update"] }"#;
        let body = json!({"policy": policy}).as_object().cloned();
        test_write_api(ctx, root, "sys/policy/idp-radius", true, body).await.unwrap();
        let user = json!({"password": "pw-123456", "policies": "idp-radius"});
        test_write_api(ctx, root, "auth/userpass/users/alice", true, user.as_object().cloned()).await.unwrap();
    }
}
