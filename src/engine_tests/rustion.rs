//! Tests for the Rustion engine, which lives in `crates/bv-engine-rustion`.
//!
//! Lifted out of the engine because they stand up a whole vault through
//! `crate::test_utils`; the engine's pure unit tests stayed with it.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

mod connect_only_tests {
    use crate::logical::Backend;
    use crate::test_utils::TestHttpServer;

    /// Regression guard for the brokered ssh-cert drop: the server-side
    /// mint in `handle_session_open_v2` inserts `credential_cert` (the
    /// signed OpenSSH cert) and `credential_serial` into the request
    /// data, but `Request::get_data` only returns keys that are
    /// **declared fields** on the matched route — an undeclared key
    /// reads back empty. If these aren't declared on the session/open
    /// routes, `pick("credential_cert")` returns "", the envelope ships
    /// `kind=ssh-cert` with no `extra["cert"]`, and Rustion silently
    /// falls back to plain publickey ("no certificate in envelope").
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_session_open_routes_declare_credential_cert_field() {
        let server = TestHttpServer::new("test_session_open_cert_field", true).await;
        let mut backend =
            crate::modules::rustion::RustionBackend::new(server.core.clone(), Default::default()).new_backend();
        backend.init().expect("backend init compiles route regexes");
        for pat in ["session/open", "v2/session/open"] {
            let (path, _) = backend.match_path(pat).unwrap_or_else(|| panic!("route `{pat}` should match"));
            for field in ["credential_cert", "credential_serial"] {
                assert!(
                    path.get_field(field).is_some(),
                    "route `{pat}` must declare `{field}` as a field, \
                     or get_data/pick cannot read the server-side-minted value \
                     back into the BVRG envelope"
                );
            }
        }
    }

    /// End-to-end authorization proof for connect-only access through
    /// `rustion/v2/session/open`:
    ///   - a connect-only caller (capability `connect`, not `read`) is denied
    ///     a direct read of the resource secret, but its v2 session-open
    ///     passes the connect gate and reaches dispatch (no bastion enrolled
    ///     → 502/503, NOT a 403 permission-denied at the gate). This proves
    ///     the credential was resolved server-side without the caller's read.
    ///   - a caller with neither `read` nor `connect` on the resource is
    ///     denied at the gate (403) before any resolution.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_connect_only_session_open_v2_gate_and_resolution() {
        let mut server = TestHttpServer::new("test_connect_only_session_open_v2", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        // Stored credential for the resource (server-side resolvable).
        server
            .write(
                "resources/secrets/db/ssh",
                serde_json::json!({ "password": "hunter2", "username": "deploy" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();

        // connect-only: may open a session, may NOT read the secret.
        // read-connect: may do both. no-connect: may call the endpoint but
        // not connect to this resource. All three may hit the rustion mount.
        let policies = [
            (
                "connect-only",
                "path \"resources/secrets/db/*\" { capabilities = [\"connect\"] }\n\
                 path \"rustion/*\" { capabilities = [\"create\", \"update\", \"read\"] }",
            ),
            ("no-connect", "path \"rustion/*\" { capabilities = [\"create\", \"update\", \"read\"] }"),
        ];
        for (name, body) in policies {
            server
                .write(
                    &format!("sys/policies/acl/{name}"),
                    serde_json::json!({ "policy": body }).as_object().cloned(),
                    Some(&root),
                )
                .unwrap();
        }

        server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), Some(&root))
            .unwrap();
        for (user, policy) in [("conn", "connect-only"), ("noconn", "no-connect")] {
            server
                .write(
                    &format!("auth/pass/users/{user}"),
                    serde_json::json!({
                        "password": "hunter22XX!",
                        "token_policies": policy,
                        "ttl": 0,
                    })
                    .as_object()
                    .cloned(),
                    Some(&root),
                )
                .unwrap();
        }

        let login = |user: &str| -> String {
            server
                .write(
                    &format!("auth/pass/login/{user}"),
                    serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                    None,
                )
                .unwrap()
                .1
                .get("auth")
                .and_then(|a| a.get("client_token"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        };

        let open_v2 = |token: &str| -> u16 {
            server
                .write(
                    "rustion/v2/session/open",
                    serde_json::json!({
                        "resource_name": "db",
                        "credential_source": { "kind": "secret", "secret_id": "ssh" },
                        "target_host": "10.0.0.5",
                        "target_port": 22,
                        "target_protocol": "ssh"
                    })
                    .as_object()
                    .cloned(),
                    Some(token),
                )
                .unwrap()
                .0
        };

        let conn = login("conn");
        let noconn = login("noconn");

        // Connect-only caller cannot read the stored credential directly.
        let (read_status, _) = server.request("GET", "resources/secrets/db/ssh", None, Some(&conn), None).unwrap();
        assert_eq!(read_status, 403, "connect-only must be denied a direct secret read");

        // ...but its v2 session-open passes the connect gate and resolves the
        // credential server-side, failing only at dispatch (no bastion).
        let conn_open = open_v2(&conn);
        assert_ne!(conn_open, 403, "connect-only must pass the connect gate, got 403");
        assert_ne!(conn_open, 401, "connect-only is authenticated, got 401");
        assert!(
            conn_open == 502 || conn_open == 503,
            "connect-only should reach dispatch and fail on no-bastion (502/503), got {conn_open}"
        );

        // No-connect caller is denied at the gate before any resolution.
        let noconn_open = open_v2(&noconn);
        assert_eq!(noconn_open, 403, "no-connect must be denied at the connect gate");
    }

    /// v1 `session/open` had **no** per-resource gate: it authorized only the
    /// endpoint path, then brokered a session to a caller-named `target_host`
    /// with caller-supplied credential material. That is why it could not be
    /// granted to a tenant — and therefore why brokered RDP and the
    /// client-resolved SSH kinds (LDAP / PKI / FIDO2) failed closed inside a
    /// namespace under `rustion-required`. Now:
    ///   - bound to a resource the caller may connect to → passes, reaching
    ///     dispatch (502/503, no bastion enrolled);
    ///   - bound to a resource the caller cannot reach → 403 at the gate;
    ///   - unbound (no `resource_id`, so no object to authorize against) →
    ///     403 without `sudo`, allowed for root.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_session_open_v1_is_per_resource_gated() {
        let mut server = TestHttpServer::new("test_session_open_v1_gate", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        server
            .write(
                "resources/resources/db",
                serde_json::json!({ "type": "server", "hostname": "db.example" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();

        for (name, body) in [
            (
                "v1-connect",
                "path \"resources/secrets/db/*\" { capabilities = [\"connect\"] }\n\
                 path \"rustion/*\" { capabilities = [\"create\", \"update\", \"read\"] }",
            ),
            ("v1-noconnect", "path \"rustion/*\" { capabilities = [\"create\", \"update\", \"read\"] }"),
        ] {
            server
                .write(
                    &format!("sys/policies/acl/{name}"),
                    serde_json::json!({ "policy": body }).as_object().cloned(),
                    Some(&root),
                )
                .unwrap();
        }

        server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), Some(&root))
            .unwrap();
        for (user, policy) in [("v1conn", "v1-connect"), ("v1noconn", "v1-noconnect")] {
            server
                .write(
                    &format!("auth/pass/users/{user}"),
                    serde_json::json!({ "password": "hunter22XX!", "token_policies": policy, "ttl": 0 })
                        .as_object()
                        .cloned(),
                    Some(&root),
                )
                .unwrap();
        }
        let login = |user: &str| -> String {
            server
                .write(
                    &format!("auth/pass/login/{user}"),
                    serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                    None,
                )
                .unwrap()
                .1
                .get("auth")
                .and_then(|a| a.get("client_token"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        };

        // `bound = false` omits `resource_id` — the raw, fleet-level shape.
        let open_v1 = |token: &str, bound: bool| -> u16 {
            let mut body = serde_json::json!({
                "target_host": "10.0.0.5",
                "target_port": 22,
                "target_protocol": "ssh",
                "credential_kind": "ssh-password",
                "credential_username": "deploy",
                "credential_material": "aHVudGVyMg=="
            });
            if bound {
                body.as_object_mut().unwrap().insert("resource_id".into(), serde_json::json!("db"));
            }
            server.write("rustion/session/open", body.as_object().cloned(), Some(token)).unwrap().0
        };

        let conn = login("v1conn");
        let noconn = login("v1noconn");

        let bound_conn = open_v1(&conn, true);
        assert_ne!(bound_conn, 403, "a connect grant on the resource must pass the v1 gate");
        assert!(
            bound_conn == 502 || bound_conn == 503,
            "should reach dispatch and fail on no-bastion (502/503), got {bound_conn}"
        );

        assert_eq!(
            open_v1(&noconn, true),
            403,
            "endpoint access alone must not open a session to a resource the caller can't reach"
        );

        // The raw shape names an arbitrary host and carries its own
        // credential, so there is nothing to authorize per-object: `sudo`.
        assert_eq!(open_v1(&conn, false), 403, "unbound open must require sudo, not a per-resource connect grant");
        assert_eq!(open_v1(&noconn, false), 403, "unbound open must require sudo");
        let bound_root = open_v1(&root, false);
        assert_ne!(bound_root, 403, "root holds sudo and keeps the raw open (the e2e harness uses it)");
    }

    /// The connect gate must recognise **share-derived** access, not only an
    /// explicit ungated grant — and it must require the share to say
    /// `connect`.
    ///
    /// `explain_capability` probes with an identity-less dry-run so that
    /// scope-gated rules contribute nothing — correct for "does an explicit
    /// grant exist?", and the reason a `scopes = ["shared"]` baseline rule
    /// can't be mistaken for a blanket one. But it was the *only* check, so
    /// every caller whose access comes from a share was refused at the gate:
    /// on a `rustion-required` resource they could not connect at all, and on
    /// any other they were pushed onto the direct dial. The gate now consults
    /// `PolicyStore::may_connect_target`, which re-runs the real evaluator
    /// with the owner / share / asset-group qualifiers hydrated.
    ///
    /// That probe asks for `connect`, not `read`. A share conveying only
    /// `read` used to imply a session, which collapsed "may see this
    /// credential" and "may open sessions as it" into one grant and made a
    /// connect-only share impossible to express. Both halves are asserted
    /// below, because the interesting property is the *gap* between them: the
    /// same read-only share that opens the resource record and its secret
    /// still cannot open a session.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_session_open_gate_requires_an_explicit_connect_share() {
        let mut server = TestHttpServer::new("test_session_open_share_gate", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        server
            .write(
                "resources/resources/db",
                serde_json::json!({ "type": "server", "hostname": "db.example" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        server
            .write(
                "resources/secrets/db/ssh",
                serde_json::json!({ "password": "hunter2", "username": "deploy" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();

        // Mirrors the share-scoped rules the `default` / `namespace-shared`
        // baselines carry: no ungated grant on the resource anywhere.
        let sharee_policy = r#"
path "resources/*" {
    capabilities = ["read", "list"]
    scopes       = ["shared"]
}
path "rustion/*" {
    capabilities = ["create", "update", "read"]
}
"#;
        let (policy_status, _) = server
            .write(
                "sys/policies/acl/sharee",
                serde_json::json!({ "policy": sharee_policy }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!(policy_status < 300, "fixture: sharee policy must save, got {policy_status}");
        server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), Some(&root))
            .unwrap();
        server
            .write(
                "auth/pass/users/sharee",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "sharee", "ttl": 0 })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        let token = server
            .write(
                "auth/pass/login/sharee",
                serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
            )
            .unwrap()
            .1
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let open = |token: &str| -> u16 {
            server
                .write(
                    "rustion/v2/session/open",
                    serde_json::json!({
                        "resource_name": "db",
                        "credential_source": { "kind": "secret", "secret_id": "ssh" },
                        "target_host": "10.0.0.5",
                        "target_port": 22,
                        "target_protocol": "ssh"
                    })
                    .as_object()
                    .cloned(),
                    Some(token),
                )
                .unwrap()
                .0
        };

        // No share yet: the share-scoped rule grants nothing, so the gate
        // refuses. This is also the proof that the fallback probe is
        // share-aware rather than simply permissive.
        assert_eq!(open(&token), 403, "a share-scoped rule with no share must not pass the gate");

        let entity_id = server
            .request("GET", "identity/entity/self", None, Some(&token), None)
            .unwrap()
            .1
            .get("data")
            .and_then(|d| d.get("entity_id"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let target_b64 = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            URL_SAFE_NO_PAD.encode("db")
        };
        server
            .write(
                &format!("identity/sharing/by-target/resource/{target_b64}/{entity_id}"),
                serde_json::json!({ "target_kind": "resource", "target_path": "db", "capabilities": "read" })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();

        // Sanity: the share really does convey access through the normal
        // request pipeline. If this ever fails the fixture is wrong, not the
        // gate.
        let record = server.request("GET", "resources/resources/db", None, Some(&token), None).unwrap().0;
        assert_eq!(record, 200, "fixture: the share must let the grantee read the resource record");
        let secret = server.request("GET", "resources/secrets/db/ssh", None, Some(&token), None).unwrap().0;
        assert_eq!(secret, 200, "fixture: the share covers the resource's secret path too");

        // …and yet it conveys no session. `read` is not `connect`: the grantor
        // shared visibility, not the right to open sessions as the credential.
        assert_eq!(
            open(&token),
            403,
            "a share granting only `read` must NOT pass the connect gate"
        );

        // Re-grant with `connect` and the same principal, same policy, same
        // resource now reaches dispatch.
        server
            .write(
                &format!("identity/sharing/by-target/resource/{target_b64}/{entity_id}"),
                serde_json::json!({
                    "target_kind": "resource",
                    "target_path": "db",
                    "capabilities": "read,connect"
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap();

        let after = open(&token);
        assert_ne!(after, 403, "a share granting `connect` must pass the gate, got 403");
        assert!(
            after == 502 || after == 503,
            "the share-grantee should reach dispatch and fail on no-bastion (502/503), got {after}"
        );
    }

    /// The connect-only shape the explicit `connect` share exists to make
    /// possible: a grantee who may open a session but may **not** read the
    /// credential behind it.
    ///
    /// This is the pairing the GUI hint in the resource grant modal describes,
    /// and it only works because `connect` is granted on its own — with the
    /// old read-implies-connect rule there was no way to express it.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_connect_only_share_grants_no_credential_read() {
        let mut server = TestHttpServer::new("test_connect_only_share", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        server
            .write(
                "resources/resources/db",
                serde_json::json!({ "type": "server", "hostname": "db.example" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        server
            .write(
                "resources/secrets/db/ssh",
                serde_json::json!({ "password": "hunter2", "username": "deploy" }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();

        let sharee_policy = r#"
path "resources/*" {
    capabilities = ["read", "list", "connect"]
    scopes       = ["shared"]
}
path "rustion/*" {
    capabilities = ["create", "update", "read"]
}
"#;
        let (policy_status, _) = server
            .write(
                "sys/policies/acl/connector",
                serde_json::json!({ "policy": sharee_policy }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert_eq!(policy_status, 204);

        server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), Some(&root))
            .unwrap();
        server
            .write(
                "auth/pass/users/connector",
                serde_json::json!({ "password": "hunter22XX!", "token_policies": "connector", "ttl": 0 })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        let token = server
            .write(
                "auth/pass/login/connector",
                serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
            )
            .unwrap()
            .1
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let entity_id = server
            .request("GET", "identity/entity/self", None, Some(&token), None)
            .unwrap()
            .1
            .get("data")
            .and_then(|d| d.get("entity_id"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let target_b64 = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            URL_SAFE_NO_PAD.encode("db")
        };

        // `connect` alone — deliberately no `read`.
        server
            .write(
                &format!("identity/sharing/by-target/resource/{target_b64}/{entity_id}"),
                serde_json::json!({
                    "target_kind": "resource",
                    "target_path": "db",
                    "capabilities": "connect"
                })
                .as_object()
                .cloned(),
                Some(&root),
            )
            .unwrap();

        // The credential stays out of reach: the scope gate maps a Read op to
        // the share's `read`, which this share does not carry.
        let secret = server.request("GET", "resources/secrets/db/ssh", None, Some(&token), None).unwrap().0;
        assert_eq!(secret, 403, "a connect-only share must not expose the credential");

        // The session still opens (reaching dispatch, which has no bastion).
        let opened = server
            .write(
                "rustion/v2/session/open",
                serde_json::json!({
                    "resource_name": "db",
                    "credential_source": { "kind": "secret", "secret_id": "ssh" },
                    "target_host": "10.0.0.5",
                    "target_port": 22,
                    "target_protocol": "ssh"
                })
                .as_object()
                .cloned(),
                Some(&token),
            )
            .unwrap()
            .0;
        assert_ne!(opened, 403, "a connect-only share must pass the connect gate");
        assert!(
            opened == 502 || opened == 503,
            "expected to reach dispatch and fail on no-bastion (502/503), got {opened}"
        );
    }

    /// The read-only resolvers (`policy/effective`, `dispatcher/preview`) take
    /// a caller-supplied `resource_id`. Every authenticated principal can call
    /// them — the connect path needs the transport verdict, and denying it made
    /// `rustion-required` invisible *and* unenforced — but ungated that let any
    /// baseline holder enumerate the transport tier and fronting bastions of
    /// every resource in the deployment.
    ///
    /// The gate is deliberately broader than the connect gate: it probes the
    /// inventory *record* (so an `ssh-engine` profile, which needs no grant on
    /// the secret path, still resolves) and it is share/owner-aware (so the
    /// share-grantees who most need the verdict aren't the ones refused).
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_resolvers_are_gated_per_resource() {
        let mut server = TestHttpServer::new("test_policy_resolver_gate", true).await;
        let root = server.root_token.clone();
        server.token = root.clone();

        for name in ["shown", "hidden"] {
            server
                .write(
                    &format!("resources/resources/{name}"),
                    serde_json::json!({ "type": "server", "hostname": format!("{name}.example") })
                        .as_object()
                        .cloned(),
                    Some(&root),
                )
                .unwrap();
        }

        // `viewer` reaches resources only through shares (the baseline shape).
        // `connector` has no grant on the record at all — only `connect` on one
        // resource's secret path, the connect-only shape.
        for (name, body) in [
            (
                "viewer",
                "\npath \"resources/*\" {\n    capabilities = [\"read\", \"list\"]\n    scopes       = [\"shared\"]\n}\n\
                 path \"rustion/*\" {\n    capabilities = [\"create\", \"update\", \"read\"]\n}\n",
            ),
            (
                "connector",
                "\npath \"resources/secrets/shown/*\" {\n    capabilities = [\"connect\"]\n}\n\
                 path \"rustion/*\" {\n    capabilities = [\"create\", \"update\", \"read\"]\n}\n",
            ),
        ] {
            let (st, _) = server
                .write(
                    &format!("sys/policies/acl/{name}"),
                    serde_json::json!({ "policy": body }).as_object().cloned(),
                    Some(&root),
                )
                .unwrap();
            assert!(st < 300, "fixture: policy `{name}` must save, got {st}");
        }

        server
            .write("sys/auth/pass", serde_json::json!({ "type": "userpass" }).as_object().cloned(), Some(&root))
            .unwrap();
        for user in ["viewer", "connector"] {
            server
                .write(
                    &format!("auth/pass/users/{user}"),
                    serde_json::json!({ "password": "hunter22XX!", "token_policies": user, "ttl": 0 })
                        .as_object()
                        .cloned(),
                    Some(&root),
                )
                .unwrap();
        }
        let login = |user: &str| -> String {
            server
                .write(
                    &format!("auth/pass/login/{user}"),
                    serde_json::json!({ "password": "hunter22XX!" }).as_object().cloned(),
                    None,
                )
                .unwrap()
                .1
                .get("auth")
                .and_then(|a| a.get("client_token"))
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        };
        let viewer = login("viewer");
        let connector = login("connector");

        // `resource_id: None` asks for the tier-only chain.
        let resolve = |route: &str, token: &str, resource_id: Option<&str>| -> u16 {
            let mut body = serde_json::json!({ "resource_type": "server" });
            if let Some(rid) = resource_id {
                body.as_object_mut().unwrap().insert("resource_id".into(), serde_json::json!(rid));
            }
            server.write(route, body.as_object().cloned(), Some(token)).unwrap().0
        };

        for route in ["rustion/policy/effective", "rustion/dispatcher/preview"] {
            // Root sees everything.
            assert!(resolve(route, &root, Some("hidden")) < 300, "root must resolve any resource");

            // A resource the viewer cannot see is refused...
            assert_eq!(
                resolve(route, &viewer, Some("hidden")),
                403,
                "{route} must not resolve a resource the caller cannot see"
            );
            // ...while the tier-only shape stays open: no object to authorize,
            // and it is the same admin-authored chain the caller's own sessions
            // already obey.
            assert!(
                resolve(route, &viewer, None) < 300,
                "{route} tier-only resolution must stay ungated"
            );

            // The connect-only caller holds nothing on the record, only
            // `connect` on the secret path — the second gate arm.
            assert!(
                resolve(route, &connector, Some("shown")) < 300,
                "{route} must resolve for a connect-only grant on the secret path"
            );
            assert_eq!(
                resolve(route, &connector, Some("hidden")),
                403,
                "{route} must still refuse a resource the connect-only caller has no grant on"
            );
        }

        // Sharing `shown` with the viewer opens the resolver for it, and only
        // for it — proof the gate reads the share rather than waving everyone
        // through once any share exists.
        let entity_id = server
            .request("GET", "identity/entity/self", None, Some(&viewer), None)
            .unwrap()
            .1
            .get("data")
            .and_then(|d| d.get("entity_id"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let target_b64 = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            URL_SAFE_NO_PAD.encode("shown")
        };
        server
            .write(
                &format!("identity/sharing/by-target/resource/{target_b64}/{entity_id}"),
                serde_json::json!({ "target_kind": "resource", "target_path": "shown", "capabilities": "read" })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();

        for route in ["rustion/policy/effective", "rustion/dispatcher/preview"] {
            assert!(
                resolve(route, &viewer, Some("shown")) < 300,
                "{route} must resolve a resource shared with the caller"
            );
            assert_eq!(
                resolve(route, &viewer, Some("hidden")),
                403,
                "{route} must still refuse the unshared resource"
            );
        }
    }
}
mod recordings_namespace_scope_tests {
    use crate::kernel_api::VaultCtx;
    use std::collections::HashMap;

    use serde_json::json;

    use crate::modules::rustion::recordings::RecordingEntry;
    use crate::modules::rustion::RustionModule;
    use crate::logical::{Operation, Request};
    use crate::test_utils::new_unseal_test_bastion_vault;

    fn rec(id: &str, host: &str) -> RecordingEntry {
        let now = chrono::Utc::now();
        RecordingEntry {
            recording_id: id.to_string(),
            session_id: format!("sess_{id}"),
            authority: "test".into(),
            format: "asciicast".into(),
            sha256: String::new(),
            size_bytes: 0,
            started_at: now,
            finished_at: now,
            target_host: host.to_string(),
            target_user: "deploy".into(),
            correlation_id: String::new(),
            bastion_id: "rt_test".into(),
            received_at: now,
            delivery_mode: "webhook".into(),
        }
    }

    fn ids_of(resp: &Option<crate::logical::Response>) -> Vec<String> {
        resp.as_ref()
            .and_then(|r| r.data.as_ref())
            .and_then(|d| d.get("recordings"))
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }

    /// The `rustion/recordings` list is deployment-global at root but, in a
    /// non-root namespace, is scoped to recordings whose `target_host` matches a
    /// resource (hostname or IP) that namespace owns. A recording matching no
    /// namespace resource stays visible only at root. This also guards the
    /// routing fix: `rustion/*` is header-scoped, so a namespaced request reaches
    /// the handler instead of 404-ing with "Router mount not found".
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_recordings_list_scoped_to_namespace_resources() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_recordings_ns_scope").await;

        let call = |op: Operation,
                    path: &str,
                    ns: &str,
                    body: Option<serde_json::Map<String, serde_json::Value>>| {
            let core = core.clone();
            let token = root.clone();
            let path = path.to_string();
            let ns = ns.to_string();
            async move {
                let mut req = Request::new(&path);
                req.operation = op;
                req.client_token = token;
                req.body = body;
                let mut h = HashMap::new();
                if !ns.is_empty() {
                    h.insert("x-bastionvault-namespace".to_string(), ns);
                }
                req.headers = Some(h);
                core.handle_request(&mut req).await
            }
        };

        // Create a child namespace — this seeds a `resources/` mount.
        call(Operation::Write, "sys/namespaces/team-alpha", "", json!({}).as_object().cloned())
            .await
            .expect("create namespace");

        // Register a resource in team-alpha (hostname `web01.corp`, IP `10.1.2.3`).
        call(
            Operation::Write,
            "resources/resources/web01",
            "team-alpha",
            json!({ "type": "server", "hostname": "web01.corp", "ip_address": "10.1.2.3" })
                .as_object()
                .cloned(),
        )
        .await
        .expect("create resource in namespace");

        // Seed the global recordings index: two hosts belong to team-alpha's
        // resource (by hostname and by IP), one belongs to no namespace resource.
        let module = core.module_manager().get_module::<RustionModule>("rustion").unwrap();
        let store = module.recordings_store().expect("recordings store initialized");
        store.put(&rec("rec_host", "web01.corp")).await.unwrap();
        store.put(&rec("rec_ip", "10.1.2.3")).await.unwrap();
        store.put(&rec("rec_other", "db99.other")).await.unwrap();

        // Root (no namespace header) sees every recording.
        let root_ids = ids_of(&call(Operation::Read, "rustion/recordings", "", None).await.unwrap());
        assert!(root_ids.contains(&"rec_host".to_string()), "root sees host match");
        assert!(root_ids.contains(&"rec_ip".to_string()), "root sees ip match");
        assert!(
            root_ids.contains(&"rec_other".to_string()),
            "root must still see the recording matching no namespace resource"
        );

        // team-alpha sees only recordings matching its resources.
        let ns_ids =
            ids_of(&call(Operation::Read, "rustion/recordings", "team-alpha", None).await.unwrap());
        assert!(ns_ids.contains(&"rec_host".to_string()), "namespace sees hostname match");
        assert!(ns_ids.contains(&"rec_ip".to_string()), "namespace sees ip match");
        assert!(
            !ns_ids.contains(&"rec_other".to_string()),
            "namespace must not see a recording matching none of its resources"
        );
    }
}
mod namespace_credential_scope_tests {
    use std::collections::HashMap;

    use serde_json::json;

    use crate::modules::rustion::RustionBackendInner;
    use crate::logical::{Operation, Request};
    use crate::test_utils::new_unseal_test_bastion_vault;

    /// The namespace split for a Rustion session: **bastion authentication is
    /// root's, the endpoint credential is the namespace's.**
    ///
    /// `rustion/` is a deployment-global mount (header-scoped in the namespace
    /// router), so a namespaced `v2/session/open` keeps using the root-enrolled
    /// fleet and the root-issued master signing cert — a child namespace never
    /// enrols its own Rustion. But the credential sealed *inside* the envelope
    /// belongs to the resource, which lives in the caller's namespace. This
    /// asserts both halves of that:
    ///
    ///   - a namespaced open resolves the namespace's own resource secret and
    ///     gets all the way to dispatch (failing only on `bastion_unavailable`,
    ///     since no bastion is enrolled in the test);
    ///   - a namespace that owns no such resource does **not** fall through to
    ///     a same-named ROOT secret — it fails closed with `not found`. Before
    ///     the prefix fix, every namespaced open read the root namespace's
    ///     `resources/secrets/<name>/<id>`, which is a cross-tenant read.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_v2_session_open_resolves_credential_in_caller_namespace() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_rustion_ns_cred_scope").await;

        let call = |op: Operation, path: &str, ns: &str, body: Option<serde_json::Map<String, serde_json::Value>>| {
            let core = core.clone();
            let token = root.clone();
            let path = path.to_string();
            let ns = ns.to_string();
            async move {
                let mut req = Request::new(&path);
                req.operation = op;
                req.client_token = token;
                req.body = body;
                let mut h = HashMap::new();
                if !ns.is_empty() {
                    h.insert("x-bastionvault-namespace".to_string(), ns);
                }
                req.headers = Some(h);
                core.handle_request(&mut req).await
            }
        };

        // Decoy at ROOT: same resource name, same secret id. A namespaced open
        // must never reach this.
        call(
            Operation::Write,
            "resources/secrets/db/ssh",
            "",
            json!({ "password": "root-decoy", "username": "root-user" }).as_object().cloned(),
        )
        .await
        .expect("write root decoy secret");

        // Two child namespaces; only `team-alpha` owns the credential.
        for ns in ["team-alpha", "team-beta"] {
            call(Operation::Write, &format!("sys/namespaces/{ns}"), "", json!({}).as_object().cloned())
                .await
                .unwrap_or_else(|e| panic!("create namespace {ns}: {e:?}"));
        }
        call(
            Operation::Write,
            "resources/secrets/db/ssh",
            "team-alpha",
            json!({ "password": "alpha-secret", "username": "alpha-user" }).as_object().cloned(),
        )
        .await
        .expect("write namespaced secret");

        let open = |ns: &str| {
            let call = &call;
            let ns = ns.to_string();
            async move {
                let body = json!({
                    "resource_name": "db",
                    "credential_source": { "kind": "secret", "secret_id": "ssh" },
                    "target_host": "10.1.2.3",
                    "target_port": 22,
                    "target_protocol": "ssh",
                })
                .as_object()
                .cloned();
                match call(Operation::Write, "rustion/v2/session/open", &ns, body).await {
                    Ok(_) => "ok".to_string(),
                    Err(e) => format!("{e:?}"),
                }
            }
        };

        // team-alpha: credential resolved from its own namespace, so the request
        // reaches the dispatcher and fails only because no bastion is enrolled.
        let alpha = open("team-alpha").await;
        assert!(
            alpha.contains("bastion_unavailable"),
            "namespaced open must resolve the namespace's own secret and reach \
             dispatch; got: {alpha}"
        );

        // team-beta: owns no such secret. Must fail closed rather than read the
        // root decoy.
        let beta = open("team-beta").await;
        assert!(
            !beta.contains("bastion_unavailable") && beta.contains("not found"),
            "a namespace that owns no such resource secret must not fall back to \
             the root namespace's same-named secret; got: {beta}"
        );

        // Root itself is unchanged: it resolves its own secret and reaches dispatch.
        let at_root = open("").await;
        assert!(at_root.contains("bastion_unavailable"), "root open must still resolve at root; got: {at_root}");
    }

    /// Unit cover for the prefix helper the resolvers share: root and an
    /// unknown namespace resolve to the empty (root-relative) prefix; a real
    /// namespace resolves to `<ns_path>/`. The master-cert / PKI path
    /// deliberately does *not* consume this — see `master::pki_issue_one`.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_sub_request_prefix() {
        let (_bvault, core, root) = new_unseal_test_bastion_vault("test_rustion_ns_prefix").await;

        let mut create = Request::new("sys/namespaces/team-alpha");
        create.operation = Operation::Write;
        create.client_token = root.clone();
        create.body = json!({}).as_object().cloned();
        core.handle_request(&mut create).await.expect("create namespace");

        let inner = RustionBackendInner { core: core.clone(), stores: Default::default() };

        let with_ns = |ns: Option<&str>| {
            let mut req = Request::new("rustion/v2/session/open");
            req.operation = Operation::Write;
            if let Some(ns) = ns {
                let mut h = HashMap::new();
                h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
                req.headers = Some(h);
            }
            req
        };

        assert_eq!(inner.namespace_sub_request_prefix(&with_ns(None)).await.unwrap(), "", "no header → root-relative");
        assert_eq!(
            inner.namespace_sub_request_prefix(&with_ns(Some(""))).await.unwrap(),
            "",
            "empty header → root-relative"
        );
        assert_eq!(
            inner.namespace_sub_request_prefix(&with_ns(Some("team-alpha"))).await.unwrap(),
            "team-alpha/",
            "namespaced caller → namespace-qualified sub-requests"
        );
        assert_eq!(
            inner.namespace_sub_request_prefix(&with_ns(Some("no-such-ns"))).await.unwrap(),
            "",
            "unknown namespace → root-relative, matching the router's best-effort branch"
        );
    }
}
