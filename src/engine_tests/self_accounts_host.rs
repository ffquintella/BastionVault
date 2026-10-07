//! The real host, driving the real `bastion-plugin-self-accounts` wasm.
//!
//! Everything else tests one half: the plugin's own tests run it against the
//! testkit's *mirror* of the host, and `src/plugins/*` tests run the host
//! against toy wasm. This is the only place the two meet, so it is where a
//! drift between the testkit and `PluginCtx` (entity rebasing, the caller
//! block, the grant gate, the purge hook) would show.
//!
//! `#[ignore]`d because it needs a build that `cargo test` does not make:
//!
//!   cd plugins-ext && cargo build --release --target wasm32-unknown-unknown \
//!       -p bastion-plugin-self-accounts
//!
//! `make plugins-test` builds it and runs this with `--run-ignored only`.

pub(crate) mod self_accounts_host_tests {
    use std::sync::Arc;

    use serde_json::{json, Map, Value};
    use sha2::{Digest, Sha256};

    use crate::core::Core;
    use crate::kernel_api::provider::{
        CallerIdentity, ProviderConnectContext, ProviderNeeds, ProviderQuery, ProviderReleaseRequest, ProviderResource,
        ProviderTarget, ReleasedSecret,
    };
    use crate::kernel_api::VaultCtx;
    use crate::plugins::manifest::{
        Capabilities, CredentialProviderCap, PluginManifest, ProviderSelection, RuntimeKind, StorageScope,
    };
    use crate::plugins::{provider as grants, PluginCatalog};
    use crate::test_utils::{new_unseal_test_bastion_vault, test_mount_api, test_write_api};

    pub(crate) fn wasm() -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("plugins-ext/target/wasm32-unknown-unknown/release/bastion_plugin_self_accounts.wasm");
        std::fs::read(&p).unwrap_or_else(|_| {
            panic!(
                "{} is missing; build it with: cd plugins-ext && cargo build --release \
                 --target wasm32-unknown-unknown -p bastion-plugin-self-accounts",
                p.display()
            )
        })
    }

    /// Mirrors `plugins-ext/bastion-plugin-self-accounts/plugin.toml`, whose own
    /// test checks that file against the spec. Also used by
    /// `engine_tests::self_accounts_connect`.
    pub(crate) fn manifest(bin: &[u8]) -> PluginManifest {
        PluginManifest {
            name: "self-accounts".into(),
            version: "0.1.0".into(),
            plugin_type: "secret".into(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.3".into(),
            sha256: hex::encode(Sha256::digest(bin)),
            size: bin.len() as u64,
            capabilities: Capabilities {
                log_emit: true,
                audit_emit: true,
                storage_prefix: Some(String::new()),
                caller_identity: true,
                storage_scope: StorageScope::Entity,
                credential_provider: Some(CredentialProviderCap {
                    display_name: "Self-account".into(),
                    selection: ProviderSelection::Operator,
                    protocols: vec!["ssh".into(), "rdp".into(), "web".into()],
                    secret_kinds: vec!["password".into(), "ssh-key".into()],
                }),
                ..Default::default()
            },
            description: String::new(),
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
            surface: None,
            client_assets: vec![],
        }
    }

    fn obj(v: Value) -> Option<Map<String, Value>> {
        v.as_object().cloned()
    }

    struct Fixture {
        core: Arc<Core>,
        root: String,
        alice: String,
        alice_entity: String,
        bob: String,
        bob_entity: String,
        _vault: crate::BastionVault,
    }

    async fn login(core: &Arc<Core>, user: &str) -> (String, String) {
        let r = test_write_api(
            core.as_ref(),
            "",
            &format!("auth/pass/login/{user}"),
            true,
            obj(json!({ "password": "hunter22XX!" })),
        )
        .await
        .unwrap()
        .unwrap();
        let auth = r.auth.unwrap();
        let entity = auth.metadata.get("entity_id").cloned().unwrap_or_default();
        assert!(!entity.is_empty(), "login must stamp an entity id");
        (auth.client_token, entity)
    }

    async fn setup(name: &str) -> Fixture {
        let (vault, core, root) = new_unseal_test_bastion_vault(name).await;
        let bin = wasm();
        let m = manifest(&bin);
        m.validate().expect("manifest validates");
        crate::plugins::verifier::write_accept_unsigned(core.barrier.as_storage(), true).await.unwrap();
        PluginCatalog::new().put(core.barrier.as_storage(), &m, &bin).await.expect("register plugin");
        test_mount_api(core.as_ref(), &root, "plugin:self-accounts", "self-accounts/").await;

        let policy = r#"path "self-accounts/*" { capabilities = ["create","read","update","delete","list"] }"#;
        test_write_api(core.as_ref(), &root, "sys/policy/sa-user", true, obj(json!({ "policy": policy })))
            .await
            .unwrap();
        test_write_api(core.as_ref(), &root, "sys/auth/pass", true, obj(json!({ "type": "userpass" }))).await.unwrap();
        for u in ["alice", "bob"] {
            test_write_api(
                core.as_ref(),
                &root,
                &format!("auth/pass/users/{u}"),
                true,
                obj(json!({ "password": "hunter22XX!", "token_policies": "sa-user", "ttl": 0 })),
            )
            .await
            .unwrap();
        }
        let (alice, alice_entity) = login(&core, "alice").await;
        let (bob, bob_entity) = login(&core, "bob").await;
        assert_ne!(alice_entity, bob_entity);
        Fixture { core, root, alice, alice_entity, bob, bob_entity, _vault: vault }
    }

    fn account() -> Option<Map<String, Value>> {
        obj(json!({
            "label": "Domain admin", "username": "felipe.adm", "domain": "CORP",
            "secret_kind": "password", "password": "hunter2-S3CRET",
            "resource_types": ["server"], "os_types": ["windows"], "protocols": ["rdp"],
            "targets": "*.corp.example.com",
        }))
    }

    fn caller(entity: &str) -> CallerIdentity {
        CallerIdentity { entity_id: entity.into(), ..Default::default() }
    }

    fn query() -> ProviderQuery {
        ProviderQuery {
            protocol: "rdp".into(),
            resource: ProviderResource { resource_type: "server".into(), os_type: Some("windows".into()) },
            target: ProviderTarget::Host { host: "dc01.corp.example.com".into(), port: 3389 },
        }
    }

    fn release_req(id: &str, mfa: bool) -> ProviderReleaseRequest {
        let q = query();
        ProviderReleaseRequest {
            account_id: id.into(),
            protocol: q.protocol,
            resource: q.resource,
            target: q.target,
            needs: ProviderNeeds { password: true, totp: false },
            connect: ProviderConnectContext { mfa_verified: mfa, transport: "direct".into() },
        }
    }

    async fn create(f: &Fixture, token: &str) -> String {
        let r = test_write_api(f.core.as_ref(), token, "self-accounts/v2/accounts", true, account())
            .await
            .unwrap()
            .unwrap();
        r.data.unwrap()["id"].as_str().unwrap().to_string()
    }

    /// Every stored *value* under the entity's prefix. Leaf keys only: the file
    /// backend cannot remove a directory, so an emptied `sa_…/` entry may still
    /// be listed after a purge; that is an id, not data.
    async fn entity_keys(f: &Fixture, entity: &str) -> Vec<String> {
        let storage = f.core.barrier.as_storage();
        let mut stack = vec![format!("core/plugins/self-accounts/data/entity/{entity}/")];
        let mut leaves = Vec::new();
        while let Some(p) = stack.pop() {
            for n in storage.list(&p).await.unwrap() {
                match n.strip_suffix('/') {
                    Some(d) => stack.push(format!("{p}{d}/")),
                    None => leaves.push(format!("{p}{n}")),
                }
            }
        }
        leaves
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn host_confines_each_entity_to_its_own_prefix() {
        let f = setup("sa_host_scope").await;
        let id = create(&f, &f.alice).await;

        // Alice's record is physically under alice's entity prefix, and nowhere else.
        assert!(!entity_keys(&f, &f.alice_entity).await.is_empty());
        assert!(entity_keys(&f, &f.bob_entity).await.is_empty());
        let plugin_wide = f.core.barrier.as_storage().list("core/plugins/self-accounts/data/").await.unwrap();
        assert_eq!(plugin_wide, vec!["entity/".to_string()], "nothing outside the entity scope");

        // Bob sees none of it, through the real router, policy and host.
        let bob_list = crate::test_utils::test_list_api(f.core.as_ref(), &f.bob, "self-accounts/v2/accounts", true)
            .await
            .unwrap()
            .unwrap();
        assert!(bob_list.data.unwrap()["entries"].as_array().unwrap().is_empty());
        let bob_read = crate::test_utils::test_read_api(
            f.core.as_ref(),
            &f.bob,
            &format!("self-accounts/v2/accounts/{id}"),
            false,
        )
        .await;
        assert!(bob_read.is_err() || bob_read.unwrap().is_none());
        let alice_read = crate::test_utils::test_read_api(
            f.core.as_ref(),
            &f.alice,
            &format!("self-accounts/v2/accounts/{id}"),
            true,
        )
        .await
        .unwrap()
        .unwrap()
        .data
        .unwrap();
        assert_eq!(alice_read["label"], "Domain admin");
        assert!(!format!("{alice_read:?}").contains("hunter2"));
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn a_token_without_an_entity_is_refused_before_the_plugin_runs() {
        let f = setup("sa_host_noentity").await;
        // The root token has no identity entity.
        let r = test_write_api(f.core.as_ref(), &f.root, "self-accounts/v2/accounts", false, account()).await;
        let e = format!("{:?}", r.err().expect("must be refused"));
        assert!(e.contains("identity-backed login"), "{e}");
        assert!(f.core.barrier.as_storage().list("core/plugins/self-accounts/data/").await.unwrap().is_empty());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn provider_calls_need_the_admin_grant_and_validate_the_release() {
        let f = setup("sa_host_grant").await;
        let id = create(&f, &f.alice).await;
        let host = f.core.plugin_host().expect("plugin host");

        // Declared but not approved: not listed, and every call is refused.
        assert!(host.credential_providers().await.is_empty());
        let e = host.provider_candidates("self-accounts", &caller(&f.alice_entity), &query()).await.unwrap_err();
        assert!(format!("{e}").contains("not approved"), "{e}");
        assert!(host
            .provider_release("self-accounts", &caller(&f.alice_entity), &release_req(&id, true))
            .await
            .is_err());

        // Approve it.
        let m = PluginCatalog::new().get_manifest(f.core.barrier.as_storage(), "self-accounts").await.unwrap().unwrap();
        grants::put_grant(f.core.barrier.as_storage(), &m, "admin", "2026-10-07T00:00:00Z".into()).await.unwrap();
        let decls = host.credential_providers().await;
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].display_name, "Self-account");

        let c = host.provider_candidates("self-accounts", &caller(&f.alice_entity), &query()).await.unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].id, id);
        assert_eq!(c[0].username, "felipe.adm");
        // Bob is offered nothing and cannot release Alice's id.
        assert!(host.provider_candidates("self-accounts", &caller(&f.bob_entity), &query()).await.unwrap().is_empty());
        assert!(host.provider_release("self-accounts", &caller(&f.bob_entity), &release_req(&id, true)).await.is_err());
        // No entity: refused by the host, not the plugin.
        assert!(host.provider_candidates("self-accounts", &caller(""), &query()).await.is_err());
        // MFA attestation is the plugin's rule, fed by the host's `connect` block.
        assert!(host
            .provider_release("self-accounts", &caller(&f.alice_entity), &release_req(&id, false))
            .await
            .is_err());

        let cred =
            host.provider_release("self-accounts", &caller(&f.alice_entity), &release_req(&id, true)).await.unwrap();
        assert_eq!(cred.username, "felipe.adm");
        assert_eq!(cred.domain.as_deref(), Some("CORP"));
        match &cred.secret {
            ReleasedSecret::Password { password, totp_seed } => {
                assert_eq!(password.as_str(), "hunter2-S3CRET");
                assert!(totp_seed.is_none());
            }
            _ => panic!("expected a password"),
        }
        assert!(!format!("{cred:?}").contains("hunter2"), "Debug must not print the secret");

        // A changed provider block voids the approval, and with it every call.
        let mut narrowed = m.clone();
        narrowed.capabilities.credential_provider.as_mut().unwrap().protocols = vec!["ssh".into()];
        assert!(!grants::grant_is_live(f.core.barrier.as_storage(), &narrowed).await);
        grants::delete_grant(f.core.barrier.as_storage(), "self-accounts").await.unwrap();
        assert!(host.credential_providers().await.is_empty());
        assert!(host.provider_candidates("self-accounts", &caller(&f.alice_entity), &query()).await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    #[ignore = "needs the wasm32-unknown-unknown build; run via `make plugins-test`"]
    async fn deleting_the_principal_purges_its_entity_data_and_only_its_own() {
        let f = setup("sa_host_purge").await;
        create(&f, &f.alice).await;
        create(&f, &f.bob).await;
        assert!(!entity_keys(&f, &f.alice_entity).await.is_empty());

        crate::test_utils::test_delete_api(f.core.as_ref(), &f.root, "auth/pass/users/alice", true, None)
            .await
            .unwrap();

        assert!(
            entity_keys(&f, &f.alice_entity).await.is_empty(),
            "alice's accounts must be purged with her last alias"
        );
        assert!(!entity_keys(&f, &f.bob_entity).await.is_empty(), "bob's accounts must survive");
        // A purge that succeeded leaves no pending-purge marker behind.
        assert!(crate::plugins::entity_data::pending_purges(f.core.barrier.as_storage()).await.unwrap().is_empty());
        // The administrator's usage counts now show bob only.
        let usage =
            crate::plugins::entity_data::entity_data_usage(f.core.as_ref(), "self-accounts").await.unwrap().unwrap();
        assert_eq!((usage.total_entities, usage.total_accounts), (1, 1), "{usage:?}");
        assert_eq!(usage.entities[0].entity_id, f.bob_entity);
        assert_eq!(usage.entities[0].display_name.as_deref(), Some("bob"));
    }
}
