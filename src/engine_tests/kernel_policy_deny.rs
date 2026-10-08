//! Deny supremacy on the request path (T119, finding F6).
//!
//! `bv-kernel`'s `policy::differential` pins the evaluator on HCL; these drive
//! the two callers that decide on its enforcing verdict with every input
//! resolved from storage, as in production: `PolicyStore::post_auth` (the
//! pre-route check, through `handle_request`) and
//! `PolicyStore::readable_targets` (per-object response filtering), and
//! `PolicyStore::may_connect_target` (the shared session-connect gate). Here
//! rather than in `bv-kernel` because they look the policy and identity
//! modules up by type (see `mod.rs`).
//!
//! Each case first shows the layered grant is live — a token without the deny
//! reads the target — so a refusal is the deny's doing, not a gate that never
//! opened.

use std::sync::Arc;

use serde_json::json;

use crate::{
    core::Core,
    logical::{Auth, Operation, Request},
    modules::{
        identity::{EntityStore, SecretShare, ShareStore},
        policy::PolicyModule,
    },
    test_utils::{new_unseal_test_bastion_vault, test_write_api},
};

const PASSWORD: &str = "hunter22XX!";

async fn write_policy(core: &Arc<Core>, root: &str, name: &str, hcl: &str) {
    test_write_api(
        core.as_ref(),
        root,
        &format!("sys/policy/{name}"),
        true,
        json!({ "policy": hcl }).as_object().cloned(),
    )
    .await
    .unwrap();
}

async fn write(core: &Arc<Core>, root: &str, path: &str, body: serde_json::Value) {
    test_write_api(core.as_ref(), root, path, true, body.as_object().cloned()).await.unwrap();
}

/// A userpass user carrying exactly `policies`; returns its token.
async fn user(core: &Arc<Core>, root: &str, name: &str, policies: &str) -> String {
    write(
        core,
        root,
        &format!("auth/pass/users/{name}"),
        json!({ "password": PASSWORD, "token_policies": policies, "ttl": 0 }),
    )
    .await;
    let mut login = Request::new(format!("auth/pass/login/{name}"));
    login.operation = Operation::Write;
    login.body = json!({ "password": PASSWORD }).as_object().cloned();
    core.handle_request(&mut login).await.unwrap().unwrap().auth.unwrap().client_token
}

/// A read through the full request path: `post_auth` resolves the asset
/// groups, owner and shares from storage and runs the enforcing check.
async fn can_read(core: &Arc<Core>, token: &str, path: &str) -> bool {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    core.handle_request(&mut req).await.is_ok()
}

/// `readable_targets` as a set-returning endpoint calls it, for a caller
/// carrying `policies` and (optionally) an identity entity.
async fn readable(core: &Arc<Core>, policies: &[&str], entity_id: Option<&str>, targets: &[&str]) -> Vec<bool> {
    let mut auth = Auth { policies: policies.iter().map(|p| p.to_string()).collect(), ..Default::default() };
    if let Some(id) = entity_id {
        auth.metadata.insert("entity_id".into(), id.into());
    }
    let mut req = Request::new("resources/search");
    req.auth = Some(auth);
    let module = core.module_manager().get_module::<PolicyModule>("policy").expect("policy module");
    let targets: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
    module.policy_store.load().readable_targets(&req, &targets).await
}

/// `may_connect_target` as the three session-connect gates call it, with the
/// target qualifiers resolved from the identity and resource-group stores.
async fn may_connect(core: &Arc<Core>, policies: &[&str], entity_id: Option<&str>, target: &str) -> bool {
    let mut auth = Auth { policies: policies.iter().map(|p| p.to_string()).collect(), ..Default::default() };
    if let Some(id) = entity_id {
        auth.metadata.insert("entity_id".into(), id.into());
    }
    let mut req = Request::new("rustion/v2/session/open");
    req.auth = Some(auth);
    let module = core.module_manager().get_module::<PolicyModule>("policy").expect("policy module");
    module.policy_store.load().may_connect_target(&req, target).await
}

/// A KV-v1 mount at `kv/` holding `alpha` and `beta`, `kv/alpha` in the
/// asset group `club`, and a userpass mount.
async fn kv_with_club(core: &Arc<Core>, root: &str) {
    write(core, root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    write(core, root, "kv/alpha", json!({ "v": "1" })).await;
    write(core, root, "kv/beta", json!({ "v": "2" })).await;
    write(core, root, "resource-group/groups/club", json!({ "secrets": "kv/alpha" })).await;
    write(core, root, "sys/auth/pass", json!({ "type": "userpass" })).await;
}

/// (a) An ungated deny on the path is not overridden by a `groups`-gated grant
/// whose gate passes.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_ungated_deny_beats_a_passing_gated_grant() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_ungated_deny_beats_a_passing_gated_grant").await;
    kv_with_club(&core, &root).await;
    write_policy(&core, &root, "p-gated", "path \"kv/*\" {\n  capabilities = [\"read\"]\n  groups = [\"club\"]\n}\n")
        .await;
    write_policy(&core, &root, "p-deny", "path \"kv/alpha\" {\n  capabilities = [\"deny\"]\n}\n").await;

    let control = user(&core, &root, "control", "p-gated").await;
    assert!(can_read(&core, &control, "kv/alpha").await, "control: the gated grant must be live");
    assert_eq!(readable(&core, &["p-gated"], None, &["kv/alpha"]).await, vec![true]);

    let denied = user(&core, &root, "denied", "p-gated,p-deny").await;
    assert!(!can_read(&core, &denied, "kv/alpha").await, "a gated grant overrode an ungated deny in pre_route");
    assert_eq!(
        readable(&core, &["p-gated", "p-deny"], None, &["kv/alpha"]).await,
        vec![false],
        "a gated grant overrode an ungated deny in readable_targets"
    );
}

/// (a) An ungated deny on the path is not overridden by a `scopes = ["shared"]`
/// grant backed by an active `SecretShare`.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_ungated_deny_beats_a_share_scoped_grant() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_ungated_deny_beats_a_share_scoped_grant").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write(&core, &root, "secret/data/team/x", json!({ "data": { "v": "x" } })).await;
    write_policy(
        &core,
        &root,
        "p-shared",
        "path \"secret/data/*\" {\n  capabilities = [\"read\"]\n  scopes = [\"shared\"]\n}\n",
    )
    .await;
    write_policy(&core, &root, "p-deny", "path \"secret/data/team/x\" {\n  capabilities = [\"deny\"]\n}\n").await;

    let control = user(&core, &root, "control", "p-shared").await;
    let denied = user(&core, &root, "denied", "p-shared,p-deny").await;

    let entities = EntityStore::new(&core).await.unwrap();
    let shares = ShareStore::new(&core).await.unwrap();
    let mut ids = Vec::new();
    for name in ["control", "denied"] {
        let entity = entities.get_by_alias_ns("userpass/", name, "").await.unwrap().expect("entity after login");
        shares
            .set_share(SecretShare {
                target_kind: "kv-secret".into(),
                target_path: "secret/team/x".into(),
                grantee_kind: String::new(),
                grantee_entity_id: entity.id.clone(),
                granted_by_entity_id: "root".into(),
                capabilities: vec!["read".into()],
                granted_at: String::new(),
                expires_at: String::new(),
            })
            .await
            .unwrap();
        ids.push(entity.id);
    }

    assert!(can_read(&core, &control, "secret/data/team/x").await, "control: the share-scoped grant must be live");
    assert_eq!(readable(&core, &["p-shared"], Some(&ids[0]), &["secret/data/team/x"]).await, vec![true]);

    assert!(
        !can_read(&core, &denied, "secret/data/team/x").await,
        "a share overrode an administrator's deny in pre_route"
    );
    assert_eq!(
        readable(&core, &["p-shared", "p-deny"], Some(&ids[1]), &["secret/data/team/x"]).await,
        vec![false],
        "a share overrode an administrator's deny in readable_targets"
    );
}

/// (b) A `groups`-gated deny that applies wipes an ungated grant, `sudo`
/// included; outside the group it contributes nothing.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_applying_gated_deny_wipes_an_ungated_grant() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_applying_gated_deny_wipes_an_ungated_grant").await;
    kv_with_club(&core, &root).await;
    write_policy(&core, &root, "p-read", "path \"kv/*\" {\n  capabilities = [\"read\", \"sudo\"]\n}\n").await;
    write_policy(
        &core,
        &root,
        "p-gated-deny",
        "path \"kv/*\" {\n  capabilities = [\"deny\"]\n  groups = [\"club\"]\n}\n",
    )
    .await;

    let control = user(&core, &root, "control", "p-read").await;
    assert!(can_read(&core, &control, "kv/alpha").await, "control: the ungated grant must be live");

    let denied = user(&core, &root, "denied", "p-read,p-gated-deny").await;
    assert!(!can_read(&core, &denied, "kv/alpha").await, "an applying gated deny did not wipe in pre_route");
    assert!(can_read(&core, &denied, "kv/beta").await, "the gated deny must not apply outside its group");
    assert_eq!(
        readable(&core, &["p-read", "p-gated-deny"], None, &["kv/alpha", "kv/beta"]).await,
        vec![false, true],
        "readable_targets must honour an applying gated deny and only it"
    );
    assert!(
        !may_connect(&core, &["p-read", "p-gated-deny"], None, "kv/alpha").await,
        "may_connect_target let an ungated read grant bypass an applying gated deny"
    );
    assert!(
        may_connect(&core, &["p-read", "p-gated-deny"], None, "kv/beta").await,
        "may_connect_target applied the gated deny outside its group"
    );
}

/// (b) A `scopes = ["shared"]` deny backed by an active `SecretShare`
/// wipes ungated read, sudo and connect grants. A second secret/resource
/// without a share proves the deny contributes nothing outside its scope.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_applying_share_scoped_deny_wipes_ungated_grants() {
    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_applying_share_scoped_deny_wipes_ungated_grants").await;
    write(&core, &root, "sys/auth/pass", json!({ "type": "userpass" })).await;
    write(&core, &root, "secret/data/team/x", json!({ "data": { "v": "x" } })).await;
    write(&core, &root, "secret/data/team/y", json!({ "data": { "v": "y" } })).await;
    write_policy(
        &core,
        &root,
        "p-read",
        "path \"secret/data/*\" {\n  capabilities = [\"read\", \"sudo\"]\n}\n\npath \"resources/secrets/*\" {\n  \
         capabilities = [\"connect\"]\n}\n",
    )
    .await;
    write_policy(
        &core,
        &root,
        "p-shared-deny",
        "path \"secret/data/*\" {\n  capabilities = [\"deny\"]\n  scopes = [\"shared\"]\n}\n\npath \
         \"resources/secrets/*\" {\n  capabilities = [\"deny\"]\n  scopes = [\"shared\"]\n}\n",
    )
    .await;

    let control = user(&core, &root, "control", "p-read").await;
    assert!(can_read(&core, &control, "secret/data/team/x").await, "control: the ungated read grant must be live");
    assert_eq!(
        readable(&core, &["p-read"], None, &["secret/data/team/x", "secret/data/team/y"]).await,
        vec![true, true]
    );
    assert!(
        may_connect(&core, &["p-read"], None, "resources/secrets/db/ssh").await,
        "control: the explicit ungated connect grant must be live"
    );

    let denied = user(&core, &root, "denied", "p-read,p-shared-deny").await;
    let entity_id = EntityStore::new(&core)
        .await
        .unwrap()
        .get_by_alias_ns("userpass/", "denied", "")
        .await
        .unwrap()
        .expect("entity after login")
        .id;
    let shares = ShareStore::new(&core).await.unwrap();
    shares
        .set_share(SecretShare {
            target_kind: "kv-secret".into(),
            target_path: "secret/team/x".into(),
            grantee_kind: String::new(),
            grantee_entity_id: entity_id.clone(),
            granted_by_entity_id: "root".into(),
            capabilities: vec!["read".into()],
            granted_at: String::new(),
            expires_at: String::new(),
        })
        .await
        .unwrap();
    shares
        .set_share(SecretShare {
            target_kind: "resource".into(),
            target_path: "db".into(),
            grantee_kind: String::new(),
            grantee_entity_id: entity_id.clone(),
            granted_by_entity_id: "root".into(),
            capabilities: vec!["connect".into()],
            granted_at: String::new(),
            expires_at: String::new(),
        })
        .await
        .unwrap();

    assert!(
        !can_read(&core, &denied, "secret/data/team/x").await,
        "an applying share-scoped deny did not wipe in pre_route"
    );
    assert!(
        can_read(&core, &denied, "secret/data/team/y").await,
        "the share-scoped deny must not apply to an unshared secret"
    );
    assert_eq!(
        readable(&core, &["p-read", "p-shared-deny"], Some(&entity_id), &["secret/data/team/x", "secret/data/team/y"],)
            .await,
        vec![false, true],
        "readable_targets must honour an applying share-scoped deny and only it"
    );
    assert!(
        !may_connect(&core, &["p-read", "p-shared-deny"], Some(&entity_id), "resources/secrets/db/ssh",).await,
        "may_connect_target let an ungated connect grant bypass an applying share-scoped deny"
    );
    assert!(
        may_connect(&core, &["p-read", "p-shared-deny"], Some(&entity_id), "resources/secrets/other/ssh",).await,
        "may_connect_target applied the share-scoped deny to an unshared resource"
    );
}
