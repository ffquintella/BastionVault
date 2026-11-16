//! Environment and entitlement store tests over an in-memory `Storage`.

use std::collections::BTreeMap;

use chrono::Duration;

use super::*;
use crate::{posix::store::IdentityWrite, test_support::MemStorage};

pub(crate) fn bound(path: &str, uuid: &str) -> BoundNamespace {
    BoundNamespace { path: path.into(), uuid: uuid.into() }
}

pub(crate) fn roles(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    pairs.iter().map(|(r, ps)| (r.to_string(), ps.iter().map(|p| p.to_string()).collect())).collect()
}

fn stores() -> (Arc<MemStorage>, PosixStore, EntitlementStore) {
    let posix = PosixStore::new(MemStorage::new_arc() as Arc<dyn Storage>);
    let mem = MemStorage::new_arc();
    let authz = EntitlementStore::new(mem.clone() as Arc<dyn Storage>);
    (mem, posix, authz)
}

fn env_write(name: &str, ns: Option<BoundNamespace>, r: Option<BTreeMap<String, Vec<String>>>) -> EnvironmentWrite {
    EnvironmentWrite { name: name.into(), namespace: ns, roles: r, description: None }
}

fn grant(entity_id: &str, env: &str, r: &[&str]) -> EntitlementWrite {
    EntitlementWrite {
        entity_id: entity_id.into(),
        environment: env.into(),
        roles: r.iter().map(|s| s.to_string()).collect(),
        not_after: None,
        source: EntitlementSource::Manual,
        granted_by: "root".into(),
    }
}

fn status(err: RvError) -> u16 {
    match err {
        RvError::ErrResponseStatus(s, _) => s,
        other => panic!("expected a status error, got {other:?}"),
    }
}

async fn identity(posix: &PosixStore, entity_id: &str, login: &str) {
    let w = IdentityWrite { entity_id: entity_id.into(), login: Some(login.into()), ..Default::default() };
    posix.create_or_update(w).await.unwrap();
}

#[tokio::test]
async fn environments_bind_one_namespace_for_life() {
    let (mem, _posix, authz) = stores();
    // A namespace is required to create one.
    assert_eq!(status(authz.put_environment(env_write("prod", None, None)).await.unwrap_err()), 400);

    let r = roles(&[("sysadmin", &["prod-admin"]), ("dba", &["prod-dba", "prod-dba"])]);
    let (env, created) =
        authz.put_environment(env_write("prod", Some(bound("prod", "u-prod")), Some(r))).await.unwrap();
    assert!(created);
    assert_eq!((env.namespace.as_str(), env.namespace_uuid.as_str()), ("prod", "u-prod"));
    assert_eq!(env.roles["dba"], vec!["prod-dba".to_string()]);
    let raw: serde_json::Value = serde_json::from_slice(&mem.raw_get("environments/prod").unwrap()).unwrap();
    assert_eq!(raw["version"], 1);

    // Roles are replaced as a whole; the namespace cannot move.
    let (env, created) = authz
        .put_environment(env_write("prod", Some(bound("prod", "u-prod")), Some(roles(&[("ops", &[])]))))
        .await
        .unwrap();
    assert!(!created);
    assert_eq!(env.roles.keys().collect::<Vec<_>>(), vec!["ops"]);
    let moved = authz.put_environment(env_write("prod", Some(bound("dev", "u-dev")), None)).await;
    assert_eq!(status(moved.unwrap_err()), 400);

    // One active environment per namespace.
    let twin = authz.put_environment(env_write("prod2", Some(bound("prod", "u-prod")), None)).await;
    assert_eq!(status(twin.unwrap_err()), 409);
    let forbidden = authz.put_environment(env_write("x", Some(bound("x", "u-x")), Some(roles(&[("a", &["root"])]))));
    assert_eq!(status(forbidden.await.unwrap_err()), 400);

    // Retirement is terminal and frees the namespace, never the name.
    assert_eq!(status(authz.retire_environment("nope").await.unwrap_err()), 404);
    let retired = authz.retire_environment("prod").await.unwrap();
    assert_eq!(retired.state, EnvironmentState::Retired);
    assert_eq!(authz.retire_environment("prod").await.unwrap().state, EnvironmentState::Retired);
    let reuse = authz.put_environment(env_write("prod", Some(bound("prod", "u-prod")), None)).await;
    assert_eq!(status(reuse.unwrap_err()), 409);
    authz.put_environment(env_write("prod2", Some(bound("prod", "u-prod")), None)).await.unwrap();
    let names: Vec<String> = authz.list_environments().await.unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["prod".to_string(), "prod2".to_string()]);
}

#[tokio::test]
async fn grants_are_validated_against_identity_and_environment() {
    let (mem, posix, authz) = stores();
    let r = roles(&[("sysadmin", &["prod-admin"]), ("dba", &["prod-dba"])]);
    authz.put_environment(env_write("prod", Some(bound("prod", "u-prod")), Some(r))).await.unwrap();
    let now = Utc::now();

    // No workforce identity yet.
    assert_eq!(status(authz.put_entitlement(&posix, grant("e-a", "prod", &["dba"]), now).await.unwrap_err()), 404);
    identity(&posix, "e-a", "alice").await;
    for (bad, code) in [
        (grant("e-a", "nope", &["dba"]), 404),
        (grant("e-a", "prod", &["dba", "ghost"]), 400),
        (grant("e-a", "prod", &[]), 400),
        (grant("e-a", "Prod", &["dba"]), 400),
        (EntitlementWrite { not_after: Some(now - Duration::seconds(1)), ..grant("e-a", "prod", &["dba"]) }, 400),
    ] {
        assert_eq!(status(authz.put_entitlement(&posix, bad, now).await.unwrap_err()), code);
    }

    let (ent, created) = authz.put_entitlement(&posix, grant("e-a", "prod", &["sysadmin", "dba"]), now).await.unwrap();
    assert!(created);
    assert_eq!(ent.roles, vec!["dba".to_string(), "sysadmin".to_string()]);
    assert_eq!(ent.granted_by, "root");
    let raw: serde_json::Value = serde_json::from_slice(&mem.raw_get("entitlements/e-a/prod").unwrap()).unwrap();
    assert_eq!(raw["version"], 1);
    let (_, created) = authz.put_entitlement(&posix, grant("e-a", "prod", &["dba"]), now).await.unwrap();
    assert!(!created);
    assert_eq!(authz.list_entitlements("e-a").await.unwrap().len(), 1);

    // Revocation, then a removed identity and a retired environment refuse grants.
    assert_eq!(authz.delete_entitlement("e-a", "prod").await.unwrap().environment, "prod");
    assert_eq!(status(authz.delete_entitlement("e-a", "prod").await.unwrap_err()), 404);
    assert!(authz.get_entitlement("e-a", "prod").await.unwrap().is_none());
    posix.transition("e-a", IdentityState::Disabled, None).await.unwrap();
    authz.put_entitlement(&posix, grant("e-a", "prod", &["dba"]), now).await.unwrap();
    posix.transition("e-a", IdentityState::Removed, None).await.unwrap();
    assert_eq!(status(authz.put_entitlement(&posix, grant("e-a", "prod", &["dba"]), now).await.unwrap_err()), 409);
    identity(&posix, "e-b", "bob").await;
    authz.retire_environment("prod").await.unwrap();
    assert_eq!(status(authz.put_entitlement(&posix, grant("e-b", "prod", &["dba"]), now).await.unwrap_err()), 409);
}

#[tokio::test]
async fn malformed_and_misplaced_records_are_refused_not_repaired() {
    let (mem, posix, authz) = stores();
    identity(&posix, "e-a", "alice").await;
    authz
        .put_environment(env_write("prod", Some(bound("prod", "u-prod")), Some(roles(&[("dba", &[])]))))
        .await
        .unwrap();
    authz.put_entitlement(&posix, grant("e-a", "prod", &["dba"]), Utc::now()).await.unwrap();
    let good = mem.raw_get("entitlements/e-a/prod").unwrap();

    let v2 = String::from_utf8(good.clone()).unwrap().replacen("\"version\":1", "\"version\":2", 1);
    mem.raw_put("entitlements/e-a/prod", v2.as_bytes());
    assert_eq!(status(authz.get_entitlement("e-a", "prod").await.unwrap_err()), 500);
    // A malformed record is not deleted on the way out either.
    assert_eq!(status(authz.delete_entitlement("e-a", "prod").await.unwrap_err()), 500);

    // A valid record copied under another identity's key.
    mem.raw_put("entitlements/e-a/prod", &good);
    mem.raw_put("entitlements/e-b/prod", &good);
    assert_eq!(status(authz.get_entitlement("e-b", "prod").await.unwrap_err()), 500);
    let env = mem.raw_get("environments/prod").unwrap();
    mem.raw_put("environments/dev", &env);
    assert_eq!(status(authz.get_environment("dev").await.unwrap_err()), 500);
    mem.raw_put("environments/prod", b"{not json");
    assert_eq!(status(authz.get_environment("prod").await.unwrap_err()), 500);
}
