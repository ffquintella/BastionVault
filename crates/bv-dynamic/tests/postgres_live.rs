//! The host's PostgreSQL connector against a real server in a throwaway
//! container. Ignored by default (the first run pulls `postgres:16`):
//!   cargo nextest run -p bv-dynamic --test postgres_live --run-ignored only
//! docker or podman (`BV_TEST_CONTAINER_ENGINE` forces one); with neither it
//! is skipped with a message, unless `BV_TEST_REQUIRE_CONTAINER` is set.
//! The container is plaintext, so the host is dialled under the operator's
//! explicit insecure policy; the verifying default is checked to refuse it.

mod support;

use std::time::Duration;

use bv_dynamic::{
    connector::{
        execute, postgres::PostgresConnector, restore_root, rotate_root, Connector, ConnectorParams, ExecPlan,
        SlotFactory,
    },
    pool::{ConnectionPool, PoolConfig, TargetSettings, TlsPolicy},
    DynamicError,
};
use serde_json::json;
use support::container::{ContainerError, PgContainer};
use zeroize::Zeroizing;

const LIMIT: Duration = Duration::from_secs(20);

fn params(url: &str, user: &str, password: &str) -> ConnectorParams {
    ConnectorParams::parse(&json!({ "kind": "postgres", "url": url, "username": user, "password": password })).unwrap()
}

/// `None`: no engine, skip.
fn container() -> Option<PgContainer> {
    match PgContainer::start() {
        Ok(c) => Some(c),
        Err(ContainerError::Unavailable(why)) if std::env::var_os("BV_TEST_REQUIRE_CONTAINER").is_none() => {
            eprintln!("SKIPPED live host-connector test: no usable container engine ({why})");
            None
        }
        Err(e) => panic!("could not start the postgres container: {e}"),
    }
}

async fn logs_in(url: &str, user: &str, password: &str) -> bool {
    let pg = PostgresConnector::default();
    match pg.connect(&params(url, user, password), &TlsPolicy::insecure_skip_verify()).await {
        Ok(mut session) => session.validate().await.is_ok(),
        Err(_) => false,
    }
}

#[test]
#[ignore = "starts a postgres container (docker/podman)"]
fn the_host_connector_creates_renews_and_revokes_on_a_real_server() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    // Declared outside the async body so the container is removed on every
    // exit path, a panic included.
    let Some(pg) = container() else { return };
    let (url, root) = (pg.url(), pg.password().to_string());
    pg.wait_ready(Duration::from_secs(90), || rt.block_on(logs_in(&url, pg.user, &root)))
        .unwrap_or_else(|e| panic!("{e}"));

    rt.block_on(async {
        let connector = PostgresConnector::default();
        let pool = ConnectionPool::new(SlotFactory::default(), PoolConfig::default());
        let insecure =
            TargetSettings { root_credential_version: 1, config_generation: 0, tls: TlsPolicy::insecure_skip_verify() };
        pool.configure("m/live", insecure);
        let root_params = params(&url, pg.user, &root);
        let user = format!("v-live-host-{}-0a1b2c3d", std::process::id());
        let password = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
        let run = |plan: ExecPlan| {
            let (pool, connector, root_params) = (&pool, &connector, &root_params);
            async move {
                let mut slot = pool.checkout("m/live").await.unwrap();
                let reused = slot.is_live();
                let out = execute(&mut slot, connector, root_params, &plan, &[password], LIMIT).await;
                (out, reused)
            }
        };

        let create =
            format!("CREATE ROLE \"{user}\" WITH LOGIN PASSWORD '{password}' VALID UNTIL '2099-01-01T00:00:00Z'");
        let (out, reused) = run(ExecPlan::Create { statements: vec![Zeroizing::new(create)] }).await;
        assert_eq!(out.unwrap().executed, 1);
        assert!(!reused, "the first execution dials");
        assert!(logs_in(&url, &user, password).await, "the created role logs in");

        let renew =
            ExecPlan::Renew { statements: vec![], username: user.clone(), expiration: "2099-06-01T00:00:00Z".into() };
        let (out, reused) = run(renew).await;
        assert_eq!(out.unwrap().executed, 1, "the connector's default renew");
        assert!(reused, "the pooled host connection was reused");

        let revoke = || ExecPlan::Revoke { statements: vec![], username: user.clone() };
        assert_eq!(run(revoke()).await.0.unwrap().executed, 2, "DROP OWNED BY + DROP ROLE IF EXISTS");
        assert!(!logs_in(&url, &user, password).await, "the role is gone");
        assert!(run(revoke()).await.0.unwrap().identity_absent, "a second revoke runs nothing");

        // A failing statement: the error is the server's, the password redacted.
        let bad = format!("CREATE ROLE \"{user}\" WITH LOGIN PASSWORD '{password}' BOGUS");
        let err = run(ExecPlan::Create { statements: vec![Zeroizing::new(bad)] }).await.0.unwrap_err();
        assert!(matches!(err, DynamicError::Execute(_)), "{err}");
        assert!(!err.to_string().contains(password) && !err.to_string().contains(&root), "{err}");

        // A rotation drains the pooled connection.
        pool.rotate("m/live", 2).unwrap();
        assert!(!pool.checkout("m/live").await.unwrap().is_live());

        // The verifying default never talks plaintext to this server.
        let verify = ConnectionPool::new(SlotFactory::default(), PoolConfig::default());
        verify.configure(
            "m/live",
            TargetSettings { root_credential_version: 1, config_generation: 0, tls: TlsPolicy::default() },
        );
        let mut slot = verify.checkout("m/live").await.unwrap();
        let create = ExecPlan::Create { statements: vec![Zeroizing::new("SELECT 1".to_string())] };
        let err = execute(&mut slot, &connector, &root_params, &create, &[], LIMIT).await.unwrap_err();
        assert!(err.to_string().contains("sslmode=disable"), "the URL's plaintext is refused, not honoured: {err}");
        let tls_url = url.replace(" sslmode=disable", "");
        let err =
            execute(&mut slot, &connector, &params(&tls_url, pg.user, &root), &create, &[], LIMIT).await.unwrap_err();
        assert!(matches!(err, DynamicError::Connect { .. }), "TLS is required and the server has none: {err}");
        assert!(!err.to_string().contains(&root), "{err}");
    });
}

/// Rotate-root through the host connector against a real server: the old root
/// secret stops logging in, the new one does, a credential made before still
/// works, one made after (with the new root) works, and undoing it (as the
/// host does when the plugin cannot store the new secret) brings the old back.
#[test]
#[ignore = "starts a postgres container (docker/podman)"]
fn the_host_rotates_the_root_on_a_real_server() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let Some(pg) = container() else { return };
    let (url, old_root) = (pg.url(), pg.password().to_string());
    pg.wait_ready(Duration::from_secs(90), || rt.block_on(logs_in(&url, pg.user, &old_root)))
        .unwrap_or_else(|e| panic!("{e}"));

    rt.block_on(async {
        let connector = PostgresConnector::default();
        let pool = ConnectionPool::new(SlotFactory::default(), PoolConfig::default());
        let insecure =
            TargetSettings { root_credential_version: 1, config_generation: 0, tls: TlsPolicy::insecure_skip_verify() };
        pool.configure("m/rot", insecure);
        let old_params = params(&url, pg.user, &old_root);
        let new_root = bv_dynamic::credential::generate_password().unwrap();
        let new_root = new_root.expose().to_string();
        let (before, after) =
            (format!("v-rot-before-{}", std::process::id()), format!("v-rot-after-{}", std::process::id()));
        let user_pw = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
        let create = |name: &str| ExecPlan::Create {
            statements: vec![Zeroizing::new(format!("CREATE ROLE \"{name}\" WITH LOGIN PASSWORD '{user_pw}'"))],
        };

        let mut slot = pool.checkout("m/rot").await.unwrap();
        execute(&mut slot, &connector, &old_params, &create(&before), &[], LIMIT).await.unwrap();
        let plan = ExecPlan::RotateRoot {
            templates: vec![],
            username: pg.user.to_string(),
            new_password: Zeroizing::new(new_root.clone()),
        };
        let restore = rotate_root(&mut slot, &connector, &old_params, &plan, &[], LIMIT).await.unwrap();
        drop(slot);
        assert!(!logs_in(&url, pg.user, &old_root).await, "the old root secret no longer logs in");
        assert!(logs_in(&url, pg.user, &new_root).await, "the new one does");
        assert!(logs_in(&url, &before, user_pw).await, "a credential made before the rotation still works");

        pool.rotate("m/rot", 2).unwrap();
        let mut slot = pool.checkout("m/rot").await.unwrap();
        assert!(!slot.is_live(), "the rotation drained the pooled connection");
        let new_params = params(&url, pg.user, &new_root);
        execute(&mut slot, &connector, &new_params, &create(&after), &[], LIMIT).await.unwrap();
        assert!(logs_in(&url, &after, user_pw).await, "a credential made with the new root works");
        drop(slot);

        let tls = TlsPolicy::insecure_skip_verify();
        restore_root(&connector, &restore, &tls, &[], LIMIT).await.unwrap();
        assert!(logs_in(&url, pg.user, &old_root).await, "undone: the old root secret logs in again");
        assert!(!logs_in(&url, pg.user, &new_root).await, "and the new one no longer does");
    });
}
