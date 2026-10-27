//! Against a real PostgreSQL, started by the test itself in a container.
//!
//! Ignored by default (`cargo test` / `make dynamic-plugins-test` stay
//! container-free: the first run pulls `postgres:16`). Run it with no other setup:
//!
//!   make dynamic-plugins-live
//!   # or: cd dynamic-engine-plugins && cargo test -p bastion-plugin-postgres --test live -- --ignored
//!
//! The container comes from `docker` or `podman` on PATH (`BV_TEST_CONTAINER_ENGINE`
//! forces one), listens on 127.0.0.1 on a random port with a random root password,
//! and is always removed, also when the test panics (tests/support/container.rs).
//! With no usable engine the test is skipped with a message, unless
//! `BV_TEST_REQUIRE_CONTAINER` is set, in which case it fails.
//!
//! To use an external server instead (development only, plaintext), set
//! `BV_TEST_POSTGRES_URL` (e.g. 'host=127.0.0.1 port=5432 dbname=postgres sslmode=disable'),
//! `BV_TEST_POSTGRES_USER` and `BV_TEST_POSTGRES_PASSWORD`.

mod support;

use std::time::Duration;

use bastion_plugin_dynamic_sdk::testing::{invoke, MockHost};
use bastion_plugin_postgres::{target::PgConnector, PostgresBackend};
use serde_json::{json, Value};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; see the header of tests/live.rs"))
}

/// Where the test runs: the external override, or a container (kept alive by
/// the guard until the end of the test).
struct Target {
    url: String,
    user: String,
    password: String,
    _container: Option<support::container::PgContainer>,
}

/// `None` means skip (no container engine); `BV_TEST_REQUIRE_CONTAINER` turns
/// that into a failure.
fn target(rt: &tokio::runtime::Runtime) -> Option<Target> {
    if std::env::var("BV_TEST_POSTGRES_URL").is_ok() {
        return Some(Target {
            url: env("BV_TEST_POSTGRES_URL"),
            user: env("BV_TEST_POSTGRES_USER"),
            password: env("BV_TEST_POSTGRES_PASSWORD"),
            _container: None,
        });
    }
    let container = match support::container::PgContainer::start() {
        Ok(c) => c,
        Err(support::container::ContainerError::Unavailable(why)) => {
            if std::env::var_os("BV_TEST_REQUIRE_CONTAINER").is_some() {
                panic!("BV_TEST_REQUIRE_CONTAINER is set but no container engine is usable: {why}");
            }
            eprintln!("SKIPPED live postgres test: no usable container engine ({why}); set BV_TEST_REQUIRE_CONTAINER to fail instead");
            return None;
        }
        Err(e) => panic!("could not start the postgres container: {e}"),
    };
    let (url, user, password) = (container.url(), container.user.to_string(), container.password().to_string());
    container
        .wait_ready(Duration::from_secs(90), || {
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), login(&url, &user, &password))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
            })
        })
        .unwrap_or_else(|e| panic!("{e}"));
    Some(Target { url, user, password, _container: Some(container) })
}

async fn login(url: &str, user: &str, password: &str) -> Result<(), tokio_postgres::Error> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.user(user).password(password);
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.simple_query("SELECT 1").await.map(|_| ())
}

#[test]
#[ignore = "starts a postgres container (docker/podman); run with `make dynamic-plugins-live` or `-- --ignored`"]
fn generate_login_renew_revoke_and_rotate_root() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // Declared before the async body so the container outlives it and is
    // removed on every exit path, including a panic.
    let Some(Target { url, user: root_user, password: root_password, _container }) = target(&rt) else { return };
    rt.block_on(async {
        let engine = PostgresBackend::new(PgConnector::default());
        // A plaintext test server: the explicit development path, as the host
        // grants it when the operator set insecure_skip_tls_verify.
        let mut host = MockHost::granting_all().with_connection("live");
        host.tls = Some(json!({ "verify": false }));
        let ok = |r: &bastion_plugin_dynamic_sdk::dispatch::Reply| {
            assert_eq!(r.status, 0, "{:?}", r.json());
        };
        let conn = json!({ "op": "write", "path": "config/live", "data": {
            "connection_url": url, "username": root_user, "password": root_password, "allowed_roles": "*" } });
        ok(&invoke(&engine, &mut host, &conn).await.0);

        let user = format!("v-test-live-{}-0a1b2c3d", std::process::id());
        let password = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
        let generate = json!({
            "op": "dynamic.generate", "role": "live", "connection": "live",
            "statements": [format!("CREATE ROLE \"{user}\" WITH LOGIN PASSWORD '{password}' VALID UNTIL '2099-01-01T00:00:00Z'")],
            "credential": { "username": user, "password": password, "expiration": "2099-01-01T00:00:00Z" },
            "ttl_secs": 600,
        });
        ok(&invoke(&engine, &mut host, &generate).await.0);
        assert_eq!(host.leases.len(), 1);
        login(&url, &user, password).await.expect("the generated credential logs in");

        let lease = |op: &str| -> Value {
            json!({ "op": op, "role": "live", "connection": "live", "username": user, "statements": [],
                    "expiration": "2099-06-01T00:00:00Z", "ttl_secs": 600, "internal": { "v": 1 } })
        };
        ok(&invoke(&engine, &mut host, &lease("dynamic.renew")).await.0);
        ok(&invoke(&engine, &mut host, &lease("dynamic.revoke")).await.0);
        assert!(login(&url, &user, password).await.is_err(), "the role is gone");
        ok(&invoke(&engine, &mut host, &lease("dynamic.revoke")).await.0);

        // Rotate the root to a new secret, check it, then put the original back.
        let rotated = "Zq9-live-rotated-root-secret";
        let rotate = |pw: &str| json!({ "op": "dynamic.rotate_root", "connection": "live", "credential": { "password": pw } });
        ok(&invoke(&engine, &mut host, &rotate(rotated)).await.0);
        login(&url, &root_user, rotated).await.expect("the new root credential works");
        ok(&invoke(&engine, &mut host, &rotate(&root_password)).await.0);
    });
}
