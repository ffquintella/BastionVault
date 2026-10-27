//! Against a real PostgreSQL. Ignored by default: a server is not guaranteed
//! where the suite runs. To run it (development only, plaintext):
//!   docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=devroot postgres:16
//!   BV_TEST_POSTGRES_URL='host=127.0.0.1 port=55432 dbname=postgres sslmode=disable' \
//!   BV_TEST_POSTGRES_USER=postgres BV_TEST_POSTGRES_PASSWORD=devroot \
//!   cargo test -p bastion-plugin-postgres --test live -- --ignored

use bastion_plugin_dynamic_sdk::testing::{invoke, MockHost};
use bastion_plugin_postgres::{target::PgConnector, PostgresBackend};
use serde_json::{json, Value};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; see the header of tests/live.rs"))
}

async fn login(url: &str, user: &str, password: &str) -> Result<(), tokio_postgres::Error> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.user(user).password(password);
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.simple_query("SELECT 1").await.map(|_| ())
}

#[test]
#[ignore = "needs a PostgreSQL server: set BV_TEST_POSTGRES_URL/_USER/_PASSWORD (see the file header)"]
fn generate_login_renew_revoke_and_rotate_root() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (url, root_user, root_password) =
            (env("BV_TEST_POSTGRES_URL"), env("BV_TEST_POSTGRES_USER"), env("BV_TEST_POSTGRES_PASSWORD"));
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
