//! The connector layer against a fake target: pool reuse, drain on rotate,
//! max_size, the TLS policy, redaction and "only rendered statements run".

use std::{
    collections::BTreeSet,
    sync::{atomic::AtomicBool, Mutex},
};

use serde_json::json;

use super::*;
use crate::pool::{ConnectionPool, PoolConfig, TargetSettings};

const ROOT_SECRET: &str = "root-secret-very-long-123";
const PASSWORD: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";

#[derive(Default)]
struct FakeTarget {
    /// (url, username, password, TLS policy) of every dial.
    dials: Mutex<Vec<(String, String, String, TlsPolicy)>>,
    committed: Mutex<Vec<Vec<String>>>,
    identities: Mutex<BTreeSet<String>>,
    fail_validation: AtomicBool,
    /// A statement containing this fails, echoing the statement.
    fail_on: Mutex<Option<String>>,
    /// Refuse to dial in plaintext under a verifying policy, like a real one.
    plaintext_target: AtomicBool,
}

struct FakeConnector(Arc<FakeTarget>);

struct FakeSession(Arc<FakeTarget>);

impl ConnectorSession for FakeSession {
    fn validate(&mut self) -> BoxFuture<'_, Result<(), DynamicError>> {
        let broken = self.0.fail_validation.load(Ordering::SeqCst);
        Box::pin(async move {
            if broken {
                Err(DynamicError::Execute("gone".into()))
            } else {
                Ok(())
            }
        })
    }

    fn execute_in_transaction<'a>(&'a mut self, statements: &'a [&'a str]) -> BoxFuture<'a, Result<(), DynamicError>> {
        Box::pin(async move {
            if let Some(bad) = self.0.fail_on.lock().unwrap().as_deref() {
                if let Some(s) = statements.iter().find(|s| s.contains(bad)) {
                    return Err(DynamicError::Execute(format!("syntax error in {s}")));
                }
            }
            self.0.committed.lock().unwrap().push(statements.iter().map(|s| s.to_string()).collect());
            Ok(())
        })
    }

    fn identity_exists<'a>(&'a mut self, name: &'a str) -> BoxFuture<'a, Result<bool, DynamicError>> {
        Box::pin(async move { Ok(self.0.identities.lock().unwrap().contains(name)) })
    }
}

impl Connector for FakeConnector {
    fn kind(&self) -> &'static str {
        "fake"
    }

    fn connect<'a>(
        &'a self,
        params: &'a ConnectorParams,
        tls: &'a TlsPolicy,
    ) -> BoxFuture<'a, Result<Box<dyn ConnectorSession>, DynamicError>> {
        Box::pin(async move {
            if tls.verifies() && self.0.plaintext_target.load(Ordering::SeqCst) {
                return Err(DynamicError::Connect {
                    connection: params.endpoint().url.clone(),
                    reason: format!(
                        "server does not support TLS (tried as {} / {})",
                        params.endpoint().username,
                        params.password()
                    ),
                });
            }
            let e = params.endpoint();
            self.0.dials.lock().unwrap().push((
                e.url.clone(),
                e.username.clone(),
                params.password().into(),
                tls.clone(),
            ));
            Ok(Box::new(FakeSession(self.0.clone())) as Box<dyn ConnectorSession>)
        })
    }

    fn default_revocation(&self, username: &str) -> Result<Vec<String>, DynamicError> {
        Ok(vec![format!("DEFAULT DROP {username}")])
    }

    fn default_renew(&self, username: &str, expiration: &str) -> Result<Vec<String>, DynamicError> {
        Ok(vec![format!("DEFAULT EXTEND {username} {expiration}")])
    }
}

fn params(url: &str) -> ConnectorParams {
    ConnectorParams::parse(&json!({ "kind": "fake", "url": url, "username": "root", "password": ROOT_SECRET })).unwrap()
}

fn create() -> ExecPlan {
    ExecPlan::Create {
        statements: vec![
            Zeroizing::new(format!("CREATE \"v-1\" PASSWORD '{PASSWORD}'")),
            Zeroizing::new("GRANT".into()),
        ],
    }
}

fn pool(max_size: usize, tls: TlsPolicy) -> ConnectionPool<SlotFactory> {
    let pool = ConnectionPool::new(SlotFactory::default(), PoolConfig { max_size, checkout_timeout: Duration::ZERO });
    pool.configure("m/prod", TargetSettings { root_credential_version: 1, config_generation: 0, tls });
    pool
}

const LIMIT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn a_pooled_connection_is_reused_and_validated_before_each_use() {
    let target = Arc::new(FakeTarget::default());
    let fake = FakeConnector(target.clone());
    let pool = pool(2, TlsPolicy::default());
    for _ in 0..3 {
        let mut slot = pool.checkout("m/prod").await.unwrap();
        let out = execute(&mut slot, &fake, &params("fake://db"), &create(), &[PASSWORD], LIMIT).await.unwrap();
        assert_eq!(out, ExecOutcome { executed: 2, identity_absent: false });
        assert!(slot.is_live());
    }
    assert_eq!(target.dials.lock().unwrap().len(), 1, "one socket, three executions");
    assert_eq!(target.committed.lock().unwrap().len(), 3);

    // Another endpoint (the plugin's stored connection moved) is never served
    // by the old socket.
    let mut slot = pool.checkout("m/prod").await.unwrap();
    execute(&mut slot, &fake, &params("fake://elsewhere"), &create(), &[], LIMIT).await.unwrap();
    assert_eq!(target.dials.lock().unwrap().len(), 2);
    assert_eq!(target.dials.lock().unwrap()[1].0, "fake://elsewhere");
}

#[tokio::test]
async fn a_broken_pooled_connection_is_replaced() {
    let target = Arc::new(FakeTarget::default());
    let fake = FakeConnector(target.clone());
    let pool = pool(1, TlsPolicy::default());
    let mut slot = pool.checkout("m/prod").await.unwrap();
    execute(&mut slot, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap();
    drop(slot);
    target.fail_validation.store(true, Ordering::SeqCst);
    let mut slot = pool.checkout("m/prod").await.unwrap();
    // The replacement fails validation too, but it is fresh: validation only
    // applies to a reused connection.
    execute(&mut slot, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap();
    assert_eq!(target.dials.lock().unwrap().len(), 2, "the broken connection was not used");
}

#[tokio::test]
async fn rotate_and_config_writes_drain_live_connections() {
    let target = Arc::new(FakeTarget::default());
    let fake = FakeConnector(target.clone());
    let pool = pool(2, TlsPolicy::default());
    let mut slot = pool.checkout("m/prod").await.unwrap();
    execute(&mut slot, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap();
    drop(slot);
    assert_eq!(pool.idle_count("m/prod"), 1);

    pool.rotate("m/prod", 2).unwrap();
    let mut slot = pool.checkout("m/prod").await.unwrap();
    assert!(!slot.is_live(), "no socket opened under the old root survives a rotation");
    execute(&mut slot, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap();
    // A config write on another node: the next checkout here sees the new
    // generation in the record and drains, even the connection checked out now.
    pool.configure(
        "m/prod",
        TargetSettings { root_credential_version: 2, config_generation: 1, tls: TlsPolicy::default() },
    );
    drop(slot);
    assert_eq!(pool.idle_count("m/prod"), 0);
    assert_eq!(target.dials.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn max_size_bounds_host_connections() {
    let fake = FakeConnector(Arc::new(FakeTarget::default()));
    let pool = pool(2, TlsPolicy::default());
    let mut a = pool.checkout("m/prod").await.unwrap();
    let mut b = pool.checkout("m/prod").await.unwrap();
    execute(&mut a, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap();
    execute(&mut b, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap();
    assert!(matches!(pool.checkout("m/prod").await, Err(DynamicError::PoolExhausted(_))));
}

/// The connector dials with the pool's policy and nothing else: the plugin's
/// request has no TLS field, and a plaintext-only target is refused under the
/// default (verifying) policy.
#[tokio::test]
async fn the_tls_policy_is_the_pools_and_cannot_be_named_by_the_plugin() {
    for smuggled in [
        json!({ "sslmode": "disable" }),
        json!({ "tls": { "verify": false } }),
        json!({ "insecure_skip_tls_verify": true }),
    ] {
        let mut v = json!({ "kind": "fake", "url": "fake://db", "username": "root", "password": ROOT_SECRET });
        v.as_object_mut().unwrap().extend(smuggled.as_object().unwrap().clone());
        let e = ConnectorParams::parse(&v).expect_err("a TLS field from the plugin");
        assert!(!e.to_string().contains(ROOT_SECRET), "{e}");
    }

    let target = Arc::new(FakeTarget::default());
    target.plaintext_target.store(true, Ordering::SeqCst);
    let fake = FakeConnector(target.clone());
    let verifying = pool(1, TlsPolicy::default());
    let mut slot = verifying.checkout("m/prod").await.unwrap();
    let err = execute(&mut slot, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap_err();
    assert!(matches!(err, DynamicError::Connect { .. }), "{err}");
    assert!(!err.to_string().contains(ROOT_SECRET), "the root secret is redacted: {err}");
    assert!(target.dials.lock().unwrap().is_empty());

    let insecure = pool(1, TlsPolicy::insecure_skip_verify());
    let mut slot = insecure.checkout("m/prod").await.unwrap();
    execute(&mut slot, &fake, &params("fake://db"), &create(), &[], LIMIT).await.unwrap();
    assert!(!target.dials.lock().unwrap()[0].3.verifies(), "only the operator's policy turns verification off");
}

#[tokio::test]
async fn errors_are_redacted_and_a_failed_connection_is_not_kept() {
    let target = Arc::new(FakeTarget::default());
    *target.fail_on.lock().unwrap() = Some("PASSWORD".into());
    let fake = FakeConnector(target.clone());
    let pool = pool(1, TlsPolicy::default());
    let mut slot = pool.checkout("m/prod").await.unwrap();
    let err = execute(&mut slot, &fake, &params("fake://db"), &create(), &[PASSWORD], LIMIT).await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("<redacted>") && !text.contains(PASSWORD), "{text}");
    assert!(!slot.is_live(), "a connection that failed mid-transaction is dropped");
}

/// Only the plan runs: the host's rendered statements, or the connector's own
/// defaults when the role named none; a revoke of a missing identity runs
/// nothing; an empty creation plan dials nothing.
#[tokio::test]
async fn only_host_rendered_statements_run() {
    let target = Arc::new(FakeTarget::default());
    let fake = FakeConnector(target.clone());
    let pool = pool(1, TlsPolicy::default());
    let run = |plan: ExecPlan| {
        let pool = &pool;
        let fake = &fake;
        async move {
            let mut slot = pool.checkout("m/prod").await.unwrap();
            execute(&mut slot, fake, &params("fake://db"), &plan, &[], LIMIT).await
        }
    };

    let empty = run(ExecPlan::Create { statements: vec![] }).await.unwrap_err();
    assert!(matches!(empty, DynamicError::Invalid { .. }), "{empty}");
    assert!(target.dials.lock().unwrap().is_empty(), "nothing dialled for a plan that cannot run");

    let renew =
        ExecPlan::Renew { statements: vec![], username: "v-1".into(), expiration: "2099-01-01T00:00:00Z".into() };
    run(renew).await.unwrap();
    let revoke_absent = ExecPlan::Revoke { statements: vec!["DROP \"v-1\"".into()], username: "v-1".into() };
    assert_eq!(run(revoke_absent).await.unwrap(), ExecOutcome { executed: 0, identity_absent: true });
    target.identities.lock().unwrap().insert("v-1".into());
    let revoke = ExecPlan::Revoke { statements: vec![], username: "v-1".into() };
    assert_eq!(run(revoke).await.unwrap(), ExecOutcome { executed: 1, identity_absent: false });
    let explicit = ExecPlan::Revoke { statements: vec!["DROP \"v-1\"".into()], username: "v-1".into() };
    run(explicit).await.unwrap();

    assert_eq!(
        *target.committed.lock().unwrap(),
        vec![
            vec!["DEFAULT EXTEND v-1 2099-01-01T00:00:00Z".to_string()],
            vec!["DEFAULT DROP v-1".to_string()],
            vec!["DROP \"v-1\"".to_string()],
        ]
    );
    // The request a plugin sends cannot carry statements of its own.
    let smuggled = json!({ "kind": "fake", "url": "u", "username": "r", "password": ROOT_SECRET, "statements": ["DROP DATABASE x"] });
    assert!(ConnectorParams::parse(&smuggled).is_err());
    // A connector of another kind is not used for these params.
    let mut slot = pool.checkout("m/prod").await.unwrap();
    let other =
        ConnectorParams::parse(&json!({ "kind": "other", "url": "u", "username": "r", "password": ROOT_SECRET }))
            .unwrap();
    assert!(execute(&mut slot, &fake, &other, &create(), &[], LIMIT).await.is_err());
}

#[test]
fn params_are_bounded_and_never_debug_the_secret() {
    let p = params("fake://db");
    assert!(!format!("{p:?}").contains(ROOT_SECRET));
    assert!(!format!("{:?}", create()).contains(PASSWORD));
    let long = json!({ "kind": "fake", "url": "x".repeat(4096), "username": "r", "password": "p" });
    assert!(ConnectorParams::parse(&long).is_err());
    let zero = json!({ "kind": "fake", "url": "u", "username": "r", "password": "p", "connect_timeout_secs": 0 });
    assert!(ConnectorParams::parse(&zero).is_err());
    let capped = json!({ "kind": "fake", "url": "u", "username": "r", "password": "p", "connect_timeout_secs": 600 });
    assert_eq!(ConnectorParams::parse(&capped).unwrap().connect_timeout(), Some(MAX_CONNECT_TIMEOUT));
    let wrong_type = json!({ "kind": "fake", "url": "u", "username": "r", "password": 12345678901u64 });
    let e = ConnectorParams::parse(&wrong_type).unwrap_err();
    assert!(!e.to_string().contains("12345678901"), "values are never echoed: {e}");
    assert_eq!(Connectors::default().with(Arc::new(FakeConnector(Arc::default()))).kinds(), ["fake"]);
}
