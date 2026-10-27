//! Test fixtures shared by the dynamic host's tests and the runtime tests:
//! an in-memory (optionally failing) `Storage`, and a fake host connector of
//! kind `fake` whose targets are looked up by URL, so tests in one process
//! never see each other's statements.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use bv_dynamic::{
    connector::{BoxFuture, Connector, ConnectorParams, ConnectorSession},
    pool::TlsPolicy,
    DynamicError,
};
use dashmap::DashMap;

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

/// A mount's storage as every node of a cluster sees it.
#[derive(Default)]
pub struct MemStorage {
    inner: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Every read and write fails, as an unreachable backend would.
    pub down: AtomicBool,
}

impl MemStorage {
    pub fn keys(&self) -> Vec<String> {
        self.inner.lock().unwrap().keys().cloned().collect()
    }

    fn check(&self) -> Result<(), RvError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(RvError::ErrResponseStatus(503, "storage unreachable".into()));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Storage for MemStorage {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        self.check()?;
        let g = self.inner.lock().unwrap();
        let mut out = BTreeSet::new();
        for k in g.keys() {
            if let Some(rest) = k.strip_prefix(prefix) {
                match rest.find('/') {
                    Some(at) => out.insert(format!("{}/", &rest[..at])),
                    None => out.insert(rest.to_string()),
                };
            }
        }
        Ok(out.into_iter().collect())
    }

    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        self.check()?;
        Ok(self.inner.lock().unwrap().get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
    }

    async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        self.check()?;
        self.inner.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        self.check()?;
        self.inner.lock().unwrap().remove(key);
        Ok(())
    }
}

/// One fake database behind the `fake` connector.
#[derive(Default)]
pub struct FakeTarget {
    /// (username, root secret, TLS policy) of every dial.
    pub dials: Mutex<Vec<(String, String, TlsPolicy)>>,
    /// Every committed transaction.
    pub committed: Mutex<Vec<Vec<String>>>,
    pub identities: Mutex<BTreeSet<String>>,
    /// A statement containing this fails, its text echoed in the error.
    pub fail_on: Mutex<Option<String>>,
    /// The root user's current secret; a dial with another one fails.
    pub root: Mutex<Option<String>>,
    /// Only this secret logs in, whatever the root's is (a new secret that
    /// does not work).
    pub only_login: Mutex<Option<String>>,
    /// After a rotation statement took effect, never answer (a call cut short
    /// by the runtime while the host still runs).
    pub hang_after_rotate: AtomicBool,
    /// Wait this long before running any statement.
    pub delay_ms: std::sync::atomic::AtomicU64,
}

fn targets() -> &'static DashMap<String, Arc<FakeTarget>> {
    static TARGETS: OnceLock<DashMap<String, Arc<FakeTarget>>> = OnceLock::new();
    TARGETS.get_or_init(DashMap::new)
}

/// The fake target at `url`, with the `fake` connector registered.
pub fn fake_target(url: &str) -> Arc<FakeTarget> {
    super::pool::register_connector(Arc::new(FakeConnector));
    targets().entry(url.to_string()).or_default().clone()
}

struct FakeConnector;

struct FakeSession(Arc<FakeTarget>);

impl ConnectorSession for FakeSession {
    fn validate(&mut self) -> BoxFuture<'_, Result<(), DynamicError>> {
        Box::pin(async { Ok(()) })
    }

    fn execute_in_transaction<'a>(&'a mut self, statements: &'a [&'a str]) -> BoxFuture<'a, Result<(), DynamicError>> {
        Box::pin(async move {
            let delay = self.0.delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            if let Some(bad) = self.0.fail_on.lock().unwrap().as_deref() {
                if let Some(s) = statements.iter().find(|s| s.contains(bad)) {
                    return Err(DynamicError::Execute(format!("syntax error in {s}")));
                }
            }
            {
                let mut ids = self.0.identities.lock().unwrap();
                for s in statements {
                    let name = s.split('"').nth(1).unwrap_or_default().to_string();
                    if s.starts_with("ROTATE") {
                        let secret = s.rsplit(' ').next().unwrap_or_default().to_string();
                        *self.0.root.lock().unwrap() = Some(secret);
                    } else if s.starts_with("CREATE") {
                        ids.insert(name);
                    } else if s.starts_with("DROP") {
                        ids.remove(&name);
                    }
                }
            }
            let rotated = statements.iter().any(|s| s.starts_with("ROTATE"));
            self.0.committed.lock().unwrap().push(statements.iter().map(|s| s.to_string()).collect());
            if rotated && self.0.hang_after_rotate.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
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
            let target = targets().get(&params.endpoint().url).map(|t| t.clone()).ok_or_else(|| {
                DynamicError::Connect { connection: params.endpoint().url.clone(), reason: "no such fake".into() }
            })?;
            let wrong = target.root.lock().unwrap().as_deref().is_some_and(|r| r != params.password());
            let refused = target.only_login.lock().unwrap().as_deref().is_some_and(|o| o != params.password());
            if wrong || refused {
                return Err(DynamicError::Connect {
                    connection: params.endpoint().url.clone(),
                    reason: format!("password authentication failed for {}", params.password()),
                });
            }
            target.dials.lock().unwrap().push((
                params.endpoint().username.clone(),
                params.password().into(),
                tls.clone(),
            ));
            Ok(Box::new(FakeSession(target)) as Box<dyn ConnectorSession>)
        })
    }

    fn default_revocation(&self, username: &str) -> Result<Vec<String>, DynamicError> {
        Ok(vec![format!("DROP \"{username}\" (default)")])
    }

    fn default_renew(&self, username: &str, expiration: &str) -> Result<Vec<String>, DynamicError> {
        Ok(vec![format!("EXTEND \"{username}\" TO {expiration} (default)")])
    }

    fn default_root_rotation(&self, username: &str, password: &str) -> Result<Vec<String>, DynamicError> {
        Ok(vec![format!("ROTATE \"{username}\" TO {password}")])
    }
}
