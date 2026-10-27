//! Host-side connectors: the host dials the target, keeps the connection in
//! its pool slot and runs on it only statements it rendered itself.
//!
//! A plugin presents its stored connection ([`ConnectorParams`]: where, as
//! whom, with which root secret) and the host does the rest under the pool's
//! TLS policy, which the plugin cannot name. What runs is an [`ExecPlan`], built
//! by the host for one call; the plugin cannot add a statement to it.

#[cfg(feature = "connector-postgres")]
pub mod postgres;
#[cfg(feature = "connector-postgres")]
pub mod tls;

use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    audit::redact,
    pool::{ConnectionFactory, PoolKey, TlsPolicy},
    DynamicError,
};

/// Dial timeout when the connection names none.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest dial a connection may ask for: inside the host's 30 s call budget.
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(25);
/// Longest one host execution (validate, dial, statements) may take.
pub const MAX_EXECUTE_TIME: Duration = Duration::from_secs(28);
/// Bounds on what a plugin may present, so a request cannot balloon.
const MAX_URL_LEN: usize = 2048;
const MAX_USERNAME_LEN: usize = 128;
const MAX_PASSWORD_LEN: usize = 1024;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The target a live connection was dialled to, as whom. Never the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub kind: String,
    pub url: String,
    pub username: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParams {
    kind: String,
    url: String,
    username: String,
    password: String,
    #[serde(default)]
    connect_timeout_secs: Option<u64>,
}

impl Drop for RawParams {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// A plugin's stored connection, presented for a host execution. There is
/// deliberately no TLS field: the policy is the operator's, from the pool.
pub struct ConnectorParams {
    endpoint: Endpoint,
    password: Zeroizing<String>,
    connect_timeout: Option<Duration>,
}

impl fmt::Debug for ConnectorParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectorParams")
            .field("endpoint", &self.endpoint)
            .field("password", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl ConnectorParams {
    /// Parse the `connector` object of a host-execution request. Unknown
    /// fields (an `sslmode`, a `tls` block, `statements`) are refused, and the
    /// error never quotes a value: it may be the root secret.
    pub fn parse(value: &Value) -> Result<Self, DynamicError> {
        let mut raw = RawParams::deserialize(value).map_err(|_| {
            DynamicError::invalid(
                "connector",
                "expected exactly kind, url, username, password and optionally connect_timeout_secs",
            )
        })?;
        let bounded = |field: &'static str, v: &str, max: usize| {
            if v.is_empty() || v.len() > max || v.contains('\0') {
                Err(DynamicError::invalid(field, format!("must be 1-{max} bytes without NUL")))
            } else {
                Ok(())
            }
        };
        crate::records::check_name("connector kind", &raw.kind)?;
        bounded("connector url", &raw.url, MAX_URL_LEN)?;
        bounded("connector username", &raw.username, MAX_USERNAME_LEN)?;
        bounded("connector password", &raw.password, MAX_PASSWORD_LEN)?;
        let connect_timeout = match raw.connect_timeout_secs {
            Some(0) => return Err(DynamicError::invalid("connect_timeout_secs", "must be positive")),
            Some(s) => Some(Duration::from_secs(s).min(MAX_CONNECT_TIMEOUT)),
            None => None,
        };
        Ok(Self {
            endpoint: Endpoint {
                kind: std::mem::take(&mut raw.kind),
                url: std::mem::take(&mut raw.url),
                username: std::mem::take(&mut raw.username),
            },
            password: Zeroizing::new(std::mem::take(&mut raw.password)),
            connect_timeout,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn kind(&self) -> &str {
        &self.endpoint.kind
    }

    /// The root secret, for the connector's handshake only.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// The dial timeout the connection asked for, already clamped.
    pub fn connect_timeout(&self) -> Option<Duration> {
        self.connect_timeout
    }
}

/// One open connection to a target.
pub trait ConnectorSession: Send {
    /// A cheap round trip proving the connection still works.
    fn validate(&mut self) -> BoxFuture<'_, Result<(), DynamicError>>;
    /// Run `statements` in one transaction: all or nothing.
    fn execute_in_transaction<'a>(&'a mut self, statements: &'a [&'a str]) -> BoxFuture<'a, Result<(), DynamicError>>;
    /// Whether the target identity `name` exists: a parameterised lookup of
    /// the connector's own, with no statement text from anyone.
    fn identity_exists<'a>(&'a mut self, name: &'a str) -> BoxFuture<'a, Result<bool, DynamicError>>;
}

/// One kind of target the host can dial (`postgres`, …).
pub trait Connector: Send + Sync {
    fn kind(&self) -> &'static str;
    /// Open a connection under exactly `tls`. Plaintext only when `tls` is the
    /// operator's `insecure_skip_tls_verify`; otherwise TLS is required and a
    /// target or URL asking for less is refused, never downgraded.
    fn connect<'a>(
        &'a self,
        params: &'a ConnectorParams,
        tls: &'a TlsPolicy,
    ) -> BoxFuture<'a, Result<Box<dyn ConnectorSession>, DynamicError>>;
    /// A label for the target `params` name, for the host log: never a
    /// credential (`postgres://db.internal:5432`).
    fn describe(&self, _params: &ConnectorParams) -> String {
        self.kind().to_string()
    }
    /// What revokes `username` when the role names no revocation statements.
    fn default_revocation(&self, username: &str) -> Result<Vec<String>, DynamicError>;
    /// What extends `username` to `expiration` when the role names no renew
    /// statements.
    fn default_renew(&self, username: &str, expiration: &str) -> Result<Vec<String>, DynamicError>;
}

/// The statements the host rendered for one call: the only ones a plugin can
/// have the host run. Built by the host's dynamic backend from the role's
/// templates (or the connector's own defaults); there is no variant carrying
/// plugin-supplied text, so a plugin cannot widen what runs.
pub enum ExecPlan {
    /// `dynamic.generate`: the creation statements (they hold the password).
    Create { statements: Vec<Zeroizing<String>> },
    /// `dynamic.renew`: the rendered renew statements, or the connector's
    /// default for `username` when the role has none.
    Renew { statements: Vec<String>, username: String, expiration: String },
    /// `dynamic.revoke`: the revocation statements rendered at generation, or
    /// the connector's default. Nothing runs when `username` is already gone.
    Revoke { statements: Vec<String>, username: String },
}

impl fmt::Debug for ExecPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, count) = match self {
            Self::Create { statements } => ("create", statements.len()),
            Self::Renew { statements, .. } => ("renew", statements.len()),
            Self::Revoke { statements, .. } => ("revoke", statements.len()),
        };
        write!(f, "ExecPlan::{kind}({count} statements)")
    }
}

impl ExecPlan {
    /// The statements to run on `connector`'s target.
    pub fn statements(&self, connector: &dyn Connector) -> Result<Vec<Zeroizing<String>>, DynamicError> {
        let owned = |list: &[String]| list.iter().map(|s| Zeroizing::new(s.clone())).collect();
        match self {
            Self::Create { statements } if statements.is_empty() => {
                Err(DynamicError::invalid("statements", "the role has no creation statements"))
            }
            Self::Create { statements } => Ok(statements.clone()),
            Self::Renew { statements, username, expiration } if statements.is_empty() => {
                Ok(owned(&connector.default_renew(username, expiration)?))
            }
            Self::Revoke { statements, username } if statements.is_empty() => {
                Ok(owned(&connector.default_revocation(username)?))
            }
            Self::Renew { statements, .. } | Self::Revoke { statements, .. } => Ok(owned(statements)),
        }
    }
}

/// What one host execution did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecOutcome {
    pub executed: usize,
    /// A revoke found its identity already gone and ran nothing.
    pub identity_absent: bool,
}

struct Live {
    endpoint: Endpoint,
    session: Box<dyn ConnectorSession>,
}

/// One pool slot: counted against the target's `max_size`, carrying the TLS
/// policy of the epoch it was opened in and, once the host dialled, the live
/// connection. A plugin that dials itself only ever holds the slot.
pub struct Slot {
    pub id: u64,
    pub tls: TlsPolicy,
    live: Option<Live>,
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot")
            .field("id", &self.id)
            .field("tls", &self.tls)
            .field("live", &self.live.is_some())
            .finish()
    }
}

impl Slot {
    pub fn is_live(&self) -> bool {
        self.live.is_some()
    }
}

/// Mints slots for the host pool. Validation is per use: a live connection
/// is checked right before the host runs anything on it (see [`execute`]).
#[derive(Default)]
pub struct SlotFactory {
    next: AtomicU64,
}

impl ConnectionFactory for SlotFactory {
    type Conn = Slot;

    async fn connect(&self, _key: &PoolKey, tls: &TlsPolicy) -> Result<Slot, DynamicError> {
        Ok(Slot { id: self.next.fetch_add(1, Ordering::SeqCst) + 1, tls: tls.clone(), live: None })
    }

    async fn validate(&self, _slot: &mut Slot) -> Result<(), DynamicError> {
        Ok(())
    }
}

/// The connectors a host offers, by kind.
#[derive(Clone, Default)]
pub struct Connectors {
    by_kind: BTreeMap<&'static str, Arc<dyn Connector>>,
}

impl Connectors {
    /// The connectors compiled into this build.
    pub fn builtin() -> Self {
        #[allow(unused_mut)]
        let mut out = Self::default();
        #[cfg(feature = "connector-postgres")]
        {
            out = out.with(Arc::new(postgres::PostgresConnector::default()));
        }
        out
    }

    pub fn with(mut self, connector: Arc<dyn Connector>) -> Self {
        self.by_kind.insert(connector.kind(), connector);
        self
    }

    pub fn get(&self, kind: &str) -> Option<Arc<dyn Connector>> {
        self.by_kind.get(kind).cloned()
    }

    pub fn kinds(&self) -> Vec<&'static str> {
        self.by_kind.keys().copied().collect()
    }
}

/// `e` with `secrets` (and the connection's root secret) replaced.
fn redacted(e: DynamicError, secrets: &[&str]) -> DynamicError {
    let r = |s: &str| redact(s, secrets);
    match e {
        DynamicError::Connect { connection, reason } => DynamicError::Connect { connection, reason: r(&reason) },
        DynamicError::Execute(reason) => DynamicError::Execute(r(&reason)),
        DynamicError::Invalid { field, reason } => DynamicError::Invalid { field, reason: r(&reason) },
        other => other,
    }
}

async fn run(
    session: &mut dyn ConnectorSession,
    plan: &ExecPlan,
    statements: &[Zeroizing<String>],
) -> Result<ExecOutcome, DynamicError> {
    if let ExecPlan::Revoke { username, .. } = plan {
        // A revoke of an identity already gone succeeds: the lease manager
        // retries failed revokes and the target may have been cleaned by hand.
        if !session.identity_exists(username).await? {
            return Ok(ExecOutcome { executed: 0, identity_absent: true });
        }
    }
    let refs: Vec<&str> = statements.iter().map(|s| s.as_str()).collect();
    session.execute_in_transaction(&refs).await?;
    Ok(ExecOutcome { executed: refs.len(), identity_absent: false })
}

async fn dial(connector: &dyn Connector, params: &ConnectorParams, tls: &TlsPolicy) -> Result<Live, DynamicError> {
    log::info!(
        "host connector dialling {} as `{}` (TLS {})",
        connector.describe(params),
        params.endpoint().username,
        if tls.verifies() { "verified" } else { "NOT verified" }
    );
    if !tls.verifies() {
        log::warn!(
            "host connector `{}` dialling a target with TLS certificate verification disabled \
             (insecure_skip_tls_verify); development only",
            connector.kind()
        );
    }
    // The connector applies the dial timeout itself; this bounds a connector
    // that does not.
    let limit = params.connect_timeout().unwrap_or(DEFAULT_CONNECT_TIMEOUT) + Duration::from_secs(2);
    let session = tokio::time::timeout(limit, connector.connect(params, tls))
        .await
        .map_err(|_| DynamicError::Execute(format!("connecting timed out after {}s", limit.as_secs())))??;
    Ok(Live { endpoint: params.endpoint().clone(), session })
}

/// Run `plan` on `slot`'s live connection, dialling one under the slot's TLS
/// policy when it has none (or one to another endpoint, or one that fails
/// validation). Errors are redacted of `secrets` and the root secret. The live
/// connection is taken out of the slot while in use and put back only after
/// a success, so a failed or cancelled execution never returns a connection
/// in an unknown transaction state to the pool.
pub async fn execute(
    slot: &mut Slot,
    connector: &dyn Connector,
    params: &ConnectorParams,
    plan: &ExecPlan,
    secrets: &[&str],
    limit: Duration,
) -> Result<ExecOutcome, DynamicError> {
    let mut needles: Vec<&str> = secrets.to_vec();
    needles.push(params.password());
    let fail = |e: DynamicError| redacted(e, &needles);
    if params.kind() != connector.kind() {
        return Err(DynamicError::invalid("connector kind", "does not match the connector"));
    }
    // Rendered before anything is dialled: a plan that cannot run opens nothing.
    let statements = plan.statements(connector).map_err(fail)?;
    let work = async {
        let reusable = slot.live.take().filter(|l| &l.endpoint == params.endpoint());
        let mut live = match reusable {
            Some(mut live) => match live.session.validate().await {
                Ok(()) => live,
                Err(e) => {
                    log::debug!(
                        "pooled {} connection failed validation and was replaced: {}",
                        connector.kind(),
                        fail(e)
                    );
                    dial(connector, params, &slot.tls).await?
                }
            },
            None => dial(connector, params, &slot.tls).await?,
        };
        let outcome = run(live.session.as_mut(), plan, &statements).await?;
        Ok::<_, DynamicError>((live, outcome))
    };
    match tokio::time::timeout(limit, work).await {
        Ok(Ok((live, outcome))) => {
            slot.live = Some(live);
            Ok(outcome)
        }
        Ok(Err(e)) => Err(fail(e)),
        Err(_) => Err(DynamicError::Execute(format!("host execution timed out after {}s", limit.as_secs()))),
    }
}

#[cfg(test)]
mod tests;
