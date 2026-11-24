//! SSO user directory (T555): one passwordless record per principal that
//! completed an OIDC or SAML login. Not a credential — nothing reads it while
//! deciding a login. Design and storage layout: features/sso-user-directory.md.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::kernel_api::VaultCtx;
use crate::{
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

/// System-view sub-path: `sys/sso-users/<hex(mount)>-<hex(username)>`.
pub const SSO_USERS_SUB_PATH: &str = "sso-users/";

/// Version this build writes. A newer record is read but never overwritten.
pub const SSO_USER_RECORD_VERSION: u32 = 1;

/// Longest principal name stored, in bytes. Refused, never truncated.
pub const MAX_SSO_USERNAME_LEN: usize = 512;

/// Longest e-mail address stored (RFC 5321's path limit).
pub const MAX_SSO_EMAIL_LEN: usize = 320;

/// What the callbacks write to the login audit for a rejected attempt.
const UNKNOWN_PRINCIPAL: &str = "(unknown)";

/// Where `email` came from. A login never overwrites an admin-set address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailSource {
    #[default]
    None,
    Idp,
    Admin,
}

/// One SSO principal. Fields added later must be `#[serde(default)]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SsoUserRecord {
    #[serde(default)]
    pub version: u32,
    /// The name the login was decided for; the namespace-assignment key.
    pub username: String,
    /// The `mount_path` stamped on the token: `oidc/` or `saml/`.
    pub mount: String,
    #[serde(default)]
    pub auth_method: String,
    /// Role of the most recent login.
    #[serde(default)]
    pub role: String,
    /// OIDC `sub` or SAML NameID of the most recent login.
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub email_source: EmailSource,
    /// RFC 3339.
    #[serde(default)]
    pub first_login: String,
    /// RFC 3339.
    #[serde(default)]
    pub last_login: String,
    #[serde(default)]
    pub login_count: u64,
}

/// What a successful SSO login contributes. Built only by [`SsoLogin::new`].
#[derive(Debug, Clone, PartialEq)]
pub struct SsoLogin {
    mount: String,
    auth_method: String,
    username: String,
    role: String,
    subject: String,
    email: Option<String>,
}

impl SsoLogin {
    /// `None` for an unusable `username` or `mount`; a bad e-mail is dropped.
    pub fn new(
        mount: &str,
        auth_method: &str,
        username: &str,
        role: &str,
        subject: &str,
        email: Option<&str>,
    ) -> Option<Self> {
        let mount = normalize_mount(mount)?;
        let username = validate_username(username)?;
        Some(Self {
            mount,
            auth_method: auth_method.to_string(),
            username,
            role: role.to_string(),
            subject: subject.to_string(),
            email: email.and_then(normalize_email),
        })
    }

    pub fn mount(&self) -> &str {
        &self.mount
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
}

/// `oidc` or `oidc/` -> `oidc/`. `None` for an empty or multi-segment mount.
pub fn normalize_mount(mount: &str) -> Option<String> {
    let bare = mount.trim().trim_end_matches('/');
    if bare.is_empty() || bare.len() > 128 {
        return None;
    }
    if !bare.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return None;
    }
    Some(format!("{bare}/"))
}

/// The name as stored, or `None`: empty, the rejected-attempt placeholder,
/// padded, too long or with control characters. Never trimmed into another
/// name, since the login keyed its assignment and entity on the exact string.
pub fn validate_username(username: &str) -> Option<String> {
    if username.is_empty() || username.trim() != username || username == UNKNOWN_PRINCIPAL {
        return None;
    }
    if username.len() > MAX_SSO_USERNAME_LEN || username.chars().any(char::is_control) {
        return None;
    }
    Some(username.to_string())
}

/// Trimmed address, or `None` when it does not look like one.
pub fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim();
    if email.is_empty() || email.len() > MAX_SSO_EMAIL_LEN || email.chars().any(|c| c.is_control() || c == ' ') {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    Some(email.to_string())
}

fn hex(s: &str) -> String {
    use std::fmt::Write as _;
    s.bytes().fold(String::with_capacity(s.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Flat storage key; hex never contains `-`, so the separator is unforgeable.
fn record_key(mount: &str, username: &str) -> String {
    format!("{}-{}", hex(mount), hex(username))
}

fn newer_version_error(version: u32) -> RvError {
    RvError::ErrString(format!(
        "sso user record is version {version} (this build writes {SSO_USER_RECORD_VERSION}); not overwriting it"
    ))
}

pub struct SsoUserStore {
    storage: Arc<dyn Storage>,
}

#[maybe_async::maybe_async]
impl SsoUserStore {
    pub fn from_core(core: &dyn VaultCtx) -> Result<Self, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };
        Ok(Self::from_system_view(&system_view))
    }

    pub fn from_system_view(system_view: &Arc<BarrierView>) -> Self {
        Self::from_storage(Arc::new(system_view.new_sub_view(SSO_USERS_SUB_PATH)))
    }

    /// Over any storage already rooted at the directory (tests).
    pub fn from_storage(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    /// One record; an unusable `mount` or `username` reads as absent.
    pub async fn get(&self, mount: &str, username: &str) -> Result<Option<SsoUserRecord>, RvError> {
        let (Some(mount), Some(username)) = (normalize_mount(mount), validate_username(username)) else {
            return Ok(None);
        };
        self.get_normalized(&mount, &username).await
    }

    async fn get_normalized(&self, mount: &str, username: &str) -> Result<Option<SsoUserRecord>, RvError> {
        match self.storage.get(&record_key(mount, username)).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(&entry.value)?)),
            None => Ok(None),
        }
    }

    /// Every record sorted by `(mount, username)`, in one bulk read. An
    /// undecodable record is skipped and logged by its hex key (no name).
    pub async fn list(&self) -> Result<Vec<SsoUserRecord>, RvError> {
        let mut out: Vec<SsoUserRecord> = Vec::new();
        for entry in self.storage.scan("", None).await? {
            match serde_json::from_slice::<SsoUserRecord>(&entry.value) {
                Ok(record) => out.push(record),
                Err(e) => log::error!(target: "sso", "sso user directory: undecodable record {}: {e}", entry.key),
            }
        }
        out.sort_by(|a, b| (a.mount.as_str(), a.username.as_str()).cmp(&(b.mount.as_str(), b.username.as_str())));
        Ok(out)
    }

    /// Upsert after a successful login: keeps `first_login` and an admin-set
    /// e-mail, refreshes the rest, increments `login_count`. No storage lock,
    /// so two concurrent logins of one principal may undercount by one.
    pub async fn record_login(&self, login: &SsoLogin) -> Result<SsoUserRecord, RvError> {
        let now = Utc::now().to_rfc3339();
        let mut record = match self.get_normalized(&login.mount, &login.username).await? {
            Some(r) if r.version > SSO_USER_RECORD_VERSION => return Err(newer_version_error(r.version)),
            Some(r) => {
                if !r.subject.is_empty() && !login.subject.is_empty() && r.subject != login.subject {
                    // A re-keyed IdP user or a non-unique `user_claim`.
                    log::warn!(
                        target: "security",
                        "sso user directory: a principal on {} logged in with a different subject than \
                         recorded; check that the role's user claim is unique",
                        login.mount
                    );
                }
                r
            }
            None => SsoUserRecord { first_login: now.clone(), ..Default::default() },
        };
        record.version = SSO_USER_RECORD_VERSION;
        record.username = login.username.clone();
        record.mount = login.mount.clone();
        record.auth_method = login.auth_method.clone();
        record.role = login.role.clone();
        record.subject = login.subject.clone();
        record.last_login = now;
        record.login_count = record.login_count.saturating_add(1);
        if let Some(email) = &login.email {
            if record.email_source != EmailSource::Admin {
                record.email = email.clone();
                record.email_source = EmailSource::Idp;
            }
        }
        self.put(&record).await?;
        Ok(record)
    }

    /// [`record_login`](Self::record_login) that never fails the login: an
    /// error is logged at ERROR (mount and error only) and returned as `false`.
    pub async fn record_login_best_effort(&self, login: &SsoLogin) -> bool {
        match self.record_login(login).await {
            Ok(_) => true,
            Err(e) => {
                log::error!(
                    target: "sso",
                    "sso user directory: could not record a successful {} login; the login continues \
                     but the user is missing from the Users page until a later login is recorded: {e}",
                    login.mount
                );
                false
            }
        }
    }

    /// Admin edit of the e-mail; `None` when no such record exists. An empty
    /// `email` clears it and lets the next login supply one again.
    pub async fn set_email(&self, mount: &str, username: &str, email: &str) -> Result<Option<SsoUserRecord>, RvError> {
        let (Some(mount), Some(username)) = (normalize_mount(mount), validate_username(username)) else {
            return Ok(None);
        };
        let Some(mut record) = self.get_normalized(&mount, &username).await? else {
            return Ok(None);
        };
        if record.version > SSO_USER_RECORD_VERSION {
            return Err(newer_version_error(record.version));
        }
        let trimmed = email.trim();
        if trimmed.is_empty() {
            record.email = String::new();
            record.email_source = EmailSource::None;
        } else {
            let Some(email) = normalize_email(trimmed) else {
                return Err(RvError::ErrString("email: not a valid e-mail address".into()));
            };
            record.email = email;
            record.email_source = EmailSource::Admin;
        }
        record.version = SSO_USER_RECORD_VERSION;
        self.put(&record).await?;
        Ok(Some(record))
    }

    /// Remove a record; `true` when one existed. Leaves the namespace
    /// assignment (removing it would *widen* where the principal may log in)
    /// and the identity entity (shares stay attached).
    pub async fn delete(&self, mount: &str, username: &str) -> Result<bool, RvError> {
        let (Some(mount), Some(username)) = (normalize_mount(mount), validate_username(username)) else {
            return Ok(false);
        };
        let key = record_key(&mount, &username);
        if self.storage.get(&key).await?.is_none() {
            return Ok(false);
        }
        self.storage.delete(&key).await?;
        Ok(true)
    }

    async fn put(&self, record: &SsoUserRecord) -> Result<(), RvError> {
        let value = serde_json::to_vec(record)?;
        self.storage.put(&StorageEntry { key: record_key(&record.mount, &record.username), value }).await
    }
}

/// Record a successful SSO login. Never fails the login (errors are logged
/// at ERROR), so the directory cannot become a second authentication gate.
#[maybe_async::maybe_async]
pub async fn record_sso_login(core: &dyn VaultCtx, login: &SsoLogin) {
    match SsoUserStore::from_core(core) {
        Ok(store) => {
            store.record_login_best_effort(login).await;
        }
        Err(e) => {
            log::error!(target: "sso", "sso user directory: store unavailable, {} login not recorded: {e}", login.mount)
        }
    }
}

/// Resolve or create the SSO principal's identity entity, so the token carries
/// the `entity_id` that owner-scoped rules and shares key on. Never refuses
/// the login: an exhausted `max_entities` quota, an absent identity module or
/// a store error means no entity (token issued without `entity_id`), a WARN.
#[maybe_async::maybe_async]
pub async fn ensure_sso_entity(core: &dyn VaultCtx, mount: &str, username: &str, ns_path: &str) -> Option<String> {
    validate_username(username)?;
    let identity = core.identity()?;
    if let Ok(Some(id)) = identity.entity_id_for_alias(mount, username, ns_path).await {
        return Some(id);
    }
    if let Err(e) = crate::kernel_api::namespace::check_entity_create(core, mount, username, ns_path).await {
        log::warn!(target: "sso", "{mount} login: identity entity not created ({e}); token issued without entity_id");
        return None;
    }
    match identity.ensure_entity_id(mount, username, ns_path).await {
        Ok(id) => Some(id),
        Err(e) => {
            log::warn!(target: "sso", "{mount} login: identity entity unavailable ({e}); token issued without entity_id");
            None
        }
    }
}

#[cfg(all(test, not(feature = "sync_handler")))]
mod tests;
