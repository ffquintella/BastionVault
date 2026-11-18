//! One username, one userpass mount (T500).
//!
//! A userpass login names its entity `("userpass/", username, namespace)`
//! whatever mount it came through, so two mounts holding one username would be
//! one entity, sharing its ownership and shares. Creating such a name is
//! refused; duplicates made before that refusal are reported, never undone.

use std::collections::BTreeMap;

use crate::{bv_error_response_status, errors::RvError, kernel_api::VaultCtx, storage::Storage};

/// The mount type this backend registers under.
const USERPASS: &str = "userpass";

/// A username more than one userpass mount holds, and those mounts' paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateUsername {
    pub username: String,
    /// `auth/<path>/` of each holder, sorted.
    pub mounts: Vec<String>,
}

fn registry_unavailable() -> RvError {
    RvError::ErrString("cannot list the userpass mounts: the auth mount registry is not available".to_string())
}

/// The `auth/<path>/` of every userpass mount holding `username`, sorted.
///
/// Callers ask only while their own mount does not hold the name, so every
/// path returned is another mount's. An unreadable mount is an error, never
/// read as "not held".
#[maybe_async::maybe_async]
pub async fn mounts_holding(core: &dyn VaultCtx, username: &str) -> Result<Vec<String>, RvError> {
    let registry = core.auth_mounts().ok_or_else(registry_unavailable)?;
    let key = format!("user/{}", username.to_lowercase());
    let mut holders = Vec::new();
    for mount in registry.auth_mounts_of_type(USERPASS)? {
        if mount.view.get(&key).await?.is_some() {
            holders.push(format!("auth/{}", mount.path));
        }
    }
    holders.sort();
    Ok(holders)
}

/// Refuse to create `username` when another userpass mount holds it (409).
///
/// Call only while this mount does not hold the name. The caller is told that
/// another userpass mount holds it, not which one: only the server log names it.
#[maybe_async::maybe_async]
pub async fn refuse_if_held_elsewhere(core: &dyn VaultCtx, username: &str) -> Result<(), RvError> {
    let holders = mounts_holding(core, username).await?;
    if holders.is_empty() {
        return Ok(());
    }
    log::warn!(
        target: "security",
        "userpass: refused to create user '{username}': already held by {}",
        holders.join(", ")
    );
    Err(bv_error_response_status!(
        409,
        "user '{}' already exists in another userpass mount; a username may be held by only one userpass mount",
        username
    ))
}

/// Every username more than one userpass mount holds, sorted by name.
///
/// Only lower-case keys count: login reads `user/<lower-case>`, so a record
/// under any other key never logs in and has no entity. A mount whose users
/// cannot be listed is logged and left out.
#[maybe_async::maybe_async]
pub async fn find_duplicate_usernames(core: &dyn VaultCtx) -> Result<Vec<DuplicateUsername>, RvError> {
    let registry = core.auth_mounts().ok_or_else(registry_unavailable)?;
    let mounts = registry.auth_mounts_of_type(USERPASS)?;
    if mounts.len() < 2 {
        return Ok(Vec::new());
    }
    let mut holders: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for mount in mounts {
        let path = format!("auth/{}", mount.path);
        let names = match mount.view.list("user/").await {
            Ok(names) => names,
            Err(e) => {
                log::warn!(target: "security", "userpass duplicate-username scan: cannot list the users of {path}: {e}");
                continue;
            }
        };
        for name in names {
            if name.is_empty() || name.contains('/') || name != name.to_lowercase() {
                continue;
            }
            holders.entry(name).or_default().push(path.clone());
        }
    }
    Ok(holders
        .into_iter()
        .filter(|(_, mounts)| mounts.len() > 1)
        .map(|(username, mut mounts)| {
            mounts.sort();
            DuplicateUsername { username, mounts }
        })
        .collect())
}

/// Log each username more than one userpass mount holds, then their count.
///
/// Runs once per unseal. It only reports: nothing is changed, and a failure is
/// logged, never returned, so it cannot hold up or fail an unseal.
#[maybe_async::maybe_async]
pub async fn report_duplicate_usernames(core: &dyn VaultCtx) {
    let duplicates = match find_duplicate_usernames(core).await {
        Ok(duplicates) => duplicates,
        Err(e) => {
            log::warn!(target: "security", "userpass duplicate-username scan failed: {e}");
            return;
        }
    };
    for duplicate in &duplicates {
        log::warn!(
            target: "security",
            "userpass username '{}' is held by {} userpass mounts ({}): they log in as one identity entity \
             and share its ownership and shares; delete it from all but one mount (T500)",
            duplicate.username,
            duplicate.mounts.len(),
            duplicate.mounts.join(", ")
        );
    }
    if !duplicates.is_empty() {
        log::warn!(
            target: "security",
            "{} userpass usernames are held by more than one userpass mount; nothing was changed (T500)",
            duplicates.len()
        );
    }
}
