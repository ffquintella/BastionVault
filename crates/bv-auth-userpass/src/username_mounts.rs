//! One username, one userpass mount (T500).
//!
//! A userpass login names its entity `("userpass/", username, namespace)`
//! whatever mount it came through, so two mounts holding one username would be
//! one entity, sharing its ownership and shares. Creating such a name is
//! refused; duplicates made before that refusal are reported, never undone.

use std::collections::BTreeMap;

use crate::{
    bv_error_response_status,
    errors::RvError,
    kernel_api::{auth::AuthMountPrincipals, VaultCtx},
    storage::{barrier_view::BarrierView, Storage},
};

/// The mount type this backend registers under.
pub(crate) const USERPASS: &str = "userpass";

/// The users of a userpass mount, as entity aliases (`userpass/<name>`), so
/// disabling the mount forgets them in every namespace (T522). Only lower-case
/// records count: login reads `user/<lower-case>`, so no other has an entity.
pub struct UserPassPrincipals;

#[maybe_async::maybe_async]
impl AuthMountPrincipals for UserPassPrincipals {
    fn alias_mount(&self) -> String {
        "userpass/".to_string()
    }

    async fn principals(&self, view: &BarrierView) -> Result<Vec<String>, RvError> {
        let names = view.list("user/").await?;
        Ok(names.into_iter().filter(|n| !n.is_empty() && !n.contains('/') && *n == n.to_lowercase()).collect())
    }

    async fn holds(&self, view: &BarrierView, name: &str) -> Result<bool, RvError> {
        Ok(view.get(&format!("user/{}", name.to_lowercase())).await?.is_some())
    }
}

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
    let mut holders = Vec::new();
    for mount in registry.auth_mounts_of_type(USERPASS)? {
        if UserPassPrincipals.holds(&mount.view, username).await? {
            holders.push(format!("auth/{}", mount.path));
        }
    }
    holders.sort();
    Ok(holders)
}

/// What a user delete does with the name's entity aliases (T500, T522).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasRule {
    /// No other userpass mount holds the name: forget it in every namespace.
    Forget,
    /// Other mounts hold it (`auth/<path>/`): their user signs in as these entities.
    Keep(Vec<String>),
    /// The other mounts could not be read: keep, and say so. A forget can be
    /// retried; the plugin-data purge that follows it cannot be undone.
    Undecided(String),
}

/// T500's keeping rule from [`mounts_holding`]'s answer.
pub fn alias_rule(holders: Result<Vec<String>, RvError>) -> AliasRule {
    match holders {
        Ok(holders) if holders.is_empty() => AliasRule::Forget,
        Ok(holders) => AliasRule::Keep(holders),
        Err(e) => AliasRule::Undecided(e.to_string()),
    }
}

/// Refuse to create `username` when another userpass mount holds it (409).
///
/// Call only while this mount does not hold the name, and under
/// [`crate::user_lock::lock_user_record`] for `username` held until the record
/// is written (T530): every mount takes the same lock for one name. The caller is told another mount holds it, never which one.
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
/// logged (`None`), never returned as an error, so it cannot fail an unseal.
#[maybe_async::maybe_async]
pub async fn report_duplicate_usernames(core: &dyn VaultCtx) -> Option<Vec<DuplicateUsername>> {
    let duplicates = match find_duplicate_usernames(core).await {
        Ok(duplicates) => duplicates,
        Err(e) => {
            log::warn!(target: "security", "userpass duplicate-username scan failed: {e}");
            return None;
        }
    };
    for duplicate in &duplicates {
        log::warn!(
            target: "security",
            "userpass username '{}' is held by {} userpass mounts ({}): they log in as one identity entity \
             and share its ownership and shares; delete it from all but one mount, then review that \
             entity's ownership and shares (T500)",
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
    Some(duplicates)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An error while reading the other mounts keeps the aliases (T522): a
    /// live duplicate must never lose its entities and plugin data on a guess.
    #[test]
    fn an_unreadable_mount_keeps_the_aliases() {
        assert_eq!(alias_rule(Ok(vec![])), AliasRule::Forget);
        let held = vec!["auth/corp/".to_string()];
        assert_eq!(alias_rule(Ok(held.clone())), AliasRule::Keep(held));
        let unreadable = alias_rule(Err(RvError::ErrString("injected".into())));
        assert!(matches!(unreadable, AliasRule::Undecided(ref e) if e.contains("injected")), "{unreadable:?}");
    }
}
