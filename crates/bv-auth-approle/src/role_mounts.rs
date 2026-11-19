//! AppRole roles across mounts (T522, T533).
//!
//! An AppRole login names its entity `("approle/", role, namespace)` whatever
//! mount it came through, so two mounts holding one role name are one entity.
//! Creating such a name is refused (T533); duplicates made before that are
//! reported at unseal, never undone, and keep their aliases on delete (T522).

use std::collections::BTreeMap;

use crate::{
    bv_error_response_status,
    errors::RvError,
    kernel_api::{auth::AuthMountPrincipals, VaultCtx},
    storage::{barrier_view::BarrierView, Storage},
};

/// The mount type this backend registers under.
pub(crate) const APPROLE: &str = "approle";

/// The roles of an AppRole mount, as entity aliases (`approle/<role>`), so
/// disabling the mount forgets them in every namespace (T522).
pub struct AppRolePrincipals;

#[maybe_async::maybe_async]
impl AuthMountPrincipals for AppRolePrincipals {
    fn alias_mount(&self) -> String {
        "approle/".to_string()
    }

    async fn principals(&self, view: &BarrierView) -> Result<Vec<String>, RvError> {
        let names = view.list("role/").await?;
        Ok(names.into_iter().filter(|n| !n.is_empty() && !n.contains('/')).collect())
    }

    async fn holds(&self, view: &BarrierView, name: &str) -> Result<bool, RvError> {
        Ok(view.get(&format!("role/{}", name.to_lowercase())).await?.is_some())
    }
}

/// What a role delete does with the name's entity aliases (T522).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasRule {
    /// No other AppRole mount holds the name: forget it in every namespace.
    Forget,
    /// Other mounts hold it (`auth/<path>/`): their role signs in as these entities.
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

/// The `auth/<path>/` of every AppRole mount holding role `name`, sorted. An
/// unreadable mount is an error, never read as "not held".
#[maybe_async::maybe_async]
pub async fn mounts_holding(core: &dyn VaultCtx, name: &str) -> Result<Vec<String>, RvError> {
    let registry = core
        .auth_mounts()
        .ok_or_else(|| RvError::ErrString("cannot list the approle mounts: no auth mount registry".to_string()))?;
    let mut holders = Vec::new();
    for mount in registry.auth_mounts_of_type(APPROLE)? {
        if AppRolePrincipals.holds(&mount.view, name).await? {
            holders.push(format!("auth/{}", mount.path));
        }
    }
    holders.sort();
    Ok(holders)
}

/// Refuse to create role `name` when another AppRole mount holds it (409).
///
/// Call only while this mount does not hold the name, under
/// [`crate::role_lock::lock_role_records`] held until the role is written.
/// The caller is told another mount holds it, never which one.
#[maybe_async::maybe_async]
pub async fn refuse_if_held_elsewhere(core: &dyn VaultCtx, name: &str) -> Result<(), RvError> {
    let name = name.to_lowercase();
    let holders = mounts_holding(core, &name).await?;
    if holders.is_empty() {
        return Ok(());
    }
    log::warn!(target: "security", "approle: refused to create role '{name}': already held by {}", holders.join(", "));
    Err(bv_error_response_status!(
        409,
        "role '{}' already exists in another approle mount; a role name may be held by only one approle mount",
        name
    ))
}

/// A role name more than one AppRole mount holds, and those mounts' paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateRoleName {
    pub name: String,
    /// `auth/<path>/` of each holder, sorted.
    pub mounts: Vec<String>,
}

/// Every role name more than one AppRole mount holds, sorted by name. A mount
/// whose roles cannot be listed is logged and left out.
#[maybe_async::maybe_async]
pub async fn find_duplicate_role_names(core: &dyn VaultCtx) -> Result<Vec<DuplicateRoleName>, RvError> {
    let registry = core
        .auth_mounts()
        .ok_or_else(|| RvError::ErrString("cannot list the approle mounts: no auth mount registry".to_string()))?;
    let mounts = registry.auth_mounts_of_type(APPROLE)?;
    if mounts.len() < 2 {
        return Ok(Vec::new());
    }
    let mut holders: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for mount in mounts {
        let path = format!("auth/{}", mount.path);
        match AppRolePrincipals.principals(&mount.view).await {
            Ok(names) => names.into_iter().for_each(|name| holders.entry(name).or_default().push(path.clone())),
            Err(e) => {
                log::warn!(target: "security", "approle duplicate-role scan: cannot list the roles of {path}: {e}")
            }
        }
    }
    Ok(holders
        .into_iter()
        .filter(|(_, mounts)| mounts.len() > 1)
        .map(|(name, mut mounts)| {
            mounts.sort();
            DuplicateRoleName { name, mounts }
        })
        .collect())
}

/// Log each role name more than one AppRole mount holds, then their count.
/// Runs once per unseal and only reports: a failure is logged (`None`), never
/// returned, so it cannot fail an unseal.
#[maybe_async::maybe_async]
pub async fn report_duplicate_role_names(core: &dyn VaultCtx) -> Option<Vec<DuplicateRoleName>> {
    let duplicates = match find_duplicate_role_names(core).await {
        Ok(duplicates) => duplicates,
        Err(e) => {
            log::warn!(target: "security", "approle duplicate-role scan failed: {e}");
            return None;
        }
    };
    for duplicate in &duplicates {
        log::warn!(
            target: "security",
            "approle role '{}' is held by {} approle mounts ({}): they log in as one identity entity and share \
             its ownership and shares; delete it from all but one mount, then review that entity's ownership \
             and shares (T533)",
            duplicate.name,
            duplicate.mounts.len(),
            duplicate.mounts.join(", ")
        );
    }
    if !duplicates.is_empty() {
        log::warn!(
            target: "security",
            "{} approle role names are held by more than one approle mount; nothing was changed (T533)",
            duplicates.len()
        );
    }
    Some(duplicates)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An error while reading the other mounts keeps the aliases (T522): a
    /// live same-named role must never lose its entities on a guess.
    #[test]
    fn an_unreadable_mount_keeps_the_aliases() {
        assert_eq!(alias_rule(Ok(vec![])), AliasRule::Forget);
        let held = vec!["auth/ar2/".to_string()];
        assert_eq!(alias_rule(Ok(held.clone())), AliasRule::Keep(held));
        let unreadable = alias_rule(Err(RvError::ErrString("injected".into())));
        assert!(matches!(unreadable, AliasRule::Undecided(ref e) if e.contains("injected")), "{unreadable:?}");
    }
}
