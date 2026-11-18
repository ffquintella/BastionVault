//! AppRole roles across mounts, for forgetting a deleted role's entity
//! aliases (T522).
//!
//! An AppRole login names its entity `("approle/", role, namespace)` whatever
//! mount it came through, so a role name another AppRole mount still holds
//! keeps its aliases: that mount's role logs in as the same entities.

use crate::{
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
