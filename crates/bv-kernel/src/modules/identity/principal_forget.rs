//! Forgetting deleted principals' entity aliases (T522).
//!
//! A login names its entity by `(mount, name)` in the namespace it logs in to,
//! so one principal has an alias in root and in every namespace it entered. A
//! deleted principal is forgotten in all of them, or a principal re-created
//! under its name would log in there as the old entity, with its ownership and
//! shares. The entity, owner and share records stay for an operator.

use crate::errors::RvError;

use super::{entity_store::EntityStore, IdentityModule};

#[maybe_async::maybe_async]
impl IdentityModule {
    /// Forget each principal's `(mount, name)` alias in every namespace, then
    /// purge the plugin data of each entity that no alias anywhere names any
    /// more. Returns the names some alias of which could not be removed.
    pub async fn forget_principals(&self, mount: &str, names: &[String]) -> Result<Vec<String>, RvError> {
        let Some(store) = self.entity_store() else {
            return Ok(Vec::new());
        };
        let forgotten = store.forget_aliases(mount, names).await?;
        let orphans = orphaned_entities(&store, &forgotten.entity_ids).await;
        if orphans.is_empty() {
            return Ok(forgotten.failed);
        }
        let Some(host) = crate::kernel_api::VaultCtx::plugin_host(self.core.as_ref()) else {
            return Ok(forgotten.failed);
        };
        for id in &orphans {
            // A failure is audited by the host, which records a pending purge
            // retried by the next automatic purge and by every
            // `DELETE v2/sys/plugins/<name>/entity-data/<id>`.
            if let Err(e) = host.purge_entity_data(id).await {
                log::error!("purging plugin data of orphaned entity {id} failed: {e}");
            }
        }
        Ok(forgotten.failed)
    }
}

/// Those of `ids` no alias in any namespace names: they can never be logged
/// into again, so their entity-scoped plugin data (personal credentials) is
/// orphaned secret material to purge. Read back from storage, so an alias a
/// failed removal left keeps its entity; none when the aliases cannot be read.
#[maybe_async::maybe_async]
pub(crate) async fn orphaned_entities(store: &EntityStore, ids: &[String]) -> Vec<String> {
    if ids.is_empty() {
        return Vec::new();
    }
    match store.still_aliased(ids).await {
        Ok(reachable) => ids.iter().filter(|id| !reachable.contains(*id)).cloned().collect(),
        Err(e) => {
            log::error!(
                "not purging the plugin data of {} entities whose aliases were forgotten: \
                 the remaining aliases could not be read: {e}",
                ids.len()
            );
            Vec::new()
        }
    }
}

/// The purge decision (T522): only what no alias anywhere names, and nothing
/// when the alias indexes cannot be read.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::identity::fault_storage;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn nothing_is_purged_when_the_aliases_cannot_be_read() {
        let (faulty, view) = fault_storage::view("sys/").await;
        let store = EntityStore::over(view);
        let gone = store.get_or_create_entity_ns("userpass/", "carol", "a").await.unwrap().id;
        let kept = store.get_or_create_entity_ns("userpass/", "dave", "b").await.unwrap().id;
        store.forget_aliases("userpass/", &["carol".to_string()]).await.unwrap();

        let both = [gone.clone(), kept.clone()];
        assert_eq!(orphaned_entities(&store, &both).await, vec![gone.clone()], "control: only carol's is orphaned");
        faulty.fail_under("sys/identity-ns/");
        assert!(orphaned_entities(&store, &both).await.is_empty(), "an unreadable index purges nothing");
    }
}
