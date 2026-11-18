//! Forgetting deleted principals' entity aliases (T522).
//!
//! A login names its entity by `(mount, name)` in the namespace it logs in to,
//! so one principal has an alias in root and in every namespace it entered. A
//! deleted principal is forgotten in all of them, or a principal re-created
//! under its name would log in there as the old entity, with its ownership and
//! shares. The entity, owner and share records stay for an operator.

use crate::errors::RvError;

use super::IdentityModule;

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
        if forgotten.entity_ids.is_empty() {
            return Ok(forgotten.failed);
        }

        // An entity no alias names can never be logged into again (a recreated
        // principal gets a new one), so its entity-scoped plugin data, such as
        // personal credentials, is orphaned secret material. Reachability is
        // read back from storage, so an alias a failed removal left keeps its
        // entity's data; if it cannot be read, nothing is purged.
        let reachable = match store.still_aliased(&forgotten.entity_ids).await {
            Ok(reachable) => reachable,
            Err(e) => {
                log::error!(
                    "not purging the plugin data of {} entities whose aliases were forgotten: \
                     the remaining aliases could not be read: {e}",
                    forgotten.entity_ids.len()
                );
                return Ok(forgotten.failed);
            }
        };
        let Some(host) = crate::kernel_api::VaultCtx::plugin_host(self.core.as_ref()) else {
            return Ok(forgotten.failed);
        };
        for id in forgotten.entity_ids.iter().filter(|id| !reachable.contains(*id)) {
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
