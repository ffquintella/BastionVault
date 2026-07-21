//! Notification storage.
//!
//! Everything lives behind the system barrier view, namespace-scoped the
//! same way the identity stores are (root uses the legacy keyspace; a
//! non-root namespace gets its own).
//!
//! Layout (root namespace):
//!   sys/notifications/messages/<id>              -> Notification (canonical)
//!   sys/notifications/inbox/<entity_id>/<id>     -> InboxEntry (per-user pointer)
//!   sys/notifications/config                     -> NotificationConfig
//!
//! Non-root namespace:
//!   notifications-ns/<b64url(ns)>/messages/<id>
//!   notifications-ns/<b64url(ns)>/inbox/<entity_id>/<id>
//!   notifications-ns/<b64url(ns)>/config
//!
//! The canonical message is written once; each recipient gets a small
//! pointer record carrying their own read state. Listing a user's inbox
//! walks their pointer keyspace and joins each against the message.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::{
    bv_error_string,
    core::Core,
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

use super::types::{InboxEntry, Notification, NotificationConfig};

const MESSAGES_SUB_PATH: &str = "notifications/messages/";
const INBOX_SUB_PATH: &str = "notifications/inbox/";
const CONFIG_KEY: &str = "notifications/config";
const NS_SUB_PATH: &str = "notifications-ns/";

pub struct NotificationStore {
    /// Retained so per-namespace + per-entity sub-views can be derived.
    system_view: Arc<BarrierView>,
    messages_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl NotificationStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };
        let messages_view = Arc::new(system_view.new_sub_view(MESSAGES_SUB_PATH));
        Ok(Arc::new(Self { system_view, messages_view }))
    }

    fn messages_view_for(&self, ns_path: &str) -> Arc<BarrierView> {
        if ns_path.is_empty() {
            return self.messages_view.clone();
        }
        let b64 = URL_SAFE_NO_PAD.encode(ns_path.as_bytes());
        Arc::new(
            self.system_view
                .new_sub_view(&format!("{NS_SUB_PATH}{b64}/messages/")),
        )
    }

    fn inbox_view_for(&self, ns_path: &str, entity_id: &str) -> Arc<BarrierView> {
        if ns_path.is_empty() {
            return Arc::new(
                self.system_view
                    .new_sub_view(&format!("{INBOX_SUB_PATH}{entity_id}/")),
            );
        }
        let b64 = URL_SAFE_NO_PAD.encode(ns_path.as_bytes());
        Arc::new(
            self.system_view
                .new_sub_view(&format!("{NS_SUB_PATH}{b64}/inbox/{entity_id}/")),
        )
    }

    fn config_key(ns_path: &str) -> String {
        if ns_path.is_empty() {
            return CONFIG_KEY.to_string();
        }
        let b64 = URL_SAFE_NO_PAD.encode(ns_path.as_bytes());
        format!("{NS_SUB_PATH}{b64}/config")
    }

    fn sanitize_id(id: &str) -> Result<&str, RvError> {
        if id.is_empty() || id.contains('/') || id.contains("..") {
            return Err(bv_error_string!("invalid notification id"));
        }
        Ok(id)
    }

    fn sanitize_entity(id: &str) -> Result<&str, RvError> {
        if id.is_empty() || id.contains('/') || id.contains("..") {
            return Err(bv_error_string!("invalid entity id"));
        }
        Ok(id)
    }

    // ---- canonical messages -------------------------------------------------

    pub async fn put_message(&self, ns_path: &str, notif: &Notification) -> Result<(), RvError> {
        let id = Self::sanitize_id(&notif.id)?;
        let entry = StorageEntry::new(id, notif)?;
        self.messages_view_for(ns_path).put(&entry).await
    }

    pub async fn get_message(
        &self,
        ns_path: &str,
        id: &str,
    ) -> Result<Option<Notification>, RvError> {
        let id = Self::sanitize_id(id)?;
        match self.messages_view_for(ns_path).get(id).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    /// Every sent notification in the namespace, newest first. Backs the
    /// admin "sent" view; not exposed to non-admins.
    pub async fn list_messages(&self, ns_path: &str) -> Result<Vec<Notification>, RvError> {
        let view = self.messages_view_for(ns_path);
        let keys = view.get_keys().await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(e) = view.get(&k).await? {
                if let Ok(n) = serde_json::from_slice::<Notification>(&e.value) {
                    out.push(n);
                }
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    // ---- per-user inbox -----------------------------------------------------

    pub async fn put_inbox(
        &self,
        ns_path: &str,
        entity_id: &str,
        entry: &InboxEntry,
    ) -> Result<(), RvError> {
        let entity_id = Self::sanitize_entity(entity_id)?;
        let id = Self::sanitize_id(&entry.notif_id)?;
        let se = StorageEntry::new(id, entry)?;
        self.inbox_view_for(ns_path, entity_id).put(&se).await
    }

    pub async fn get_inbox_entry(
        &self,
        ns_path: &str,
        entity_id: &str,
        id: &str,
    ) -> Result<Option<InboxEntry>, RvError> {
        let entity_id = Self::sanitize_entity(entity_id)?;
        let id = Self::sanitize_id(id)?;
        match self.inbox_view_for(ns_path, entity_id).get(id).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn list_inbox_entries(
        &self,
        ns_path: &str,
        entity_id: &str,
    ) -> Result<Vec<InboxEntry>, RvError> {
        let entity_id = Self::sanitize_entity(entity_id)?;
        let view = self.inbox_view_for(ns_path, entity_id);
        let keys = view.get_keys().await?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(e) = view.get(&k).await? {
                if let Ok(entry) = serde_json::from_slice::<InboxEntry>(&e.value) {
                    out.push(entry);
                }
            }
        }
        Ok(out)
    }

    pub async fn delete_inbox_entry(
        &self,
        ns_path: &str,
        entity_id: &str,
        id: &str,
    ) -> Result<(), RvError> {
        let entity_id = Self::sanitize_entity(entity_id)?;
        let id = Self::sanitize_id(id)?;
        self.inbox_view_for(ns_path, entity_id).delete(id).await
    }

    /// Trim a user's inbox to `cap` entries, deleting the oldest *read*
    /// entries first (by `delivered_at`), then the oldest unread if still
    /// over cap. Keeps inboxes bounded without silently dropping unread
    /// mail unless the cap is genuinely exceeded.
    pub async fn prune_inbox(
        &self,
        ns_path: &str,
        entity_id: &str,
        cap: usize,
    ) -> Result<(), RvError> {
        let mut entries = self.list_inbox_entries(ns_path, entity_id).await?;
        if entries.len() <= cap {
            return Ok(());
        }
        // Oldest-first; read entries considered more disposable than unread.
        entries.sort_by(|a, b| {
            a.is_read()
                .cmp(&b.is_read())
                .reverse()
                .then(a.delivered_at.cmp(&b.delivered_at))
        });
        let to_remove = entries.len() - cap;
        for entry in entries.into_iter().take(to_remove) {
            let _ = self
                .delete_inbox_entry(ns_path, entity_id, &entry.notif_id)
                .await;
        }
        Ok(())
    }

    // ---- config -------------------------------------------------------------

    pub async fn get_config(&self, ns_path: &str) -> Result<NotificationConfig, RvError> {
        match self.system_view.get(&Self::config_key(ns_path)).await? {
            Some(e) => Ok(serde_json::from_slice(&e.value).unwrap_or_default()),
            None => Ok(NotificationConfig::default()),
        }
    }

    pub async fn put_config(
        &self,
        ns_path: &str,
        cfg: &NotificationConfig,
    ) -> Result<(), RvError> {
        let entry = StorageEntry::new(Self::config_key(ns_path).as_str(), cfg)?;
        self.system_view.put(&entry).await
    }
}
