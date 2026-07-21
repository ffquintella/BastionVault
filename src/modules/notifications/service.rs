//! The notification service — the orchestrator that ties targeting,
//! storage, the in-app inbox, and plugin channel delivery together.
//!
//! Reachable from anywhere with an `Arc<Core>` via
//! `core.module_manager.get_module::<NotificationsModule>("notifications")
//! .service()`. The logical backend handlers call it for the HTTP
//! surface; the plugin runtime host imports (`bv.notify_*`) call the
//! plugin-scoped helpers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::Utc;
use serde_json::{json, Value};

use crate::{bv_error_string, core::Core, errors::RvError, utils::generate_uuid};

use super::channel;
use super::contacts;
use super::store::NotificationStore;
use super::types::{
    ChannelInfo, InboxEntry, Notification, NotificationConfig, Recipient, SendOutcome,
    IN_APP_CHANNEL_ID,
};

/// Per-plugin rolling send-rate window.
struct RateWindow {
    started: Instant,
    count: u32,
}

pub struct NotificationService {
    core: Arc<Core>,
    store: Arc<NotificationStore>,
    plugin_rate: Mutex<HashMap<String, RateWindow>>,
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

impl NotificationService {
    pub fn new(core: Arc<Core>, store: Arc<NotificationStore>) -> Arc<Self> {
        Arc::new(Self {
            core,
            store,
            plugin_rate: Mutex::new(HashMap::new()),
        })
    }

    // ---- sending ------------------------------------------------------------

    /// Persist and deliver a notification. `notif.source` is expected to
    /// already be set by the caller (`"system"`, `"admin:<entity>"`, or
    /// `"plugin:<name>"`). Assigns id/created_at/namespace, resolves the
    /// target, writes the canonical message + per-user inboxes (in-app),
    /// then fans out to any requested external channels.
    pub async fn send(
        &self,
        mut notif: Notification,
        ns_path: &str,
    ) -> Result<SendOutcome, RvError> {
        if notif.title.trim().is_empty() {
            return Err(bv_error_string!("notification title is required"));
        }
        notif.id = generate_uuid();
        notif.created_at = now_iso();
        notif.namespace = ns_path.to_string();

        let entity_ids = contacts::resolve_target_entities(&self.core, &notif.target, ns_path).await?;
        notif.recipient_count = entity_ids.len() as u64;

        // Canonical record first, so an inbox pointer can never dangle.
        self.store.put_message(ns_path, &notif).await?;

        // In-app delivery: one pointer per recipient.
        let cfg = self.store.get_config(ns_path).await.unwrap_or_default();
        for eid in &entity_ids {
            let entry = InboxEntry {
                notif_id: notif.id.clone(),
                delivered_at: notif.created_at.clone(),
                read_at: String::new(),
            };
            if self.store.put_inbox(ns_path, eid, &entry).await.is_ok() {
                let _ = self
                    .store
                    .prune_inbox(ns_path, eid, cfg.inbox_cap as usize)
                    .await;
            }
        }

        // External channels (anything beyond the reserved in-app id).
        let mut channel_results = Vec::new();
        let external: Vec<String> = notif
            .channels
            .iter()
            .filter(|c| c.as_str() != IN_APP_CHANNEL_ID && !c.trim().is_empty())
            .cloned()
            .collect();
        if !external.is_empty() {
            let recipients: Vec<Recipient> =
                contacts::resolve_recipients(&self.core, &entity_ids, ns_path)
                    .await
                    .unwrap_or_default();
            for ch in external {
                let res = channel::deliver_to_channel(&self.core, &ch, &notif, &recipients).await;
                if let Some(err) = &res.error {
                    log::warn!(
                        "notification {} channel `{}` delivery error: {}",
                        notif.id,
                        res.channel,
                        err
                    );
                }
                channel_results.push(res);
            }
        }

        Ok(SendOutcome {
            id: notif.id,
            recipient_count: notif.recipient_count,
            channel_results,
        })
    }

    /// Plugin-originated send. Enforces the per-plugin rate limit and
    /// forces `source = "plugin:<name>"` so a plugin can never spoof a
    /// system/admin origin.
    pub async fn send_from_plugin(
        &self,
        plugin_name: &str,
        mut notif: Notification,
        ns_path: &str,
    ) -> Result<SendOutcome, RvError> {
        let limit = self
            .store
            .get_config(ns_path)
            .await
            .unwrap_or_default()
            .plugin_rate_per_min;
        self.check_plugin_rate(plugin_name, limit)?;
        notif.source = format!("plugin:{plugin_name}");
        self.send(notif, ns_path).await
    }

    fn check_plugin_rate(&self, plugin_name: &str, limit: u32) -> Result<(), RvError> {
        if limit == 0 {
            return Ok(());
        }
        let mut map = self
            .plugin_rate
            .lock()
            .map_err(|_| bv_error_string!("notification rate limiter poisoned"))?;
        let now = Instant::now();
        let window = map.entry(plugin_name.to_string()).or_insert(RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(window.started) >= Duration::from_secs(60) {
            window.started = now;
            window.count = 0;
        }
        if window.count >= limit {
            return Err(bv_error_string!(format!(
                "plugin `{plugin_name}` exceeded the notification send rate limit ({limit}/min)"
            )));
        }
        window.count += 1;
        Ok(())
    }

    // ---- inbox reads --------------------------------------------------------

    /// The caller's inbox as GUI-ready JSON: each notification merged
    /// with the caller's read state. `recipient_count` is stripped (it is
    /// an admin-only field).
    pub async fn inbox(
        &self,
        ns_path: &str,
        entity_id: &str,
        include_read: bool,
    ) -> Result<Vec<Value>, RvError> {
        let entries = self.store.list_inbox_entries(ns_path, entity_id).await?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            if !include_read && e.is_read() {
                continue;
            }
            let Some(msg) = self.store.get_message(ns_path, &e.notif_id).await? else {
                continue;
            };
            let mut v = serde_json::to_value(&msg)?;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("read".into(), json!(e.is_read()));
                obj.insert("read_at".into(), json!(e.read_at));
                obj.insert("delivered_at".into(), json!(e.delivered_at));
                obj.remove("recipient_count");
            }
            out.push(v);
        }
        out.sort_by(|a, b| {
            let da = a.get("delivered_at").and_then(|x| x.as_str()).unwrap_or("");
            let db = b.get("delivered_at").and_then(|x| x.as_str()).unwrap_or("");
            db.cmp(da)
        });
        Ok(out)
    }

    pub async fn unread_count(&self, ns_path: &str, entity_id: &str) -> Result<u64, RvError> {
        let entries = self.store.list_inbox_entries(ns_path, entity_id).await?;
        Ok(entries.iter().filter(|e| !e.is_read()).count() as u64)
    }

    pub async fn mark_read(
        &self,
        ns_path: &str,
        entity_id: &str,
        id: &str,
    ) -> Result<(), RvError> {
        if let Some(mut e) = self.store.get_inbox_entry(ns_path, entity_id, id).await? {
            if e.read_at.is_empty() {
                e.read_at = now_iso();
                self.store.put_inbox(ns_path, entity_id, &e).await?;
            }
        }
        Ok(())
    }

    pub async fn mark_all_read(&self, ns_path: &str, entity_id: &str) -> Result<u64, RvError> {
        let entries = self.store.list_inbox_entries(ns_path, entity_id).await?;
        let mut n = 0u64;
        for mut e in entries {
            if e.read_at.is_empty() {
                e.read_at = now_iso();
                if self.store.put_inbox(ns_path, entity_id, &e).await.is_ok() {
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    pub async fn dismiss(&self, ns_path: &str, entity_id: &str, id: &str) -> Result<(), RvError> {
        self.store.delete_inbox_entry(ns_path, entity_id, id).await
    }

    // ---- channels + admin ---------------------------------------------------

    pub async fn list_channels(&self) -> Result<Vec<ChannelInfo>, RvError> {
        channel::list_channels(&self.core).await
    }

    pub async fn test_channel(
        &self,
        channel_id: &str,
        to_email: &str,
    ) -> Result<super::types::ChannelDeliveryResult, RvError> {
        if to_email.trim().is_empty() {
            return Err(bv_error_string!("a destination address is required for a test"));
        }
        Ok(channel::test_channel(&self.core, channel_id, to_email, &now_iso()).await)
    }

    /// Every notification sent in the namespace (admin audit view).
    pub async fn list_sent(&self, ns_path: &str) -> Result<Vec<Notification>, RvError> {
        self.store.list_messages(ns_path).await
    }

    pub async fn get_config(&self, ns_path: &str) -> Result<NotificationConfig, RvError> {
        self.store.get_config(ns_path).await
    }

    pub async fn put_config(
        &self,
        ns_path: &str,
        cfg: &NotificationConfig,
    ) -> Result<(), RvError> {
        self.store.put_config(ns_path, cfg).await
    }

    // ---- plugin-scoped reads (bv.notify_list / bv.notify_get) ---------------

    /// Notifications authored by `plugin_name` (source = `plugin:<name>`).
    /// A plugin can only ever see what it itself raised — never another
    /// user's inbox.
    pub async fn list_authored_by_plugin(
        &self,
        plugin_name: &str,
        ns_path: &str,
    ) -> Result<Vec<Notification>, RvError> {
        let src = format!("plugin:{plugin_name}");
        Ok(self
            .store
            .list_messages(ns_path)
            .await?
            .into_iter()
            .filter(|n| n.source == src)
            .collect())
    }

    pub async fn get_authored_by_plugin(
        &self,
        plugin_name: &str,
        ns_path: &str,
        id: &str,
    ) -> Result<Option<Notification>, RvError> {
        let src = format!("plugin:{plugin_name}");
        Ok(self
            .store
            .get_message(ns_path, id)
            .await?
            .filter(|n| n.source == src))
    }
}
