//! Notifications module.
//!
//! A first-class in-app notification system plus the substrate that lets
//! plugins raise notifications and provide delivery channels
//! (email/SMS/Slack/…). See `features/notifications.md`.
//!
//! The module mounts a logical backend at `notifications/` (reached via
//! the forward-going `/v2/notifications/…` API), so every route rides the
//! standard ACL + audit + namespace pipeline and resolves the caller from
//! `req.auth`. A caller only ever reads *their own* inbox (server-scoped
//! by `entity_id`); composing a broadcast to a group / all users sits
//! behind the `create` ACL on `v2/notifications/send`.

use std::{any::Any, collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use derive_more::Deref;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::Module;
use crate::{
    bv_error_string,
    context::Context,
    core::Core,
    errors::RvError,
    logical::{Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response},
    modules::identity::caller_audit_actor,
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal,
};

pub mod channel;
pub mod contacts;
pub mod service;
pub mod store;
pub mod types;

pub use service::NotificationService;
pub use store::NotificationStore;
pub use types::{
    ChannelInfo, InboxEntry, Notification, NotificationConfig, NotificationTarget, Recipient,
    Severity,
};

static NOTIFICATIONS_BACKEND_HELP: &str = r#"
The notifications backend delivers in-app notifications to users, user
groups, or everyone, and fans them out to plugin-provided channels
(email, Slack, SMS, …). Users read their own inbox; administrators
compose and broadcast, manage channels, and tune retention.
"#;

#[derive(Default)]
pub struct NotificationsModule {
    pub name: String,
    pub core: Arc<Core>,
    pub service: ArcSwap<Option<Arc<NotificationService>>>,
}

pub struct NotificationsBackendInner {
    pub core: Arc<Core>,
}

#[derive(Deref)]
pub struct NotificationsBackend {
    #[deref]
    pub inner: Arc<NotificationsBackendInner>,
}

impl NotificationsBackend {
    pub fn new(core: Arc<Core>) -> Self {
        Self { inner: Arc::new(NotificationsBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let h_send = self.inner.clone();
        let h_inbox_read = self.inner.clone();
        let h_inbox_list = self.inner.clone();
        let h_unread = self.inner.clone();
        let h_read_all = self.inner.clone();
        let h_read = self.inner.clone();
        let h_dismiss = self.inner.clone();
        let h_channels_read = self.inner.clone();
        let h_channels_list = self.inner.clone();
        let h_channel_test = self.inner.clone();
        let h_sent_read = self.inner.clone();
        let h_sent_list = self.inner.clone();
        let h_config_read = self.inner.clone();
        let h_config_write = self.inner.clone();

        new_logical_backend!({
            paths: [
                {
                    pattern: r"send$",
                    fields: {
                        "title": { field_type: FieldType::Str, required: true, description: "Notification title." },
                        "body": { field_type: FieldType::Str, default: "", description: "Notification body." },
                        "severity": { field_type: FieldType::Str, default: "info", description: "info | success | warning | critical." },
                        "channels": { field_type: FieldType::CommaStringSlice, required: false, description: "Channel ids to deliver through beyond the in-app inbox." },
                        "action_url": { field_type: FieldType::Str, required: false, description: "Optional deep link opened when the notification is clicked." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_send.handle_send}
                    ],
                    help: "Compose and send a notification. Body carries `target` (a {kind,...} object) and optional `metadata`."
                },
                {
                    pattern: r"inbox/unread-count$",
                    operations: [
                        {op: Operation::Read, handler: h_unread.handle_unread_count}
                    ],
                    help: "Number of unread notifications in the caller's inbox."
                },
                {
                    pattern: r"inbox/read-all$",
                    operations: [
                        {op: Operation::Write, handler: h_read_all.handle_mark_all_read}
                    ],
                    help: "Mark every notification in the caller's inbox read."
                },
                {
                    pattern: r"inbox/(?P<id>[^/]+)/read$",
                    fields: {
                        "id": { field_type: FieldType::Str, required: true, description: "Notification id." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_read.handle_mark_read}
                    ],
                    help: "Mark one notification read."
                },
                {
                    pattern: r"inbox/(?P<id>[^/]+)$",
                    fields: {
                        "id": { field_type: FieldType::Str, required: true, description: "Notification id." }
                    },
                    operations: [
                        {op: Operation::Delete, handler: h_dismiss.handle_dismiss}
                    ],
                    help: "Dismiss (remove) one notification from the caller's inbox."
                },
                {
                    pattern: r"inbox/?$",
                    operations: [
                        {op: Operation::Read, handler: h_inbox_read.handle_inbox_list},
                        {op: Operation::List, handler: h_inbox_list.handle_inbox_list}
                    ],
                    help: "The caller's inbox (read + unread)."
                },
                {
                    pattern: r"channels/(?P<channel>[^/]+)/test$",
                    fields: {
                        "channel": { field_type: FieldType::Str, required: true, description: "Channel id (`<plugin>:<channel>`)." },
                        "to": { field_type: FieldType::Str, required: true, description: "Destination address for the test." }
                    },
                    operations: [
                        {op: Operation::Write, handler: h_channel_test.handle_channel_test}
                    ],
                    help: "Send a test notification through a channel (admin)."
                },
                {
                    pattern: r"channels/?$",
                    operations: [
                        {op: Operation::Read, handler: h_channels_read.handle_channels_list},
                        {op: Operation::List, handler: h_channels_list.handle_channels_list}
                    ],
                    help: "List available delivery channels."
                },
                {
                    pattern: r"sent/?$",
                    operations: [
                        {op: Operation::Read, handler: h_sent_read.handle_sent_list},
                        {op: Operation::List, handler: h_sent_list.handle_sent_list}
                    ],
                    help: "Every notification sent in the namespace (admin audit view)."
                },
                {
                    pattern: r"config$",
                    fields: {
                        "inbox_cap": { field_type: FieldType::Int, required: false, description: "Max notifications retained per user inbox." },
                        "plugin_rate_per_min": { field_type: FieldType::Int, required: false, description: "Per-plugin send rate limit (per rolling minute)." }
                    },
                    operations: [
                        {op: Operation::Read, handler: h_config_read.handle_config_read},
                        {op: Operation::Write, handler: h_config_write.handle_config_write}
                    ],
                    help: "Read or update notification settings (admin)."
                }
            ],
            help: NOTIFICATIONS_BACKEND_HELP,
        })
    }
}

/// Body payload for `POST v2/notifications/send`. `target` and
/// `metadata` are read from the raw body since `target` is a nested
/// object the typed field layer doesn't model.
#[derive(Debug, Deserialize)]
struct SendPayload {
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    severity: Option<String>,
    target: NotificationTarget,
    #[serde(default)]
    channels: Vec<String>,
    #[serde(default)]
    action_url: Option<String>,
    #[serde(default)]
    metadata: Map<String, Value>,
}

fn ns_from_req(req: &Request) -> String {
    crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref())
}

#[maybe_async::maybe_async]
impl NotificationsBackendInner {
    fn resolve_service(&self) -> Result<Arc<NotificationService>, RvError> {
        self.core
            .module_manager
            .get_module::<NotificationsModule>("notifications")
            .and_then(|m| m.service())
            .ok_or_else(|| bv_error_string!("notification service unavailable"))
    }

    /// The caller's stable inbox key. Empty for tokens with no entity
    /// (e.g. root) — those have no inbox, which is the correct outcome.
    fn caller_entity(req: &Request) -> String {
        caller_audit_actor(req)
    }

    pub async fn handle_send(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);

        let body = req.body.clone().unwrap_or_default();
        let payload: SendPayload = serde_json::from_value(Value::Object(body))
            .map_err(|e| bv_error_string!(format!("invalid notification payload: {e}")))?;

        let caller = Self::caller_entity(req);
        let source = if caller.is_empty() {
            "system".to_string()
        } else {
            format!("user:{caller}")
        };

        let notif = Notification {
            id: String::new(),
            title: payload.title,
            body: payload.body,
            severity: payload
                .severity
                .as_deref()
                .map(Severity::parse)
                .unwrap_or_default(),
            source,
            target: payload.target,
            channels: payload.channels,
            action_url: payload.action_url,
            created_at: String::new(),
            namespace: String::new(),
            metadata: payload.metadata,
            recipient_count: 0,
        };

        let outcome = service.send(notif, &ns).await?;
        let data = serde_json::to_value(&outcome)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_inbox_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let entity = Self::caller_entity(req);
        let items = service.inbox(&ns, &entity, true).await?;
        let mut data = Map::new();
        data.insert("notifications".into(), Value::Array(items));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_unread_count(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let entity = Self::caller_entity(req);
        let count = service.unread_count(&ns, &entity).await?;
        let mut data = Map::new();
        data.insert("unread".into(), Value::from(count));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_mark_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let entity = Self::caller_entity(req);
        let id = req.get_data("id")?.as_str().unwrap_or("").to_string();
        service.mark_read(&ns, &entity, &id).await?;
        Ok(None)
    }

    pub async fn handle_mark_all_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let entity = Self::caller_entity(req);
        let n = service.mark_all_read(&ns, &entity).await?;
        let mut data = Map::new();
        data.insert("marked".into(), Value::from(n));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_dismiss(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let entity = Self::caller_entity(req);
        let id = req.get_data("id")?.as_str().unwrap_or("").to_string();
        service.dismiss(&ns, &entity, &id).await?;
        Ok(None)
    }

    pub async fn handle_channels_list(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let channels = service.list_channels().await?;
        let mut data = Map::new();
        data.insert("channels".into(), serde_json::to_value(channels).unwrap_or(Value::Null));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_channel_test(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let channel = req.get_data("channel")?.as_str().unwrap_or("").to_string();
        let to = req.get_data("to")?.as_str().unwrap_or("").to_string();
        let result = service.test_channel(&channel, &to).await?;
        let data = serde_json::to_value(&result)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_sent_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let sent = service.list_sent(&ns).await?;
        let mut data = Map::new();
        data.insert("notifications".into(), serde_json::to_value(sent).unwrap_or(Value::Null));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_config_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let cfg = service.get_config(&ns).await?;
        let data = serde_json::to_value(&cfg)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_config_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let service = self.resolve_service()?;
        let ns = ns_from_req(req);
        let mut cfg = service.get_config(&ns).await?;
        if let Ok(v) = req.get_data("inbox_cap") {
            if let Some(n) = v.as_u64() {
                cfg.inbox_cap = n as u32;
            }
        }
        if let Ok(v) = req.get_data("plugin_rate_per_min") {
            if let Some(n) = v.as_u64() {
                cfg.plugin_rate_per_min = n as u32;
            }
        }
        service.put_config(&ns, &cfg).await?;
        Ok(None)
    }
}

impl NotificationsModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self {
            name: "notifications".to_string(),
            core,
            service: ArcSwap::new(Arc::new(None)),
        }
    }

    pub fn service(&self) -> Option<Arc<NotificationService>> {
        self.service.load().as_ref().clone()
    }
}

#[maybe_async::maybe_async]
impl Module for NotificationsModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn setup(&self, core: &Core) -> Result<(), RvError> {
        let backend_new_func = move |c: Arc<Core>| -> Result<Arc<dyn Backend>, RvError> {
            let mut b = NotificationsBackend::new(c).new_backend();
            b.init()?;
            Ok(Arc::new(b))
        };
        core.add_logical_backend("notifications", Arc::new(backend_new_func))
    }

    async fn init(&self, core: &Core) -> Result<(), RvError> {
        let store = NotificationStore::new(core).await?;
        let service = NotificationService::new(self.core.clone(), store);
        self.service.store(Arc::new(Some(service)));
        Ok(())
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        self.service.store(Arc::new(None));
        core.delete_logical_backend("notifications")
    }
}

#[cfg(test)]
mod notifications_tests {
    use serde_json::{json, Map};

    use crate::test_utils::{
        new_unseal_test_bastion_vault, test_mount_auth_api, test_read_api, test_write_api,
    };

    fn obj(v: serde_json::Value) -> Option<Map<String, serde_json::Value>> {
        v.as_object().cloned()
    }

    /// End-to-end: send a notification to a user, read it from that
    /// user's inbox, mark it read, and confirm the admin + channel views.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn notification_send_and_inbox_roundtrip() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("notif_roundtrip").await;

        // A userpass user (pre-provisions the identity entity + alias).
        test_mount_auth_api(&core, &root, "userpass", "pass").await;
        test_write_api(
            &core,
            &root,
            "auth/pass/users/alice",
            true,
            obj(json!({ "password": "123qwe!@#", "ttl": 0 })),
        )
        .await
        .unwrap();

        // Log in as alice → token carrying her entity_id.
        let login = test_write_api(
            &core,
            "",
            "auth/pass/login/alice",
            true,
            obj(json!({ "password": "123qwe!@#" })),
        )
        .await
        .unwrap()
        .unwrap();
        let alice_token = login.auth.unwrap().client_token;

        // Root broadcasts to alice by login name.
        let sent = test_write_api(
            &core,
            &root,
            "notifications/send",
            true,
            obj(json!({
                "title": "Maintenance",
                "body": "tonight at 22:00",
                "severity": "warning",
                "target": { "kind": "username", "name": "alice" },
                "channels": []
            })),
        )
        .await
        .unwrap()
        .unwrap();
        let sent_data = sent.data.unwrap();
        assert_eq!(
            sent_data.get("recipient_count").and_then(|v| v.as_u64()),
            Some(1)
        );
        let notif_id = sent_data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Alice sees one unread notification.
        let inbox = test_read_api(&core, &alice_token, "notifications/inbox", true)
            .await
            .unwrap()
            .unwrap();
        let items = inbox
            .data
            .unwrap()
            .get("notifications")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("read").and_then(|v| v.as_bool()), Some(false));

        let unread = test_read_api(
            &core,
            &alice_token,
            "notifications/inbox/unread-count",
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            unread.data.unwrap().get("unread").and_then(|v| v.as_u64()),
            Some(1)
        );

        // Mark read → unread drops to zero.
        test_write_api(
            &core,
            &alice_token,
            &format!("notifications/inbox/{notif_id}/read"),
            true,
            Some(Map::new()),
        )
        .await
        .unwrap();
        let unread2 = test_read_api(
            &core,
            &alice_token,
            "notifications/inbox/unread-count",
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            unread2.data.unwrap().get("unread").and_then(|v| v.as_u64()),
            Some(0)
        );

        // The built-in in-app channel is always present.
        let channels = test_read_api(&core, &root, "notifications/channels", true)
            .await
            .unwrap()
            .unwrap();
        let chans = channels
            .data
            .unwrap()
            .get("channels")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert!(chans
            .iter()
            .any(|c| c.get("id").and_then(|v| v.as_str()) == Some("in-app")));

        // Admin "sent" view lists the broadcast.
        let sent_list = test_read_api(&core, &root, "notifications/sent", true)
            .await
            .unwrap()
            .unwrap();
        let sent_arr = sent_list
            .data
            .unwrap()
            .get("notifications")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(sent_arr.len(), 1);
    }

    /// Targeting `all_users` reaches a provisioned user; dismiss removes
    /// the inbox entry.
    #[maybe_async::test(
        feature = "sync_handler",
        async(all(not(feature = "sync_handler")), tokio::test)
    )]
    async fn notification_all_users_and_dismiss() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("notif_all_users").await;
        test_mount_auth_api(&core, &root, "userpass", "pass").await;
        test_write_api(
            &core,
            &root,
            "auth/pass/users/bob",
            true,
            obj(json!({ "password": "123qwe!@#", "ttl": 0 })),
        )
        .await
        .unwrap();
        let login = test_write_api(
            &core,
            "",
            "auth/pass/login/bob",
            true,
            obj(json!({ "password": "123qwe!@#" })),
        )
        .await
        .unwrap()
        .unwrap();
        let bob_token = login.auth.unwrap().client_token;

        let sent = test_write_api(
            &core,
            &root,
            "notifications/send",
            true,
            obj(json!({
                "title": "Everyone",
                "body": "hello all",
                "severity": "info",
                "target": { "kind": "all_users" },
                "channels": []
            })),
        )
        .await
        .unwrap()
        .unwrap();
        let id = sent
            .data
            .unwrap()
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Bob dismisses it (DELETE) → inbox empties.
        dismiss(&core, &bob_token, &id).await.unwrap();

        let inbox = test_read_api(&core, &bob_token, "notifications/inbox", true)
            .await
            .unwrap()
            .unwrap();
        let items = inbox
            .data
            .unwrap()
            .get("notifications")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(items.len(), 0);
    }

    /// Helper: issue a DELETE against the inbox dismiss route (the
    /// generic test helpers only cover read/write/list).
    async fn dismiss(
        core: &crate::core::Core,
        token: &str,
        id: &str,
    ) -> Result<Option<crate::logical::Response>, crate::errors::RvError> {
        let mut req = crate::logical::Request::new(&format!("notifications/inbox/{id}"));
        req.operation = crate::logical::Operation::Delete;
        req.client_token = token.to_string();
        core.handle_request(&mut req).await
    }
}
