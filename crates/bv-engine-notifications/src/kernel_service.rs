//! `NotificationsModule` as the vault's [`NotificationSink`].
//!
//! The consumer is the plugin runtime's `bv.notify_*` host imports, which used
//! to reach `NotificationService` by naming `NotificationsModule` — putting a
//! Tier 3 engine in the plugin substrate's compile unit.
//!
//! The trait speaks JSON rather than `Notification`/`SendOutcome`. That is not
//! laziness: the plugin ABI is already a JSON boundary, the runtime was
//! transcoding a plugin's JSON into a `Notification` only to have the service
//! validate it again, and keeping the notification schema on one side of the
//! seam means it can change without touching the runtime. The service still
//! overwrites `source`, so a plugin cannot forge a system origin.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::{errors::RvError, kernel_api::engines::NotificationSink};

use super::{
    types::{Notification, Severity},
    NotificationsModule,
};

#[maybe_async::maybe_async]
impl NotificationSink for NotificationsModule {
    async fn send_from_plugin(
        &self,
        author: &str,
        notification: Value,
        ns_path: &str,
    ) -> Result<Value, RvError> {
        let service = self
            .service()
            .ok_or_else(|| crate::bv_error_string!("notification service unavailable"))?;
        // A malformed `severity` must not fail the send — the pre-trait code
        // ran it through `Severity::parse`, which defaults unknown input to
        // `info`. Normalise before decoding so that stays true.
        let mut notification = notification;
        if let Some(sev) = notification.get("severity").and_then(|v| v.as_str()) {
            let normalised = Severity::parse(sev).as_str();
            notification["severity"] = Value::String(normalised.to_string());
        }
        let notif: Notification = serde_json::from_value(notification)?;
        let outcome = service.send_from_plugin(author, notif, ns_path).await?;
        Ok(json!({ "id": outcome.id, "recipient_count": outcome.recipient_count }))
    }

    async fn list_authored_by_plugin(
        &self,
        author: &str,
        ns_path: &str,
    ) -> Result<Vec<Value>, RvError> {
        let service = self
            .service()
            .ok_or_else(|| crate::bv_error_string!("notification service unavailable"))?;
        let list = service.list_authored_by_plugin(author, ns_path).await?;
        list.into_iter().map(|n| serde_json::to_value(n).map_err(RvError::from)).collect()
    }

    async fn get_authored_by_plugin(
        &self,
        author: &str,
        ns_path: &str,
        id: &str,
    ) -> Result<Option<Value>, RvError> {
        let service = self
            .service()
            .ok_or_else(|| crate::bv_error_string!("notification service unavailable"))?;
        match service.get_authored_by_plugin(author, ns_path, id).await? {
            Some(n) => Ok(Some(serde_json::to_value(n)?)),
            None => Ok(None),
        }
    }
}

/// Publish the notifications module as the vault's notification sink.
pub fn register(module: Arc<NotificationsModule>, services: &crate::kernel_api::KernelServices) {
    services.set_notifications(module);
}
