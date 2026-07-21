//! Notification delivery channels.
//!
//! Two kinds of channel exist:
//!
//! * **In-app** (built-in) — writing a per-user inbox pointer. Handled
//!   directly by the [`super::service::NotificationService`]; it is not
//!   dispatched through this module.
//! * **Plugin channels** — a plugin declares one or more
//!   `notification_channels` in its manifest. The service dispatches
//!   delivery here, which invokes the plugin's active version (via the
//!   non-mount [`crate::plugins::invoke_active_plugin`] path) with a
//!   `notify_deliver` envelope and interprets the result.
//!
//! Channel ids are `"<plugin>:<channel_id>"`; the in-app channel is the
//! reserved id [`IN_APP_CHANNEL_ID`].

use std::sync::Arc;

use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    plugins::{invoke_active_plugin, InvokeOutcome, PluginCatalog},
};

use super::types::{ChannelDeliveryResult, ChannelInfo, Notification, Recipient, IN_APP_CHANNEL_ID};
use bv_plugin_manifest::ChannelKind;

fn channel_kind_str(kind: ChannelKind) -> String {
    match kind {
        ChannelKind::Email => "email",
        ChannelKind::Sms => "sms",
        ChannelKind::Slack => "slack",
        ChannelKind::Teams => "teams",
        ChannelKind::Whatsapp => "whatsapp",
        ChannelKind::Webhook => "webhook",
        ChannelKind::Other => "other",
    }
    .to_string()
}

/// List all delivery channels the server offers. The built-in in-app
/// channel is always present; plugin channels come from the active
/// version of every registered plugin declaring `notification_channels`.
pub async fn list_channels(core: &Arc<Core>) -> Result<Vec<ChannelInfo>, RvError> {
    let mut out = vec![ChannelInfo {
        id: IN_APP_CHANNEL_ID.to_string(),
        name: "In-app".to_string(),
        kind: "in-app".to_string(),
        description: "Delivered to the recipient's in-app notification center.".to_string(),
        provider: "builtin".to_string(),
        enabled: true,
    }];

    let storage = core.barrier.as_storage();
    let manifests = PluginCatalog::new().list(storage).await.unwrap_or_default();
    for m in manifests {
        for ch in &m.capabilities.notification_channels {
            out.push(ChannelInfo {
                id: format!("{}:{}", m.name, ch.id),
                name: ch.name.clone(),
                kind: channel_kind_str(ch.kind),
                description: ch.description.clone(),
                provider: format!("plugin:{}", m.name),
                enabled: true,
            });
        }
    }
    Ok(out)
}

/// Deliver a notification to a single **plugin** channel. The in-app
/// channel is never routed here — the service writes inboxes directly.
/// Never returns `Err`: a delivery failure is captured in the result's
/// `failed` count + `error` so one bad channel can't fail the send.
pub async fn deliver_to_channel(
    core: &Arc<Core>,
    channel_id: &str,
    notif: &Notification,
    recipients: &[Recipient],
) -> ChannelDeliveryResult {
    let total = recipients.len() as u64;

    let Some((plugin_name, sub_channel)) = channel_id.split_once(':') else {
        return err_result(channel_id, total, "unknown channel id".to_string());
    };

    let envelope = json!({
        "op": "notify_deliver",
        "channel": sub_channel,
        "notification": notif,
        "recipients": recipients,
    });
    let input = match serde_json::to_vec(&envelope) {
        Ok(b) => b,
        Err(e) => return err_result(channel_id, total, format!("serialise envelope: {e}")),
    };

    match invoke_active_plugin(core.clone(), plugin_name, &input).await {
        Ok(output) => {
            if let InvokeOutcome::PluginError(code) = output.outcome {
                let msg = parse_error(&output.response)
                    .unwrap_or_else(|| format!("plugin returned status {code}"));
                return err_result(channel_id, total, msg);
            }
            parse_delivery(channel_id, total, &output.response)
        }
        Err(e) => err_result(channel_id, total, e.to_string()),
    }
}

/// Send a one-off test notification through a channel to a supplied
/// address (admin-only). Reuses the `notify_deliver` path with a single
/// synthetic recipient so plugins need no separate test op.
pub async fn test_channel(
    core: &Arc<Core>,
    channel_id: &str,
    to_email: &str,
    now_iso: &str,
) -> ChannelDeliveryResult {
    let notif = Notification {
        id: format!("test-{}", now_iso),
        title: "BastionVault test notification".to_string(),
        body: "This is a test notification confirming the channel is configured correctly."
            .to_string(),
        severity: super::types::Severity::Info,
        source: "system".to_string(),
        target: super::types::NotificationTarget::AllUsers,
        channels: vec![channel_id.to_string()],
        action_url: None,
        created_at: now_iso.to_string(),
        namespace: String::new(),
        metadata: serde_json::Map::new(),
        recipient_count: 1,
    };
    let recipients = vec![Recipient {
        entity_id: String::new(),
        display_name: "Test recipient".to_string(),
        email: to_email.to_string(),
        phone: String::new(),
    }];
    deliver_to_channel(core, channel_id, &notif, &recipients).await
}

fn err_result(channel_id: &str, total: u64, msg: String) -> ChannelDeliveryResult {
    ChannelDeliveryResult {
        channel: channel_id.to_string(),
        delivered: 0,
        failed: total,
        error: Some(msg),
    }
}

fn parse_error(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string()))
}

/// Interpret a plugin's `notify_deliver` response. Accepts either
/// `{"delivered": [...], "failed": [...]}` (arrays) or
/// `{"delivered": <n>, "failed": <n>}` (counts). A response that carries
/// neither is treated as "all delivered" so a terse plugin still works.
fn parse_delivery(channel_id: &str, total: u64, bytes: &[u8]) -> ChannelDeliveryResult {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        // Non-JSON success response: assume delivered.
        return ChannelDeliveryResult {
            channel: channel_id.to_string(),
            delivered: total,
            failed: 0,
            error: None,
        };
    };

    let delivered = count_field(v.get("delivered"));
    let failed = count_field(v.get("failed"));

    let (delivered, failed) = match (delivered, failed) {
        (Some(d), Some(f)) => (d, f),
        (Some(d), None) => (d, total.saturating_sub(d)),
        (None, Some(f)) => (total.saturating_sub(f), f),
        (None, None) => (total, 0),
    };

    let error = v
        .get("error")
        .and_then(|e| e.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    ChannelDeliveryResult {
        channel: channel_id.to_string(),
        delivered,
        failed,
        error,
    }
}

fn count_field(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Array(a)) => Some(a.len() as u64),
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    }
}
