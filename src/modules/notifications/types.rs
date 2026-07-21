//! Core notification data types.
//!
//! These types are the contract between the notification service, its
//! storage, the HTTP surface, the GUI, and plugin channels. They are the
//! single source of truth for how a notification is shaped on the wire.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Severity of a notification. Drives the GUI icon/colour and lets
/// operators filter. Ordered least → most urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Success,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Success => "success",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    /// Parse a severity, defaulting to `Info` for unknown/empty input so
    /// a malformed sender never fails the whole send.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "success" => Severity::Success,
            "warning" => Severity::Warning,
            "critical" => Severity::Critical,
            _ => Severity::Info,
        }
    }
}

/// Who a notification targets. Resolved to a set of entity ids at send
/// time by the [`crate::modules::notifications::service`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotificationTarget {
    /// A single user by stable entity id (`EntityStore`).
    User { entity_id: String },
    /// A single user by login name; resolved to an entity via the
    /// `userpass/` alias index.
    Username { name: String },
    /// Every member of a user or app group. `group_kind` is `"user"` or
    /// `"app"` (the identity `GroupKind`); named `group_kind` rather than
    /// `kind` to avoid colliding with the serde internal tag.
    Group { group_kind: String, name: String },
    /// Every user in the namespace.
    AllUsers,
}

impl NotificationTarget {
    /// Short human label for audit + the admin "sent" view.
    pub fn label(&self) -> String {
        match self {
            NotificationTarget::User { entity_id } => format!("user:{entity_id}"),
            NotificationTarget::Username { name } => format!("user:{name}"),
            NotificationTarget::Group { group_kind, name } => {
                format!("group:{group_kind}/{name}")
            }
            NotificationTarget::AllUsers => "all-users".to_string(),
        }
    }
}

/// Canonical stored notification. One record per raised notification,
/// referenced by every recipient's inbox entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub severity: Severity,
    /// Origin of the notification: `"system"`, `"admin:<entity_id>"`, or
    /// `"plugin:<name>"`. Host-controlled — a plugin can never forge a
    /// non-`plugin:` source.
    #[serde(default)]
    pub source: String,
    pub target: NotificationTarget,
    /// Channel ids to deliver through, beyond the always-on in-app
    /// inbox. Empty = in-app only. Entries are either `"in-app"` or a
    /// plugin channel `"<plugin>:<channel_id>"`.
    #[serde(default)]
    pub channels: Vec<String>,
    /// Optional deep link the GUI opens when the notification is clicked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_url: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub metadata: Map<String, Value>,
    /// Number of recipients resolved at send time. Surfaced only in the
    /// admin "sent" view.
    #[serde(default)]
    pub recipient_count: u64,
}

/// A per-user inbox pointer at a canonical [`Notification`]. Holds the
/// user-specific read state so the same message can be unread for one
/// recipient and read for another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxEntry {
    pub notif_id: String,
    #[serde(default)]
    pub delivered_at: String,
    /// RFC3339 timestamp the recipient read the notification; empty =
    /// unread.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub read_at: String,
}

impl InboxEntry {
    pub fn is_read(&self) -> bool {
        !self.read_at.is_empty()
    }
}

/// A resolved recipient handed to a channel for delivery. Contact
/// details are best-effort: the in-app channel needs only `entity_id`;
/// email/SMS channels use `email` / `phone` and skip recipients that
/// lack the address they need.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    pub entity_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub phone: String,
}

/// A channel descriptor surfaced to the GUI channel list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// `"in-app"` for the built-in channel, or `"<plugin>:<channel_id>"`
    /// for a plugin-provided one.
    pub id: String,
    pub name: String,
    /// Transport family: `"in-app"`, `"email"`, `"sms"`, `"slack"`, …
    pub kind: String,
    #[serde(default)]
    pub description: String,
    /// `"builtin"` or `"plugin:<name>"`.
    pub provider: String,
    /// Whether the channel is currently usable (a plugin channel is
    /// disabled if the plugin has no active version).
    pub enabled: bool,
}

/// Outcome of one channel's delivery attempt, surfaced to the sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDeliveryResult {
    pub channel: String,
    pub delivered: u64,
    pub failed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of a [`crate::modules::notifications::service::NotificationService::send`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendOutcome {
    pub id: String,
    pub recipient_count: u64,
    #[serde(default)]
    pub channel_results: Vec<ChannelDeliveryResult>,
}

/// Operator-tunable notification settings, persisted at
/// `sys/notifications/config` (per namespace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Max notifications retained per user inbox; oldest read entries are
    /// pruned first once this is exceeded.
    #[serde(default = "default_inbox_cap")]
    pub inbox_cap: u32,
    /// Per-plugin send rate limit: max plugin-originated notifications in
    /// a rolling 60-second window.
    #[serde(default = "default_plugin_rate")]
    pub plugin_rate_per_min: u32,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            inbox_cap: default_inbox_cap(),
            plugin_rate_per_min: default_plugin_rate(),
        }
    }
}

fn default_inbox_cap() -> u32 {
    200
}

fn default_plugin_rate() -> u32 {
    60
}

/// The always-present built-in channel id.
pub const IN_APP_CHANNEL_ID: &str = "in-app";
