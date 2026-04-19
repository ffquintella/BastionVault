//! Group store for the identity module.
//!
//! Stores user groups and application groups behind the vault barrier and
//! provides the policy-expansion helper used by auth backends at login time.
//!
//! Storage layout (all under the system barrier view):
//!   sys/identity/group/user/{group}   -> GroupEntry (kind = User)
//!   sys/identity/group/app/{group}    -> GroupEntry (kind = App)
//!
//! Group membership is looked up at login time by scanning the relevant kind's
//! keyspace. The expected cardinality is small (tens to low hundreds of
//! groups); if this grows we can add a reverse member index as a follow-up.

use std::{fmt, sync::Arc};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    core::Core,
    errors::RvError,
    bv_error_string,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};

const GROUP_USER_SUB_PATH: &str = "identity/group/user/";
const GROUP_APP_SUB_PATH: &str = "identity/group/app/";
const HISTORY_USER_SUB_PATH: &str = "identity/group-history/user/";
const HISTORY_APP_SUB_PATH: &str = "identity/group-history/app/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupKind {
    User,
    App,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupKind::User => "user",
            GroupKind::App => "app",
        }
    }

    pub fn parse(s: &str) -> Result<Self, RvError> {
        match s {
            "user" => Ok(GroupKind::User),
            "app" => Ok(GroupKind::App),
            _ => Err(bv_error_string!(format!("invalid group kind: {s}"))),
        }
    }
}

impl fmt::Display for GroupKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// Audit log entry for a group change. Records the list of top-level
/// fields that changed along with their before/after values so the GUI
/// can reconstruct prior states and the operator can see exactly what
/// changed. Only the values of the fields listed in `changed_fields`
/// appear in the `before` and `after` maps.
///
/// Values:
///   - `description`: JSON string
///   - `members`:     JSON array of strings
///   - `policies`:    JSON array of strings
///
/// For `create`, `before` is empty; for `delete`, `after` is empty; for
/// `update`, both hold the values of exactly the changed fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    #[serde(default)]
    pub changed_fields: Vec<String>,
    #[serde(default)]
    pub before: Map<String, Value>,
    #[serde(default)]
    pub after: Map<String, Value>,
}

pub struct GroupStore {
    user_view: Arc<BarrierView>,
    app_view: Arc<BarrierView>,
    history_user_view: Arc<BarrierView>,
    history_app_view: Arc<BarrierView>,
}

#[maybe_async::maybe_async]
impl GroupStore {
    pub async fn new(core: &Core) -> Result<Arc<Self>, RvError> {
        let Some(system_view) = core.state.load().system_view.as_ref().cloned() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let user_view = Arc::new(system_view.new_sub_view(GROUP_USER_SUB_PATH));
        let app_view = Arc::new(system_view.new_sub_view(GROUP_APP_SUB_PATH));
        let history_user_view = Arc::new(system_view.new_sub_view(HISTORY_USER_SUB_PATH));
        let history_app_view = Arc::new(system_view.new_sub_view(HISTORY_APP_SUB_PATH));

        Ok(Arc::new(Self {
            user_view,
            app_view,
            history_user_view,
            history_app_view,
        }))
    }

    fn view(&self, kind: GroupKind) -> Arc<BarrierView> {
        match kind {
            GroupKind::User => self.user_view.clone(),
            GroupKind::App => self.app_view.clone(),
        }
    }

    fn history_view(&self, kind: GroupKind) -> Arc<BarrierView> {
        match kind {
            GroupKind::User => self.history_user_view.clone(),
            GroupKind::App => self.history_app_view.clone(),
        }
    }

    fn sanitize_name(name: &str) -> Result<String, RvError> {
        let n = name.trim().to_lowercase();
        if n.is_empty() {
            return Err(bv_error_string!("group name missing"));
        }
        if n.contains('/') || n.contains("..") {
            return Err(bv_error_string!("invalid group name"));
        }
        Ok(n)
    }

    pub async fn set_group(&self, kind: GroupKind, mut entry: GroupEntry) -> Result<(), RvError> {
        let name = Self::sanitize_name(&entry.name)?;
        entry.name = name.clone();
        // Normalize members + policies: trim, drop empties, dedup.
        entry.members = normalize(entry.members);
        entry.policies = normalize(entry.policies);

        let view = self.view(kind);
        let value = serde_json::to_vec(&entry)?;
        view.put(&StorageEntry { key: name, value }).await
    }

    pub async fn get_group(&self, kind: GroupKind, name: &str) -> Result<Option<GroupEntry>, RvError> {
        let name = Self::sanitize_name(name)?;
        let view = self.view(kind);
        let entry = view.get(&name).await?;
        match entry {
            Some(e) => {
                let g: GroupEntry = serde_json::from_slice(&e.value)?;
                Ok(Some(g))
            }
            None => Ok(None),
        }
    }

    pub async fn list_groups(&self, kind: GroupKind) -> Result<Vec<String>, RvError> {
        let view = self.view(kind);
        let mut keys = view.get_keys().await?;
        keys.sort();
        Ok(keys)
    }

    pub async fn delete_group(&self, kind: GroupKind, name: &str) -> Result<(), RvError> {
        let name = Self::sanitize_name(name)?;
        let view = self.view(kind);
        view.delete(&name).await
    }

    /// Append an audit entry for a group change. History keys are
    /// `{name}/{20-digit-nanos}` so `list_history` returns them in
    /// chronological order.
    pub async fn append_history(
        &self,
        kind: GroupKind,
        name: &str,
        entry: GroupHistoryEntry,
    ) -> Result<(), RvError> {
        let name = Self::sanitize_name(name)?;
        let view = self.history_view(kind);
        let key = format!("{name}/{}", hist_seq());
        let value = serde_json::to_vec(&entry)?;
        view.put(&StorageEntry { key, value }).await
    }

    /// Return the full history for a single group, newest entry first.
    /// History persists after the group is deleted so audit records remain
    /// available until explicitly purged.
    pub async fn list_history(
        &self,
        kind: GroupKind,
        name: &str,
    ) -> Result<Vec<GroupHistoryEntry>, RvError> {
        let name = Self::sanitize_name(name)?;
        let view = self.history_view(kind);
        let prefix = format!("{name}/");
        let mut keys = view.list(&prefix).await?;
        keys.sort();
        keys.reverse();

        let mut entries = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = view.get(&full).await? {
                if let Ok(h) = serde_json::from_slice::<GroupHistoryEntry>(&e.value) {
                    entries.push(h);
                }
            }
        }
        Ok(entries)
    }

    /// Return the union of `direct_policies` with the policies of every group
    /// of the given `kind` that lists `member` in its `members` list. Names are
    /// compared case-insensitively (group names are lowercased on write).
    pub async fn expand_policies(
        &self,
        kind: GroupKind,
        member: &str,
        direct_policies: &[String],
    ) -> Result<Vec<String>, RvError> {
        let member_lc = member.trim().to_lowercase();
        let groups = self.list_groups(kind).await?;

        let mut merged: Vec<String> = direct_policies.to_vec();
        for g_name in groups {
            let Some(g) = self.get_group(kind, &g_name).await? else {
                continue;
            };
            let is_member = g.members.iter().any(|m| m.trim().to_lowercase() == member_lc);
            if !is_member {
                continue;
            }
            for p in &g.policies {
                if !merged.iter().any(|x| x == p) {
                    merged.push(p.clone());
                }
            }
        }

        Ok(merged)
    }
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch, used
/// as the suffix of history log keys so listing returns entries in
/// chronological order.
fn hist_seq() -> String {
    let n = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}

fn normalize(mut v: Vec<String>) -> Vec<String> {
    v.iter_mut().for_each(|s| *s = s.trim().to_string());
    v.retain(|s| !s.is_empty());
    let mut out: Vec<String> = Vec::with_capacity(v.len());
    for s in v {
        if !out.iter().any(|x| x == &s) {
            out.push(s);
        }
    }
    out
}
