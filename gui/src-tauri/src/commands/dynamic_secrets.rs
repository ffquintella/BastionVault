//! Tauri commands for dynamic-secret mounts in the Secrets page (T62,
//! features/dynamic-secrets.md Phase 5): list a mount's roles and generate a
//! credential (`creds/<role>`). Both go through the logical API in the active
//! namespace; the remote backend sends them to `/v2/<mount>/…`.
//! The generated credential is handed to the webview once and never logged.

use bv_client::{JsonResponse, Operation};
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use super::make_request;
use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

/// A generated (or cache-served) credential and its lease. No `Debug`, so the
/// credential cannot reach a log line through `{:?}`.
#[derive(Serialize, Default)]
pub struct DynamicCredsResult {
    /// The credential: `username`, `password` and any plugin extras.
    pub data: Map<String, Value>,
    pub lease_id: Option<String>,
    pub lease_duration: Option<u64>,
    pub renewable: Option<bool>,
    /// A credential-cache hit: the lease (named in the host's `data`) is shared
    /// with the earlier read of the same identity that created it.
    pub cache_hit: bool,
    pub warnings: Vec<String>,
}

#[tauri::command]
pub async fn dynamic_list_roles(state: State<'_, AppState>, mount: String) -> CmdResult<Vec<String>> {
    let mount = checked_mount(&mount)?;
    let resp = make_request(&state, Operation::List, format!("{mount}/roles/"), None).await?;
    let keys = resp.and_then(|r| r.data).and_then(|d| d.get("keys").cloned());
    let roles = keys
        .as_ref()
        .and_then(Value::as_array)
        .map(|k| k.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();
    Ok(roles)
}

#[tauri::command]
pub async fn dynamic_generate_creds(
    state: State<'_, AppState>,
    mount: String,
    role: String,
) -> CmdResult<DynamicCredsResult> {
    let mount = checked_mount(&mount)?;
    let role = checked_role(&role)?;
    let resp = make_request(&state, Operation::Read, format!("{mount}/creds/{role}"), None).await?;
    let resp = resp.ok_or("the mount answered without a credential")?;
    Ok(creds_result(resp))
}

/// A fresh credential carries its lease at the top level; a cache hit carries
/// none and names the shared lease in `data` instead (docs/api.md, *Credential
/// cache*). Either way the lease fields leave `data`, which keeps only the
/// credential.
fn creds_result(resp: JsonResponse) -> DynamicCredsResult {
    let mut data = resp.data.unwrap_or_default();
    let named_id = data.remove("lease_id").and_then(|v| v.as_str().map(String::from));
    let named_ttl = data.remove("lease_duration").and_then(|v| v.as_u64());
    let named_renewable = data.remove("renewable").and_then(|v| v.as_bool());
    match resp.lease_id {
        Some(lease_id) => DynamicCredsResult {
            data,
            lease_id: Some(lease_id),
            lease_duration: resp.lease_duration,
            renewable: resp.renewable,
            cache_hit: false,
            warnings: resp.warnings,
        },
        None => DynamicCredsResult {
            data,
            cache_hit: named_id.is_some(),
            lease_id: named_id,
            lease_duration: named_ttl,
            renewable: named_renewable,
            warnings: resp.warnings,
        },
    }
}

/// A mount path without the slashes around it; refuses anything that could
/// step out of the mount or turn into a query on the remote URL.
fn checked_mount(mount: &str) -> Result<&str, CommandError> {
    let mount = mount.trim().trim_matches('/');
    if mount.is_empty() || mount.contains("..") || mount.contains(['?', '#']) || mount.chars().any(char::is_control) {
        return Err("invalid mount path".into());
    }
    Ok(mount)
}

/// One role name: a single path segment.
fn checked_role(role: &str) -> Result<&str, CommandError> {
    let role = role.trim();
    if role.is_empty() || role.contains(['/', '?', '#']) || role.contains("..") || role.chars().any(char::is_control)
    {
        return Err("invalid role name".into());
    }
    Ok(role)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn response(body: Value) -> JsonResponse {
        JsonResponse::from_json(body)
    }

    #[test]
    fn a_fresh_credential_keeps_its_top_level_lease() {
        let r = creds_result(response(json!({
            "data": { "username": "v-u", "password": "p" },
            "lease_id": "db/creds/ro/a1", "lease_duration": 3600, "renewable": true
        })));
        assert!(!r.cache_hit);
        assert_eq!(r.lease_id.as_deref(), Some("db/creds/ro/a1"));
        assert_eq!((r.lease_duration, r.renewable), (Some(3600), Some(true)));
        assert_eq!(r.data.len(), 2);
    }

    #[test]
    fn a_cache_hit_names_the_shared_lease_in_data() {
        let r = creds_result(response(json!({
            "data": { "username": "v-u", "password": "p", "lease_id": "db/creds/ro/a1",
                      "lease_duration": 900, "renewable": false },
            "warnings": ["served from the credential cache"]
        })));
        assert!(r.cache_hit);
        assert_eq!(r.lease_id.as_deref(), Some("db/creds/ro/a1"));
        assert_eq!((r.lease_duration, r.renewable), (Some(900), Some(false)));
        assert!(!r.data.contains_key("lease_id"), "lease fields leave the credential");
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn paths_that_leave_the_mount_are_refused() {
        assert_eq!(checked_mount("/database/").unwrap(), "database");
        assert_eq!(checked_role("readonly").unwrap(), "readonly");
        for bad in ["", "/", "a/../b", "db?x=1", "db#f"] {
            assert!(checked_mount(bad).is_err(), "{bad:?}");
        }
        for bad in ["", "a/b", "..", "r?x", "r#f"] {
            assert!(checked_role(bad).is_err(), "{bad:?}");
        }
    }
}
