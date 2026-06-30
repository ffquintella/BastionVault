use std::collections::HashMap;

use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

#[derive(Serialize, Default)]
pub struct SecretData {
    pub data: HashMap<String, Value>,
    /// For KV v2 env-scoped reads: the environment whose overrides were
    /// merged into `data`, or `None` when the base (shared) set was returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_env: Option<String>,
    /// Environments declared on this secret (empty for plain/legacy secrets).
    pub available_envs: Vec<String>,
}

#[derive(Serialize)]
pub struct SecretListResult {
    pub keys: Vec<String>,
}

/// Adjust a KV path for v2 by inserting the appropriate prefix after the mount.
fn adjust_kv_path(path: &str, mount: &str, mount_type: &str, prefix: &str) -> String {
    if mount_type == "kv-v2" && !mount.is_empty() {
        let rel = path.strip_prefix(mount).unwrap_or(path);
        format!("{mount}{prefix}/{rel}")
    } else {
        path.to_string()
    }
}

#[tauri::command]
pub async fn list_secrets(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<SecretListResult> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let actual_path = adjust_kv_path(&path, m, mt, "metadata");
    let resp = make_request(&state, Operation::List, actual_path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let keys: Vec<String> = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(SecretListResult { keys });
                }
            }
            Ok(SecretListResult { keys: vec![] })
        }
        None => Ok(SecretListResult { keys: vec![] }),
    }
}

#[tauri::command]
pub async fn read_secret(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
    env: Option<String>,
) -> CmdResult<SecretData> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let mut actual_path = adjust_kv_path(&path, m, mt, "data");
    // Carry the env selector as a query param; the server lifts it into the
    // request data so the ACL check and KV engine both see it. Works for both
    // the embedded and remote backends.
    if let Some(e) = env.as_deref().filter(|s| !s.is_empty()) {
        actual_path = format!("{actual_path}?env={e}");
    }
    let resp = make_request(&state, Operation::Read, actual_path, None).await?;

    match resp {
        Some(r) => {
            let raw = r.data.unwrap_or_default();
            // v2 nests the actual secret under a "data" key and exposes env
            // info under "metadata".
            if mt == "kv-v2" {
                let data = raw
                    .get("data")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let meta = raw.get("metadata");
                let resolved_env = meta
                    .and_then(|m| m.get("resolved_env"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let available_envs = meta
                    .and_then(|m| m.get("available_envs"))
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                Ok(SecretData { data, resolved_env, available_envs })
            } else {
                Ok(SecretData {
                    data: raw.into_iter().collect(),
                    resolved_env: None,
                    available_envs: Vec::new(),
                })
            }
        }
        None => Err("Secret not found".into()),
    }
}

#[tauri::command]
pub async fn write_secret(
    state: State<'_, AppState>,
    path: String,
    data: HashMap<String, String>,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let actual_path = adjust_kv_path(&path, m, mt, "data");

    let mut kv_body = Map::new();
    for (k, v) in data {
        kv_body.insert(k, Value::String(v));
    }

    // v2 wraps the data in a "data" envelope
    let body = if mt == "kv-v2" {
        let mut wrapper = Map::new();
        wrapper.insert("data".to_string(), Value::Object(kv_body));
        wrapper
    } else {
        kv_body
    };

    make_request(&state, Operation::Write, actual_path, Some(body)).await?;
    Ok(())
}

/// Write key/value pairs as overrides for a single environment (KV v2 only).
/// The server carries the secret's base values and other environments forward
/// into the new version, replacing only this environment's overrides.
#[tauri::command]
pub async fn write_secret_env(
    state: State<'_, AppState>,
    path: String,
    env: String,
    data: HashMap<String, String>,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Err("environment-scoped writes require a kv-v2 mount".into());
    }
    if env.trim().is_empty() {
        return Err("env is required".into());
    }
    let actual_path = adjust_kv_path(&path, m, mt, "data");

    let mut kv_body = Map::new();
    for (k, v) in data {
        kv_body.insert(k, Value::String(v));
    }
    let mut body = Map::new();
    body.insert("data".to_string(), Value::Object(kv_body));
    body.insert("env".to_string(), Value::String(env));

    make_request(&state, Operation::Write, actual_path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_secret(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let actual_path = adjust_kv_path(&path, m, mt, "metadata");
    make_request(&state, Operation::Delete, actual_path, None).await?;
    Ok(())
}

// ── Secret history / versions ──────────────────────────────────────

#[derive(Serialize)]
pub struct SecretVersionInfo {
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    pub username: String,
    pub operation: String,
}

#[derive(Serialize)]
pub struct SecretVersionListResult {
    pub current_version: u64,
    pub oldest_version: u64,
    pub versions: Vec<SecretVersionInfo>,
}

#[derive(Serialize)]
pub struct SecretVersionData {
    pub data: HashMap<String, Value>,
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    pub username: String,
    pub operation: String,
}

/// List every stored version of a KV-v2 secret (newest first). Returns
/// the per-version metadata -- `created_time`, the username of whoever
/// wrote it, and the soft-delete/destroy state. KV-v1 does not support
/// versioning; callers receive an empty list in that case.
#[tauri::command]
pub async fn list_secret_versions(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<SecretVersionListResult> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Ok(SecretVersionListResult {
            current_version: 0,
            oldest_version: 0,
            versions: vec![],
        });
    }
    let actual_path = adjust_kv_path(&path, m, mt, "metadata");
    let resp = make_request(&state, Operation::Read, actual_path, None).await?;

    let data = match resp.and_then(|r| r.data) {
        Some(d) => d,
        None => {
            return Ok(SecretVersionListResult {
                current_version: 0,
                oldest_version: 0,
                versions: vec![],
            });
        }
    };

    let current_version = data
        .get("current_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let oldest_version = data
        .get("oldest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut versions: Vec<SecretVersionInfo> = Vec::new();
    if let Some(Value::Object(vmap)) = data.get("versions") {
        for (k, v) in vmap {
            let Ok(version) = k.parse::<u64>() else { continue };
            let obj = match v.as_object() {
                Some(o) => o,
                None => continue,
            };
            versions.push(SecretVersionInfo {
                version,
                created_time: obj
                    .get("created_time")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                deletion_time: obj
                    .get("deletion_time")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                destroyed: obj
                    .get("destroyed")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                username: obj
                    .get("username")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                operation: obj
                    .get("operation")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    // Newest version first.
    versions.sort_by_key(|x| std::cmp::Reverse(x.version));

    Ok(SecretVersionListResult {
        current_version,
        oldest_version,
        versions,
    })
}

/// Read a specific historical version of a KV-v2 secret. Not valid for
/// KV-v1 (where only the current value exists).
#[tauri::command]
pub async fn read_secret_version(
    state: State<'_, AppState>,
    path: String,
    version: u64,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<SecretVersionData> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Err("Versioning is only available on kv-v2 mounts".into());
    }
    let actual_path = adjust_kv_path(&path, m, mt, "data");

    let mut body = Map::new();
    body.insert("version".to_string(), Value::from(version));
    let resp = make_request(&state, Operation::Read, actual_path, Some(body)).await?;

    let raw = resp.and_then(|r| r.data).ok_or("Version not found")?;
    let data_map = raw
        .get("data")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let meta = raw
        .get("metadata")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    Ok(SecretVersionData {
        data: data_map.into_iter().collect(),
        version: meta.get("version").and_then(|v| v.as_u64()).unwrap_or(version),
        created_time: meta
            .get("created_time")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        deletion_time: meta
            .get("deletion_time")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        destroyed: meta
            .get("destroyed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        username: meta
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        operation: meta
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

// ── KV-v2 version actions ───────────────────────────────────────────
//
// Soft-delete, undelete, and destroy each target one or more specific
// versions on a single secret. All three are no-ops on `kv-v1` mounts —
// the underlying KV v1 path layout has no concept of multiple versions
// or a deletion-time/destroyed flag, so the GUI gates the buttons on
// `mount_type == "kv-v2"` and these commands simply refuse if called
// against a v1 mount to keep the server free of surprising writes.

#[tauri::command]
pub async fn soft_delete_secret_versions(
    state: State<'_, AppState>,
    path: String,
    versions: Vec<u64>,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Err("Soft-delete by version is only available on kv-v2 mounts".into());
    }
    if versions.is_empty() {
        return Err("At least one version must be supplied".into());
    }
    let actual_path = adjust_kv_path(&path, m, mt, "data");
    let mut body = Map::new();
    body.insert(
        "versions".to_string(),
        Value::Array(versions.into_iter().map(Value::from).collect()),
    );
    make_request(&state, Operation::Delete, actual_path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn undelete_secret_versions(
    state: State<'_, AppState>,
    path: String,
    versions: Vec<u64>,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Err("Undelete is only available on kv-v2 mounts".into());
    }
    if versions.is_empty() {
        return Err("At least one version must be supplied".into());
    }
    let actual_path = adjust_kv_path(&path, m, mt, "undelete");
    let mut body = Map::new();
    body.insert(
        "versions".to_string(),
        Value::Array(versions.into_iter().map(Value::from).collect()),
    );
    make_request(&state, Operation::Write, actual_path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn destroy_secret_versions(
    state: State<'_, AppState>,
    path: String,
    versions: Vec<u64>,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Err("Destroy is only available on kv-v2 mounts".into());
    }
    if versions.is_empty() {
        return Err("At least one version must be supplied".into());
    }
    let actual_path = adjust_kv_path(&path, m, mt, "destroy");
    let mut body = Map::new();
    body.insert(
        "versions".to_string(),
        Value::Array(versions.into_iter().map(Value::from).collect()),
    );
    make_request(&state, Operation::Write, actual_path, Some(body)).await?;
    Ok(())
}

// ── CAS-aware write ─────────────────────────────────────────────────

/// Write a new version with check-and-set. `cas` must equal the current
/// version (0 for the very first write). Returns the freshly-created
/// version number so the GUI can surface it back to the operator and
/// avoid an extra round-trip to refresh metadata.
#[tauri::command]
pub async fn write_secret_cas(
    state: State<'_, AppState>,
    path: String,
    data: HashMap<String, String>,
    cas: u64,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<u64> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Err("CAS writes are only available on kv-v2 mounts".into());
    }
    let actual_path = adjust_kv_path(&path, m, mt, "data");

    let mut kv_body = Map::new();
    for (k, v) in data {
        kv_body.insert(k, Value::String(v));
    }
    let mut options = Map::new();
    options.insert("cas".to_string(), Value::from(cas));
    let mut wrapper = Map::new();
    wrapper.insert("data".to_string(), Value::Object(kv_body));
    wrapper.insert("options".to_string(), Value::Object(options));

    let resp = make_request(&state, Operation::Write, actual_path, Some(wrapper)).await?;
    let new_version = resp
        .and_then(|r| r.data)
        .and_then(|d| d.get("version").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    Ok(new_version)
}

// ── KV-v2 engine config ─────────────────────────────────────────────

#[derive(Serialize, serde::Deserialize, Default)]
pub struct KvV2EngineConfig {
    /// Default max versions retained per secret (0 = unlimited).
    pub max_versions: u64,
    /// When true, every write must supply a `cas` value.
    pub cas_required: bool,
    /// Duration after which versions are auto-soft-deleted. `"0s"` disables.
    pub delete_version_after: String,
    /// Advisory environment names offered in the GUI's env selector. Free-form
    /// env names are still accepted on writes — this is a convenience list.
    #[serde(default)]
    pub environments: Vec<String>,
}

#[tauri::command]
pub async fn read_kv_v2_engine_config(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<KvV2EngineConfig> {
    if mount.is_empty() {
        return Err("mount path is required".into());
    }
    let path = format!("{}config", ensure_trailing_slash(&mount));
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(KvV2EngineConfig {
        max_versions: data.get("max_versions").and_then(|v| v.as_u64()).unwrap_or(0),
        cas_required: data
            .get("cas_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        delete_version_after: data
            .get("delete_version_after")
            .and_then(|v| v.as_str())
            .unwrap_or("0s")
            .to_string(),
        environments: data
            .get("environments")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    })
}

#[tauri::command]
pub async fn write_kv_v2_engine_config(
    state: State<'_, AppState>,
    mount: String,
    config: KvV2EngineConfig,
) -> CmdResult<()> {
    if mount.is_empty() {
        return Err("mount path is required".into());
    }
    let path = format!("{}config", ensure_trailing_slash(&mount));
    let mut body = Map::new();
    body.insert("max_versions".to_string(), Value::from(config.max_versions));
    body.insert("cas_required".to_string(), Value::Bool(config.cas_required));
    body.insert(
        "delete_version_after".to_string(),
        Value::String(config.delete_version_after),
    );
    body.insert(
        "environments".to_string(),
        Value::Array(config.environments.into_iter().map(Value::String).collect()),
    );
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

fn ensure_trailing_slash(p: &str) -> String {
    if p.ends_with('/') {
        p.to_string()
    } else {
        format!("{p}/")
    }
}

/// Create a new secret-engine mount. `options` is an optional
/// engine-level bag stored on the `MountEntry`; for KV v2 the GUI
/// populates `max_versions` / `cas_required` / `delete_version_after`
/// here so the new mount is born with the operator's desired defaults
/// instead of needing an immediate follow-up `config` write.
#[tauri::command]
pub async fn mount_engine(
    state: State<'_, AppState>,
    path: String,
    engine_type: String,
    description: String,
    options: Option<HashMap<String, String>>,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("type".to_string(), Value::String(engine_type));
    if !description.is_empty() {
        body.insert("description".to_string(), Value::String(description));
    }
    if let Some(opts) = options {
        if !opts.is_empty() {
            let mut opt_map = Map::new();
            for (k, v) in opts {
                opt_map.insert(k, Value::String(v));
            }
            body.insert("options".to_string(), Value::Object(opt_map));
        }
    }

    make_request(
        &state,
        Operation::Write,
        format!("sys/mounts/{path}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn unmount_engine(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("sys/mounts/{path}"), None).await?;
    Ok(())
}

#[tauri::command]
pub async fn enable_auth_method(
    state: State<'_, AppState>,
    path: String,
    auth_type: String,
    description: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("type".to_string(), Value::String(auth_type));
    if !description.is_empty() {
        body.insert("description".to_string(), Value::String(description));
    }

    make_request(
        &state,
        Operation::Write,
        format!("sys/auth/{path}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn disable_auth_method(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("sys/auth/{path}"), None).await?;
    Ok(())
}
