use std::collections::HashMap;

use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

/// Mount path the AppID (type `approle`) backend is enabled at, with a trailing
/// slash. It is operator-chosen (`appid/` on some deployments), so it cannot be
/// assumed to be `approle/`: hardcoding it made every AppID command 404 with
/// `Router mount not found` on such a server. Prefers `approle/` when several
/// approle mounts exist, otherwise the first by path; `approle/` when none is
/// listed, so the request fails the way it always did instead of guessing.
pub(crate) fn pick_approle_mount(auth_mounts: &Map<String, Value>) -> String {
    let mut paths: Vec<&String> = auth_mounts
        .iter()
        .filter(|(_, v)| v.get("type").and_then(Value::as_str) == Some("approle"))
        .map(|(k, _)| k)
        .collect();
    paths.sort();
    if paths.iter().any(|p| p.as_str() == "approle/") {
        return "approle/".to_string();
    }
    paths.first().map(|p| format!("{}/", p.trim_end_matches('/'))).unwrap_or_else(|| "approle/".to_string())
}

pub(crate) async fn resolve_approle_mount(state: &State<'_, AppState>) -> CmdResult<String> {
    let map = super::system::read_ui_mounts(state, "auth").await?;
    Ok(pick_approle_mount(&map))
}

/// `auth/<approle mount>/<rest>`.
async fn approle_path(state: &State<'_, AppState>, rest: &str) -> CmdResult<String> {
    Ok(format!("auth/{}{rest}", resolve_approle_mount(state).await?))
}

/// The AppID mount path, for the GUI's namespace-assignment records, which are
/// keyed by the mount a token was minted on.
#[tauri::command]
pub async fn get_approle_mount(state: State<'_, AppState>) -> CmdResult<String> {
    resolve_approle_mount(&state).await
}

#[cfg(test)]
mod mount_tests {
    use super::pick_approle_mount;
    use serde_json::json;

    fn m(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn follows_a_renamed_mount() {
        let map = m(json!({"appid/": {"type": "approle"}, "userpass/": {"type": "userpass"}}));
        assert_eq!(pick_approle_mount(&map), "appid/");
    }

    #[test]
    fn prefers_the_default_path_when_both_exist() {
        let map = m(json!({"appid/": {"type": "approle"}, "approle/": {"type": "approle"}}));
        assert_eq!(pick_approle_mount(&map), "approle/");
    }

    #[test]
    fn falls_back_to_the_default_when_none_is_listed() {
        assert_eq!(pick_approle_mount(&m(json!({"userpass/": {"type": "userpass"}}))), "approle/");
    }
}

// ── Role CRUD ──────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AppRoleListResult {
    pub roles: Vec<String>,
}

#[derive(Serialize, serde::Deserialize, Default, Clone)]
pub struct MachineBinding {
    pub machine_id: String,
    #[serde(default)]
    pub spiffe_id: String,
    #[serde(default)]
    pub environments: Vec<String>,
}

#[derive(Serialize)]
pub struct AppRoleInfo {
    pub name: String,
    pub bind_secret_id: bool,
    pub secret_id_num_uses: i64,
    pub secret_id_ttl: u64,
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
    pub token_num_uses: i64,
    pub secret_id_bound_cidrs: Vec<String>,
    pub token_bound_cidrs: Vec<String>,
    pub bound_source_ips: Vec<String>,
    pub bypass_machine_binding: bool,
    pub bound_machines: Vec<MachineBinding>,
}

#[derive(Serialize)]
pub struct MachineBindingList {
    pub machines: Vec<MachineBinding>,
}

#[tauri::command]
pub async fn list_approles(state: State<'_, AppState>) -> CmdResult<AppRoleListResult> {
    let resp = make_request(&state, Operation::List, approle_path(&state, "role/").await?, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let roles = keys.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    return Ok(AppRoleListResult { roles });
                }
            }
            Ok(AppRoleListResult { roles: vec![] })
        }
        None => Ok(AppRoleListResult { roles: vec![] }),
    }
}

#[tauri::command]
pub async fn read_approle(state: State<'_, AppState>, name: String) -> CmdResult<AppRoleInfo> {
    let resp =
        make_request(&state, Operation::Read, approle_path(&state, &format!("role/{name}")).await?, None).await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            let get_str_vec = |key: &str| -> Vec<String> {
                data.and_then(|d| d.get(key))
                    .and_then(|v| match v {
                        Value::Array(a) => Some(a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
                        Value::String(s) => {
                            Some(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
                        }
                        _ => None,
                    })
                    .unwrap_or_default()
            };

            Ok(AppRoleInfo {
                name,
                bind_secret_id: data.and_then(|d| d.get("bind_secret_id")).and_then(|v| v.as_bool()).unwrap_or(true),
                secret_id_num_uses: data
                    .and_then(|d| d.get("secret_id_num_uses"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                secret_id_ttl: data.and_then(|d| d.get("secret_id_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                token_policies: get_str_vec("token_policies"),
                token_ttl: data.and_then(|d| d.get("token_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                token_max_ttl: data.and_then(|d| d.get("token_max_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                token_num_uses: data.and_then(|d| d.get("token_num_uses")).and_then(|v| v.as_i64()).unwrap_or(0),
                secret_id_bound_cidrs: get_str_vec("secret_id_bound_cidrs"),
                token_bound_cidrs: get_str_vec("token_bound_cidrs"),
                bound_source_ips: get_str_vec("bound_source_ips"),
                bypass_machine_binding: data
                    .and_then(|d| d.get("bypass_machine_binding"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                bound_machines: data
                    .and_then(|d| d.get("bound_machines"))
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
            })
        }
        None => Err("Role not found".into()),
    }
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn write_approle(
    state: State<'_, AppState>,
    name: String,
    bind_secret_id: bool,
    token_policies: String,
    secret_id_num_uses: i64,
    secret_id_ttl: String,
    token_ttl: String,
    token_max_ttl: String,
    bound_source_ips: String,
    bypass_machine_binding: bool,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("bind_secret_id".into(), Value::Bool(bind_secret_id));
    // Always sent: clearing the box must clear the filter / re-gate the ID.
    body.insert("bound_source_ips".into(), Value::String(bound_source_ips));
    body.insert("bypass_machine_binding".into(), Value::Bool(bypass_machine_binding));
    if !token_policies.is_empty() {
        body.insert("token_policies".into(), Value::String(token_policies));
    }
    body.insert("secret_id_num_uses".into(), Value::Number(secret_id_num_uses.into()));
    if !secret_id_ttl.is_empty() {
        body.insert("secret_id_ttl".into(), Value::String(secret_id_ttl));
    }
    if !token_ttl.is_empty() {
        body.insert("token_ttl".into(), Value::String(token_ttl));
    }
    if !token_max_ttl.is_empty() {
        body.insert("token_max_ttl".into(), Value::String(token_max_ttl));
    }

    make_request(&state, Operation::Write, approle_path(&state, &format!("role/{name}")).await?, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_approle(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, approle_path(&state, &format!("role/{name}")).await?, None).await?;
    Ok(())
}

// ── Role ID ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RoleIdInfo {
    pub role_id: String,
}

#[tauri::command]
pub async fn read_role_id(state: State<'_, AppState>, name: String) -> CmdResult<RoleIdInfo> {
    let resp =
        make_request(&state, Operation::Read, approle_path(&state, &format!("role/{name}/role-id")).await?, None)
            .await?;

    match resp {
        Some(r) => {
            let role_id =
                r.data.as_ref().and_then(|d| d.get("role_id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            Ok(RoleIdInfo { role_id })
        }
        None => Err("Role ID not found".into()),
    }
}

// ── Secret ID Management ───────────────────────────────────────────

#[derive(Serialize)]
pub struct SecretIdResponse {
    pub secret_id: String,
    pub secret_id_accessor: String,
    pub secret_id_ttl: u64,
}

#[derive(Serialize)]
pub struct SecretIdAccessorList {
    pub accessors: Vec<String>,
}

#[derive(Serialize)]
pub struct SecretIdAccessorInfo {
    pub secret_id_accessor: String,
    pub secret_id_num_uses: i64,
    pub secret_id_ttl: u64,
    pub creation_time: String,
    pub expiration_time: String,
    pub metadata: HashMap<String, String>,
    pub cidr_list: Vec<String>,
    pub environments: Vec<String>,
}

#[tauri::command]
pub async fn generate_secret_id(
    state: State<'_, AppState>,
    name: String,
    metadata: String,
    environments: Vec<String>,
) -> CmdResult<SecretIdResponse> {
    let mut body = Map::new();
    if !metadata.is_empty() {
        body.insert("metadata".into(), Value::String(metadata));
    }
    if !environments.is_empty() {
        body.insert("environments".into(), Value::Array(environments.into_iter().map(Value::String).collect()));
    }

    let resp = make_request(
        &state,
        Operation::Write,
        approle_path(&state, &format!("role/{name}/secret-id/")).await?,
        Some(body),
    )
    .await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            Ok(SecretIdResponse {
                secret_id: data.and_then(|d| d.get("secret_id")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                secret_id_accessor: data
                    .and_then(|d| d.get("secret_id_accessor"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                secret_id_ttl: data.and_then(|d| d.get("secret_id_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
            })
        }
        None => Err("Failed to generate secret ID".into()),
    }
}

#[tauri::command]
pub async fn list_secret_id_accessors(state: State<'_, AppState>, name: String) -> CmdResult<SecretIdAccessorList> {
    let resp =
        make_request(&state, Operation::List, approle_path(&state, &format!("role/{name}/secret-id/")).await?, None)
            .await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let accessors = keys.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    return Ok(SecretIdAccessorList { accessors });
                }
            }
            Ok(SecretIdAccessorList { accessors: vec![] })
        }
        None => Ok(SecretIdAccessorList { accessors: vec![] }),
    }
}

#[tauri::command]
pub async fn lookup_secret_id_accessor(
    state: State<'_, AppState>,
    name: String,
    accessor: String,
) -> CmdResult<SecretIdAccessorInfo> {
    let mut body = Map::new();
    body.insert("secret_id_accessor".into(), Value::String(accessor.clone()));

    let resp = make_request(
        &state,
        Operation::Write,
        approle_path(&state, &format!("role/{name}/secret-id-accessor/lookup/")).await?,
        Some(body),
    )
    .await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();

            let metadata: HashMap<String, String> = data
                .and_then(|d| d.get("metadata"))
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let cidr_list: Vec<String> = data
                .and_then(|d| d.get("cidr_list"))
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let environments: Vec<String> = data
                .and_then(|d| d.get("environments"))
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();

            Ok(SecretIdAccessorInfo {
                secret_id_accessor: accessor,
                secret_id_num_uses: data
                    .and_then(|d| d.get("secret_id_num_uses"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                secret_id_ttl: data.and_then(|d| d.get("secret_id_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                creation_time: data
                    .and_then(|d| d.get("creation_time"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                expiration_time: data
                    .and_then(|d| d.get("expiration_time"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                metadata,
                cidr_list,
                environments,
            })
        }
        None => Err("Accessor not found".into()),
    }
}

#[tauri::command]
pub async fn destroy_secret_id_accessor(state: State<'_, AppState>, name: String, accessor: String) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("secret_id_accessor".into(), Value::String(accessor));

    make_request(
        &state,
        Operation::Write,
        approle_path(&state, &format!("role/{name}/secret-id-accessor/destroy/")).await?,
        Some(body),
    )
    .await?;
    Ok(())
}

// ── Machine Bindings ───────────────────────────────────────────────

#[tauri::command]
pub async fn list_role_machines(state: State<'_, AppState>, name: String) -> CmdResult<MachineBindingList> {
    let resp =
        make_request(&state, Operation::List, approle_path(&state, &format!("role/{name}/machine/")).await?, None)
            .await?;

    match resp {
        Some(r) => {
            let machines = r
                .data
                .as_ref()
                .and_then(|d| d.get("machines"))
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            Ok(MachineBindingList { machines })
        }
        None => Ok(MachineBindingList { machines: vec![] }),
    }
}

#[tauri::command]
pub async fn add_role_machine(
    state: State<'_, AppState>,
    name: String,
    machine_id: String,
    spiffe_id: String,
    environments: Vec<String>,
) -> CmdResult<()> {
    let mut body = Map::new();
    if !machine_id.is_empty() {
        body.insert("machine_id".into(), Value::String(machine_id));
    }
    if !spiffe_id.is_empty() {
        body.insert("spiffe_id".into(), Value::String(spiffe_id));
    }
    body.insert("environments".into(), Value::Array(environments.into_iter().map(Value::String).collect()));

    make_request(&state, Operation::Write, approle_path(&state, &format!("role/{name}/machine/")).await?, Some(body))
        .await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_role_machine(state: State<'_, AppState>, name: String, machine_id: String) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        approle_path(&state, &format!("role/{name}/machine/{machine_id}")).await?,
        None,
    )
    .await?;
    Ok(())
}
