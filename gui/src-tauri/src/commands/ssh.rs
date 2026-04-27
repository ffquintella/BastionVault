//! Tauri commands bridging the desktop GUI to the SSH Secret Engine.
//!
//! Mirrors `commands/pki.rs`: each command is a thin wrapper over
//! `make_request` that targets a `<mount>/<route>` path under a
//! caller-supplied mount, then projects the response into a
//! GUI-friendly serialisable struct. The mount path is parameterised
//! so an operator who mounted at `ssh-prod/` rather than `ssh/` can
//! drive both from the same UI.
//!
//! Phase 4 surface only — the engine itself ships Phases 1-3 (CA mode
//! + Ed25519 / ML-DSA-65, OTP mode + helper, role policy enforcement);
//! this file is the GUI's view of it.

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

async fn make_request(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> Result<Option<bastion_vault::logical::Response>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = operation;
    req.path = path;
    req.client_token = token;
    req.body = body;

    core.handle_request(&mut req).await.map_err(CommandError::from)
}

/// Normalise an operator-supplied mount string. Trailing slashes are
/// stripped because the path-building code below always concatenates
/// `<mount>/<route>` with an explicit slash.
fn mount_prefix(mount: &str) -> String {
    let trimmed = mount.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "ssh".to_string()
    } else {
        trimmed.to_string()
    }
}

fn data_to_map(resp: Option<bastion_vault::logical::Response>) -> Map<String, Value> {
    resp.and_then(|r| r.data).unwrap_or_default()
}

fn val_str(map: &Map<String, Value>, key: &str) -> String {
    map.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn val_u64(map: &Map<String, Value>, key: &str) -> u64 {
    map.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn val_bool(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

// ── Mount lifecycle ───────────────────────────────────────────────

#[derive(Serialize)]
pub struct SshMountInfo {
    pub path: String,
}

/// List every mount of `type = "ssh"` so the GUI's mount picker can
/// offer them. Reads `sys/mounts` and filters; cheap enough for a
/// per-page-load call.
#[tauri::command]
pub async fn ssh_list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<SshMountInfo>> {
    let resp = make_request(&state, Operation::Read, "sys/mounts".into(), None).await?;
    let map = data_to_map(resp);
    let mut out = Vec::new();
    for (path, info) in map.iter() {
        if let Some(t) = info.get("type").and_then(|v| v.as_str()) {
            if t == "ssh" {
                out.push(SshMountInfo { path: path.clone() });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Mount the engine at the given path. Convenience for a fresh GUI
/// install where no `ssh/` mount exists yet.
#[tauri::command]
pub async fn ssh_enable_mount(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let mount_path = path.trim().trim_end_matches('/').to_string();
    if mount_path.is_empty() {
        return Err("mount path required".into());
    }
    let mut body = Map::new();
    body.insert("type".into(), Value::String("ssh".into()));
    let api_path = format!("sys/mounts/{mount_path}/");
    make_request(&state, Operation::Write, api_path, Some(body)).await?;
    Ok(())
}

// ── CA management ────────────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct SshCaInfo {
    pub public_key: String,
    pub algorithm: String,
}

#[tauri::command]
pub async fn ssh_read_ca(state: State<'_, AppState>, mount: String) -> CmdResult<SshCaInfo> {
    let path = format!("{}/config/ca", mount_prefix(&mount));
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let map = data_to_map(resp);
    Ok(SshCaInfo {
        public_key: val_str(&map, "public_key"),
        algorithm: val_str(&map, "algorithm"),
    })
}

#[derive(Deserialize)]
pub struct SshGenerateCaRequest {
    pub mount: String,
    /// `""` / `"ed25519"` → Ed25519 (default), `"mldsa65"` → ML-DSA-65
    /// (requires the engine built with `ssh_pqc`).
    pub algorithm: Option<String>,
    /// Operator-supplied OpenSSH private key to import. Mutually
    /// exclusive with `algorithm`; if both are present the engine
    /// uses the imported key and the algorithm is inferred.
    pub private_key: Option<String>,
}

#[tauri::command]
pub async fn ssh_generate_ca(
    state: State<'_, AppState>,
    request: SshGenerateCaRequest,
) -> CmdResult<SshCaInfo> {
    let path = format!("{}/config/ca", mount_prefix(&request.mount));
    let mut body = Map::new();
    if let Some(a) = request.algorithm.as_ref().filter(|s| !s.is_empty()) {
        body.insert("algorithm".into(), Value::String(a.clone()));
    }
    if let Some(k) = request.private_key.as_ref().filter(|s| !s.is_empty()) {
        body.insert("private_key".into(), Value::String(k.clone()));
    }
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let map = data_to_map(resp);
    Ok(SshCaInfo {
        public_key: val_str(&map, "public_key"),
        algorithm: val_str(&map, "algorithm"),
    })
}

#[tauri::command]
pub async fn ssh_delete_ca(state: State<'_, AppState>, mount: String) -> CmdResult<()> {
    let path = format!("{}/config/ca", mount_prefix(&mount));
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

// ── Roles ─────────────────────────────────────────────────────────

/// GUI-side role view. Mirrors the server's `RoleEntry` shape but
/// with durations exposed as the same humantime-friendly strings the
/// server accepts on writes — operators round-trip them through
/// the form unchanged.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SshRoleConfig {
    pub key_type: String,
    pub algorithm_signer: String,
    pub cert_type: String,
    pub allowed_users: String,
    pub default_user: String,
    pub allowed_extensions: String,
    pub default_extensions: std::collections::BTreeMap<String, String>,
    pub allowed_critical_options: String,
    pub default_critical_options: std::collections::BTreeMap<String, String>,
    pub ttl: String,
    pub max_ttl: String,
    pub not_before_duration: String,
    pub key_id_format: String,
    // Phase 2 OTP fields.
    pub cidr_list: String,
    pub exclude_cidr_list: String,
    pub port: u16,
    // Phase 3 PQC field.
    pub pqc_only: bool,
}

#[tauri::command]
pub async fn ssh_list_roles(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<Vec<String>> {
    let path = format!("{}/roles", mount_prefix(&mount));
    let resp = make_request(&state, Operation::List, path, None).await?;
    let map = data_to_map(resp);
    let keys = map
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(keys)
}

#[tauri::command]
pub async fn ssh_read_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<SshRoleConfig> {
    let path = format!("{}/roles/{}", mount_prefix(&mount), name);
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let map = data_to_map(resp);

    // Durations come back as raw seconds in the engine's serde
    // round-trip. Render them as `<n>s` so the form keeps round-tripping
    // through the same humantime parser the server uses on writes.
    let dur_str = |k: &str| -> String {
        match map.get(k) {
            Some(v) if v.is_number() => format!("{}s", v.as_u64().unwrap_or(0)),
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    };

    let kv_map = |k: &str| -> std::collections::BTreeMap<String, String> {
        map.get(k)
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(SshRoleConfig {
        key_type: val_str(&map, "key_type"),
        algorithm_signer: val_str(&map, "algorithm_signer"),
        cert_type: val_str(&map, "cert_type"),
        allowed_users: val_str(&map, "allowed_users"),
        default_user: val_str(&map, "default_user"),
        allowed_extensions: val_str(&map, "allowed_extensions"),
        default_extensions: kv_map("default_extensions"),
        allowed_critical_options: val_str(&map, "allowed_critical_options"),
        default_critical_options: kv_map("default_critical_options"),
        ttl: dur_str("ttl"),
        max_ttl: dur_str("max_ttl"),
        not_before_duration: dur_str("not_before_duration"),
        key_id_format: val_str(&map, "key_id_format"),
        cidr_list: val_str(&map, "cidr_list"),
        exclude_cidr_list: val_str(&map, "exclude_cidr_list"),
        port: val_u64(&map, "port") as u16,
        pqc_only: val_bool(&map, "pqc_only"),
    })
}

#[tauri::command]
pub async fn ssh_write_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
    config: SshRoleConfig,
) -> CmdResult<()> {
    let path = format!("{}/roles/{}", mount_prefix(&mount), name);

    // Translate the GUI struct into the engine's request body. We
    // skip empty strings on optional fields so the partial-update
    // semantics on the server preserve any existing value the
    // operator didn't touch this round.
    let mut body = Map::new();
    let push_str = |body: &mut Map<String, Value>, k: &str, v: &str| {
        if !v.is_empty() {
            body.insert(k.into(), Value::String(v.into()));
        }
    };
    push_str(&mut body, "key_type", &config.key_type);
    push_str(&mut body, "algorithm_signer", &config.algorithm_signer);
    push_str(&mut body, "cert_type", &config.cert_type);
    push_str(&mut body, "allowed_users", &config.allowed_users);
    push_str(&mut body, "default_user", &config.default_user);
    push_str(&mut body, "allowed_extensions", &config.allowed_extensions);
    push_str(&mut body, "allowed_critical_options", &config.allowed_critical_options);
    push_str(&mut body, "ttl", &config.ttl);
    push_str(&mut body, "max_ttl", &config.max_ttl);
    push_str(&mut body, "not_before_duration", &config.not_before_duration);
    push_str(&mut body, "key_id_format", &config.key_id_format);
    push_str(&mut body, "cidr_list", &config.cidr_list);
    push_str(&mut body, "exclude_cidr_list", &config.exclude_cidr_list);
    if config.port != 0 {
        body.insert("port".into(), Value::Number(config.port.into()));
    }
    if config.pqc_only {
        body.insert("pqc_only".into(), Value::Bool(true));
    }

    // Maps round-trip as serde_json objects — the engine handler
    // matches on `Value::Object`.
    let to_obj = |m: &std::collections::BTreeMap<String, String>| -> Value {
        let mut out = Map::new();
        for (k, v) in m {
            out.insert(k.clone(), Value::String(v.clone()));
        }
        Value::Object(out)
    };
    body.insert("default_extensions".into(), to_obj(&config.default_extensions));
    body.insert(
        "default_critical_options".into(),
        to_obj(&config.default_critical_options),
    );

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ssh_delete_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    let path = format!("{}/roles/{}", mount_prefix(&mount), name);
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

// ── Sign (CA mode) ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SshSignRequest {
    pub mount: String,
    pub role: String,
    pub public_key: String,
    pub valid_principals: Option<String>,
    pub ttl: Option<String>,
    pub cert_type: Option<String>,
    pub key_id: Option<String>,
}

#[derive(Serialize, Default)]
pub struct SshSignResult {
    pub signed_key: String,
    pub serial_number: String,
    /// Algorithm string the server picked (`ssh-ed25519` for the
    /// classical path, `ssh-mldsa65@openssh.com` for the PQC path).
    /// Empty when the server didn't surface it (Phase 1 classical).
    pub algorithm: String,
}

#[tauri::command]
pub async fn ssh_sign(state: State<'_, AppState>, request: SshSignRequest) -> CmdResult<SshSignResult> {
    let path = format!("{}/sign/{}", mount_prefix(&request.mount), request.role);
    let mut body = Map::new();
    body.insert("public_key".into(), Value::String(request.public_key));
    if let Some(p) = request.valid_principals.filter(|s| !s.is_empty()) {
        body.insert("valid_principals".into(), Value::String(p));
    }
    if let Some(t) = request.ttl.filter(|s| !s.is_empty()) {
        body.insert("ttl".into(), Value::String(t));
    }
    if let Some(c) = request.cert_type.filter(|s| !s.is_empty()) {
        body.insert("cert_type".into(), Value::String(c));
    }
    if let Some(k) = request.key_id.filter(|s| !s.is_empty()) {
        body.insert("key_id".into(), Value::String(k));
    }
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let map = data_to_map(resp);
    Ok(SshSignResult {
        signed_key: val_str(&map, "signed_key"),
        serial_number: val_str(&map, "serial_number"),
        algorithm: val_str(&map, "algorithm"),
    })
}

// ── OTP creds (OTP mode) ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct SshCredsRequest {
    pub mount: String,
    pub role: String,
    pub ip: String,
    pub username: Option<String>,
    pub ttl: Option<String>,
}

#[derive(Serialize, Default)]
pub struct SshCredsResult {
    pub key: String,
    pub key_type: String,
    pub username: String,
    pub ip: String,
    pub port: u64,
    pub ttl: u64,
}

#[tauri::command]
pub async fn ssh_creds(
    state: State<'_, AppState>,
    request: SshCredsRequest,
) -> CmdResult<SshCredsResult> {
    let path = format!("{}/creds/{}", mount_prefix(&request.mount), request.role);
    let mut body = Map::new();
    body.insert("ip".into(), Value::String(request.ip));
    if let Some(u) = request.username.filter(|s| !s.is_empty()) {
        body.insert("username".into(), Value::String(u));
    }
    if let Some(t) = request.ttl.filter(|s| !s.is_empty()) {
        body.insert("ttl".into(), Value::String(t));
    }
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let map = data_to_map(resp);
    Ok(SshCredsResult {
        key: val_str(&map, "key"),
        key_type: val_str(&map, "key_type"),
        username: val_str(&map, "username"),
        ip: val_str(&map, "ip"),
        port: val_u64(&map, "port"),
        ttl: val_u64(&map, "ttl"),
    })
}

#[derive(Deserialize)]
pub struct SshLookupRequest {
    pub mount: String,
    pub ip: String,
    pub username: Option<String>,
}

#[derive(Serialize, Default)]
pub struct SshLookupResult {
    pub roles: Vec<String>,
}

#[tauri::command]
pub async fn ssh_lookup(
    state: State<'_, AppState>,
    request: SshLookupRequest,
) -> CmdResult<SshLookupResult> {
    let path = format!("{}/lookup", mount_prefix(&request.mount));
    let mut body = Map::new();
    body.insert("ip".into(), Value::String(request.ip));
    if let Some(u) = request.username.filter(|s| !s.is_empty()) {
        body.insert("username".into(), Value::String(u));
    }
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let map = data_to_map(resp);
    let roles = map
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(SshLookupResult { roles })
}
