//! Tauri commands bridging the desktop GUI to the PKI Secret Engine.
//!
//! Mirrors the pattern in `commands/approle.rs`: every command is a thin
//! wrapper over `make_request` that routes to a `pki/<route>` path under a
//! caller-provided mount, then projects the response data into a
//! GUI-friendly serializable struct. The mount path is parameterised so
//! one mount of the engine can be administered per call (the operator can
//! mount PKI at any path via `sys/mounts/<path>/`).

use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
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

/// Normalise an operator-supplied mount string into the form the router
/// expects. We accept either `pki` or `pki/`; downstream code always
/// concatenates with `/<route>`.
fn mount_prefix(mount: &str) -> String {
    let trimmed = mount.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "pki".to_string()
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

fn val_i64(map: &Map<String, Value>, key: &str) -> i64 {
    map.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}

fn val_bool(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn val_str_array(map: &Map<String, Value>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

// ── Mount lifecycle ───────────────────────────────────────────────

#[derive(Serialize)]
pub struct PkiMountInfo {
    pub path: String,
    pub mount_type: String,
}

/// List every mount of `type = "pki"` so the GUI can show a mount
/// picker. Calls `sys/mounts` and filters; cheap enough to do per-page
/// load.
#[tauri::command]
pub async fn pki_list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<PkiMountInfo>> {
    let resp = make_request(&state, Operation::Read, "sys/mounts".into(), None).await?;
    let map = data_to_map(resp);
    let mut out = Vec::new();
    for (path, info) in map.iter() {
        if let Some(t) = info.get("type").and_then(|v| v.as_str()) {
            if t == "pki" {
                out.push(PkiMountInfo { path: path.clone(), mount_type: t.to_string() });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Mount the PKI engine at `path/`. Operator-friendly equivalent of
/// `POST /v1/sys/mounts/<path>/` with `type=pki`.
#[tauri::command]
pub async fn pki_enable_mount(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let path = path.trim_end_matches('/');
    let body = json!({"type": "pki"}).as_object().cloned().unwrap_or_default();
    make_request(&state, Operation::Write, format!("sys/mounts/{path}/"), Some(body)).await?;
    Ok(())
}

// ── Issuers ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PkiIssuerSummary {
    pub id: String,
    pub name: String,
    pub is_default: bool,
}

#[derive(Serialize)]
pub struct PkiIssuerListResult {
    pub issuers: Vec<PkiIssuerSummary>,
}

/// `LIST /v1/<mount>/issuers` — projection: `{keys, key_info}` →
/// flat `Vec<PkiIssuerSummary>` so the GUI can render a single table.
#[tauri::command]
pub async fn pki_list_issuers(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<PkiIssuerListResult> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::List, format!("{mount}/issuers"), None).await?;
    let map = data_to_map(resp);
    let keys = val_str_array(&map, "keys");
    let key_info = map.get("key_info").and_then(|v| v.as_object()).cloned().unwrap_or_default();

    let mut issuers = Vec::with_capacity(keys.len());
    for id in keys {
        let entry = key_info.get(&id).and_then(|v| v.as_object()).cloned().unwrap_or_default();
        issuers.push(PkiIssuerSummary {
            id: id.clone(),
            name: val_str(&entry, "name"),
            is_default: val_bool(&entry, "is_default"),
        });
    }
    Ok(PkiIssuerListResult { issuers })
}

#[derive(Serialize)]
pub struct PkiIssuerDetail {
    pub id: String,
    pub name: String,
    pub certificate: String,
    pub key_type: String,
    pub common_name: String,
    pub not_after: i64,
    pub ca_kind: String,
    pub is_default: bool,
    pub usage: Vec<String>,
}

#[tauri::command]
pub async fn pki_read_issuer(
    state: State<'_, AppState>,
    mount: String,
    reference: String,
) -> CmdResult<PkiIssuerDetail> {
    let mount = mount_prefix(&mount);
    let resp =
        make_request(&state, Operation::Read, format!("{mount}/issuer/{reference}"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiIssuerDetail {
        id: val_str(&map, "issuer_id"),
        name: val_str(&map, "issuer_name"),
        certificate: val_str(&map, "certificate"),
        key_type: val_str(&map, "key_type"),
        common_name: val_str(&map, "common_name"),
        not_after: val_i64(&map, "not_after"),
        ca_kind: val_str(&map, "ca_kind"),
        is_default: val_bool(&map, "is_default"),
        usage: val_str_array(&map, "usage"),
    })
}

#[tauri::command]
pub async fn pki_rename_issuer(
    state: State<'_, AppState>,
    mount: String,
    reference: String,
    new_name: String,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let body = json!({"issuer_name": new_name}).as_object().cloned().unwrap_or_default();
    make_request(&state, Operation::Write, format!("{mount}/issuer/{reference}"), Some(body))
        .await?;
    Ok(())
}

#[tauri::command]
pub async fn pki_set_issuer_usages(
    state: State<'_, AppState>,
    mount: String,
    reference: String,
    usages: Vec<String>,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    // Engine accepts a comma-separated `usage` string.
    let usage_str = usages.join(",");
    let body = json!({"usage": usage_str}).as_object().cloned().unwrap_or_default();
    make_request(&state, Operation::Write, format!("{mount}/issuer/{reference}"), Some(body))
        .await?;
    Ok(())
}

#[tauri::command]
pub async fn pki_delete_issuer(
    state: State<'_, AppState>,
    mount: String,
    reference: String,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    make_request(&state, Operation::Delete, format!("{mount}/issuer/{reference}"), None).await?;
    Ok(())
}

#[derive(Serialize)]
pub struct PkiDefaultIssuer {
    pub default: String,
    pub default_name: String,
}

#[tauri::command]
pub async fn pki_read_default_issuer(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<PkiDefaultIssuer> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/config/issuers"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiDefaultIssuer { default: val_str(&map, "default"), default_name: val_str(&map, "default_name") })
}

#[tauri::command]
pub async fn pki_set_default_issuer(
    state: State<'_, AppState>,
    mount: String,
    reference: String,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let body = json!({"default": reference}).as_object().cloned().unwrap_or_default();
    make_request(&state, Operation::Write, format!("{mount}/config/issuers"), Some(body)).await?;
    Ok(())
}

// ── Root + intermediate lifecycle ─────────────────────────────────

#[derive(Deserialize)]
pub struct PkiGenerateRootRequest {
    pub mount: String,
    pub mode: String, // "internal" | "exported"
    pub common_name: String,
    pub organization: Option<String>,
    pub key_type: Option<String>,
    pub key_bits: Option<u64>,
    pub ttl: Option<String>,
    pub issuer_name: Option<String>,
    /// Phase L3: promote a managed key (by id or name) to root issuer.
    pub key_ref: Option<String>,
}

#[derive(Serialize)]
pub struct PkiRootResult {
    pub certificate: String,
    pub issuer_id: String,
    pub issuer_name: String,
    pub expiration: i64,
    /// Only populated in `exported` mode AND when `key_ref` was not used.
    pub private_key: Option<String>,
    pub private_key_type: Option<String>,
    /// Phase L3: when `key_ref` was used, the resolved managed key UUID.
    #[serde(default)]
    pub key_id: String,
}

#[tauri::command]
pub async fn pki_generate_root(
    state: State<'_, AppState>,
    request: PkiGenerateRootRequest,
) -> CmdResult<PkiRootResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("common_name".into(), json!(request.common_name));
    if let Some(o) = request.organization {
        body.insert("organization".into(), json!(o));
    }
    if let Some(k) = request.key_type {
        body.insert("key_type".into(), json!(k));
    }
    if let Some(b) = request.key_bits {
        body.insert("key_bits".into(), json!(b));
    }
    if let Some(t) = request.ttl {
        body.insert("ttl".into(), json!(t));
    }
    if let Some(n) = request.issuer_name {
        body.insert("issuer_name".into(), json!(n));
    }
    if let Some(k) = request.key_ref.filter(|s| !s.is_empty()) {
        body.insert("key_ref".into(), json!(k));
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{mount}/root/generate/{}", request.mode),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiRootResult {
        certificate: val_str(&map, "certificate"),
        issuer_id: val_str(&map, "issuer_id"),
        issuer_name: val_str(&map, "issuer_name"),
        expiration: val_i64(&map, "expiration"),
        private_key: map.get("private_key").and_then(|v| v.as_str()).map(String::from),
        private_key_type: map.get("private_key_type").and_then(|v| v.as_str()).map(String::from),
        key_id: val_str(&map, "key_id"),
    })
}

#[derive(Deserialize)]
pub struct PkiGenerateIntermediateRequest {
    pub mount: String,
    pub mode: String,
    pub common_name: String,
    pub organization: Option<String>,
    pub key_type: Option<String>,
    pub key_bits: Option<u64>,
    /// Phase L3: back the pending intermediate with a managed key.
    pub key_ref: Option<String>,
}

#[derive(Serialize)]
pub struct PkiIntermediateResult {
    pub csr: String,
    pub private_key: Option<String>,
    pub private_key_type: Option<String>,
    /// Phase L3: when `key_ref` was used, the resolved managed key UUID.
    #[serde(default)]
    pub key_id: String,
}

#[tauri::command]
pub async fn pki_generate_intermediate(
    state: State<'_, AppState>,
    request: PkiGenerateIntermediateRequest,
) -> CmdResult<PkiIntermediateResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("common_name".into(), json!(request.common_name));
    if let Some(o) = request.organization {
        body.insert("organization".into(), json!(o));
    }
    if let Some(k) = request.key_type {
        body.insert("key_type".into(), json!(k));
    }
    if let Some(b) = request.key_bits {
        body.insert("key_bits".into(), json!(b));
    }
    if let Some(k) = request.key_ref.filter(|s| !s.is_empty()) {
        body.insert("key_ref".into(), json!(k));
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{mount}/intermediate/generate/{}", request.mode),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiIntermediateResult {
        csr: val_str(&map, "csr"),
        private_key: map.get("private_key").and_then(|v| v.as_str()).map(String::from),
        private_key_type: map.get("private_key_type").and_then(|v| v.as_str()).map(String::from),
        key_id: val_str(&map, "key_id"),
    })
}

#[derive(Deserialize)]
pub struct PkiSetSignedIntermediateRequest {
    pub mount: String,
    pub certificate: String,
    pub issuer_name: Option<String>,
}

#[derive(Serialize)]
pub struct PkiSetSignedResult {
    pub issuer_id: String,
    pub issuer_name: String,
}

#[tauri::command]
pub async fn pki_set_signed_intermediate(
    state: State<'_, AppState>,
    request: PkiSetSignedIntermediateRequest,
) -> CmdResult<PkiSetSignedResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("certificate".into(), json!(request.certificate));
    if let Some(n) = request.issuer_name {
        body.insert("issuer_name".into(), json!(n));
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{mount}/intermediate/set-signed"),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiSetSignedResult { issuer_id: val_str(&map, "issuer_id"), issuer_name: val_str(&map, "issuer_name") })
}

#[derive(Deserialize)]
pub struct PkiSignIntermediateRequest {
    pub mount: String,
    pub csr: String,
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub ttl: Option<String>,
    pub max_path_length: Option<i64>,
    pub issuer_ref: Option<String>,
}

#[derive(Serialize)]
pub struct PkiSignIntermediateResult {
    pub certificate: String,
    pub issuing_ca: String,
}

#[tauri::command]
pub async fn pki_sign_intermediate(
    state: State<'_, AppState>,
    request: PkiSignIntermediateRequest,
) -> CmdResult<PkiSignIntermediateResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("csr".into(), json!(request.csr));
    if let Some(cn) = request.common_name {
        body.insert("common_name".into(), json!(cn));
    }
    if let Some(o) = request.organization {
        body.insert("organization".into(), json!(o));
    }
    if let Some(t) = request.ttl {
        body.insert("ttl".into(), json!(t));
    }
    if let Some(m) = request.max_path_length {
        body.insert("max_path_length".into(), json!(m));
    }
    if let Some(r) = request.issuer_ref {
        body.insert("issuer_ref".into(), json!(r));
    }
    let resp =
        make_request(&state, Operation::Write, format!("{mount}/root/sign-intermediate"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiSignIntermediateResult {
        certificate: val_str(&map, "certificate"),
        issuing_ca: val_str(&map, "issuing_ca"),
    })
}

#[derive(Deserialize)]
pub struct PkiImportCaBundleRequest {
    pub mount: String,
    pub pem_bundle: String,
    pub issuer_name: Option<String>,
}

#[tauri::command]
pub async fn pki_import_ca_bundle(
    state: State<'_, AppState>,
    request: PkiImportCaBundleRequest,
) -> CmdResult<PkiSetSignedResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("pem_bundle".into(), json!(request.pem_bundle));
    if let Some(n) = request.issuer_name {
        body.insert("issuer_name".into(), json!(n));
    }
    let resp = make_request(&state, Operation::Write, format!("{mount}/config/ca"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiSetSignedResult { issuer_id: val_str(&map, "issuer_id"), issuer_name: val_str(&map, "issuer_name") })
}

// ── Roles ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct PkiRoleConfig {
    pub ttl: String,
    pub max_ttl: String,
    pub key_type: String,
    pub key_bits: u64,
    pub allow_localhost: bool,
    pub allow_any_name: bool,
    pub allow_subdomains: bool,
    pub allow_bare_domains: bool,
    pub allow_ip_sans: bool,
    pub server_flag: bool,
    pub client_flag: bool,
    pub use_csr_sans: bool,
    pub use_csr_common_name: bool,
    pub key_usage: Vec<String>,
    pub ext_key_usage: Vec<String>,
    pub country: String,
    pub province: String,
    pub locality: String,
    pub organization: String,
    pub ou: String,
    pub no_store: bool,
    pub generate_lease: bool,
    pub issuer_ref: String,
    // Phase L2 — key reuse on issue/sign
    #[serde(default)]
    pub allow_key_reuse: bool,
    #[serde(default)]
    pub allowed_key_refs: Vec<String>,
    // Phase L4 — emission controls
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allow_glob_domains: bool,
    #[serde(default = "default_acme_enabled")]
    pub acme_enabled: bool,
}

fn default_acme_enabled() -> bool {
    true
}

impl Default for PkiRoleConfig {
    fn default() -> Self {
        Self {
            ttl: String::new(),
            max_ttl: String::new(),
            key_type: "ec".into(),
            key_bits: 0,
            allow_localhost: true,
            allow_any_name: true,
            allow_subdomains: false,
            allow_bare_domains: false,
            allow_ip_sans: true,
            server_flag: true,
            client_flag: true,
            use_csr_sans: true,
            use_csr_common_name: true,
            key_usage: vec!["DigitalSignature".into(), "KeyEncipherment".into()],
            ext_key_usage: vec![],
            country: String::new(),
            province: String::new(),
            locality: String::new(),
            organization: String::new(),
            ou: String::new(),
            no_store: false,
            generate_lease: false,
            issuer_ref: String::new(),
            allow_key_reuse: false,
            allowed_key_refs: Vec::new(),
            allowed_domains: Vec::new(),
            allow_glob_domains: false,
            acme_enabled: true,
        }
    }
}

#[tauri::command]
pub async fn pki_list_roles(state: State<'_, AppState>, mount: String) -> CmdResult<Vec<String>> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::List, format!("{mount}/roles"), None).await?;
    Ok(val_str_array(&data_to_map(resp), "keys"))
}

#[tauri::command]
pub async fn pki_read_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<PkiRoleConfig> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/roles/{name}"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiRoleConfig {
        ttl: val_str(&map, "ttl"),
        max_ttl: val_str(&map, "max_ttl"),
        key_type: val_str(&map, "key_type"),
        key_bits: val_u64(&map, "key_bits"),
        allow_localhost: val_bool(&map, "allow_localhost"),
        allow_any_name: val_bool(&map, "allow_any_name"),
        allow_subdomains: val_bool(&map, "allow_subdomains"),
        allow_bare_domains: val_bool(&map, "allow_bare_domains"),
        allow_ip_sans: val_bool(&map, "allow_ip_sans"),
        server_flag: val_bool(&map, "server_flag"),
        client_flag: val_bool(&map, "client_flag"),
        use_csr_sans: val_bool(&map, "use_csr_sans"),
        use_csr_common_name: val_bool(&map, "use_csr_common_name"),
        key_usage: val_str_array(&map, "key_usage"),
        ext_key_usage: val_str_array(&map, "ext_key_usage"),
        country: val_str(&map, "country"),
        province: val_str(&map, "province"),
        locality: val_str(&map, "locality"),
        organization: val_str(&map, "organization"),
        ou: val_str(&map, "ou"),
        no_store: val_bool(&map, "no_store"),
        generate_lease: val_bool(&map, "generate_lease"),
        issuer_ref: val_str(&map, "issuer_ref"),
        allow_key_reuse: val_bool(&map, "allow_key_reuse"),
        allowed_key_refs: val_str_array(&map, "allowed_key_refs"),
        allowed_domains: val_str_array(&map, "allowed_domains"),
        allow_glob_domains: val_bool(&map, "allow_glob_domains"),
        // pre-L4 roles deserialise without `acme_enabled` — default true
        // matches the engine's serde default.
        acme_enabled: map.get("acme_enabled").and_then(|v| v.as_bool()).unwrap_or(true),
    })
}

#[tauri::command]
pub async fn pki_write_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
    config: PkiRoleConfig,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let mut body = Map::new();
    body.insert("ttl".into(), json!(config.ttl));
    body.insert("max_ttl".into(), json!(config.max_ttl));
    body.insert("key_type".into(), json!(config.key_type));
    body.insert("key_bits".into(), json!(config.key_bits));
    body.insert("allow_localhost".into(), json!(config.allow_localhost));
    body.insert("allow_any_name".into(), json!(config.allow_any_name));
    body.insert("allow_subdomains".into(), json!(config.allow_subdomains));
    body.insert("allow_bare_domains".into(), json!(config.allow_bare_domains));
    body.insert("allow_ip_sans".into(), json!(config.allow_ip_sans));
    body.insert("server_flag".into(), json!(config.server_flag));
    body.insert("client_flag".into(), json!(config.client_flag));
    body.insert("use_csr_sans".into(), json!(config.use_csr_sans));
    body.insert("use_csr_common_name".into(), json!(config.use_csr_common_name));
    body.insert("key_usage".into(), json!(config.key_usage.join(",")));
    body.insert("ext_key_usage".into(), json!(config.ext_key_usage.join(",")));
    body.insert("country".into(), json!(config.country));
    body.insert("province".into(), json!(config.province));
    body.insert("locality".into(), json!(config.locality));
    body.insert("organization".into(), json!(config.organization));
    body.insert("ou".into(), json!(config.ou));
    body.insert("no_store".into(), json!(config.no_store));
    body.insert("generate_lease".into(), json!(config.generate_lease));
    if !config.issuer_ref.is_empty() {
        body.insert("issuer_ref".into(), json!(config.issuer_ref));
    }
    body.insert("allow_key_reuse".into(), json!(config.allow_key_reuse));
    body.insert("allowed_key_refs".into(), json!(config.allowed_key_refs.join(",")));
    body.insert("allowed_domains".into(), json!(config.allowed_domains.join(",")));
    body.insert("allow_glob_domains".into(), json!(config.allow_glob_domains));
    body.insert("acme_enabled".into(), json!(config.acme_enabled));
    make_request(&state, Operation::Write, format!("{mount}/roles/{name}"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn pki_delete_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    make_request(&state, Operation::Delete, format!("{mount}/roles/{name}"), None).await?;
    Ok(())
}

// ── Issuance ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PkiIssueRequest {
    pub mount: String,
    pub role: String,
    pub common_name: String,
    pub alt_names: Option<String>,
    pub ip_sans: Option<String>,
    pub ttl: Option<String>,
    pub issuer_ref: Option<String>,
    /// Phase L2: pin issuance to a managed key from `pki/keys/*`.
    pub key_ref: Option<String>,
}

#[derive(Serialize)]
pub struct PkiIssueResult {
    pub certificate: String,
    pub issuing_ca: String,
    pub private_key: String,
    pub private_key_type: String,
    pub serial_number: String,
    pub issuer_id: String,
    /// Phase L3: leaf-issuer → root chain.
    #[serde(default)]
    pub ca_chain: Vec<String>,
    /// Phase L2: when `key_ref` was used, the resolved managed key UUID.
    #[serde(default)]
    pub key_id: String,
}

#[tauri::command]
pub async fn pki_issue_cert(
    state: State<'_, AppState>,
    request: PkiIssueRequest,
) -> CmdResult<PkiIssueResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("common_name".into(), json!(request.common_name));
    if let Some(a) = request.alt_names {
        body.insert("alt_names".into(), json!(a));
    }
    if let Some(i) = request.ip_sans {
        body.insert("ip_sans".into(), json!(i));
    }
    if let Some(t) = request.ttl {
        body.insert("ttl".into(), json!(t));
    }
    if let Some(r) = request.issuer_ref {
        body.insert("issuer_ref".into(), json!(r));
    }
    if let Some(k) = request.key_ref.filter(|s| !s.is_empty()) {
        body.insert("key_ref".into(), json!(k));
    }
    let resp =
        make_request(&state, Operation::Write, format!("{mount}/issue/{}", request.role), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiIssueResult {
        certificate: val_str(&map, "certificate"),
        issuing_ca: val_str(&map, "issuing_ca"),
        private_key: val_str(&map, "private_key"),
        private_key_type: val_str(&map, "private_key_type"),
        serial_number: val_str(&map, "serial_number"),
        issuer_id: val_str(&map, "issuer_id"),
        ca_chain: val_str_array(&map, "ca_chain"),
        key_id: val_str(&map, "key_id"),
    })
}

#[derive(Deserialize)]
pub struct PkiSignCsrRequest {
    pub mount: String,
    pub role: String,
    pub csr: String,
    pub common_name: Option<String>,
    pub alt_names: Option<String>,
    pub ttl: Option<String>,
    pub issuer_ref: Option<String>,
    /// Phase L2: assert the CSR's SPKI matches a managed key.
    pub key_ref: Option<String>,
}

#[derive(Serialize)]
pub struct PkiSignResult {
    pub certificate: String,
    pub issuing_ca: String,
    pub serial_number: String,
    pub issuer_id: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
    #[serde(default)]
    pub key_id: String,
}

#[tauri::command]
pub async fn pki_sign_csr(
    state: State<'_, AppState>,
    request: PkiSignCsrRequest,
) -> CmdResult<PkiSignResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("csr".into(), json!(request.csr));
    if let Some(cn) = request.common_name {
        body.insert("common_name".into(), json!(cn));
    }
    if let Some(a) = request.alt_names {
        body.insert("alt_names".into(), json!(a));
    }
    if let Some(t) = request.ttl {
        body.insert("ttl".into(), json!(t));
    }
    if let Some(r) = request.issuer_ref {
        body.insert("issuer_ref".into(), json!(r));
    }
    if let Some(k) = request.key_ref.filter(|s| !s.is_empty()) {
        body.insert("key_ref".into(), json!(k));
    }
    let resp =
        make_request(&state, Operation::Write, format!("{mount}/sign/{}", request.role), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiSignResult {
        certificate: val_str(&map, "certificate"),
        issuing_ca: val_str(&map, "issuing_ca"),
        serial_number: val_str(&map, "serial_number"),
        issuer_id: val_str(&map, "issuer_id"),
        ca_chain: val_str_array(&map, "ca_chain"),
        key_id: val_str(&map, "key_id"),
    })
}

#[derive(Deserialize)]
pub struct PkiSignVerbatimRequest {
    pub mount: String,
    pub csr: String,
    pub ttl: Option<String>,
    pub issuer_ref: Option<String>,
}

#[tauri::command]
pub async fn pki_sign_verbatim(
    state: State<'_, AppState>,
    request: PkiSignVerbatimRequest,
) -> CmdResult<PkiSignResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("csr".into(), json!(request.csr));
    if let Some(t) = request.ttl {
        body.insert("ttl".into(), json!(t));
    }
    if let Some(r) = request.issuer_ref {
        body.insert("issuer_ref".into(), json!(r));
    }
    let resp = make_request(&state, Operation::Write, format!("{mount}/sign-verbatim"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiSignResult {
        certificate: val_str(&map, "certificate"),
        issuing_ca: val_str(&map, "issuing_ca"),
        serial_number: val_str(&map, "serial_number"),
        issuer_id: val_str(&map, "issuer_id"),
        ca_chain: val_str_array(&map, "ca_chain"),
        key_id: val_str(&map, "key_id"),
    })
}

// ── Cert lifecycle ───────────────────────────────────────────────

#[tauri::command]
pub async fn pki_list_certs(state: State<'_, AppState>, mount: String) -> CmdResult<Vec<String>> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::List, format!("{mount}/certs"), None).await?;
    Ok(val_str_array(&data_to_map(resp), "keys"))
}

#[derive(Serialize)]
pub struct PkiCertRecord {
    pub serial_number: String,
    pub certificate: String,
    pub issued_at: u64,
    pub revoked_at: Option<u64>,
    /// Subject Common Name parsed from the cert. Empty when the
    /// certificate's Subject has no CN attribute (uncommon but legal —
    /// the SAN would carry the identity in that case).
    #[serde(default)]
    pub common_name: String,
    /// Unix-seconds NotAfter from the cert's validity. `0` if the PEM
    /// fails to parse for any reason — the GUI surfaces "—" in that
    /// case rather than a wrong date.
    #[serde(default)]
    pub not_after: u64,
    /// True when the cert was indexed via `pki/certs/import` rather
    /// than issued by this engine — has no matching key, no issuer,
    /// CRL builder skips it.
    #[serde(default)]
    pub is_orphaned: bool,
    /// Provenance label set at import time (e.g. `xca-import`). Empty
    /// for engine-issued certs.
    #[serde(default)]
    pub source: String,
    /// UUID of the issuer that signed this cert when the engine
    /// knows. Empty for orphan imports and for pre-Phase-5.2 records
    /// (the migration shim leaves this absent).
    #[serde(default)]
    pub issuer_id: String,
    /// Issuer DN as text, parsed from the cert PEM. Always populated
    /// (the cert always has an Issuer field). The GUI's Certificates
    /// tab uses this as the human-readable Emitter cell, with a
    /// "owned" / "external" badge derived from `issuer_id` plus the
    /// mount's issuer registry.
    #[serde(default)]
    pub issuer_dn: String,
}

/// Parse `(common_name, not_after_unix, issuer_dn)` out of a PEM-
/// encoded certificate. Returns empty / 0 on any parse failure so
/// the caller can render a graceful fallback instead of erroring out
/// the whole list view. The `issuer_dn` field is the full RFC 4514
/// distinguished-name string (`x509-cert`'s `Display` impl), used by
/// the GUI's Emitter column when the cert was orphan-imported and
/// the engine has no `issuer_id` recorded for it.
fn parse_cert_meta(pem: &str) -> (String, u64, String) {
    use x509_cert::der::Decode;
    let Ok(der) = bastion_vault::modules::pki::csr::decode_pem_or_der(pem) else {
        return (String::new(), 0, String::new());
    };
    let Ok(cert) = x509_cert::Certificate::from_der(&der) else {
        return (String::new(), 0, String::new());
    };

    // Subject CN: walk the RDN sequence for the OID 2.5.4.3.
    let cn_oid: x509_cert::der::asn1::ObjectIdentifier =
        "2.5.4.3".parse().expect("CN OID literal is valid");
    let mut common_name = String::new();
    'outer: for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == cn_oid {
                if let Ok(s) = atv.value.decode_as::<x509_cert::der::asn1::PrintableStringRef<'_>>() {
                    common_name = s.as_str().to_string();
                    break 'outer;
                }
                if let Ok(s) = atv.value.decode_as::<x509_cert::der::asn1::Utf8StringRef<'_>>() {
                    common_name = s.as_str().to_string();
                    break 'outer;
                }
                if let Ok(s) = atv.value.decode_as::<x509_cert::der::asn1::Ia5StringRef<'_>>() {
                    common_name = s.as_str().to_string();
                    break 'outer;
                }
            }
        }
    }

    // NotAfter: x509-cert's Time enum exposes both `UtcTime` and
    // `GeneralTime`; both convert to `SystemTime` via `to_system_time()`.
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_system_time()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Issuer DN as RFC 4514 text — `x509-cert`'s `Display` impl on
    // `Name` walks the RDN sequence and produces e.g.
    // `CN=Test Root,O=Acme Inc.,C=US`. Empty string when the cert's
    // Issuer field is empty (rare; only seen on malformed test certs).
    let issuer_dn = cert.tbs_certificate.issuer.to_string();

    (common_name, not_after, issuer_dn)
}

#[tauri::command]
pub async fn pki_read_cert(
    state: State<'_, AppState>,
    mount: String,
    serial: String,
) -> CmdResult<PkiCertRecord> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/cert/{serial}"), None).await?;
    let map = data_to_map(resp);
    let certificate = val_str(&map, "certificate");
    let (common_name, not_after, issuer_dn) = parse_cert_meta(&certificate);
    Ok(PkiCertRecord {
        serial_number: val_str(&map, "serial_number"),
        certificate,
        issued_at: val_u64(&map, "issued_at"),
        revoked_at: map.get("revoked_at").and_then(|v| v.as_u64()),
        common_name,
        not_after,
        is_orphaned: map.get("is_orphaned").and_then(|v| v.as_bool()).unwrap_or(false),
        source: val_str(&map, "source"),
        issuer_id: val_str(&map, "issuer_id"),
        issuer_dn,
    })
}

#[derive(Deserialize)]
pub struct PkiImportCertRequest {
    pub mount: String,
    pub certificate: String,
    pub source: Option<String>,
}

#[derive(Serialize)]
pub struct PkiImportCertResult {
    pub serial_number: String,
    pub not_after: u64,
    pub is_orphaned: bool,
    pub source: String,
}

/// Index an externally-issued cert via `pki/certs/import`. The cert is
/// stored with `is_orphaned = true` and surfaces in `pki_list_certs` /
/// `pki_read_cert` alongside engine-issued certs. No key is stored;
/// the CRL builder skips orphaned records.
#[tauri::command]
pub async fn pki_import_cert(
    state: State<'_, AppState>,
    request: PkiImportCertRequest,
) -> CmdResult<PkiImportCertResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("certificate".into(), json!(request.certificate));
    if let Some(s) = request.source {
        body.insert("source".into(), json!(s));
    }
    let resp = make_request(&state, Operation::Write, format!("{mount}/certs/import"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiImportCertResult {
        serial_number: val_str(&map, "serial_number"),
        not_after: val_u64(&map, "not_after"),
        is_orphaned: map.get("is_orphaned").and_then(|v| v.as_bool()).unwrap_or(true),
        source: val_str(&map, "source"),
    })
}

#[derive(Serialize)]
pub struct PkiRevokeResult {
    pub revocation_time: u64,
    pub serial_number: String,
    pub issuer_id: String,
}

#[tauri::command]
pub async fn pki_revoke_cert(
    state: State<'_, AppState>,
    mount: String,
    serial: String,
) -> CmdResult<PkiRevokeResult> {
    let mount = mount_prefix(&mount);
    let body = json!({"serial_number": serial}).as_object().cloned().unwrap_or_default();
    let resp = make_request(&state, Operation::Write, format!("{mount}/revoke"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiRevokeResult {
        revocation_time: val_u64(&map, "revocation_time"),
        serial_number: val_str(&map, "serial_number"),
        issuer_id: val_str(&map, "issuer_id"),
    })
}

#[derive(Serialize)]
pub struct PkiCaResult {
    pub certificate: String,
    pub issuer_id: String,
    pub issuer_name: String,
}

#[tauri::command]
pub async fn pki_read_ca(state: State<'_, AppState>, mount: String) -> CmdResult<PkiCaResult> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/ca"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiCaResult {
        certificate: val_str(&map, "certificate"),
        issuer_id: val_str(&map, "issuer_id"),
        issuer_name: val_str(&map, "issuer_name"),
    })
}

#[derive(Serialize)]
pub struct PkiCrlResult {
    pub crl: String,
    pub issuer_id: String,
}

#[tauri::command]
pub async fn pki_read_crl(state: State<'_, AppState>, mount: String) -> CmdResult<PkiCrlResult> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/crl"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiCrlResult { crl: val_str(&map, "crl"), issuer_id: val_str(&map, "issuer_id") })
}

#[tauri::command]
pub async fn pki_read_issuer_crl(
    state: State<'_, AppState>,
    mount: String,
    reference: String,
) -> CmdResult<PkiCrlResult> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/issuer/{reference}/crl"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiCrlResult { crl: val_str(&map, "crl"), issuer_id: val_str(&map, "issuer_id") })
}

#[derive(Serialize)]
pub struct PkiRotateCrlResult {
    pub crl: String,
    pub crl_number: u64,
    pub issuer_id: String,
}

#[tauri::command]
pub async fn pki_rotate_crl(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<PkiRotateCrlResult> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Write, format!("{mount}/crl/rotate"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiRotateCrlResult {
        crl: val_str(&map, "crl"),
        crl_number: val_u64(&map, "crl_number"),
        issuer_id: val_str(&map, "issuer_id"),
    })
}

// ── Tidy + auto-tidy + URL/CRL config ─────────────────────────────

#[derive(Deserialize)]
pub struct PkiTidyRequest {
    pub mount: String,
    pub tidy_cert_store: Option<bool>,
    pub tidy_revoked_certs: Option<bool>,
    pub safety_buffer: Option<String>,
}

#[derive(Serialize)]
pub struct PkiTidyResult {
    pub certs_deleted: u64,
    pub revoked_entries_deleted: u64,
    pub duration_ms: u64,
    pub safety_buffer_seconds: u64,
}

#[tauri::command]
pub async fn pki_run_tidy(
    state: State<'_, AppState>,
    request: PkiTidyRequest,
) -> CmdResult<PkiTidyResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    if let Some(b) = request.tidy_cert_store {
        body.insert("tidy_cert_store".into(), json!(b));
    }
    if let Some(b) = request.tidy_revoked_certs {
        body.insert("tidy_revoked_certs".into(), json!(b));
    }
    if let Some(s) = request.safety_buffer {
        body.insert("safety_buffer".into(), json!(s));
    }
    let resp = make_request(&state, Operation::Write, format!("{mount}/tidy"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiTidyResult {
        certs_deleted: val_u64(&map, "certs_deleted"),
        revoked_entries_deleted: val_u64(&map, "revoked_entries_deleted"),
        duration_ms: val_u64(&map, "duration_ms"),
        safety_buffer_seconds: val_u64(&map, "safety_buffer_seconds"),
    })
}

#[derive(Serialize)]
pub struct PkiTidyStatus {
    pub last_run_at_unix: u64,
    pub last_run_duration_ms: u64,
    pub certs_deleted: u64,
    pub revoked_entries_deleted: u64,
    pub safety_buffer_seconds: u64,
    pub source: String,
}

#[tauri::command]
pub async fn pki_read_tidy_status(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<PkiTidyStatus> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/tidy-status"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiTidyStatus {
        last_run_at_unix: val_u64(&map, "last_run_at_unix"),
        last_run_duration_ms: val_u64(&map, "last_run_duration_ms"),
        certs_deleted: val_u64(&map, "certs_deleted"),
        revoked_entries_deleted: val_u64(&map, "revoked_entries_deleted"),
        safety_buffer_seconds: val_u64(&map, "safety_buffer_seconds"),
        source: val_str(&map, "source"),
    })
}

#[derive(Serialize, Deserialize)]
pub struct PkiAutoTidyConfig {
    pub enabled: bool,
    pub interval: String,
    pub tidy_cert_store: bool,
    pub tidy_revoked_certs: bool,
    pub safety_buffer: String,
}

#[tauri::command]
pub async fn pki_read_auto_tidy(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<PkiAutoTidyConfig> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/config/auto-tidy"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiAutoTidyConfig {
        enabled: val_bool(&map, "enabled"),
        interval: val_str(&map, "interval"),
        tidy_cert_store: val_bool(&map, "tidy_cert_store"),
        tidy_revoked_certs: val_bool(&map, "tidy_revoked_certs"),
        safety_buffer: val_str(&map, "safety_buffer"),
    })
}

#[tauri::command]
pub async fn pki_write_auto_tidy(
    state: State<'_, AppState>,
    mount: String,
    config: PkiAutoTidyConfig,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let mut body = Map::new();
    body.insert("enabled".into(), json!(config.enabled));
    body.insert("interval".into(), json!(config.interval));
    body.insert("tidy_cert_store".into(), json!(config.tidy_cert_store));
    body.insert("tidy_revoked_certs".into(), json!(config.tidy_revoked_certs));
    body.insert("safety_buffer".into(), json!(config.safety_buffer));
    make_request(&state, Operation::Write, format!("{mount}/config/auto-tidy"), Some(body)).await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct PkiUrlsConfig {
    pub issuing_certificates: Vec<String>,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_servers: Vec<String>,
}

#[tauri::command]
pub async fn pki_read_config_urls(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<PkiUrlsConfig> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/config/urls"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiUrlsConfig {
        issuing_certificates: val_str_array(&map, "issuing_certificates"),
        crl_distribution_points: val_str_array(&map, "crl_distribution_points"),
        ocsp_servers: val_str_array(&map, "ocsp_servers"),
    })
}

#[tauri::command]
pub async fn pki_write_config_urls(
    state: State<'_, AppState>,
    mount: String,
    config: PkiUrlsConfig,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let mut body = Map::new();
    body.insert("issuing_certificates".into(), json!(config.issuing_certificates.join(",")));
    body.insert("crl_distribution_points".into(), json!(config.crl_distribution_points.join(",")));
    body.insert("ocsp_servers".into(), json!(config.ocsp_servers.join(",")));
    make_request(&state, Operation::Write, format!("{mount}/config/urls"), Some(body)).await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct PkiCrlConfig {
    pub expiry: String,
    pub disable: bool,
}

#[tauri::command]
pub async fn pki_read_config_crl(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<PkiCrlConfig> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/config/crl"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiCrlConfig { expiry: val_str(&map, "expiry"), disable: val_bool(&map, "disable") })
}

#[tauri::command]
pub async fn pki_write_config_crl(
    state: State<'_, AppState>,
    mount: String,
    config: PkiCrlConfig,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let mut body = Map::new();
    body.insert("expiry".into(), json!(config.expiry));
    body.insert("disable".into(), json!(config.disable));
    make_request(&state, Operation::Write, format!("{mount}/config/crl"), Some(body)).await?;
    Ok(())
}

// ── Managed key store (Phase L1) ─────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct PkiManagedKey {
    pub key_id: String,
    #[serde(default)]
    pub name: String,
    pub key_type: String,
    #[serde(default)]
    pub key_bits: u64,
    #[serde(default)]
    pub public_key: String,
    pub source: String,
    #[serde(default)]
    pub exported: bool,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub issuer_ref_count: u64,
    #[serde(default)]
    pub cert_ref_count: u64,
}

#[tauri::command]
pub async fn pki_list_keys(state: State<'_, AppState>, mount: String) -> CmdResult<Vec<String>> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::List, format!("{mount}/keys"), None).await?;
    Ok(val_str_array(&data_to_map(resp), "keys"))
}

#[tauri::command]
pub async fn pki_read_key(
    state: State<'_, AppState>,
    mount: String,
    key_ref: String,
) -> CmdResult<PkiManagedKey> {
    let mount = mount_prefix(&mount);
    let resp =
        make_request(&state, Operation::Read, format!("{mount}/key/{key_ref}"), None).await?;
    let map = data_to_map(resp);
    Ok(PkiManagedKey {
        key_id: val_str(&map, "key_id"),
        name: val_str(&map, "name"),
        key_type: val_str(&map, "key_type"),
        key_bits: val_u64(&map, "key_bits"),
        public_key: val_str(&map, "public_key"),
        source: val_str(&map, "source"),
        exported: val_bool(&map, "exported"),
        created_at: val_u64(&map, "created_at"),
        issuer_ref_count: val_u64(&map, "issuer_ref_count"),
        cert_ref_count: val_u64(&map, "cert_ref_count"),
    })
}

#[derive(Deserialize)]
pub struct PkiGenerateKeyRequest {
    pub mount: String,
    /// `internal` (private not echoed) or `exported` (private returned once).
    pub mode: String,
    pub key_type: String,
    #[serde(default)]
    pub key_bits: u64,
    #[serde(default)]
    pub name: String,
}

#[derive(Serialize)]
pub struct PkiGenerateKeyResult {
    pub key_id: String,
    pub key_type: String,
    pub source: String,
    pub exported: bool,
    /// Only populated in `exported` mode.
    pub private_key: Option<String>,
    pub public_key: String,
    #[serde(default)]
    pub name: String,
}

#[tauri::command]
pub async fn pki_generate_key(
    state: State<'_, AppState>,
    request: PkiGenerateKeyRequest,
) -> CmdResult<PkiGenerateKeyResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("key_type".into(), json!(request.key_type));
    if request.key_bits > 0 {
        body.insert("key_bits".into(), json!(request.key_bits));
    }
    if !request.name.is_empty() {
        body.insert("name".into(), json!(request.name));
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{mount}/keys/generate/{}", request.mode),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiGenerateKeyResult {
        key_id: val_str(&map, "key_id"),
        key_type: val_str(&map, "key_type"),
        source: val_str(&map, "source"),
        exported: val_bool(&map, "exported"),
        private_key: map.get("private_key").and_then(|v| v.as_str()).map(String::from),
        public_key: val_str(&map, "public_key"),
        name: val_str(&map, "name"),
    })
}

#[derive(Deserialize)]
pub struct PkiImportKeyRequest {
    pub mount: String,
    pub private_key: String,
    #[serde(default)]
    pub name: String,
}

#[tauri::command]
pub async fn pki_import_key(
    state: State<'_, AppState>,
    request: PkiImportKeyRequest,
) -> CmdResult<PkiGenerateKeyResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("private_key".into(), json!(request.private_key));
    if !request.name.is_empty() {
        body.insert("name".into(), json!(request.name));
    }
    let resp =
        make_request(&state, Operation::Write, format!("{mount}/keys/import"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(PkiGenerateKeyResult {
        key_id: val_str(&map, "key_id"),
        key_type: val_str(&map, "key_type"),
        source: val_str(&map, "source"),
        exported: val_bool(&map, "exported"),
        private_key: None,
        public_key: val_str(&map, "public_key"),
        name: val_str(&map, "name"),
    })
}

#[tauri::command]
pub async fn pki_delete_key(
    state: State<'_, AppState>,
    mount: String,
    key_ref: String,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    make_request(&state, Operation::Delete, format!("{mount}/key/{key_ref}"), None).await?;
    Ok(())
}

// ── Issuer chain (Phase L3) ──────────────────────────────────────

#[derive(Serialize)]
pub struct PkiIssuerChain {
    pub issuer_id: String,
    pub issuer_name: String,
    pub ca_chain: Vec<String>,
    pub certificate_bundle: String,
}

#[tauri::command]
pub async fn pki_read_issuer_chain(
    state: State<'_, AppState>,
    mount: String,
    issuer_ref: String,
) -> CmdResult<PkiIssuerChain> {
    let mount = mount_prefix(&mount);
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{mount}/issuer/{issuer_ref}/chain"),
        None,
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiIssuerChain {
        issuer_id: val_str(&map, "issuer_id"),
        issuer_name: val_str(&map, "issuer_name"),
        ca_chain: val_str_array(&map, "ca_chain"),
        certificate_bundle: val_str(&map, "certificate_bundle"),
    })
}

// Avoid unused-import lints when individual command bodies don't use the
// `HashMap` re-export brought in by the `commands/` parent.
#[allow(dead_code)]
fn _unused_imports() {
    let _: HashMap<(), ()> = HashMap::new();
}
