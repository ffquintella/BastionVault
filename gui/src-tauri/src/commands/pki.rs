//! Tauri commands bridging the desktop GUI to the PKI Secret Engine.
//!
//! Mirrors the pattern in `commands/approle.rs`: every command is a thin
//! wrapper over `make_request` that routes to a `pki/<route>` path under a
//! caller-provided mount, then projects the response data into a
//! GUI-friendly serializable struct. The mount path is parameterised so
//! one mount of the engine can be administered per call (the operator can
//! mount PKI at any path via `sys/mounts/<path>/`).

use std::collections::HashMap;

use bv_client::{JsonResponse, Operation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

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

fn data_to_map(resp: Option<JsonResponse>) -> Map<String, Value> {
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
/// picker. Uses `sys/internal/ui/mounts`, which returns the mount
/// table filtered to entries the caller has any ACL access on —
/// so a `pki-user` token (no `sys/mounts` read) still gets back
/// the PKI mounts it is allowed to use. Response shape is
/// `{ "secret": { "<path>": { "type": "pki", ... }, ... }, "auth": {...} }`,
/// so we drill into `secret` before filtering on `type == "pki"`.
#[tauri::command]
pub async fn pki_list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<PkiMountInfo>> {
    let resp = make_request(
        &state,
        Operation::Read,
        "sys/internal/ui/mounts".into(),
        None,
    )
    .await?;
    let map = data_to_map(resp);
    let mut out = Vec::new();
    if let Some(Value::Object(secret)) = map.get("secret") {
        for (path, info) in secret.iter() {
            if let Some(t) = info.get("type").and_then(|v| v.as_str()) {
                if t == "pki" {
                    out.push(PkiMountInfo {
                        path: path.clone(),
                        mount_type: t.to_string(),
                    });
                }
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

/// Unmount (delete) the PKI engine at `path/`. Operator-friendly equivalent
/// of `DELETE /v1/sys/mounts/<path>/`. This is destructive: the barrier view
/// backing the mount is cleared, so every issuer, key, role, and stored
/// certificate under it is discarded. Like the mount write, it routes through
/// `sys/mounts/*`, which the server treats as a root/sudo path — a delegated
/// `pki-admin` token cannot unmount, so the GUI only offers this to full
/// admins.
#[tauri::command]
pub async fn pki_disable_mount(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let path = path.trim_end_matches('/');
    make_request(&state, Operation::Delete, format!("sys/mounts/{path}/"), None).await?;
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
    /// Phase L8: managed-key UUID this issuer's keypair lives under
    /// in the `pki/keys/*` store. Empty for pre-L8 records that
    /// haven't been re-read (the engine's lazy-migration shim
    /// populates this on first load).
    #[serde(default)]
    pub key_id: String,
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
        key_id: val_str(&map, "key_id"),
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

// ── External-signing CSR flow (`pki/csr/*`) ──────────────────────────

#[derive(Deserialize)]
pub struct PkiCsrGenerateRequest {
    pub mount: String,
    pub role: String,
    pub common_name: String,
    pub alt_names: Option<String>,
    pub ip_sans: Option<String>,
    pub key_ref: Option<String>,
    pub exported: Option<bool>,
}

#[derive(Serialize)]
pub struct PkiCsrGenerateResult {
    pub csr_id: String,
    pub csr: String,
    pub key_id: String,
    pub role: String,
    pub common_name: String,
    pub private_key: Option<String>,
    pub private_key_type: Option<String>,
}

#[tauri::command]
pub async fn pki_csr_generate(
    state: State<'_, AppState>,
    request: PkiCsrGenerateRequest,
) -> CmdResult<PkiCsrGenerateResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("role".into(), json!(request.role));
    body.insert("common_name".into(), json!(request.common_name));
    if let Some(s) = request.alt_names.filter(|s| !s.is_empty()) {
        body.insert("alt_names".into(), json!(s));
    }
    if let Some(s) = request.ip_sans.filter(|s| !s.is_empty()) {
        body.insert("ip_sans".into(), json!(s));
    }
    if let Some(k) = request.key_ref.filter(|s| !s.is_empty()) {
        body.insert("key_ref".into(), json!(k));
    }
    if request.exported.unwrap_or(false) {
        body.insert("exported".into(), json!(true));
    }
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{mount}/csr/generate"),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiCsrGenerateResult {
        csr_id: val_str(&map, "csr_id"),
        csr: val_str(&map, "csr"),
        key_id: val_str(&map, "key_id"),
        role: val_str(&map, "role"),
        common_name: val_str(&map, "common_name"),
        private_key: map.get("private_key").and_then(|v| v.as_str()).map(String::from),
        private_key_type: map.get("private_key_type").and_then(|v| v.as_str()).map(String::from),
    })
}

#[tauri::command]
pub async fn pki_csr_list(state: State<'_, AppState>, mount: String) -> CmdResult<Vec<String>> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::List, format!("{mount}/csr"), None).await?;
    Ok(val_str_array(&data_to_map(resp), "keys"))
}

#[derive(Serialize)]
pub struct PkiCsrPending {
    pub csr_id: String,
    pub role: String,
    pub key_id: String,
    pub common_name: String,
    pub csr: String,
    pub created_at: u64,
}

#[tauri::command]
pub async fn pki_csr_read(
    state: State<'_, AppState>,
    mount: String,
    csr_id: String,
) -> CmdResult<Option<PkiCsrPending>> {
    let mount = mount_prefix(&mount);
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{mount}/csr/{csr_id}"),
        None,
    )
    .await
    .ok();
    let Some(resp) = resp else { return Ok(None) };
    let map = data_to_map(resp);
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(PkiCsrPending {
        csr_id: val_str(&map, "csr_id"),
        role: val_str(&map, "role"),
        key_id: val_str(&map, "key_id"),
        common_name: val_str(&map, "common_name"),
        csr: val_str(&map, "csr"),
        created_at: map.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
    }))
}

#[tauri::command]
pub async fn pki_csr_delete(
    state: State<'_, AppState>,
    mount: String,
    csr_id: String,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    make_request(
        &state,
        Operation::Delete,
        format!("{mount}/csr/{csr_id}"),
        None,
    )
    .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct PkiCsrSetSignedRequest {
    pub mount: String,
    pub csr_id: String,
    pub certificate: String,
}

#[derive(Serialize)]
pub struct PkiCsrSetSignedResult {
    pub serial_number: String,
    pub not_after: u64,
    pub key_id: String,
    pub source: String,
    pub is_orphaned: bool,
}

#[tauri::command]
pub async fn pki_csr_set_signed(
    state: State<'_, AppState>,
    request: PkiCsrSetSignedRequest,
) -> CmdResult<PkiCsrSetSignedResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("certificate".into(), json!(request.certificate));
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{mount}/csr/{}/set-signed", request.csr_id),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiCsrSetSignedResult {
        serial_number: val_str(&map, "serial_number"),
        not_after: map.get("not_after").and_then(|v| v.as_u64()).unwrap_or(0),
        key_id: val_str(&map, "key_id"),
        source: val_str(&map, "source"),
        is_orphaned: map.get("is_orphaned").and_then(|v| v.as_bool()).unwrap_or(true),
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
) -> CmdResult<PkiCaImportResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("pem_bundle".into(), json!(request.pem_bundle));
    if let Some(n) = request.issuer_name {
        body.insert("issuer_name".into(), json!(n));
    }
    let resp = make_request(&state, Operation::Write, format!("{mount}/config/ca"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(ca_import_result(&map))
}

/// Import a CA from a PKCS#12 (`.p12` / `.pfx`) container. The
/// front-end reads the file as bytes and base64-encodes them; this
/// command unwraps the bag (with the operator-supplied passphrase),
/// re-emits the cert + private key as a single PEM bundle, and
/// hands the bundle to the existing `pki/config/ca` route. The
/// passphrase never leaves the Tauri process; the bundle PEM is
/// short-lived in memory and dropped as soon as `pki/config/ca`
/// returns.
#[derive(Deserialize)]
pub struct PkiImportCaPkcs12Request {
    pub mount: String,
    /// Base64-encoded PKCS#12 / PFX bytes (DER container).
    pub pkcs12_b64: String,
    /// PKCS#12 passphrase. Empty string is allowed (some tools mint
    /// password-less containers).
    pub passphrase: String,
    pub issuer_name: Option<String>,
}

/// Locally unwrap a PKCS#12 / PFX container into PEM blocks. The
/// passphrase never leaves this process. Returns the (optional) private
/// key normalised to PKCS#8 PEM, plus every certificate found — the
/// private-key chain's certs first (leaf then chain), followed by any
/// standalone certificate entries (trust anchors). DER duplicates are
/// de-duplicated so a cert that appears in both the key chain and as a
/// standalone bag is only emitted once.
///
/// `Relaxed` import policy matches the pre-0.3 behaviour: take whatever
/// the container holds even when key/cert linking metadata is imperfect
/// (xca and Windows exports are routinely sloppy here). `Strict` would
/// silently drop such entries.
fn unwrap_pkcs12(der: &[u8], passphrase: &str) -> Result<(Option<String>, Vec<String>), String> {
    use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
    use pem::Pem;
    use std::collections::HashSet;

    let keystore = KeyStore::from_pkcs12(der, passphrase, Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| format!("passphrase rejected or container malformed: {e}"))?;

    let mut key_pem: Option<String> = None;
    let mut cert_pems: Vec<String> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    // Prefer the linked private-key chain first so its leaf cert lands
    // ahead of any standalone/trust certs. p12-keystore normalises the
    // private key to PKCS#8 DER regardless of the inner key type
    // (RSA / EC / Ed25519), which is exactly the shape the server's
    // `keys/import` / `config/ca` splitter expects behind a
    // `PRIVATE KEY` header.
    if let Some((_alias, chain)) = keystore.private_key_chain() {
        key_pem = Some(pem::encode(&Pem::new(
            "PRIVATE KEY",
            chain.key().as_der().to_vec(),
        )));
        for c in chain.certs() {
            if seen.insert(c.as_der().to_vec()) {
                cert_pems.push(pem::encode(&Pem::new("CERTIFICATE", c.as_der().to_vec())));
            }
        }
    }
    for (_alias, entry) in keystore.entries() {
        if let KeyStoreEntry::Certificate(cert) = entry {
            if seen.insert(cert.as_der().to_vec()) {
                cert_pems.push(pem::encode(&Pem::new(
                    "CERTIFICATE",
                    cert.as_der().to_vec(),
                )));
            }
        }
    }
    Ok((key_pem, cert_pems))
}

#[tauri::command]
pub async fn pki_import_ca_pkcs12(
    state: State<'_, AppState>,
    request: PkiImportCaPkcs12Request,
) -> CmdResult<PkiCaImportResult> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let der = B64
        .decode(request.pkcs12_b64.trim())
        .map_err(|e| format!("pki_import_ca_pkcs12: base64 decode failed: {e}"))?;
    let (key_pem, cert_pems) =
        unwrap_pkcs12(&der, &request.passphrase).map_err(|e| format!("pki_import_ca_pkcs12: {e}"))?;
    let key_pem = key_pem.ok_or("pki_import_ca_pkcs12: container has no private key entry")?;
    if cert_pems.is_empty() {
        return Err("pki_import_ca_pkcs12: container has no certificate".into());
    }

    // Concat in any order — `split_pem_bundle` recognises both blocks by
    // tag. `cert_pems` is leaf-then-chain, so an intermediate bundled
    // with its root still imports cleanly. The key goes last.
    let mut bundle = String::new();
    for c in &cert_pems {
        bundle.push_str(c);
        if !c.ends_with('\n') {
            bundle.push('\n');
        }
    }
    bundle.push_str(&key_pem);

    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("pem_bundle".into(), json!(bundle));
    if let Some(n) = request.issuer_name {
        body.insert("issuer_name".into(), json!(n));
    }
    let resp =
        make_request(&state, Operation::Write, format!("{mount}/config/ca"), Some(body)).await?;
    let map = data_to_map(resp);
    Ok(ca_import_result(&map))
}

// ── CA chain parsing / preview ─────────────────────────────────────

/// One certificate node in a parsed CA chain, shared by the pre-import
/// preview (`pki_parse_chain`) and the post-import result
/// (`PkiCaImportResult`). The front-end links nodes into a tree by
/// matching each node's `issuer` DN against another node's `subject` DN.
#[derive(Serialize)]
pub struct PkiChainNode {
    pub subject: String,
    pub issuer: String,
    pub common_name: String,
    pub issuer_common_name: String,
    pub serial: String,
    pub not_after: i64,
    pub is_ca: bool,
    pub self_signed: bool,
}

#[derive(Serialize)]
pub struct PkiChainPreview {
    pub nodes: Vec<PkiChainNode>,
    /// Whether the bundle carries a private key at all. If false, the
    /// import will register every CA as a trust/chain-only issuer.
    pub key_present: bool,
    /// Human-readable notes the modal shows before import — e.g. a
    /// non-CA cert in the paste, or "no key → trust-only import".
    pub warnings: Vec<String>,
}

/// Pull the CN out of an RFC-2253/4514 DN string (`CN=foo,O=bar`).
/// Handles the CN appearing anywhere in the DN; returns "" if absent.
fn cn_from_dn(dn: &str) -> String {
    for part in dn.split(',') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("CN=") {
            return rest.to_string();
        }
    }
    String::new()
}

/// Parse a certificate DER into a chain node (display-only facts).
fn chain_node_from_der(der: &[u8]) -> Option<PkiChainNode> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let subject = cert.tbs_certificate.subject.to_string();
    let issuer = cert.tbs_certificate.issuer.to_string();
    let is_ca = cert
        .tbs_certificate
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);
    Some(PkiChainNode {
        common_name: cn_from_dn(&subject),
        issuer_common_name: cn_from_dn(&issuer),
        self_signed: subject == issuer,
        subject,
        issuer,
        serial: format!("{:x}", cert.tbs_certificate.serial),
        not_after: cert.tbs_certificate.validity.not_after.timestamp(),
        is_ca,
    })
}

/// Parse a pasted PEM bundle **locally** (no vault access, so it works
/// in embedded and remote modes alike) into a chain preview: one node
/// per CERTIFICATE block plus whether a private key is present. Powers
/// the "tree preview" in the Import root CA modal before the operator
/// commits the import.
#[tauri::command]
pub fn pki_parse_chain(pem_bundle: String) -> CmdResult<PkiChainPreview> {
    let mut nodes = Vec::new();
    let mut key_present = false;
    let mut warnings = Vec::new();

    // `parse_many` tolerates surrounding whitespace/comments between
    // blocks; unknown/garbage blocks are skipped rather than fatal.
    let blocks = pem::parse_many(pem_bundle.as_bytes()).unwrap_or_default();
    for block in &blocks {
        let tag = block.tag();
        if tag == "CERTIFICATE" {
            match chain_node_from_der(block.contents()) {
                Some(node) => {
                    if !node.is_ca {
                        let who = if node.common_name.is_empty() {
                            format!("serial {}", node.serial)
                        } else {
                            node.common_name.clone()
                        };
                        warnings.push(format!(
                            "“{who}” is not a CA certificate — it will be rejected. Remove leaf certs; import them via the Certificates tab."
                        ));
                    }
                    nodes.push(node);
                }
                None => warnings.push("A CERTIFICATE block could not be parsed and will be rejected.".into()),
            }
        } else if tag.contains("PRIVATE KEY") || tag == "BV PQC SIGNER" {
            key_present = true;
        }
    }

    if nodes.is_empty() {
        warnings.push("No certificate found yet — paste at least one CA certificate.".into());
    } else if !key_present {
        warnings.push(
            "No private key in the paste — every CA will be imported as trust/chain-only (cannot sign).".into(),
        );
    }

    Ok(PkiChainPreview { nodes, key_present, warnings })
}

// ── CA import result ────────────────────────────────────────────────

/// One imported (or skipped) certificate from a `pki/config/ca` call.
#[derive(Serialize, Default)]
pub struct PkiImportedCert {
    pub issuer_id: String,
    pub issuer_name: String,
    pub common_name: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub self_signed: bool,
    pub has_key: bool,
    pub keyless: bool,
    pub skipped: bool,
}

/// Result of a CA bundle / PKCS#12 import: the primary (signing or root)
/// issuer plus the full per-cert breakdown the modal renders as a tree.
#[derive(Serialize, Default)]
pub struct PkiCaImportResult {
    pub issuer_id: String,
    pub issuer_name: String,
    pub imported_issuers: Vec<String>,
    pub imported_keys: Vec<String>,
    pub chain: Vec<PkiImportedCert>,
}

/// Project a `pki/config/ca` response map into [`PkiCaImportResult`].
fn ca_import_result(map: &Map<String, Value>) -> PkiCaImportResult {
    let str_list = |k: &str| -> Vec<String> {
        map.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let chain = map
        .get("chain")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|e| PkiImportedCert {
                    issuer_id: val_str_v(e, "issuer_id"),
                    issuer_name: val_str_v(e, "issuer_name"),
                    common_name: val_str_v(e, "common_name"),
                    subject: val_str_v(e, "subject"),
                    issuer: val_str_v(e, "issuer"),
                    serial: val_str_v(e, "serial"),
                    self_signed: e.get("self_signed").and_then(Value::as_bool).unwrap_or(false),
                    has_key: e.get("has_key").and_then(Value::as_bool).unwrap_or(false),
                    keyless: e.get("keyless").and_then(Value::as_bool).unwrap_or(false),
                    skipped: e.get("skipped").and_then(Value::as_bool).unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();
    PkiCaImportResult {
        issuer_id: val_str(map, "issuer_id"),
        issuer_name: val_str(map, "issuer_name"),
        imported_issuers: str_list("imported_issuers"),
        imported_keys: str_list("imported_keys"),
        chain,
    }
}

/// Read a string field from an arbitrary JSON value's object body.
fn val_str_v(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
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
    /// Subject Alternative Name entries pulled from the cert's SAN
    /// extension. Empty when the cert has no SAN. Each list is the
    /// raw textual form (DNS / IP / email / URI) so the detail panel
    /// can render them as `<key>: <value>` pairs without re-parsing.
    #[serde(default)]
    pub san_dns: Vec<String>,
    #[serde(default)]
    pub san_ip: Vec<String>,
    #[serde(default)]
    pub san_email: Vec<String>,
    #[serde(default)]
    pub san_uri: Vec<String>,
    /// Key-Usage and Extended-Key-Usage decodes (textual labels like
    /// `digitalSignature`, `serverAuth`). Empty when the cert omits
    /// the extension.
    #[serde(default)]
    pub key_usages: Vec<String>,
    #[serde(default)]
    pub ext_key_usages: Vec<String>,
}

#[derive(Default)]
struct CertExtras {
    san_dns: Vec<String>,
    san_ip: Vec<String>,
    san_email: Vec<String>,
    san_uri: Vec<String>,
    key_usages: Vec<String>,
    ext_key_usages: Vec<String>,
}

/// Parse the cert's SubjectAltName, KeyUsage, and ExtendedKeyUsage
/// extensions into textual entries. Tolerant of missing / malformed
/// extensions: any failure returns the partial result accumulated so
/// far, never panics.
fn parse_cert_extras(der: &[u8]) -> CertExtras {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::*;
    let mut out = CertExtras::default();
    let Ok((_, parsed)) = X509Certificate::from_der(der) else {
        return out;
    };
    for ext in parsed.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for gn in &san.general_names {
                    match gn {
                        GeneralName::DNSName(s) => out.san_dns.push((*s).to_string()),
                        GeneralName::IPAddress(bytes) => {
                            out.san_ip.push(format_ip(bytes));
                        }
                        GeneralName::RFC822Name(s) => out.san_email.push((*s).to_string()),
                        GeneralName::URI(s) => out.san_uri.push((*s).to_string()),
                        _ => {}
                    }
                }
            }
            ParsedExtension::KeyUsage(ku) => {
                if ku.digital_signature() { out.key_usages.push("digitalSignature".into()); }
                if ku.non_repudiation() { out.key_usages.push("nonRepudiation".into()); }
                if ku.key_encipherment() { out.key_usages.push("keyEncipherment".into()); }
                if ku.data_encipherment() { out.key_usages.push("dataEncipherment".into()); }
                if ku.key_agreement() { out.key_usages.push("keyAgreement".into()); }
                if ku.key_cert_sign() { out.key_usages.push("keyCertSign".into()); }
                if ku.crl_sign() { out.key_usages.push("cRLSign".into()); }
                if ku.encipher_only() { out.key_usages.push("encipherOnly".into()); }
                if ku.decipher_only() { out.key_usages.push("decipherOnly".into()); }
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                if eku.server_auth { out.ext_key_usages.push("serverAuth".into()); }
                if eku.client_auth { out.ext_key_usages.push("clientAuth".into()); }
                if eku.code_signing { out.ext_key_usages.push("codeSigning".into()); }
                if eku.email_protection { out.ext_key_usages.push("emailProtection".into()); }
                if eku.time_stamping { out.ext_key_usages.push("timeStamping".into()); }
                if eku.ocsp_signing { out.ext_key_usages.push("OCSPSigning".into()); }
                for oid in &eku.other {
                    out.ext_key_usages.push(oid.to_string());
                }
            }
            _ => {}
        }
    }
    out
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let mut groups = [0u16; 8];
            for (i, g) in groups.iter_mut().enumerate() {
                *g = ((bytes[i * 2] as u16) << 8) | bytes[i * 2 + 1] as u16;
            }
            groups
                .iter()
                .map(|g| format!("{g:x}"))
                .collect::<Vec<_>>()
                .join(":")
        }
        _ => hex::encode(bytes),
    }
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
    let extras = bastion_vault::modules::pki::csr::decode_pem_or_der(&certificate)
        .map(|der| parse_cert_extras(&der))
        .unwrap_or_default();
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
        san_dns: extras.san_dns,
        san_ip: extras.san_ip,
        san_email: extras.san_email,
        san_uri: extras.san_uri,
        key_usages: extras.key_usages,
        ext_key_usages: extras.ext_key_usages,
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

#[derive(Deserialize)]
pub struct PkiImportCertsFileRequest {
    pub mount: String,
    /// Container encoding: `pem` | `pkcs7` | `pkcs12`. Anything else is
    /// rejected before any network call.
    pub format: String,
    /// Base64 of the raw file bytes exactly as read from disk.
    pub data_b64: String,
    /// PKCS#12 passphrase. Empty string is allowed. Ignored for
    /// `pem` / `pkcs7`, which don't carry an encryption layer here.
    #[serde(default)]
    pub passphrase: String,
    /// Provenance label recorded on each imported cert (defaults to the
    /// container format when empty).
    #[serde(default)]
    pub source: String,
}

/// One certificate's outcome from a multi-cert file import.
#[derive(Serialize)]
pub struct PkiImportedCertEntry {
    pub serial_number: String,
    pub common_name: String,
    /// True when the cert was newly indexed. False when it was already
    /// present (`already indexed`) or failed — see `error`.
    pub imported: bool,
    /// True specifically for the "already indexed" case, so the GUI can
    /// count it as skipped rather than failed.
    pub already_present: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct PkiImportCertsFileResult {
    pub imported: usize,
    pub skipped: usize,
    pub failed: usize,
    pub entries: Vec<PkiImportedCertEntry>,
}

/// Extract certificate PEM blocks from a PEM / PKCS#7 / PKCS#12 file.
/// Every returned string is a normalised `-----BEGIN CERTIFICATE-----`
/// block. The passphrase is only consulted for PKCS#12.
fn extract_cert_pems(
    format: &str,
    bytes: &[u8],
    passphrase: &str,
) -> Result<Vec<String>, String> {
    use pem::Pem;

    match format.to_ascii_lowercase().as_str() {
        "pem" => {
            // A PEM file may bundle several certs (and unrelated blocks
            // like keys). Keep only CERTIFICATE blocks; re-encode each so
            // the output is canonical regardless of the input's wrapping.
            let text = std::str::from_utf8(bytes)
                .map_err(|_| "PEM file is not valid UTF-8".to_string())?;
            let blocks = pem::parse_many(text)
                .map_err(|e| format!("PEM parse failed: {e}"))?;
            let certs: Vec<String> = blocks
                .into_iter()
                .filter(|p| p.tag() == "CERTIFICATE")
                .map(|p| pem::encode(&Pem::new("CERTIFICATE", p.contents().to_vec())))
                .collect();
            if certs.is_empty() {
                return Err("no CERTIFICATE blocks found in PEM file".into());
            }
            Ok(certs)
        }
        "pkcs7" | "p7b" | "p7c" => extract_pkcs7_cert_pems(bytes),
        "pkcs12" | "p12" | "pfx" => {
            let (_key, cert_pems) = unwrap_pkcs12(bytes, passphrase)?;
            if cert_pems.is_empty() {
                return Err("PKCS#12 container has no certificate".into());
            }
            Ok(cert_pems)
        }
        other => Err(format!(
            "unknown format `{other}` (accepted: pem, pkcs7, pkcs12)"
        )),
    }
}

/// Pull every certificate out of a certs-only PKCS#7 `SignedData`
/// envelope. Accepts either raw DER or PEM-armored (`-----BEGIN PKCS7`)
/// input — the shape `pki_export_cert format=pkcs7` produces and what
/// OpenSSL / macOS / Windows tooling emits for `.p7b`.
fn extract_pkcs7_cert_pems(bytes: &[u8]) -> Result<Vec<String>, String> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use pem::Pem;
    use x509_cert::der::{Decode, Encode};

    // Unwrap PEM armor if present; otherwise treat the bytes as DER.
    let der: Vec<u8> = match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("BEGIN PKCS7") || text.contains("BEGIN PKCS #7") => {
            pem::parse(text.trim())
                .map_err(|e| format!("PKCS#7 PEM parse failed: {e}"))?
                .contents()
                .to_vec()
        }
        _ => bytes.to_vec(),
    };

    let ci = ContentInfo::from_der(&der)
        .map_err(|e| format!("PKCS#7 ContentInfo decode failed: {e}"))?;
    // id-signedData = 1.2.840.113549.1.7.2. A certs-only .p7b is always
    // SignedData; reject anything else with a clear message.
    if ci.content_type.to_string() != "1.2.840.113549.1.7.2" {
        return Err(format!(
            "PKCS#7 is not SignedData (content type {})",
            ci.content_type
        ));
    }
    let signed: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| format!("PKCS#7 SignedData decode failed: {e}"))?;
    let cert_set = signed
        .certificates
        .ok_or("PKCS#7 SignedData carries no certificates")?;

    let mut out = Vec::new();
    for choice in cert_set.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            let der = cert
                .to_der()
                .map_err(|e| format!("PKCS#7 certificate re-encode failed: {e}"))?;
            out.push(pem::encode(&Pem::new("CERTIFICATE", der)));
        }
    }
    if out.is_empty() {
        return Err("PKCS#7 SignedData has no X.509 certificates".into());
    }
    Ok(out)
}

/// Import one or more certificates from a PEM / PKCS#7 / PKCS#12 file
/// into the orphan-cert index (`pki/certs/import`). Each cert is indexed
/// independently; a per-cert failure (or an already-indexed serial) is
/// recorded in the result rather than aborting the whole batch. No
/// private key is stored on this path — use the Keys tab's PKCS#12
/// import to grab a key.
#[tauri::command]
pub async fn pki_import_certs_file(
    state: State<'_, AppState>,
    request: PkiImportCertsFileRequest,
) -> CmdResult<PkiImportCertsFileResult> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let bytes = B64
        .decode(request.data_b64.trim())
        .map_err(|e| format!("pki_import_certs_file: base64 decode failed: {e}"))?;
    let cert_pems = extract_cert_pems(&request.format, &bytes, &request.passphrase)
        .map_err(|e| format!("pki_import_certs_file: {e}"))?;

    let source = if request.source.trim().is_empty() {
        format!("{}-import", request.format.to_ascii_lowercase())
    } else {
        request.source.trim().to_string()
    };
    let mount = mount_prefix(&request.mount);

    let mut entries = Vec::with_capacity(cert_pems.len());
    let (mut imported, mut skipped, mut failed) = (0usize, 0usize, 0usize);

    for pem_str in &cert_pems {
        // Best-effort CN for display; a parse miss just leaves it blank.
        let common_name = pem::parse(pem_str.trim())
            .ok()
            .and_then(|p| chain_node_from_der(p.contents()))
            .map(|n| n.common_name)
            .unwrap_or_default();

        let mut body = Map::new();
        body.insert("certificate".into(), json!(pem_str));
        body.insert("source".into(), json!(source));
        match make_request(
            &state,
            Operation::Write,
            format!("{mount}/certs/import"),
            Some(body),
        )
        .await
        {
            Ok(resp) => {
                let map = data_to_map(resp);
                imported += 1;
                entries.push(PkiImportedCertEntry {
                    serial_number: val_str(&map, "serial_number"),
                    common_name,
                    imported: true,
                    already_present: false,
                    error: None,
                });
            }
            Err(e) => {
                let msg = e.to_string();
                // An "already indexed" serial is a skip, not a failure —
                // re-importing a bundle that overlaps existing certs is a
                // normal operation.
                if msg.to_ascii_lowercase().contains("already indexed") {
                    skipped += 1;
                    entries.push(PkiImportedCertEntry {
                        serial_number: String::new(),
                        common_name,
                        imported: false,
                        already_present: true,
                        error: None,
                    });
                } else {
                    failed += 1;
                    entries.push(PkiImportedCertEntry {
                        serial_number: String::new(),
                        common_name,
                        imported: false,
                        already_present: false,
                        error: Some(msg),
                    });
                }
            }
        }
    }

    Ok(PkiImportCertsFileResult {
        imported,
        skipped,
        failed,
        entries,
    })
}

#[derive(Serialize)]
pub struct PkiRevokeResult {
    pub revocation_time: u64,
    pub serial_number: String,
    pub issuer_id: String,
}

// ── Cert / issuer export (PEM / PKCS#7) ──────────────────────────────

#[derive(Deserialize)]
pub struct PkiExportCertRequest {
    pub mount: String,
    pub serial: String,
    /// `pem` (default) | `pkcs7` | `pkcs12`.
    pub format: Option<String>,
    pub include_private_key: Option<bool>,
    /// `normal` (default) | `backup`.
    pub mode: Option<String>,
    /// Required when `format=pkcs12`.
    pub password: Option<String>,
}

#[derive(Serialize)]
pub struct PkiExportResult {
    /// `pem` | `pkcs7` | `pkcs12`. Echoed back so the GUI can label
    /// the save dialog correctly.
    pub format: String,
    /// Suggested filename extension (no leading dot).
    pub filename_extension: String,
    /// Encoded payload — UTF-8 for text formats, base64 for PKCS#12
    /// (raw DER bytes don't fit cleanly in JSON otherwise).
    pub body: String,
    /// `utf8` | `base64`. Tells the GUI whether to decode the body
    /// before writing it to disk.
    #[serde(default)]
    pub body_encoding: String,
    pub includes_private_key: bool,
    #[serde(default)]
    pub backup_mode: bool,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub issuer_id: String,
    #[serde(default)]
    pub issuer_name: String,
}

#[tauri::command]
pub async fn pki_export_cert(
    state: State<'_, AppState>,
    request: PkiExportCertRequest,
) -> CmdResult<PkiExportResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    if let Some(f) = request.format.filter(|s| !s.is_empty()) {
        body.insert("format".into(), json!(f));
    }
    if let Some(b) = request.include_private_key {
        body.insert("include_private_key".into(), json!(b));
    }
    if let Some(m) = request.mode.filter(|s| !s.is_empty()) {
        body.insert("mode".into(), json!(m));
    }
    if let Some(p) = request.password.filter(|s| !s.is_empty()) {
        body.insert("password".into(), json!(p));
    }
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{mount}/cert/{}/export", request.serial),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiExportResult {
        format: val_str(&map, "format"),
        filename_extension: val_str(&map, "filename_extension"),
        body: val_str(&map, "body"),
        body_encoding: val_str(&map, "body_encoding"),
        includes_private_key: map
            .get("includes_private_key")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        backup_mode: map.get("backup_mode").and_then(|v| v.as_bool()).unwrap_or(false),
        serial_number: val_str(&map, "serial_number"),
        issuer_id: String::new(),
        issuer_name: String::new(),
    })
}

#[derive(Deserialize)]
pub struct PkiExportIssuerRequest {
    pub mount: String,
    pub issuer_ref: String,
    pub format: Option<String>,
    pub include_chain: Option<bool>,
    pub password: Option<String>,
}

#[tauri::command]
pub async fn pki_export_issuer(
    state: State<'_, AppState>,
    request: PkiExportIssuerRequest,
) -> CmdResult<PkiExportResult> {
    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    if let Some(f) = request.format.filter(|s| !s.is_empty()) {
        body.insert("format".into(), json!(f));
    }
    if let Some(b) = request.include_chain {
        body.insert("include_chain".into(), json!(b));
    }
    if let Some(p) = request.password.filter(|s| !s.is_empty()) {
        body.insert("password".into(), json!(p));
    }
    let resp = make_request(
        &state,
        Operation::Read,
        format!("{mount}/issuer/{}/export", request.issuer_ref),
        Some(body),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(PkiExportResult {
        format: val_str(&map, "format"),
        filename_extension: val_str(&map, "filename_extension"),
        body: val_str(&map, "body"),
        body_encoding: val_str(&map, "body_encoding"),
        includes_private_key: false,
        backup_mode: false,
        serial_number: String::new(),
        issuer_id: val_str(&map, "issuer_id"),
        issuer_name: val_str(&map, "issuer_name"),
    })
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
    /// PEM-encoded private key. Optional when a `pkcs12_b64` container is
    /// supplied — the key is then unwrapped from the container instead.
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub name: String,
    /// Optional base64 PKCS#12 / PFX container. When present, the private
    /// key is unwrapped locally (the passphrase never leaves this
    /// process) and used in place of `private_key`; any certificates in
    /// the container are ignored — this path only grabs the key.
    #[serde(default)]
    pub pkcs12_b64: String,
    /// PKCS#12 passphrase. Empty string is allowed for password-less
    /// containers. Ignored unless `pkcs12_b64` is set.
    #[serde(default)]
    pub passphrase: String,
}

#[tauri::command]
pub async fn pki_import_key(
    state: State<'_, AppState>,
    request: PkiImportKeyRequest,
) -> CmdResult<PkiGenerateKeyResult> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let private_key = if !request.pkcs12_b64.trim().is_empty() {
        let der = B64
            .decode(request.pkcs12_b64.trim())
            .map_err(|e| format!("pki_import_key: base64 decode failed: {e}"))?;
        let (key_pem, _certs) =
            unwrap_pkcs12(&der, &request.passphrase).map_err(|e| format!("pki_import_key: {e}"))?;
        key_pem.ok_or("pki_import_key: PKCS#12 container has no private key entry")?
    } else {
        request.private_key.clone()
    };
    if private_key.trim().is_empty() {
        return Err("pki_import_key: no private key provided".into());
    }

    let mount = mount_prefix(&request.mount);
    let mut body = Map::new();
    body.insert("private_key".into(), json!(private_key));
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
    force: Option<bool>,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let body = json!({"force": force.unwrap_or(false)})
        .as_object()
        .cloned()
        .unwrap_or_default();
    make_request(&state, Operation::Delete, format!("{mount}/key/{key_ref}"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn pki_delete_cert(
    state: State<'_, AppState>,
    mount: String,
    serial: String,
    force: Option<bool>,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let body = json!({"force": force.unwrap_or(false), "serial": serial.clone()})
        .as_object()
        .cloned()
        .unwrap_or_default();
    make_request(&state, Operation::Delete, format!("{mount}/cert/{serial}"), Some(body)).await?;
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

#[cfg(test)]
mod tests {
    //! Coverage for the client-side container parsers on the PKI import
    //! path (`unwrap_pkcs12`, `extract_pkcs7_cert_pems`,
    //! `extract_cert_pems`). These are pure functions — no vault call —
    //! so we exercise the DER/ASN.1 handling directly, including
    //! malformed-input rejection. Fixtures are generated in-test with
    //! `rcgen` so no binary blobs live in the repo.

    use super::*;

    /// A self-signed cert plus its PKCS#8 private key, both DER.
    struct Fixture {
        cert_der: Vec<u8>,
        cert_pem: String,
        key_pkcs8_der: Vec<u8>,
    }

    fn make_cert(cn: &str) -> Fixture {
        let ck = rcgen::generate_simple_self_signed(vec![cn.to_string()]).unwrap();
        Fixture {
            cert_der: ck.cert.der().to_vec(),
            cert_pem: ck.cert.pem(),
            key_pkcs8_der: ck.signing_key.serialize_der(),
        }
    }

    /// Build a certs-only PKCS#7 `SignedData` `ContentInfo`, mirroring
    /// the shape the server's export path produces. Returns DER.
    fn make_pkcs7_der(certs: &[&[u8]]) -> Vec<u8> {
        use cms::cert::CertificateChoices;
        use cms::content_info::ContentInfo;
        use cms::content_info::CmsVersion;
        use cms::signed_data::{
            CertificateSet, EncapsulatedContentInfo, SignedData, SignerInfos,
        };
        use cms::revocation::RevocationInfoChoices;
        use x509_cert::der::{asn1::SetOfVec, Any, Decode, Encode};
        use x509_cert::Certificate as X509Cert;

        let mut set: CertificateSet = CertificateSet(SetOfVec::new());
        for der in certs {
            let c = X509Cert::from_der(der).unwrap();
            set.0.insert(CertificateChoices::Certificate(c)).unwrap();
        }
        let signed = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::new(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: "1.2.840.113549.1.7.1".parse().unwrap(),
                econtent: None,
            },
            certificates: Some(set),
            crls: Some(RevocationInfoChoices(Default::default())),
            signer_infos: SignerInfos(SetOfVec::new()),
        };
        let inner = signed.to_der().unwrap();
        let ci = ContentInfo {
            content_type: "1.2.840.113549.1.7.2".parse().unwrap(),
            content: Any::from_der(&inner).unwrap(),
        };
        ci.to_der().unwrap()
    }

    /// Build a PKCS#12 container holding the fixture's key + cert.
    fn make_pkcs12(fx: &Fixture, extra_certs: &[&[u8]], passphrase: &str) -> Vec<u8> {
        use p12_keystore::{
            Certificate as P12Cert, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain,
        };

        let mut store = KeyStore::new();
        let key = PrivateKey::from_der(&fx.key_pkcs8_der).unwrap();
        let leaf = P12Cert::from_der(&fx.cert_der).unwrap();
        let chain = PrivateKeyChain::new(vec![0u8; 20], key, vec![leaf]);
        store.add_entry("leaf", KeyStoreEntry::PrivateKeyChain(chain));
        for (i, der) in extra_certs.iter().enumerate() {
            let c = P12Cert::from_der(der).unwrap();
            store.add_entry(&format!("ca{i}"), KeyStoreEntry::Certificate(c));
        }
        store.writer(passphrase).write().unwrap()
    }

    fn cert_count(pem: &str) -> usize {
        pem::parse_many(pem)
            .unwrap()
            .iter()
            .filter(|p| p.tag() == "CERTIFICATE")
            .count()
    }

    #[test]
    fn extract_pem_single_cert() {
        let fx = make_cert("pem-single.example");
        let out = extract_cert_pems("pem", fx.cert_pem.as_bytes(), "").unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(cert_count(&out[0]), 1);
    }

    #[test]
    fn extract_pem_bundle_multiple_and_ignores_key() {
        let a = make_cert("pem-a.example");
        let b = make_cert("pem-b.example");
        // A bundle with two certs and a private key block interleaved.
        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", a.key_pkcs8_der.clone()));
        let bundle = format!("{}{}{}", a.cert_pem, key_pem, b.cert_pem);
        let out = extract_cert_pems("pem", bundle.as_bytes(), "").unwrap();
        // Both certs extracted; the key block dropped.
        assert_eq!(out.len(), 2);
        for c in &out {
            assert_eq!(cert_count(c), 1);
            assert!(c.contains("BEGIN CERTIFICATE"));
        }
    }

    #[test]
    fn extract_pem_rejects_keys_only() {
        let fx = make_cert("keys-only.example");
        let key_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", fx.key_pkcs8_der));
        let err = extract_cert_pems("pem", key_pem.as_bytes(), "").unwrap_err();
        assert!(err.contains("no CERTIFICATE"), "got: {err}");
    }

    #[test]
    fn extract_unknown_format_rejected() {
        let err = extract_cert_pems("jks", b"whatever", "").unwrap_err();
        assert!(err.contains("unknown format"), "got: {err}");
    }

    #[test]
    fn extract_pkcs7_der_and_pem_roundtrip() {
        let a = make_cert("p7-a.example");
        let b = make_cert("p7-b.example");
        let der = make_pkcs7_der(&[&a.cert_der, &b.cert_der]);

        // DER input.
        let out = extract_cert_pems("pkcs7", &der, "").unwrap();
        assert_eq!(out.len(), 2);

        // PEM-armored input (what a `.p7b` usually is).
        let armored = pem::encode(&pem::Pem::new("PKCS7", der.clone()));
        let out2 = extract_cert_pems("pkcs7", armored.as_bytes(), "").unwrap();
        assert_eq!(out2.len(), 2);
    }

    #[test]
    fn extract_pkcs7_rejects_garbage() {
        let err = extract_cert_pems("pkcs7", b"not der at all", "").unwrap_err();
        assert!(err.contains("ContentInfo decode"), "got: {err}");
    }

    #[test]
    fn unwrap_pkcs12_returns_key_and_all_certs() {
        let leaf = make_cert("p12-leaf.example");
        let ca = make_cert("p12-ca.example");
        let der = make_pkcs12(&leaf, &[&ca.cert_der], "s3cret");

        let (key, certs) = unwrap_pkcs12(&der, "s3cret").unwrap();
        assert!(key.unwrap().contains("BEGIN PRIVATE KEY"));
        // Leaf (from the key chain) + the standalone CA cert.
        assert_eq!(certs.len(), 2);
        for c in &certs {
            assert!(c.contains("BEGIN CERTIFICATE"));
        }
    }

    #[test]
    fn unwrap_pkcs12_wrong_passphrase_rejected() {
        let fx = make_cert("p12-badpw.example");
        let der = make_pkcs12(&fx, &[], "correct");
        let err = unwrap_pkcs12(&der, "wrong").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn extract_pkcs12_via_format_dispatch() {
        let fx = make_cert("p12-dispatch.example");
        let der = make_pkcs12(&fx, &[], "pw");
        let out = extract_cert_pems("pkcs12", &der, "pw").unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("BEGIN CERTIFICATE"));
    }
}
