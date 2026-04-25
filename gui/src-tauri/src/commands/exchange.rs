//! Tauri commands backing the GUI Exchange page.
//!
//! Embedded mode: dispatches directly to `bastion_vault::exchange::*`
//! against the open vault's barrier-decrypted storage. Bypasses the HTTP
//! layer because there isn't one in embedded mode — the GUI runs in
//! the same process as the vault.
//!
//! Remote mode: routes through the existing `Client::sys()` HTTP API
//! (`/v1/sys/exchange/export`, `/v1/sys/exchange/import/preview`,
//! `/v1/sys/exchange/import/apply`).

use base64::Engine;
use bastion_vault::exchange;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ScopeSelectorInput {
    /// One of "kv_path", "resource", "asset_group", "resource_group".
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub mount: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

fn parse_scope(include: &[ScopeSelectorInput]) -> Result<exchange::ScopeSpec, CommandError> {
    let mut out = Vec::with_capacity(include.len());
    for s in include {
        let sel = match s.kind.as_str() {
            "kv_path" => exchange::ScopeSelector::KvPath {
                mount: s.mount.clone().unwrap_or_default(),
                path: s.path.clone().unwrap_or_default(),
            },
            "resource" => exchange::ScopeSelector::Resource {
                id: s.id.clone().unwrap_or_default(),
            },
            "asset_group" => exchange::ScopeSelector::AssetGroup {
                id: s.id.clone().unwrap_or_default(),
            },
            "resource_group" => exchange::ScopeSelector::ResourceGroup {
                id: s.id.clone().unwrap_or_default(),
            },
            _ => return Err("unknown scope selector type".into()),
        };
        out.push(sel);
    }
    Ok(exchange::ScopeSpec {
        kind: exchange::ScopeKind::Selective,
        include: out,
    })
}

#[derive(Debug, Serialize)]
pub struct ExchangeExportResult {
    /// Base64-encoded file bytes (`.bvx` envelope or plaintext JSON).
    pub file_b64: String,
    pub size_bytes: u64,
    pub format: String,
}

/// `bastion_vault::exchange::export_to_document` then optional `.bvx`
/// envelope. Mirrors the HTTP endpoint shape so the frontend's API
/// surface is identical across embedded and remote modes.
#[tauri::command]
pub async fn exchange_export(
    state: State<'_, AppState>,
    include: Vec<ScopeSelectorInput>,
    format: String,
    password: Option<String>,
    allow_plaintext: Option<bool>,
    comment: Option<String>,
) -> CmdResult<ExchangeExportResult> {
    let scope = parse_scope(&include)?;
    let allow_plaintext_b = allow_plaintext.unwrap_or(false);

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);
    let token = state.token.lock().await.clone().unwrap_or_default();

    let outcome = exchange_export_inner(
        &core_arc,
        scope,
        format.clone(),
        password,
        allow_plaintext_b,
        comment.clone(),
    )
    .await;

    // Audit, success or failure. The audit body records the format +
    // comment + scope-shape (HMAC redaction handles values inside).
    let mut body = serde_json::Map::new();
    body.insert("format".into(), serde_json::Value::String(format));
    body.insert(
        "comment".into(),
        comment.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null),
    );
    body.insert("allow_plaintext".into(), serde_json::Value::Bool(allow_plaintext_b));
    let err_str = match &outcome {
        Err(e) => Some(format!("{e:?}")),
        _ => None,
    };
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &token,
        "sys/exchange/export",
        bastion_vault::logical::Operation::Write,
        Some(body),
        err_str.as_deref(),
    )
    .await;
    outcome
}

async fn exchange_export_inner(
    core_arc: &std::sync::Arc<bastion_vault::core::Core>,
    scope: exchange::ScopeSpec,
    format: String,
    password: Option<String>,
    allow_plaintext: bool,
    comment: Option<String>,
) -> CmdResult<ExchangeExportResult> {
    let mounts = exchange::scope::MountIndex::from_core(core_arc).map_err(CommandError::from)?;
    let document = exchange::scope::export_to_document(
        core_arc.barrier.as_storage(),
        &mounts,
        exchange::ExporterInfo::default(),
        scope,
    )
    .await
    .map_err(CommandError::from)?;

    let inner_bytes =
        exchange::canonical::to_canonical_vec(&document).map_err(CommandError::from)?;

    let (bytes, format_label) = match format.as_str() {
        "json" => {
            if !allow_plaintext {
                return Err("plaintext export refused (set allowPlaintext: true)".into());
            }
            (inner_bytes, "json")
        }
        "bvx" => {
            let pw = password.as_deref().ok_or("password required for bvx format")?;
            let bytes = exchange::encrypt_bvx(&inner_bytes, pw, "", comment).map_err(CommandError::from)?;
            (bytes, "bvx")
        }
        _ => return Err("format must be \"bvx\" or \"json\"".into()),
    };

    Ok(ExchangeExportResult {
        size_bytes: bytes.len() as u64,
        file_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
        format: format_label.to_string(),
    })
}

#[derive(Debug, Serialize)]
pub struct ExchangePreviewResult {
    pub token: String,
    pub expires_in_secs: u64,
    pub total: u64,
    pub new: u64,
    pub identical: u64,
    pub conflict: u64,
    pub items: Vec<PreviewItem>,
}

#[derive(Debug, Serialize)]
pub struct PreviewItem {
    pub mount: String,
    pub path: String,
    /// "new" | "identical" | "conflict"
    pub classification: String,
}

/// Decrypt + parse + classify; store the parsed document under a token
/// in `core.exchange_preview_store`. The apply call must present the
/// same token within the TTL.
#[tauri::command]
pub async fn exchange_preview(
    state: State<'_, AppState>,
    file_b64: String,
    format: String,
    password: Option<String>,
    allow_plaintext: Option<bool>,
) -> CmdResult<ExchangePreviewResult> {
    let allow_plaintext = allow_plaintext.unwrap_or(false);
    let file_bytes = base64::engine::general_purpose::STANDARD
        .decode(file_b64.as_bytes())
        .map_err(|_| "input not valid base64")?;

    let document_bytes = match format.as_str() {
        "bvx" => {
            let pw = password.as_deref().ok_or("password required for bvx format")?;
            exchange::decrypt_bvx(&file_bytes, pw).map_err(CommandError::from)?
        }
        "json" => {
            if !allow_plaintext {
                return Err("plaintext import refused (set allowPlaintext: true)".into());
            }
            file_bytes
        }
        _ => return Err("format must be \"bvx\" or \"json\"".into()),
    };

    let document: exchange::ExchangeDocument =
        serde_json::from_slice(&document_bytes).map_err(|_| "document is not valid bvx.v1 JSON")?;
    document
        .validate_schema_tag()
        .map_err(|_| "unsupported bvx schema tag")?;

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let storage = core.barrier.as_storage();

    let mut new = 0u64;
    let mut identical = 0u64;
    let mut conflict = 0u64;
    let mut items: Vec<PreviewItem> = Vec::with_capacity(document.items.kv.len());
    for kv in &document.items.kv {
        let mount = if kv.mount.ends_with('/') { kv.mount.clone() } else { format!("{}/", kv.mount) };
        let path = kv.path.strip_prefix('/').unwrap_or(&kv.path);
        let full_path = format!("{mount}{path}");
        let new_bytes = match &kv.value {
            Value::Object(map) if map.len() == 1 && map.contains_key("_base64") => {
                if let Some(Value::String(b64)) = map.get("_base64") {
                    base64::engine::general_purpose::STANDARD
                        .decode(b64.as_bytes())
                        .map_err(|_| "_base64 not valid")?
                } else {
                    serde_json::to_vec(&kv.value).map_err(|_| "json serialize failed")?
                }
            }
            _ => serde_json::to_vec(&kv.value).map_err(|_| "json serialize failed")?,
        };
        let existing = storage.get(&full_path).await.map_err(CommandError::from)?;
        let classification = match &existing {
            None => {
                new += 1;
                "new"
            }
            Some(e) if e.value == new_bytes => {
                identical += 1;
                "identical"
            }
            Some(_) => {
                conflict += 1;
                "conflict"
            }
        };
        items.push(PreviewItem {
            mount: kv.mount.clone(),
            path: kv.path.clone(),
            classification: classification.to_string(),
        });
    }

    let owner = state.token.lock().await.clone().unwrap_or_default();
    let preview_token = core.exchange_preview_store.insert(document, owner.clone());
    let expires_in_secs = core.exchange_preview_store.ttl_secs();

    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);
    let mut audit_body = serde_json::Map::new();
    audit_body.insert("format".into(), Value::String(format));
    audit_body.insert("allow_plaintext".into(), Value::Bool(allow_plaintext));
    audit_body.insert("total".into(), Value::Number(items.len().into()));
    audit_body.insert("new".into(), Value::Number(new.into()));
    audit_body.insert("identical".into(), Value::Number(identical.into()));
    audit_body.insert("conflict".into(), Value::Number(conflict.into()));
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &owner,
        "sys/exchange/import/preview",
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        None,
    )
    .await;

    Ok(ExchangePreviewResult {
        token: preview_token,
        expires_in_secs,
        total: items.len() as u64,
        new,
        identical,
        conflict,
        items,
    })
}

#[derive(Debug, Serialize)]
pub struct ExchangeApplyResult {
    pub written: u64,
    pub unchanged: u64,
    pub skipped: u64,
    pub renamed: u64,
}

#[tauri::command]
pub async fn exchange_apply(
    state: State<'_, AppState>,
    token: String,
    conflict_policy: Option<String>,
) -> CmdResult<ExchangeApplyResult> {
    let policy = match conflict_policy.as_deref().unwrap_or("skip") {
        "skip" => exchange::ConflictPolicy::Skip,
        "overwrite" => exchange::ConflictPolicy::Overwrite,
        "rename" => exchange::ConflictPolicy::Rename,
        _ => return Err("conflict_policy must be skip|overwrite|rename".into()),
    };

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();

    let owner = state.token.lock().await.clone().unwrap_or_default();
    let document = core
        .exchange_preview_store
        .consume(&token, &owner)
        .map_err(CommandError::from)?;

    let result = exchange::scope::import_from_document(core.barrier.as_storage(), &document, policy)
        .await
        .map_err(CommandError::from)?;

    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);
    let mut audit_body = serde_json::Map::new();
    audit_body.insert(
        "conflict_policy".into(),
        Value::String(conflict_policy.unwrap_or_else(|| "skip".to_string())),
    );
    audit_body.insert("written".into(), Value::Number(result.written.into()));
    audit_body.insert("unchanged".into(), Value::Number(result.unchanged.into()));
    audit_body.insert("skipped".into(), Value::Number(result.skipped.into()));
    audit_body.insert("renamed".into(), Value::Number(result.renamed.into()));
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &owner,
        "sys/exchange/import/apply",
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        None,
    )
    .await;

    Ok(ExchangeApplyResult {
        written: result.written,
        unchanged: result.unchanged,
        skipped: result.skipped,
        renamed: result.renamed,
    })
}

// Silence the unused-import warning when nothing else in the module uses
// `json` (currently only used in tests; keep the import for symmetry
// with sibling command modules that use it).
#[allow(dead_code)]
fn _silence_unused() -> Value {
    json!({})
}
