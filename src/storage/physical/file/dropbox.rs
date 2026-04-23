//! Dropbox `FileTarget` — stores `BackendEntry` JSON bytes as
//! files in the vault's dedicated App Folder on the user's Dropbox.
//!
//! Feature-gated on `cloud_dropbox`. Zero new external deps —
//! reuses `ureq` for HTTP, `serde_json` for API responses, and the
//! shared `oauth` + `creds` modules from earlier phases.
//!
//! Scope sandbox. The provider config at
//! `oauth::well_known_provider("dropbox")` ships no explicit
//! scopes — the App Folder sandbox is baked into the app's type
//! at developer-console registration time. Operators who register
//! BastionVault as an "App folder" app get a dedicated directory
//! under the user's Dropbox, and nothing else is visible.
//!
//! API style. Dropbox v2 is path-based (like OneDrive) but sends
//! its metadata in a `Dropbox-API-Arg` header for upload/download
//! and as JSON bodies for everything else. Upload/download go
//! through `content.dropboxapi.com`; metadata ops go through
//! `api.dropboxapi.com`. Endpoints used:
//!
//!   POST /2/files/upload            (content.) — write
//!   POST /2/files/download          (content.) — read
//!   POST /2/files/delete_v2         (api.)     — delete
//!   POST /2/files/list_folder       (api.)     — list
//!   POST /2/files/list_folder/continue (api.)  — list pagination
//!
//! Error shape. App-logic errors (file not found, conflict, etc.)
//! come back as HTTP 409 with a JSON body whose `error.".tag"` and
//! nested fields identify the specific cause. We pull out
//! "path_lookup/not_found" and map to `Ok(None)` on read / no-op
//! on delete / empty vec on list — matching `FileTarget`'s contract.
//!
//! Size ceiling. The `/2/files/upload` endpoint accepts up to
//! 150 MiB per call. Values above surface a clear error referencing
//! Dropbox's upload-session endpoints (chunked uploads) as a
//! deferred optimization. Vault keys are well under the limit in
//! practice; file-resource blobs are capped at 32 MiB above the
//! barrier anyway.

use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::{json, Value};
use ureq::{config::Config as UreqConfig, Agent};

use crate::errors::RvError;

use super::{creds, oauth, target::FileTarget};

const API_BASE: &str = "https://api.dropboxapi.com";
const CONTENT_BASE: &str = "https://content.dropboxapi.com";

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_EXPIRY_SKEW: Duration = Duration::from_secs(60);
/// Per Dropbox docs, the single-shot `/2/files/upload` endpoint is
/// documented as supporting up to 150 MiB. Above that, the upload-
/// session flow is required — out of scope for Phase 6.
const MAX_SINGLESHOT_BYTES: usize = 150 * 1024 * 1024;

#[derive(Debug)]
pub struct DropboxTarget {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    client_id: String,
    client_secret: Option<String>,
    credentials_ref: String,
    /// Prefix within the App Folder, normalized to start with `/`
    /// (Dropbox path format) and never end with `/`. Empty → `""`
    /// (app root).
    prefix: String,
    cached_access_token: Mutex<Option<CachedAccessToken>>,
    agent: Agent,
    #[allow(dead_code)]
    http_timeout: Duration,
}

#[derive(Debug)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

impl DropboxTarget {
    /// Construct a `DropboxTarget` from a raw config map.
    ///
    /// Required keys:
    ///   `client_id`       — your OAuth application's client id.
    ///   `credentials_ref` — URI naming where the refresh token
    ///                        lives. Written by `bvault operator
    ///                        cloud-target connect --target=dropbox`.
    ///
    /// Optional keys:
    ///   `client_secret`     — confidential-client secret.
    ///   `prefix`            — path inside the App Folder.
    ///   `http_timeout_secs` — per-request timeout; default 30.
    pub fn from_config(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        let client_id = conf
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("dropbox target: `client_id` is required".into()))?
            .to_string();
        let client_secret = conf
            .get("client_secret")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let credentials_ref = conf
            .get("credentials_ref")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RvError::ErrString(
                    "dropbox target: `credentials_ref` is required (run `bvault operator \
                     cloud-target connect --target=dropbox` to populate it)"
                        .into(),
                )
            })?
            .to_string();
        let prefix = normalize_prefix(conf.get("prefix").and_then(|v| v.as_str()).unwrap_or(""));
        let http_timeout = conf
            .get("http_timeout_secs")
            .and_then(|v| v.as_u64())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_HTTP_TIMEOUT);

        let agent: Agent = UreqConfig::builder()
            .timeout_global(Some(http_timeout))
            .http_status_as_error(false)
            .build()
            .into();

        let _ = creds::resolve(&credentials_ref)?;

        Ok(Self {
            inner: Arc::new(Inner {
                client_id,
                client_secret,
                credentials_ref,
                prefix,
                cached_access_token: Mutex::new(None),
                agent,
                http_timeout,
            }),
        })
    }
}

impl Inner {
    fn ensure_access_token(&self) -> Result<String, RvError> {
        {
            let cache = self.cached_access_token.lock().map_err(|e| {
                RvError::ErrString(format!("dropbox: token cache poisoned: {e}"))
            })?;
            if let Some(entry) = cache.as_ref() {
                if entry.expires_at > Instant::now() + TOKEN_EXPIRY_SKEW {
                    return Ok(entry.token.clone());
                }
            }
        }
        let refresh_secret = creds::resolve(&self.credentials_ref)?;
        let refresh_str = refresh_secret.as_str()?.trim().to_string();
        let provider = oauth::well_known_provider("dropbox")?;
        let creds_obj = oauth::OAuthCredentials {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        };
        let resp = oauth::refresh_access_token(&provider, &creds_obj, &refresh_str)?;
        let new_token = resp.access_token.clone();
        let expires_in = resp.expires_in.unwrap_or(3600);
        {
            let mut cache = self.cached_access_token.lock().map_err(|e| {
                RvError::ErrString(format!("dropbox: token cache poisoned: {e}"))
            })?;
            *cache = Some(CachedAccessToken {
                token: new_token.clone(),
                expires_at: Instant::now() + Duration::from_secs(expires_in),
            });
        }
        if let Some(rotated) = resp.refresh_token.as_deref() {
            if !rotated.is_empty() && rotated != refresh_str {
                creds::persist(&self.credentials_ref, rotated.as_bytes())?;
            }
        }
        Ok(new_token)
    }

    /// Compose the Dropbox path for a vault key, prepending any
    /// configured prefix.
    fn object_path(&self, key: &str) -> String {
        let normalized = if key.starts_with('/') {
            key.to_string()
        } else {
            format!("/{key}")
        };
        if self.prefix.is_empty() {
            normalized
        } else {
            format!("{}{normalized}", self.prefix)
        }
    }

    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        let path = self.object_path(key);
        let token = self.ensure_access_token()?;
        let api_arg = serde_json::to_string(&json!({ "path": path })).unwrap();
        let resp = self
            .agent
            .post(&format!("{CONTENT_BASE}/2/files/download"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Dropbox-API-Arg", api_arg)
            .send(&[][..])
            .map_err(|e| RvError::ErrString(format!("dropbox: GET {key}: {e}")))?;
        let status = resp.status().as_u16();
        if status == 409 {
            // Parse the error body; `path/not_found` becomes None.
            let text = resp.into_body().read_to_string().unwrap_or_default();
            if is_not_found(&text) {
                return Ok(None);
            }
            return Err(RvError::ErrString(format!(
                "dropbox: GET {key}: 409: {text}"
            )));
        }
        if !(200..300).contains(&status) {
            return Err(RvError::ErrString(format!(
                "dropbox: GET {key}: http status {status}"
            )));
        }
        Ok(Some(
            resp.into_body()
                .read_to_vec()
                .map_err(|e| RvError::ErrString(format!("dropbox: GET {key}: body: {e}")))?,
        ))
    }

    fn write(&self, key: &str, bytes: &[u8]) -> Result<(), RvError> {
        if bytes.len() > MAX_SINGLESHOT_BYTES {
            return Err(RvError::ErrString(format!(
                "dropbox: single-shot upload limited to {} bytes; key `{}` is {} bytes \
                 (upload-session support ships in a later phase)",
                MAX_SINGLESHOT_BYTES,
                key,
                bytes.len()
            )));
        }
        let path = self.object_path(key);
        let token = self.ensure_access_token()?;
        let api_arg = serde_json::to_string(&json!({
            "path": path,
            "mode": "overwrite",
            "autorename": false,
            "mute": true,
        }))
        .unwrap();
        let resp = self
            .agent
            .post(&format!("{CONTENT_BASE}/2/files/upload"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Dropbox-API-Arg", api_arg)
            .header("Content-Type", "application/octet-stream")
            .send(bytes)
            .map_err(|e| RvError::ErrString(format!("dropbox: PUT {key}: {e}")))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let detail = resp.into_body().read_to_string().unwrap_or_default();
            return Err(RvError::ErrString(format!(
                "dropbox: PUT {key}: http status {status}: {detail}"
            )));
        }
        // Drain the metadata response so the connection is clean
        // for the pool's next borrower.
        let _ = resp.into_body().read_to_string();
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), RvError> {
        let path = self.object_path(key);
        let token = self.ensure_access_token()?;
        let body = serde_json::to_vec(&json!({ "path": path })).unwrap();
        let resp = self
            .agent
            .post(&format!("{API_BASE}/2/files/delete_v2"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .send(&body[..])
            .map_err(|e| RvError::ErrString(format!("dropbox: DELETE {key}: {e}")))?;
        let status = resp.status().as_u16();
        if status == 409 {
            let text = resp.into_body().read_to_string().unwrap_or_default();
            if is_not_found(&text) {
                return Ok(());
            }
            return Err(RvError::ErrString(format!(
                "dropbox: DELETE {key}: 409: {text}"
            )));
        }
        if !(200..300).contains(&status) {
            return Err(RvError::ErrString(format!(
                "dropbox: DELETE {key}: http status {status}"
            )));
        }
        let _ = resp.into_body().read_to_string();
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        let path = {
            let full = self.object_path(prefix.trim_end_matches('/'));
            // `/2/files/list_folder` takes `""` for app root, not `/`.
            if full == "/" {
                String::new()
            } else {
                full
            }
        };
        let token = self.ensure_access_token()?;
        let mut entries: Vec<ListEntry> = Vec::new();

        // Initial page.
        let body = serde_json::to_vec(&json!({
            "path": path,
            "recursive": false,
        }))
        .unwrap();
        let mut url = format!("{API_BASE}/2/files/list_folder");
        let mut request_body = body;
        loop {
            let resp = self
                .agent
                .post(&url)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .send(&request_body[..])
                .map_err(|e| RvError::ErrString(format!("dropbox: LIST: {e}")))?;
            let status = resp.status().as_u16();
            if status == 409 {
                let text = resp.into_body().read_to_string().unwrap_or_default();
                if is_not_found(&text) {
                    return Ok(Vec::new());
                }
                return Err(RvError::ErrString(format!(
                    "dropbox: LIST: 409: {text}"
                )));
            }
            if !(200..300).contains(&status) {
                return Err(RvError::ErrString(format!(
                    "dropbox: LIST: http status {status}"
                )));
            }
            let text = resp
                .into_body()
                .read_to_string()
                .map_err(|e| RvError::ErrString(format!("dropbox: LIST body: {e}")))?;
            let parsed: ListResponse = serde_json::from_str(&text)
                .map_err(|e| RvError::ErrString(format!("dropbox: LIST parse: {e}")))?;
            entries.extend(parsed.entries);
            if parsed.has_more {
                let cursor = parsed.cursor.unwrap_or_default();
                if cursor.is_empty() {
                    break;
                }
                url = format!("{API_BASE}/2/files/list_folder/continue");
                request_body = serde_json::to_vec(&json!({ "cursor": cursor })).unwrap();
            } else {
                break;
            }
        }

        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            match e.tag.as_str() {
                "folder" => out.push(format!("{}/", e.name)),
                _ => out.push(e.name),
            }
        }
        Ok(out)
    }
}

/// Normalize a user-supplied prefix into Dropbox's path format:
/// empty stays empty; non-empty gets a leading `/`, never a trailing
/// `/` (Dropbox rejects paths ending with `/` except for root).
fn normalize_prefix(p: &str) -> String {
    let trimmed = p.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

/// Very-light detection of `path/not_found` in a 409 error body.
/// Dropbox's error structure is shaped like
/// `{"error_summary":"path/not_found/..","error":{...}}`, so a
/// substring match on `not_found` is both narrow enough to avoid
/// false positives and robust against schema drift.
fn is_not_found(body: &str) -> bool {
    body.contains("not_found")
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    entries: Vec<ListEntry>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct ListEntry {
    #[serde(rename = ".tag")]
    tag: String,
    name: String,
}

async fn blocking<F, T>(f: F) -> Result<T, RvError>
where
    F: FnOnce() -> Result<T, RvError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(RvError::ErrString(format!(
            "dropbox: worker panic/cancel: {e}"
        ))),
    }
}

#[maybe_async::maybe_async]
impl FileTarget for DropboxTarget {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        let inner = self.inner.clone();
        let key = key.to_string();
        blocking(move || inner.read(&key)).await
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        let inner = self.inner.clone();
        let key = key.to_string();
        let bytes = value.to_vec();
        blocking(move || inner.write(&key, &bytes)).await
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        let inner = self.inner.clone();
        let key = key.to_string();
        blocking(move || inner.delete(&key)).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }
        let inner = self.inner.clone();
        let prefix = prefix.to_string();
        blocking(move || inner.list(&prefix)).await
    }

    async fn lock(&self, _lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        Ok(Box::new(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(v: Value) -> HashMap<String, Value> {
        v.as_object().unwrap().clone().into_iter().collect()
    }

    fn ref_with_token(tok: &str) -> (String, std::path::PathBuf) {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bvault_dropbox_test_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::write(&p, tok).unwrap();
        (format!("file:{}", p.display()), p)
    }

    #[test]
    fn normalize_prefix_behavior() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("/"), "");
        assert_eq!(normalize_prefix("foo"), "/foo");
        assert_eq!(normalize_prefix("/foo"), "/foo");
        assert_eq!(normalize_prefix("foo/"), "/foo");
        assert_eq!(normalize_prefix("/foo/bar/"), "/foo/bar");
    }

    #[test]
    fn is_not_found_detects() {
        assert!(is_not_found(
            r#"{"error_summary":"path/not_found/..","error":{".tag":"path","path":{".tag":"not_found"}}}"#
        ));
        assert!(!is_not_found(r#"{"error_summary":"other/conflict/.."}"#));
    }

    #[test]
    fn from_config_requires_client_id() {
        let (reference, path) = ref_with_token("rt");
        let err = DropboxTarget::from_config(&cfg(json!({
            "credentials_ref": reference,
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("`client_id`"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_requires_credentials_ref() {
        let err = DropboxTarget::from_config(&cfg(json!({"client_id":"cid"}))).unwrap_err();
        assert!(format!("{err}").contains("`credentials_ref`"));
    }

    #[test]
    fn from_config_verifies_credentials_ref_resolves() {
        let err = DropboxTarget::from_config(&cfg(json!({
            "client_id": "cid",
            "credentials_ref": "file:/definitely/not/a/real/path/nowhere",
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("cannot read"));
    }

    #[test]
    fn from_config_accepts_minimal_valid() {
        let (reference, path) = ref_with_token("rt");
        let t = DropboxTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference,
        })))
        .unwrap();
        assert_eq!(t.inner.client_id, "cid");
        assert_eq!(t.inner.prefix, "");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_accepts_full() {
        let (reference, path) = ref_with_token("rt");
        let t = DropboxTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "client_secret":"sec",
            "credentials_ref": reference,
            "prefix":"bvault/data",
            "http_timeout_secs": 15,
        })))
        .unwrap();
        assert_eq!(t.inner.prefix, "/bvault/data");
        assert_eq!(t.inner.http_timeout, Duration::from_secs(15));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn object_path_prepends_prefix() {
        let (reference, path) = ref_with_token("rt");
        let t = DropboxTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference,
            "prefix":"bvault",
        })))
        .unwrap();
        assert_eq!(t.inner.object_path("sys/foo"), "/bvault/sys/foo");
        assert_eq!(t.inner.object_path("/sys/foo"), "/bvault/sys/foo");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn object_path_no_prefix_still_leading_slash() {
        let (reference, path) = ref_with_token("rt");
        let t = DropboxTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference,
        })))
        .unwrap();
        assert_eq!(t.inner.object_path("sys/foo"), "/sys/foo");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn list_response_parses() {
        let body = r#"{
            "entries": [
                {".tag":"file","name":"a.json"},
                {".tag":"folder","name":"sub"},
                {".tag":"file","name":"b.json"}
            ],
            "cursor":"abc",
            "has_more": false
        }"#;
        let parsed: ListResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[1].tag, "folder");
        assert!(!parsed.has_more);
        assert_eq!(parsed.cursor.as_deref(), Some("abc"));
    }

    #[test]
    fn list_response_parses_missing_fields() {
        let body = r#"{"entries":[]}"#;
        let parsed: ListResponse = serde_json::from_str(body).unwrap();
        assert!(parsed.entries.is_empty());
        assert!(!parsed.has_more);
        assert!(parsed.cursor.is_none());
    }

    /// Live integration test — ignored unless env vars are set.
    ///   BVAULT_TEST_DROPBOX_CLIENT_ID=...
    ///   BVAULT_TEST_DROPBOX_CREDS_FILE=/path/to/refresh-token
    ///   cargo test --features cloud_dropbox -- --ignored dropbox_target_live_roundtrip
    #[tokio::test]
    #[ignore]
    async fn dropbox_target_live_roundtrip() {
        let client_id =
            std::env::var("BVAULT_TEST_DROPBOX_CLIENT_ID").expect("BVAULT_TEST_DROPBOX_CLIENT_ID");
        let creds_file = std::env::var("BVAULT_TEST_DROPBOX_CREDS_FILE")
            .expect("BVAULT_TEST_DROPBOX_CREDS_FILE");
        let prefix = format!(
            "bvault-test-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        let target = DropboxTarget::from_config(&cfg(json!({
            "client_id": client_id,
            "credentials_ref": format!("file:{creds_file}"),
            "prefix": prefix,
        })))
        .expect("target construct");

        let payload = b"the quick brown fox".to_vec();
        target.write("dir/leaf.json", &payload).await.unwrap();
        let got = target.read("dir/leaf.json").await.unwrap();
        assert_eq!(got.as_deref(), Some(payload.as_slice()));

        let listed = target.list("dir/").await.unwrap();
        assert!(listed.iter().any(|s| s == "leaf.json"), "got: {listed:?}");

        target.delete("dir/leaf.json").await.unwrap();
        assert!(target.read("dir/leaf.json").await.unwrap().is_none());
    }
}
