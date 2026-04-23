//! Google Drive `FileTarget` — stores `BackendEntry` JSON bytes as
//! files in the vault's dedicated App Data folder on the user's
//! Google Drive.
//!
//! Feature-gated on `cloud_gdrive`. Zero new external deps — reuses
//! `ureq` for HTTP, `serde_json` for Drive v3 responses, and the
//! shared `oauth` + `creds` modules from earlier phases.
//!
//! Scope sandbox. Only `drive.appdata` is requested (see
//! `oauth::well_known_provider("gdrive")`). Files created with the
//! special parent id `appDataFolder` are visible only to this
//! application; the user's personal Drive stays invisible to
//! BastionVault, and vault data never mixes with personal files.
//!
//! Drive v3 is ID-based, not path-based. To put a file at vault
//! key `sys/foo/bar.json`, we:
//!
//!   1. Search for a folder `sys` with parent `appDataFolder`.
//!      Create it if missing.
//!   2. Search for a folder `foo` with parent=`sys`-id. Create if
//!      missing.
//!   3. Search for a file `bar.json` with parent=`foo`-id. Update
//!      its content if it exists, otherwise create.
//!
//! Searches use Drive v3's query grammar (`?q=name='x' and '<parent>'
//! in parents and trashed=false&spaces=appDataFolder`). Folder ids
//! don't change once assigned, so we cache the full-path → folder-id
//! map behind a mutex to skip repeat lookups within a process.
//!
//! Eventual consistency caveat. Google's search index is eventually
//! consistent; a file created moments ago may not appear in the
//! next search. The vault is single-writer per target, so self-
//! reads are not affected (we route writes via the cached folder
//! id and update-by-file-id when possible). Matches the design
//! doc's "cloud is eventually consistent" caveat.
//!
//! Structure. `GoogleDriveTarget` is a thin `Arc<Inner>` wrapper so
//! each async `FileTarget` method can hand its `Arc` into a single
//! `tokio::task::spawn_blocking` closure that performs every HTTP
//! round-trip synchronously — same pattern as `S3Target` and
//! `OneDriveTarget`, but with more per-operation HTTP work (chain
//! resolution, search, then upload) so pushing the whole sequence
//! onto a worker thread keeps the runtime free of sync HTTP stalls.

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

const DRIVE_BASE: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD_BASE: &str = "https://www.googleapis.com/upload/drive/v3";
const APP_DATA_FOLDER: &str = "appDataFolder";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_EXPIRY_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct GoogleDriveTarget {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    client_id: String,
    client_secret: Option<String>,
    credentials_ref: String,
    /// Path prefix inside the App Data folder, split into segments.
    /// Empty means "root of app data". No leading / trailing `""`.
    prefix_segments: Vec<String>,
    cached_access_token: Mutex<Option<CachedAccessToken>>,
    /// Full folder-path → folder-id cache. Keys are always the
    /// canonical joined path (no leading / trailing slashes).
    folder_id_cache: Mutex<HashMap<String, String>>,
    agent: Agent,
    #[allow(dead_code)]
    http_timeout: Duration,
}

#[derive(Debug)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

impl GoogleDriveTarget {
    /// Construct a `GoogleDriveTarget` from a raw config map.
    ///
    /// Required keys:
    ///   `client_id`       — your OAuth application's client id.
    ///   `credentials_ref` — URI naming where the refresh token
    ///                        lives (written by `bvault operator
    ///                        cloud-target connect --target=gdrive`).
    ///
    /// Optional keys:
    ///   `client_secret`     — confidential-client secret.
    ///   `prefix`            — path inside the App Data folder.
    ///   `http_timeout_secs` — per-request timeout; default 30.
    pub fn from_config(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        let client_id = conf
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("gdrive target: `client_id` is required".into()))?
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
                    "gdrive target: `credentials_ref` is required (run `bvault operator \
                     cloud-target connect --target=gdrive` to populate it)"
                        .into(),
                )
            })?
            .to_string();
        let prefix_segments =
            split_path(conf.get("prefix").and_then(|v| v.as_str()).unwrap_or(""));
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

        // Fail-fast on a typoed credentials_ref.
        let _ = creds::resolve(&credentials_ref)?;

        Ok(Self {
            inner: Arc::new(Inner {
                client_id,
                client_secret,
                credentials_ref,
                prefix_segments,
                cached_access_token: Mutex::new(None),
                folder_id_cache: Mutex::new(HashMap::new()),
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
                RvError::ErrString(format!("gdrive: token cache poisoned: {e}"))
            })?;
            if let Some(entry) = cache.as_ref() {
                if entry.expires_at > Instant::now() + TOKEN_EXPIRY_SKEW {
                    return Ok(entry.token.clone());
                }
            }
        }
        let refresh_secret = creds::resolve(&self.credentials_ref)?;
        let refresh_str = refresh_secret.as_str()?.trim().to_string();
        let provider = oauth::well_known_provider("gdrive")?;
        let creds_obj = oauth::OAuthCredentials {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        };
        let resp = oauth::refresh_access_token(&provider, &creds_obj, &refresh_str)?;
        let new_token = resp.access_token.clone();
        let expires_in = resp.expires_in.unwrap_or(3600);
        {
            let mut cache = self.cached_access_token.lock().map_err(|e| {
                RvError::ErrString(format!("gdrive: token cache poisoned: {e}"))
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

    /// Resolve a folder-path (relative to App Data, with any target
    /// prefix prepended) to a Drive file id. `Ok(None)` means a
    /// segment along the chain is missing and `create_missing` was
    /// false.
    fn resolve_folder_chain(
        &self,
        relative_segments: &[String],
        create_missing: bool,
    ) -> Result<Option<String>, RvError> {
        let mut full_segments: Vec<String> = self.prefix_segments.clone();
        full_segments.extend_from_slice(relative_segments);

        let mut accumulated: Vec<String> = Vec::new();
        let mut parent_id = APP_DATA_FOLDER.to_string();
        for seg in &full_segments {
            accumulated.push(seg.clone());
            let cache_key = accumulated.join("/");
            if let Some(id) = self
                .folder_id_cache
                .lock()
                .map_err(|e| RvError::ErrString(format!("gdrive: cache poisoned: {e}")))?
                .get(&cache_key)
            {
                parent_id = id.clone();
                continue;
            }
            match self.lookup_folder(&parent_id, seg)? {
                Some(id) => {
                    self.folder_id_cache
                        .lock()
                        .map_err(|e| RvError::ErrString(format!("gdrive: cache poisoned: {e}")))?
                        .insert(cache_key.clone(), id.clone());
                    parent_id = id;
                }
                None if create_missing => {
                    let id = self.create_folder(&parent_id, seg)?;
                    self.folder_id_cache
                        .lock()
                        .map_err(|e| RvError::ErrString(format!("gdrive: cache poisoned: {e}")))?
                        .insert(cache_key.clone(), id.clone());
                    parent_id = id;
                }
                None => return Ok(None),
            }
        }
        Ok(Some(parent_id))
    }

    fn lookup_folder(&self, parent_id: &str, name: &str) -> Result<Option<String>, RvError> {
        let q = format!(
            "name='{}' and '{}' in parents and mimeType='{}' and trashed=false",
            escape_query(name),
            escape_query(parent_id),
            FOLDER_MIME,
        );
        Ok(self.search(&q)?.into_iter().next().map(|f| f.id))
    }

    fn lookup_file(&self, parent_id: &str, name: &str) -> Result<Option<String>, RvError> {
        let q = format!(
            "name='{}' and '{}' in parents and mimeType!='{}' and trashed=false",
            escape_query(name),
            escape_query(parent_id),
            FOLDER_MIME,
        );
        Ok(self.search(&q)?.into_iter().next().map(|f| f.id))
    }

    fn create_folder(&self, parent_id: &str, name: &str) -> Result<String, RvError> {
        let body = json!({
            "name": name,
            "mimeType": FOLDER_MIME,
            "parents": [parent_id],
        });
        let token = self.ensure_access_token()?;
        let url = format!("{DRIVE_BASE}/files?fields=id");
        let resp = self
            .agent
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .send(&serde_json::to_vec(&body).unwrap()[..])
            .map_err(|e| RvError::ErrString(format!("gdrive: create folder `{name}`: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| RvError::ErrString(format!("gdrive: create folder body: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(RvError::ErrString(format!(
                "gdrive: create folder `{name}`: http status {status}: {text}"
            )));
        }
        let parsed: FileId = serde_json::from_str(&text)
            .map_err(|e| RvError::ErrString(format!("gdrive: create folder parse: {e}")))?;
        Ok(parsed.id)
    }

    fn search(&self, q: &str) -> Result<Vec<FileMeta>, RvError> {
        let token = self.ensure_access_token()?;
        let mut url = url::Url::parse(&format!("{DRIVE_BASE}/files")).unwrap();
        url.query_pairs_mut()
            .append_pair("q", q)
            .append_pair("spaces", APP_DATA_FOLDER)
            .append_pair("fields", "files(id,name,mimeType)")
            .append_pair("pageSize", "1000");
        let resp = self
            .agent
            .get(url.as_str())
            .header("Authorization", format!("Bearer {token}"))
            .call()
            .map_err(|e| RvError::ErrString(format!("gdrive: search: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| RvError::ErrString(format!("gdrive: search body: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(RvError::ErrString(format!(
                "gdrive: search: http status {status}: {text}"
            )));
        }
        let parsed: SearchResponse = serde_json::from_str(&text)
            .map_err(|e| RvError::ErrString(format!("gdrive: search parse: {e}")))?;
        Ok(parsed.files)
    }

    fn upload_new_file(
        &self,
        parent_id: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<String, RvError> {
        let boundary = format!(
            "bvault-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let metadata = json!({ "name": name, "parents": [parent_id] });
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap();

        // multipart/related body: one JSON part with metadata, one
        // octet-stream part with content, CRLF-delimited boundaries.
        let mut body: Vec<u8> = Vec::with_capacity(bytes.len() + metadata_bytes.len() + 256);
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        body.extend_from_slice(&metadata_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let token = self.ensure_access_token()?;
        let url = format!("{UPLOAD_BASE}/files?uploadType=multipart&fields=id");
        let resp = self
            .agent
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header(
                "Content-Type",
                format!("multipart/related; boundary={boundary}"),
            )
            .send(&body[..])
            .map_err(|e| RvError::ErrString(format!("gdrive: upload `{name}`: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| RvError::ErrString(format!("gdrive: upload body: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(RvError::ErrString(format!(
                "gdrive: upload `{name}`: http status {status}: {text}"
            )));
        }
        let parsed: FileId = serde_json::from_str(&text)
            .map_err(|e| RvError::ErrString(format!("gdrive: upload parse: {e}")))?;
        Ok(parsed.id)
    }

    fn update_file_content(&self, file_id: &str, bytes: &[u8]) -> Result<(), RvError> {
        let token = self.ensure_access_token()?;
        let url = format!("{UPLOAD_BASE}/files/{file_id}?uploadType=media");
        let resp = self
            .agent
            .patch(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/octet-stream")
            .send(bytes)
            .map_err(|e| RvError::ErrString(format!("gdrive: update `{file_id}`: {e}")))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let detail = resp
                .into_body()
                .read_to_string()
                .unwrap_or_else(|_| "<no body>".into());
            return Err(RvError::ErrString(format!(
                "gdrive: update `{file_id}`: http status {status}: {detail}"
            )));
        }
        Ok(())
    }

    fn download_file(&self, file_id: &str) -> Result<Vec<u8>, RvError> {
        let token = self.ensure_access_token()?;
        let url = format!("{DRIVE_BASE}/files/{file_id}?alt=media");
        let resp = self
            .agent
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .call()
            .map_err(|e| RvError::ErrString(format!("gdrive: download `{file_id}`: {e}")))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(RvError::ErrString(format!(
                "gdrive: download `{file_id}`: http status {status}"
            )));
        }
        resp.into_body()
            .read_to_vec()
            .map_err(|e| RvError::ErrString(format!("gdrive: download body: {e}")))
    }

    fn delete_file(&self, file_id: &str) -> Result<(), RvError> {
        let token = self.ensure_access_token()?;
        let url = format!("{DRIVE_BASE}/files/{file_id}");
        let resp = self
            .agent
            .delete(&url)
            .header("Authorization", format!("Bearer {token}"))
            .call()
            .map_err(|e| RvError::ErrString(format!("gdrive: delete `{file_id}`: {e}")))?;
        let status = resp.status().as_u16();
        if status == 204 || status == 404 || (200..300).contains(&status) {
            Ok(())
        } else {
            Err(RvError::ErrString(format!(
                "gdrive: delete `{file_id}`: http status {status}"
            )))
        }
    }
}

/// Split a `/`-delimited path into non-empty segments, discarding
/// leading / trailing / empty parts. `""` → `[]`, `"a"` → `["a"]`,
/// `"/a/b/"` → `["a","b"]`, `"a//b"` → `["a","b"]`.
fn split_path(p: &str) -> Vec<String> {
    p.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Split a vault key into `(parent_segments, filename)`.
/// `"a/b/c"` → `(["a","b"], "c")`; `"x"` → `([], "x")`.
fn split_parent_and_name(key: &str) -> (Vec<String>, String) {
    let parts = split_path(key);
    let name = parts.last().cloned().unwrap_or_default();
    let parent: Vec<String> = parts[..parts.len().saturating_sub(1)].to_vec();
    (parent, name)
}

/// Drive v3 query literals use single quotes; literal single quotes
/// inside a string escape as `\'`. Backslashes escape as `\\`.
fn escape_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            _ => out.push(ch),
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct FileId {
    id: String,
}

#[derive(Debug, Deserialize)]
struct FileMeta {
    id: String,
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "mimeType", default)]
    mime_type: String,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    files: Vec<FileMeta>,
}

async fn blocking<F, T>(f: F) -> Result<T, RvError>
where
    F: FnOnce() -> Result<T, RvError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(RvError::ErrString(format!(
            "gdrive: worker panic/cancel: {e}"
        ))),
    }
}

#[maybe_async::maybe_async]
impl FileTarget for GoogleDriveTarget {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        let inner = self.inner.clone();
        let key = key.to_string();
        blocking(move || {
            let (parent_segs, name) = split_parent_and_name(&key);
            let parent_id = match inner.resolve_folder_chain(&parent_segs, false)? {
                Some(id) => id,
                None => return Ok(None),
            };
            let file_id = match inner.lookup_file(&parent_id, &name)? {
                Some(id) => id,
                None => return Ok(None),
            };
            Ok(Some(inner.download_file(&file_id)?))
        })
        .await
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        let inner = self.inner.clone();
        let key = key.to_string();
        let bytes = value.to_vec();
        blocking(move || {
            let (parent_segs, name) = split_parent_and_name(&key);
            if name.is_empty() {
                return Err(RvError::ErrString(format!(
                    "gdrive: empty filename in key `{key}`"
                )));
            }
            let parent_id = inner
                .resolve_folder_chain(&parent_segs, true)?
                .expect("create_missing=true always returns Some");
            match inner.lookup_file(&parent_id, &name)? {
                Some(id) => inner.update_file_content(&id, &bytes),
                None => inner.upload_new_file(&parent_id, &name, &bytes).map(|_| ()),
            }
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        let inner = self.inner.clone();
        let key = key.to_string();
        blocking(move || {
            let (parent_segs, name) = split_parent_and_name(&key);
            let parent_id = match inner.resolve_folder_chain(&parent_segs, false)? {
                Some(id) => id,
                None => return Ok(()),
            };
            match inner.lookup_file(&parent_id, &name)? {
                Some(id) => inner.delete_file(&id),
                None => Ok(()),
            }
        })
        .await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }
        let inner = self.inner.clone();
        let prefix = prefix.to_string();
        blocking(move || {
            let segs = split_path(&prefix);
            let parent_id = match inner.resolve_folder_chain(&segs, false)? {
                Some(id) => id,
                None => return Ok(Vec::new()),
            };
            let q = format!(
                "'{}' in parents and trashed=false",
                escape_query(&parent_id)
            );
            let hits = inner.search(&q)?;
            let mut out = Vec::with_capacity(hits.len());
            for h in hits {
                if h.mime_type == FOLDER_MIME {
                    out.push(format!("{}/", h.name));
                } else {
                    out.push(h.name);
                }
            }
            Ok(out)
        })
        .await
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
            "bvault_gdrive_test_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::write(&p, tok).unwrap();
        (format!("file:{}", p.display()), p)
    }

    #[test]
    fn split_path_behavior() {
        assert!(split_path("").is_empty());
        assert!(split_path("/").is_empty());
        assert_eq!(split_path("a"), vec!["a".to_string()]);
        assert_eq!(split_path("a/b/c"), vec!["a", "b", "c"]);
        assert_eq!(split_path("/a/b/"), vec!["a", "b"]);
        assert_eq!(split_path("a//b"), vec!["a", "b"]);
    }

    #[test]
    fn split_parent_and_name_behavior() {
        let (p, n) = split_parent_and_name("a/b/c");
        assert_eq!(p, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(n, "c");

        let (p, n) = split_parent_and_name("leaf");
        assert!(p.is_empty());
        assert_eq!(n, "leaf");

        let (p, n) = split_parent_and_name("/a");
        assert!(p.is_empty());
        assert_eq!(n, "a");
    }

    #[test]
    fn escape_query_escapes_quotes_and_backslashes() {
        assert_eq!(escape_query("foo"), "foo");
        assert_eq!(escape_query("a'b"), "a\\'b");
        assert_eq!(escape_query("a\\b"), "a\\\\b");
        assert_eq!(escape_query("a'b\\c"), "a\\'b\\\\c");
    }

    #[test]
    fn from_config_requires_client_id() {
        let (reference, path) = ref_with_token("rt");
        let err = GoogleDriveTarget::from_config(&cfg(json!({
            "credentials_ref": reference,
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("`client_id`"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_requires_credentials_ref() {
        let err = GoogleDriveTarget::from_config(&cfg(json!({"client_id":"cid"}))).unwrap_err();
        assert!(format!("{err}").contains("`credentials_ref`"));
    }

    #[test]
    fn from_config_verifies_credentials_ref_resolves() {
        let err = GoogleDriveTarget::from_config(&cfg(json!({
            "client_id": "cid",
            "credentials_ref": "file:/definitely/not/a/real/path/nowhere",
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("cannot read"));
    }

    #[test]
    fn from_config_accepts_minimal_valid() {
        let (reference, path) = ref_with_token("rt");
        let t = GoogleDriveTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference,
        })))
        .unwrap();
        assert_eq!(t.inner.client_id, "cid");
        assert!(t.inner.prefix_segments.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_accepts_full() {
        let (reference, path) = ref_with_token("rt");
        let t = GoogleDriveTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "client_secret":"sec",
            "credentials_ref": reference,
            "prefix":"bvault/data",
            "http_timeout_secs": 15,
        })))
        .unwrap();
        assert_eq!(
            t.inner.prefix_segments,
            vec!["bvault".to_string(), "data".to_string()]
        );
        assert_eq!(t.inner.http_timeout, Duration::from_secs(15));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn search_response_parses() {
        let body = r#"{
            "files": [
                {"id":"abc","name":"foo","mimeType":"application/octet-stream"},
                {"id":"def","name":"sub","mimeType":"application/vnd.google-apps.folder"}
            ]
        }"#;
        let parsed: SearchResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files[0].id, "abc");
        assert_eq!(parsed.files[1].mime_type, FOLDER_MIME);
    }

    #[test]
    fn search_response_parses_empty() {
        let parsed: SearchResponse = serde_json::from_str(r#"{"files":[]}"#).unwrap();
        assert!(parsed.files.is_empty());
    }

    #[test]
    fn search_response_parses_missing_field() {
        let parsed: SearchResponse = serde_json::from_str(r#"{}"#).unwrap();
        assert!(parsed.files.is_empty());
    }

    /// Live integration test — ignored unless env vars are set.
    ///   BVAULT_TEST_GDRIVE_CLIENT_ID=...
    ///   BVAULT_TEST_GDRIVE_CREDS_FILE=/path/to/refresh-token
    ///   cargo test --features cloud_gdrive -- --ignored gdrive_target_live_roundtrip
    #[tokio::test]
    #[ignore]
    async fn gdrive_target_live_roundtrip() {
        let client_id =
            std::env::var("BVAULT_TEST_GDRIVE_CLIENT_ID").expect("BVAULT_TEST_GDRIVE_CLIENT_ID");
        let creds_file =
            std::env::var("BVAULT_TEST_GDRIVE_CREDS_FILE").expect("BVAULT_TEST_GDRIVE_CREDS_FILE");
        let prefix = format!(
            "bvault-test-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        let target = GoogleDriveTarget::from_config(&cfg(json!({
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
        // Eventual consistency on Drive search; the lookup-by-id
        // path should still register the deletion cleanly.
        assert!(target.read("dir/leaf.json").await.unwrap().is_none());
    }
}
