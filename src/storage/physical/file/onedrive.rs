//! OneDrive `FileTarget` — stores `BackendEntry` JSON bytes as
//! files in the vault's dedicated App Folder on the user's OneDrive.
//!
//! Feature-gated on `cloud_onedrive`. When the feature is off, this
//! module compiles out completely; the default build carries zero
//! OneDrive code and no additional deps (OneDrive reuses `ureq`
//! + `serde_json` that are already in the tree, plus the shared
//! `oauth` + `creds` modules from earlier phases).
//!
//! Scope sandbox. We only ever request `Files.ReadWrite.AppFolder`
//! (see `oauth::well_known_provider("onedrive")`), which restricts
//! the vault to a folder Graph API calls `approot`. BastionVault
//! cannot see the rest of the user's OneDrive, and the user cannot
//! accidentally mix vault data with their personal files. Matches
//! the design doc's "narrowest available scope" guidance.
//!
//! Authentication. On construction the target caches nothing; on
//! each operation it takes a short mutex to check / refresh the
//! access token using the `refresh_token` stored at
//! `credentials_ref`. If the provider rotates the refresh token,
//! the new one is persisted via `creds::persist` — atomically, so
//! a concurrent reader sees the old or new token but never a
//! partial write.
//!
//! Upload size ceiling. Phase 4 uses the Graph API's single-shot
//! PUT `:/content` endpoint, which Microsoft documents as supporting
//! content up to 4 MiB. Every vault key we care about today is far
//! below that (policies, tokens, small blobs); a larger write
//! surfaces a clear error with the remediation ("upload session
//! support ships in a later phase"). Vault keys are not File
//! Resources — those already have their own 32 MiB cap handled in
//! `src/modules/files/mod.rs`, above the barrier.
//!
//! Single-writer. OneDrive's conflict-resolution semantics are
//! last-write-wins on the item id. The spec's documented single-
//! writer-per-target assumption applies; `lock()` is a no-op.

use std::{
    any::Any,
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::Value;
use ureq::{config::Config as UreqConfig, Agent};

use crate::errors::RvError;

use super::{creds, oauth, target::FileTarget};

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound the Graph API enforces on the single-shot `:/content`
/// upload endpoint. Values above this need the upload-session flow,
/// which is intentionally out of scope for Phase 4.
const MAX_SINGLESHOT_BYTES: usize = 4 * 1024 * 1024;
/// Skew we apply on access-token expiry so a token that's *almost*
/// expired is refreshed proactively rather than failing mid-request.
const TOKEN_EXPIRY_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct OneDriveTarget {
    client_id: String,
    client_secret: Option<String>,
    /// `credentials_ref` (e.g. `file:/etc/bvault/onedrive-refresh`)
    /// that the refresh token lives at. Resolved on each token
    /// refresh so an operator who hand-rotates the token doesn't
    /// have to bounce the vault.
    credentials_ref: String,
    /// Path prefix inside the App Folder. Empty means "root of the
    /// app folder". Always normalized with a trailing `/` if non-
    /// empty so concatenation never produces `//`.
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

impl OneDriveTarget {
    /// Construct a `OneDriveTarget` from a raw config map.
    ///
    /// Required keys:
    ///   `client_id`       — your OAuth application's client id
    ///                        (BastionVault ships no consumer-
    ///                        provider client secrets).
    ///   `credentials_ref` — URI naming where the refresh token
    ///                        lives (see `creds::resolve`). Written
    ///                        by `bvault operator cloud-target
    ///                        connect`.
    ///
    /// Optional keys:
    ///   `client_secret`       — confidential-client secret; omit
    ///                            for public-client PKCE-only apps.
    ///   `prefix`              — path inside the App Folder.
    ///   `http_timeout_secs`   — per-request timeout; default 30.
    pub fn from_config(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        let client_id = conf
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("onedrive target: `client_id` is required".into()))?
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
                    "onedrive target: `credentials_ref` is required (run `bvault operator \
                     cloud-target connect --target=onedrive` to populate it)"
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

        // Eagerly verify we can resolve the refresh token so a typo
        // in `credentials_ref` fails at boot rather than on the
        // first I/O. We don't *consume* it here — the mutex-
        // protected `ensure_access_token` path does that on demand.
        let _ = creds::resolve(&credentials_ref)?;

        Ok(Self {
            client_id,
            client_secret,
            credentials_ref,
            prefix,
            cached_access_token: Mutex::new(None),
            agent,
            http_timeout,
        })
    }

    fn item_url(&self, key: &str, tail: &str) -> String {
        // `approot:/<path>:<tail>` where `tail` is one of `"/content"`,
        // `"/children"`, `""` (delete / metadata).
        let object = format!("{}{}", self.prefix, key);
        let encoded = encode_path(&object);
        if tail.is_empty() {
            format!("{GRAPH_BASE}/me/drive/special/approot:/{encoded}:")
        } else {
            format!("{GRAPH_BASE}/me/drive/special/approot:/{encoded}:{tail}")
        }
    }

    /// Children of `approot` directly (no colon-path) for `list("")`.
    fn root_children_url(&self) -> String {
        if self.prefix.is_empty() {
            format!("{GRAPH_BASE}/me/drive/special/approot/children")
        } else {
            // Prefix is a folder inside the AppFolder; fall back to
            // the colon-path form against that folder.
            let encoded = encode_path(self.prefix.trim_end_matches('/'));
            format!("{GRAPH_BASE}/me/drive/special/approot:/{encoded}:/children")
        }
    }

    /// Return a currently-valid access token, refreshing if needed.
    /// Blocks the calling thread — designed to be invoked from the
    /// `spawn_blocking` wrapper around each HTTP verb so we never
    /// park the tokio runtime.
    fn ensure_access_token(&self) -> Result<String, RvError> {
        // Fast path: cached token is still valid.
        {
            let cache = self.cached_access_token.lock().map_err(|e| {
                RvError::ErrString(format!("onedrive: token cache poisoned: {e}"))
            })?;
            if let Some(entry) = cache.as_ref() {
                if entry.expires_at > Instant::now() + TOKEN_EXPIRY_SKEW {
                    return Ok(entry.token.clone());
                }
            }
        }

        // Slow path: refresh. Resolve the refresh token from the
        // configured reference (so rotated tokens pick up without a
        // restart), then hit the provider.
        let refresh_secret = creds::resolve(&self.credentials_ref)?;
        let refresh_str = refresh_secret.as_str()?.trim().to_string();
        let provider = oauth::well_known_provider("onedrive")?;
        let creds_obj = oauth::OAuthCredentials {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        };
        let resp = oauth::refresh_access_token(&provider, &creds_obj, &refresh_str)?;

        let expires_in = resp.expires_in.unwrap_or(3600);
        let new_token = resp.access_token.clone();
        {
            let mut cache = self.cached_access_token.lock().map_err(|e| {
                RvError::ErrString(format!("onedrive: token cache poisoned: {e}"))
            })?;
            *cache = Some(CachedAccessToken {
                token: new_token.clone(),
                expires_at: Instant::now() + Duration::from_secs(expires_in),
            });
        }

        // If the provider rotated the refresh token, persist the
        // new one. Unrotated responses omit the field; keep the
        // stored token unchanged in that case.
        if let Some(rotated) = resp.refresh_token.as_deref() {
            if !rotated.is_empty() && rotated != refresh_str {
                creds::persist(&self.credentials_ref, rotated.as_bytes())?;
            }
        }

        Ok(new_token)
    }
}

/// Normalize a user-supplied prefix: empty stays empty, non-empty
/// gets a trailing `/` so concatenation with keys never double-
/// slashes. Leading `/` is trimmed — Graph API doesn't want it.
fn normalize_prefix(p: &str) -> String {
    let trimmed = p.trim_start_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/")
    }
}

/// URL-encode each path segment independently, keeping `/` as the
/// segment separator. Same shape as S3's key encoding but targeted
/// at Graph API's colon-path syntax.
///
/// The unreserved set per RFC 3986 §2.3 (`A-Z a-z 0-9 - . _ ~`) is
/// passed through verbatim; everything else — including `:`, spaces,
/// and non-ASCII bytes — is percent-encoded so keys with awkward
/// characters round-trip cleanly.
fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        for b in segment.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Percent-decode a segment Graph API returned — children names
/// come back as plain UTF-8 text in JSON, but we keep the helper
/// for defensive symmetry with `S3Target::percent_decode`. Graph
/// does not URL-encode its JSON payloads; if a non-UTF-8 byte ever
/// appears we fall back lossily rather than panicking.
#[allow(dead_code)]
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct ChildrenResponse {
    #[serde(default)]
    value: Vec<ChildItem>,
    #[serde(rename = "@odata.nextLink", default)]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChildItem {
    name: String,
    /// Present only on folder items.
    #[serde(default)]
    folder: Option<serde_json::Value>,
}

async fn blocking<F, T>(f: F) -> Result<T, RvError>
where
    F: FnOnce() -> Result<T, RvError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(RvError::ErrString(format!(
            "onedrive: worker panic/cancel: {e}"
        ))),
    }
}

#[maybe_async::maybe_async]
impl FileTarget for OneDriveTarget {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        let url = self.item_url(key, "/content");
        let token = self.ensure_access_token()?;
        let agent = self.agent.clone();
        let key_owned = key.to_string();
        blocking(move || {
            // `:/content` returns raw bytes on 200, 302 (pre-signed
            // download URL) on some paths, 404 on missing. ureq
            // follows redirects by default, so we just handle 200
            // and 404 explicitly.
            let resp = agent
                .get(&url)
                .header("Authorization", format!("Bearer {token}"))
                .call()
                .map_err(|e| RvError::ErrString(format!("onedrive: GET {key_owned}: {e}")))?;
            let status = resp.status().as_u16();
            if status == 404 {
                return Ok(None);
            }
            if !(200..300).contains(&status) {
                return Err(RvError::ErrString(format!(
                    "onedrive: GET {key_owned}: http status {status}"
                )));
            }
            let body = resp
                .into_body()
                .read_to_vec()
                .map_err(|e| RvError::ErrString(format!("onedrive: read body: {e}")))?;
            Ok(Some(body))
        })
        .await
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        if value.len() > MAX_SINGLESHOT_BYTES {
            return Err(RvError::ErrString(format!(
                "onedrive: single-shot upload limited to {} bytes; key `{}` is {} bytes \
                 (upload-session support ships in a later phase)",
                MAX_SINGLESHOT_BYTES,
                key,
                value.len()
            )));
        }
        let url = self.item_url(key, "/content");
        let token = self.ensure_access_token()?;
        let agent = self.agent.clone();
        let body = value.to_vec();
        let key_owned = key.to_string();
        blocking(move || {
            let resp = agent
                .put(&url)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/octet-stream")
                .send(&body[..])
                .map_err(|e| RvError::ErrString(format!("onedrive: PUT {key_owned}: {e}")))?;
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                // Drain the error body so the surfaced message
                // carries Graph's explanation (helps debug 400s on
                // name-constraint violations).
                let detail = resp
                    .into_body()
                    .read_to_string()
                    .unwrap_or_else(|_| "<no body>".into());
                return Err(RvError::ErrString(format!(
                    "onedrive: PUT {key_owned}: http status {status}: {detail}"
                )));
            }
            Ok(())
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        let url = self.item_url(key, "");
        let token = self.ensure_access_token()?;
        let agent = self.agent.clone();
        let key_owned = key.to_string();
        blocking(move || {
            let resp = agent
                .delete(&url)
                .header("Authorization", format!("Bearer {token}"))
                .call()
                .map_err(|e| RvError::ErrString(format!("onedrive: DELETE {key_owned}: {e}")))?;
            let status = resp.status().as_u16();
            // 204 on success; 404 treated as success per FileTarget contract.
            if status == 204 || status == 404 || (200..300).contains(&status) {
                Ok(())
            } else {
                Err(RvError::ErrString(format!(
                    "onedrive: DELETE {key_owned}: http status {status}"
                )))
            }
        })
        .await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }
        // Graph API exposes children-of-a-folder as a collection
        // rather than a "list with prefix" primitive. We translate
        // `prefix = "a/b/"` into "list the children of folder
        // `a/b`"; a non-empty non-trailing prefix is interpreted as
        // a full folder path too.
        let trimmed = prefix.trim_end_matches('/');
        let initial_url = if trimmed.is_empty() {
            self.root_children_url()
        } else {
            self.item_url(trimmed, "/children")
        };

        let mut url = initial_url;
        let mut out: Vec<String> = Vec::new();
        loop {
            let token = self.ensure_access_token()?;
            let agent = self.agent.clone();
            let url_copy = url.clone();
            let body = blocking(move || {
                let resp = agent
                    .get(&url_copy)
                    .header("Authorization", format!("Bearer {token}"))
                    .call()
                    .map_err(|e| RvError::ErrString(format!("onedrive: LIST: {e}")))?;
                let status = resp.status().as_u16();
                if status == 404 {
                    return Ok::<Option<String>, RvError>(None);
                }
                if !(200..300).contains(&status) {
                    return Err(RvError::ErrString(format!(
                        "onedrive: LIST: http status {status}"
                    )));
                }
                let body = resp
                    .into_body()
                    .read_to_string()
                    .map_err(|e| RvError::ErrString(format!("onedrive: LIST body: {e}")))?;
                Ok(Some(body))
            })
            .await?;

            let body = match body {
                Some(b) => b,
                // Missing prefix: empty listing, matching the local
                // target's contract.
                None => return Ok(Vec::new()),
            };
            let parsed: ChildrenResponse = serde_json::from_str(&body).map_err(|e| {
                RvError::ErrString(format!("onedrive: LIST parse: {e}"))
            })?;
            for item in parsed.value {
                if item.folder.is_some() {
                    out.push(format!("{}/", item.name));
                } else {
                    out.push(item.name);
                }
            }
            match parsed.next_link {
                Some(next) if !next.is_empty() => url = next,
                _ => break,
            }
        }
        Ok(out)
    }

    async fn lock(&self, _lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        // Single-writer-per-target (documented); `FileTarget::lock`
        // is a no-op for OneDrive, matching S3.
        Ok(Box::new(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(v: Value) -> HashMap<String, Value> {
        v.as_object().unwrap().clone().into_iter().collect()
    }

    /// Write a fresh `file:` credentials_ref so `from_config` sees
    /// a resolvable value without talking to any real provider.
    fn ref_with_token(tok: &str) -> (String, std::path::PathBuf) {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bvault_onedrive_test_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::write(&p, tok).unwrap();
        (format!("file:{}", p.display()), p)
    }

    #[test]
    fn from_config_requires_client_id() {
        let (reference, path) = ref_with_token("rt");
        let err = OneDriveTarget::from_config(&cfg(json!({
            "credentials_ref": reference,
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("`client_id`"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_requires_credentials_ref() {
        let err = OneDriveTarget::from_config(&cfg(json!({"client_id":"cid"}))).unwrap_err();
        assert!(format!("{err}").contains("`credentials_ref`"));
    }

    #[test]
    fn from_config_verifies_credentials_ref_resolves() {
        let err = OneDriveTarget::from_config(&cfg(json!({
            "client_id": "cid",
            "credentials_ref": "file:/definitely/not/a/real/path/nowhere",
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("cannot read"));
    }

    #[test]
    fn from_config_accepts_minimal_valid() {
        let (reference, path) = ref_with_token("rt");
        let t = OneDriveTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference,
        })))
        .unwrap();
        assert_eq!(t.client_id, "cid");
        assert!(t.client_secret.is_none());
        assert_eq!(t.prefix, "");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn from_config_accepts_full() {
        let (reference, path) = ref_with_token("rt");
        let t = OneDriveTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "client_secret":"sec",
            "credentials_ref": reference,
            "prefix":"bvault",
            "http_timeout_secs": 15,
        })))
        .unwrap();
        assert_eq!(t.prefix, "bvault/");
        assert_eq!(t.client_secret.as_deref(), Some("sec"));
        assert_eq!(t.http_timeout, Duration::from_secs(15));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn normalize_prefix_behavior() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("foo"), "foo/");
        assert_eq!(normalize_prefix("foo/"), "foo/");
        assert_eq!(normalize_prefix("/foo"), "foo/");
        assert_eq!(normalize_prefix("/foo/bar/"), "foo/bar/");
    }

    #[test]
    fn encode_path_preserves_slashes_encodes_specials() {
        assert_eq!(encode_path("foo/bar"), "foo/bar");
        assert_eq!(encode_path("a b/c d"), "a%20b/c%20d");
        assert_eq!(encode_path("sys:v1/foo"), "sys%3Av1/foo");
        assert_eq!(encode_path("hello.world_3-a~b"), "hello.world_3-a~b");
    }

    #[test]
    fn item_url_composes_expected_endpoint() {
        let (reference, path) = ref_with_token("rt");
        let t = OneDriveTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference,
            "prefix":"bvault",
        })))
        .unwrap();
        assert_eq!(
            t.item_url("sys/foo", "/content"),
            format!("{GRAPH_BASE}/me/drive/special/approot:/bvault/sys/foo:/content")
        );
        assert_eq!(
            t.item_url("sys/foo", ""),
            format!("{GRAPH_BASE}/me/drive/special/approot:/bvault/sys/foo:")
        );
        assert_eq!(
            t.item_url("sys/foo", "/children"),
            format!("{GRAPH_BASE}/me/drive/special/approot:/bvault/sys/foo:/children")
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn root_children_url_respects_prefix() {
        let (reference, path) = ref_with_token("rt");
        // No prefix: hits `approot/children` directly.
        let t_no = OneDriveTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference.clone(),
        })))
        .unwrap();
        assert_eq!(
            t_no.root_children_url(),
            format!("{GRAPH_BASE}/me/drive/special/approot/children")
        );

        // With prefix: colon-path into the prefix folder.
        let t_pref = OneDriveTarget::from_config(&cfg(json!({
            "client_id":"cid",
            "credentials_ref": reference,
            "prefix":"bvault",
        })))
        .unwrap();
        assert_eq!(
            t_pref.root_children_url(),
            format!("{GRAPH_BASE}/me/drive/special/approot:/bvault:/children")
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn children_response_parses() {
        let body = r#"{
            "value": [
                {"name": "foo.bin"},
                {"name": "subdir", "folder": {"childCount": 3}},
                {"name": "bar.bin"}
            ]
        }"#;
        let parsed: ChildrenResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.value.len(), 3);
        assert!(parsed.value[0].folder.is_none());
        assert!(parsed.value[1].folder.is_some());
        assert!(parsed.value[2].folder.is_none());
        assert!(parsed.next_link.is_none());
    }

    #[test]
    fn children_response_parses_next_link() {
        let body = r#"{
            "value": [{"name":"a"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/..."
        }"#;
        let parsed: ChildrenResponse = serde_json::from_str(body).unwrap();
        assert!(parsed.next_link.unwrap().contains("nextLink") == false);
    }

    #[test]
    fn percent_decode_matches_encode() {
        let encoded = encode_path("a b/c:d");
        assert_eq!(percent_decode(&encoded), "a b/c:d");
    }

    /// Live integration test — ignored unless all the env vars
    /// below are set. Expects a pre-populated refresh token on disk.
    /// Mirrors the S3 live test.
    ///
    /// Enable with:
    ///   BVAULT_TEST_ONEDRIVE_CLIENT_ID=...
    ///   BVAULT_TEST_ONEDRIVE_CREDS_FILE=/path/to/refresh-token
    ///   cargo test --features cloud_onedrive -- --ignored onedrive_target_live_roundtrip
    #[tokio::test]
    #[ignore]
    async fn onedrive_target_live_roundtrip() {
        let client_id = std::env::var("BVAULT_TEST_ONEDRIVE_CLIENT_ID")
            .expect("BVAULT_TEST_ONEDRIVE_CLIENT_ID");
        let creds_file = std::env::var("BVAULT_TEST_ONEDRIVE_CREDS_FILE")
            .expect("BVAULT_TEST_ONEDRIVE_CREDS_FILE");
        let prefix = format!(
            "bvault-test-{}/",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        let target = OneDriveTarget::from_config(&cfg(json!({
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
