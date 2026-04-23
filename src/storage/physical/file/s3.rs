//! S3 `FileTarget` — stores `BackendEntry` JSON bytes as objects in
//! an S3-compatible bucket.
//!
//! Feature-gated on `cloud_s3`. When the feature is off, this module
//! compiles out completely and the default build carries zero S3
//! code or transitive deps.
//!
//! Stack choice — why `rusty-s3` + `ureq` rather than `aws-sdk-s3`:
//! The Phase-2b brief asked for the smallest viable crate. `aws-sdk-s3`
//! pulls ~50–80 transitive deps and a whole HTTP/TLS stack. `rusty-s3`
//! is a pure URL-signing + XML-parsing library (~4 new deps on top of
//! what we already ship) and leaves HTTP to whatever client the app
//! already uses. Since `ureq` is already in the tree for
//! post-quantum-TLS-compatible HTTP, we pair the two: `rusty-s3` signs
//! every request, `ureq` moves the bytes. `ureq` is synchronous, so
//! each verb on the async `FileTarget` trait hops through
//! `tokio::task::spawn_blocking` to avoid parking the runtime.
//!
//! Works against MinIO via `endpoint_url = "http://host:port"` +
//! `url_style = "path"`. AWS S3 works with the default virtual-host
//! style (region-aware endpoints).
//!
//! Locking: S3 has no native lock primitive. The spec's documented
//! single-writer-per-target assumption applies; `lock()` is a no-op
//! that returns a trivial guard.

use std::{any::Any, collections::HashMap, sync::Arc, time::Duration};

use rusty_s3::{
    actions::{DeleteObject, GetObject, ListObjectsV2, PutObject, S3Action},
    Bucket, Credentials, UrlStyle,
};
use serde_json::Value;
use ureq::{config::Config as UreqConfig, Agent};
use url::Url;

use crate::errors::RvError;

use super::target::FileTarget;

/// How long a presigned URL stays valid. Each operation signs
/// on-demand immediately before issuing the HTTP request, so a
/// single minute is plenty and minimizes the replay window.
const SIGN_EXPIRY: Duration = Duration::from_secs(60);

/// Upper bound on how long a single HTTP request may take. Tuned
/// for vault-shaped traffic (small objects, low latency). Operators
/// can override via `http_timeout_secs` in the config.
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct S3Target {
    bucket: Bucket,
    credentials: Credentials,
    /// Object-key prefix under which all vault keys live. Empty
    /// string means "root of the bucket". Always normalized with a
    /// trailing `/` if non-empty so we can concatenate without
    /// double-`/` accidents.
    prefix: String,
    /// Retained for debug / observability; current `Agent` holds the
    /// effective timeout internally. Kept on the struct so
    /// tooling-style introspection (future metrics export) has a
    /// single source of truth.
    #[allow(dead_code)]
    http_timeout: Duration,
    agent: Agent,
}

impl S3Target {
    /// Construct an `S3Target` from a raw config map.
    ///
    /// Required keys:
    ///   `bucket` (string) — bucket name.
    ///   `region` (string) — AWS region (MinIO accepts any string,
    ///                        but one must be present to satisfy
    ///                        SigV4).
    ///
    /// Optional keys:
    ///   `endpoint_url`      — custom endpoint (MinIO, localstack).
    ///                         When absent, AWS virtual-host-style
    ///                         `https://s3.<region>.amazonaws.com`.
    ///   `url_style`         — `"virtual"` (default) or `"path"`
    ///                         (required for most MinIO setups).
    ///   `prefix`            — object-key prefix; auto-appends `/`.
    ///   `credentials_ref`   — URI handled by the creds resolver.
    ///                         JSON body parsed as static AWS creds;
    ///                         absent falls back to `AWS_ACCESS_KEY_ID`
    ///                         / `AWS_SECRET_ACCESS_KEY` env vars.
    ///   `http_timeout_secs` — override per-request timeout.
    pub fn from_config(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        let bucket_name = conf
            .get("bucket")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("s3 target: `bucket` is required".into()))?;
        let region = conf
            .get("region")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RvError::ErrString("s3 target: `region` is required".into()))?;

        let endpoint_url: Url = match conf.get("endpoint_url").and_then(|v| v.as_str()) {
            Some(u) => u
                .parse()
                .map_err(|e| RvError::ErrString(format!("s3 target: bad `endpoint_url`: {e}")))?,
            None => format!("https://s3.{region}.amazonaws.com")
                .parse()
                .expect("AWS URL is valid"),
        };
        let url_style = match conf.get("url_style").and_then(|v| v.as_str()).unwrap_or("virtual") {
            "path" => UrlStyle::Path,
            "virtual" | "virtual-hosted" => UrlStyle::VirtualHost,
            other => {
                return Err(RvError::ErrString(format!(
                    "s3 target: unknown `url_style = {other}` (expected `path` or `virtual`)"
                )));
            }
        };

        let bucket = Bucket::new(endpoint_url, url_style, bucket_name.to_string(), region.to_string())
            .map_err(|e| RvError::ErrString(format!("s3 target: bucket construct: {e}")))?;

        let credentials = resolve_credentials(conf)?;

        let prefix = normalize_prefix(conf.get("prefix").and_then(|v| v.as_str()).unwrap_or(""));

        let http_timeout = conf
            .get("http_timeout_secs")
            .and_then(|v| v.as_u64())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_HTTP_TIMEOUT);

        // ureq 3.x: configure once, produce an `Agent`. We turn off
        // `http_status_as_error` so our code can route 404 cleanly to
        // `Ok(None)` in `read()` / no-op in `delete()` rather than
        // matching on an error variant.
        let agent: Agent = UreqConfig::builder()
            .timeout_global(Some(http_timeout))
            .http_status_as_error(false)
            .build()
            .into();

        Ok(Self {
            bucket,
            credentials,
            prefix,
            http_timeout,
            agent,
        })
    }

    /// Compose the full S3 object key for a vault key, applying the
    /// configured prefix.
    fn object_key(&self, raw: &str) -> String {
        format!("{}{}", self.prefix, raw)
    }
}

/// Pull AWS credentials out of the config. Supports two paths:
///   1. `credentials_ref` resolves to a JSON object
///      `{access_key_id, secret_access_key, session_token?}`
///   2. When `credentials_ref` is absent, fall back to
///      `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
///      `AWS_SESSION_TOKEN` env vars (rusty-s3's built-in loader).
fn resolve_credentials(conf: &HashMap<String, Value>) -> Result<Credentials, RvError> {
    if let Some(reference) = conf.get("credentials_ref").and_then(|v| v.as_str()) {
        let secret = super::creds::resolve(reference)?;
        let text = secret.as_str()?;
        #[derive(serde::Deserialize)]
        struct StaticCreds {
            access_key_id: String,
            secret_access_key: String,
            #[serde(default)]
            session_token: Option<String>,
        }
        let parsed: StaticCreds = serde_json::from_str(text.trim()).map_err(|e| {
            RvError::ErrString(format!(
                "s3 target: credentials_ref must resolve to JSON \
                 `{{access_key_id, secret_access_key, session_token?}}`: {e}"
            ))
        })?;
        Ok(match parsed.session_token {
            Some(t) => Credentials::new_with_token(parsed.access_key_id, parsed.secret_access_key, t),
            None => Credentials::new(parsed.access_key_id, parsed.secret_access_key),
        })
    } else {
        Credentials::from_env().ok_or_else(|| {
            RvError::ErrString(
                "s3 target: no `credentials_ref` and `AWS_ACCESS_KEY_ID` / \
                 `AWS_SECRET_ACCESS_KEY` are not set"
                    .into(),
            )
        })
    }
}

fn normalize_prefix(p: &str) -> String {
    if p.is_empty() || p.ends_with('/') {
        p.to_string()
    } else {
        format!("{p}/")
    }
}

#[maybe_async::maybe_async]
impl FileTarget for S3Target {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        let object_key = self.object_key(key);
        let action = GetObject::new(&self.bucket, Some(&self.credentials), &object_key);
        let url = action.sign(SIGN_EXPIRY);
        let agent = self.agent.clone();
        let url_str = url.to_string();
        let key_owned = key.to_string();
        blocking(move || {
            let resp = agent
                .get(&url_str)
                .call()
                .map_err(|e| RvError::ErrString(format!("s3 target: GET {key_owned}: {e}")))?;
            let status = resp.status().as_u16();
            if status == 404 {
                return Ok(None);
            }
            if !(200..300).contains(&status) {
                return Err(RvError::ErrString(format!(
                    "s3 target: GET {key_owned}: http status {status}"
                )));
            }
            let body = resp
                .into_body()
                .read_to_vec()
                .map_err(|e| RvError::ErrString(format!("s3 target: read body: {e}")))?;
            Ok(Some(body))
        })
        .await
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        let object_key = self.object_key(key);
        let action = PutObject::new(&self.bucket, Some(&self.credentials), &object_key);
        let url = action.sign(SIGN_EXPIRY);
        let agent = self.agent.clone();
        let url_str = url.to_string();
        let body = value.to_vec();
        let key_owned = key.to_string();
        blocking(move || {
            // The presigned URL uses UNSIGNED-PAYLOAD by default, which
            // both AWS S3 and MinIO accept on presigned PUTs. ureq's
            // `.send(&[u8])` sets Content-Length automatically.
            let resp = agent
                .put(&url_str)
                .send(&body[..])
                .map_err(|e| RvError::ErrString(format!("s3 target: PUT {key_owned}: {e}")))?;
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                return Err(RvError::ErrString(format!(
                    "s3 target: PUT {key_owned}: http status {status}"
                )));
            }
            Ok(())
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        let object_key = self.object_key(key);
        let action = DeleteObject::new(&self.bucket, Some(&self.credentials), &object_key);
        let url = action.sign(SIGN_EXPIRY);
        let agent = self.agent.clone();
        let url_str = url.to_string();
        let key_owned = key.to_string();
        blocking(move || {
            // S3 returns 204 whether the object existed or not; some
            // S3-compatible servers return 404 for missing keys. Both
            // match the `FileTarget::delete` "ok either way" contract.
            let resp = agent
                .delete(&url_str)
                .call()
                .map_err(|e| RvError::ErrString(format!("s3 target: DELETE {key_owned}: {e}")))?;
            let status = resp.status().as_u16();
            if status == 404 || (200..300).contains(&status) {
                Ok(())
            } else {
                Err(RvError::ErrString(format!(
                    "s3 target: DELETE {key_owned}: http status {status}"
                )))
            }
        })
        .await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }
        // S3 object-level prefix = configured target prefix + the
        // caller's vault prefix. Trailing `/` is preserved in the
        // returned directory entries after we strip the request prefix.
        let object_prefix = self.object_key(prefix);
        let full_prefix = object_prefix.clone();

        // Walk pagination to completion — presigned `sign` needs the
        // ContinuationToken added to the action before signing, so
        // each page is a fresh signed URL.
        let mut results: Vec<String> = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
            action.with_prefix(full_prefix.clone());
            action.with_delimiter("/");
            if let Some(ct) = continuation.as_deref() {
                action.with_continuation_token(ct.to_string());
            }
            let url = action.sign(SIGN_EXPIRY);
            let agent = self.agent.clone();
            let url_str = url.to_string();
            let body = blocking(move || {
                let resp = agent
                    .get(&url_str)
                    .call()
                    .map_err(|e| RvError::ErrString(format!("s3 target: LIST: {e}")))?;
                let status = resp.status().as_u16();
                if !(200..300).contains(&status) {
                    return Err(RvError::ErrString(format!(
                        "s3 target: LIST: http status {status}"
                    )));
                }
                let buf = resp
                    .into_body()
                    .read_to_vec()
                    .map_err(|e| RvError::ErrString(format!("s3 target: LIST body: {e}")))?;
                Ok::<Vec<u8>, RvError>(buf)
            })
            .await?;

            let parsed = ListObjectsV2::parse_response(&body)
                .map_err(|e| RvError::ErrString(format!("s3 target: LIST parse: {e}")))?;

            // Strip the object-prefix before returning so callers see
            // keys relative to what they asked for — matches the local
            // target's contract. Directory entries keep their trailing `/`.
            for item in &parsed.contents {
                let key = urldecode(&item.key);
                if let Some(tail) = key.strip_prefix(&full_prefix) {
                    results.push(tail.to_string());
                }
            }
            for cp in &parsed.common_prefixes {
                let p = urldecode(&cp.prefix);
                if let Some(tail) = p.strip_prefix(&full_prefix) {
                    results.push(tail.to_string());
                }
            }

            match parsed.next_continuation_token {
                Some(t) if !t.is_empty() => continuation = Some(t),
                _ => break,
            }
        }
        Ok(results)
    }

    async fn lock(&self, _lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        // Documented single-writer-per-target assumption applies.
        // If multi-writer ever becomes in-scope we'll need a real
        // arbiter (e.g., a best-effort `.lock` object with an ETag
        // precondition or a DynamoDB table).
        Ok(Box::new(()))
    }
}

/// Decode a URL-encoded S3 key. `list_objects_v2` is always invoked
/// with `encoding-type=url` (rusty-s3 sets this by default) so
/// returned `Key` and `Prefix` values are percent-encoded. Convert
/// back to the raw bytes the caller would have passed to `put`.
fn urldecode(s: &str) -> String {
    percent_decode(s)
}

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
    String::from_utf8(out).unwrap_or_else(|e| {
        // Non-UTF8 keys are not a thing in BastionVault (keys are
        // UTF-8 by the Backend trait). Fall back to lossy rather
        // than panicking — the list row just becomes unusable for
        // subsequent read / delete, which is the sharpest failure
        // signal anyway.
        String::from_utf8_lossy(e.as_bytes()).into_owned()
    })
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Hop a synchronous `ureq` call over to `spawn_blocking` so we
/// never park the tokio runtime. Errors flatten through the returned
/// `Result`; panics inside the closure become an `RvError`.
async fn blocking<F, T>(f: F) -> Result<T, RvError>
where
    F: FnOnce() -> Result<T, RvError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(join_err) => Err(RvError::ErrString(format!(
            "s3 target: worker panic/cancel: {join_err}"
        ))),
    }
}

/// Suppress `unused` warnings on methods Arc-only access the bucket via
/// the handler closures. Referenced so Clippy / rustc see them used.
#[allow(dead_code)]
fn _assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<S3Target>();
    is_send_sync::<Arc<dyn FileTarget>>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(v: Value) -> HashMap<String, Value> {
        v.as_object().unwrap().clone().into_iter().collect()
    }

    #[test]
    fn from_config_requires_bucket() {
        let err = S3Target::from_config(&cfg(json!({"region":"us-east-1"}))).unwrap_err();
        assert!(format!("{err}").contains("`bucket` is required"));
    }

    #[test]
    fn from_config_requires_region() {
        let err = S3Target::from_config(&cfg(json!({"bucket":"b"}))).unwrap_err();
        assert!(format!("{err}").contains("`region` is required"));
    }

    #[test]
    fn from_config_rejects_unknown_url_style() {
        let creds = r#"{"access_key_id":"a","secret_access_key":"b"}"#;
        let ref_inline = format!("inline:{}", base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            creds.as_bytes(),
        ));
        let err = S3Target::from_config(&cfg(json!({
            "bucket":"b",
            "region":"us-east-1",
            "url_style":"bogus",
            "credentials_ref": ref_inline,
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("unknown `url_style"));
    }

    #[test]
    fn from_config_accepts_inline_credentials_ref() {
        let creds = r#"{"access_key_id":"AKIA","secret_access_key":"sekret"}"#;
        let ref_inline = format!(
            "inline:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, creds.as_bytes()),
        );
        let target = S3Target::from_config(&cfg(json!({
            "bucket":"b",
            "region":"us-east-1",
            "endpoint_url":"http://minio.local:9000",
            "url_style":"path",
            "prefix":"bvault",
            "credentials_ref": ref_inline,
        })))
        .expect("ok");
        assert_eq!(target.prefix, "bvault/");
        assert_eq!(target.credentials.key(), "AKIA");
        assert_eq!(target.credentials.secret(), "sekret");
    }

    #[test]
    fn from_config_rejects_bad_credentials_json() {
        let bad = "inline:bm90LWpzb24="; // base64("not-json")
        let err = S3Target::from_config(&cfg(json!({
            "bucket":"b","region":"us-east-1","credentials_ref": bad,
        })))
        .unwrap_err();
        assert!(format!("{err}").contains("JSON"));
    }

    #[test]
    fn normalize_prefix_appends_slash() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("bvault"), "bvault/");
        assert_eq!(normalize_prefix("bvault/"), "bvault/");
        assert_eq!(normalize_prefix("a/b"), "a/b/");
    }

    #[test]
    fn object_key_prepends_prefix() {
        let creds = r#"{"access_key_id":"a","secret_access_key":"b"}"#;
        let ref_inline = format!(
            "inline:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, creds.as_bytes()),
        );
        let t = S3Target::from_config(&cfg(json!({
            "bucket":"b","region":"us-east-1","prefix":"p","credentials_ref": ref_inline,
        })))
        .unwrap();
        assert_eq!(t.object_key("sys/foo"), "p/sys/foo");
    }

    #[test]
    fn percent_decode_handles_common_cases() {
        assert_eq!(percent_decode("foo%2Fbar"), "foo/bar");
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("a%20b"), "a b");
        // Truncated escape falls through as literal characters.
        assert_eq!(percent_decode("oops%2"), "oops%2");
    }

    /// Live MinIO integration test — ignored unless explicitly run
    /// with the relevant env vars set. Designed to mirror the
    /// backend-level test suite against a real endpoint.
    ///
    /// Enable with:
    ///   BVAULT_TEST_S3_ENDPOINT=http://localhost:9000 \
    ///   BVAULT_TEST_S3_BUCKET=bvault-test \
    ///   BVAULT_TEST_S3_REGION=us-east-1 \
    ///   AWS_ACCESS_KEY_ID=minioadmin \
    ///   AWS_SECRET_ACCESS_KEY=minioadmin \
    ///   cargo test --features cloud_s3 -- --ignored s3_target_live_roundtrip
    #[tokio::test]
    #[ignore]
    async fn s3_target_live_roundtrip() {
        let endpoint =
            std::env::var("BVAULT_TEST_S3_ENDPOINT").expect("BVAULT_TEST_S3_ENDPOINT");
        let bucket = std::env::var("BVAULT_TEST_S3_BUCKET").expect("BVAULT_TEST_S3_BUCKET");
        let region =
            std::env::var("BVAULT_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let target = S3Target::from_config(&cfg(json!({
            "bucket": bucket,
            "region": region,
            "endpoint_url": endpoint,
            "url_style": "path",
            "prefix": format!("bvault-test-{}/", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        })))
        .expect("target construct");

        let payload = b"the quick brown fox".to_vec();

        // put → get round-trip
        target.write("dir/leaf.json", &payload).await.unwrap();
        let got = target.read("dir/leaf.json").await.unwrap();
        assert_eq!(got.as_deref(), Some(payload.as_slice()));

        // list sees the leaf
        let listed = target.list("dir/").await.unwrap();
        assert!(listed.iter().any(|s| s == "leaf.json"), "got: {listed:?}");

        // delete then read is None
        target.delete("dir/leaf.json").await.unwrap();
        assert!(target.read("dir/leaf.json").await.unwrap().is_none());
    }
}
