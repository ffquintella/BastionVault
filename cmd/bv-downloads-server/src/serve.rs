//! The axum surface: five routes, no write path, no directory listing.
//!
//! Every servable URL is decided at **startup**, from the manifest, and stored
//! in [`AppState::assets`]. A request path is matched against that map
//! byte-for-byte; anything else is a 404 that never touches the filesystem.
//! That is a stronger guarantee than normalising `..` out of a path and
//! handing the remainder to a directory server, and it is the reason there is
//! no `ServeDir` here — see features/packaging-distribution-website.md
//! § Security Considerations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio_util::io::ReaderStream;

use crate::manifest::{mime, Asset, ValidatedManifest};
use crate::render::RenderedIndex;

/// Everything the request path is allowed to see. Immutable after startup.
pub struct AppState {
    index_html: String,
    /// CSP for the index page, pinning its inline `<style>`/`<script>` by hash.
    csp: HeaderValue,
    manifest_json: Vec<u8>,
    /// URL path (no leading slash) → the file it maps to.
    assets: HashMap<String, Asset>,
    /// Canonical served root. Re-checked on every open so a symlink swapped in
    /// after startup cannot escape it.
    root: PathBuf,
}

impl AppState {
    pub fn new(validated: ValidatedManifest, index: RenderedIndex) -> Self {
        let assets = validated
            .assets
            .into_iter()
            .map(|a| (a.url.clone(), a))
            .collect();
        Self {
            index_html: index.html,
            csp: HeaderValue::from_str(&index.csp).expect("CSP is ASCII by construction"),
            manifest_json: validated.raw,
            assets,
            root: validated.root,
        }
    }

    /// Number of servable files, for the startup log line.
    pub fn asset_count(&self) -> usize {
        self.assets.len()
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/manifest.json", get(manifest_json))
        // Not a wildcard route: the fallback sees the raw path and looks it up
        // in the allow-list. Nothing is routed by pattern, so there is no
        // pattern to trick.
        .fallback(file)
        .with_state(state)
}

/// `X-Content-Type-Options: nosniff` on everything. We pin the MIME of every
/// artefact from its manifest `kind`; sniffing would let a browser second-guess
/// that and, for instance, render an operator-supplied `.pem` as HTML.
fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn index(State(state): State<Arc<AppState>>) -> Response {
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, mime::HTML)],
        state.index_html.clone(),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, state.csp.clone());
    harden(response)
}

async fn healthz() -> Response {
    harden((StatusCode::OK, [(header::CONTENT_TYPE, mime::TEXT)], "ok").into_response())
}

/// The manifest, echoed byte-for-byte. A consumer verifying a detached
/// signature over it must see the operator's bytes, not our re-serialisation.
async fn manifest_json(State(state): State<Arc<AppState>>) -> Response {
    harden(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime::JSON)],
            state.manifest_json.clone(),
        )
            .into_response(),
    )
}

/// Artefacts, signatures and certificates — and nothing else.
///
/// The request path is **not** percent-decoded. Manifest validation restricts
/// every name to `[A-Za-z0-9._+-]`, characters no client encodes, so an exact
/// byte match against the allow-list is sound and `%2e%2e%2f` simply misses.
async fn file(State(state): State<Arc<AppState>>, method: Method, uri: Uri) -> Response {
    // The fallback answers every method, so the read-only guarantee is
    // enforced here rather than by the router: there is no verb that reaches
    // anything but this function, and this function only opens files.
    if method != Method::GET && method != Method::HEAD {
        return not_found();
    }
    let Some(key) = uri.path().strip_prefix('/') else {
        return not_found();
    };
    let Some(asset) = state.assets.get(key) else {
        return not_found();
    };

    // Startup validated this path; re-check at open time so a volume that
    // changed underneath us (a symlink swapped in for a regular file) fails
    // closed instead of being followed.
    match tokio::fs::symlink_metadata(&asset.path).await {
        Ok(meta) if meta.is_file() && asset.path.starts_with(&state.root) => {}
        _ => return not_found(),
    }

    let Ok(handle) = tokio::fs::File::open(&asset.path).await else {
        return not_found();
    };

    let body = Body::from_stream(ReaderStream::new(handle));
    harden(
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, asset.mime.to_string()),
                (header::CONTENT_LENGTH, asset.len.to_string()),
            ],
            body,
        )
            .into_response(),
    )
}

/// One 404 for everything: an unknown path, a path that traverses, and a file
/// that disappeared all look identical from outside. There is no directory
/// listing and no "did you mean".
fn not_found() -> Response {
    harden(
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, mime::TEXT)],
            "not found\n",
        )
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::load_and_validate;
    use crate::render::render;
    use axum::body::to_bytes;
    use axum::http::Request;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::Path;
    use tower::ServiceExt as _;

    /// A root with one deb, its signature and its certificate.
    fn fixture_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("v0.4.0")).expect("mkdir");
        fs::write(dir.path().join("v0.4.0/bvault_0.4.0_amd64.deb"), b"deb bytes").expect("write");
        fs::write(dir.path().join("v0.4.0/bvault_0.4.0_amd64.deb.sig"), b"sig").expect("write");
        fs::write(dir.path().join("v0.4.0/bvault_0.4.0_amd64.deb.pem"), b"pem").expect("write");
        fs::write(dir.path().join("v0.4.0/BastionVault-0.4.0-x64.msi"), b"msi bytes").expect("write");
        fs::write(dir.path().join("v0.4.0/BastionVault-0.4.0-x64.msi.sig"), b"sig").expect("write");
        fs::write(
            dir.path().join("manifest.json"),
            format!(
                r#"{{"version":"0.4.0","released":"2026-06-01","files":[
                  {{"platform":"linux","arch":"amd64","kind":"cli-deb",
                    "name":"bvault_0.4.0_amd64.deb","size":9,"sha256":"{}",
                    "cosign_signature":"v0.4.0/bvault_0.4.0_amd64.deb.sig",
                    "cosign_certificate":"v0.4.0/bvault_0.4.0_amd64.deb.pem"}},
                  {{"platform":"windows","arch":"amd64","kind":"gui-msi",
                    "name":"BastionVault-0.4.0-x64.msi","size":9,"sha256":"{}",
                    "cosign_signature":"v0.4.0/BastionVault-0.4.0-x64.msi.sig"}}]}}"#,
                crate::manifest::hex_lower(&Sha256::digest(b"deb bytes")),
                crate::manifest::hex_lower(&Sha256::digest(b"msi bytes")),
            ),
        )
        .expect("write manifest");
        dir
    }

    fn app(root: &Path) -> (Router, Arc<AppState>) {
        let validated = load_and_validate(root, true).expect("valid fixture");
        let index = render(&validated, None).expect("render");
        let state = Arc::new(AppState::new(validated, index));
        (router(state.clone()), state)
    }

    async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
        let response = app.clone().oneshot(request).await.expect("infallible");
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body")
            .to_vec();
        (status, headers, body)
    }

    async fn get_path(app: &Router, path: &str) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("request");
        send(app, request).await
    }

    fn header_of(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let dir = fixture_root();
        let (app, _) = app(dir.path());
        let (status, headers, body) = get_path(&app, "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"ok");
        assert_eq!(
            header_of(&headers, "x-content-type-options").as_deref(),
            Some("nosniff")
        );
    }

    #[tokio::test]
    async fn index_is_html_with_a_hash_pinned_csp() {
        let dir = fixture_root();
        let (app, _) = app(dir.path());
        let (status, headers, body) = get_path(&app, "/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_of(&headers, "content-type").as_deref(),
            Some(mime::HTML)
        );
        let csp = header_of(&headers, "content-security-policy").expect("csp");
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        let html = String::from_utf8(body).expect("utf-8");
        assert!(html.contains("bvault_0.4.0_amd64.deb"));
        assert!(html.contains("BastionVault-0.4.0-x64.msi"));
    }

    #[tokio::test]
    async fn manifest_is_served_byte_for_byte() {
        let dir = fixture_root();
        let on_disk = fs::read(dir.path().join("manifest.json")).expect("read");
        let (app, _) = app(dir.path());
        let (status, headers, body) = get_path(&app, "/manifest.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_of(&headers, "content-type").as_deref(),
            Some(mime::JSON)
        );
        assert_eq!(body, on_disk);
    }

    #[tokio::test]
    async fn artefacts_are_served_with_the_mime_their_kind_pins() {
        let dir = fixture_root();
        let (app, _) = app(dir.path());

        for (path, expected_mime, expected_body) in [
            ("/v0.4.0/bvault_0.4.0_amd64.deb", mime::DEB, "deb bytes"),
            ("/v0.4.0/BastionVault-0.4.0-x64.msi", mime::MSI, "msi bytes"),
            ("/v0.4.0/bvault_0.4.0_amd64.deb.sig", mime::SIG, "sig"),
            ("/v0.4.0/bvault_0.4.0_amd64.deb.pem", mime::PEM, "pem"),
        ] {
            let (status, headers, body) = get_path(&app, path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(
                header_of(&headers, "content-type").as_deref(),
                Some(expected_mime),
                "{path}"
            );
            assert_eq!(
                header_of(&headers, "content-length").as_deref(),
                Some(expected_body.len().to_string().as_str()),
                "{path}"
            );
            assert_eq!(body, expected_body.as_bytes(), "{path}");
        }
    }

    #[tokio::test]
    async fn everything_outside_the_manifest_is_a_404() {
        let dir = fixture_root();
        // Present on disk, absent from the manifest.
        fs::write(dir.path().join("v0.4.0/unlisted.deb"), b"nope").expect("write");
        fs::write(dir.path().join("secret.txt"), b"nope").expect("write");
        let (app, _) = app(dir.path());

        for path in [
            "/v0.4.0/unlisted.deb",
            "/secret.txt",
            "/v0.4.0/",
            "/v0.4.0",
            "/manifest.json.sig",
            "/static/style.css",
            "/index.html",
        ] {
            let (status, _, _) = get_path(&app, path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path} should not be served");
        }
    }

    #[tokio::test]
    async fn traversal_attempts_are_404_and_never_read_the_filesystem() {
        let dir = fixture_root();
        let (app, _) = app(dir.path());
        for path in [
            "/../etc/passwd",
            "/v0.4.0/../../etc/passwd",
            "/%2e%2e/etc/passwd",
            "/v0.4.0/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/./manifest.json",
            "//etc/passwd",
            "/v0.4.0/bvault_0.4.0_amd64.deb/../../../etc/passwd",
        ] {
            let (status, _, body) = get_path(&app, path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(body, b"not found\n", "{path}");
        }
    }

    #[tokio::test]
    async fn a_symlink_swapped_in_after_startup_stops_being_served() {
        let dir = fixture_root();
        let (app, _) = app(dir.path());

        // It serves before the swap.
        let (status, _, _) = get_path(&app, "/v0.4.0/bvault_0.4.0_amd64.deb").await;
        assert_eq!(status, StatusCode::OK);

        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().expect("tempdir");
            let secret = outside.path().join("secret");
            fs::write(&secret, b"not yours").expect("write");
            let target = dir.path().join("v0.4.0/bvault_0.4.0_amd64.deb");
            fs::remove_file(&target).expect("rm");
            std::os::unix::fs::symlink(&secret, &target).expect("symlink");

            let (status, _, body) = get_path(&app, "/v0.4.0/bvault_0.4.0_amd64.deb").await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_ne!(body, b"not yours");
        }
    }

    #[tokio::test]
    async fn there_is_no_write_path() {
        let dir = fixture_root();
        let (app, _) = app(dir.path());
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let request = Request::builder()
                .method(method)
                .uri("/v0.4.0/bvault_0.4.0_amd64.deb")
                .body(Body::empty())
                .expect("request");
            let (status, _, _) = send(&app, request).await;
            // The fallback answers every method, and it only ever reads.
            assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
        }
    }
}
