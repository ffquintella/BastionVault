//! End-to-end test: spawn the real `bv-downloads-server` binary against the
//! checked-in fixture root and exercise every documented endpoint over a real
//! socket.
//!
//! This lives in the crate's own `tests/` rather than the repository's, which
//! is where features/packaging-distribution-website.md § Phase 1 puts it. The
//! repository's `tests/` links the full workspace graph (a 245 MB rlib, ~30
//! binaries — see AGENTS.md § 4 L4); this crate depends on none of it, and
//! paying that link cost to drive an HTTP server that also depends on none of
//! it would be a minute of build time for nothing. AGENTS.md § "Test
//! locations" already has a row for exactly this shape: "Standalone crate
//! tests | crates/bv-client/tests".
//!
//! The HTTP client is hand-rolled over `TcpStream` rather than pulled in as a
//! dev-dependency: the requests are three lines of HTTP/1.1 with
//! `Connection: close`, and adding `reqwest` (and a TLS stack) to a crate
//! whose entire point is a minimal trusted computing base is a poor trade.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;

/// The fixture root, in the layout the container expects.
fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/v0.4.0")
}

/// A running server, killed when the test drops it.
struct Server {
    child: Child,
    addr: String,
    /// Drains the child's piped stdout for as long as the server lives. The
    /// server prints more than the one startup line — `--verify-hashes` adds a
    /// second, and shutdown adds a third — and dropping the read end of the
    /// pipe after the startup line would make the child's next `println!` fail
    /// with EPIPE, panic, and reset any in-flight connection. Draining on a
    /// thread also means a chatty server can never block on a full pipe.
    stdout: Option<JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The child is gone, so the drain thread has hit EOF; join it so the
        // pipe is closed before the test process exits.
        if let Some(drain) = self.stdout.take() {
            let _ = drain.join();
        }
    }
}

impl Server {
    /// Start on an ephemeral port and read the bound address back off stdout.
    /// Binding port 0 keeps the test safe to run concurrently with anything
    /// else — nothing here is port-bound in the sense AGENTS.md § 4 warns about.
    fn start(extra: &[&str]) -> Server {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bv-downloads-server"))
            .arg("--root")
            .arg(fixture_root())
            .arg("--addr")
            .arg("127.0.0.1:0")
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn bv-downloads-server");

        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("startup line");

        // Keep reading for as long as the server runs, on a thread: the read
        // end of this pipe must outlive the child's later `println!`s.
        let drain = std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = reader.read_to_end(&mut sink);
        });

        let addr = line
            .split("http://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_else(|| panic!("no bound address in startup line: {line:?}"))
            .to_string();

        Server {
            child,
            addr,
            stdout: Some(drain),
        }
    }

    fn get(&self, path: &str) -> HttpResponse {
        self.request("GET", path)
    }

    fn request(&self, method: &str, path: &str) -> HttpResponse {
        let mut stream = TcpStream::connect(&self.addr).expect("connect");
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.addr
        )
        .expect("write request");
        stream.flush().expect("flush");

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("read response");
        HttpResponse::parse(&raw)
    }
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn parse(raw: &[u8]) -> HttpResponse {
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("headers terminator");
        let head = std::str::from_utf8(&raw[..split]).expect("ascii headers");
        let body = raw[split + 4..].to_vec();

        let mut lines = head.split("\r\n");
        let status_line = lines.next().expect("status line");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status code in {status_line:?}"));

        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();

        HttpResponse {
            status,
            headers,
            body,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).expect("utf-8 body")
    }
}

/// The fixture manifest, parsed just enough to assert against.
struct Entry {
    name: String,
    sha256: String,
    signature: String,
    certificate: String,
    mime: &'static str,
}

fn fixture_entries() -> Vec<Entry> {
    let raw = std::fs::read_to_string(fixture_root().join("manifest.json")).expect("manifest");
    // Deliberately not using serde here: the point of this test is to compare
    // what the server rendered against the operator's file, so it reads the
    // file the same way an operator would eyeball it.
    let mut out = Vec::new();
    for chunk in raw.split("\"name\": \"").skip(1) {
        let name = chunk.split('"').next().expect("name").to_string();
        let sha256 = chunk
            .split("\"sha256\": \"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("sha256")
            .to_string();
        let signature = chunk
            .split("\"cosign_signature\": \"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("cosign_signature")
            .to_string();
        let certificate = chunk
            .split("\"cosign_certificate\": \"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("cosign_certificate")
            .to_string();
        let mime = match Path::new(&name).extension().and_then(|e| e.to_str()) {
            Some("deb") => "application/vnd.debian.binary-package",
            Some("rpm") => "application/x-rpm",
            Some("pkg") => "application/x-newton-compatible-pkg",
            Some("msi") => "application/x-msi",
            other => panic!("unexpected fixture extension {other:?}"),
        };
        out.push(Entry {
            name,
            sha256,
            signature,
            certificate,
            mime,
        });
    }
    assert_eq!(out.len(), 8, "fixture should cover all eight artefact kinds");
    out
}

#[test]
fn healthz_is_plain_ok() {
    let server = Server::start(&[]);
    let response = server.get("/healthz");
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "ok");
}

#[test]
fn index_lists_every_fixture_file_with_its_hash_and_signature_link() {
    let server = Server::start(&["--verify-hashes"]);
    let response = server.get("/");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));

    let csp = response.header("content-security-policy").expect("csp");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(!csp.contains("unsafe-inline"), "{csp}");

    let html = response.text();
    for entry in fixture_entries() {
        assert!(
            html.contains(&format!("href=\"/v0.4.0/{}\"", entry.name)),
            "no download link for {}",
            entry.name
        );
        assert!(
            html.contains(&entry.sha256),
            "no sha256 for {} on the page",
            entry.name
        );
        assert!(
            html.contains(&format!("href=\"/{}\"", entry.signature)),
            "no signature link for {}",
            entry.name
        );
        assert!(
            html.contains(&format!("href=\"/{}\"", entry.certificate)),
            "no certificate link for {}",
            entry.name
        );
    }
}

#[test]
fn manifest_endpoint_returns_the_operators_bytes() {
    let server = Server::start(&[]);
    let response = server.get("/manifest.json");
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    let on_disk = std::fs::read(fixture_root().join("manifest.json")).expect("read");
    assert_eq!(response.body, on_disk);
}

#[test]
fn every_artefact_signature_and_certificate_is_downloadable() {
    let server = Server::start(&[]);
    for entry in fixture_entries() {
        let artefact = server.get(&format!("/v0.4.0/{}", entry.name));
        assert_eq!(artefact.status, 200, "{}", entry.name);
        assert_eq!(artefact.header("content-type"), Some(entry.mime), "{}", entry.name);
        let on_disk =
            std::fs::read(fixture_root().join("v0.4.0").join(&entry.name)).expect("read artefact");
        assert_eq!(artefact.body, on_disk, "{}", entry.name);
        assert_eq!(
            artefact.header("content-length").map(str::to_string),
            Some(on_disk.len().to_string()),
            "{}",
            entry.name
        );

        for (path, mime) in [
            (&entry.signature, "application/octet-stream"),
            (&entry.certificate, "application/x-pem-file"),
        ] {
            let response = server.get(&format!("/{path}"));
            assert_eq!(response.status, 200, "{path}");
            assert_eq!(response.header("content-type"), Some(mime), "{path}");
        }
    }
}

#[test]
fn undocumented_paths_and_traversals_are_404() {
    let server = Server::start(&[]);
    for path in [
        "/index.html",
        "/static/style.css",
        "/v0.4.0/",
        "/v0.4.0",
        "/v0.4.0/does-not-exist.deb",
        "/../etc/passwd",
        "/v0.4.0/../../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/manifest.json/../../etc/passwd",
    ] {
        let response = server.get(path);
        assert_eq!(response.status, 404, "{path} must not be served");
        assert!(
            !response.text().contains("root:"),
            "{path} leaked file contents"
        );
    }
}

#[test]
fn there_is_no_write_path() {
    let server = Server::start(&[]);
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let response = server.request(method, "/v0.4.0/bvault_0.4.0_amd64.deb");
        assert_eq!(response.status, 404, "{method} reached a handler");
    }
}

#[test]
fn a_manifest_naming_a_missing_file_refuses_to_start() {
    let dir = std::env::temp_dir().join(format!("bv-downloads-broken-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("v9.9.9")).expect("mkdir");
    std::fs::write(
        dir.join("manifest.json"),
        r#"{"version":"9.9.9","released":"2026-06-01","files":[
            {"platform":"linux","arch":"amd64","kind":"cli-deb","name":"gone.deb","size":1,
             "sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#,
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bv-downloads-server"))
        .arg("--root")
        .arg(&dir)
        .arg("--addr")
        .arg("127.0.0.1:0")
        .output()
        .expect("run");

    let _ = std::fs::remove_dir_all(&dir);

    assert!(!output.status.success(), "should have refused to start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("gone.deb"), "{stderr}");
    assert!(stderr.contains("missing from disk"), "{stderr}");
    assert_eq!(stderr.trim().lines().count(), 1, "{stderr}");
}

#[test]
fn half_configured_tls_refuses_to_start() {
    let output = Command::new(env!("CARGO_BIN_EXE_bv-downloads-server"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--addr")
        .arg("127.0.0.1:0")
        .env("BV_DOWNLOADS_TLS_CERT", "/etc/tls/cert.pem")
        .output()
        .expect("run");

    assert!(!output.status.success(), "should have refused to start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BV_DOWNLOADS_TLS"), "{stderr}");
    assert!(stderr.contains("not implemented"), "{stderr}");
}
