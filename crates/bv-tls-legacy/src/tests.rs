//! Loopback handshakes, HTTP exchanges and fail-closed checks against the
//! test server half, the OpenSSL interop check, and the manual live check.

use std::{net::SocketAddr, time::Duration};

use http::{header, Method, Request, Response};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::{
    error::{alert, TlsError},
    http::{exchange, send, HttpError, HttpLimits},
    suite::{CipherSuite, OFFERED},
    test_server::{pki, serve, ServerOptions, ServerOutcome, Tamper, TestPki},
    ClientConfig, ConnectionInfo, ServerName, TrustAnchors,
};

async fn spawn_server(pki: TestPki, opts: ServerOptions) -> (SocketAddr, JoinHandle<ServerOutcome>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        serve(tcp, &pki, &opts).await
    });
    (addr, task)
}

fn anchors(pki: &TestPki) -> TrustAnchors {
    let mut trust = TrustAnchors::empty();
    trust.add_der(&pki.ca_der).expect("test CA");
    trust
}

async fn client_get(
    addr: SocketAddr,
    name: &str,
    trust: &TrustAnchors,
    config: &ClientConfig,
) -> Result<(ConnectionInfo, Response<Vec<u8>>), HttpError> {
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let server_name = ServerName::try_from(name.to_string()).expect("name");
    let mut tls = crate::connect(tcp, server_name, trust, config).await.map_err(HttpError::Tls)?;
    let request = Request::get(format!("https://{name}/.well-known/openid-configuration"))
        .header(header::ACCEPT, "application/json")
        .body(Vec::new())
        .unwrap();
    let response = exchange(&mut tls, &request, name, &HttpLimits::default()).await?;
    Ok((tls.connection_info(), response))
}

/// Run one exchange against a server with `opts`, trusting the test CA.
async fn run(opts: ServerOptions) -> (Result<(ConnectionInfo, Response<Vec<u8>>), HttpError>, ServerOutcome) {
    let pki = pki(&["idp.test"]);
    let trust = anchors(&pki);
    let (addr, server) = spawn_server(pki, opts).await;
    let result = client_get(addr, "idp.test", &trust, &ClientConfig::default()).await;
    (result, server.await.expect("server task"))
}

fn tls_error(r: Result<(ConnectionInfo, Response<Vec<u8>>), HttpError>) -> TlsError {
    match r {
        Err(HttpError::Tls(e)) => e,
        Err(other) => panic!("expected a TLS error, got {other:?}"),
        Ok((info, _)) => panic!("expected a TLS error, got a response over {info:?}"),
    }
}

#[tokio::test]
async fn every_suite_handshakes_and_carries_http() {
    for suite in OFFERED {
        let (result, outcome) = run(ServerOptions { suites: vec![suite], ..Default::default() }).await;
        let (info, response) = result.unwrap_or_else(|e| panic!("{suite:?}: {e}"));
        assert_eq!(info.suite, suite);
        assert!(info.extended_master_secret, "EMS echoed by the server is used");
        assert!(info.secure_renegotiation);
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"ok");
        assert_eq!(response.headers()["content-type"], "text/plain");
        assert_eq!(outcome.sni.as_deref(), Some("idp.test"), "SNI is always sent for a DNS name");
        let request = String::from_utf8(outcome.request).unwrap();
        assert!(
            request.starts_with(
                "GET /.well-known/openid-configuration HTTP/1.1\r\nHost: idp.test\r\nConnection: close\r\n"
            ),
            "{request}"
        );
    }
}

#[tokio::test]
async fn works_without_ems_or_renegotiation_info_and_with_pss() {
    let (result, _) = run(ServerOptions { echo_ems: false, renegotiation_info: None, ..Default::default() }).await;
    let (info, response) = result.unwrap();
    assert!(!info.extended_master_secret && !info.secure_renegotiation);
    assert_eq!(response.body(), b"ok");

    let (result, _) = run(ServerOptions { sig_scheme: 0x0804, ..Default::default() }).await;
    assert_eq!(result.unwrap().1.status(), 200);
}

#[tokio::test]
async fn large_chunked_body_spans_records() {
    let body: Vec<u8> = (0..40_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for chunk in body.chunks(7000) {
        response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        response.extend_from_slice(chunk);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\n\r\n");
    let (result, _) = run(ServerOptions { response, ..Default::default() }).await;
    assert_eq!(result.unwrap().1.body(), &body);
}

#[tokio::test]
async fn close_delimited_body_needs_close_notify() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"issuer\":\"x\"}".to_vec();
    let (result, _) = run(ServerOptions { response: response.clone(), ..Default::default() }).await;
    assert_eq!(result.unwrap().1.body(), b"{\"issuer\":\"x\"}");

    let (result, _) = run(ServerOptions { response, tamper: Tamper::NoCloseNotify, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::UnexpectedEof(_)), "a truncatable body is refused");
}

#[tokio::test]
async fn ip_literal_server_names_verify_against_ip_sans_without_sni() {
    let pki = pki(&["127.0.0.1"]);
    let trust = anchors(&pki);
    let (addr, server) = spawn_server(pki, ServerOptions::default()).await;
    let (_, response) = client_get(addr, "127.0.0.1", &trust, &ClientConfig::default()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(server.await.unwrap().sni, None, "RFC 6066: no SNI for an IP literal");
}

#[tokio::test]
async fn send_posts_over_a_fresh_connection() {
    let pki = pki(&["127.0.0.1"]);
    let trust = anchors(&pki);
    let (addr, server) = spawn_server(pki, ServerOptions::default()).await;
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("https://127.0.0.1:{}/token", addr.port()))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(b"grant_type=authorization_code".to_vec())
        .unwrap();
    let response = send(request, &trust, &HttpLimits::default()).await.unwrap();
    assert_eq!(response.status(), 200);
    let seen = String::from_utf8(server.await.unwrap().request).unwrap();
    assert!(seen.starts_with(&format!("POST /token HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n", addr.port())), "{seen}");
    assert!(seen.ends_with("Content-Length: 29\r\n\r\ngrant_type=authorization_code"), "{seen}");
}

// ── fail closed ──────────────────────────────────────────────────────

#[tokio::test]
async fn untrusted_chain_is_refused() {
    let pki = pki(&["idp.test"]);
    let (addr, server) = spawn_server(pki, ServerOptions::default()).await;
    let e = tls_error(client_get(addr, "idp.test", &TrustAnchors::with_webpki_roots(), &ClientConfig::default()).await);
    assert!(matches!(&e, TlsError::CertificateRejected(r) if r.starts_with("UnknownIssuer")), "{e}");
    assert_eq!(server.await.unwrap().client_alert, Some(alert::UNKNOWN_CA));
}

#[tokio::test]
async fn wrong_hostname_is_refused() {
    let pki = pki(&["idp.test"]);
    let trust = anchors(&pki);
    let (addr, server) = spawn_server(pki, ServerOptions::default()).await;
    let e = tls_error(client_get(addr, "other.test", &trust, &ClientConfig::default()).await);
    assert!(matches!(&e, TlsError::CertificateRejected(r) if r.contains("NotValidForName")), "{e}");
    assert_eq!(server.await.unwrap().client_alert, Some(alert::BAD_CERTIFICATE));
}

#[tokio::test]
async fn bad_server_key_exchange_signature_is_refused() {
    let (result, outcome) = run(ServerOptions { tamper: Tamper::SkeSignature, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::BadServerKeyExchangeSignature));
    assert_eq!(outcome.client_alert, Some(alert::DECRYPT_ERROR));
}

#[tokio::test]
async fn tampered_server_finished_is_refused() {
    let (result, outcome) = run(ServerOptions { tamper: Tamper::Finished, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::FinishedMismatch));
    assert_eq!(outcome.client_alert, Some(alert::DECRYPT_ERROR), "sent under the new keys");
}

#[tokio::test]
async fn downgrade_to_tls11_is_refused() {
    let (result, outcome) = run(ServerOptions { version: 0x0302, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::UnsupportedVersion(0x0302)));
    assert_eq!(outcome.client_alert, Some(alert::PROTOCOL_VERSION));
}

#[tokio::test]
async fn suite_not_offered_is_refused() {
    let (result, outcome) = run(ServerOptions { force_suite: Some(0xC02F), ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::UnsupportedCipherSuite(0xC02F)));
    assert_eq!(outcome.client_alert, Some(alert::ILLEGAL_PARAMETER));
}

#[tokio::test]
async fn unsolicited_extension_and_bad_renegotiation_info_are_refused() {
    let (result, outcome) = run(ServerOptions { extra_extension: Some((35, Vec::new())), ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::PeerMisbehaved { alert: alert::UNSUPPORTED_EXTENSION, .. }));
    assert_eq!(outcome.client_alert, Some(alert::UNSUPPORTED_EXTENSION));

    let (result, outcome) = run(ServerOptions { renegotiation_info: Some(vec![1, 0]), ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::PeerMisbehaved { alert: alert::HANDSHAKE_FAILURE, .. }));
    assert_eq!(outcome.client_alert, Some(alert::HANDSHAKE_FAILURE));
}

#[tokio::test]
async fn certificate_request_is_refused() {
    let (result, outcome) = run(ServerOptions { tamper: Tamper::CertificateRequest, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::ClientCertificateRequested));
    assert_eq!(outcome.client_alert, Some(alert::HANDSHAKE_FAILURE));
}

#[tokio::test]
async fn server_closing_mid_handshake_fails() {
    let (result, _) = run(ServerOptions { tamper: Tamper::CloseAfterServerHello, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::UnexpectedEof(_)));
}

#[tokio::test]
async fn stalled_handshake_times_out() {
    let pki = pki(&["idp.test"]);
    let trust = anchors(&pki);
    let (addr, server) =
        spawn_server(pki, ServerOptions { tamper: Tamper::StallAfterServerHello, ..Default::default() }).await;
    let config = ClientConfig { handshake_timeout: Duration::from_millis(300) };
    let e = tls_error(client_get(addr, "idp.test", &trust, &config).await);
    assert!(matches!(e, TlsError::HandshakeTimeout));
    server.abort();
}

/// A bad MAC and a bad padding are indistinguishable: same error variant,
/// same message, same alert on the wire.
#[tokio::test]
async fn bad_mac_and_bad_padding_fail_identically() {
    let (mac_result, mac_outcome) = run(ServerOptions { tamper: Tamper::AppBadMac, ..Default::default() }).await;
    let (pad_result, pad_outcome) = run(ServerOptions { tamper: Tamper::AppBadPadding, ..Default::default() }).await;
    let (mac_e, pad_e) = (tls_error(mac_result), tls_error(pad_result));
    assert!(matches!(mac_e, TlsError::BadRecordMac) && matches!(pad_e, TlsError::BadRecordMac));
    assert_eq!(mac_e.to_string(), pad_e.to_string());
    assert_eq!(mac_outcome.client_alert, Some(alert::BAD_RECORD_MAC));
    assert_eq!(pad_outcome.client_alert, Some(alert::BAD_RECORD_MAC));
}

#[tokio::test]
async fn oversized_and_truncated_records_fail() {
    let (result, _) = run(ServerOptions { tamper: Tamper::AppOversizedRecord, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::RecordOverflow));
    let (result, _) = run(ServerOptions { tamper: Tamper::AppTruncatedRecord, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::UnexpectedEof(_)));
}

#[tokio::test]
async fn renegotiation_attempt_is_refused() {
    let (result, outcome) =
        run(ServerOptions { tamper: Tamper::HelloRequestAfterHandshake, ..Default::default() }).await;
    assert!(matches!(tls_error(result), TlsError::RenegotiationRefused));
    assert_eq!(outcome.client_alert, Some(alert::NO_RENEGOTIATION));
}

#[tokio::test]
async fn trust_anchors_take_pem_and_refuse_garbage() {
    let pki = pki(&["idp.test"]);
    let mut trust = TrustAnchors::with_webpki_roots();
    let before = trust.len();
    assert_eq!(trust.add_pem(&pki.ca_pem).unwrap(), 1);
    assert_eq!(trust.len(), before + 1);
    assert!(trust.add_pem("no pem here").is_err());
    assert!(trust.add_der(b"not der").is_err());
}

// ── interop with an independent implementation ──────────────────────

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Our client against `openssl s_server -tls1_2 -cipher <suite> -www` for
/// each suite. Skips (does not fail) when no `openssl` is on PATH (or in
/// `BV_TLS_LEGACY_OPENSSL`) or when it does not offer the suite, as macOS
/// LibreSSL may not. Any handshake or record failure with a server that
/// started is a failure.
#[tokio::test]
async fn interop_with_openssl_s_server() {
    let openssl = std::env::var("BV_TLS_LEGACY_OPENSSL").unwrap_or_else(|_| "openssl".to_string());
    let version = match std::process::Command::new(&openssl).arg("version").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => {
            eprintln!("skipping OpenSSL interop: `{openssl}` is not available");
            return;
        }
    };
    let pki = pki(&["127.0.0.1"]);
    let dir = std::env::temp_dir().join(format!("bv-tls-legacy-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, &pki.leaf_pem).unwrap();
    std::fs::write(&key, &pki.leaf_key_pem).unwrap();
    let trust = anchors(&pki);

    let cases = [
        ("ECDHE-RSA-AES256-SHA", CipherSuite::EcdheRsaAes256CbcSha),
        ("ECDHE-RSA-AES128-SHA", CipherSuite::EcdheRsaAes128CbcSha),
        ("ECDHE-RSA-AES128-SHA256", CipherSuite::EcdheRsaAes128CbcSha256),
        ("ECDHE-RSA-AES256-SHA384", CipherSuite::EcdheRsaAes256CbcSha384),
    ];
    let mut ran = 0;
    for (cipher, suite) in cases {
        let port = free_port();
        let mut child = tokio::process::Command::new(&openssl)
            .args(["s_server", "-accept", &port.to_string(), "-tls1_2", "-cipher", cipher, "-www", "-quiet"])
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn openssl");
        let mut tcp = None;
        for _ in 0..50 {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)).await {
                tcp = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let Some(tcp) = tcp else {
            eprintln!("skipping {cipher}: `{version}` s_server did not start with it");
            continue;
        };
        let name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let mut tls = crate::connect(tcp, name, &trust, &ClientConfig::default())
            .await
            .unwrap_or_else(|e| panic!("{cipher} against {version}: {e}"));
        assert_eq!(tls.connection_info().suite, suite, "{version}");
        tls.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        // `-www` closes after the page; whether it sends close_notify is
        // the server's business, the bytes before it have been verified.
        while let Ok(n) = tls.read(&mut buf).await {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.0 200 ok"), "{cipher} against {version}: {text:.200}");
        let _ = child.kill().await;
        ran += 1;
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("OpenSSL interop: {ran} of 4 suites exercised against `{version}`");
}

/// Manual proof against a real IdP. Run with
/// `BV_TLS_LEGACY_LIVE_URL=https://<idp>/<path>/.well-known/openid-configuration \
///  cargo nextest run -p bv-tls-legacy --lib live_fetch --run-ignored only --no-capture`.
/// `BV_TLS_LEGACY_LIVE_CA_PEM` may name a PEM file of extra anchors.
#[tokio::test]
#[ignore = "manual: needs network access to the URL in BV_TLS_LEGACY_LIVE_URL"]
async fn live_fetch_from_env_url() {
    let url = std::env::var("BV_TLS_LEGACY_LIVE_URL").expect("set BV_TLS_LEGACY_LIVE_URL");
    let mut trust = TrustAnchors::with_webpki_roots();
    if let Ok(path) = std::env::var("BV_TLS_LEGACY_LIVE_CA_PEM") {
        trust.add_pem(&std::fs::read_to_string(path).expect("CA PEM file")).expect("CA PEM");
    }
    let request = Request::get(url).header(header::ACCEPT, "application/json").body(Vec::new()).unwrap();
    let response = send(request, &trust, &HttpLimits::default()).await.unwrap_or_else(|e| panic!("{e}"));
    eprintln!(
        "status {}; content-type {:?}; {} bytes",
        response.status(),
        response.headers().get(header::CONTENT_TYPE),
        response.body().len()
    );
    assert!(response.status().is_success());
}
