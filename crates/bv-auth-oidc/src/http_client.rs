//! The HTTP client the OIDC flow uses for discovery, JWKS and the token
//! exchange, and the extra trust anchors `oidc_discovery_ca_pem` gives it.
//!
//! The anchors are added to the built-in (webpki) roots, never in their
//! place; certificate and hostname verification stay on. The client is
//! built per call, so one mount's anchors reach no other HTTP client.

use std::time::Duration;

use openidconnect::reqwest;

use crate::errors::RvError;

/// Upper bound on the raw `oidc_discovery_ca_pem` text.
pub(crate) const MAX_DISCOVERY_CA_PEM_BYTES: usize = 64 * 1024;
/// Upper bound on the number of CERTIFICATE blocks in it.
pub(crate) const MAX_DISCOVERY_CA_CERTS: usize = 8;

const FIELD: &str = "oidc_discovery_ca_pem";
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

/// The client for discovery, JWKS and the token exchange: built-in roots
/// plus every certificate in `extra_ca_pem` (empty: none). A stored value
/// that no longer parses fails the call — no fallback to a client without
/// the operator's anchors.
pub(crate) fn reqwest_http_client(extra_ca_pem: &str) -> Result<reqwest::Client, RvError> {
    let mut builder = base_client_builder();
    if !extra_ca_pem.trim().is_empty() {
        let blocks = certificate_blocks(extra_ca_pem)
            .map_err(|e| RvError::ErrString(format!("{e}; rewrite `{FIELD}` at the mount's `config`")))?;
        for cert in decode_certificates(&blocks)? {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder.build().map_err(|e| RvError::ErrString(format!("oidc: http client: {}", error_chain(&e))))
}

/// Validate operator input for `oidc_discovery_ca_pem` and return what to
/// store: `""` for blank input, otherwise only the certificate blocks
/// (LF endings, input order; comments and `openssl` banners dropped).
/// Accepts 1..=8 CERTIFICATE blocks, each an X.509 certificate the TLS
/// stack takes as a trust anchor; any other PEM block is refused.
pub(crate) fn normalize_discovery_ca_pem(input: &str) -> Result<String, RvError> {
    check_size(input)?;
    if input.trim().is_empty() {
        return Ok(String::new());
    }
    let blocks = certificate_blocks(input)?;
    let certs = decode_certificates(&blocks)?;
    // Building a client parses each root with webpki's trust-anchor
    // parser: that is the X.509 check, one client per certificate so the
    // error names the offending block.
    for (index, cert) in certs.into_iter().enumerate() {
        base_client_builder().add_root_certificate(cert).build().map_err(|e| {
            RvError::ErrString(format!(
                "oidc: `{FIELD}` certificate #{} is not a valid X.509 certificate: {}",
                index + 1,
                error_chain(&e)
            ))
        })?;
    }
    Ok(blocks.concat())
}

/// Settings every OIDC HTTP client shares.
fn base_client_builder() -> reqwest::ClientBuilder {
    reqwest::ClientBuilder::new()
        // OIDC redirects on the IdP side are expected; disabling
        // redirects on our side follows the openidconnect crate's
        // explicit recommendation in the library docs to avoid
        // leaking bearer tokens through a misconfigured IdP.
        .redirect(reqwest::redirect::Policy::none())
        // A slow IdP must not hang the vault.
        .timeout(Duration::from_secs(30))
}

/// Split `input` into its CERTIFICATE blocks, each rebuilt as
/// `-----BEGIN CERTIFICATE-----\n<body>\n-----END CERTIFICATE-----\n`.
/// Enforces the size and count limits and refuses private keys, other
/// labels and unbalanced markers; base64 and DER are the caller's.
fn certificate_blocks(input: &str) -> Result<Vec<String>, RvError> {
    check_size(input)?;

    // A private key is refused first, wherever it sits, with a message
    // that says so and never quotes the input.
    let has_private_key = input
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with("-----BEGIN") && line.to_ascii_uppercase().contains("PRIVATE KEY"));
    if has_private_key {
        return Err(RvError::ErrString(format!(
            "oidc: `{FIELD}` contains a private key; supply only the CA certificate(s). Nothing was stored"
        )));
    }

    let malformed = |line_no: usize, what: &str| {
        RvError::ErrString(format!("oidc: `{FIELD}` is not well-formed PEM: line {line_no}: {what}"))
    };

    let mut blocks = Vec::new();
    // Body lines of the block being read, and the line its BEGIN was on.
    let mut open: Option<(usize, Vec<&str>)> = None;
    for (index, raw) in input.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        if line.starts_with("-----BEGIN") {
            let Some(label) = begin_label(line) else {
                return Err(malformed(line_no, "truncated BEGIN marker"));
            };
            if label != CERTIFICATE_LABEL {
                return Err(RvError::ErrString(format!(
                    "oidc: `{FIELD}` contains a `{}` PEM block (line {line_no}); only CERTIFICATE blocks are accepted",
                    printable_label(label)
                )));
            }
            if open.is_some() {
                return Err(malformed(line_no, "BEGIN CERTIFICATE inside another block"));
            }
            open = Some((line_no, Vec::new()));
        } else if line.starts_with("-----END") {
            let Some(label) = end_label(line) else {
                return Err(malformed(line_no, "truncated END marker"));
            };
            let Some((_, body)) = open.take() else {
                return Err(malformed(line_no, "END marker without a BEGIN"));
            };
            if label != CERTIFICATE_LABEL {
                return Err(malformed(line_no, "END marker does not match BEGIN CERTIFICATE"));
            }
            if blocks.len() == MAX_DISCOVERY_CA_CERTS {
                return Err(RvError::ErrString(format!(
                    "oidc: `{FIELD}` has more than {MAX_DISCOVERY_CA_CERTS} certificates; the limit is \
                     {MAX_DISCOVERY_CA_CERTS}"
                )));
            }
            let mut block = String::from("-----BEGIN CERTIFICATE-----\n");
            for body_line in body {
                block.push_str(body_line);
                block.push('\n');
            }
            block.push_str("-----END CERTIFICATE-----\n");
            blocks.push(block);
        } else if let Some((_, body)) = open.as_mut() {
            if !line.is_empty() {
                body.push(line);
            }
        }
        // Text outside a block (comments, `openssl` banners) is ignored.
    }
    if let Some((begin_line, _)) = open {
        return Err(malformed(begin_line, "BEGIN CERTIFICATE has no END marker"));
    }
    if blocks.is_empty() {
        return Err(RvError::ErrString(format!("oidc: `{FIELD}` contains no PEM CERTIFICATE block")));
    }
    Ok(blocks)
}

/// Base64-decode each block built by [`certificate_blocks`] (one
/// certificate per block).
fn decode_certificates(blocks: &[String]) -> Result<Vec<reqwest::Certificate>, RvError> {
    let mut certs = Vec::with_capacity(blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        let not_base64 = || {
            RvError::ErrString(format!("oidc: `{FIELD}` certificate #{} is not valid base64-encoded PEM", index + 1))
        };
        let mut decoded = reqwest::Certificate::from_pem_bundle(block.as_bytes()).map_err(|_| not_base64())?;
        match (decoded.pop(), decoded.is_empty()) {
            (Some(cert), true) => certs.push(cert),
            _ => return Err(not_base64()),
        }
    }
    Ok(certs)
}

fn check_size(input: &str) -> Result<(), RvError> {
    if input.len() > MAX_DISCOVERY_CA_PEM_BYTES {
        return Err(RvError::ErrString(format!(
            "oidc: `{FIELD}` is {} bytes; the limit is {MAX_DISCOVERY_CA_PEM_BYTES}",
            input.len()
        )));
    }
    Ok(())
}

/// The label of a complete `-----BEGIN <label>-----` line.
fn begin_label(line: &str) -> Option<&str> {
    line.strip_prefix("-----BEGIN ")?.strip_suffix("-----").filter(|l| !l.is_empty())
}

/// The label of a complete `-----END <label>-----` line.
fn end_label(line: &str) -> Option<&str> {
    line.strip_prefix("-----END ")?.strip_suffix("-----").filter(|l| !l.is_empty())
}

/// A PEM label made safe to echo: letters, digits and spaces, bounded.
fn printable_label(label: &str) -> String {
    label.chars().filter(|c| c.is_ascii_alphanumeric() || *c == ' ').take(40).collect()
}

/// `e` and its sources, so an error names the TLS-level cause. Only for
/// errors whose chain carries no secret (client build, discovery, JWKS).
pub(crate) fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(inner) = source {
        out.push_str(": ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

/// Certificate material for tests: a throwaway root, an intermediate it
/// issued, and a leaf the intermediate issued.
#[cfg(test)]
pub(crate) mod test_pki {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    pub(crate) struct Chain {
        pub root_pem: String,
        pub intermediate_pem: String,
        pub leaf_der: Vec<u8>,
        pub leaf_key_der: Vec<u8>,
        pub leaf_key_pem: String,
    }

    fn ca_params(common_name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
    }

    /// A root → intermediate → leaf chain; the leaf is for `leaf_names`
    /// (DNS names or IP literals).
    pub(crate) fn chain(leaf_names: &[&str]) -> Chain {
        let root_key = KeyPair::generate().expect("root key");
        let root_params = ca_params("BastionVault OIDC test root");
        let root = root_params.self_signed(&root_key).expect("root cert");

        let intermediate_key = KeyPair::generate().expect("intermediate key");
        let intermediate_params = ca_params("BastionVault OIDC test intermediate");
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &Issuer::from_params(&root_params, &root_key))
            .expect("intermediate cert");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = CertificateParams::new(leaf_names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .expect("leaf params")
            .signed_by(&leaf_key, &Issuer::from_params(&intermediate_params, &intermediate_key))
            .expect("leaf cert");

        Chain {
            root_pem: root.pem(),
            intermediate_pem: intermediate.pem(),
            leaf_der: leaf.der().to_vec(),
            leaf_key_der: leaf_key.serialize_der(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }

    /// One self-signed CA certificate, as PEM.
    pub(crate) fn ca_pem() -> String {
        let key = KeyPair::generate().expect("CA key");
        ca_params("BastionVault OIDC test CA").self_signed(&key).expect("CA cert").pem()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{
        rustls::{
            self,
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        },
        TlsAcceptor,
    };

    use super::{test_pki, *};

    fn err_text(r: Result<String, RvError>) -> String {
        match r {
            Ok(v) => panic!("expected an error, got Ok({v:?})"),
            Err(e) => e.to_string(),
        }
    }

    // ── validation and normalisation ────────────────────────────────

    #[test]
    fn blank_input_normalizes_to_empty() {
        assert_eq!(normalize_discovery_ca_pem("").unwrap(), "");
        assert_eq!(normalize_discovery_ca_pem("  \r\n\t\n").unwrap(), "");
    }

    #[test]
    fn valid_ca_pem_is_accepted_and_builds_a_client() {
        let pem = test_pki::ca_pem();
        let normalized = normalize_discovery_ca_pem(&pem).unwrap();
        assert_eq!(normalized.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert_eq!(normalized, pem.replace("\r\n", "\n"));
        reqwest_http_client(&normalized).expect("client with the extra CA");
    }

    #[test]
    fn empty_extra_ca_builds_a_client() {
        reqwest_http_client("").expect("client without an extra CA");
    }

    #[test]
    fn bundle_keeps_only_certificate_blocks() {
        let chain = test_pki::chain(&["idp.test"]);
        let input = format!(
            "# GeoTrust-style intermediate and its root\nsubject=CN = test\n{}\nissuer=CN = root\n{}",
            chain.intermediate_pem, chain.root_pem
        );
        let normalized = normalize_discovery_ca_pem(&input).unwrap();
        assert_eq!(normalized, format!("{}{}", chain.intermediate_pem, chain.root_pem).replace("\r\n", "\n"));
        assert!(!normalized.contains("subject="));
        assert!(!normalized.contains('#'));
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let lf = test_pki::ca_pem().replace("\r\n", "\n");
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(normalize_discovery_ca_pem(&crlf).unwrap(), lf);
    }

    #[test]
    fn text_without_a_certificate_is_rejected() {
        let e = err_text(normalize_discovery_ca_pem("not a certificate"));
        assert!(e.contains("no PEM CERTIFICATE block"), "{e}");
    }

    #[test]
    fn malformed_pem_is_rejected() {
        let pem = test_pki::ca_pem();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("\n");

        let unterminated = format!("-----BEGIN CERTIFICATE-----\n{body}\n");
        assert!(err_text(normalize_discovery_ca_pem(&unterminated)).contains("not well-formed PEM"));

        let end_only = format!("{body}\n-----END CERTIFICATE-----\n");
        assert!(err_text(normalize_discovery_ca_pem(&end_only)).contains("not well-formed PEM"));

        let nested = format!("-----BEGIN CERTIFICATE-----\n{pem}-----END CERTIFICATE-----\n");
        assert!(err_text(normalize_discovery_ca_pem(&nested)).contains("not well-formed PEM"));

        let truncated_marker = format!("-----BEGIN CERTIFICATE\n{body}\n-----END CERTIFICATE-----\n");
        assert!(err_text(normalize_discovery_ca_pem(&truncated_marker)).contains("not well-formed PEM"));

        let bad_base64 = "-----BEGIN CERTIFICATE-----\n!!!! not base64 !!!!\n-----END CERTIFICATE-----\n";
        let e = err_text(normalize_discovery_ca_pem(bad_base64));
        assert!(e.contains("certificate #1") && e.contains("base64"), "{e}");
    }

    #[test]
    fn base64_that_is_not_x509_is_rejected() {
        // "hello world, this is not DER" — decodes, but is no certificate.
        let not_der =
            "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQsIHRoaXMgaXMgbm90IERFUg==\n-----END CERTIFICATE-----\n";
        let e = err_text(normalize_discovery_ca_pem(not_der));
        assert!(e.contains("certificate #1") && e.contains("not a valid X.509 certificate"), "{e}");

        // The second of two blocks is the bad one, and the message says so.
        let input = format!("{}{not_der}", test_pki::ca_pem());
        let e = err_text(normalize_discovery_ca_pem(&input));
        assert!(e.contains("certificate #2"), "{e}");
    }

    #[test]
    fn a_private_key_alone_is_rejected_without_echoing_it() {
        let chain = test_pki::chain(&["idp.test"]);
        let e = err_text(normalize_discovery_ca_pem(&chain.leaf_key_pem));
        assert!(e.contains("private key"), "{e}");
        let key_body = chain.leaf_key_pem.lines().nth(1).expect("key body line");
        assert!(!e.contains(key_body), "error echoed key material: {e}");
    }

    #[test]
    fn a_certificate_with_a_private_key_is_rejected() {
        let chain = test_pki::chain(&["idp.test"]);
        let input = format!("{}{}", chain.intermediate_pem, chain.leaf_key_pem);
        assert!(err_text(normalize_discovery_ca_pem(&input)).contains("private key"));

        // Any flavour of private-key label, wherever it sits.
        let rsa = format!("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n{}", chain.root_pem);
        assert!(err_text(normalize_discovery_ca_pem(&rsa)).contains("private key"));
        let enc = format!(
            "{}-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
            chain.root_pem
        );
        assert!(err_text(normalize_discovery_ca_pem(&enc)).contains("private key"));
    }

    #[test]
    fn other_pem_blocks_are_rejected() {
        let input = format!("{}-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n", test_pki::ca_pem());
        let e = err_text(normalize_discovery_ca_pem(&input));
        assert!(e.contains("X509 CRL") && e.contains("only CERTIFICATE blocks"), "{e}");
    }

    #[test]
    fn oversized_input_is_rejected() {
        let pem = test_pki::ca_pem();
        let padding = "#".repeat(MAX_DISCOVERY_CA_PEM_BYTES + 1 - pem.len());
        let input = format!("{padding}\n{pem}");
        assert!(input.len() > MAX_DISCOVERY_CA_PEM_BYTES);
        let e = err_text(normalize_discovery_ca_pem(&input));
        assert!(e.contains("limit is 65536"), "{e}");

        // The limit holds even for input that would otherwise clear.
        let blank = " ".repeat(MAX_DISCOVERY_CA_PEM_BYTES + 1);
        assert!(err_text(normalize_discovery_ca_pem(&blank)).contains("limit is 65536"));
    }

    #[test]
    fn certificate_count_is_bounded() {
        let pem = test_pki::ca_pem();
        let at_limit = pem.repeat(MAX_DISCOVERY_CA_CERTS);
        assert_eq!(
            normalize_discovery_ca_pem(&at_limit).unwrap().matches("BEGIN CERTIFICATE").count(),
            MAX_DISCOVERY_CA_CERTS
        );
        let over = pem.repeat(MAX_DISCOVERY_CA_CERTS + 1);
        let e = err_text(normalize_discovery_ca_pem(&over));
        assert!(e.contains("limit is 8"), "{e}");
    }

    #[test]
    fn an_unusable_stored_value_fails_the_client_build() {
        // No fallback to a client without the operator's anchors.
        assert!(reqwest_http_client("garbage").is_err());
        let chain = test_pki::chain(&["idp.test"]);
        assert!(reqwest_http_client(&chain.leaf_key_pem).is_err());
    }

    // ── real TLS handshakes ─────────────────────────────────────────

    /// A loopback HTTPS server presenting `chain` (leaf first); answers
    /// every request with `200 ok`. Dropping it stops accepting.
    struct TlsServer {
        addr: SocketAddr,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TlsServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn start_tls_server(chain: Vec<Vec<u8>>, key_der: Vec<u8>) -> TlsServer {
        let config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(
                    chain.into_iter().map(CertificateDer::from).collect(),
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
                )
                .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // A client that refuses the certificate ends here.
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let mut head = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) if head.len() + n > 64 * 1024 => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        TlsServer { addr, task }
    }

    async fn get(client: &reqwest::Client, addr: SocketAddr) -> Result<u16, String> {
        client.get(format!("https://{addr}/")).send().await.map(|r| r.status().as_u16()).map_err(|e| error_chain(&e))
    }

    /// The production failure: the IdP sends only its leaf, whose issuer
    /// (an intermediate) is in no built-in store. Pasting that issuer into
    /// `oidc_discovery_ca_pem` makes the same handshake succeed.
    #[tokio::test]
    async fn the_extra_ca_completes_a_chain_the_idp_does_not_send() {
        let chain = test_pki::chain(&["127.0.0.1"]);
        let server = start_tls_server(vec![chain.leaf_der.clone()], chain.leaf_key_der.clone()).await;

        let plain = reqwest_http_client("").expect("plain client");
        let e = get(&plain, server.addr).await.expect_err("built-in roots must not trust the test chain");
        assert!(e.to_ascii_lowercase().contains("certificate"), "unexpected failure: {e}");

        let unrelated = reqwest_http_client(&normalize_discovery_ca_pem(&test_pki::ca_pem()).unwrap()).unwrap();
        assert!(get(&unrelated, server.addr).await.is_err(), "an unrelated CA must not help");

        let ca = normalize_discovery_ca_pem(&chain.intermediate_pem).unwrap();
        let with_ca = reqwest_http_client(&ca).expect("client with the intermediate");
        assert_eq!(get(&with_ca, server.addr).await, Ok(200));
    }

    /// Adding an anchor must not relax hostname verification.
    #[tokio::test]
    async fn the_extra_ca_does_not_disable_hostname_checks() {
        let chain = test_pki::chain(&["idp.example.invalid"]);
        let server = start_tls_server(vec![chain.leaf_der.clone()], chain.leaf_key_der.clone()).await;
        let ca = normalize_discovery_ca_pem(&chain.intermediate_pem).unwrap();
        let with_ca = reqwest_http_client(&ca).expect("client with the intermediate");
        let e = get(&with_ca, server.addr).await.expect_err("a leaf for another name must be refused");
        assert!(e.to_ascii_lowercase().contains("certificate"), "unexpected failure: {e}");
    }
}
