//! Test-only TLS 1.2 server half for the four CBC suites, with knobs to
//! break the handshake or the record layer in specific ways. It reuses the
//! client's record layer, so the independent-implementation checks are the
//! PRF vectors and the OpenSSL interop test, not this.

use std::{sync::OnceLock, time::Duration};

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{RsaEncoding, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PSS_SHA256},
};
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::{sec1::ToSec1Point, Generate},
    PublicKey,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    codec::{handshake_message, put_vec_u16, put_vec_u24, put_vec_u8, Reader},
    error::TlsError,
    handshake::{ext, msg, ConnectionInfo, RecordIo, SECP256R1},
    prf,
    record::{content, Decryptor, Encryptor, SealTamper, TLS12},
    stream::LegacyTlsStream,
    suite::CipherSuite,
};

/// One RSA-2048 key per test process (aws-lc keygen), as PKCS#8 DER.
fn rsa_pkcs8() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        let kp = RsaKeyPair::generate(KeySize::Rsa2048).expect("RSA keygen");
        let der: aws_lc_rs::encoding::Pkcs8V1Der<'static> = kp.as_der().expect("PKCS#8");
        der.as_ref().to_vec()
    })
}

/// A throwaway ECDSA CA and an RSA leaf it issued for `names`.
pub(crate) struct TestPki {
    pub ca_der: Vec<u8>,
    pub ca_pem: String,
    pub leaf: CertificateDer<'static>,
    pub leaf_pem: String,
    pub leaf_key_pem: String,
}

pub(crate) fn pki(names: &[&str]) -> TestPki {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "bv-tls-legacy test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).expect("CA cert");

    let leaf_key = KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(rsa_pkcs8()), &PKCS_RSA_SHA256)
        .expect("leaf key");
    let leaf = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
        .expect("leaf params")
        .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
        .expect("leaf cert");
    TestPki {
        ca_der: ca.der().to_vec(),
        ca_pem: ca.pem(),
        leaf: CertificateDer::from(leaf.der().to_vec()),
        leaf_pem: leaf.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
    }
}

/// Ways to misbehave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tamper {
    None,
    SkeSignature,
    Finished,
    CertificateRequest,
    CloseAfterServerHello,
    StallAfterServerHello,
    AppBadMac,
    AppBadPadding,
    AppOversizedRecord,
    AppTruncatedRecord,
    HelloRequestAfterHandshake,
    /// Response sent, then the TCP connection closed without close_notify.
    NoCloseNotify,
}

#[derive(Clone, Debug)]
pub(crate) struct ServerOptions {
    /// Preference order; the first one the client offered is chosen.
    pub suites: Vec<CipherSuite>,
    pub force_suite: Option<u16>,
    pub version: u16,
    pub echo_ems: bool,
    pub renegotiation_info: Option<Vec<u8>>,
    pub extra_extension: Option<(u16, Vec<u8>)>,
    pub sig_scheme: u16,
    pub tamper: Tamper,
    pub response: Vec<u8>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            suites: crate::suite::OFFERED.to_vec(),
            force_suite: None,
            version: TLS12,
            echo_ems: true,
            renegotiation_info: Some(vec![0]),
            extra_extension: None,
            sig_scheme: 0x0401,
            tamper: Tamper::None,
            response: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok".to_vec(),
        }
    }
}

/// What the server saw.
#[derive(Debug, Default)]
pub(crate) struct ServerOutcome {
    pub sni: Option<String>,
    pub request: Vec<u8>,
    /// The alert the client sent when it gave up, if it sent one.
    pub client_alert: Option<u8>,
}

struct ClientHelloInfo {
    random: [u8; 32],
    suites: Vec<u16>,
    ems: bool,
    sni: Option<String>,
}

fn parse_client_hello(body: &[u8]) -> Result<ClientHelloInfo, TlsError> {
    let mut r = Reader::new(body, "ClientHello");
    r.u16()?;
    let random: [u8; 32] = r.bytes(32)?.try_into().unwrap();
    r.vec_u8()?;
    let mut sr = Reader::new(r.vec_u16()?, "suites");
    let mut suites = Vec::new();
    while !sr.is_empty() {
        suites.push(sr.u16()?);
    }
    r.vec_u8()?;
    let mut info = ClientHelloInfo { random, suites, ems: false, sni: None };
    let mut er = Reader::new(r.vec_u16()?, "extensions");
    while !er.is_empty() {
        let t = er.u16()?;
        let data = er.vec_u16()?;
        match t {
            ext::SERVER_NAME => {
                let mut d = Reader::new(data, "sni");
                let mut list = Reader::new(d.vec_u16()?, "sni list");
                list.u8()?;
                info.sni = Some(String::from_utf8_lossy(list.vec_u16()?).into_owned());
            }
            ext::EXTENDED_MASTER_SECRET => info.ems = true,
            _ => {}
        }
    }
    Ok(info)
}

fn sign(scheme: u16, msg: &[u8]) -> Vec<u8> {
    let kp = RsaKeyPair::from_pkcs8(rsa_pkcs8()).expect("key");
    let encoding: &'static dyn RsaEncoding = match scheme {
        0x0401 => &RSA_PKCS1_SHA256,
        0x0501 => &RSA_PKCS1_SHA384,
        0x0804 => &RSA_PSS_SHA256,
        _ => &RSA_PKCS1_SHA256,
    };
    let mut sig = vec![0u8; kp.public_modulus_len()];
    kp.sign(encoding, &SystemRandom::new(), msg, &mut sig).expect("sign");
    sig
}

/// Read records until an alert (returned) or the end of the connection.
async fn capture_alert(rio: &mut RecordIo<TcpStream>) -> Option<u8> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rio.read_record()).await {
            Ok(Ok((content::ALERT, payload))) if payload.len() == 2 => return Some(payload[1]),
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
}

/// Serve one connection according to `opts`.
pub(crate) async fn serve(tcp: TcpStream, pki: &TestPki, opts: &ServerOptions) -> ServerOutcome {
    let mut out = ServerOutcome::default();
    let mut rio = RecordIo::new(tcp);
    rio.plain_version = opts.version;
    let Ok((t, ch)) = rio.read_handshake().await else { return out };
    assert_eq!(t, msg::CLIENT_HELLO);
    let Ok(hello) = parse_client_hello(&ch[4..]) else { return out };
    out.sni = hello.sni.clone();
    let mut transcript = ch.clone();

    let suite_id = opts.force_suite.unwrap_or_else(|| {
        opts.suites.iter().map(|s| s.id()).find(|id| hello.suites.contains(id)).expect("a common suite")
    });
    let ems = opts.echo_ems && hello.ems;
    let mut server_random = [0u8; 32];
    getrandom::fill(&mut server_random).unwrap();

    let mut sh = Vec::new();
    sh.extend_from_slice(&opts.version.to_be_bytes());
    sh.extend_from_slice(&server_random);
    put_vec_u8(&mut sh, &[0x5a; 32]); // a session id the client must ignore
    sh.extend_from_slice(&suite_id.to_be_bytes());
    sh.push(0);
    let mut exts = Vec::new();
    let mut push = |t: u16, d: &[u8]| {
        exts.extend_from_slice(&t.to_be_bytes());
        put_vec_u16(&mut exts, d);
    };
    if ems {
        push(ext::EXTENDED_MASTER_SECRET, &[]);
    }
    if let Some(ri) = &opts.renegotiation_info {
        push(ext::RENEGOTIATION_INFO, ri);
    }
    push(ext::EC_POINT_FORMATS, &[1, 0]);
    if let Some((t, d)) = &opts.extra_extension {
        push(*t, d);
    }
    put_vec_u16(&mut sh, &exts);
    let sh = handshake_message(msg::SERVER_HELLO, &sh);
    transcript.extend_from_slice(&sh);
    let mut flight = Vec::new();
    rio.queue_record(content::HANDSHAKE, &sh, &mut flight).unwrap();

    let Some(suite) = CipherSuite::from_id(suite_id).filter(|_| opts.version == TLS12) else {
        let _ = rio.write_flush(&flight).await;
        out.client_alert = capture_alert(&mut rio).await;
        return out;
    };
    match opts.tamper {
        Tamper::CloseAfterServerHello => {
            let _ = rio.write_flush(&flight).await;
            let _ = rio.io.shutdown().await;
            return out;
        }
        Tamper::StallAfterServerHello => {
            let _ = rio.write_flush(&flight).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            return out;
        }
        _ => {}
    }
    rio.plain_version = TLS12;
    rio.strict_version = true;

    let mut cert_list = Vec::new();
    put_vec_u24(&mut cert_list, pki.leaf.as_ref());
    let mut cert_body = Vec::new();
    put_vec_u24(&mut cert_body, &cert_list);
    let cert = handshake_message(msg::CERTIFICATE, &cert_body);

    let secret = EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng).unwrap();
    let point = secret.public_key().to_sec1_point(false);
    let mut params = vec![3u8];
    params.extend_from_slice(&SECP256R1.to_be_bytes());
    put_vec_u8(&mut params, point.as_bytes());
    let mut signed = hello.random.to_vec();
    signed.extend_from_slice(&server_random);
    signed.extend_from_slice(&params);
    let mut signature = sign(opts.sig_scheme, &signed);
    if opts.tamper == Tamper::SkeSignature {
        signature[10] ^= 0x01;
    }
    let mut ske_body = params.clone();
    ske_body.extend_from_slice(&opts.sig_scheme.to_be_bytes());
    put_vec_u16(&mut ske_body, &signature);
    let ske = handshake_message(msg::SERVER_KEY_EXCHANGE, &ske_body);

    let done = handshake_message(msg::SERVER_HELLO_DONE, &[]);
    for m in [&cert, &ske] {
        transcript.extend_from_slice(m);
        rio.queue_record(content::HANDSHAKE, m, &mut flight).unwrap();
    }
    if opts.tamper == Tamper::CertificateRequest {
        let mut body = Vec::new();
        put_vec_u8(&mut body, &[1]);
        put_vec_u16(&mut body, &[4, 1]);
        put_vec_u16(&mut body, &[]);
        let cr = handshake_message(msg::CERTIFICATE_REQUEST, &body);
        rio.queue_record(content::HANDSHAKE, &cr, &mut flight).unwrap();
    }
    transcript.extend_from_slice(&done);
    rio.queue_record(content::HANDSHAKE, &done, &mut flight).unwrap();
    if rio.write_flush(&flight).await.is_err() {
        return out;
    }

    let (t, cke) = match rio.read_handshake().await {
        Ok(m) => m,
        Err(TlsError::AlertReceived(d)) => {
            out.client_alert = Some(d);
            return out;
        }
        Err(_) => return out,
    };
    if t == msg::CLIENT_KEY_EXCHANGE {
        transcript.extend_from_slice(&cke);
    } else {
        return out;
    }
    let client_point = Reader::new(&cke[4..], "cke").vec_u8().unwrap().to_vec();
    let client_key = PublicKey::from_sec1_bytes(&client_point).unwrap();
    let pre_master = secret.diffie_hellman(&client_key).raw_secret_bytes().to_vec();
    let hash = suite.prf();
    let master = if ems {
        prf::extended_master_secret(hash, &pre_master, &prf::transcript_hash(hash, &transcript))
    } else {
        prf::master_secret(hash, &pre_master, &hello.random, &server_random)
    };
    let keys = prf::key_material(suite, &master, &hello.random, &server_random);
    if rio.read_change_cipher_spec().await.is_err() {
        return out;
    }
    rio.decryptor = Some(Decryptor::new(suite, &keys.client_mac, &keys.client_key).unwrap());
    let expected = prf::verify_data(hash, &master, b"client finished", &prf::transcript_hash(hash, &transcript));
    let Ok((t, fin)) = rio.read_handshake().await else { return out };
    assert_eq!(t, msg::FINISHED);
    assert_eq!(&fin[4..], &expected[..], "client Finished must verify");
    transcript.extend_from_slice(&fin);

    let mut verify = prf::verify_data(hash, &master, b"server finished", &prf::transcript_hash(hash, &transcript));
    if opts.tamper == Tamper::Finished {
        verify[0] ^= 0x01;
    }
    let mut flight = Vec::new();
    rio.queue_record(content::CHANGE_CIPHER_SPEC, &[1], &mut flight).unwrap();
    rio.encryptor = Some(Encryptor::new(suite, &keys.server_mac, &keys.server_key).unwrap());
    rio.queue_record(content::HANDSHAKE, &handshake_message(msg::FINISHED, &verify), &mut flight).unwrap();
    if rio.write_flush(&flight).await.is_err() {
        return out;
    }
    if opts.tamper == Tamper::Finished {
        out.client_alert = capture_alert(&mut rio).await;
        return out;
    }

    let info = ConnectionInfo { suite, extended_master_secret: ems, secure_renegotiation: true };
    let (io, rx, decryptor, encryptor) = rio.into_parts();
    let mut stream = LegacyTlsStream::new(io, rx, decryptor.unwrap(), encryptor.unwrap(), info);

    // The request: head, then Content-Length bytes if any.
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = out.request.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&out.request[..end]).to_ascii_lowercase();
            let body_len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: ").map(|v| v.trim().parse::<usize>().unwrap()))
                .unwrap_or(0);
            if out.request.len() >= end + 4 + body_len {
                break;
            }
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return out,
            Ok(n) => out.request.extend_from_slice(&buf[..n]),
        }
    }

    let mut raw = Vec::new();
    match opts.tamper {
        Tamper::AppBadMac | Tamper::AppBadPadding => {
            let how = if opts.tamper == Tamper::AppBadMac { SealTamper::FlipMac } else { SealTamper::BadPadding };
            stream.encryptor.seal_tampered(content::APPLICATION_DATA, &opts.response, &mut raw, how).unwrap();
        }
        Tamper::AppOversizedRecord => {
            raw.extend_from_slice(&[content::APPLICATION_DATA, 3, 3, 0x48, 0x01]);
            raw.extend(std::iter::repeat_n(0u8, 0x4801));
        }
        Tamper::AppTruncatedRecord => {
            stream.encryptor.seal(content::APPLICATION_DATA, &opts.response, &mut raw).unwrap();
            raw.truncate(raw.len() / 2);
        }
        Tamper::HelloRequestAfterHandshake => {
            stream.encryptor.seal(content::HANDSHAKE, &[0, 0, 0, 0], &mut raw).unwrap();
        }
        _ => {}
    }
    if !raw.is_empty() {
        let io = stream.get_mut();
        let _ = io.write_all(&raw).await;
        let _ = io.flush().await;
        if opts.tamper == Tamper::AppTruncatedRecord {
            let _ = io.shutdown().await;
            return out;
        }
        // The client's alert arrives protected with its keys.
        if let Ok(Err(e)) = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            if let Some(Ok(tls)) = e.into_inner().map(|inner| inner.downcast::<TlsError>()) {
                if let TlsError::AlertReceived(d) = *tls {
                    out.client_alert = Some(d);
                }
            }
        }
        return out;
    }
    let _ = stream.write_all(&opts.response).await;
    let _ = stream.flush().await;
    if opts.tamper == Tamper::NoCloseNotify {
        let _ = stream.get_mut().shutdown().await;
    } else {
        let _ = stream.shutdown().await;
    }
    out
}
