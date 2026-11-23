//! The client handshake: full ECDHE-RSA handshake, no resumption, no
//! renegotiation, no client certificate. Anything the server sends that is
//! not exactly what was negotiated is a fatal error naming the violation.

use std::time::Duration;

use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::{sec1::ToSec1Point, Generate},
    PublicKey,
};
use rustls_pki_types::{CertificateDer, ServerName};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{
    codec::{decode_error, handshake_message, put_vec_u16, put_vec_u8, Reader},
    error::{alert, TlsError},
    prf,
    record::{content, Decryptor, Encryptor, HEADER_LEN, MAX_CIPHERTEXT, MAX_PLAINTEXT, TLS12},
    suite::{CipherSuite, OFFERED},
    verify::{verify_server_chain, verify_ske_signature, TrustAnchors, MAX_CHAIN_LEN, OFFERED_SIGNATURE_SCHEMES},
};

/// Handshake message types (RFC 5246 §7.4).
pub(crate) mod msg {
    pub const HELLO_REQUEST: u8 = 0;
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const CERTIFICATE: u8 = 11;
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    pub const CERTIFICATE_REQUEST: u8 = 13;
    pub const SERVER_HELLO_DONE: u8 = 14;
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    pub const FINISHED: u8 = 20;
}

/// Extension types (RFC 6066, RFC 8422, RFC 5246, RFC 7627, RFC 5746).
pub(crate) mod ext {
    pub const SERVER_NAME: u16 = 0;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const EC_POINT_FORMATS: u16 = 11;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// The one named group offered (RFC 8422 §5.1.1).
pub(crate) const SECP256R1: u16 = 23;
/// Largest handshake message accepted (certificate chains included).
pub(crate) const MAX_HANDSHAKE_MESSAGE: usize = 64 * 1024;
/// How long a best-effort alert may take before the connection is dropped.
const ALERT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Client settings. Verification is not configurable.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Upper bound on the whole handshake.
    pub handshake_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self { handshake_timeout: Duration::from_secs(10) }
    }
}

/// What was negotiated. None of it is secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub suite: CipherSuite,
    /// RFC 7627 extended master secret in use.
    pub extended_master_secret: bool,
    /// The server answered the RFC 5746 `renegotiation_info` extension.
    pub secure_renegotiation: bool,
}

/// Records over a transport, during the handshake: reassembles handshake
/// messages across records and protects records once keys are installed.
pub(crate) struct RecordIo<IO> {
    pub(crate) io: IO,
    pub(crate) rx: Vec<u8>,
    hs_buf: Vec<u8>,
    pub(crate) decryptor: Option<Decryptor>,
    pub(crate) encryptor: Option<Encryptor>,
    /// Version written on plaintext records (0x0301 for the first flight,
    /// as most stacks do, then 0x0303).
    pub(crate) plain_version: u16,
    /// Whether incoming records must carry exactly 0x0303 (after the hellos).
    pub(crate) strict_version: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> RecordIo<IO> {
    pub(crate) fn new(io: IO) -> Self {
        Self {
            io,
            rx: Vec::new(),
            hs_buf: Vec::new(),
            decryptor: None,
            encryptor: None,
            plain_version: 0x0301,
            strict_version: false,
        }
    }

    async fn fill(&mut self, need: usize) -> Result<(), TlsError> {
        let mut buf = [0u8; 4096];
        while self.rx.len() < need {
            let n = self.io.read(&mut buf).await.map_err(TlsError::Io)?;
            if n == 0 {
                return Err(TlsError::UnexpectedEof("during the handshake"));
            }
            self.rx.extend_from_slice(&buf[..n]);
        }
        Ok(())
    }

    /// The next record: content type and (decrypted, verified) payload.
    pub(crate) async fn read_record(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        self.fill(HEADER_LEN).await?;
        let content_type = self.rx[0];
        let version = u16::from_be_bytes([self.rx[1], self.rx[2]]);
        let len = usize::from(u16::from_be_bytes([self.rx[3], self.rx[4]]));
        if !(content::CHANGE_CIPHER_SPEC..=content::APPLICATION_DATA).contains(&content_type) {
            return Err(TlsError::PeerMisbehaved {
                alert: alert::UNEXPECTED_MESSAGE,
                what: "record of an unknown content type",
            });
        }
        let version_ok = if self.strict_version { version == TLS12 } else { (0x0301..=TLS12).contains(&version) };
        if !version_ok {
            return Err(TlsError::PeerMisbehaved {
                alert: alert::PROTOCOL_VERSION,
                what: "record carries a protocol version other than TLS 1.2",
            });
        }
        let limit = if self.decryptor.is_some() { MAX_CIPHERTEXT } else { MAX_PLAINTEXT };
        if len > limit {
            return Err(TlsError::RecordOverflow);
        }
        self.fill(HEADER_LEN + len).await?;
        let mut fragment = self.rx[HEADER_LEN..HEADER_LEN + len].to_vec();
        self.rx.drain(..HEADER_LEN + len);
        let payload = match self.decryptor.as_mut() {
            Some(d) => d.open(content_type, &mut fragment)?.to_vec(),
            None => fragment,
        };
        Ok((content_type, payload))
    }

    /// The next complete handshake message, header included.
    pub(crate) async fn read_handshake(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        loop {
            if self.hs_buf.len() >= 4 {
                let len = (usize::from(self.hs_buf[1]) << 16)
                    | (usize::from(self.hs_buf[2]) << 8)
                    | usize::from(self.hs_buf[3]);
                if len > MAX_HANDSHAKE_MESSAGE {
                    return Err(TlsError::PeerMisbehaved {
                        alert: alert::ILLEGAL_PARAMETER,
                        what: "handshake message larger than 64 KiB",
                    });
                }
                if self.hs_buf.len() >= 4 + len {
                    let message: Vec<u8> = self.hs_buf.drain(..4 + len).collect();
                    return Ok((message[0], message));
                }
            }
            let (content_type, payload) = self.read_record().await?;
            match content_type {
                content::HANDSHAKE if payload.is_empty() => {
                    return Err(TlsError::PeerMisbehaved {
                        alert: alert::UNEXPECTED_MESSAGE,
                        what: "zero-length handshake record",
                    })
                }
                content::HANDSHAKE => self.hs_buf.extend_from_slice(&payload),
                content::ALERT => return Err(alert_error(&payload)),
                content::CHANGE_CIPHER_SPEC => {
                    return Err(TlsError::PeerMisbehaved {
                        alert: alert::UNEXPECTED_MESSAGE,
                        what: "ChangeCipherSpec where a handshake message was expected",
                    })
                }
                _ => {
                    return Err(TlsError::PeerMisbehaved {
                        alert: alert::UNEXPECTED_MESSAGE,
                        what: "application data during the handshake",
                    })
                }
            }
        }
    }

    /// The peer's ChangeCipherSpec, which must not split a handshake message.
    pub(crate) async fn read_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if !self.hs_buf.is_empty() {
            return Err(TlsError::PeerMisbehaved {
                alert: alert::UNEXPECTED_MESSAGE,
                what: "ChangeCipherSpec in the middle of a handshake message",
            });
        }
        let (content_type, payload) = self.read_record().await?;
        match content_type {
            content::CHANGE_CIPHER_SPEC if payload == [1] => Ok(()),
            content::CHANGE_CIPHER_SPEC => Err(decode_error("ChangeCipherSpec")),
            content::ALERT => Err(alert_error(&payload)),
            _ => Err(TlsError::PeerMisbehaved {
                alert: alert::UNEXPECTED_MESSAGE,
                what: "expected ChangeCipherSpec (session tickets, renegotiation and extra messages are not accepted)",
            }),
        }
    }

    pub(crate) fn handshake_buffer_is_empty(&self) -> bool {
        self.hs_buf.is_empty()
    }

    /// Append one record to `out`, protected if keys are installed.
    pub(crate) fn queue_record(&mut self, content_type: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<(), TlsError> {
        match self.encryptor.as_mut() {
            Some(e) => e.seal(content_type, payload, out),
            None => {
                out.push(content_type);
                out.extend_from_slice(&self.plain_version.to_be_bytes());
                put_vec_u16(out, payload);
                Ok(())
            }
        }
    }

    pub(crate) async fn write_flush(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.io.write_all(data).await.map_err(TlsError::Io)?;
        self.io.flush().await.map_err(TlsError::Io)
    }

    /// A fatal alert, best effort: failures to send it are ignored.
    pub(crate) async fn send_alert(&mut self, description: u8) {
        let mut out = Vec::new();
        if self.queue_record(content::ALERT, &[2, description], &mut out).is_ok() {
            let _ = tokio::time::timeout(ALERT_WRITE_TIMEOUT, self.write_flush(&out)).await;
        }
    }

    pub(crate) fn into_parts(self) -> (IO, Vec<u8>, Option<Decryptor>, Option<Encryptor>) {
        (self.io, self.rx, self.decryptor, self.encryptor)
    }
}

/// The error for a received alert record.
pub(crate) fn alert_error(payload: &[u8]) -> TlsError {
    match payload {
        [_, description] => TlsError::AlertReceived(*description),
        _ => decode_error("alert"),
    }
}

fn unexpected(what: &'static str) -> TlsError {
    TlsError::PeerMisbehaved { alert: alert::UNEXPECTED_MESSAGE, what }
}

fn push_ext(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    put_vec_u16(out, data);
}

/// The ClientHello handshake message.
pub(crate) fn client_hello(random: &[u8; 32], sni: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(random);
    put_vec_u8(&mut body, &[]); // no session id: no resumption
    let suites: Vec<u8> = OFFERED.iter().flat_map(|s| s.id().to_be_bytes()).collect();
    put_vec_u16(&mut body, &suites);
    put_vec_u8(&mut body, &[0]); // null compression only

    let mut exts = Vec::new();
    if let Some(host) = sni {
        let mut list = vec![0u8]; // host_name
        put_vec_u16(&mut list, host.as_bytes());
        let mut data = Vec::new();
        put_vec_u16(&mut data, &list);
        push_ext(&mut exts, ext::SERVER_NAME, &data);
    }
    let mut groups = Vec::new();
    put_vec_u16(&mut groups, &SECP256R1.to_be_bytes());
    push_ext(&mut exts, ext::SUPPORTED_GROUPS, &groups);
    let mut formats = Vec::new();
    put_vec_u8(&mut formats, &[0]); // uncompressed
    push_ext(&mut exts, ext::EC_POINT_FORMATS, &formats);
    let schemes: Vec<u8> = OFFERED_SIGNATURE_SCHEMES.iter().flat_map(|s| s.to_be_bytes()).collect();
    let mut sigalgs = Vec::new();
    put_vec_u16(&mut sigalgs, &schemes);
    push_ext(&mut exts, ext::SIGNATURE_ALGORITHMS, &sigalgs);
    push_ext(&mut exts, ext::EXTENDED_MASTER_SECRET, &[]);
    push_ext(&mut exts, ext::RENEGOTIATION_INFO, &[0]); // empty renegotiated_connection
    put_vec_u16(&mut body, &exts);
    handshake_message(msg::CLIENT_HELLO, &body)
}

/// What the client keeps from ServerHello.
#[derive(Debug)]
pub(crate) struct ServerHello {
    pub random: [u8; 32],
    pub suite: CipherSuite,
    pub extended_master_secret: bool,
    pub secure_renegotiation: bool,
}

/// Strict ServerHello check: TLS 1.2, an offered suite, null compression, and
/// only extensions the client sent, each once and well formed.
pub(crate) fn parse_server_hello(body: &[u8], sent_sni: bool) -> Result<ServerHello, TlsError> {
    let mut r = Reader::new(body, "ServerHello");
    let version = r.u16()?;
    if version != TLS12 {
        return Err(TlsError::UnsupportedVersion(version));
    }
    let random: [u8; 32] = r.bytes(32)?.try_into().expect("32 bytes");
    if r.vec_u8()?.len() > 32 {
        return Err(decode_error("ServerHello session id"));
    }
    let suite_id = r.u16()?;
    let suite = CipherSuite::from_id(suite_id).ok_or(TlsError::UnsupportedCipherSuite(suite_id))?;
    if r.u8()? != 0 {
        return Err(TlsError::PeerMisbehaved {
            alert: alert::ILLEGAL_PARAMETER,
            what: "ServerHello selected a compression method; only null was offered",
        });
    }
    let mut hello = ServerHello { random, suite, extended_master_secret: false, secure_renegotiation: false };
    if r.is_empty() {
        return Ok(hello);
    }
    let exts = r.vec_u16()?;
    r.finish()?;
    let mut er = Reader::new(exts, "ServerHello extensions");
    let mut seen: Vec<u16> = Vec::new();
    while !er.is_empty() {
        let ext_type = er.u16()?;
        let data = er.vec_u16()?;
        if seen.contains(&ext_type) {
            return Err(TlsError::PeerMisbehaved {
                alert: alert::ILLEGAL_PARAMETER,
                what: "ServerHello repeats an extension",
            });
        }
        seen.push(ext_type);
        match ext_type {
            ext::SERVER_NAME if sent_sni => {
                if !data.is_empty() {
                    return Err(decode_error("ServerHello server_name"));
                }
            }
            ext::EC_POINT_FORMATS => {
                let mut d = Reader::new(data, "ServerHello ec_point_formats");
                let formats = d.vec_u8()?;
                d.finish()?;
                if !formats.contains(&0) {
                    return Err(TlsError::PeerMisbehaved {
                        alert: alert::ILLEGAL_PARAMETER,
                        what: "server does not accept uncompressed EC points",
                    });
                }
            }
            ext::EXTENDED_MASTER_SECRET => {
                if !data.is_empty() {
                    return Err(decode_error("ServerHello extended_master_secret"));
                }
                hello.extended_master_secret = true;
            }
            ext::RENEGOTIATION_INFO => {
                if data != [0] {
                    return Err(TlsError::PeerMisbehaved {
                        alert: alert::HANDSHAKE_FAILURE,
                        what: "renegotiation_info is not empty on an initial handshake (RFC 5746)",
                    });
                }
                hello.secure_renegotiation = true;
            }
            _ => {
                return Err(TlsError::PeerMisbehaved {
                    alert: alert::UNSUPPORTED_EXTENSION,
                    what: "ServerHello carries an extension the client did not send",
                })
            }
        }
    }
    Ok(hello)
}

/// The server's certificate list, leaf first, bounded.
pub(crate) fn parse_certificate(body: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut r = Reader::new(body, "Certificate");
    let list = r.vec_u24()?;
    r.finish()?;
    let mut lr = Reader::new(list, "Certificate list");
    let mut chain = Vec::new();
    while !lr.is_empty() {
        let cert = lr.vec_u24()?;
        if cert.is_empty() {
            return Err(decode_error("Certificate entry"));
        }
        if chain.len() == MAX_CHAIN_LEN {
            return Err(TlsError::CertificateRejected(format!("server sent more than {MAX_CHAIN_LEN} certificates")));
        }
        chain.push(CertificateDer::from(cert.to_vec()));
    }
    if chain.is_empty() {
        return Err(TlsError::CertificateRejected("server sent an empty certificate list".into()));
    }
    Ok(chain)
}

/// ServerKeyExchange for ECDHE: the signed params, the point, the scheme and
/// the signature.
pub(crate) struct ServerKeyExchange<'a> {
    pub params: &'a [u8],
    pub point: &'a [u8],
    pub scheme: u16,
    pub signature: &'a [u8],
}

pub(crate) fn parse_server_key_exchange(body: &[u8]) -> Result<ServerKeyExchange<'_>, TlsError> {
    let mut r = Reader::new(body, "ServerKeyExchange");
    if r.u8()? != 3 {
        return Err(TlsError::PeerMisbehaved {
            alert: alert::ILLEGAL_PARAMETER,
            what: "ServerKeyExchange curve type is not named_curve",
        });
    }
    if r.u16()? != SECP256R1 {
        return Err(TlsError::PeerMisbehaved {
            alert: alert::ILLEGAL_PARAMETER,
            what: "server chose a curve other than secp256r1, the only one offered",
        });
    }
    let point = r.vec_u8()?;
    if point.len() != 65 || point[0] != 0x04 {
        return Err(TlsError::PeerMisbehaved {
            alert: alert::ILLEGAL_PARAMETER,
            what: "ServerKeyExchange point is not an uncompressed secp256r1 point",
        });
    }
    let params = &body[..4 + point.len()];
    let scheme = r.u16()?;
    let signature = r.vec_u16()?;
    r.finish()?;
    if !OFFERED_SIGNATURE_SCHEMES.contains(&scheme) {
        return Err(TlsError::PeerMisbehaved {
            alert: alert::ILLEGAL_PARAMETER,
            what: "ServerKeyExchange signed with a scheme the client did not offer",
        });
    }
    Ok(ServerKeyExchange { params, point, scheme, signature })
}

fn expect_message(got: u8, want: u8, what: &'static str) -> Result<(), TlsError> {
    if got == want {
        return Ok(());
    }
    if got == msg::HELLO_REQUEST {
        return Err(TlsError::RenegotiationRefused);
    }
    Err(unexpected(what))
}

/// Run the client side of the handshake over `rio`.
pub(crate) async fn client_handshake<IO: AsyncRead + AsyncWrite + Unpin>(
    rio: &mut RecordIo<IO>,
    server_name: &ServerName<'_>,
    trust: &TrustAnchors,
) -> Result<ConnectionInfo, TlsError> {
    let sni = match server_name {
        ServerName::DnsName(name) => Some(name.as_ref().trim_end_matches('.').to_string()),
        // RFC 6066 §3: literal IP addresses are not sent in SNI.
        ServerName::IpAddress(_) => None,
        _ => return Err(TlsError::InvalidServerName),
    };

    let mut client_random = [0u8; 32];
    getrandom::fill(&mut client_random).map_err(|_| TlsError::Internal("the operating system RNG failed"))?;
    let hello = client_hello(&client_random, sni.as_deref());
    let mut transcript = hello.clone();
    let mut out = Vec::new();
    rio.queue_record(content::HANDSHAKE, &hello, &mut out)?;
    rio.write_flush(&out).await?;

    let (t, m) = rio.read_handshake().await?;
    expect_message(t, msg::SERVER_HELLO, "expected ServerHello")?;
    transcript.extend_from_slice(&m);
    // From here on every record (an alert refusing this ServerHello too) is
    // TLS 1.2 in both directions.
    rio.plain_version = TLS12;
    rio.strict_version = true;
    let sh = parse_server_hello(&m[4..], sni.is_some())?;

    let (t, m) = rio.read_handshake().await?;
    expect_message(t, msg::CERTIFICATE, "expected Certificate (anonymous and PSK suites are not offered)")?;
    transcript.extend_from_slice(&m);
    let chain = parse_certificate(&m[4..])?;
    verify_server_chain(&chain, server_name, trust)?;

    let (t, m) = rio.read_handshake().await?;
    expect_message(t, msg::SERVER_KEY_EXCHANGE, "expected ServerKeyExchange")?;
    transcript.extend_from_slice(&m);
    let ske = parse_server_key_exchange(&m[4..])?;
    let mut signed = Vec::with_capacity(64 + ske.params.len());
    signed.extend_from_slice(&client_random);
    signed.extend_from_slice(&sh.random);
    signed.extend_from_slice(ske.params);
    verify_ske_signature(&chain[0], ske.scheme, &signed, ske.signature)?;
    let server_key = PublicKey::from_sec1_bytes(ske.point).map_err(|_| TlsError::PeerMisbehaved {
        alert: alert::ILLEGAL_PARAMETER,
        what: "ServerKeyExchange point is not on secp256r1",
    })?;

    let (t, m) = rio.read_handshake().await?;
    match t {
        msg::SERVER_HELLO_DONE if m.len() == 4 => {}
        msg::SERVER_HELLO_DONE => return Err(decode_error("ServerHelloDone")),
        msg::CERTIFICATE_REQUEST => return Err(TlsError::ClientCertificateRequested),
        other => expect_message(other, msg::SERVER_HELLO_DONE, "expected ServerHelloDone")?,
    }
    transcript.extend_from_slice(&m);

    // Key exchange. The ephemeral secret and the shared secret are wiped on
    // drop by `p256`; the copies made here are `Zeroizing`.
    let secret = EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng)
        .map_err(|_| TlsError::Internal("the operating system RNG failed"))?;
    let our_point = secret.public_key().to_sec1_point(false);
    let pre_master = Zeroizing::new(secret.diffie_hellman(&server_key).raw_secret_bytes().to_vec());
    drop(secret);
    let mut cke_body = Vec::new();
    put_vec_u8(&mut cke_body, our_point.as_bytes());
    let cke = handshake_message(msg::CLIENT_KEY_EXCHANGE, &cke_body);
    transcript.extend_from_slice(&cke);

    let suite = sh.suite;
    let hash = suite.prf();
    let master = if sh.extended_master_secret {
        prf::extended_master_secret(hash, &pre_master, &prf::transcript_hash(hash, &transcript))
    } else {
        prf::master_secret(hash, &pre_master, &client_random, &sh.random)
    };
    drop(pre_master);
    let keys = prf::key_material(suite, &master, &client_random, &sh.random);

    let client_verify = prf::verify_data(hash, &master, b"client finished", &prf::transcript_hash(hash, &transcript));
    let finished = handshake_message(msg::FINISHED, &client_verify);
    let mut out = Vec::new();
    rio.queue_record(content::HANDSHAKE, &cke, &mut out)?;
    rio.queue_record(content::CHANGE_CIPHER_SPEC, &[1], &mut out)?;
    rio.encryptor = Some(Encryptor::new(suite, &keys.client_mac, &keys.client_key)?);
    rio.queue_record(content::HANDSHAKE, &finished, &mut out)?;
    rio.write_flush(&out).await?;
    transcript.extend_from_slice(&finished);

    rio.read_change_cipher_spec().await?;
    rio.decryptor = Some(Decryptor::new(suite, &keys.server_mac, &keys.server_key)?);
    let expected = prf::verify_data(hash, &master, b"server finished", &prf::transcript_hash(hash, &transcript));
    let (t, m) = rio.read_handshake().await?;
    expect_message(t, msg::FINISHED, "expected server Finished")?;
    if m.len() != 4 + prf::VERIFY_DATA_LEN {
        return Err(decode_error("Finished"));
    }
    if !bool::from(m[4..].ct_eq(&expected[..])) {
        return Err(TlsError::FinishedMismatch);
    }
    if !rio.handshake_buffer_is_empty() {
        return Err(unexpected("handshake data after the server Finished"));
    }
    Ok(ConnectionInfo {
        suite,
        extended_master_secret: sh.extended_master_secret,
        secure_renegotiation: sh.secure_renegotiation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_body(version: u16, suite: u16, compression: u8, exts: Option<&[u8]>) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&version.to_be_bytes());
        b.extend_from_slice(&[7u8; 32]);
        put_vec_u8(&mut b, &[]);
        b.extend_from_slice(&suite.to_be_bytes());
        b.push(compression);
        if let Some(e) = exts {
            put_vec_u16(&mut b, e);
        }
        b
    }

    fn one_ext(t: u16, data: &[u8]) -> Vec<u8> {
        let mut e = Vec::new();
        push_ext(&mut e, t, data);
        e
    }

    #[test]
    fn client_hello_offers_exactly_the_narrow_set() {
        let ch = client_hello(&[1u8; 32], Some("idp.example"));
        assert_eq!(ch[0], msg::CLIENT_HELLO);
        let mut r = Reader::new(&ch[4..], "t");
        assert_eq!(r.u16().unwrap(), TLS12);
        r.bytes(32).unwrap();
        assert!(r.vec_u8().unwrap().is_empty(), "no session id");
        assert_eq!(r.vec_u16().unwrap(), &[0xC0, 0x28, 0xC0, 0x27, 0xC0, 0x14, 0xC0, 0x13]);
        assert_eq!(r.vec_u8().unwrap(), &[0]);
        let exts = r.vec_u16().unwrap();
        r.finish().unwrap();
        let mut er = Reader::new(exts, "t");
        let mut types = Vec::new();
        while !er.is_empty() {
            types.push(er.u16().unwrap());
            er.vec_u16().unwrap();
        }
        assert_eq!(types, vec![0, 10, 11, 13, 23, 0xff01]);
        // An IP literal is never sent as SNI.
        let ch = client_hello(&[1u8; 32], None);
        assert!(!ch.windows(b"idp".len()).any(|w| w == b"idp"));
    }

    #[test]
    fn server_hello_is_checked_strictly() {
        let ok = parse_server_hello(&hello_body(TLS12, 0xC013, 0, None), true).unwrap();
        assert_eq!(ok.suite, CipherSuite::EcdheRsaAes128CbcSha);
        assert!(!ok.extended_master_secret && !ok.secure_renegotiation);

        let mut exts = one_ext(ext::EXTENDED_MASTER_SECRET, &[]);
        exts.extend(one_ext(ext::RENEGOTIATION_INFO, &[0]));
        exts.extend(one_ext(ext::EC_POINT_FORMATS, &[1, 0]));
        exts.extend(one_ext(ext::SERVER_NAME, &[]));
        let ok = parse_server_hello(&hello_body(TLS12, 0xC028, 0, Some(&exts)), true).unwrap();
        assert!(ok.extended_master_secret && ok.secure_renegotiation);

        // Downgrade to TLS 1.1 / 1.0.
        for v in [0x0302, 0x0301, 0x0300] {
            assert!(matches!(
                parse_server_hello(&hello_body(v, 0xC013, 0, None), true),
                Err(TlsError::UnsupportedVersion(x)) if x == v
            ));
        }
        // A suite that was not offered (GCM, static RSA, the SCSV).
        for s in [0xC02F, 0x002F, 0x00FF] {
            assert!(matches!(
                parse_server_hello(&hello_body(TLS12, s, 0, None), true),
                Err(TlsError::UnsupportedCipherSuite(x)) if x == s
            ));
        }
        // Compression.
        assert!(parse_server_hello(&hello_body(TLS12, 0xC013, 1, None), true).is_err());
        // Unsolicited extensions: session ticket, ALPN, SNI when none was sent.
        for (t, d) in [(35u16, &[][..]), (16, &[0, 3, 2, b'h', b'2'][..])] {
            let e = parse_server_hello(&hello_body(TLS12, 0xC013, 0, Some(&one_ext(t, d))), true).unwrap_err();
            assert_eq!(e.alert(), Some(alert::UNSUPPORTED_EXTENSION));
        }
        assert!(parse_server_hello(&hello_body(TLS12, 0xC013, 0, Some(&one_ext(0, &[]))), false).is_err());
        // Non-empty renegotiation_info on an initial handshake.
        let e = parse_server_hello(&hello_body(TLS12, 0xC013, 0, Some(&one_ext(0xff01, &[1, 9]))), true).unwrap_err();
        assert_eq!(e.alert(), Some(alert::HANDSHAKE_FAILURE));
        // Duplicated extension.
        let mut dup = one_ext(23, &[]);
        dup.extend(one_ext(23, &[]));
        assert!(parse_server_hello(&hello_body(TLS12, 0xC013, 0, Some(&dup)), true).is_err());
        // Compressed points only.
        assert!(parse_server_hello(&hello_body(TLS12, 0xC013, 0, Some(&one_ext(11, &[1, 1]))), true).is_err());
        // Trailing garbage.
        let mut body = hello_body(TLS12, 0xC013, 0, Some(&[]));
        body.push(0);
        assert!(parse_server_hello(&body, true).is_err());
    }

    #[test]
    fn server_key_exchange_is_checked_strictly() {
        let mut point = vec![4u8];
        point.extend_from_slice(&[1u8; 64]);
        let build = |curve_type: u8, curve: u16, point: &[u8], scheme: u16| {
            let mut b = vec![curve_type];
            b.extend_from_slice(&curve.to_be_bytes());
            put_vec_u8(&mut b, point);
            b.extend_from_slice(&scheme.to_be_bytes());
            put_vec_u16(&mut b, &[9u8; 256]);
            b
        };
        let ok = build(3, SECP256R1, &point, 0x0401);
        let parsed = parse_server_key_exchange(&ok).unwrap();
        assert_eq!(parsed.params, &ok[..69]);
        assert_eq!(parsed.scheme, 0x0401);
        // P-384, x25519, explicit curves, compressed points, SHA-1 signatures.
        assert!(parse_server_key_exchange(&build(3, 24, &point, 0x0401)).is_err());
        assert!(parse_server_key_exchange(&build(3, 29, &point, 0x0401)).is_err());
        assert!(parse_server_key_exchange(&build(1, SECP256R1, &point, 0x0401)).is_err());
        let mut compressed = vec![2u8];
        compressed.extend_from_slice(&[1u8; 32]);
        assert!(parse_server_key_exchange(&build(3, SECP256R1, &compressed, 0x0401)).is_err());
        assert!(parse_server_key_exchange(&build(3, SECP256R1, &point, 0x0201)).is_err());
    }

    #[test]
    fn certificate_list_is_bounded() {
        let mut list = Vec::new();
        for _ in 0..=MAX_CHAIN_LEN {
            crate::codec::put_vec_u24(&mut list, &[0x30]);
        }
        let mut body = Vec::new();
        crate::codec::put_vec_u24(&mut body, &list);
        assert!(matches!(parse_certificate(&body), Err(TlsError::CertificateRejected(_))));
        let mut empty = Vec::new();
        crate::codec::put_vec_u24(&mut empty, &[]);
        assert!(matches!(parse_certificate(&empty), Err(TlsError::CertificateRejected(_))));
    }
}
