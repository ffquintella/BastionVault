//! The one error type of the TLS layer.
//!
//! Every message names what went wrong in operator terms and never carries
//! key material, handshake secrets or decrypted data. Record-protection
//! failures are deliberately a single variant ([`TlsError::BadRecordMac`])
//! with a single message: a bad MAC and a bad CBC padding must not be
//! distinguishable by error, alert or timing (Lucky13 / padding oracles).

use std::{fmt, io};

/// TLS alert descriptions this crate sends or names (RFC 5246 §7.2).
pub(crate) mod alert {
    pub const CLOSE_NOTIFY: u8 = 0;
    pub const UNEXPECTED_MESSAGE: u8 = 10;
    pub const BAD_RECORD_MAC: u8 = 20;
    pub const RECORD_OVERFLOW: u8 = 22;
    pub const HANDSHAKE_FAILURE: u8 = 40;
    pub const BAD_CERTIFICATE: u8 = 42;
    pub const CERTIFICATE_EXPIRED: u8 = 45;
    pub const ILLEGAL_PARAMETER: u8 = 47;
    pub const UNKNOWN_CA: u8 = 48;
    pub const DECODE_ERROR: u8 = 50;
    pub const DECRYPT_ERROR: u8 = 51;
    pub const PROTOCOL_VERSION: u8 = 70;
    pub const INTERNAL_ERROR: u8 = 80;
    pub const NO_RENEGOTIATION: u8 = 100;
    pub const UNSUPPORTED_EXTENSION: u8 = 110;

    /// RFC name of an alert description, for messages.
    pub fn name(description: u8) -> &'static str {
        match description {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            21 => "decryption_failed",
            22 => "record_overflow",
            30 => "decompression_failure",
            40 => "handshake_failure",
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            47 => "illegal_parameter",
            48 => "unknown_ca",
            49 => "access_denied",
            50 => "decode_error",
            51 => "decrypt_error",
            70 => "protocol_version",
            71 => "insufficient_security",
            80 => "internal_error",
            86 => "inappropriate_fallback",
            90 => "user_canceled",
            100 => "no_renegotiation",
            110 => "unsupported_extension",
            112 => "unrecognized_name",
            _ => "unknown alert",
        }
    }
}

/// A failure of the legacy TLS client. Fatal: the connection is unusable
/// after any of these.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsError {
    /// The underlying transport failed.
    Io(io::Error),
    /// The peer closed the transport without a `close_notify`, mid-handshake
    /// or mid-record (truncation is never treated as a clean end).
    UnexpectedEof(&'static str),
    /// The handshake did not finish within the configured time.
    HandshakeTimeout,
    /// A protected record failed its MAC or padding check. One variant, one
    /// message, one alert, whatever the cause.
    BadRecordMac,
    /// A record exceeded the RFC 5246 size limits.
    RecordOverflow,
    /// The server sent a fatal alert (or a warning alert other than
    /// `close_notify`, which this client treats as fatal).
    AlertReceived(u8),
    /// The server negotiated a protocol version other than TLS 1.2.
    UnsupportedVersion(u16),
    /// The server selected a cipher suite this client did not offer.
    UnsupportedCipherSuite(u16),
    /// The server violated the protocol; `what` says how.
    PeerMisbehaved { alert: u8, what: &'static str },
    /// The server's certificate chain or name did not verify.
    CertificateRejected(String),
    /// The ServerKeyExchange signature did not verify under the server's
    /// certificate key.
    BadServerKeyExchangeSignature,
    /// The server's `Finished` did not match the transcript.
    FinishedMismatch,
    /// The server tried to start a renegotiation; this client never accepts one.
    RenegotiationRefused,
    /// The server asked for a client certificate; this client sends none.
    ClientCertificateRequested,
    /// The trust anchors given to the client could not be used.
    InvalidTrustAnchor(String),
    /// The server name could not be used for SNI / verification.
    InvalidServerName,
    /// A local failure (randomness, key generation) that is not the peer's fault.
    Internal(&'static str),
}

impl TlsError {
    /// The fatal alert to send to the peer for this failure, if any.
    pub(crate) fn alert(&self) -> Option<u8> {
        match self {
            TlsError::BadRecordMac => Some(alert::BAD_RECORD_MAC),
            TlsError::RecordOverflow => Some(alert::RECORD_OVERFLOW),
            TlsError::UnsupportedVersion(_) => Some(alert::PROTOCOL_VERSION),
            TlsError::UnsupportedCipherSuite(_) => Some(alert::ILLEGAL_PARAMETER),
            TlsError::PeerMisbehaved { alert, .. } => Some(*alert),
            TlsError::CertificateRejected(reason) => Some(if reason.starts_with("UnknownIssuer") {
                alert::UNKNOWN_CA
            } else if reason.starts_with("CertExpired") || reason.starts_with("CertNotValidYet") {
                alert::CERTIFICATE_EXPIRED
            } else {
                alert::BAD_CERTIFICATE
            }),
            TlsError::BadServerKeyExchangeSignature | TlsError::FinishedMismatch => Some(alert::DECRYPT_ERROR),
            TlsError::RenegotiationRefused => Some(alert::NO_RENEGOTIATION),
            TlsError::ClientCertificateRequested => Some(alert::HANDSHAKE_FAILURE),
            TlsError::Internal(_) => Some(alert::INTERNAL_ERROR),
            TlsError::Io(_)
            | TlsError::UnexpectedEof(_)
            | TlsError::HandshakeTimeout
            | TlsError::AlertReceived(_)
            | TlsError::InvalidTrustAnchor(_)
            | TlsError::InvalidServerName => None,
        }
    }

    /// The `io::ErrorKind` this failure maps to when surfaced through
    /// `AsyncRead` / `AsyncWrite`.
    pub(crate) fn io_kind(&self) -> io::ErrorKind {
        match self {
            TlsError::Io(e) => e.kind(),
            TlsError::UnexpectedEof(_) => io::ErrorKind::UnexpectedEof,
            TlsError::HandshakeTimeout => io::ErrorKind::TimedOut,
            TlsError::AlertReceived(_) => io::ErrorKind::ConnectionAborted,
            _ => io::ErrorKind::InvalidData,
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("legacy TLS 1.2 (CBC) client: ")?;
        match self {
            TlsError::Io(e) => write!(f, "transport error: {e}"),
            TlsError::UnexpectedEof(what) => write!(f, "connection closed without close_notify {what}"),
            TlsError::HandshakeTimeout => f.write_str("handshake timed out"),
            TlsError::BadRecordMac => f.write_str("record failed integrity check (bad_record_mac)"),
            TlsError::RecordOverflow => f.write_str("record exceeds the TLS size limit (record_overflow)"),
            TlsError::AlertReceived(d) => write!(f, "server sent fatal alert {} ({d})", alert::name(*d)),
            TlsError::UnsupportedVersion(v) => {
                write!(f, "server negotiated protocol version 0x{v:04x}; only TLS 1.2 (0x0303) is accepted")
            }
            TlsError::UnsupportedCipherSuite(s) => {
                write!(f, "server selected cipher suite 0x{s:04x}, which this client did not offer")
            }
            TlsError::PeerMisbehaved { what, .. } => write!(f, "protocol violation by the server: {what}"),
            TlsError::CertificateRejected(reason) => write!(f, "server certificate rejected: {reason}"),
            TlsError::BadServerKeyExchangeSignature => {
                f.write_str("ServerKeyExchange signature does not verify under the server certificate")
            }
            TlsError::FinishedMismatch => f.write_str("server Finished does not match the handshake transcript"),
            TlsError::RenegotiationRefused => f.write_str("server attempted a renegotiation; refused"),
            TlsError::ClientCertificateRequested => {
                f.write_str("server requested a client certificate; this client does not send one")
            }
            TlsError::InvalidTrustAnchor(reason) => write!(f, "unusable trust anchor: {reason}"),
            TlsError::InvalidServerName => f.write_str("server name is not a valid DNS name or IP address"),
            TlsError::Internal(what) => write!(f, "internal error: {what}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TlsError {
    fn from(e: io::Error) -> Self {
        // A TLS failure surfaced through AsyncRead/AsyncWrite travels as an
        // io::Error wrapping the TlsError; unwrap it rather than nest it.
        if e.get_ref().is_some_and(|inner| inner.is::<TlsError>()) {
            let kind = e.kind();
            return match e.into_inner().map(|inner| inner.downcast::<TlsError>()) {
                Some(Ok(tls)) => *tls,
                _ => TlsError::Io(io::Error::from(kind)),
            };
        }
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return TlsError::UnexpectedEof("by the peer");
        }
        TlsError::Io(e)
    }
}

impl From<TlsError> for io::Error {
    fn from(e: TlsError) -> Self {
        match e {
            TlsError::Io(inner) => inner,
            other => io::Error::new(other.io_kind(), other),
        }
    }
}
