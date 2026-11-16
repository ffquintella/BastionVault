//! LDAPv3 messages (RFC 4511 §4): decoding of the requests this directory
//! answers, encoding of its responses, and (in [`client`]) the request side
//! used by the tests and the whole-vault test. Every string and list is
//! bounded; write operations are recognised by tag only and never parsed.

use zeroize::Zeroizing;

use super::{
    ber::{self, BerError, Reader},
    filter::Filter,
};

pub const OID_STARTTLS: &str = "1.3.6.1.4.1.1466.20037";
pub const OID_NOTICE_OF_DISCONNECTION: &str = "1.3.6.1.4.1.1466.20036";

const MAX_DN_OCTETS: usize = 1024;
const MAX_OID_OCTETS: usize = 128;
const MAX_MECHANISM_OCTETS: usize = 64;
const MAX_ATTRIBUTE_OCTETS: usize = 128;
pub const MAX_REQUESTED_ATTRIBUTES: usize = 64;
pub const MAX_CONTROLS: usize = 16;
const MAX_CREDENTIAL_OCTETS: usize = 1024;

pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const ENUMERATED: u8 = 0x0a;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const BIND_REQUEST: u8 = 0x60;
    pub const BIND_RESPONSE: u8 = 0x61;
    pub const UNBIND_REQUEST: u8 = 0x42;
    pub const SEARCH_REQUEST: u8 = 0x63;
    pub const SEARCH_RESULT_ENTRY: u8 = 0x64;
    pub const SEARCH_RESULT_DONE: u8 = 0x65;
    pub const MODIFY_REQUEST: u8 = 0x66;
    pub const MODIFY_RESPONSE: u8 = 0x67;
    pub const ADD_REQUEST: u8 = 0x68;
    pub const ADD_RESPONSE: u8 = 0x69;
    pub const DEL_REQUEST: u8 = 0x4a;
    pub const DEL_RESPONSE: u8 = 0x6b;
    pub const MODDN_REQUEST: u8 = 0x6c;
    pub const MODDN_RESPONSE: u8 = 0x6d;
    pub const COMPARE_REQUEST: u8 = 0x6e;
    pub const COMPARE_RESPONSE: u8 = 0x6f;
    pub const ABANDON_REQUEST: u8 = 0x50;
    pub const EXTENDED_REQUEST: u8 = 0x77;
    pub const EXTENDED_RESPONSE: u8 = 0x78;
    pub const CONTROLS: u8 = 0xa0;
    pub const AUTH_SIMPLE: u8 = 0x80;
    pub const AUTH_SASL: u8 = 0xa3;
    pub const EXT_REQUEST_NAME: u8 = 0x80;
    pub const EXT_REQUEST_VALUE: u8 = 0x81;
    pub const EXT_RESPONSE_NAME: u8 = 0x8a;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    AuthMethodNotSupported = 7,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    NoSuchObject = 32,
    InvalidDnSyntax = 34,
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    Other = 80,
}

impl ResultCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::OperationsError => "operations_error",
            Self::ProtocolError => "protocol_error",
            Self::TimeLimitExceeded => "time_limit_exceeded",
            Self::SizeLimitExceeded => "size_limit_exceeded",
            Self::AuthMethodNotSupported => "auth_method_not_supported",
            Self::UnavailableCriticalExtension => "unavailable_critical_extension",
            Self::ConfidentialityRequired => "confidentiality_required",
            Self::NoSuchObject => "no_such_object",
            Self::InvalidDnSyntax => "invalid_dn_syntax",
            Self::InappropriateAuthentication => "inappropriate_authentication",
            Self::InvalidCredentials => "invalid_credentials",
            Self::InsufficientAccessRights => "insufficient_access_rights",
            Self::Busy => "busy",
            Self::Unavailable => "unavailable",
            Self::UnwillingToPerform => "unwilling_to_perform",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base,
    One,
    Sub,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::One => "one",
            Self::Sub => "sub",
        }
    }
}

/// Never printed: `Debug` hides the secret.
pub enum BindAuth {
    Simple(Zeroizing<Vec<u8>>),
    Sasl {
        mechanism: String,
        credentials: Option<Zeroizing<Vec<u8>>>,
    },
    /// Reserved or unknown choice (RFC 4511 §4.2).
    Unsupported,
}

impl std::fmt::Debug for BindAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Simple(_) => f.write_str("Simple(..)"),
            Self::Sasl { mechanism, .. } => write!(f, "Sasl({mechanism})"),
            Self::Unsupported => f.write_str("Unsupported"),
        }
    }
}

#[derive(Debug)]
pub struct BindRequest {
    pub version: i32,
    pub name: String,
    pub auth: BindAuth,
}

#[derive(Debug, Clone)]
pub struct SearchRequest {
    pub base: String,
    pub scope: Scope,
    pub size_limit: i32,
    pub time_limit: i32,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOp {
    Modify,
    Add,
    Delete,
    ModifyDn,
    Compare,
}

impl WriteOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Modify => "modify",
            Self::Add => "add",
            Self::Delete => "delete",
            Self::ModifyDn => "modify_dn",
            Self::Compare => "compare",
        }
    }

    pub fn response_tag(self) -> u8 {
        match self {
            Self::Modify => tag::MODIFY_RESPONSE,
            Self::Add => tag::ADD_RESPONSE,
            Self::Delete => tag::DEL_RESPONSE,
            Self::ModifyDn => tag::MODDN_RESPONSE,
            Self::Compare => tag::COMPARE_RESPONSE,
        }
    }
}

#[derive(Debug)]
pub enum Op {
    Bind(BindRequest),
    Unbind,
    Search(SearchRequest),
    /// Refused without reading the body.
    Write(WriteOp),
    Abandon,
    Extended {
        oid: String,
    },
}

impl Op {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Bind(_) => "bind",
            Self::Unbind => "unbind",
            Self::Search(_) => "search",
            Self::Write(w) => w.as_str(),
            Self::Abandon => "abandon",
            Self::Extended { .. } => "extended",
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub id: i32,
    pub op: Op,
    /// Controls marked critical, by OID. None is supported, so any is a
    /// refusal (RFC 4511 §4.1.11); non-critical controls are ignored.
    pub critical_controls: Vec<String>,
}

/// Why a PDU was not understood; `id` when the message id was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    pub id: Option<i32>,
    pub error: BerError,
}

fn oid(content: &[u8]) -> Result<String, BerError> {
    let s = ber::utf8(content, MAX_OID_OCTETS)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(BerError::BadString);
    }
    Ok(s.to_string())
}

fn bounded_secret(content: &[u8]) -> Result<Zeroizing<Vec<u8>>, BerError> {
    if content.len() > MAX_CREDENTIAL_OCTETS {
        return Err(BerError::TooLarge);
    }
    Ok(Zeroizing::new(content.to_vec()))
}

fn decode_bind(content: &[u8]) -> Result<BindRequest, BerError> {
    let mut r = Reader::new(content);
    let version = ber::int(r.expect(tag::INTEGER)?)?;
    let version = i32::try_from(version).map_err(|_| BerError::BadInteger)?;
    let name = ber::utf8(r.expect(tag::OCTET_STRING)?, MAX_DN_OCTETS)?.to_string();
    let (t, c) = r.any()?;
    let auth = match t {
        tag::AUTH_SIMPLE => BindAuth::Simple(bounded_secret(c)?),
        tag::AUTH_SASL => {
            let mut s = Reader::new(c);
            let mechanism = ber::utf8(s.expect(tag::OCTET_STRING)?, MAX_MECHANISM_OCTETS)?.to_string();
            let credentials = s.optional(tag::OCTET_STRING)?.map(bounded_secret).transpose()?;
            s.finish()?;
            BindAuth::Sasl { mechanism, credentials }
        }
        _ => BindAuth::Unsupported,
    };
    r.finish()?;
    Ok(BindRequest { version, name, auth })
}

fn decode_search(content: &[u8]) -> Result<SearchRequest, BerError> {
    let mut r = Reader::new(content);
    let base = ber::utf8(r.expect(tag::OCTET_STRING)?, MAX_DN_OCTETS)?.to_string();
    let scope = match ber::int(r.expect(tag::ENUMERATED)?)? {
        0 => Scope::Base,
        1 => Scope::One,
        2 => Scope::Sub,
        _ => return Err(BerError::BadInteger),
    };
    if !(0..=3).contains(&ber::int(r.expect(tag::ENUMERATED)?)?) {
        return Err(BerError::BadInteger);
    }
    let size_limit = ber::uint31(r.expect(tag::INTEGER)?)?;
    let time_limit = ber::uint31(r.expect(tag::INTEGER)?)?;
    let types_only = ber::boolean(r.expect(tag::BOOLEAN)?)?;
    let (ft, fc) = r.any()?;
    let filter = Filter::decode(ft, fc)?;
    let mut list = Reader::new(r.expect(tag::SEQUENCE)?);
    let mut attributes = Vec::new();
    while !list.is_empty() {
        if attributes.len() == MAX_REQUESTED_ATTRIBUTES {
            return Err(BerError::TooMany);
        }
        attributes.push(ber::utf8(list.expect(tag::OCTET_STRING)?, MAX_ATTRIBUTE_OCTETS)?.to_string());
    }
    r.finish()?;
    Ok(SearchRequest { base, scope, size_limit, time_limit, types_only, filter, attributes })
}

fn decode_controls(content: &[u8]) -> Result<Vec<String>, BerError> {
    let mut r = Reader::new(content);
    let (mut count, mut critical) = (0, Vec::new());
    while !r.is_empty() {
        count += 1;
        if count > MAX_CONTROLS {
            return Err(BerError::TooMany);
        }
        let mut c = Reader::new(r.expect(tag::SEQUENCE)?);
        let control = oid(c.expect(tag::OCTET_STRING)?)?;
        let is_critical = c.optional(tag::BOOLEAN)?.map(ber::boolean).transpose()?.unwrap_or(false);
        let _value = c.optional(tag::OCTET_STRING)?;
        c.finish()?;
        if is_critical {
            critical.push(control);
        }
    }
    Ok(critical)
}

/// Decode one whole LDAPMessage PDU.
pub fn decode_message(pdu: &[u8]) -> Result<Message, DecodeError> {
    let err = |id, error| DecodeError { id, error };
    let mut outer = Reader::new(pdu);
    let body = outer.expect(tag::SEQUENCE).map_err(|e| err(None, e))?;
    outer.finish().map_err(|e| err(None, e))?;
    let mut r = Reader::new(body);
    let id = r.expect(tag::INTEGER).and_then(ber::uint31).map_err(|e| err(None, e))?;
    let at = |e| err(Some(id), e);
    if id == 0 {
        // Message id 0 is reserved for unsolicited notifications.
        return Err(at(BerError::BadInteger));
    }
    let (t, content) = r.any().map_err(at)?;
    let op = match t {
        tag::BIND_REQUEST => Op::Bind(decode_bind(content).map_err(at)?),
        tag::UNBIND_REQUEST => {
            if !content.is_empty() {
                return Err(at(BerError::TrailingData));
            }
            Op::Unbind
        }
        tag::SEARCH_REQUEST => Op::Search(decode_search(content).map_err(at)?),
        tag::MODIFY_REQUEST => Op::Write(WriteOp::Modify),
        tag::ADD_REQUEST => Op::Write(WriteOp::Add),
        tag::DEL_REQUEST => Op::Write(WriteOp::Delete),
        tag::MODDN_REQUEST => Op::Write(WriteOp::ModifyDn),
        tag::COMPARE_REQUEST => Op::Write(WriteOp::Compare),
        tag::ABANDON_REQUEST => {
            ber::uint31(content).map_err(at)?;
            Op::Abandon
        }
        tag::EXTENDED_REQUEST => {
            let mut x = Reader::new(content);
            let name = oid(x.expect(tag::EXT_REQUEST_NAME).map_err(at)?).map_err(at)?;
            let _value = x.optional(tag::EXT_REQUEST_VALUE).map_err(at)?;
            x.finish().map_err(at)?;
            Op::Extended { oid: name }
        }
        _ => return Err(at(BerError::UnexpectedTag)),
    };
    let critical_controls = match r.optional(tag::CONTROLS).map_err(at)? {
        Some(c) => decode_controls(c).map_err(at)?,
        None => Vec::new(),
    };
    r.finish().map_err(at)?;
    Ok(Message { id, op, critical_controls })
}

// ─── Responses ──────────────────────────────────────────────────────

fn ldap_result(out: &mut Vec<u8>, code: ResultCode, matched: &str, message: &str) {
    ber::put_int(out, tag::ENUMERATED, code as i64);
    ber::put(out, tag::OCTET_STRING, matched.as_bytes());
    ber::put(out, tag::OCTET_STRING, message.as_bytes());
}

fn envelope(id: i32, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    ber::nest(&mut out, tag::SEQUENCE, |m| {
        ber::put_int(m, tag::INTEGER, i64::from(id));
        f(m);
    });
    out
}

/// Any response whose body is a bare LDAPResult (bind, search done, the
/// write operations).
pub fn result(id: i32, op_tag: u8, code: ResultCode, matched: &str, message: &str) -> Vec<u8> {
    envelope(id, |m| ber::nest(m, op_tag, |r| ldap_result(r, code, matched, message)))
}

pub fn extended_response(id: i32, code: ResultCode, message: &str, name: Option<&str>) -> Vec<u8> {
    envelope(id, |m| {
        ber::nest(m, tag::EXTENDED_RESPONSE, |r| {
            ldap_result(r, code, "", message);
            if let Some(name) = name {
                ber::put(r, tag::EXT_RESPONSE_NAME, name.as_bytes());
            }
        })
    })
}

/// The unsolicited notice sent before the server closes a connection it
/// cannot continue (RFC 4511 §4.4.1).
pub fn notice_of_disconnection(code: ResultCode, message: &str) -> Vec<u8> {
    extended_response(0, code, message, Some(OID_NOTICE_OF_DISCONNECTION))
}

pub fn search_entry(id: i32, dn: &str, attrs: &[(&str, &[String])], types_only: bool) -> Vec<u8> {
    envelope(id, |m| {
        ber::nest(m, tag::SEARCH_RESULT_ENTRY, |e| {
            ber::put(e, tag::OCTET_STRING, dn.as_bytes());
            ber::nest(e, tag::SEQUENCE, |list| {
                for (name, values) in attrs {
                    ber::nest(list, tag::SEQUENCE, |a| {
                        ber::put(a, tag::OCTET_STRING, name.as_bytes());
                        ber::nest(a, tag::SET, |set| {
                            if !types_only {
                                for v in *values {
                                    ber::put(set, tag::OCTET_STRING, v.as_bytes());
                                }
                            }
                        });
                    });
                }
            });
        })
    })
}

/// The response refusing `op` with `code`; `None` for operations that have
/// no response (unbind, abandon).
pub fn refusal(id: i32, op: &Op, code: ResultCode, message: &str) -> Option<Vec<u8>> {
    match op {
        Op::Bind(_) => Some(result(id, tag::BIND_RESPONSE, code, "", message)),
        Op::Search(_) => Some(result(id, tag::SEARCH_RESULT_DONE, code, "", message)),
        Op::Write(w) => Some(result(id, w.response_tag(), code, "", message)),
        Op::Extended { .. } => Some(extended_response(id, code, message, None)),
        Op::Unbind | Op::Abandon => None,
    }
}

/// The request side, for the tests and the whole-vault test: a minimal
/// LDAP client, independent of the server's decoder only in the sense that
/// it encodes; replies are read with the same [`Reader`].
pub mod client {
    use super::*;

    fn message(id: i32, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        envelope(id, f)
    }

    pub fn bind_simple(id: i32, dn: &str, password: &str) -> Vec<u8> {
        message(id, |m| {
            ber::nest(m, tag::BIND_REQUEST, |b| {
                ber::put_int(b, tag::INTEGER, 3);
                ber::put(b, tag::OCTET_STRING, dn.as_bytes());
                ber::put(b, tag::AUTH_SIMPLE, password.as_bytes());
            })
        })
    }

    pub fn bind_sasl(id: i32, mechanism: &str, credentials: Option<&[u8]>) -> Vec<u8> {
        message(id, |m| {
            ber::nest(m, tag::BIND_REQUEST, |b| {
                ber::put_int(b, tag::INTEGER, 3);
                ber::put(b, tag::OCTET_STRING, b"");
                ber::nest(b, tag::AUTH_SASL, |s| {
                    ber::put(s, tag::OCTET_STRING, mechanism.as_bytes());
                    if let Some(c) = credentials {
                        ber::put(s, tag::OCTET_STRING, c);
                    }
                });
            })
        })
    }

    pub fn search(id: i32, base: &str, scope: Scope, size_limit: i32, filter: &Filter, attrs: &[&str]) -> Vec<u8> {
        message(id, |m| {
            ber::nest(m, tag::SEARCH_REQUEST, |s| {
                ber::put(s, tag::OCTET_STRING, base.as_bytes());
                ber::put_int(s, tag::ENUMERATED, scope as i64);
                ber::put_int(s, tag::ENUMERATED, 0);
                ber::put_int(s, tag::INTEGER, i64::from(size_limit));
                ber::put_int(s, tag::INTEGER, 0);
                ber::put_bool(s, tag::BOOLEAN, false);
                filter.encode(s);
                ber::nest(s, tag::SEQUENCE, |l| {
                    attrs.iter().for_each(|a| ber::put(l, tag::OCTET_STRING, a.as_bytes()))
                });
            })
        })
    }

    pub fn unbind(id: i32) -> Vec<u8> {
        message(id, |m| ber::put(m, tag::UNBIND_REQUEST, b""))
    }

    pub fn start_tls(id: i32) -> Vec<u8> {
        message(id, |m| {
            ber::nest(m, tag::EXTENDED_REQUEST, |x| ber::put(x, tag::EXT_REQUEST_NAME, OID_STARTTLS.as_bytes()))
        })
    }

    /// A write request with a plausible body; the server never reads it.
    pub fn write(id: i32, op: WriteOp, dn: &str) -> Vec<u8> {
        message(id, |m| match op {
            WriteOp::Delete => ber::put(m, tag::DEL_REQUEST, dn.as_bytes()),
            other => {
                let t = match other {
                    WriteOp::Modify => tag::MODIFY_REQUEST,
                    WriteOp::Add => tag::ADD_REQUEST,
                    WriteOp::ModifyDn => tag::MODDN_REQUEST,
                    _ => tag::COMPARE_REQUEST,
                };
                ber::nest(m, t, |b| {
                    ber::put(b, tag::OCTET_STRING, dn.as_bytes());
                    ber::nest(b, tag::SEQUENCE, |_| {});
                });
            }
        })
    }

    /// One reply, flattened.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Reply {
        pub id: i32,
        pub tag: u8,
        /// The result code, for every reply but an entry.
        pub code: Option<i64>,
        /// The entry DN, or the result's matched DN.
        pub dn: String,
        pub message: String,
        pub attrs: Vec<(String, Vec<String>)>,
        pub response_name: Option<String>,
    }

    impl Reply {
        pub fn values(&self, name: &str) -> Vec<&str> {
            self.attrs
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .flat_map(|(_, v)| v.iter().map(String::as_str))
                .collect()
        }
    }

    fn text(c: &[u8]) -> Result<String, BerError> {
        Ok(ber::utf8(c, ber::MAX_PDU_LEN)?.to_string())
    }

    pub fn read_reply(pdu: &[u8]) -> Result<Reply, BerError> {
        let mut outer = Reader::new(pdu);
        let mut r = Reader::new(outer.expect(tag::SEQUENCE)?);
        outer.finish()?;
        let id = ber::uint31(r.expect(tag::INTEGER)?)?;
        let (t, body) = r.any()?;
        let mut b = Reader::new(body);
        let mut reply = Reply {
            id,
            tag: t,
            code: None,
            dn: String::new(),
            message: String::new(),
            attrs: vec![],
            response_name: None,
        };
        if t == tag::SEARCH_RESULT_ENTRY {
            reply.dn = text(b.expect(tag::OCTET_STRING)?)?;
            let mut list = Reader::new(b.expect(tag::SEQUENCE)?);
            while !list.is_empty() {
                let mut a = Reader::new(list.expect(tag::SEQUENCE)?);
                let name = text(a.expect(tag::OCTET_STRING)?)?;
                let mut set = Reader::new(a.expect(tag::SET)?);
                let mut values = Vec::new();
                while !set.is_empty() {
                    values.push(text(set.expect(tag::OCTET_STRING)?)?);
                }
                reply.attrs.push((name, values));
            }
            return Ok(reply);
        }
        reply.code = Some(ber::int(b.expect(tag::ENUMERATED)?)?);
        reply.dn = text(b.expect(tag::OCTET_STRING)?)?;
        reply.message = text(b.expect(tag::OCTET_STRING)?)?;
        if let Some(name) = b.optional(tag::EXT_RESPONSE_NAME)? {
            reply.response_name = Some(text(name)?);
        }
        Ok(reply)
    }
}
