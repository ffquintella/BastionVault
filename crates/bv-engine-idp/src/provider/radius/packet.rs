//! RADIUS packet codec (RFC 2865 §3, §5; RFC 3579 §3.2). Parsing is
//! bounded (packet length, attribute count) and structural only; the
//! provider decides what a well-formed packet means. MD5 and HMAC-MD5 are
//! the protocol's own constructions, computed with RustCrypto's `md-5` and
//! `hmac`; the Message-Authenticator check is constant-time.

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use zeroize::{Zeroize, Zeroizing};

pub const HEADER_LEN: usize = 20;
pub const MIN_PACKET_LEN: usize = HEADER_LEN;
/// RFC 2865 §3: the largest packet either side may send.
pub const MAX_PACKET_LEN: usize = 4096;
/// More attributes than any Access-Request this provider answers needs.
pub const MAX_ATTRIBUTES: usize = 128;
pub const AUTHENTICATOR_LEN: usize = 16;
/// RFC 2865 §5.2: User-Password is 16 to 128 octets, a multiple of 16.
pub const MAX_PASSWORD_LEN: usize = 128;
/// The longest value one attribute can carry.
pub const MAX_ATTRIBUTE_VALUE_LEN: usize = 253;
/// A string VSA's value: 253 minus the vendor id and sub-attribute header.
pub const MAX_VSA_VALUE_LEN: usize = 247;
const MESSAGE_AUTHENTICATOR_ATTR_LEN: usize = 2 + AUTHENTICATOR_LEN;

pub mod code {
    pub const ACCESS_REQUEST: u8 = 1;
    pub const ACCESS_ACCEPT: u8 = 2;
    pub const ACCESS_REJECT: u8 = 3;
}

pub mod attr {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const CHAP_PASSWORD: u8 = 3;
    pub const STATE: u8 = 24;
    pub const VENDOR_SPECIFIC: u8 = 26;
    pub const EAP_MESSAGE: u8 = 79;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
}

type HmacMd5 = Hmac<Md5>;

/// Why a packet could not be parsed. Every variant is silently discarded
/// (RFC 2865 §3): nothing about it can be trusted enough to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    TooShort,
    TooLong,
    /// The Length field is below the header size or above the bytes received.
    BadLength,
    /// An attribute's length runs past the packet or is below 2, or type 0.
    BadAttribute,
    TooManyAttributes,
    /// A value too long to encode, or a reply over [`MAX_PACKET_LEN`].
    Oversize,
}

impl PacketError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooLong => "too_long",
            Self::BadLength => "bad_length",
            Self::BadAttribute => "bad_attribute",
            Self::TooManyAttributes => "too_many_attributes",
            Self::Oversize => "oversize",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub kind: u8,
    pub value: &'a [u8],
    /// Offset of the type octet within the packet.
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct Packet<'a> {
    pub code: u8,
    pub identifier: u8,
    pub authenticator: [u8; AUTHENTICATOR_LEN],
    pub attributes: Vec<Attribute<'a>>,
    /// Exactly `Length` octets; trailing padding is not part of it.
    pub raw: &'a [u8],
}

/// The length a stream framer must read, from the first four octets.
pub fn frame_len(header: &[u8; 4]) -> Result<usize, PacketError> {
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if len < MIN_PACKET_LEN {
        return Err(PacketError::BadLength);
    }
    if len > MAX_PACKET_LEN {
        return Err(PacketError::TooLong);
    }
    Ok(len)
}

/// Parse one packet. Octets after `Length` are padding and ignored (RFC 2865
/// §3); fewer octets than `Length` is an error.
pub fn parse(buf: &[u8]) -> Result<Packet<'_>, PacketError> {
    if buf.len() < MIN_PACKET_LEN {
        return Err(PacketError::TooShort);
    }
    if buf.len() > MAX_PACKET_LEN {
        return Err(PacketError::TooLong);
    }
    let len = frame_len(&[buf[0], buf[1], buf[2], buf[3]])?;
    if len > buf.len() {
        return Err(PacketError::BadLength);
    }
    let raw = &buf[..len];
    let mut authenticator = [0u8; AUTHENTICATOR_LEN];
    authenticator.copy_from_slice(&raw[4..HEADER_LEN]);
    let mut attributes = Vec::new();
    let mut at = HEADER_LEN;
    while at < len {
        if len - at < 2 {
            return Err(PacketError::BadAttribute);
        }
        let (kind, attr_len) = (raw[at], usize::from(raw[at + 1]));
        if kind == 0 || attr_len < 2 || at + attr_len > len {
            return Err(PacketError::BadAttribute);
        }
        if attributes.len() == MAX_ATTRIBUTES {
            return Err(PacketError::TooManyAttributes);
        }
        attributes.push(Attribute { kind, value: &raw[at + 2..at + attr_len], offset: at });
        at += attr_len;
    }
    Ok(Packet { code: raw[0], identifier: raw[1], authenticator, attributes, raw })
}

/// More than one instance of an attribute that may appear at most once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duplicate(pub u8);

impl<'a> Packet<'a> {
    pub fn count(&self, kind: u8) -> usize {
        self.attributes.iter().filter(|a| a.kind == kind).count()
    }

    /// The value of an attribute allowed at most once.
    pub fn single(&self, kind: u8) -> Result<Option<&'a [u8]>, Duplicate> {
        let mut found = None;
        for a in self.attributes.iter().filter(|a| a.kind == kind) {
            if found.is_some() {
                return Err(Duplicate(kind));
            }
            found = Some(a.value);
        }
        Ok(found)
    }
}

/// Outcome of the Message-Authenticator check on a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageAuthCheck {
    Valid,
    Missing,
    Duplicate,
    Malformed,
    Invalid,
}

pub fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&out);
    digest
}

fn hmac_md5(secret: &[u8]) -> HmacMd5 {
    // HMAC accepts a key of any length; this cannot fail.
    <HmacMd5 as KeyInit>::new_from_slice(secret).expect("HMAC takes keys of any length")
}

/// RFC 3579 §3.2: HMAC-MD5 over the packet with the Message-Authenticator
/// value zeroed. Compared in constant time.
pub fn check_message_authenticator(p: &Packet<'_>, secret: &[u8]) -> MessageAuthCheck {
    let found: Vec<&Attribute<'_>> = p.attributes.iter().filter(|a| a.kind == attr::MESSAGE_AUTHENTICATOR).collect();
    let ma = match found.as_slice() {
        [] => return MessageAuthCheck::Missing,
        [one] => *one,
        _ => return MessageAuthCheck::Duplicate,
    };
    if ma.value.len() != AUTHENTICATOR_LEN {
        return MessageAuthCheck::Malformed;
    }
    let mut zeroed = p.raw.to_vec();
    zeroed[ma.offset + 2..ma.offset + 2 + AUTHENTICATOR_LEN].fill(0);
    let mut mac = hmac_md5(secret);
    mac.update(&zeroed);
    match mac.verify_slice(ma.value) {
        Ok(()) => MessageAuthCheck::Valid,
        Err(_) => MessageAuthCheck::Invalid,
    }
}

/// RFC 2865 §5.2, receiving side. Trailing NUL padding is removed.
pub fn unhide_password(
    hidden: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; AUTHENTICATOR_LEN],
) -> Result<Zeroizing<Vec<u8>>, PacketError> {
    if hidden.len() < 16 || hidden.len() > MAX_PASSWORD_LEN || !hidden.len().is_multiple_of(16) {
        return Err(PacketError::BadAttribute);
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(hidden.len()));
    let mut b = Zeroizing::new(md5(&[secret, request_authenticator]));
    for chunk in hidden.chunks(16) {
        plain.extend(chunk.iter().zip(b.iter()).map(|(c, k)| c ^ k));
        *b = md5(&[secret, chunk]);
    }
    while plain.last() == Some(&0) {
        plain.pop();
    }
    Ok(plain)
}

/// RFC 2865 §5.2, sending side (NAS); used by tests and client tooling.
pub fn hide_password(
    password: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; AUTHENTICATOR_LEN],
) -> Result<Vec<u8>, PacketError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(PacketError::Oversize);
    }
    let padded_len = password.len().div_ceil(16).max(1) * 16;
    let mut padded = Zeroizing::new(vec![0u8; padded_len]);
    padded[..password.len()].copy_from_slice(password);
    let mut out = Vec::with_capacity(padded_len);
    let mut b = md5(&[secret, request_authenticator]);
    for chunk in padded.chunks(16) {
        let start = out.len();
        out.extend(chunk.iter().zip(b.iter()).map(|(p, k)| p ^ k));
        b = md5(&[secret, &out[start..]]);
    }
    b.zeroize();
    Ok(out)
}

/// The value of a Vendor-Specific attribute (RFC 2865 §5.26) carrying one
/// string sub-attribute.
pub fn vendor_specific(vendor_id: u32, vendor_type: u8, value: &[u8]) -> Result<Vec<u8>, PacketError> {
    if vendor_id == 0 || vendor_id > 0x00FF_FFFF || value.is_empty() || value.len() > MAX_VSA_VALUE_LEN {
        return Err(PacketError::Oversize);
    }
    let mut v = Vec::with_capacity(6 + value.len());
    v.extend_from_slice(&vendor_id.to_be_bytes());
    v.push(vendor_type);
    v.push(u8::try_from(2 + value.len()).map_err(|_| PacketError::Oversize)?);
    v.extend_from_slice(value);
    Ok(v)
}

fn push_attribute(out: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), PacketError> {
    if value.len() > MAX_ATTRIBUTE_VALUE_LEN {
        return Err(PacketError::Oversize);
    }
    out.push(kind);
    out.push(u8::try_from(2 + value.len()).map_err(|_| PacketError::Oversize)?);
    out.extend_from_slice(value);
    Ok(())
}

/// Header plus a zeroed Message-Authenticator first (the BlastRADIUS
/// mitigation places it first), then `attributes`; Length is filled in.
fn assemble(
    code: u8,
    identifier: u8,
    authenticator: &[u8; AUTHENTICATOR_LEN],
    attributes: &[(u8, Vec<u8>)],
) -> Result<Vec<u8>, PacketError> {
    let mut out = Vec::with_capacity(MIN_PACKET_LEN + MESSAGE_AUTHENTICATOR_ATTR_LEN);
    out.extend_from_slice(&[code, identifier, 0, 0]);
    out.extend_from_slice(authenticator);
    push_attribute(&mut out, attr::MESSAGE_AUTHENTICATOR, &[0u8; AUTHENTICATOR_LEN])?;
    for (kind, value) in attributes {
        if *kind == attr::MESSAGE_AUTHENTICATOR {
            return Err(PacketError::BadAttribute);
        }
        push_attribute(&mut out, *kind, value)?;
    }
    if out.len() > MAX_PACKET_LEN {
        return Err(PacketError::Oversize);
    }
    let len = u16::try_from(out.len()).map_err(|_| PacketError::Oversize)?;
    out[2..4].copy_from_slice(&len.to_be_bytes());
    Ok(out)
}

fn sign_message_authenticator(packet: &mut [u8], secret: &[u8]) {
    let mut mac = hmac_md5(secret);
    mac.update(packet);
    let tag = mac.finalize().into_bytes();
    let at = HEADER_LEN + 2;
    packet[at..at + AUTHENTICATOR_LEN].copy_from_slice(&tag);
}

/// An Access-Accept or Access-Reject answering a request with
/// `request_authenticator`: Message-Authenticator first, then the Response
/// Authenticator over the finished packet (RFC 2865 §3, RFC 3579 §3.2).
pub fn encode_response(
    code: u8,
    identifier: u8,
    request_authenticator: &[u8; AUTHENTICATOR_LEN],
    attributes: &[(u8, Vec<u8>)],
    secret: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let mut out = assemble(code, identifier, request_authenticator, attributes)?;
    sign_message_authenticator(&mut out, secret);
    let response_authenticator = md5(&[&out, secret]);
    out[4..HEADER_LEN].copy_from_slice(&response_authenticator);
    Ok(out)
}

/// An Access-Request as a NAS sends it, with a Message-Authenticator; for
/// tests and client tooling.
pub fn encode_request(
    identifier: u8,
    request_authenticator: &[u8; AUTHENTICATOR_LEN],
    attributes: &[(u8, Vec<u8>)],
    secret: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let mut out = assemble(code::ACCESS_REQUEST, identifier, request_authenticator, attributes)?;
    sign_message_authenticator(&mut out, secret);
    Ok(out)
}

/// A NAS's check of a reply: Response Authenticator and
/// Message-Authenticator, both against the request it sent.
pub fn verify_response(reply: &[u8], request_authenticator: &[u8; AUTHENTICATOR_LEN], secret: &[u8]) -> bool {
    let Ok(p) = parse(reply) else {
        return false;
    };
    let mut with_request_auth = p.raw.to_vec();
    with_request_auth[4..HEADER_LEN].copy_from_slice(request_authenticator);
    let expected = md5(&[&with_request_auth, secret]);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(p.authenticator.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return false;
    }
    let Ok(as_signed) = parse(&with_request_auth) else {
        return false;
    };
    check_message_authenticator(&as_signed, secret) == MessageAuthCheck::Valid
}
