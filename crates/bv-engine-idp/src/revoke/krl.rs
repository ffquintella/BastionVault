//! OpenSSH KRL encoder (OpenSSH `PROTOCOL.krl`): a header plus one
//! certificate section per CA, each holding a serial list. Unsigned: sshd
//! does not check KRL signatures, and the deny feed carries the same serials
//! under a signature. This is serialization only; no cryptography.

use std::collections::{BTreeMap, BTreeSet};

use ssh_key::PublicKey;

use crate::errors::RvError;

const KRL_MAGIC: u64 = 0x5353_484b_524c_0a00; // "SSHKRL\n\0"
const KRL_FORMAT_VERSION: u32 = 1;
const KRL_SECTION_CERTIFICATES: u8 = 1;
const KRL_SECTION_CERT_SERIAL_LIST: u8 = 0x20;

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RvError> {
    let len = u32::try_from(bytes.len()).map_err(|_| bv_errors::bv_error_string!("KRL field exceeds 4 GiB"))?;
    put_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Build a KRL revoking `serials` per CA (OpenSSH public-key line ->
/// serials). Serial 0 cannot be expressed in a KRL and is refused; a CA
/// with no serial gets no section.
pub fn build_krl(
    krl_version: u64,
    generated_at: u64,
    comment: &str,
    serials: &BTreeMap<String, BTreeSet<u64>>,
) -> Result<Vec<u8>, RvError> {
    let mut out = Vec::new();
    put_u64(&mut out, KRL_MAGIC);
    put_u32(&mut out, KRL_FORMAT_VERSION);
    put_u64(&mut out, krl_version);
    put_u64(&mut out, generated_at);
    put_u64(&mut out, 0); // flags
    put_string(&mut out, b"")?; // reserved
    put_string(&mut out, comment.as_bytes())?;
    for (ca, set) in serials {
        if set.is_empty() {
            continue;
        }
        if set.contains(&0) {
            return Err(bv_errors::bv_error_string!("serial 0 cannot be revoked in a KRL"));
        }
        let ca_key = PublicKey::from_openssh(ca)
            .map_err(|e| bv_errors::bv_error_string!(&format!("recorded CA key does not parse: {e}")))?;
        let ca_blob = ca_key
            .to_bytes()
            .map_err(|e| bv_errors::bv_error_string!(&format!("CA key cannot be wire-encoded: {e}")))?;
        let mut list = Vec::with_capacity(set.len() * 8);
        for serial in set {
            put_u64(&mut list, *serial);
        }
        let mut section = Vec::new();
        put_string(&mut section, &ca_blob)?;
        put_string(&mut section, b"")?; // reserved
        section.push(KRL_SECTION_CERT_SERIAL_LIST);
        put_string(&mut section, &list)?;
        out.push(KRL_SECTION_CERTIFICATES);
        put_string(&mut out, &section)?;
    }
    Ok(out)
}

/// A decoded KRL: version and, per CA wire blob, the revoked serials. For
/// tests and the host helper's self-check; reads only what `build_krl` writes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedKrl {
    pub krl_version: u64,
    pub generated_at: u64,
    pub serials: BTreeMap<Vec<u8>, BTreeSet<u64>>,
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

pub fn parse_krl(bytes: &[u8]) -> Result<ParsedKrl, String> {
    let mut r = Reader { buf: bytes };
    let bad = |what: &str| format!("malformed KRL: {what}");
    if r.u64() != Some(KRL_MAGIC) || r.u32() != Some(KRL_FORMAT_VERSION) {
        return Err(bad("magic or format version"));
    }
    let krl_version = r.u64().ok_or_else(|| bad("version"))?;
    let generated_at = r.u64().ok_or_else(|| bad("date"))?;
    r.u64().ok_or_else(|| bad("flags"))?;
    r.string().ok_or_else(|| bad("reserved"))?;
    r.string().ok_or_else(|| bad("comment"))?;
    let mut serials: BTreeMap<Vec<u8>, BTreeSet<u64>> = BTreeMap::new();
    while !r.buf.is_empty() {
        if r.u8() != Some(KRL_SECTION_CERTIFICATES) {
            return Err(bad("unexpected section type"));
        }
        let mut s = Reader { buf: r.string().ok_or_else(|| bad("section length"))? };
        let ca = s.string().ok_or_else(|| bad("ca key"))?.to_vec();
        s.string().ok_or_else(|| bad("section reserved"))?;
        while !s.buf.is_empty() {
            if s.u8() != Some(KRL_SECTION_CERT_SERIAL_LIST) {
                return Err(bad("unexpected certificate subsection"));
            }
            let mut list = Reader { buf: s.string().ok_or_else(|| bad("serial list"))? };
            if !list.buf.len().is_multiple_of(8) {
                return Err(bad("serial list length"));
            }
            let entry = serials.entry(ca.clone()).or_default();
            while let Some(serial) = list.u64() {
                entry.insert(serial);
            }
        }
    }
    Ok(ParsedKrl { krl_version, generated_at, serials })
}
