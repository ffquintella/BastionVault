//! Bounds-checked reading and writing of TLS wire structures. Every read
//! failure is a `decode_error` naming the structure being parsed.

use crate::error::{alert, TlsError};

pub(crate) fn decode_error(what: &'static str) -> TlsError {
    TlsError::PeerMisbehaved { alert: alert::DECODE_ERROR, what }
}

/// A cursor over a received structure.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or_else(|| decode_error(self.what))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u24(&mut self) -> Result<usize, TlsError> {
        let b = self.bytes(3)?;
        Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }

    /// `opaque x<0..2^8-1>`.
    pub(crate) fn vec_u8(&mut self) -> Result<&'a [u8], TlsError> {
        let n = usize::from(self.u8()?);
        self.bytes(n)
    }

    /// `opaque x<0..2^16-1>`.
    pub(crate) fn vec_u16(&mut self) -> Result<&'a [u8], TlsError> {
        let n = usize::from(self.u16()?);
        self.bytes(n)
    }

    /// `opaque x<0..2^24-1>`.
    pub(crate) fn vec_u24(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u24()?;
        self.bytes(n)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Fails if anything is left: trailing bytes are a decode error.
    pub(crate) fn finish(&self) -> Result<(), TlsError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(decode_error(self.what))
        }
    }
}

/// Append `data` with a 1-byte length prefix.
pub(crate) fn put_vec_u8(out: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= 0xff);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// Append `data` with a 2-byte length prefix.
pub(crate) fn put_vec_u16(out: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= 0xffff);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Append `data` with a 3-byte length prefix.
pub(crate) fn put_vec_u24(out: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= 0xff_ffff);
    let n = data.len();
    out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    out.extend_from_slice(data);
}

/// A handshake message: `type(1) || length(3) || body`.
pub(crate) fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    put_vec_u24(&mut out, body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let mut r = Reader::new(&[0x00, 0x03, 1, 2], "test structure");
        assert!(r.vec_u16().is_err(), "length 3 with 2 bytes left");
        let mut r = Reader::new(&[0x02, 9, 9, 7], "test structure");
        assert_eq!(r.vec_u8().unwrap(), &[9, 9]);
        assert!(r.finish().is_err(), "a trailing byte is left");
        assert_eq!(r.u8().unwrap(), 7);
        r.finish().unwrap();
        assert!(r.u8().is_err());
        let e = Reader::new(&[0xff], "ServerHello").u16().unwrap_err();
        assert!(e.to_string().contains("ServerHello"), "{e}");
    }

    #[test]
    fn writers_round_trip() {
        let mut out = Vec::new();
        put_vec_u8(&mut out, b"ab");
        put_vec_u16(&mut out, b"cde");
        put_vec_u24(&mut out, b"f");
        let mut r = Reader::new(&out, "t");
        assert_eq!(r.vec_u8().unwrap(), b"ab");
        assert_eq!(r.vec_u16().unwrap(), b"cde");
        assert_eq!(r.vec_u24().unwrap(), b"f");
        r.finish().unwrap();
        assert_eq!(handshake_message(20, &[1, 2]), vec![20, 0, 0, 2, 1, 2]);
    }
}
