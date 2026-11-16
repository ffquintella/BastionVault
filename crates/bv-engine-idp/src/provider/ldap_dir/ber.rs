//! The BER subset LDAPv3 uses (RFC 4511 §5.1): definite lengths only,
//! single-octet tags, primitive strings, integers of at most four octets.
//! Hand-written because the codec already in the dependency graph (`lber`,
//! ldap3's) recurses without a depth bound and reads an indefinite length
//! as zero. Nothing here recurses; filters bound their own depth.

/// Largest PDU the directory reads or a nested element may claim.
pub const MAX_PDU_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    Truncated,
    IndefiniteLength,
    LengthTooLong,
    TooLarge,
    HighTagNumber,
    UnexpectedTag,
    BadInteger,
    BadBoolean,
    BadString,
    TrailingData,
    TooDeep,
    TooMany,
}

impl BerError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::IndefiniteLength => "indefinite_length",
            Self::LengthTooLong => "length_too_long",
            Self::TooLarge => "too_large",
            Self::HighTagNumber => "high_tag_number",
            Self::UnexpectedTag => "unexpected_tag",
            Self::BadInteger => "bad_integer",
            Self::BadBoolean => "bad_boolean",
            Self::BadString => "bad_string",
            Self::TrailingData => "trailing_data",
            Self::TooDeep => "too_deep",
            Self::TooMany => "too_many",
        }
    }
}

/// The length octets at the start of `buf`: `(length, octets used)`.
pub fn length(buf: &[u8]) -> Result<(usize, usize), BerError> {
    let first = *buf.first().ok_or(BerError::Truncated)?;
    match first {
        0..=0x7f => Ok((usize::from(first), 1)),
        0x80 => Err(BerError::IndefiniteLength),
        0x81..=0x84 => {
            let n = usize::from(first & 0x7f);
            let octets = buf.get(1..=n).ok_or(BerError::Truncated)?;
            let len = octets.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            if len > MAX_PDU_LEN as u64 {
                return Err(BerError::TooLarge);
            }
            Ok((len as usize, 1 + n))
        }
        _ => Err(BerError::LengthTooLong),
    }
}

/// Total size of the PDU whose first octets are `head`, or `None` while
/// more octets are needed to tell. Refuses before the body is read.
pub fn pdu_len(head: &[u8]) -> Result<Option<usize>, BerError> {
    let Some(&tag) = head.first() else {
        return Ok(None);
    };
    if tag & 0x1f == 0x1f {
        return Err(BerError::HighTagNumber);
    }
    let Some(&first) = head.get(1) else {
        return Ok(None);
    };
    let need = match first {
        0..=0x7f => 1,
        0x80 => return Err(BerError::IndefiniteLength),
        0x81..=0x84 => 1 + usize::from(first & 0x7f),
        _ => return Err(BerError::LengthTooLong),
    };
    if head.len() < 1 + need {
        return Ok(None);
    }
    let (len, used) = length(&head[1..])?;
    let total = 1 + used + len;
    if total > MAX_PDU_LEN {
        return Err(BerError::TooLarge);
    }
    Ok(Some(total))
}

/// Reads one TLV at a time from a slice.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// The next element: `(tag, content)`.
    pub fn any(&mut self) -> Result<(u8, &'a [u8]), BerError> {
        let (&tag, rest) = self.buf.split_first().ok_or(BerError::Truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(BerError::HighTagNumber);
        }
        let (len, used) = length(rest)?;
        let rest = &rest[used..];
        if len > rest.len() {
            return Err(BerError::Truncated);
        }
        let (content, tail) = rest.split_at(len);
        self.buf = tail;
        Ok((tag, content))
    }

    /// The next element, which must carry `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], BerError> {
        match self.peek_tag() {
            None => Err(BerError::Truncated),
            Some(t) if t != tag => Err(BerError::UnexpectedTag),
            Some(_) => Ok(self.any()?.1),
        }
    }

    /// The next element if it carries `tag`.
    pub fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, BerError> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.any()?.1))
        } else {
            Ok(None)
        }
    }

    pub fn finish(&self) -> Result<(), BerError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(BerError::TrailingData)
        }
    }
}

/// An INTEGER or ENUMERATED of one to four octets (two's complement).
pub fn int(content: &[u8]) -> Result<i64, BerError> {
    if content.is_empty() || content.len() > 4 {
        return Err(BerError::BadInteger);
    }
    let start: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    Ok(content.iter().fold(start, |acc, b| (acc << 8) | i64::from(*b)))
}

/// A non-negative INTEGER that fits an `i32` (message ids, limits).
pub fn uint31(content: &[u8]) -> Result<i32, BerError> {
    i32::try_from(int(content)?).ok().filter(|v| *v >= 0).ok_or(BerError::BadInteger)
}

pub fn boolean(content: &[u8]) -> Result<bool, BerError> {
    match content {
        [b] => Ok(*b != 0),
        _ => Err(BerError::BadBoolean),
    }
}

/// A UTF-8 string of at most `max` octets.
pub fn utf8(content: &[u8], max: usize) -> Result<&str, BerError> {
    if content.len() > max {
        return Err(BerError::TooLarge);
    }
    std::str::from_utf8(content).map_err(|_| BerError::BadString)
}

// ─── Writer ─────────────────────────────────────────────────────────

pub fn put_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    // Responses are far below 4 GiB; saturate rather than wrap.
    let bytes = u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    out.push(0x80 | (4 - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

pub fn put(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    put_len(out, content.len());
    out.extend_from_slice(content);
}

/// Minimal two's-complement encoding.
pub fn put_int(out: &mut Vec<u8>, tag: u8, v: i64) {
    let b = v.to_be_bytes();
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    put(out, tag, &b[i..]);
}

pub fn put_bool(out: &mut Vec<u8>, tag: u8, v: bool) {
    put(out, tag, &[if v { 0xff } else { 0 }]);
}

/// A constructed element whose content `f` writes.
pub fn nest(out: &mut Vec<u8>, tag: u8, f: impl FnOnce(&mut Vec<u8>)) {
    let mut inner = Vec::new();
    f(&mut inner);
    put(out, tag, &inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_minimally() {
        for v in [0i64, 1, 127, 128, 255, 256, -1, -128, -129, 65535, i32::MAX as i64, i32::MIN as i64] {
            let mut out = Vec::new();
            put_int(&mut out, 0x02, v);
            let mut r = Reader::new(&out);
            let content = r.expect(0x02).unwrap();
            r.finish().unwrap();
            assert_eq!(int(content).unwrap(), v, "{v}");
            assert!(content.len() <= 4);
        }
        let mut out = Vec::new();
        put_int(&mut out, 0x02, 128);
        assert_eq!(out, [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(int(&[]), Err(BerError::BadInteger));
        assert_eq!(int(&[1, 2, 3, 4, 5]), Err(BerError::BadInteger));
        assert_eq!(uint31(&[0xff]), Err(BerError::BadInteger), "negative");
        assert_eq!(uint31(&[0x00, 0x80, 0, 0]), Ok(0x0080_0000));
    }

    #[test]
    fn lengths_short_long_and_refused() {
        for len in [0usize, 1, 127, 128, 255, 256, 4096, MAX_PDU_LEN] {
            let mut out = Vec::new();
            put_len(&mut out, len);
            assert_eq!(length(&out), Ok((len, out.len())), "{len}");
        }
        assert_eq!(length(&[0x80]), Err(BerError::IndefiniteLength));
        assert_eq!(length(&[0x85, 0, 0, 0, 0, 1]), Err(BerError::LengthTooLong));
        assert_eq!(length(&[0xff]), Err(BerError::LengthTooLong));
        assert_eq!(length(&[0x84, 0xff, 0xff, 0xff, 0xff]), Err(BerError::TooLarge));
        assert_eq!(length(&[0x82, 0x01]), Err(BerError::Truncated));
        assert_eq!(length(&[]), Err(BerError::Truncated));
        // Non-minimal long form is BER-legal and accepted.
        assert_eq!(length(&[0x82, 0x00, 0x05]), Ok((5, 3)));
    }

    #[test]
    fn pdu_len_needs_only_the_header() {
        assert_eq!(pdu_len(&[]), Ok(None));
        assert_eq!(pdu_len(&[0x30]), Ok(None));
        assert_eq!(pdu_len(&[0x30, 0x05]), Ok(Some(7)));
        assert_eq!(pdu_len(&[0x30, 0x82, 0x01]), Ok(None));
        assert_eq!(pdu_len(&[0x30, 0x82, 0x01, 0x00]), Ok(Some(260)));
        assert_eq!(pdu_len(&[0x30, 0x80]), Err(BerError::IndefiniteLength));
        assert_eq!(pdu_len(&[0x3f, 0x01]), Err(BerError::HighTagNumber));
        assert_eq!(pdu_len(&[0x30, 0x83, 0x01, 0x00, 0x00]), Err(BerError::TooLarge));
        assert_eq!(pdu_len(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]), Err(BerError::TooLarge));
    }

    #[test]
    fn reader_refuses_what_lies_beyond_its_slice() {
        assert_eq!(Reader::new(&[0x04, 0x05, b'a']).any(), Err(BerError::Truncated));
        assert_eq!(Reader::new(&[0x1f, 0x01, 0x00]).any(), Err(BerError::HighTagNumber));
        assert_eq!(Reader::new(&[0x04, 0x01, b'a']).expect(0x02), Err(BerError::UnexpectedTag));
        let mut r = Reader::new(&[0x04, 0x01, b'a', 0x05, 0x00]);
        assert_eq!(r.expect(0x04), Ok(&b"a"[..]));
        assert_eq!(r.finish(), Err(BerError::TrailingData));
        assert_eq!(boolean(&[]), Err(BerError::BadBoolean));
        assert_eq!(boolean(&[0, 0]), Err(BerError::BadBoolean));
        assert_eq!(boolean(&[0x01]), Ok(true));
        assert_eq!(utf8(&[0xff], 10), Err(BerError::BadString));
        assert_eq!(utf8(b"abc", 2), Err(BerError::TooLarge));
    }
}
