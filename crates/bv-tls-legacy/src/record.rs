//! TLS 1.2 record protection for the AES-CBC + HMAC suites (RFC 5246
//! §6.2.3.2): MAC-then-encrypt with an explicit, random per-record IV.
//!
//! [`Decryptor::open`] is the padding-oracle / Lucky13 surface: one error
//! for every length/padding/MAC failure, constant-time padding check over a
//! fixed window, record-length-only hashing work, constant-address MAC
//! extraction. Rationale and residual risk: features/legacy-tls-cbc.md.

use std::hint::black_box;

use aes::{Aes128, Aes256};
use cbc::cipher::{array::Array, consts::U16, BlockModeDecrypt, BlockModeEncrypt, InnerIvInit};
use hmac::{
    digest::{block_api::EagerHash, Digest},
    Hmac, KeyInit, Mac,
};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use zeroize::Zeroizing;

use crate::{
    error::TlsError,
    suite::{CipherSuite, MacAlg},
};

/// `type(1) || version(2) || length(2)`.
pub(crate) const HEADER_LEN: usize = 5;
/// RFC 5246 §6.2.1: a plaintext fragment is at most 2^14 bytes.
pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;
/// RFC 5246 §6.2.3: a ciphertext fragment is at most 2^14 + 2048 bytes.
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 2048;
/// The only protocol version on the wire once ServerHello is in.
pub(crate) const TLS12: u16 = 0x0303;

const BLOCK: usize = 16;
const MAX_MAC: usize = 48;

/// Record content types (RFC 5246 §6.2.1).
pub(crate) mod content {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

/// AES key schedule; both variants zeroize on drop (`aes/zeroize`).
enum AesKey {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl AesKey {
    fn new(key: &[u8]) -> Result<Self, TlsError> {
        let wrong = |_| TlsError::Internal("record key has the wrong length");
        match key.len() {
            16 => Aes128::new_from_slice(key).map(AesKey::Aes128).map_err(wrong),
            32 => Aes256::new_from_slice(key).map(AesKey::Aes256).map_err(wrong),
            _ => Err(TlsError::Internal("record key has the wrong length")),
        }
    }

    /// CBC-decrypt `data` (a whole number of blocks) in place.
    fn cbc_decrypt(&self, iv: &[u8; BLOCK], data: &mut [u8]) {
        let (blocks, rest) = Array::<u8, U16>::slice_as_chunks_mut(data);
        debug_assert!(rest.is_empty(), "caller checks the block alignment");
        let iv = Array::<u8, U16>::from(*iv);
        match self {
            AesKey::Aes128(k) => cbc::Decryptor::<Aes128>::inner_iv_init(k.clone(), &iv).decrypt_blocks(blocks),
            AesKey::Aes256(k) => cbc::Decryptor::<Aes256>::inner_iv_init(k.clone(), &iv).decrypt_blocks(blocks),
        }
    }

    /// CBC-encrypt `data` (a whole number of blocks) in place.
    fn cbc_encrypt(&self, iv: &[u8; BLOCK], data: &mut [u8]) {
        let (blocks, rest) = Array::<u8, U16>::slice_as_chunks_mut(data);
        debug_assert!(rest.is_empty(), "caller pads to the block size");
        let iv = Array::<u8, U16>::from(*iv);
        match self {
            AesKey::Aes128(k) => cbc::Encryptor::<Aes128>::inner_iv_init(k.clone(), &iv).encrypt_blocks(blocks),
            AesKey::Aes256(k) => cbc::Encryptor::<Aes256>::inner_iv_init(k.clone(), &iv).encrypt_blocks(blocks),
        }
    }
}

/// One direction's keys and sequence number.
struct Protection {
    suite: CipherSuite,
    aes: AesKey,
    mac_key: Zeroizing<Vec<u8>>,
    seq: u64,
}

impl Protection {
    fn new(suite: CipherSuite, mac_key: &[u8], enc_key: &[u8]) -> Result<Self, TlsError> {
        if mac_key.len() != suite.mac().len() || enc_key.len() != suite.enc_key_len() {
            return Err(TlsError::Internal("record keys do not match the cipher suite"));
        }
        Ok(Self { suite, aes: AesKey::new(enc_key)?, mac_key: Zeroizing::new(mac_key.to_vec()), seq: 0 })
    }

    /// The sequence number for the next record. RFC 5246 §6.1 forbids a wrap;
    /// with no renegotiation the only answer is to stop.
    fn next_seq(&mut self) -> Result<u64, TlsError> {
        let seq = self.seq;
        self.seq = seq.checked_add(1).ok_or(TlsError::Internal("record sequence number exhausted"))?;
        Ok(seq)
    }
}

/// `seq_num || type || version || length` — the MAC's header (RFC 5246 §6.2.3.1).
fn mac_header(seq: u64, content_type: u8, len: usize) -> [u8; 13] {
    let mut h = [0u8; 13];
    h[..8].copy_from_slice(&seq.to_be_bytes());
    h[8] = content_type;
    h[9..11].copy_from_slice(&TLS12.to_be_bytes());
    h[11] = (len >> 8) as u8;
    h[12] = len as u8;
    h
}

/// HMAC of `header || data`, for the send side (no secret-dependent lengths).
fn mac_plain(alg: MacAlg, key: &[u8], header: &[u8; 13], data: &[u8]) -> [u8; MAX_MAC] {
    fn run<D>(key: &[u8], header: &[u8; 13], data: &[u8]) -> [u8; MAX_MAC]
    where
        D: EagerHash,
        Hmac<D>: Mac + KeyInit,
    {
        let mut mac = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
        Mac::update(&mut mac, header);
        Mac::update(&mut mac, data);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; MAX_MAC];
        out[..tag.len()].copy_from_slice(&tag);
        out
    }
    match alg {
        MacAlg::Sha1 => run::<Sha1>(key, header, data),
        MacAlg::Sha256 => run::<Sha256>(key, header, data),
        MacAlg::Sha384 => run::<Sha384>(key, header, data),
    }
}

/// Constant-time TLS padding check over the last `min(256, len)` bytes.
/// Returns whether the padding is well formed *and* leaves room for the MAC,
/// and how many bytes to strip (0 when it is not: a bad padding is treated
/// as zero-length padding, RFC 5246 §6.2.3.2).
fn padding_ct(body: &[u8], mac_len: usize) -> (Choice, usize) {
    let len = body.len();
    debug_assert!(len > mac_len, "caller enforces the minimum length");
    let pad = u32::from(body[len - 1]);
    // pad + 1 (the length byte) + mac_len must fit in the record.
    let mut good = (pad + 1 + mac_len as u32).ct_lt(&(len as u32 + 1));
    // The window is fixed by the public record length, never by `pad`.
    for i in 1..=len.min(256) {
        let in_pad = (i as u32).ct_lt(&(pad + 2));
        let matches = u32::from(body[len - i]).ct_eq(&pad);
        good &= !in_pad | matches;
    }
    let to_remove = u32::conditional_select(&0, &(pad + 1), good);
    (good, to_remove as usize)
}

/// HMAC of `header || body[..data_len]` with work that depends only on
/// `body.len()`: the bytes after the MAC go into the same running inner hash
/// (finalised too), and a one-block finalisation of the real tag is topped
/// up with one dummy compression. `block`/`len_field` describe the hash.
fn mac_ct<D>(
    key: &[u8],
    header: &[u8; 13],
    body: &[u8],
    data_len: usize,
    mac_len: usize,
    block: usize,
    len_field: usize,
) -> [u8; MAX_MAC]
where
    D: EagerHash,
    Hmac<D>: Mac + KeyInit + Clone,
{
    let mut mac = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    Mac::update(&mut mac, header);
    Mac::update(&mut mac, &body[..data_len]);
    let tag = mac.clone().finalize().into_bytes();

    // The inner hash now streams 13 + body.len() - mac_len bytes in all.
    Mac::update(&mut mac, &body[data_len + mac_len..]);
    black_box(mac.finalize().into_bytes());

    // One finalisation compression if 0x80 and the length field fitted after
    // the data, else two: equalise to two (the documented residual branch).
    let inner_len = block + header.len() + data_len;
    if inner_len % block < block - len_field {
        let mut dummy = D::new();
        Digest::update(&mut dummy, &[0u8; 128][..block]);
        black_box(&dummy);
    }

    let mut out = [0u8; MAX_MAC];
    out[..mac_len].copy_from_slice(&tag[..mac_len]);
    out
}

/// `body[data_len..data_len + mac_len]` without a secret-dependent address:
/// every offset the MAC could start at is read and the right one selected
/// with a constant-time mask.
fn extract_mac_ct(body: &[u8], data_len: usize, mac_len: usize) -> [u8; MAX_MAC] {
    let mut out = [0u8; MAX_MAC];
    let highest = body.len() - mac_len;
    let lowest = highest.saturating_sub(256);
    for start in lowest..=highest {
        let selected = (start as u32).ct_eq(&(data_len as u32));
        for k in 0..mac_len {
            out[k].conditional_assign(&body[start + k], selected);
        }
    }
    out
}

/// Padding + MAC verification of a decrypted record body: the plaintext
/// length (meaningless if the verdict is false) and the verdict.
fn verify_ct(alg: MacAlg, key: &[u8], seq: u64, content_type: u8, body: &[u8]) -> (usize, Choice) {
    let mac_len = alg.len();
    let (pad_good, to_remove) = padding_ct(body, mac_len);
    // No underflow: a good padding was checked to leave room for the MAC; a
    // bad one strips nothing and len > mac_len.
    let data_len = body.len() - to_remove - mac_len;
    let header = mac_header(seq, content_type, data_len);
    let expected = match alg {
        MacAlg::Sha1 => mac_ct::<Sha1>(key, &header, body, data_len, mac_len, 64, 8),
        MacAlg::Sha256 => mac_ct::<Sha256>(key, &header, body, data_len, mac_len, 64, 8),
        MacAlg::Sha384 => mac_ct::<Sha384>(key, &header, body, data_len, mac_len, 128, 16),
    };
    let received = extract_mac_ct(body, data_len, mac_len);
    let mac_good = expected[..mac_len].ct_eq(&received[..mac_len]);
    (data_len, pad_good & mac_good)
}

/// Test-only ways to break an outgoing record, for the negative tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealTamper {
    /// Valid padding, wrong MAC.
    FlipMac,
    /// Correct MAC, one padding byte wrong.
    BadPadding,
    /// Correct MAC, padding length byte pointing past the record start.
    PaddingTooLong,
}

/// The sending half of an established direction.
pub(crate) struct Encryptor(Protection);

impl Encryptor {
    pub(crate) fn new(suite: CipherSuite, mac_key: &[u8], enc_key: &[u8]) -> Result<Self, TlsError> {
        Protection::new(suite, mac_key, enc_key).map(Self)
    }

    /// Append one protected record carrying `plaintext` to `out`.
    pub(crate) fn seal(&mut self, content_type: u8, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), TlsError> {
        self.seal_inner(content_type, plaintext, out, false, 0)
    }

    #[cfg(test)]
    pub(crate) fn seal_tampered(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        out: &mut Vec<u8>,
        tamper: SealTamper,
    ) -> Result<(), TlsError> {
        match tamper {
            SealTamper::FlipMac => self.seal_inner(content_type, plaintext, out, true, 0),
            SealTamper::BadPadding => self.seal_inner(content_type, plaintext, out, false, 1),
            SealTamper::PaddingTooLong => self.seal_inner(content_type, plaintext, out, false, 2),
        }
    }

    /// `flip_mac` / `pad_tamper` serve the negative tests only; production
    /// always passes `false, 0`.
    fn seal_inner(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        out: &mut Vec<u8>,
        flip_mac: bool,
        pad_tamper: u8,
    ) -> Result<(), TlsError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(TlsError::Internal("record plaintext exceeds 2^14 bytes"));
        }
        let p = &mut self.0;
        let seq = p.next_seq()?;
        let mac_len = p.suite.mac().len();
        let mut tag = mac_plain(p.suite.mac(), &p.mac_key, &mac_header(seq, content_type, plaintext.len()), plaintext);
        if flip_mac {
            tag[0] ^= 0x01;
        }
        let content_len = plaintext.len() + mac_len;
        // Minimal padding: content || padding || padding_length fills whole
        // blocks; each padding byte equals padding_length.
        let mut pad = (BLOCK - (content_len + 1) % BLOCK) % BLOCK;
        if pad_tamper == 1 && pad == 0 {
            pad = BLOCK; // room for a padding byte to corrupt
        }
        let fragment_len = BLOCK + content_len + pad + 1;

        let mut iv = [0u8; BLOCK];
        getrandom::fill(&mut iv).map_err(|_| TlsError::Internal("the operating system RNG failed"))?;

        out.reserve(HEADER_LEN + fragment_len);
        out.push(content_type);
        out.extend_from_slice(&TLS12.to_be_bytes());
        out.extend_from_slice(&(fragment_len as u16).to_be_bytes());
        out.extend_from_slice(&iv);
        let body_start = out.len();
        out.extend_from_slice(plaintext);
        out.extend_from_slice(&tag[..mac_len]);
        out.extend(std::iter::repeat_n(pad as u8, pad + 1));
        match pad_tamper {
            1 => out[body_start + content_len] ^= 0x01,
            2 => {
                let last = out.len() - 1;
                out[last] = 0xff;
            }
            _ => {}
        }
        p.aes.cbc_encrypt(&iv, &mut out[body_start..]);
        Ok(())
    }
}

/// The receiving half of an established direction.
pub(crate) struct Decryptor(Protection);

impl Decryptor {
    pub(crate) fn new(suite: CipherSuite, mac_key: &[u8], enc_key: &[u8]) -> Result<Self, TlsError> {
        Protection::new(suite, mac_key, enc_key).map(Self)
    }

    /// Decrypt and verify one record's fragment in place and return its
    /// plaintext. Every padding, MAC or length failure is
    /// [`TlsError::BadRecordMac`].
    pub(crate) fn open<'a>(&mut self, content_type: u8, fragment: &'a mut [u8]) -> Result<&'a [u8], TlsError> {
        let seq = self.0.next_seq()?;
        let alg = self.0.suite.mac();
        let min_len = BLOCK + (alg.len() + 1).div_ceil(BLOCK) * BLOCK;
        if fragment.len() < min_len || !fragment.len().is_multiple_of(BLOCK) || fragment.len() > MAX_CIPHERTEXT {
            return Err(TlsError::BadRecordMac);
        }
        let (iv, body) = fragment.split_at_mut(BLOCK);
        let iv: [u8; BLOCK] = (&*iv).try_into().expect("split at BLOCK");
        self.0.aes.cbc_decrypt(&iv, body);
        let (data_len, ok) = verify_ct(alg, &self.0.mac_key, seq, content_type, body);
        if !bool::from(ok) {
            return Err(TlsError::BadRecordMac);
        }
        if data_len > MAX_PLAINTEXT {
            return Err(TlsError::RecordOverflow);
        }
        let fragment: &'a [u8] = fragment;
        Ok(&fragment[BLOCK..BLOCK + data_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::OFFERED;

    fn pair(suite: CipherSuite) -> (Encryptor, Decryptor) {
        let mac_key: Vec<u8> = (0..suite.mac().len() as u8).collect();
        let enc_key: Vec<u8> = (100..100 + suite.enc_key_len() as u8).collect();
        (Encryptor::new(suite, &mac_key, &enc_key).unwrap(), Decryptor::new(suite, &mac_key, &enc_key).unwrap())
    }

    fn fragment_of(record: &[u8]) -> Vec<u8> {
        assert_eq!(record[1..3], TLS12.to_be_bytes());
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), HEADER_LEN + len);
        record[HEADER_LEN..].to_vec()
    }

    #[test]
    fn round_trip_every_suite_and_length() {
        for suite in OFFERED {
            let (mut enc, mut dec) = pair(suite);
            for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 47, 48, 55, 56, 63, 64, 100, 1000, MAX_PLAINTEXT] {
                let msg: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let mut rec = Vec::new();
                enc.seal(content::APPLICATION_DATA, &msg, &mut rec).unwrap();
                let mut frag = fragment_of(&rec);
                assert_eq!(frag.len() % BLOCK, 0);
                let pt = dec.open(content::APPLICATION_DATA, &mut frag).unwrap();
                assert_eq!(pt, &msg[..], "{suite:?} len {len}");
            }
        }
    }

    #[test]
    fn fresh_iv_per_record() {
        let (mut enc, _) = pair(CipherSuite::EcdheRsaAes128CbcSha);
        let mut a = Vec::new();
        let mut b = Vec::new();
        enc.seal(content::APPLICATION_DATA, b"same", &mut a).unwrap();
        enc.seal(content::APPLICATION_DATA, b"same", &mut b).unwrap();
        assert_ne!(a[HEADER_LEN..HEADER_LEN + BLOCK], b[HEADER_LEN..HEADER_LEN + BLOCK]);
    }

    #[test]
    fn sequence_number_and_content_type_are_authenticated() {
        let (mut enc, mut dec) = pair(CipherSuite::EcdheRsaAes256CbcSha384);
        let mut r1 = Vec::new();
        let mut r2 = Vec::new();
        enc.seal(content::APPLICATION_DATA, b"one", &mut r1).unwrap();
        enc.seal(content::APPLICATION_DATA, b"two", &mut r2).unwrap();
        // Reordered (or replayed) record: the second one under seq 0.
        let mut f2 = fragment_of(&r2);
        assert!(matches!(dec.open(content::APPLICATION_DATA, &mut f2), Err(TlsError::BadRecordMac)));

        let (mut enc, mut dec) = pair(CipherSuite::EcdheRsaAes256CbcSha384);
        let mut r = Vec::new();
        enc.seal(content::APPLICATION_DATA, b"x", &mut r).unwrap();
        let mut f = fragment_of(&r);
        assert!(matches!(dec.open(content::HANDSHAKE, &mut f), Err(TlsError::BadRecordMac)));
    }

    /// Bad MAC, bad padding, padding longer than the record, a flipped
    /// ciphertext bit, misaligned, short and oversized fragments: one and
    /// the same error (variant, message and alert).
    #[test]
    fn every_record_failure_is_the_same_bad_record_mac() {
        let expected = TlsError::BadRecordMac.to_string();
        for suite in OFFERED {
            let mut failures: Vec<TlsError> = Vec::new();
            for tamper in [SealTamper::FlipMac, SealTamper::BadPadding, SealTamper::PaddingTooLong] {
                for len in [0usize, 1, 12, 27, 64, 300] {
                    let (mut enc, mut dec) = pair(suite);
                    let mut rec = Vec::new();
                    enc.seal_tampered(content::APPLICATION_DATA, &vec![0x41u8; len], &mut rec, tamper).unwrap();
                    let mut frag = fragment_of(&rec);
                    failures.push(dec.open(content::APPLICATION_DATA, &mut frag).unwrap_err());
                }
            }
            let (mut enc, mut dec) = pair(suite);
            let mut rec = Vec::new();
            enc.seal(content::APPLICATION_DATA, b"hello", &mut rec).unwrap();
            let mut frag = fragment_of(&rec);
            let n = frag.len();
            frag[n - BLOCK - 1] ^= 0x80;
            failures.push(dec.open(content::APPLICATION_DATA, &mut frag).unwrap_err());
            for bad_len in [0usize, BLOCK, BLOCK + 1, 2 * BLOCK + 3, MAX_CIPHERTEXT + BLOCK] {
                let (_, mut dec) = pair(suite);
                let mut frag = vec![0u8; bad_len];
                failures.push(dec.open(content::APPLICATION_DATA, &mut frag).unwrap_err());
            }
            for e in failures {
                assert!(matches!(e, TlsError::BadRecordMac), "{suite:?}: {e:?}");
                assert_eq!(e.to_string(), expected);
                assert_eq!(e.alert(), Some(crate::error::alert::BAD_RECORD_MAC));
            }
        }
    }

    #[test]
    fn padding_check_accepts_only_well_formed_padding() {
        let mut body = [0u8; 32];
        body[28..].copy_from_slice(&[3, 3, 3, 3]);
        let (ok, strip) = padding_ct(&body, 20);
        assert!(bool::from(ok));
        assert_eq!(strip, 4);
        body[29] = 2;
        let (ok, strip) = padding_ct(&body, 20);
        assert!(!bool::from(ok));
        assert_eq!(strip, 0);
        // 11 bytes of padding + length byte + 20-byte MAC fill 32 exactly;
        // 12 leaves no room for the MAC.
        assert!(bool::from(padding_ct(&[11u8; 32], 20).0));
        assert!(!bool::from(padding_ct(&[12u8; 32], 20).0));
        // The largest padding (255) inside the 256-byte window.
        let body = [255u8; 256 + 32];
        let (ok, strip) = padding_ct(&body, 20);
        assert!(bool::from(ok));
        assert_eq!(strip, 256);
    }

    #[test]
    fn mac_extraction_selects_the_right_offset() {
        let body: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let highest = body.len() - 20;
        for data_len in [highest - 256, highest - 200, highest - 17, highest - 1, highest] {
            let got = extract_mac_ct(&body, data_len, 20);
            assert_eq!(&got[..20], &body[data_len..data_len + 20]);
        }
    }

    /// The constant-work MAC equals the straightforward one.
    #[test]
    fn constant_time_mac_matches_plain_mac() {
        for alg in [MacAlg::Sha1, MacAlg::Sha256, MacAlg::Sha384] {
            let key = vec![7u8; alg.len()];
            for data_len in [0usize, 1, 40, 55, 56, 63, 64, 111, 112, 127, 128, 500] {
                let mut body = vec![0x5au8; data_len + alg.len() + 17];
                body[data_len] = 1;
                let header = mac_header(9, content::APPLICATION_DATA, data_len);
                let plain = mac_plain(alg, &key, &header, &body[..data_len]);
                let ct = match alg {
                    MacAlg::Sha1 => mac_ct::<Sha1>(&key, &header, &body, data_len, alg.len(), 64, 8),
                    MacAlg::Sha256 => mac_ct::<Sha256>(&key, &header, &body, data_len, alg.len(), 64, 8),
                    MacAlg::Sha384 => mac_ct::<Sha384>(&key, &header, &body, data_len, alg.len(), 128, 16),
                };
                assert_eq!(plain[..alg.len()], ct[..alg.len()], "{alg:?} {data_len}");
            }
        }
    }

    #[test]
    fn oversized_plaintext_is_refused_on_seal() {
        let (mut enc, _) = pair(CipherSuite::EcdheRsaAes128CbcSha);
        let mut out = Vec::new();
        assert!(enc.seal(content::APPLICATION_DATA, &vec![0u8; MAX_PLAINTEXT + 1], &mut out).is_err());
    }
}
