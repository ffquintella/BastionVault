//! `authenticatorData` and `attestationObject` parsing.
//!
//! Layout of `authenticatorData` (binary, big-endian):
//!
//! ```text
//! offset  size                    field
//! 0       32                      rpIdHash (SHA-256)
//! 32      1                       flags
//! 33      4                       signCount (u32 BE)
//! 37      ...                     attestedCredentialData (if AT flag set)
//!                                 extensions               (if ED flag set)
//! ```
//!
//! attestedCredentialData layout:
//!
//! ```text
//! 0       16                      AAGUID
//! 16      2                       credentialIdLength (u16 BE)
//! 18      L                       credentialId
//! 18+L    ...                     credentialPublicKey (COSE_Key, CBOR)
//! ```
//!
//! `attestationObject` is a CBOR map with keys `fmt` (text), `authData`
//! (bstr), `attStmt` (map). We only accept `fmt = "none"` and don't look
//! at `attStmt` at all.

use ciborium::value::Value as CborValue;
use sha2::{Digest, Sha256};

use super::errors::RpError;

/// authenticatorData flags byte. We expose accessors only for the bits
/// the verifier actually consults.
#[derive(Debug, Clone, Copy)]
pub struct Flags(pub u8);

impl Flags {
    pub fn user_present(&self) -> bool {
        self.0 & 0x01 != 0
    }
    pub fn attested_credential_data(&self) -> bool {
        self.0 & 0x40 != 0
    }
}

#[derive(Debug)]
pub struct AttestedCredential {
    #[allow(dead_code)]
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// Raw COSE_Key CBOR bytes (re-parsed at verification time).
    pub cose_public_key: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: Flags,
    pub sign_count: u32,
    pub attested_credential: Option<AttestedCredential>,
}

impl AuthenticatorData {
    /// Parse the binary authenticatorData blob.
    pub fn parse(raw: &[u8]) -> Result<Self, RpError> {
        if raw.len() < 37 {
            return Err(RpError::BadAuthData(format!(
                "expected at least 37 bytes, got {}",
                raw.len()
            )));
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&raw[0..32]);
        let flags = Flags(raw[32]);
        let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);

        let mut idx = 37;
        let attested_credential = if flags.attested_credential_data() {
            if raw.len() < idx + 18 {
                return Err(RpError::BadAuthData(
                    "truncated attestedCredentialData header".into(),
                ));
            }
            let mut aaguid = [0u8; 16];
            aaguid.copy_from_slice(&raw[idx..idx + 16]);
            idx += 16;
            let cred_id_len = u16::from_be_bytes([raw[idx], raw[idx + 1]]) as usize;
            idx += 2;
            if raw.len() < idx + cred_id_len {
                return Err(RpError::BadAuthData(
                    "truncated credentialId".into(),
                ));
            }
            let credential_id = raw[idx..idx + cred_id_len].to_vec();
            idx += cred_id_len;

            // The remaining bytes start with a CBOR-encoded COSE_Key. We need
            // to know exactly how many bytes that key consumed so we can
            // distinguish it from the optional extensions map that follows.
            let cose_len = cbor_item_len(&raw[idx..]).map_err(|e| {
                RpError::BadAuthData(format!("could not measure COSE_Key length: {e}"))
            })?;
            if raw.len() < idx + cose_len {
                return Err(RpError::BadAuthData(
                    "truncated credentialPublicKey".into(),
                ));
            }
            let cose_public_key = raw[idx..idx + cose_len].to_vec();
            // We don't validate trailing extensions; their presence is fine.

            Some(AttestedCredential { aaguid, credential_id, cose_public_key })
        } else {
            None
        };

        Ok(Self { rp_id_hash, flags, sign_count, attested_credential })
    }

    pub fn expect_rp_id(&self, rp_id: &str) -> Result<(), RpError> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        if self.rp_id_hash == expected {
            Ok(())
        } else {
            Err(RpError::RpIdMismatch)
        }
    }
}

/// Measure how many bytes the *first* CBOR item in `bytes` occupies.
///
/// Used to find the boundary between the credentialPublicKey CBOR map
/// and the optional extensions map that may follow it inside
/// authenticatorData. We rely on `ciborium` to decode the item and
/// then re-serialize to compute the length — slightly wasteful but
/// straightforward and avoids a hand-rolled CBOR scanner.
fn cbor_item_len(bytes: &[u8]) -> Result<usize, String> {
    let mut cursor = std::io::Cursor::new(bytes);
    let val: CborValue = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| format!("decode: {e}"))?;
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&val, &mut buf).map_err(|e| format!("re-encode: {e}"))?;
    if buf.len() > bytes.len() {
        return Err("re-encoded length exceeds input".into());
    }
    // CBOR is canonical for fixed-shape data only; our re-encode may
    // disagree on indefinite-length forms. Sanity-check that the
    // re-encode is a prefix of the original.
    if &bytes[..buf.len()] != buf.as_slice() {
        // Fall back to the cursor position the decoder reached. This is
        // the more general truth, but not all readers expose it cleanly.
        return Ok(cursor.position() as usize);
    }
    Ok(buf.len())
}

/// Parsed `attestationObject`.
#[derive(Debug)]
pub struct AttestationObject {
    pub fmt: String,
    pub auth_data: Vec<u8>,
    /// Kept opaque — we don't validate the attestation statement.
    #[allow(dead_code)]
    pub att_stmt: CborValue,
}

impl AttestationObject {
    pub fn parse(raw: &[u8]) -> Result<Self, RpError> {
        let val: CborValue = ciborium::de::from_reader(raw)
            .map_err(|e| RpError::Cbor(format!("attestationObject: {e}")))?;
        let map = match val {
            CborValue::Map(m) => m,
            _ => return Err(RpError::Cbor("attestationObject is not a CBOR map".into())),
        };

        let mut fmt: Option<String> = None;
        let mut auth_data: Option<Vec<u8>> = None;
        let mut att_stmt: Option<CborValue> = None;
        for (k, v) in map {
            let key = match k {
                CborValue::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "fmt" => {
                    if let CborValue::Text(s) = v {
                        fmt = Some(s);
                    }
                }
                "authData" => {
                    if let CborValue::Bytes(b) = v {
                        auth_data = Some(b);
                    }
                }
                "attStmt" => att_stmt = Some(v),
                _ => {}
            }
        }

        Ok(Self {
            fmt: fmt.ok_or_else(|| RpError::Cbor("missing fmt".into()))?,
            auth_data: auth_data.ok_or_else(|| RpError::Cbor("missing authData".into()))?,
            att_stmt: att_stmt.unwrap_or(CborValue::Map(Vec::new())),
        })
    }
}
