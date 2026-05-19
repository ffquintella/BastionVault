//! BVRG-v1 envelope — Rustion-integration session-grant format.
//!
//! Wire layout (frozen by `features/rustion-integration.md`):
//!
//! ```text
//! BVRG-v1 := magic("BVRG\x01") || sig_len:u16 || sig || ct_len:u32 || ct
//!
//! sig := sign(master_priv, sha256(magic || ct_len || ct))   // hybrid Ed25519 + ML-DSA-65
//! ct  := ML-KEM-768-encap(rustion_pub) || ChaCha20-Poly1305(payload, dek)
//! ```
//!
//! The signature half is **hybrid by construction**: the bytes carry an
//! Ed25519-sig followed by an ML-DSA-65-sig, length-prefixed. Verifying
//! requires **both** halves to verify — there is no downgrade path, and
//! a tampered envelope that drops one half is rejected at the
//! length-check stage.
//!
//! The ciphertext half uses the existing `KemDemEnvelopeV1` (KEM-DEM:
//! ML-KEM-768 wraps an ephemeral ChaCha20-Poly1305 data key, the AEAD
//! encrypts the CBOR-encoded payload). The KEM-DEM serialised bytes
//! are what sit inside the BVRG-v1 frame's `ct` slot.
//!
//! Payload is a CBOR map; the exact field set lives in `BvrgPayload`.
//! Forward-compatible: unknown fields on decode are ignored, so a
//! Rustion that hasn't shipped a future field gracefully drops it.
//!
//! Production note: the verify path is intentionally fail-closed. A
//! mismatched magic, oversize length, malformed CBOR, signature
//! failure on either half, or AEAD tag failure all return the same
//! coarse error category from the public surface. Callers that want
//! detailed diagnostics (audit replay attacks, key rotation events,
//! …) read the `BvrgError` returned and map it to their own
//! taxonomy.

use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{CryptoError, KemDemEnvelopeV1, MlKem768Provider};

// ─── Frame constants ───────────────────────────────────────────────

/// Magic bytes prefix: `B`, `V`, `R`, `G`, version `0x01`.
pub const BVRG_MAGIC: &[u8; 5] = b"BVRG\x01";

/// Hard cap on the full envelope size. Matches the spec's 16 KiB
/// budget so a hostile peer can't push us into an OOM-loop with a
/// 4 GiB `ct_len`.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;

/// Hard cap on the inner CBOR payload (after decrypt). Same budget as
/// the envelope minus the framing + sig overhead.
const MAX_PAYLOAD_BYTES: usize = 12 * 1024;

/// Hybrid signature wire format: Ed25519 sig length (always 64 bytes,
/// but framed as `u16` for forward-compat), then the 64 sig bytes,
/// then the ML-DSA-65 sig (3309 bytes for level 65). Length-prefixing
/// each half independently lets us extend to a third PQC algorithm
/// later without re-spinning the wire format.
const ED25519_SIG_LEN: usize = 64;
const MLDSA65_SIG_LEN: usize = ml_dsa_65::SIG_LEN;

// ─── Public types ──────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BvrgError {
    #[error("envelope shorter than minimum framing")]
    EnvelopeTooShort,
    #[error("envelope longer than MAX_ENVELOPE_BYTES ({MAX_ENVELOPE_BYTES})")]
    EnvelopeTooLong,
    #[error("payload longer than MAX_PAYLOAD_BYTES ({MAX_PAYLOAD_BYTES})")]
    PayloadTooLong,
    #[error("magic prefix mismatch — not a BVRG envelope")]
    MagicMismatch,
    #[error("length fields disagree with framing")]
    LengthMismatch,
    #[error("hybrid signature could not be parsed")]
    HybridSignatureMalformed,
    #[error("Ed25519 signature half failed verification")]
    Ed25519SignatureInvalid,
    #[error("ML-DSA-65 signature half failed verification")]
    MlDsa65SignatureInvalid,
    #[error("ciphertext failed to decrypt (KEM-DEM tag or KEM mismatch)")]
    CiphertextInvalid,
    #[error("CBOR payload failed to decode")]
    PayloadDecode,
    #[error("payload version unsupported")]
    PayloadVersionUnsupported,
    #[error("inner crypto primitive failed: {0}")]
    Inner(#[from] CryptoError),
    #[error("provided public key has the wrong length")]
    PublicKeyLength,
}

/// Hybrid master keypair held by BastionVault. The Ed25519 half is
/// classical; the ML-DSA-65 half is the PQC counterpart. Both are
/// required — there is no classical-only mode.
pub struct BvrgMasterSigningKey {
    pub ed25519: SigningKey,
    /// ML-DSA-65 secret seed (the engine rederives the expanded
    /// private key per sign). 32 bytes.
    pub mldsa65_seed: Zeroizing<[u8; crate::signature::ML_DSA_65_SEED_LEN]>,
}

/// Hybrid master public key. Pinned by Rustion's authority record on
/// the receiver side; published by `bvault rustion master export` on
/// the sender side.
#[derive(Clone, Debug)]
pub struct BvrgMasterPublicKey {
    pub ed25519: VerifyingKey,
    /// ML-DSA-65 public key bytes (1952 bytes).
    pub mldsa65: Vec<u8>,
}

impl BvrgMasterPublicKey {
    /// Reconstruct from on-wire byte slices. Both halves are required;
    /// classical-only is refused as a downgrade attack at construction
    /// time so the rest of the module can treat the key as trusted.
    pub fn from_bytes(ed25519: &[u8], mldsa65: &[u8]) -> Result<Self, BvrgError> {
        let ed_arr: [u8; 32] = ed25519
            .try_into()
            .map_err(|_| BvrgError::PublicKeyLength)?;
        let ed25519 = VerifyingKey::from_bytes(&ed_arr)
            .map_err(|_| BvrgError::PublicKeyLength)?;
        if mldsa65.len() != ml_dsa_65::PK_LEN {
            return Err(BvrgError::PublicKeyLength);
        }
        Ok(Self {
            ed25519,
            mldsa65: mldsa65.to_vec(),
        })
    }
}

/// CBOR payload — the operationally-meaningful body that travels
/// inside the envelope ciphertext.
///
/// Field naming mirrors `features/rustion-integration.md § Envelope
/// format`; serde renames keep CBOR keys short on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BvrgPayload {
    /// Schema version. Currently `1`; bumped on any wire-incompatible
    /// change. Rustion refuses unknown versions with `envelope_version_unsupported`.
    pub v: u32,
    /// Operation: `"open" | "renew" | "kill" | "attest" | "enrol" | "deenrol" | "replay"`.
    pub op: String,
    /// 16 random bytes; anti-replay against Rustion's nonce LRU.
    #[serde(with = "serde_bytes_wrapper")]
    pub nonce: Vec<u8>,
    /// Unix-seconds.
    pub issued_at: i64,
    /// Unix-seconds. Signature validity (distinct from session TTL).
    pub not_after: i64,
    /// Free-form target descriptor — only `open` envelopes need it
    /// populated. Encoded as a CBOR map so unknown protocol fields
    /// don't break older decoders.
    #[serde(default)]
    pub target: Option<BvrgTarget>,
    /// Credential material. `open` only.
    #[serde(default)]
    pub credential: Option<BvrgCredential>,
    /// Session policy overlay. `open` and `renew` honour different
    /// subsets; Rustion clamps to its authority record's caps.
    #[serde(default)]
    pub session: Option<BvrgSession>,
    /// Operator identity. Always populated.
    pub operator: BvrgOperator,
    /// UUID linking this envelope to BV's own audit chain entries.
    pub correlation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BvrgTarget {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub hostkey_pin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BvrgCredential {
    /// `ssh-key | ssh-password | rdp-password | rdp-cert | …`
    pub kind: String,
    pub username: String,
    #[serde(with = "serde_bytes_wrapper")]
    pub material: Vec<u8>,
    /// Open-ended extension bag (CBOR map).
    #[serde(default)]
    pub extra: Option<CborValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BvrgSession {
    pub ttl_secs: u32,
    pub max_renewals: u8,
    /// `"always" | "off" | "input-redacted"`
    pub recording: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BvrgOperator {
    pub vault_user_id: String,
    pub vault_user_name: String,
    pub vault_session_id: String,
    pub src_ip: String,
    /// Phase-9 attestation binding — stamped on every envelope so
    /// Rustion can refuse a cloned master keypair re-used by a
    /// different BV deployment.
    #[serde(default)]
    pub deployment_id: String,
}

// ─── Build ─────────────────────────────────────────────────────────

/// Encode → encrypt → sign → frame. Returns the on-wire byte buffer
/// Rustion will receive as the body of `POST /v1/sessions` (or
/// `/renew`, `/kill`, …).
pub fn build(
    payload: &BvrgPayload,
    master: &BvrgMasterSigningKey,
    rustion_kem_pub: &[u8],
) -> Result<Vec<u8>, BvrgError> {
    // 1. CBOR-encode the payload.
    let mut cbor_buf = Vec::with_capacity(512);
    ciborium::ser::into_writer(payload, &mut cbor_buf)
        .map_err(|_| BvrgError::PayloadDecode)?;
    if cbor_buf.len() > MAX_PAYLOAD_BYTES {
        return Err(BvrgError::PayloadTooLong);
    }

    // 2. Encrypt the CBOR with ML-KEM-768 + ChaCha20-Poly1305. The
    // KEM-DEM helper does the heavy lifting; we serialise its
    // canonical representation to a byte slab and inline that as
    // the BVRG `ct` field.
    let kem_envelope = KemDemEnvelopeV1::seal(
        &MlKem768Provider,
        rustion_kem_pub,
        BVRG_MAGIC, // AAD: binds the ciphertext to this format version
        &cbor_buf,
    )?;
    let ct = encode_kem_envelope(&kem_envelope)?;
    let ct_len = u32::try_from(ct.len()).map_err(|_| BvrgError::EnvelopeTooLong)?;

    // 3. Compute the TBS hash = sha256(magic || ct_len || ct). The
    // magic + length are bound into the hash so that an attacker who
    // captured the inner ciphertext can't repackage it under a
    // different version byte or a smaller length prefix.
    let tbs = tbs_hash(BVRG_MAGIC, ct_len, &ct);

    // 4. Sign both halves of the hybrid pair. Ed25519 first, ML-DSA-65
    // second — the wire order is fixed.
    let ed_sig = master.ed25519.sign(&tbs);
    let mldsa_sig = sign_mldsa65(master.mldsa65_seed.as_ref(), &tbs)?;

    // 5. Frame the hybrid sig: ed25519 length-prefixed, then mldsa65
    // length-prefixed. The outer `sig_len` covers both segments +
    // their length prefixes.
    let mut sig = Vec::with_capacity(2 + ED25519_SIG_LEN + 2 + MLDSA65_SIG_LEN);
    sig.extend_from_slice(&(ED25519_SIG_LEN as u16).to_be_bytes());
    sig.extend_from_slice(&ed_sig.to_bytes());
    sig.extend_from_slice(&(mldsa_sig.len() as u16).to_be_bytes());
    sig.extend_from_slice(&mldsa_sig);
    let sig_len = u16::try_from(sig.len()).map_err(|_| BvrgError::EnvelopeTooLong)?;

    // 6. Frame the envelope.
    let total = BVRG_MAGIC.len() + 2 + sig.len() + 4 + ct.len();
    if total > MAX_ENVELOPE_BYTES {
        return Err(BvrgError::EnvelopeTooLong);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(BVRG_MAGIC);
    out.extend_from_slice(&sig_len.to_be_bytes());
    out.extend_from_slice(&sig);
    out.extend_from_slice(&ct_len.to_be_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

// ─── Verify ────────────────────────────────────────────────────────

/// Unwrapped envelope — what `verify` returns on success. Carries the
/// decoded payload plus the framing facts the caller's replay-window
/// + nonce-LRU + policy stage needs.
#[derive(Debug, Clone)]
pub struct VerifiedEnvelope {
    pub payload: BvrgPayload,
    /// The TBS hash that was signed — useful for binding follow-up
    /// audit events to this specific envelope.
    pub envelope_fingerprint: [u8; 32],
}

/// Frame-parse → verify hybrid sig → decrypt → decode CBOR. Returns
/// the decoded payload on success. Any failure is fail-closed.
pub fn verify(
    envelope: &[u8],
    master_pub: &BvrgMasterPublicKey,
    rustion_kem_secret: &[u8],
) -> Result<VerifiedEnvelope, BvrgError> {
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(BvrgError::EnvelopeTooLong);
    }
    if envelope.len() < BVRG_MAGIC.len() + 2 + 4 {
        return Err(BvrgError::EnvelopeTooShort);
    }
    if &envelope[..BVRG_MAGIC.len()] != BVRG_MAGIC {
        return Err(BvrgError::MagicMismatch);
    }
    let mut cursor = BVRG_MAGIC.len();

    // sig_len
    let sig_len = u16::from_be_bytes(
        envelope[cursor..cursor + 2]
            .try_into()
            .map_err(|_| BvrgError::EnvelopeTooShort)?,
    ) as usize;
    cursor += 2;
    if cursor + sig_len + 4 > envelope.len() {
        return Err(BvrgError::LengthMismatch);
    }
    let sig_bytes = &envelope[cursor..cursor + sig_len];
    cursor += sig_len;

    // ct_len
    let ct_len = u32::from_be_bytes(
        envelope[cursor..cursor + 4]
            .try_into()
            .map_err(|_| BvrgError::LengthMismatch)?,
    );
    cursor += 4;
    if cursor + ct_len as usize != envelope.len() {
        return Err(BvrgError::LengthMismatch);
    }
    let ct = &envelope[cursor..];

    // Parse the hybrid signature: 2 + 64 + 2 + 3309 expected.
    let (ed_sig_bytes, mldsa_sig_bytes) = split_hybrid_sig(sig_bytes)?;

    let tbs = tbs_hash(BVRG_MAGIC, ct_len, ct);

    // Verify both halves of the hybrid pair. Both must succeed —
    // there is no fallback, no "Ed25519 ok skip ML-DSA" path.
    let ed_sig =
        Ed25519Signature::from_slice(ed_sig_bytes).map_err(|_| BvrgError::Ed25519SignatureInvalid)?;
    master_pub
        .ed25519
        .verify(&tbs, &ed_sig)
        .map_err(|_| BvrgError::Ed25519SignatureInvalid)?;

    verify_mldsa65(&master_pub.mldsa65, &tbs, mldsa_sig_bytes)?;

    // Decrypt the inner KEM-DEM envelope.
    let kem_envelope = decode_kem_envelope(ct)?;
    let plaintext = kem_envelope
        .open(&MlKem768Provider, rustion_kem_secret, BVRG_MAGIC)
        .map_err(|_| BvrgError::CiphertextInvalid)?;

    if plaintext.len() > MAX_PAYLOAD_BYTES {
        return Err(BvrgError::PayloadTooLong);
    }
    let payload: BvrgPayload =
        ciborium::de::from_reader(plaintext.as_slice()).map_err(|_| BvrgError::PayloadDecode)?;
    if payload.v != 1 {
        return Err(BvrgError::PayloadVersionUnsupported);
    }

    Ok(VerifiedEnvelope {
        payload,
        envelope_fingerprint: tbs,
    })
}

// ─── Helpers ───────────────────────────────────────────────────────

fn tbs_hash(magic: &[u8], ct_len: u32, ct: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(magic);
    h.update(ct_len.to_be_bytes());
    h.update(ct);
    h.finalize().into()
}

fn split_hybrid_sig(sig: &[u8]) -> Result<(&[u8], &[u8]), BvrgError> {
    if sig.len() < 2 + ED25519_SIG_LEN + 2 {
        return Err(BvrgError::HybridSignatureMalformed);
    }
    let ed_len = u16::from_be_bytes([sig[0], sig[1]]) as usize;
    if ed_len != ED25519_SIG_LEN || 2 + ed_len + 2 > sig.len() {
        return Err(BvrgError::HybridSignatureMalformed);
    }
    let ed_sig = &sig[2..2 + ed_len];
    let ml_len_off = 2 + ed_len;
    let ml_len = u16::from_be_bytes([sig[ml_len_off], sig[ml_len_off + 1]]) as usize;
    let ml_start = ml_len_off + 2;
    if ml_len != MLDSA65_SIG_LEN || ml_start + ml_len != sig.len() {
        return Err(BvrgError::HybridSignatureMalformed);
    }
    let ml_sig = &sig[ml_start..];
    Ok((ed_sig, ml_sig))
}

fn sign_mldsa65(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, BvrgError> {
    let seed_arr: [u8; crate::signature::ML_DSA_65_SEED_LEN] = seed
        .try_into()
        .map_err(|_| BvrgError::PublicKeyLength)?;
    let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed_arr);
    let sig = sk
        .try_sign(message, &[])
        .map_err(|_| BvrgError::MlDsa65SignatureInvalid)?;
    Ok(sig.to_vec())
}

fn verify_mldsa65(pubkey: &[u8], message: &[u8], sig: &[u8]) -> Result<(), BvrgError> {
    let pk_arr: [u8; ml_dsa_65::PK_LEN] = pubkey
        .try_into()
        .map_err(|_| BvrgError::PublicKeyLength)?;
    let sig_arr: [u8; MLDSA65_SIG_LEN] = sig
        .try_into()
        .map_err(|_| BvrgError::HybridSignatureMalformed)?;
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
        .map_err(|_| BvrgError::PublicKeyLength)?;
    if pk.verify(message, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(BvrgError::MlDsa65SignatureInvalid)
    }
}

fn encode_kem_envelope(env: &KemDemEnvelopeV1) -> Result<Vec<u8>, BvrgError> {
    // Use CBOR for the inner envelope too — keeps the dependency
    // count down (no second serializer) and the result is
    // forward-compatible with new fields on the existing struct.
    let mut buf = Vec::with_capacity(64);
    ciborium::ser::into_writer(env, &mut buf).map_err(|_| BvrgError::PayloadDecode)?;
    Ok(buf)
}

fn decode_kem_envelope(bytes: &[u8]) -> Result<KemDemEnvelopeV1, BvrgError> {
    ciborium::de::from_reader(bytes).map_err(|_| BvrgError::CiphertextInvalid)
}

/// Mint the standard 16-byte nonce a build() caller stamps into the
/// payload. Surfaced so tests + integration paths can build payloads
/// without re-deriving the convention.
pub fn fresh_nonce() -> Vec<u8> {
    use rand::Rng;
    let mut buf = vec![0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Unix-seconds shim. Surfaced so tests + integration paths can build
/// payloads without re-importing `SystemTime`.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// CBOR's serde implementation doesn't auto-bytefy `Vec<u8>`, so a
// thin wrapper module makes serialization land as a CBOR byte string
// instead of an array of integers (much smaller on the wire and what
// Rustion's CBOR decoder expects).
mod serde_bytes_wrapper {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let bb: serde_bytes::ByteBuf = serde_bytes::ByteBuf::deserialize(d)?;
        Ok(bb.into_vec())
    }

    // Tiny inlined re-impl of serde_bytes::{Bytes,ByteBuf} so this
    // module doesn't grow a new crate dependency.
    mod serde_bytes {
        use std::fmt;

        pub struct Bytes<'a>(&'a [u8]);
        impl<'a> Bytes<'a> {
            pub fn new(b: &'a [u8]) -> Self {
                Self(b)
            }
        }
        impl serde::Serialize for Bytes<'_> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(self.0)
            }
        }

        #[derive(Default)]
        pub struct ByteBuf(Vec<u8>);
        impl ByteBuf {
            pub fn into_vec(self) -> Vec<u8> {
                self.0
            }
        }
        impl<'de> serde::Deserialize<'de> for ByteBuf {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = ByteBuf;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("byte string")
                    }
                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<ByteBuf, E> {
                        Ok(ByteBuf(v.to_vec()))
                    }
                    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<ByteBuf, E> {
                        Ok(ByteBuf(v))
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<ByteBuf, A::Error> {
                        let mut v: Vec<u8> = Vec::new();
                        while let Some(b) = seq.next_element::<u8>()? {
                            v.push(b);
                        }
                        Ok(ByteBuf(v))
                    }
                }
                d.deserialize_byte_buf(V)
            }
        }
    }
}

// ─── Convenience: keypair generation for callers + tests ───────────

impl BvrgMasterSigningKey {
    /// Generate a fresh hybrid master keypair. Production code mints
    /// the Ed25519 + ML-DSA-65 halves under the PKI engine; this
    /// helper exists for synthetic-envelope tests and the local-dev
    /// `bvault rustion master init --self-signed` path.
    pub fn generate() -> Result<Self, BvrgError> {
        use rand::Rng;
        let mut ed_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut ed_seed);
        let ed25519 = SigningKey::from_bytes(&ed_seed);

        let mut ml_seed = Zeroizing::new([0u8; crate::signature::ML_DSA_65_SEED_LEN]);
        rand::rng().fill_bytes(ml_seed.as_mut());

        Ok(Self {
            ed25519,
            mldsa65_seed: ml_seed,
        })
    }

    /// Project the public half. Cheap — derives the Ed25519 verifying
    /// key from the signing key and the ML-DSA-65 pubkey from the
    /// seed (FIPS 204 rederives the expanded pubkey deterministically).
    pub fn public_key(&self) -> BvrgMasterPublicKey {
        let (ml_pk, _ml_sk) = ml_dsa_65::KG::keygen_from_seed(&self.mldsa65_seed);
        BvrgMasterPublicKey {
            ed25519: self.ed25519.verifying_key(),
            mldsa65: ml_pk.into_bytes().to_vec(),
        }
    }
}
