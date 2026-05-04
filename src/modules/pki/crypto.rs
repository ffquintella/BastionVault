//! PKI crypto abstraction.
//!
//! All signing identities (root CA, intermediate CA, issued leaves when we
//! self-sign for tests) flow through [`CertSigner`]. Phase 1 ships the
//! classical algorithms below; Phase 2 will add ML-DSA-44/65/87 implementations
//! behind the same trait.
//!
//! `rcgen::SigningKey` is what the underlying X.509 builders speak, so every
//! [`CertSigner`] exposes one. Phase 2's PQC signers will provide a custom
//! `SigningKey` impl backed by `fips204` rather than `rcgen::KeyPair`.

use rcgen::{KeyPair, SignatureAlgorithm};
use zeroize::Zeroizing;

#[cfg(feature = "pki_pqc_composite")]
use super::composite::CompositeSigner;
use super::pqc::{MlDsaLevel, MlDsaSigner};
use crate::errors::RvError;

/// Algorithm classes accepted by the PKI engine.
///
/// Phase 1 covers the classical set; PQC variants land in Phase 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    /// Composite ECDSA-P256 + ML-DSA-44 (`id-MLDSA44-ECDSA-P256-SHA256`).
    /// Phase 3 preview, gated behind the `pki_pqc_composite` feature.
    #[cfg(feature = "pki_pqc_composite")]
    CompositeEcdsaP256MlDsa44,
    /// Composite ECDSA-P256 + ML-DSA-65 (`id-MLDSA65-ECDSA-P256-SHA512`).
    /// The original Phase 3 ship — see [`super::composite`].
    #[cfg(feature = "pki_pqc_composite")]
    CompositeEcdsaP256MlDsa65,
    /// Composite ECDSA-P384 + ML-DSA-87 (`id-MLDSA87-ECDSA-P384-SHA512`).
    /// Highest classical/PQ security level on offer; matches the
    /// "top-of-the-line" tier in the IETF lamps draft.
    #[cfg(feature = "pki_pqc_composite")]
    CompositeEcdsaP384MlDsa87,
}

/// Coarse partition used by the PKI engine to enforce "no mixed chains by
/// default" — issuing a PQC leaf from a classical CA (or vice-versa) is
/// rejected up front unless the caller has opted into mixed chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmClass {
    Classical,
    Pqc,
    /// Composite (hybrid) — both halves valid. Distinct from `Classical` and
    /// `Pqc` so the mixed-chain guard in [`super::path_issue`] reads cleanly:
    /// composite role on composite CA only, no cross-class issuance.
    #[cfg(feature = "pki_pqc_composite")]
    Composite,
}

impl KeyAlgorithm {
    /// Parse a `(key_type, key_bits)` role tuple into a concrete algorithm.
    ///
    /// `key_bits == 0` selects the algorithm's default size (matches Vault's
    /// behaviour for `key_bits = 0`).
    pub fn from_role(key_type: &str, key_bits: u32) -> Result<Self, RvError> {
        match (key_type, key_bits) {
            ("rsa", 0) | ("rsa", 2048) => Ok(Self::Rsa2048),
            ("rsa", 3072) => Ok(Self::Rsa3072),
            ("rsa", 4096) => Ok(Self::Rsa4096),
            ("ec", 0) | ("ec", 256) => Ok(Self::EcdsaP256),
            ("ec", 384) => Ok(Self::EcdsaP384),
            ("ed25519", 0) => Ok(Self::Ed25519),
            // ML-DSA roles must leave `key_bits` at 0 — the security level is
            // encoded in the algorithm name, not the bit count. Setting
            // `key_bits` (or `signature_bits`) on a PQC role is rejected here
            // so misconfigured roles fail at write time, not mid-issuance.
            ("ml-dsa-44", 0) => Ok(Self::MlDsa44),
            ("ml-dsa-65", 0) => Ok(Self::MlDsa65),
            ("ml-dsa-87", 0) => Ok(Self::MlDsa87),
            ("ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87", _) => Err(RvError::ErrPkiKeyBitsInvalid),
            // Composite roles — same `key_bits = 0` rule as PQC.
            #[cfg(feature = "pki_pqc_composite")]
            ("ecdsa-p256+ml-dsa-44", 0) => Ok(Self::CompositeEcdsaP256MlDsa44),
            #[cfg(feature = "pki_pqc_composite")]
            ("ecdsa-p256+ml-dsa-65", 0) => Ok(Self::CompositeEcdsaP256MlDsa65),
            #[cfg(feature = "pki_pqc_composite")]
            ("ecdsa-p384+ml-dsa-87", 0) => Ok(Self::CompositeEcdsaP384MlDsa87),
            #[cfg(feature = "pki_pqc_composite")]
            (
                "ecdsa-p256+ml-dsa-44" | "ecdsa-p256+ml-dsa-65" | "ecdsa-p384+ml-dsa-87",
                _,
            ) => Err(RvError::ErrPkiKeyBitsInvalid),
            ("rsa", _) => Err(RvError::ErrPkiKeyBitsInvalid),
            ("ec", _) => Err(RvError::ErrPkiKeyBitsInvalid),
            _ => Err(RvError::ErrPkiKeyTypeInvalid),
        }
    }

    pub fn class(self) -> AlgorithmClass {
        match self {
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => AlgorithmClass::Pqc,
            #[cfg(feature = "pki_pqc_composite")]
            Self::CompositeEcdsaP256MlDsa44
            | Self::CompositeEcdsaP256MlDsa65
            | Self::CompositeEcdsaP384MlDsa87 => AlgorithmClass::Composite,
            _ => AlgorithmClass::Classical,
        }
    }

    pub fn ml_dsa_level(self) -> Option<MlDsaLevel> {
        match self {
            Self::MlDsa44 => Some(MlDsaLevel::L44),
            Self::MlDsa65 => Some(MlDsaLevel::L65),
            Self::MlDsa87 => Some(MlDsaLevel::L87),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => "rsa",
            Self::EcdsaP256 | Self::EcdsaP384 => "ec",
            Self::Ed25519 => "ed25519",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
            #[cfg(feature = "pki_pqc_composite")]
            Self::CompositeEcdsaP256MlDsa44 => "ecdsa-p256+ml-dsa-44",
            #[cfg(feature = "pki_pqc_composite")]
            Self::CompositeEcdsaP256MlDsa65 => "ecdsa-p256+ml-dsa-65",
            #[cfg(feature = "pki_pqc_composite")]
            Self::CompositeEcdsaP384MlDsa87 => "ecdsa-p384+ml-dsa-87",
        }
    }

    pub fn key_bits(self) -> u32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::EcdsaP256 => 256,
            Self::EcdsaP384 => 384,
            Self::Ed25519 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => 0,
            #[cfg(feature = "pki_pqc_composite")]
            Self::CompositeEcdsaP256MlDsa44
            | Self::CompositeEcdsaP256MlDsa65
            | Self::CompositeEcdsaP384MlDsa87 => 0,
        }
    }

    fn rcgen_alg(self) -> Result<&'static SignatureAlgorithm, RvError> {
        Ok(match self {
            // `rcgen` does not currently support generating fresh RSA keys via
            // its default `ring` provider; callers that pick RSA today fall back
            // to `EcdsaP256` semantics (see `generate`). The match is kept so
            // a future RSA generator slots in without changing the public API.
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => &rcgen::PKCS_RSA_SHA256,
            Self::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            Self::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            Self::Ed25519 => &rcgen::PKCS_ED25519,
            // PQC algorithms are not driven through rcgen — see [`super::x509_pqc`].
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => return Err(RvError::ErrPkiKeyTypeInvalid),
            #[cfg(feature = "pki_pqc_composite")]
            Self::CompositeEcdsaP256MlDsa44
            | Self::CompositeEcdsaP256MlDsa65
            | Self::CompositeEcdsaP384MlDsa87 => return Err(RvError::ErrPkiKeyTypeInvalid),
        })
    }
}

/// Phase-1 unified signer over `rcgen::KeyPair`.
///
/// Wraps the keypair plus its algorithm tag so storage round-trips can
/// reconstruct the same algorithm without sniffing the DER. The PEM bytes
/// hold the PKCS#8 private key — they are barrier-encrypted on disk and
/// zeroized in memory after use.
pub struct CertSigner {
    alg: KeyAlgorithm,
    inner: KeyPair,
    pem: Zeroizing<String>,
}

impl CertSigner {
    /// Generate a fresh keypair for `alg`.
    pub fn generate(alg: KeyAlgorithm) -> Result<Self, RvError> {
        // Phase 5.3: RSA generation goes through the `rsa` crate (which
        // rcgen 0.14 + ring cannot do natively), then we serialize to
        // PKCS#8 PEM and load that into rcgen via
        // `KeyPair::from_pem_and_sign_algo`. The `_and_sign_algo` form
        // pins the *signing* algorithm — RSA-2048 → SHA-256, RSA-3072 →
        // SHA-384, RSA-4096 → SHA-512 — because rcgen otherwise picks
        // SHA-256 by default, which is wrong for the larger key sizes.
        if matches!(alg, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096) {
            return Self::generate_rsa(alg);
        }
        let kp = KeyPair::generate_for(alg.rcgen_alg()?).map_err(rcgen_err)?;
        let pem = Zeroizing::new(kp.serialize_pem());
        Ok(Self { alg, inner: kp, pem })
    }

    fn generate_rsa(alg: KeyAlgorithm) -> Result<Self, RvError> {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        use rsa::RsaPrivateKey;

        let bits = alg.key_bits() as usize;
        // `rsa 0.9` is pinned to `rand_core 0.6`; the project's top-level
        // `rand = "0.10"` exports a different `OsRng` / `SysRng` that
        // doesn't satisfy the older `CryptoRngCore` bound. Use rsa's own
        // re-export for an apples-to-apples RNG. (Same workaround the
        // SAML signing code uses.)
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).map_err(|e| {
            log::error!("pki: RSA-{bits} generation failed: {e}");
            RvError::ErrPkiInternal
        })?;
        let pem = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| {
                log::error!("pki: RSA PKCS#8 emit failed: {e}");
                RvError::ErrPkiInternal
            })?
            .to_string();

        // Hand the PKCS#8 PEM to rcgen, pinning the per-bit-size signing
        // algorithm. The `_and_sign_algo` variant is what tells rcgen
        // which SHA hash to use when this keypair signs a TBS later.
        let sign_alg: &'static rcgen::SignatureAlgorithm = match alg {
            KeyAlgorithm::Rsa2048 => &rcgen::PKCS_RSA_SHA256,
            KeyAlgorithm::Rsa3072 => &rcgen::PKCS_RSA_SHA384,
            KeyAlgorithm::Rsa4096 => &rcgen::PKCS_RSA_SHA512,
            _ => unreachable!("generate_rsa called with non-RSA algorithm"),
        };
        let kp = KeyPair::from_pem_and_sign_algo(&pem, sign_alg).map_err(rcgen_err)?;
        Ok(Self { alg, inner: kp, pem: Zeroizing::new(pem) })
    }

    /// Reconstruct a signer from its serialized PKCS#8 PEM (as produced by
    /// [`pem_pkcs8`](Self::pem_pkcs8)). Algorithm is recovered from the
    /// keypair itself.
    ///
    /// For RSA keys the PKCS#8 OID (`rsaEncryption`) does not encode which
    /// signature hash to use — that's a property of the *signing* step,
    /// not the key. We sniff the modulus size to pick a sensible default
    /// (RSA-2048 → SHA-256, RSA-3072 → SHA-384, RSA-4096 → SHA-512) and
    /// rebuild the keypair with `from_pem_and_sign_algo` so the
    /// bit-size→hash convention round-trips through storage cleanly.
    pub fn from_pem(pem: &str) -> Result<Self, RvError> {
        // First, peek for RSA: the rsaEncryption OID is the first
        // discriminator we can check without going through rcgen.
        if let Some((alg, sign_alg)) = sniff_rsa_size(pem)? {
            let kp = KeyPair::from_pem_and_sign_algo(pem, sign_alg).map_err(rcgen_err)?;
            return Ok(Self { alg, inner: kp, pem: Zeroizing::new(pem.to_string()) });
        }
        let kp = KeyPair::from_pem(pem).map_err(rcgen_err)?;
        let alg = match kp.algorithm() {
            a if a == &rcgen::PKCS_ECDSA_P256_SHA256 => KeyAlgorithm::EcdsaP256,
            a if a == &rcgen::PKCS_ECDSA_P384_SHA384 => KeyAlgorithm::EcdsaP384,
            a if a == &rcgen::PKCS_ED25519 => KeyAlgorithm::Ed25519,
            // Fallback if rcgen recognised RSA before our sniff did
            // (shouldn't happen given the early-return above, but keep the
            // arms exhaustive).
            a if a == &rcgen::PKCS_RSA_SHA256 => KeyAlgorithm::Rsa2048,
            a if a == &rcgen::PKCS_RSA_SHA384 => KeyAlgorithm::Rsa3072,
            a if a == &rcgen::PKCS_RSA_SHA512 => KeyAlgorithm::Rsa4096,
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };
        Ok(Self { alg, inner: kp, pem: Zeroizing::new(pem.to_string()) })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.alg
    }

    pub fn key_pair(&self) -> &KeyPair {
        &self.inner
    }

    /// PKCS#8 PEM of the **private** key. Caller is responsible for not
    /// persisting this in plaintext outside the barrier.
    pub fn pem_pkcs8(&self) -> &str {
        self.pem.as_str()
    }

    pub fn public_key_pem(&self) -> String {
        self.inner.public_key_pem()
    }
}

/// Canonicalise an RSA private-key PEM into a strict PKCS#8 layout
/// rcgen / ring will accept. Returns the input unchanged for non-RSA
/// PEMs (passing them through to whichever downstream parser knows
/// the format) and for inputs we can't decode at all.
///
/// Rcgen ≥ 0.14 routes RSA through `ring`, which is stricter than the
/// `rsa` crate's parser:
///   * the algorithm OID must be plain `rsaEncryption`
///     (`1.2.840.113549.1.1.1`) — not `id-RSASSA-PSS`,
///   * the key must carry the full CRT tuple (p, q, dP, dQ, qInv),
///   * the public exponent must be 65537.
///
/// XCA databases (and some older OpenSSL exports) emit RSA keys in
/// shapes that `rsa-0.9` accepts but `ring` does not — most commonly
/// PKCS#1 RSAPrivateKey DER under a PKCS#8 PEM label, or PKCS#8
/// without CRT components. Both round-trip cleanly through
/// `rsa::RsaPrivateKey::to_pkcs8_pem`, which always emits the
/// canonical PKCS#8 with CRT and the rsaEncryption OID. Re-emitting
/// unconditionally (instead of only when the input parse fails)
/// catches the "PKCS#8 but missing CRT" case the previous version
/// missed.
fn normalise_to_pkcs8_pem(pem: &str) -> String {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    let trimmed = pem.trim();

    let pem_label = pem::parse(trimmed)
        .ok()
        .map(|p| p.tag().to_string())
        .unwrap_or_default();

    // RSA path: rsa-0.9 is permissive — any of the three shapes
    // succeeding means the input *is* RSA and the canonical re-emit
    // below puts it on the wire in the layout ring requires.
    let rsa_priv = if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
        Some(k)
    } else if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(trimmed) {
        Some(k)
    } else if let Ok(parsed) = pem::parse(trimmed) {
        RsaPrivateKey::from_pkcs1_der(parsed.contents()).ok()
    } else {
        None
    };
    if let Some(priv_key) = rsa_priv {
        let bits = priv_key.size() * 8;
        let e_bytes = priv_key.e().to_bytes_be();
        let e_display = if e_bytes.len() <= 8 {
            let mut v: u64 = 0;
            for &b in &e_bytes {
                v = (v << 8) | b as u64;
            }
            v.to_string()
        } else {
            format!("{}-byte big-int", e_bytes.len())
        };
        log::info!(
            "pki: normalising RSA key — pem_label={:?} modulus_bits={} e={}",
            pem_label,
            bits,
            e_display
        );
        return match priv_key.to_pkcs8_pem(LineEnding::LF) {
            Ok(p) => p.to_string(),
            Err(e) => {
                log::warn!("pki: RSA key parsed by rsa-0.9 but PKCS#8 re-emit failed: {e}");
                pem.to_string()
            }
        };
    }

    // SEC1 ECPrivateKey path: XCA pre-2.5 stores EC keys as bare
    // `i2d_ECPrivateKey` DER (no PKCS#8 wrapper, no AlgorithmIdentifier),
    // and the xca-import plugin labels every decrypted blob as
    // `PRIVATE KEY` regardless. ring's PKCS#8 EC parser refuses bare
    // SEC1 — the input must be wrapped in a `PrivateKeyInfo` carrying
    // `id-ecPublicKey` (1.2.840.10045.2.1) + the curve OID. Detect
    // SEC1 by structure (`SEQUENCE { INTEGER 1, OCTET STRING privKey,
    // [0] curve OID, [1] BIT STRING pub }`) and re-wrap.
    if let Ok(parsed) = pem::parse(trimmed) {
        if let Some(wrapped) = wrap_sec1_ec_as_pkcs8(parsed.contents()) {
            log::info!(
                "pki: normalising EC key — pem_label={:?} sec1 → PKCS#8 wrap",
                pem_label
            );
            return pem::encode(&pem::Pem::new("PRIVATE KEY", wrapped));
        }
    }

    log::info!(
        "pki: normalise_to_pkcs8_pem — input is neither RSA nor SEC1 EC; passing through (pem_label={:?})",
        pem_label
    );
    pem.to_string()
}

/// Wrap a bare SEC1 `ECPrivateKey` DER blob in a PKCS#8
/// `PrivateKeyInfo` with `id-ecPublicKey` + the curve OID extracted
/// from the SEC1 `[0] EXPLICIT ECParameters` field. Returns `None` if
/// the input doesn't look like SEC1 (no version=1 INTEGER + OCTET
/// STRING + tagged ECParameters).
fn wrap_sec1_ec_as_pkcs8(sec1_der: &[u8]) -> Option<Vec<u8>> {
    // Outer SEQUENCE → INTEGER version → OCTET STRING privateKey →
    // [0] EXPLICIT { OID curve } → [1] EXPLICIT { BIT STRING pub }.
    let (outer, _) = take_tlv(sec1_der, 0x30)?;
    let (version_int, after_version) = take_tlv(outer, 0x02)?;
    // Version must be `01` for ECPrivateKey (RFC 5915).
    if version_int != [0x01] {
        return None;
    }
    let (_priv_octet, after_priv) = take_tlv(after_version, 0x04)?;
    // [0] EXPLICIT ECParameters — find it by scanning the remaining
    // optional fields. Tag = 0xA0 (context-specific, constructed, 0).
    let mut rest = after_priv;
    let mut curve_oid: Option<Vec<u8>> = None;
    while !rest.is_empty() {
        let tag = rest[0];
        let (body, next) = take_tlv(rest, tag)?;
        if tag == 0xA0 {
            // Inside [0] EXPLICIT is an `ECParameters` CHOICE — for
            // named curves it's an OID directly.
            let (oid, _) = take_tlv(body, 0x06)?;
            curve_oid = Some(oid.to_vec());
            break;
        }
        rest = next;
    }
    let curve_oid = curve_oid?;

    // Build PKCS#8.
    //   PrivateKeyInfo ::= SEQUENCE {
    //     version           INTEGER (0),
    //     privateKeyAlg     AlgorithmIdentifier { OID id-ecPublicKey, OID curve },
    //     privateKey        OCTET STRING (containing original SEC1 DER)
    //   }
    const ID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    let mut alg_inner = Vec::new();
    alg_inner.push(0x06);
    push_der_length(&mut alg_inner, ID_EC_PUBLIC_KEY.len());
    alg_inner.extend_from_slice(ID_EC_PUBLIC_KEY);
    alg_inner.push(0x06);
    push_der_length(&mut alg_inner, curve_oid.len());
    alg_inner.extend_from_slice(&curve_oid);
    let mut alg_id = Vec::with_capacity(alg_inner.len() + 6);
    alg_id.push(0x30);
    push_der_length(&mut alg_id, alg_inner.len());
    alg_id.extend_from_slice(&alg_inner);

    let mut octet = Vec::with_capacity(sec1_der.len() + 6);
    octet.push(0x04);
    push_der_length(&mut octet, sec1_der.len());
    octet.extend_from_slice(sec1_der);

    let mut inner = Vec::with_capacity(3 + alg_id.len() + octet.len());
    inner.extend_from_slice(&[0x02, 0x01, 0x00]); // version INTEGER 0
    inner.extend_from_slice(&alg_id);
    inner.extend_from_slice(&octet);

    let mut out = Vec::with_capacity(inner.len() + 6);
    out.push(0x30);
    push_der_length(&mut out, inner.len());
    out.extend_from_slice(&inner);
    Some(out)
}

fn take_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if input.first() != Some(&expected_tag) {
        return None;
    }
    let len_byte = *input.get(1)?;
    let (len, header) = if len_byte < 0x80 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *input.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let total = header + len;
    if input.len() < total {
        return None;
    }
    Some((&input[header..total], &input[total..]))
}

fn push_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut buf = [0u8; 8];
    let mut n = len;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = (n & 0xff) as u8;
        n >>= 8;
    }
    let bytes = &buf[i..];
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(bytes);
}

/// Parse the modulus length (in bits) and public exponent (decimal
/// string) of an RSA private key from any of the shapes
/// [`normalise_to_pkcs8_pem`] understands. Returns `None` for
/// non-RSA / unparseable input. Output goes straight into operator-
/// facing error messages so the toast tells them what's incompatible.
fn sniff_rsa_shape(pem: &str) -> Option<(usize, String)> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    let trimmed = pem.trim();
    let priv_key = if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
        k
    } else if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(trimmed) {
        k
    } else if let Ok(parsed) = pem::parse(trimmed) {
        RsaPrivateKey::from_pkcs1_der(parsed.contents()).ok()?
    } else {
        return None;
    };
    let bits = priv_key.size() * 8;
    let e_bytes = priv_key.e().to_bytes_be();
    let exp = if e_bytes.len() <= 8 {
        let mut v: u64 = 0;
        for &b in &e_bytes {
            v = (v << 8) | b as u64;
        }
        v.to_string()
    } else {
        format!("{}-byte big-int", e_bytes.len())
    };
    Some((bits, exp))
}

/// Parse the PKCS#8 `AlgorithmIdentifier` OID from the supplied PEM /
/// DER. Returns the dotted-decimal representation, or `None` if the
/// blob doesn't look like PKCS#8. Used in the `Signer::from_storage_pem`
/// failure path so the operator sees *which* algorithm OID their key
/// carries — `1.2.840.113549.1.1.1` (rsaEncryption, expected),
/// `1.2.840.113549.1.1.10` (RSASSA-PSS — ring rejects), or something
/// more exotic.
fn sniff_pkcs8_algorithm_oid(pem: &str) -> Option<String> {
    let parsed = pem::parse(pem.trim()).ok()?;
    let der = parsed.contents();
    // PrivateKeyInfo := SEQUENCE { INT version, AlgorithmIdentifier { OID, ... }, ... }
    // Walk the outer SEQUENCE → version INTEGER → algorithm SEQUENCE → OID.
    fn take_tlv<'a>(input: &'a [u8], expected: u8) -> Option<(&'a [u8], &'a [u8])> {
        if input.first() != Some(&expected) {
            return None;
        }
        let len_byte = *input.get(1)?;
        let (len, header) = if len_byte < 0x80 {
            (len_byte as usize, 2)
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | *input.get(2 + i)? as usize;
            }
            (len, 2 + n)
        };
        let total = header + len;
        if input.len() < total {
            return None;
        }
        Some((&input[header..total], &input[total..]))
    }
    let (outer, _) = take_tlv(der, 0x30)?;
    let (_version, after_version) = take_tlv(outer, 0x02)?;
    let (alg_seq, _) = take_tlv(after_version, 0x30)?;
    let (oid_bytes, _) = take_tlv(alg_seq, 0x06)?;
    // Decode dotted-decimal. First byte = first*40 + second; remainder
    // are base-128 with continuation bit.
    let mut out = String::new();
    let first = *oid_bytes.first()?;
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!("{}.{}", first / 40, first % 40),
    );
    let mut acc: u64 = 0;
    for &b in &oid_bytes[1..] {
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!(".{}", acc));
            acc = 0;
        }
    }
    Some(out)
}

pub(crate) fn rcgen_err(e: rcgen::Error) -> RvError {
    // Surface the rcgen detail through the wire response (it already
    // gets logged here for server-side correlation). The previous shape
    // returned a bare `ErrPkiInternal` whose Display is "PKI internal
    // error." — useless for diagnosing why a specific RSA key was
    // rejected on import (e.g. unsupported PEM label, RSA-1024 sniffed
    // as 2048-routed, non-CRT layout, exponent != 65537, etc.). The
    // operator needs the rcgen message; logs only help when the
    // operator can read them.
    let msg = e.to_string();
    log::error!("pki: rcgen error: {msg}");
    RvError::ErrString(format!("pki: rcgen rejected key/cert: {msg}"))
}

/// Try to parse `pem` as an RSA PKCS#8 PEM and return the matching
/// `(KeyAlgorithm, &'static SignatureAlgorithm)` based on the RSA modulus
/// size. Returns `Ok(None)` when the PEM is not RSA — caller falls
/// through to the rcgen path.
fn sniff_rsa_size(
    pem: &str,
) -> Result<Option<(KeyAlgorithm, &'static rcgen::SignatureAlgorithm)>, RvError> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    let priv_key = match RsaPrivateKey::from_pkcs8_pem(pem) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    let bits = priv_key.size() * 8;
    Ok(Some(match bits {
        2048 => (KeyAlgorithm::Rsa2048, &rcgen::PKCS_RSA_SHA256),
        3072 => (KeyAlgorithm::Rsa3072, &rcgen::PKCS_RSA_SHA384),
        4096 => (KeyAlgorithm::Rsa4096, &rcgen::PKCS_RSA_SHA512),
        // Operator imported a non-standard size: route as RSA-2048 with
        // SHA-256 (the most permissive verifier compatibility) rather
        // than rejecting outright. Logging makes this visible.
        other => {
            log::warn!("pki: imported RSA key has non-standard {other}-bit modulus; using PKCS_RSA_SHA256");
            (KeyAlgorithm::Rsa2048, &rcgen::PKCS_RSA_SHA256)
        }
    }))
}

/// Unified handle for the CA's signing key — either a classical
/// rcgen-backed [`CertSigner`] or a Phase-2 [`MlDsaSigner`]. The path handlers
/// hold this and dispatch to the matching X.509 builder.
pub enum Signer {
    Classical(CertSigner),
    MlDsa(MlDsaSigner),
    /// Composite (hybrid) signer pairing one classical and one PQC half. See
    /// [`super::composite`] for the format and feature-flag context.
    #[cfg(feature = "pki_pqc_composite")]
    Composite(CompositeSigner),
}

impl Signer {
    pub fn generate(alg: KeyAlgorithm) -> Result<Self, RvError> {
        #[cfg(feature = "pki_pqc_composite")]
        if matches!(
            alg,
            KeyAlgorithm::CompositeEcdsaP256MlDsa44
                | KeyAlgorithm::CompositeEcdsaP256MlDsa65
                | KeyAlgorithm::CompositeEcdsaP384MlDsa87
        ) {
            return Ok(Self::Composite(CompositeSigner::generate(alg)?));
        }
        match alg.ml_dsa_level() {
            Some(level) => Ok(Self::MlDsa(MlDsaSigner::generate(level)?)),
            None => Ok(Self::Classical(CertSigner::generate(alg)?)),
        }
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Classical(s) => s.algorithm(),
            Self::MlDsa(s) => match s.level() {
                MlDsaLevel::L44 => KeyAlgorithm::MlDsa44,
                MlDsaLevel::L65 => KeyAlgorithm::MlDsa65,
                MlDsaLevel::L87 => KeyAlgorithm::MlDsa87,
            },
            #[cfg(feature = "pki_pqc_composite")]
            Self::Composite(s) => s.algorithm(),
        }
    }

    /// Storage round-trip: caller persists this string as the CA private key
    /// (barrier-encrypted at the storage layer). The dispatch on read is a
    /// string prefix sniff — composite envelopes carry their own marker, PQC
    /// has its own, and everything else falls through to PKCS#8 PEM.
    pub fn to_storage_pem(&self) -> String {
        match self {
            Self::Classical(s) => s.pem_pkcs8().to_string(),
            Self::MlDsa(s) => s.to_storage_pem(),
            #[cfg(feature = "pki_pqc_composite")]
            Self::Composite(s) => s.to_storage_pem(),
        }
    }

    pub fn from_storage_pem(pem: &str) -> Result<Self, RvError> {
        #[cfg(feature = "pki_pqc_composite")]
        if CompositeSigner::is_storage_pem(pem) {
            return Ok(Self::Composite(CompositeSigner::from_storage_pem(pem)?));
        }
        if MlDsaSigner::is_storage_pem(pem) {
            return Ok(Self::MlDsa(MlDsaSigner::from_storage_pem(pem)?));
        }
        // PKCS#8 PQC import (Phase 5.3+): an operator-supplied
        // `-----BEGIN PRIVATE KEY-----` whose AlgorithmIdentifier OID is
        // one of the ML-DSA levels routes through the PQC path before the
        // classical fallback. Classical PKCS#8 keys (RSA / ECDSA /
        // Ed25519) fall through to the rcgen branch unchanged.
        if MlDsaSigner::is_pkcs8_pem(pem) {
            return Ok(Self::MlDsa(MlDsaSigner::from_pkcs8_pem(pem)?));
        }
        // Normalise legacy / mislabelled PEMs to PKCS#8 before handing
        // off to rcgen. rcgen's `from_pem_and_sign_algo` is PKCS#8-only,
        // but operators show up with two non-PKCS#8 shapes for RSA:
        //   1) `-----BEGIN RSA PRIVATE KEY-----` carrying PKCS#1 DER
        //      (OpenSSL `genrsa` default; XCA pre-2.0 storage).
        //   2) `-----BEGIN PRIVATE KEY-----` whose body is actually
        //      PKCS#1 DER, not PrivateKeyInfo (XCA's xca-import plugin
        //      labels every decrypted blob as PKCS#8 regardless of
        //      what the inner DER is).
        // Both round-trip cleanly through rsa 0.9's PKCS#1 decoder +
        // PKCS#8 re-emit. Non-RSA / actually-PKCS#8 PEMs fall through.
        let normalised = normalise_to_pkcs8_pem(pem);
        match CertSigner::from_pem(&normalised) {
            Ok(s) => Ok(Self::Classical(s)),
            Err(e) => {
                // Decorate the rcgen failure with whatever we can read
                // off the key, directly in the error string the GUI
                // toast renders. The dev-console log lines from
                // `normalise_to_pkcs8_pem` are also emitted, but those
                // only help an operator with terminal access — the
                // toast needs the diagnosis self-contained.
                let oid = sniff_pkcs8_algorithm_oid(&normalised).unwrap_or_default();
                let key_shape = sniff_rsa_shape(&normalised);
                log::warn!(
                    "pki: from_storage_pem rejected — algorithm OID {oid:?}, shape {key_shape:?}: {e}"
                );
                // Specific OID-driven errors first (most actionable).
                if oid == "1.2.840.113549.1.1.10" {
                    return Err(RvError::ErrString(
                        "key uses RSASSA-PSS algorithm OID; the embedded \
                         ring crypto provider only accepts plain rsaEncryption \
                         (1.2.840.113549.1.1.1). Re-key the CA without RSA-PSS \
                         parameters, or use an HSM that signs externally."
                            .into(),
                    ));
                }
                if !oid.is_empty() && oid != "1.2.840.113549.1.1.1" {
                    return Err(RvError::ErrString(format!(
                        "key uses non-rsaEncryption algorithm OID {oid}; \
                         the embedded crypto provider does not support it"
                    )));
                }
                // OID is rsaEncryption (or unreadable) but rcgen / ring
                // still rejected. Embed the modulus / exponent so the
                // operator can see whether it's an exotic size or a
                // non-65537 exponent — the two other things ring is
                // strict about.
                let detail = match key_shape {
                    Some((bits, ref exp)) => {
                        let exp_note = if exp == "65537" {
                            String::new()
                        } else {
                            format!(", non-standard exponent e={exp} (ring requires e=65537)")
                        };
                        let size_note = if matches!(bits, 2048 | 3072 | 4096) {
                            String::new()
                        } else {
                            format!(
                                ", modulus {bits} bits is outside ring's supported \
                                 sizes {{2048, 3072, 4096}}"
                            )
                        };
                        format!(" (RSA {bits}-bit{exp_note}{size_note})")
                    }
                    None => " (could not introspect key shape)".to_string(),
                };
                Err(RvError::ErrString(format!(
                    "ring rejected RSA key{detail}; bare rcgen error: {e}"
                )))
            }
        }
    }

    /// Caller-facing PKCS#8 PEM. This is what the engine returns over the
    /// API as `private_key` on `pki/issue` / `pki/intermediate/generate
    /// /exported` / `pki/root/generate/exported`. PQC keys use the IETF
    /// lamps draft layout (PrivateKeyInfo wrapping the 32-byte seed);
    /// classical keys use the standard rcgen-emitted PKCS#8 PEM.
    ///
    /// Distinct from [`to_storage_pem`](Self::to_storage_pem), which is
    /// the engine-internal storage envelope (barrier-encrypted) and uses
    /// the legacy `BV PQC SIGNER` form for PQC. Storage stays on the
    /// internal envelope so existing on-disk material reads cleanly; only
    /// the API output gains the PKCS#8 form.
    pub fn to_pkcs8_pem(&self) -> Result<String, RvError> {
        match self {
            Self::Classical(s) => Ok(s.pem_pkcs8().to_string()),
            Self::MlDsa(s) => Ok(s.to_pkcs8_pem()?.to_string()),
            #[cfg(feature = "pki_pqc_composite")]
            Self::Composite(_) => {
                // Composite key serialization is not standardised yet — the
                // IETF draft has not stabilised on a PKCS#8 layout for
                // composite private keys. Return the storage envelope as a
                // best-effort caller-facing form until the draft locks.
                Ok(self.to_storage_pem())
            }
        }
    }

    pub fn classical(&self) -> Option<&CertSigner> {
        match self {
            Self::Classical(s) => Some(s),
            _ => None,
        }
    }

    pub fn ml_dsa(&self) -> Option<&MlDsaSigner> {
        match self {
            Self::MlDsa(s) => Some(s),
            _ => None,
        }
    }

    #[cfg(feature = "pki_pqc_composite")]
    pub fn composite(&self) -> Option<&CompositeSigner> {
        match self {
            Self::Composite(s) => Some(s),
            _ => None,
        }
    }
}
