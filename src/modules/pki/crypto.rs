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
        use pkcs8::{EncodePrivateKey, LineEnding};
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

pub(crate) fn rcgen_err(e: rcgen::Error) -> RvError {
    log::error!("pki: rcgen error: {e}");
    RvError::ErrPkiInternal
}

/// Try to parse `pem` as an RSA PKCS#8 PEM and return the matching
/// `(KeyAlgorithm, &'static SignatureAlgorithm)` based on the RSA modulus
/// size. Returns `Ok(None)` when the PEM is not RSA — caller falls
/// through to the rcgen path.
fn sniff_rsa_size(
    pem: &str,
) -> Result<Option<(KeyAlgorithm, &'static rcgen::SignatureAlgorithm)>, RvError> {
    use pkcs8::DecodePrivateKey;
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
        Ok(Self::Classical(CertSigner::from_pem(pem)?))
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
