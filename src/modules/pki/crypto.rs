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
    /// Composite ECDSA-P256 + ML-DSA-65. Phase 3 preview, gated behind the
    /// `pki_pqc_composite` feature.
    #[cfg(feature = "pki_pqc_composite")]
    CompositeEcdsaP256MlDsa65,
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
            ("ecdsa-p256+ml-dsa-65", 0) => Ok(Self::CompositeEcdsaP256MlDsa65),
            #[cfg(feature = "pki_pqc_composite")]
            ("ecdsa-p256+ml-dsa-65", _) => Err(RvError::ErrPkiKeyBitsInvalid),
            ("rsa", _) => Err(RvError::ErrPkiKeyBitsInvalid),
            ("ec", _) => Err(RvError::ErrPkiKeyBitsInvalid),
            _ => Err(RvError::ErrPkiKeyTypeInvalid),
        }
    }

    pub fn class(self) -> AlgorithmClass {
        match self {
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => AlgorithmClass::Pqc,
            #[cfg(feature = "pki_pqc_composite")]
            Self::CompositeEcdsaP256MlDsa65 => AlgorithmClass::Composite,
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
            Self::CompositeEcdsaP256MlDsa65 => "ecdsa-p256+ml-dsa-65",
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
            Self::CompositeEcdsaP256MlDsa65 => 0,
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
            Self::CompositeEcdsaP256MlDsa65 => return Err(RvError::ErrPkiKeyTypeInvalid),
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
        // RSA generation is not available through `rcgen`'s default crypto
        // provider; reject early with a clear error rather than panicking
        // mid-issuance. Phase 2 will plug a `rsa` crate-backed generator
        // directly into rcgen's `SigningKey` trait.
        if matches!(alg, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096) {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }
        let kp = KeyPair::generate_for(alg.rcgen_alg()?).map_err(rcgen_err)?;
        let pem = Zeroizing::new(kp.serialize_pem());
        Ok(Self { alg, inner: kp, pem })
    }

    /// Reconstruct a signer from its serialized PKCS#8 PEM (as produced by
    /// `pem_pkcs8`). Algorithm is recovered from the keypair itself.
    pub fn from_pem(pem: &str) -> Result<Self, RvError> {
        let kp = KeyPair::from_pem(pem).map_err(rcgen_err)?;
        let alg = match kp.algorithm() {
            a if a == &rcgen::PKCS_ECDSA_P256_SHA256 => KeyAlgorithm::EcdsaP256,
            a if a == &rcgen::PKCS_ECDSA_P384_SHA384 => KeyAlgorithm::EcdsaP384,
            a if a == &rcgen::PKCS_ED25519 => KeyAlgorithm::Ed25519,
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
        if matches!(alg, KeyAlgorithm::CompositeEcdsaP256MlDsa65) {
            return Ok(Self::Composite(CompositeSigner::generate()?));
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
            Self::Composite(_) => KeyAlgorithm::CompositeEcdsaP256MlDsa65,
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
            Ok(Self::MlDsa(MlDsaSigner::from_storage_pem(pem)?))
        } else {
            Ok(Self::Classical(CertSigner::from_pem(pem)?))
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
