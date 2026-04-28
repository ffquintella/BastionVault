//! Key types and capability matrix.
//!
//! The capability table is the authoritative answer to "can this key
//! be used for X?" — every path handler that performs a crypto op
//! checks the capability before touching key material. Forbidding an
//! op at this layer (rather than failing inside the algorithm impl)
//! gives a clear, uniform error message and prevents algorithm
//! misuse from compiling silently.

use serde::{Deserialize, Serialize};

use crate::errors::RvError;

/// One discriminant per concrete algorithm. Vault parity for the names
/// where applicable (`aes256-gcm96`, `chacha20-poly1305`, ...). PQC
/// names follow the FIPS spec (`ml-kem-768`, `ml-dsa-65`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyType {
    // ── Symmetric AEAD ────────────────────────────────────────────
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,

    // ── Symmetric MAC ─────────────────────────────────────────────
    Hmac,

    // ── Asymmetric signing (classical) ────────────────────────────
    Ed25519,

    // ── Asymmetric KEM (PQC) ──────────────────────────────────────
    #[serde(rename = "ml-kem-768")]
    MlKem768,

    // ── Asymmetric signing (PQC) ──────────────────────────────────
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,

    // ── Hybrid (composite) — Phase 4, feature-gated ───────────────
    #[cfg(feature = "transit_pqc_hybrid")]
    #[serde(rename = "hybrid-ed25519+ml-dsa-65")]
    HybridEd25519MlDsa65,
    #[cfg(feature = "transit_pqc_hybrid")]
    #[serde(rename = "hybrid-x25519+ml-kem-768")]
    HybridX25519MlKem768,
}

impl KeyType {
    pub fn parse(s: &str) -> Result<Self, RvError> {
        match s {
            "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            "hmac" => Ok(Self::Hmac),
            "ed25519" => Ok(Self::Ed25519),
            "ml-kem-768" => Ok(Self::MlKem768),
            "ml-dsa-44" => Ok(Self::MlDsa44),
            "ml-dsa-65" => Ok(Self::MlDsa65),
            "ml-dsa-87" => Ok(Self::MlDsa87),
            #[cfg(feature = "transit_pqc_hybrid")]
            "hybrid-ed25519+ml-dsa-65" => Ok(Self::HybridEd25519MlDsa65),
            #[cfg(feature = "transit_pqc_hybrid")]
            "hybrid-x25519+ml-kem-768" => Ok(Self::HybridX25519MlKem768),
            other => Err(RvError::ErrString(format!(
                "unsupported key_type `{other}`; \
                 supported: chacha20-poly1305, hmac, ed25519, \
                 ml-kem-768, ml-dsa-44, ml-dsa-65, ml-dsa-87 \
                 (and hybrid-* with the `transit_pqc_hybrid` build feature)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::Hmac => "hmac",
            Self::Ed25519 => "ed25519",
            Self::MlKem768 => "ml-kem-768",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridEd25519MlDsa65 => "hybrid-ed25519+ml-dsa-65",
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridX25519MlKem768 => "hybrid-x25519+ml-kem-768",
        }
    }

    /// True for symmetric AEAD keys (encrypt + decrypt).
    pub fn is_symmetric_aead(self) -> bool {
        matches!(self, Self::Chacha20Poly1305)
    }

    /// True for keys that participate in encrypt/decrypt at all.
    pub fn supports_encrypt(self) -> bool {
        match self {
            Self::Chacha20Poly1305 | Self::MlKem768 => true,
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridX25519MlKem768 => true,
            _ => false,
        }
    }

    /// True for keys that produce signatures.
    pub fn supports_sign(self) -> bool {
        match self {
            Self::Ed25519 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => true,
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridEd25519MlDsa65 => true,
            _ => false,
        }
    }

    /// True for keys that can produce HMACs.
    pub fn supports_hmac(self) -> bool {
        matches!(self, Self::Hmac | Self::Chacha20Poly1305)
    }

    /// True if the key type can produce a wrapped datakey. Symmetric
    /// AEAD keys cannot — `datakey` is the asymmetric-wrap primitive.
    pub fn supports_datakey(self) -> bool {
        match self {
            Self::MlKem768 => true,
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridX25519MlKem768 => true,
            _ => false,
        }
    }

    /// True if the public material can be returned safely. `Hmac` and
    /// `Chacha20Poly1305` are symmetric — there is no public half.
    pub fn has_public_material(self) -> bool {
        match self {
            Self::Ed25519 | Self::MlKem768 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => true,
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridEd25519MlDsa65 | Self::HybridX25519MlKem768 => true,
            _ => false,
        }
    }

    /// Wire-format algorithm tag used in the `bvault:vN:pqc:<algo>:...`
    /// framing. Empty for classical symmetric (Vault-shape `bvault:vN:`).
    pub fn pqc_wire_tag(self) -> Option<&'static str> {
        match self {
            Self::MlKem768 => Some("ml-kem-768"),
            Self::MlDsa44 => Some("ml-dsa-44"),
            Self::MlDsa65 => Some("ml-dsa-65"),
            Self::MlDsa87 => Some("ml-dsa-87"),
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridEd25519MlDsa65 => Some("hybrid-ed25519+ml-dsa-65"),
            #[cfg(feature = "transit_pqc_hybrid")]
            Self::HybridX25519MlKem768 => Some("hybrid-x25519+ml-kem-768"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip() {
        for kt in [
            KeyType::Chacha20Poly1305,
            KeyType::Hmac,
            KeyType::Ed25519,
            KeyType::MlKem768,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
            KeyType::MlDsa87,
        ] {
            assert_eq!(KeyType::parse(kt.as_str()).unwrap(), kt);
        }
    }

    #[test]
    fn capabilities_are_disjoint_for_sign_vs_encrypt() {
        // No key supports both signing and encryption simultaneously.
        // This is the property that path handlers rely on to refuse
        // misuse.
        for kt in [
            KeyType::Chacha20Poly1305,
            KeyType::Hmac,
            KeyType::Ed25519,
            KeyType::MlKem768,
            KeyType::MlDsa65,
        ] {
            assert!(
                !(kt.supports_sign() && kt.supports_encrypt()),
                "{kt:?} claims both sign and encrypt — algorithm misuse possible"
            );
        }
    }
}
