//! Post-quantum signers for the PKI engine — ML-DSA-44 / 65 / 87.
//!
//! `rcgen` 0.14's built-in ML-DSA support is gated behind `aws_lc_rs_unstable`,
//! which pulls `aws-lc-sys` — explicitly forbidden by
//! [`features/pki-secret-engine.md`](../../../features/pki-secret-engine.md).
//! So Phase 2 sidesteps rcgen for PQC entirely: the leaf/root TBSCertificate
//! and CRL TbsCertList are assembled with `x509-cert` + `der` (see
//! [`x509_pqc`](super::x509_pqc)), and the DER bytes are signed with
//! [`fips204`](https://crates.io/crates/fips204) wrapped in `bv_crypto`.
//!
//! This module owns:
//! - the OID table for the three security levels (RFC draft IETF lamps),
//! - the [`MlDsaLevel`] enum role configs map onto,
//! - the [`MlDsaSigner`] struct (seed + cached public key + level), and
//! - a small custom PEM envelope used for sealed storage round-tripping.

use base64::{engine::general_purpose::STANDARD, Engine};
use bv_crypto::{MlDsa44Provider, MlDsa65Provider, MlDsa87Provider};
use const_oid::ObjectIdentifier;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::errors::RvError;

/// IETF lamps draft OIDs (`2.16.840.1.101.3.4.3.{17,18,19}`). These are the
/// same OIDs `rcgen` uses internally for `PKCS_ML_DSA_*`; pinned here so the
/// engine's PQC certs interoperate when verifiers eventually gain ML-DSA
/// support.
pub const OID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
pub const OID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
pub const OID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// One of the three NIST security levels. Selected by the role's `key_type`
/// field (`ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlDsaLevel {
    L44,
    L65,
    L87,
}

impl MlDsaLevel {
    pub fn from_role(key_type: &str) -> Option<Self> {
        match key_type {
            "ml-dsa-44" => Some(Self::L44),
            "ml-dsa-65" => Some(Self::L65),
            "ml-dsa-87" => Some(Self::L87),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::L44 => "ml-dsa-44",
            Self::L65 => "ml-dsa-65",
            Self::L87 => "ml-dsa-87",
        }
    }

    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::L44 => OID_ML_DSA_44,
            Self::L65 => OID_ML_DSA_65,
            Self::L87 => OID_ML_DSA_87,
        }
    }
}

/// Sealed-storage envelope. We do not use a standard PKCS#8 OID for the seed
/// because the IETF-LAMPS draft for ML-DSA `OneAsymmetricKey` was still in
/// flux at write-time and we want a forward-compatible internal format that
/// does not get baked into on-disk state. The envelope is engine-internal —
/// it is barrier-encrypted at rest and never returned over the API.
const PEM_LABEL: &str = "BV PQC SIGNER";

#[derive(Debug, Serialize, Deserialize)]
struct StorageEnvelope {
    alg: String,
    seed_b64: String,
    public_key_b64: String,
}

/// The signer the PKI engine hands to the PQC X.509 builder. The seed
/// regenerates the private key on demand so the long-lived in-memory secret
/// stays small (32 bytes) and zeroized on drop.
#[derive(Clone)]
pub struct MlDsaSigner {
    level: MlDsaLevel,
    seed: Zeroizing<[u8; 32]>,
    public_key: Vec<u8>,
}

impl MlDsaSigner {
    pub fn generate(level: MlDsaLevel) -> Result<Self, RvError> {
        match level {
            MlDsaLevel::L44 => {
                let kp = MlDsa44Provider.generate_keypair().map_err(pqc_err)?;
                Ok(Self {
                    level,
                    seed: Zeroizing::new(*kp.secret_seed()),
                    public_key: kp.public_key().to_vec(),
                })
            }
            MlDsaLevel::L65 => {
                let kp = MlDsa65Provider.generate_keypair().map_err(pqc_err)?;
                Ok(Self {
                    level,
                    seed: Zeroizing::new(*kp.secret_seed()),
                    public_key: kp.public_key().to_vec(),
                })
            }
            MlDsaLevel::L87 => {
                let kp = MlDsa87Provider.generate_keypair().map_err(pqc_err)?;
                Ok(Self {
                    level,
                    seed: Zeroizing::new(*kp.secret_seed()),
                    public_key: kp.public_key().to_vec(),
                })
            }
        }
    }

    pub fn level(&self) -> MlDsaLevel {
        self.level
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign `message` with an empty context (Vault parity — no caller-supplied
    /// context octets in the PKI engine). The caller passes the DER bytes of
    /// the TBSCertificate or TBSCertList directly.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RvError> {
        match self.level {
            MlDsaLevel::L44 => MlDsa44Provider.sign(self.seed.as_slice(), message, &[]).map_err(pqc_err),
            MlDsaLevel::L65 => MlDsa65Provider.sign(self.seed.as_slice(), message, &[]).map_err(pqc_err),
            MlDsaLevel::L87 => MlDsa87Provider.sign(self.seed.as_slice(), message, &[]).map_err(pqc_err),
        }
    }

    /// Serialize for sealed storage. Output is a PEM-wrapped JSON envelope.
    pub fn to_storage_pem(&self) -> String {
        let env = StorageEnvelope {
            alg: self.level.as_str().to_string(),
            seed_b64: STANDARD.encode(self.seed.as_slice()),
            public_key_b64: STANDARD.encode(&self.public_key),
        };
        let json = serde_json::to_string(&env).unwrap_or_default();
        let body = STANDARD.encode(json.as_bytes());
        let mut wrapped = String::with_capacity(body.len() + 64);
        wrapped.push_str("-----BEGIN ");
        wrapped.push_str(PEM_LABEL);
        wrapped.push_str("-----\n");
        for chunk in body.as_bytes().chunks(64) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap());
            wrapped.push('\n');
        }
        wrapped.push_str("-----END ");
        wrapped.push_str(PEM_LABEL);
        wrapped.push_str("-----\n");
        wrapped
    }

    /// Heuristic used by the unified [`Signer`](super::crypto::Signer) loader
    /// to dispatch storage PEM to the PQC path.
    pub fn is_storage_pem(s: &str) -> bool {
        s.contains("-----BEGIN BV PQC SIGNER-----")
    }

    pub fn from_storage_pem(pem: &str) -> Result<Self, RvError> {
        let begin = pem.find("-----BEGIN BV PQC SIGNER-----").ok_or(RvError::ErrPkiPemBundleInvalid)?;
        let end = pem.find("-----END BV PQC SIGNER-----").ok_or(RvError::ErrPkiPemBundleInvalid)?;
        let body_start = pem[begin..].find('\n').map(|i| begin + i + 1).ok_or(RvError::ErrPkiPemBundleInvalid)?;
        let body = pem[body_start..end].chars().filter(|c| !c.is_whitespace()).collect::<String>();
        let json_bytes = STANDARD.decode(body.as_bytes()).map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let env: StorageEnvelope = serde_json::from_slice(&json_bytes).map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let level = MlDsaLevel::from_role(&env.alg).ok_or(RvError::ErrPkiKeyTypeInvalid)?;
        let seed_vec = STANDARD.decode(env.seed_b64.as_bytes()).map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let seed: [u8; 32] = seed_vec.try_into().map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let public_key = STANDARD.decode(env.public_key_b64.as_bytes()).map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        Ok(Self { level, seed: Zeroizing::new(seed), public_key })
    }
}

fn pqc_err(e: bv_crypto::CryptoError) -> RvError {
    log::error!("pki/pqc: {e:?}");
    RvError::ErrPkiInternal
}
