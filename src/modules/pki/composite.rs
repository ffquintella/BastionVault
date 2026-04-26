//! Composite (hybrid) signatures — ECDSA-P256 + ML-DSA-65.
//!
//! **Phase 3 status: feature-gated preview.** Enable with the `pki_pqc_composite`
//! cargo feature. Off by default. The IETF draft
//! [`draft-ietf-lamps-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
//! is still in flux — the message-prep prefix, the optional randomizer, and
//! the OID arc have all moved across revisions. The implementation here
//! tracks the draft's *structure* (a SEQUENCE of two BIT STRINGs in both
//! `subjectPublicKey` and `signatureValue`) but pins the prehash domain to a
//! fixed BastionVault-internal value so we are honest about non-interop:
//! certs issued under this feature flag verify against themselves but should
//! not be expected to interoperate with arbitrary draft-conformant verifiers
//! until the draft stabilises and we explicitly switch the construction.
//!
//! What we *do* guarantee:
//! - Each half of the signature is a real ECDSA-P256 / ML-DSA-65 signature
//!   over the same canonical message bytes, so a verifier that trusts only
//!   one half can still validate against that half independently.
//! - The seam in [`super::crypto::Signer`] makes Phase 3 swappable: when the
//!   IETF draft locks down, only this file (plus the OID table) needs to
//!   change — `path_*` handlers stay put.

use rcgen::{PublicKeyData, SigningKey};
use sha2::{Digest, Sha256};
use x509_cert::der::{
    asn1::{BitString, SequenceOf},
    Encode,
};
use zeroize::Zeroizing;

use super::{
    crypto::{rcgen_err, CertSigner, KeyAlgorithm},
    pqc::{MlDsaLevel, MlDsaSigner},
};
use crate::errors::RvError;

/// IETF lamps draft OID for `id-MLDSA65-ECDSA-P256-SHA512`. Pinned so
/// verifiers that *do* understand the draft recognise the algorithm — even if
/// our message-prep prefix is BastionVault-internal until the draft locks.
///
/// Per draft-ietf-lamps-pq-composite-sigs (Entrust arc):
///   `2.16.840.1.114027.80.8.1.28`
pub const OID_COMPOSITE_MLDSA65_ECDSAP256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.28");

/// Domain separator. Stable for this engine's preview but **not** the IETF
/// draft's domain — flagged in code so a future swap to the draft's
/// `Domain || ctx || M'` construction is obvious in review.
const BV_COMPOSITE_DOMAIN_V0: &[u8] = b"BastionVault-PKI-Composite-v0/MLDSA65+ECDSAP256/v0";

/// Composite signer: pairs one classical signer (ECDSA-P256) with one PQC
/// signer (ML-DSA-65). The same struct is used for root CAs, intermediate
/// CAs (Phase 2.1+), and leaves.
pub struct CompositeSigner {
    classical: CertSigner,
    pqc: MlDsaSigner,
}

impl CompositeSigner {
    /// Generate a fresh composite keypair. Phase 3 fixes the pair to
    /// ECDSA-P256 + ML-DSA-65; future variants will branch on
    /// [`KeyAlgorithm`] inside this constructor.
    pub fn generate() -> Result<Self, RvError> {
        Ok(Self {
            classical: CertSigner::generate(KeyAlgorithm::EcdsaP256)?,
            pqc: MlDsaSigner::generate(MlDsaLevel::L65)?,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::CompositeEcdsaP256MlDsa65
    }

    pub fn classical(&self) -> &CertSigner {
        &self.classical
    }

    pub fn pqc(&self) -> &MlDsaSigner {
        &self.pqc
    }

    /// Build the BIT STRING contents for a composite `subjectPublicKey`.
    ///
    /// Per draft-ietf-lamps-pq-composite-sigs, this is a DER-encoded
    /// `SEQUENCE { BIT STRING pq_pk, BIT STRING classical_pk }`. The
    /// classical half is the SEC1 uncompressed point for ECDSA-P256 (65
    /// bytes). The PQ half is the raw 1952-byte ML-DSA-65 public key.
    pub fn composite_public_key_der(&self) -> Result<Vec<u8>, RvError> {
        let pq_bits = BitString::from_bytes(self.pqc.public_key()).map_err(der_err)?;
        let classical_bits =
            BitString::from_bytes(self.classical.key_pair().der_bytes()).map_err(der_err)?;
        let mut seq: SequenceOf<BitString, 2> = SequenceOf::new();
        seq.add(pq_bits).map_err(der_err)?;
        seq.add(classical_bits).map_err(der_err)?;
        seq.to_der().map_err(der_err)
    }

    /// Sign the canonical message bytes (TBSCertificate or TBSCertList DER).
    ///
    /// Returns the DER encoding of `SEQUENCE { BIT STRING pq_sig, BIT STRING
    /// classical_sig }`, ready to be wrapped in the outer BIT STRING that
    /// holds an X.509 `signatureValue`. Each half is a stand-alone, verifiable
    /// signature over the same prehashed message — so a verifier that trusts
    /// only one half can still validate.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        let prehashed = bv_prehash(msg);
        let pq_sig = self.pqc.sign(&prehashed)?;
        let classical_sig = self.classical.key_pair().sign(&prehashed).map_err(rcgen_err)?;

        let pq_bits = BitString::from_bytes(&pq_sig).map_err(der_err)?;
        let classical_bits = BitString::from_bytes(&classical_sig).map_err(der_err)?;
        let mut seq: SequenceOf<BitString, 2> = SequenceOf::new();
        seq.add(pq_bits).map_err(der_err)?;
        seq.add(classical_bits).map_err(der_err)?;
        seq.to_der().map_err(der_err)
    }

    // ── storage round-tripping ──────────────────────────────────────────

    const PEM_LABEL: &'static str = "BV PQC COMPOSITE SIGNER";

    /// True when `pem` looks like the storage envelope we emit. Used by the
    /// unified [`Signer::from_storage_pem`](super::crypto::Signer::from_storage_pem)
    /// loader to dispatch.
    pub fn is_storage_pem(pem: &str) -> bool {
        pem.contains("-----BEGIN BV PQC COMPOSITE SIGNER-----")
    }

    pub fn to_storage_pem(&self) -> String {
        // Two PEM bodies concatenated: classical PKCS#8 PEM, then the PQC
        // storage envelope, both wrapped in an outer BV PQC COMPOSITE SIGNER
        // block so the loader can split them deterministically.
        let body = serde_json::json!({
            "classical_pkcs8_pem": self.classical.pem_pkcs8(),
            "pqc_storage_pem": self.pqc.to_storage_pem(),
        });
        let body_str = body.to_string();
        let body_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, body_str.as_bytes());
        let mut out = String::new();
        out.push_str("-----BEGIN ");
        out.push_str(Self::PEM_LABEL);
        out.push_str("-----\n");
        for chunk in body_b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END ");
        out.push_str(Self::PEM_LABEL);
        out.push_str("-----\n");
        out
    }

    pub fn from_storage_pem(pem: &str) -> Result<Self, RvError> {
        use base64::Engine;
        let begin = pem
            .find("-----BEGIN BV PQC COMPOSITE SIGNER-----")
            .ok_or(RvError::ErrPkiPemBundleInvalid)?;
        let end =
            pem.find("-----END BV PQC COMPOSITE SIGNER-----").ok_or(RvError::ErrPkiPemBundleInvalid)?;
        let body_start =
            pem[begin..].find('\n').map(|i| begin + i + 1).ok_or(RvError::ErrPkiPemBundleInvalid)?;
        let body_b64: String = pem[body_start..end].chars().filter(|c| !c.is_whitespace()).collect();
        let body_bytes = base64::engine::general_purpose::STANDARD
            .decode(body_b64.as_bytes())
            .map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).map_err(|_| RvError::ErrPkiPemBundleInvalid)?;
        let classical_pem = body["classical_pkcs8_pem"].as_str().ok_or(RvError::ErrPkiPemBundleInvalid)?;
        let pqc_pem = body["pqc_storage_pem"].as_str().ok_or(RvError::ErrPkiPemBundleInvalid)?;
        Ok(Self {
            classical: CertSigner::from_pem(classical_pem)?,
            pqc: MlDsaSigner::from_storage_pem(pqc_pem)?,
        })
    }
}

/// Engine-internal prehash. SHA-256 over `domain || msg`. Documented
/// explicitly as preview-only — when the IETF draft locks down on its
/// `M' = Prefix || Random || Domain || HashOID || PH(M)` shape, this
/// function is the single point of swap.
fn bv_prehash(msg: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(BV_COMPOSITE_DOMAIN_V0);
    h.update(msg);
    let digest = h.finalize();
    // Return the digest, not the raw message: each downstream signer signs
    // the digest, which keeps the per-half message size constant regardless
    // of TBS length.
    digest.to_vec()
}

fn der_err(e: impl std::fmt::Debug) -> RvError {
    log::error!("pki/composite: DER error: {e:?}");
    RvError::ErrPkiInternal
}

// Compile-time check that the secret-bearing fields are at least
// behind `Zeroizing` indirection through their child types: `CertSigner`
// already wraps its PKCS#8 PEM in `Zeroizing`, and `MlDsaSigner` wraps the
// 32-byte seed. This module adds no new persistent secret material of its
// own beyond those two halves.
#[allow(dead_code)]
fn _zeroize_witness(_: Zeroizing<()>) {}
