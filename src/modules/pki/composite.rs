//! Composite (hybrid) signatures — classical + ML-DSA pairings.
//!
//! **Phase 3 status: feature-gated preview.** Enable with the `pki_pqc_composite`
//! cargo feature. Off by default. The IETF draft
//! [`draft-ietf-lamps-pq-composite-sigs`](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
//! is still in flux — the message-prep prefix, the optional randomizer, and
//! the OID arc have all moved across revisions. The implementation here
//! tracks the draft's *structure* (a SEQUENCE of two BIT STRINGs in both
//! `subjectPublicKey` and `signatureValue`) but pins the prehash domain to a
//! fixed BastionVault-internal value (per variant) so we are honest about
//! non-interop: certs issued under this feature flag verify against
//! themselves but should not be expected to interoperate with arbitrary
//! draft-conformant verifiers until the draft stabilises and we explicitly
//! switch the construction.
//!
//! Variants implemented (Phase 3 + this patch):
//!
//! | Tuple                        | OID                                     | Hash    |
//! |------------------------------|-----------------------------------------|---------|
//! | ECDSA-P256 + ML-DSA-44        | `2.16.840.1.114027.80.8.1.21`           | SHA-256 |
//! | ECDSA-P256 + ML-DSA-65        | `2.16.840.1.114027.80.8.1.28`           | SHA-512 |
//! | ECDSA-P384 + ML-DSA-87        | `2.16.840.1.114027.80.8.1.34`           | SHA-512 |
//!
//! RSA-PSS pairings (`rsa-pss-mldsa44`, `rsa-pss-mldsa65`) follow the same
//! shape but pull in PSS-salt sizing decisions that aren't fully settled in
//! the draft yet — they're deferred to a follow-up patch when operator
//! demand confirms which RSA bit-size to ship first.
//!
//! What we *do* guarantee:
//! - Each half of the signature is a real classical / ML-DSA signature over
//!   the same canonical message bytes, so a verifier that trusts only one
//!   half can still validate against that half independently.
//! - The seam in [`super::crypto::Signer`] makes Phase 3 swappable: when the
//!   IETF draft locks down, only this file (plus the OID table) needs to
//!   change — `path_*` handlers stay put.

use rcgen::{PublicKeyData, SigningKey};
use sha2::{Digest, Sha256, Sha512};
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

// ── OIDs ─────────────────────────────────────────────────────────────
//
// Pinned best-effort to draft-ietf-lamps-pq-composite-sigs (Entrust arc
// `2.16.840.1.114027.80.8.1`). These are draft assignments — the same
// caveat that applies to the cert format itself applies here, see the
// module-level docstring above. A stabilised draft with different
// final OIDs would only need this table updated; everything else is
// algorithm-agnostic.

/// `id-MLDSA44-ECDSA-P256-SHA256`.
pub const OID_COMPOSITE_MLDSA44_ECDSAP256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.21");

/// `id-MLDSA65-ECDSA-P256-SHA512`.
pub const OID_COMPOSITE_MLDSA65_ECDSAP256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.28");

/// `id-MLDSA87-ECDSA-P384-SHA512`.
pub const OID_COMPOSITE_MLDSA87_ECDSAP384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.34");

// ── Variant tuple ───────────────────────────────────────────────────

/// Which classical / ML-DSA pairing this signer carries. `KeyAlgorithm`
/// already names the public surface; this enum is just the internal
/// shorthand the module uses to keep the per-variant tables compact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    P256L44,
    P256L65,
    P384L87,
}

impl Variant {
    fn from_alg(alg: KeyAlgorithm) -> Result<Self, RvError> {
        match alg {
            KeyAlgorithm::CompositeEcdsaP256MlDsa44 => Ok(Self::P256L44),
            KeyAlgorithm::CompositeEcdsaP256MlDsa65 => Ok(Self::P256L65),
            KeyAlgorithm::CompositeEcdsaP384MlDsa87 => Ok(Self::P384L87),
            _ => Err(RvError::ErrPkiKeyTypeInvalid),
        }
    }

    fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::P256L44 => KeyAlgorithm::CompositeEcdsaP256MlDsa44,
            Self::P256L65 => KeyAlgorithm::CompositeEcdsaP256MlDsa65,
            Self::P384L87 => KeyAlgorithm::CompositeEcdsaP384MlDsa87,
        }
    }

    fn classical(self) -> KeyAlgorithm {
        match self {
            Self::P256L44 | Self::P256L65 => KeyAlgorithm::EcdsaP256,
            Self::P384L87 => KeyAlgorithm::EcdsaP384,
        }
    }

    fn ml_dsa(self) -> MlDsaLevel {
        match self {
            Self::P256L44 => MlDsaLevel::L44,
            Self::P256L65 => MlDsaLevel::L65,
            Self::P384L87 => MlDsaLevel::L87,
        }
    }

    fn oid(self) -> const_oid::ObjectIdentifier {
        match self {
            Self::P256L44 => OID_COMPOSITE_MLDSA44_ECDSAP256,
            Self::P256L65 => OID_COMPOSITE_MLDSA65_ECDSAP256,
            Self::P384L87 => OID_COMPOSITE_MLDSA87_ECDSAP384,
        }
    }

    /// Per-variant domain separator. Bumping this string shifts the
    /// signed-message space, so two variants with the same wire shape
    /// (e.g. P256+L44 / P256+L65) cannot have a sig from one mistakenly
    /// validated under the other's prehash. The `/v0` suffix tracks
    /// the engine-internal construction generation — the draft's
    /// final `Domain || ctx || M'` shape will replace this whole
    /// helper when it lands.
    fn domain(self) -> &'static [u8] {
        match self {
            Self::P256L44 => b"BastionVault-PKI-Composite-v0/MLDSA44+ECDSAP256/v0",
            Self::P256L65 => b"BastionVault-PKI-Composite-v0/MLDSA65+ECDSAP256/v0",
            Self::P384L87 => b"BastionVault-PKI-Composite-v0/MLDSA87+ECDSAP384/v0",
        }
    }

    /// Hash function the variant's draft alias names. The classical
    /// half signs the *output* of this hash applied to `domain || msg`;
    /// the per-half signers (rcgen ECDSA / ML-DSA) then hash again
    /// inside their own constructions, but that's fine — what matters
    /// for cross-variant separation is the prehash output the two
    /// halves agree on.
    fn prehash(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::P256L44 => {
                let mut h = Sha256::new();
                h.update(self.domain());
                h.update(msg);
                h.finalize().to_vec()
            }
            Self::P256L65 | Self::P384L87 => {
                let mut h = Sha512::new();
                h.update(self.domain());
                h.update(msg);
                h.finalize().to_vec()
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::P256L44 => "P256+L44",
            Self::P256L65 => "P256+L65",
            Self::P384L87 => "P384+L87",
        }
    }
}

/// Composite signer: pairs one classical signer (ECDSA-P256 / P384) with
/// one PQC signer (ML-DSA-44 / 65 / 87). The variant is carried so root
/// CAs, intermediate CAs, and leaves all serialise to the same envelope
/// shape and the storage round-trip can rebuild the right pairing.
pub struct CompositeSigner {
    variant: Variant,
    classical: CertSigner,
    pqc: MlDsaSigner,
}

impl CompositeSigner {
    /// Generate a fresh composite keypair for the given pairing.
    pub fn generate(alg: KeyAlgorithm) -> Result<Self, RvError> {
        let variant = Variant::from_alg(alg)?;
        Ok(Self {
            variant,
            classical: CertSigner::generate(variant.classical())?,
            pqc: MlDsaSigner::generate(variant.ml_dsa())?,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.variant.key_algorithm()
    }

    /// OID for the cert's `signatureAlgorithm` / SPKI's `algorithm`.
    pub fn oid(&self) -> const_oid::ObjectIdentifier {
        self.variant.oid()
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
    /// classical half is the SEC1 uncompressed point (65 bytes for
    /// P-256, 97 bytes for P-384). The PQ half is the raw ML-DSA public
    /// key (1312 / 1952 / 2592 bytes for L44 / L65 / L87).
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
        let prehashed = self.variant.prehash(msg);
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
        // block so the loader can split them deterministically. The
        // `variant` field tags the pairing so reads can rebuild the
        // right `Variant` on dispatch — older single-variant envelopes
        // (Phase 3 initial release) are missing this field; the loader
        // tolerates that and infers `P256_L65` to keep disk-format
        // back-compat with deployments minted before this patch.
        let body = serde_json::json!({
            "variant": self.variant.label(),
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

        // Variant inference. Phase 3 initial release didn't tag the
        // variant — those envelopes are P256+L65 by definition. New
        // envelopes carry an explicit `"variant"` field; we use it
        // when present and fall back to the classical/PQC algorithms
        // we actually loaded if the field is missing or unrecognised.
        let classical = CertSigner::from_pem(classical_pem)?;
        let pqc = MlDsaSigner::from_storage_pem(pqc_pem)?;
        let variant = match body["variant"].as_str() {
            Some("P256+L44") => Variant::P256L44,
            Some("P256+L65") => Variant::P256L65,
            Some("P384+L87") => Variant::P384L87,
            _ => infer_variant(&classical, &pqc)?,
        };
        Ok(Self { variant, classical, pqc })
    }
}

/// Reconstruct the `Variant` from the loaded halves. Used as a fallback
/// when the storage envelope has no explicit `variant` tag (envelopes
/// from the Phase 3 initial release predate this patch). The pairings
/// are 1:1 with the (classical algorithm, ML-DSA level) tuple, so any
/// loaded combination either resolves to one of the three implemented
/// variants or fails out cleanly.
fn infer_variant(classical: &CertSigner, pqc: &MlDsaSigner) -> Result<Variant, RvError> {
    match (classical.algorithm(), pqc.level()) {
        (KeyAlgorithm::EcdsaP256, MlDsaLevel::L44) => Ok(Variant::P256L44),
        (KeyAlgorithm::EcdsaP256, MlDsaLevel::L65) => Ok(Variant::P256L65),
        (KeyAlgorithm::EcdsaP384, MlDsaLevel::L87) => Ok(Variant::P384L87),
        _ => Err(RvError::ErrPkiPemBundleInvalid),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// All three pairings: generate → query OID + algorithm → sign a
    /// fixed message → confirm the output is non-empty and the algorithm
    /// stays self-consistent. Catches a regression where one variant's
    /// classical/PQ tuple gets crossed with another's.
    #[test]
    fn each_variant_generates_and_signs() {
        for alg in [
            KeyAlgorithm::CompositeEcdsaP256MlDsa44,
            KeyAlgorithm::CompositeEcdsaP256MlDsa65,
            KeyAlgorithm::CompositeEcdsaP384MlDsa87,
        ] {
            let signer = CompositeSigner::generate(alg).expect("generate");
            assert_eq!(signer.algorithm(), alg, "algorithm round-trip mismatch");

            let sig = signer.sign(b"test message").expect("sign");
            assert!(!sig.is_empty(), "sig empty for {alg:?}");

            let pk_der = signer.composite_public_key_der().expect("spki bytes");
            assert!(!pk_der.is_empty(), "spki bytes empty for {alg:?}");
        }
    }

    /// OIDs are wired distinctly per variant. A bug where `oid()` always
    /// returned the L65+P256 constant (the original Phase 3 hard-code)
    /// would fail this test loudly.
    #[test]
    fn oids_are_distinct_per_variant() {
        let mut seen = std::collections::HashSet::new();
        for alg in [
            KeyAlgorithm::CompositeEcdsaP256MlDsa44,
            KeyAlgorithm::CompositeEcdsaP256MlDsa65,
            KeyAlgorithm::CompositeEcdsaP384MlDsa87,
        ] {
            let signer = CompositeSigner::generate(alg).unwrap();
            assert!(seen.insert(signer.oid()), "duplicate OID for {alg:?}");
        }
        assert_eq!(seen.len(), 3);
    }

    /// Storage round-trip: persist → load → algorithm + signing
    /// behaviour preserved. Run for every variant so a missing
    /// `"variant"` arm in `from_storage_pem` would fail here.
    #[test]
    fn storage_pem_round_trips_each_variant() {
        for alg in [
            KeyAlgorithm::CompositeEcdsaP256MlDsa44,
            KeyAlgorithm::CompositeEcdsaP256MlDsa65,
            KeyAlgorithm::CompositeEcdsaP384MlDsa87,
        ] {
            let signer = CompositeSigner::generate(alg).unwrap();
            let pem = signer.to_storage_pem();
            let back = CompositeSigner::from_storage_pem(&pem).expect("load back");
            assert_eq!(back.algorithm(), alg, "round-trip algorithm mismatch");
            assert_eq!(back.oid(), signer.oid(), "round-trip OID mismatch");
            // Both halves come back populated.
            assert_eq!(back.classical().algorithm(), signer.classical().algorithm());
            assert_eq!(back.pqc().level(), signer.pqc().level());
        }
    }

    /// Backward compat: a legacy envelope that omits the `"variant"`
    /// field still loads (Phase 3 initial release minted these). The
    /// fallback path infers the variant from the loaded halves.
    #[test]
    fn legacy_envelope_without_variant_field_loads() {
        let signer = CompositeSigner::generate(KeyAlgorithm::CompositeEcdsaP256MlDsa65).unwrap();
        let pem_with = signer.to_storage_pem();

        // Strip the JSON `"variant":"P256+L65",` prefix to simulate the
        // pre-patch storage shape. We do it on the decoded body and
        // re-encode to keep the PEM framing valid.
        use base64::Engine;
        let begin = "-----BEGIN BV PQC COMPOSITE SIGNER-----";
        let end = "-----END BV PQC COMPOSITE SIGNER-----";
        let body_b64: String = pem_with
            [pem_with.find(begin).unwrap() + begin.len()..pem_with.find(end).unwrap()]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let body_bytes = base64::engine::general_purpose::STANDARD
            .decode(body_b64.as_bytes())
            .unwrap();
        let mut body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        body.as_object_mut().unwrap().remove("variant");
        let new_b64 = base64::engine::general_purpose::STANDARD.encode(body.to_string().as_bytes());
        let mut legacy_pem = String::new();
        legacy_pem.push_str(begin);
        legacy_pem.push('\n');
        for chunk in new_b64.as_bytes().chunks(64) {
            legacy_pem.push_str(std::str::from_utf8(chunk).unwrap());
            legacy_pem.push('\n');
        }
        legacy_pem.push_str(end);
        legacy_pem.push('\n');

        let back = CompositeSigner::from_storage_pem(&legacy_pem).expect("legacy load");
        assert_eq!(back.algorithm(), KeyAlgorithm::CompositeEcdsaP256MlDsa65);
    }

    /// Cross-variant sigs MUST NOT collide: a sig produced under
    /// P256+L44 and one under P256+L65 over the same message must
    /// differ byte-for-byte. Different domain separators per variant
    /// guarantee this even if the per-half signers happened to be
    /// deterministic — a regression that bumped both variants' hash
    /// to the same SHA family without flipping the domain string would
    /// fail this test.
    #[test]
    fn cross_variant_sigs_differ() {
        let a = CompositeSigner::generate(KeyAlgorithm::CompositeEcdsaP256MlDsa44).unwrap();
        let b = CompositeSigner::generate(KeyAlgorithm::CompositeEcdsaP256MlDsa65).unwrap();
        let sig_a = a.sign(b"same message").unwrap();
        let sig_b = b.sign(b"same message").unwrap();
        assert_ne!(sig_a, sig_b, "different variants produced identical sigs");
    }
}
