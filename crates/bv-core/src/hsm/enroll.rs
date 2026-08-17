//! Cluster bootstrap and node enrollment (spec § Capability 3).
//!
//! * The bootstrap node creates the **custody root record** — the trust anchor
//!   every later enrollment chains to — signed by its `bv-identity` key.
//! * A joining node presents an **attestation bundle** for its `bv-identity`
//!   and `bv-authz` keys, proving they were generated inside a genuine device
//!   and are non-exportable. The sponsor verifies the attestation and pins the
//!   new node's public keys before any key material moves.
//!
//! The actual key transfer is in [`crate::hsm::replicate`]; this module
//! establishes and verifies the trust relationships around it.

use serde::{Deserialize, Serialize};

use crate::{
    errors::RvError,
    hsm::{context, verify_identity_signature, HsmBackend, HsmObjectId, ResolvedHsmConfig},
};

/// The cluster custody root: the trust anchor established at bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRootRecord {
    pub version: u8,
    pub cluster_uuid: String,
    pub epoch: u64,
    pub bootstrap_node: String,
    pub bootstrap_serial: String,
    pub wrap_barrier: HsmObjectId,
    pub wrap_pqc: HsmObjectId,
    pub identity: HsmObjectId,
    pub authz: HsmObjectId,
    /// SEC1-uncompressed P-256 public key of the bootstrap `bv-identity`.
    #[serde(with = "serde_bytes")]
    pub bootstrap_identity_pub: Vec<u8>,
    /// Ed25519 verifying key of the bootstrap `bv-authz`.
    #[serde(with = "serde_bytes")]
    pub bootstrap_authz_pub: Vec<u8>,
}

impl CustodyRootRecord {
    pub fn tbs(&self) -> Vec<u8> {
        fn push(out: &mut Vec<u8>, b: &[u8]) {
            out.extend_from_slice(&(b.len() as u64).to_be_bytes());
            out.extend_from_slice(b);
        }
        let mut out = Vec::new();
        push(&mut out, b"bastionvault/hsm/custody-root/v1");
        push(&mut out, self.cluster_uuid.as_bytes());
        push(&mut out, &self.epoch.to_be_bytes());
        push(&mut out, self.bootstrap_node.as_bytes());
        push(&mut out, self.bootstrap_serial.as_bytes());
        push(&mut out, &self.wrap_barrier.to_be_bytes());
        push(&mut out, &self.wrap_pqc.to_be_bytes());
        push(&mut out, &self.identity.to_be_bytes());
        push(&mut out, &self.authz.to_be_bytes());
        push(&mut out, &self.bootstrap_identity_pub);
        push(&mut out, &self.bootstrap_authz_pub);
        out
    }
}

/// A custody root plus the bootstrap node's `bv-identity` signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCustodyRoot {
    pub record: CustodyRootRecord,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

fn custody_root_ctx(cluster_uuid: &str) -> String {
    format!("{}/custody-root/{cluster_uuid}", context::HSM_CTX_PREFIX)
}

/// Bootstrap: build and sign the cluster custody root on the first node.
#[maybe_async::maybe_async]
pub async fn create_custody_root(
    backend: &dyn HsmBackend,
    config: &ResolvedHsmConfig,
    cluster_uuid: &str,
) -> Result<SignedCustodyRoot, RvError> {
    let record = CustodyRootRecord {
        version: 1,
        cluster_uuid: cluster_uuid.to_string(),
        epoch: 0,
        bootstrap_node: config.node_id.clone(),
        bootstrap_serial: backend.device_serial(),
        wrap_barrier: config.objects.wrap_barrier,
        wrap_pqc: config.objects.wrap_pqc,
        identity: config.objects.identity,
        authz: config.objects.authz,
        bootstrap_identity_pub: backend.identity_public_key()?,
        bootstrap_authz_pub: backend.authz_public_key()?,
    };
    let ctx = custody_root_ctx(cluster_uuid);
    let signature = backend.sign(config.objects.identity, &ctx, &record.tbs()).await?;
    Ok(SignedCustodyRoot { record, signature })
}

/// Verify a custody root signature against the embedded bootstrap identity key.
/// (Pinning that identity key out-of-band is the operator's root of trust.)
pub fn verify_custody_root(signed: &SignedCustodyRoot) -> Result<(), RvError> {
    let ctx = custody_root_ctx(&signed.record.cluster_uuid);
    verify_identity_signature(
        &signed.record.bootstrap_identity_pub,
        &ctx,
        &signed.record.tbs(),
        &signed.signature,
    )
}

/// A node's attestation bundles for its two attestable keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentAttestation {
    pub node_id: String,
    #[serde(with = "serde_bytes")]
    pub identity_bundle: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub authz_bundle: Vec<u8>,
}

/// A verified, pinned joining node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledNode {
    pub node_id: String,
    pub serial: String,
    pub identity_pub: Vec<u8>,
    pub authz_pub: Vec<u8>,
}

/// Produce this node's attestation bundles for enrollment.
#[maybe_async::maybe_async]
pub async fn attestation_for_enrollment(
    backend: &dyn HsmBackend,
    config: &ResolvedHsmConfig,
) -> Result<EnrollmentAttestation, RvError> {
    Ok(EnrollmentAttestation {
        node_id: config.node_id.clone(),
        identity_bundle: backend.attest(config.objects.identity).await?,
        authz_bundle: backend.attest(config.objects.authz).await?,
    })
}

/// Sponsor side: verify a joiner's attestation bundles and pin its keys. The
/// attested keys MUST be non-exportable (spec § Security). The sponsor's own
/// backend verifies the bundle (mock: test CA; hardware: Yubico chain).
#[maybe_async::maybe_async]
pub async fn verify_enrollment(
    sponsor: &dyn HsmBackend,
    attestation: &EnrollmentAttestation,
) -> Result<EnrolledNode, RvError> {
    let identity = sponsor.verify_attestation(&attestation.identity_bundle).await?;
    if !identity.non_exportable {
        return Err(RvError::ErrHsmAttestationInvalid("joiner identity key is exportable".into()));
    }
    let authz = sponsor.verify_attestation(&attestation.authz_bundle).await?;
    if !authz.non_exportable {
        return Err(RvError::ErrHsmAttestationInvalid("joiner authz key is exportable".into()));
    }
    if identity.serial != authz.serial {
        return Err(RvError::ErrHsmAttestationInvalid("joiner keys attest to different devices".into()));
    }
    Ok(EnrolledNode {
        node_id: attestation.node_id.clone(),
        serial: identity.serial,
        identity_pub: identity.public_key,
        authz_pub: authz.public_key,
    })
}

#[cfg(all(test, feature = "hsm_mock"))]
mod tests {
    use super::*;
    use crate::hsm::{mock::MockHsmBackend, HsmObjectIds, RecoveryMode};
    use std::time::Duration;
    use zeroize::Zeroizing;

    fn cfg(node: &str) -> ResolvedHsmConfig {
        ResolvedHsmConfig {
            backend_type: "mock".into(),
            connector: String::new(),
            objects: HsmObjectIds::default(),
            password: Zeroizing::new(String::new()),
            domains: vec![1],
            pqc_key_cache_ttl: Duration::from_secs(60),
            recovery: RecoveryMode::None,
            state_path: String::new(),
            node_id: node.into(),
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn custody_root_sign_and_verify() {
        let hsm = MockHsmBackend::open(&cfg("boot")).await.unwrap();
        let root = create_custody_root(&hsm, &cfg("boot"), "cluster-uuid").await.unwrap();
        verify_custody_root(&root).unwrap();

        // Tampered record fails.
        let mut bad = root.clone();
        bad.record.epoch = 7;
        assert!(verify_custody_root(&bad).is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn enrollment_attestation_verifies_and_pins() {
        let sponsor = MockHsmBackend::open(&cfg("sponsor")).await.unwrap();
        let joiner = MockHsmBackend::open(&cfg("joiner")).await.unwrap();

        let attestation = attestation_for_enrollment(&joiner, &cfg("joiner")).await.unwrap();
        let enrolled = verify_enrollment(&sponsor, &attestation).await.unwrap();

        assert_eq!(enrolled.node_id, "joiner");
        assert_eq!(enrolled.identity_pub, joiner.identity_public_key().unwrap());
        assert_eq!(enrolled.authz_pub, joiner.authz_public_key().unwrap());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn tampered_attestation_bundle_is_rejected() {
        let sponsor = MockHsmBackend::open(&cfg("sponsor")).await.unwrap();
        let joiner = MockHsmBackend::open(&cfg("joiner")).await.unwrap();
        let mut attestation = attestation_for_enrollment(&joiner, &cfg("joiner")).await.unwrap();
        let n = attestation.identity_bundle.len() - 1;
        attestation.identity_bundle[n] ^= 0xff;
        assert!(verify_enrollment(&sponsor, &attestation).await.is_err());
    }
}
