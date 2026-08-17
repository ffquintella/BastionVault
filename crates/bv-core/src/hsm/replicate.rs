//! HSM-to-HSM key replication channel and migration transcript
//! (spec § Capability 3).
//!
//! Cluster-shared key material (barrier KEK, PQC seeds) must reach every node
//! without ever being persisted or transmitted in a form decryptable outside an
//! enrolled HSM. Each node stores its own copy, wrapped by its own device. This
//! module implements the authenticated transfer:
//!
//! 1. Sponsor and joiner ECDH their `bv-identity` keys (each `derive_ecdh` runs
//!    inside its own HSM).
//! 2. `channel_key = HKDF-SHA-512(s_ecdh, salt = cluster_uuid,
//!    info = ctx_replication ‖ transcript_hash)`; the payload is sealed with
//!    ChaCha20-Poly1305.
//! 3. The sponsor unwraps a cluster secret (signed, audited authorization),
//!    seals it to the channel; the joiner opens it and **immediately re-wraps
//!    it under its own `bv-wrap-*` keys, zeroizing the plaintext**. Plaintext
//!    exists only transiently in `Zeroizing` buffers, never on the wire (which
//!    carries only channel-encrypted data) and never in storage.
//! 4. The whole exchange is bound to a [`MigrationTranscript`] that **both
//!    HSMs sign** (`bv-identity` ECDSA). A node whose blobs don't match a valid
//!    transcript refuses to unseal.

use bv_crypto::{AeadCipher, Chacha20Poly1305Cipher, Nonce, SymmetricKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        authz::{self, UnwrapRequest},
        blob::{Context, Purpose},
        context, HsmBackend, HsmObjectId, ResolvedHsmConfig,
    },
};

/// Derive the ChaCha20-Poly1305 channel key from the ECDH secret, bound to the
/// cluster, epoch, and transcript hash.
pub fn channel_key(
    s_ecdh: &[u8],
    cluster_uuid: &str,
    epoch: u64,
    transcript_hash: &[u8],
) -> Result<SymmetricKey, RvError> {
    let hk = Hkdf::<Sha512>::new(Some(cluster_uuid.as_bytes()), s_ecdh);
    let mut info = context::replication_channel(cluster_uuid, epoch).into_bytes();
    info.extend_from_slice(transcript_hash);
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    hk.expand(&info, okm.as_mut_slice()).map_err(|_| RvError::ErrHsm("HKDF expand failed for channel key".into()))?;
    SymmetricKey::try_from_slice(&okm).map_err(|e| RvError::ErrHsm(format!("channel key: {e}")))
}

/// Seal a plaintext payload for the channel: `nonce ‖ ciphertext`.
pub fn seal_payload(key: &SymmetricKey, plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
    let nonce = Nonce::generate();
    let ct = Chacha20Poly1305Cipher
        .encrypt(key, &nonce, b"bastionvault/hsm/replication/v1", plaintext)
        .map_err(|e| RvError::ErrHsm(format!("channel seal: {e}")))?;
    let mut out = nonce.as_bytes().to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a channel payload sealed by [`seal_payload`].
pub fn open_payload(key: &SymmetricKey, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
    if wrapped.len() < 12 {
        return Err(RvError::ErrHsmBlobInvalid);
    }
    let (nonce_bytes, ct) = wrapped.split_at(12);
    let nonce = Nonce::try_from_slice(nonce_bytes).map_err(|_| RvError::ErrHsmBlobInvalid)?;
    let pt = Chacha20Poly1305Cipher
        .decrypt(key, &nonce, b"bastionvault/hsm/replication/v1", ct)
        .map_err(|_| RvError::ErrHsmContextMismatch)?;
    Ok(Zeroizing::new(pt))
}

/// The object ids provisioned on a node, recorded in the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptObjectIds {
    pub wrap_barrier: HsmObjectId,
    pub wrap_pqc: HsmObjectId,
    pub identity: HsmObjectId,
    pub authz: HsmObjectId,
}

/// The full, dual-signable record binding an enrollment/replication exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationTranscript {
    pub version: u8,
    pub cluster_uuid: String,
    pub epoch: u64,
    pub sponsor_node: String,
    pub sponsor_serial: String,
    pub joiner_node: String,
    pub joiner_serial: String,
    pub object_ids: TranscriptObjectIds,
    /// Hex SHA-256 of every wrapped blob produced for the joiner.
    pub blob_digests: Vec<String>,
    /// Hex fingerprints of the sponsor and joiner `bv-authz` keys.
    pub sponsor_authz_fp: String,
    pub joiner_authz_fp: String,
    /// Logical (Raft) timestamp, supplied by the caller — never wall-clock.
    pub logical_ts: u64,
}

impl MigrationTranscript {
    /// Deterministic to-be-signed encoding (length-prefixed, domain separated).
    pub fn tbs(&self) -> Vec<u8> {
        fn push(out: &mut Vec<u8>, b: &[u8]) {
            out.extend_from_slice(&(b.len() as u64).to_be_bytes());
            out.extend_from_slice(b);
        }
        let mut out = Vec::new();
        push(&mut out, b"bastionvault/hsm/migration-transcript/v1");
        push(&mut out, &[self.version]);
        push(&mut out, self.cluster_uuid.as_bytes());
        push(&mut out, &self.epoch.to_be_bytes());
        push(&mut out, self.sponsor_node.as_bytes());
        push(&mut out, self.sponsor_serial.as_bytes());
        push(&mut out, self.joiner_node.as_bytes());
        push(&mut out, self.joiner_serial.as_bytes());
        push(&mut out, &self.object_ids.wrap_barrier.to_be_bytes());
        push(&mut out, &self.object_ids.wrap_pqc.to_be_bytes());
        push(&mut out, &self.object_ids.identity.to_be_bytes());
        push(&mut out, &self.object_ids.authz.to_be_bytes());
        for d in &self.blob_digests {
            push(&mut out, d.as_bytes());
        }
        push(&mut out, self.sponsor_authz_fp.as_bytes());
        push(&mut out, self.joiner_authz_fp.as_bytes());
        push(&mut out, &self.logical_ts.to_be_bytes());
        out
    }

    /// Hash used to bind the channel key to this exact transcript.
    pub fn hash(&self) -> Vec<u8> {
        Sha256::digest(self.tbs()).to_vec()
    }
}

/// A transcript signed by both the sponsor and the joiner `bv-identity` keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTranscript {
    pub transcript: MigrationTranscript,
    #[serde(with = "serde_bytes")]
    pub sponsor_sig: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub joiner_sig: Vec<u8>,
}

/// Context string used when an identity key signs a transcript.
fn transcript_sign_ctx(cluster_uuid: &str, epoch: u64) -> String {
    context::migration_transcript(cluster_uuid, epoch)
}

/// Sign a transcript with a node's `bv-identity` key (ECDSA-P256).
#[maybe_async::maybe_async]
pub async fn sign_transcript(
    backend: &dyn HsmBackend,
    identity_key: HsmObjectId,
    transcript: &MigrationTranscript,
) -> Result<Vec<u8>, RvError> {
    let ctx = transcript_sign_ctx(&transcript.cluster_uuid, transcript.epoch);
    backend.sign(identity_key, &ctx, &transcript.tbs()).await
}

/// Verify a doubly-signed transcript against the sponsor and joiner identity
/// public keys (SEC1-uncompressed P-256). Tolerates both DER and fixed-size
/// ECDSA encodings so a homogeneous mock or hardware cluster both verify.
pub fn verify_signed_transcript(
    signed: &SignedTranscript,
    sponsor_identity_pub: &[u8],
    joiner_identity_pub: &[u8],
) -> Result<(), RvError> {
    let ctx = transcript_sign_ctx(&signed.transcript.cluster_uuid, signed.transcript.epoch);
    let signed_bytes = crate::hsm::domain_separated(&ctx, &signed.transcript.tbs());
    verify_ecdsa(sponsor_identity_pub, &signed_bytes, &signed.sponsor_sig)
        .map_err(|_| RvError::ErrHsmTranscriptInvalid("sponsor signature invalid".into()))?;
    verify_ecdsa(joiner_identity_pub, &signed_bytes, &signed.joiner_sig)
        .map_err(|_| RvError::ErrHsmTranscriptInvalid("joiner signature invalid".into()))?;
    Ok(())
}

/// Verify a P-256 ECDSA signature that may be DER (hardware) or fixed 64-byte
/// (mock) encoded.
fn verify_ecdsa(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), RvError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| RvError::ErrHsmTranscriptInvalid("bad key".into()))?;
    let signature = Signature::from_der(sig).or_else(|_| Signature::from_slice(sig));
    let signature = signature.map_err(|_| RvError::ErrHsmTranscriptInvalid("bad signature".into()))?;
    vk.verify(msg, &signature).map_err(|_| RvError::ErrHsmTranscriptInvalid("verify failed".into()))
}

/// Sponsor side: unwrap a cluster secret (signed, audited) and seal it to the
/// channel. Returns channel-encrypted bytes — plaintext never leaves this fn.
#[maybe_async::maybe_async]
pub async fn export_secret_to_channel(
    sponsor: &dyn HsmBackend,
    config: &ResolvedHsmConfig,
    wrap_key: HsmObjectId,
    secret_blob: &[u8],
    key: &SymmetricKey,
    counter: u64,
) -> Result<Vec<u8>, RvError> {
    let blob = crate::hsm::blob::BvHsmBlob::from_bytes(secret_blob)?;
    let ctx = blob.context();
    let request =
        UnwrapRequest::new(ctx.context.clone(), secret_blob, &config.node_id, ctx.epoch, counter, ctx.purpose);
    let authorization = authz::sign_authorization(sponsor, config.objects.authz, request).await?;
    log::info!(target: "security", "hsm replication unwrap authorized: {}", authz::audit_record(&authorization));
    let plaintext = sponsor.unwrap_data(wrap_key, &ctx, secret_blob).await?;
    seal_payload(key, &plaintext)
}

/// Joiner side: open a channel payload and immediately re-wrap it under this
/// node's own wrap key, zeroizing the plaintext. Returns the new local blob.
#[maybe_async::maybe_async]
pub async fn import_secret_from_channel(
    joiner: &dyn HsmBackend,
    wrap_key: HsmObjectId,
    target_ctx: &Context,
    key: &SymmetricKey,
    channel_payload: &[u8],
) -> Result<Vec<u8>, RvError> {
    let plaintext = open_payload(key, channel_payload)?;
    // Re-wrap under the joiner's own device; `plaintext` zeroizes on drop.
    joiner.wrap_data(wrap_key, target_ctx, &plaintext).await
}

/// Digest of a wrapped blob, for transcript binding.
pub fn blob_digest(blob: &[u8]) -> String {
    hex::encode(Sha256::digest(blob))
}

/// Rebuild a barrier-KEK [`Context`] for a joiner node.
pub fn barrier_context(cluster_uuid: &str, epoch: u64, node_id: &str) -> Context {
    Context::new(context::barrier_kek(cluster_uuid), Purpose::BarrierKek, epoch, node_id)
}

#[cfg(all(test, feature = "hsm_mock"))]
mod tests {
    use super::*;
    use crate::hsm::{mock::MockHsmBackend, HsmObjectIds, RecoveryMode};
    use std::{sync::Arc, time::Duration};

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
    async fn two_node_kek_replication_round_trip() {
        let sponsor = Arc::new(MockHsmBackend::open(&cfg("sponsor")).await.unwrap());
        let joiner = Arc::new(MockHsmBackend::open(&cfg("joiner")).await.unwrap());
        let cluster = "cluster-uuid";
        let epoch = 0u64;

        // Sponsor wraps a KEK for itself.
        let kek = b"the-shared-barrier-kek-32-bytes!";
        let sponsor_ctx = barrier_context(cluster, epoch, "sponsor");
        let sponsor_blob = sponsor.wrap_data(HsmObjectIds::default().wrap_barrier, &sponsor_ctx, kek).await.unwrap();

        // Build + dual-sign the transcript.
        let transcript = MigrationTranscript {
            version: 1,
            cluster_uuid: cluster.into(),
            epoch,
            sponsor_node: "sponsor".into(),
            sponsor_serial: sponsor.device_serial(),
            joiner_node: "joiner".into(),
            joiner_serial: joiner.device_serial(),
            object_ids: TranscriptObjectIds {
                wrap_barrier: HsmObjectIds::default().wrap_barrier,
                wrap_pqc: HsmObjectIds::default().wrap_pqc,
                identity: HsmObjectIds::default().identity,
                authz: HsmObjectIds::default().authz,
            },
            blob_digests: vec![],
            sponsor_authz_fp: sponsor.authz_fingerprint().unwrap(),
            joiner_authz_fp: joiner.authz_fingerprint().unwrap(),
            logical_ts: 1,
        };
        let sponsor_sig = sign_transcript(sponsor.as_ref(), HsmObjectIds::default().identity, &transcript).await.unwrap();
        let joiner_sig = sign_transcript(joiner.as_ref(), HsmObjectIds::default().identity, &transcript).await.unwrap();
        let signed = SignedTranscript { transcript: transcript.clone(), sponsor_sig, joiner_sig };
        verify_signed_transcript(&signed, &sponsor.identity_public_key().unwrap(), &joiner.identity_public_key().unwrap())
            .unwrap();

        // Establish the channel key on both sides (ECDH inside each HSM).
        let th = transcript.hash();
        let sp_ecdh = sponsor.derive_ecdh(HsmObjectIds::default().identity, &joiner.identity_public_key().unwrap()).await.unwrap();
        let jo_ecdh = joiner.derive_ecdh(HsmObjectIds::default().identity, &sponsor.identity_public_key().unwrap()).await.unwrap();
        let sp_key = channel_key(&sp_ecdh, cluster, epoch, &th).unwrap();
        let jo_key = channel_key(&jo_ecdh, cluster, epoch, &th).unwrap();

        // Sponsor exports, joiner re-wraps under its own device.
        let payload = export_secret_to_channel(
            sponsor.as_ref(),
            &cfg("sponsor"),
            HsmObjectIds::default().wrap_barrier,
            &sponsor_blob,
            &sp_key,
            1,
        )
        .await
        .unwrap();
        let joiner_ctx = barrier_context(cluster, epoch, "joiner");
        let joiner_blob =
            import_secret_from_channel(joiner.as_ref(), HsmObjectIds::default().wrap_barrier, &joiner_ctx, &jo_key, &payload)
                .await
                .unwrap();

        // The joiner can now recover the same KEK from its own blob.
        let recovered = joiner.unwrap_data(HsmObjectIds::default().wrap_barrier, &joiner_ctx, &joiner_blob).await.unwrap();
        assert_eq!(recovered.as_slice(), kek);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn tampered_transcript_fails_verification() {
        let sponsor = Arc::new(MockHsmBackend::open(&cfg("sponsor")).await.unwrap());
        let joiner = Arc::new(MockHsmBackend::open(&cfg("joiner")).await.unwrap());
        let mut transcript = MigrationTranscript {
            version: 1,
            cluster_uuid: "c".into(),
            epoch: 0,
            sponsor_node: "sponsor".into(),
            sponsor_serial: sponsor.device_serial(),
            joiner_node: "joiner".into(),
            joiner_serial: joiner.device_serial(),
            object_ids: TranscriptObjectIds { wrap_barrier: 2, wrap_pqc: 3, identity: 4, authz: 5 },
            blob_digests: vec!["deadbeef".into()],
            sponsor_authz_fp: sponsor.authz_fingerprint().unwrap(),
            joiner_authz_fp: joiner.authz_fingerprint().unwrap(),
            logical_ts: 1,
        };
        let sponsor_sig = sign_transcript(sponsor.as_ref(), HsmObjectIds::default().identity, &transcript).await.unwrap();
        let joiner_sig = sign_transcript(joiner.as_ref(), HsmObjectIds::default().identity, &transcript).await.unwrap();
        // Tamper after signing.
        transcript.blob_digests = vec!["0000".into()];
        let signed = SignedTranscript { transcript, sponsor_sig, joiner_sig };
        assert!(verify_signed_transcript(
            &signed,
            &sponsor.identity_public_key().unwrap(),
            &joiner.identity_public_key().unwrap()
        )
        .is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn wrong_channel_key_cannot_open_payload() {
        let a = MockHsmBackend::open(&cfg("a")).await.unwrap();
        let key = channel_key(&[1u8; 32], "c", 0, &[9u8; 32]).unwrap();
        let wrong = channel_key(&[2u8; 32], "c", 0, &[9u8; 32]).unwrap();
        let payload = seal_payload(&key, b"secret").unwrap();
        assert!(open_payload(&wrong, &payload).is_err());
        assert_eq!(open_payload(&key, &payload).unwrap().as_slice(), b"secret");
        let _ = a;
    }
}
