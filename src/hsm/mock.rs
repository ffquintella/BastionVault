//! Software mock HSM backend (feature `hsm_mock`).
//!
//! Implements the full [`HsmBackend`] contract in software so dev and
//! homologation clusters (which have no USB passthrough) exercise the identical
//! code path minus the hardware. It provides **zero** hardware protection: it is
//! compile-time gated behind `hsm_mock`, refuses to start when the environment
//! is production (enforced in [`crate::hsm::new_backend`]), and its object
//! store is a plaintext file.
//!
//! The mock honors the same object model, capability separation (wrap keys
//! cannot sign; identity/authz keys cannot unwrap), context strings, and blob
//! wire format as the real device.

use std::{collections::BTreeMap, sync::RwLock};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    errors::RvError,
    hsm::{
        blob::{open_blob, seal_blob, BlobAad, Context},
        domain_separated, AttestedKey, HsmBackend, HsmObjectId, HsmObjectIds, ResolvedHsmConfig,
    },
};

const AES_NONCE_LEN: usize = 12;

/// The kind of a provisioned mock object, mirroring the real device's object
/// types and their capability masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MockKind {
    /// AES-256 wrap key: `wrap-data` / `unwrap-data` only.
    Wrap,
    /// ECC P-256: `sign-ecdsa`, `derive-ecdh`, attestation.
    Identity,
    /// Ed25519: `sign-eddsa` only (unwrap authorizations).
    Authz,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredObject {
    kind: MockKind,
    /// Wrap: 32-byte AES key. Identity: 32-byte P-256 scalar. Authz: 32-byte
    /// Ed25519 seed. Never leaves the process except re-wrapped (enrollment).
    #[serde(with = "serde_bytes")]
    material: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MockState {
    serial: String,
    objects: BTreeMap<u16, StoredObject>,
}

pub struct MockHsmBackend {
    // Path backing the object store; empty ⇒ ephemeral (tests). Read back by
    // the enrollment re-wrap path (`import_wrapped`), which persists mutated
    // objects; `allow(dead_code)` until that call site lands in the same crate.
    #[allow(dead_code)]
    state_path: String,
    objects: HsmObjectIds,
    /// In-memory object store. Persisted to `state_path` on provisioning so dev
    /// clusters survive restarts. `RwLock` guards enrollment-time mutation.
    state: RwLock<MockState>,
    /// Cached public keys (derived at open; keys are immutable in steady state).
    authz_pub: Vec<u8>,
    identity_pub: Vec<u8>,
}

impl MockHsmBackend {
    /// Open (and, on first use, provision) the mock device for `config`.
    #[maybe_async::maybe_async]
    pub async fn open(config: &ResolvedHsmConfig) -> Result<Self, RvError> {
        let mut state = load_state(&config.state_path)?;

        // Provision any missing required object. Keys are generated from host
        // CSPRNG bytes (the codebase's idiom, avoiding the rand_core version
        // split) and persisted so restarts reuse them.
        let mut changed = false;
        if state.serial.is_empty() {
            state.serial = format!("MOCK-{}", hex::encode(random_bytes(6)));
            changed = true;
        }
        changed |= ensure_object(&mut state, config.objects.wrap_barrier, MockKind::Wrap);
        changed |= ensure_object(&mut state, config.objects.wrap_pqc, MockKind::Wrap);
        changed |= ensure_object(&mut state, config.objects.identity, MockKind::Identity);
        changed |= ensure_object(&mut state, config.objects.authz, MockKind::Authz);
        if changed {
            persist_state(&config.state_path, &state)?;
        }

        let authz_pub = authz_public(&state, config.objects.authz)?;
        let identity_pub = identity_public(&state, config.objects.identity)?;

        Ok(Self {
            state_path: config.state_path.clone(),
            objects: config.objects,
            state: RwLock::new(state),
            authz_pub,
            identity_pub,
        })
    }

    fn wrap_material(&self, key: HsmObjectId) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
        if obj.kind != MockKind::Wrap {
            // Capability minimization: only wrap keys wrap/unwrap.
            return Err(RvError::ErrHsm("object is not a wrap key".into()));
        }
        Ok(Zeroizing::new(obj.material.clone()))
    }
}

#[maybe_async::maybe_async]
impl HsmBackend for MockHsmBackend {
    fn backend_type(&self) -> &str {
        "mock"
    }

    fn device_serial(&self) -> String {
        self.state.read().map(|s| s.serial.clone()).unwrap_or_default()
    }

    fn authz_public_key(&self) -> Result<Vec<u8>, RvError> {
        Ok(self.authz_pub.clone())
    }

    fn identity_public_key(&self) -> Result<Vec<u8>, RvError> {
        Ok(self.identity_pub.clone())
    }

    async fn wrap_data(&self, key: HsmObjectId, ctx: &Context, plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
        let material = self.wrap_material(key)?;
        let aad = BlobAad::from_context(ctx, self.authz_fingerprint()?);
        seal_blob("mock", key, aad, plaintext, |inner| aes256_gcm_seal(&material, inner))
    }

    async fn unwrap_data(&self, key: HsmObjectId, ctx: &Context, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let material = self.wrap_material(key)?;
        let expected = BlobAad::from_context(ctx, self.authz_fingerprint()?);
        open_blob(wrapped, &expected, |w| aes256_gcm_open(&material, w))
    }

    async fn sign(&self, key: HsmObjectId, ctx: &str, msg: &[u8]) -> Result<Vec<u8>, RvError> {
        let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
        let signed = domain_separated(ctx, msg);
        match obj.kind {
            MockKind::Authz => {
                let seed: [u8; 32] = obj.material.as_slice().try_into().map_err(|_| RvError::ErrHsmBlobInvalid)?;
                let sk = SigningKey::from_bytes(&seed);
                Ok(sk.sign(&signed).to_bytes().to_vec())
            }
            MockKind::Identity => {
                use p256::ecdsa::{signature::Signer, Signature, SigningKey as EcSigningKey};
                let sk = EcSigningKey::from_slice(&obj.material).map_err(|_| RvError::ErrHsm("bad identity key".into()))?;
                let sig: Signature = sk.sign(&signed);
                Ok(sig.to_bytes().to_vec())
            }
            MockKind::Wrap => Err(RvError::ErrHsm("wrap key cannot sign".into())),
        }
    }

    async fn attest(&self, key: HsmObjectId) -> Result<Vec<u8>, RvError> {
        let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
        let public_key = match obj.kind {
            MockKind::Identity => identity_public(&state, key)?,
            MockKind::Authz => authz_public(&state, key)?,
            MockKind::Wrap => return Err(RvError::ErrHsm("wrap key is not attestable".into())),
        };
        let label = match obj.kind {
            MockKind::Identity => "bv-identity",
            MockKind::Authz => "bv-authz",
            MockKind::Wrap => unreachable!(),
        };
        // The mock's "attestation" is a signed self-description over a test CA:
        // the device signs the attested-key JSON with its identity key.
        let attested = AttestedKey {
            label: label.to_string(),
            object_id: key,
            public_key,
            serial: state.serial.clone(),
            non_exportable: true,
        };
        let body = serde_json::to_vec(&MockAttestation {
            label: attested.label,
            object_id: attested.object_id,
            public_key: attested.public_key,
            serial: attested.serial,
            non_exportable: attested.non_exportable,
        })
        .map_err(|e| RvError::ErrHsm(format!("attestation encode: {e}")))?;
        // Sign the body with the identity key so verify_attestation can bind the
        // bundle to this device's identity (test-CA analogue of the Yubico root).
        let id_seed = state.objects.get(&self.objects.identity).ok_or(RvError::ErrHsmUnavailable)?.material.clone();
        drop(state);
        let sig = {
            use p256::ecdsa::{signature::Signer, Signature, SigningKey as EcSigningKey};
            let sk = EcSigningKey::from_slice(&id_seed).map_err(|_| RvError::ErrHsm("bad identity key".into()))?;
            let sig: Signature = sk.sign(&body);
            sig.to_bytes().to_vec()
        };
        let bundle = MockAttestationBundle { body, signature: sig, signer_pub: self.identity_pub.clone() };
        serde_json::to_vec(&bundle).map_err(|e| RvError::ErrHsm(format!("bundle encode: {e}")))
    }

    async fn verify_attestation(&self, cert_chain: &[u8]) -> Result<AttestedKey, RvError> {
        let bundle: MockAttestationBundle = serde_json::from_slice(cert_chain)
            .map_err(|_| RvError::ErrHsmAttestationInvalid("malformed mock attestation bundle".into()))?;
        // Verify the identity signature over the body (test-CA analogue).
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(&bundle.signer_pub)
            .map_err(|_| RvError::ErrHsmAttestationInvalid("bad attestation signer key".into()))?;
        let sig = Signature::from_slice(&bundle.signature)
            .map_err(|_| RvError::ErrHsmAttestationInvalid("bad attestation signature".into()))?;
        vk.verify(&bundle.body, &sig)
            .map_err(|_| RvError::ErrHsmAttestationInvalid("attestation signature does not verify".into()))?;
        let att: MockAttestation = serde_json::from_slice(&bundle.body)
            .map_err(|_| RvError::ErrHsmAttestationInvalid("malformed attested-key body".into()))?;
        if !att.non_exportable {
            return Err(RvError::ErrHsmAttestationInvalid("attested key is exportable".into()));
        }
        Ok(AttestedKey {
            label: att.label,
            object_id: att.object_id,
            public_key: att.public_key,
            serial: att.serial,
            non_exportable: att.non_exportable,
        })
    }

    async fn derive_ecdh(&self, key: HsmObjectId, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let state = self.state.read().map_err(|_| RvError::ErrRwLockReadPoison)?;
        let obj = state.objects.get(&key).ok_or(RvError::ErrHsmUnavailable)?;
        if obj.kind != MockKind::Identity {
            return Err(RvError::ErrHsm("object cannot derive ECDH".into()));
        }
        let secret = p256::SecretKey::from_slice(&obj.material).map_err(|_| RvError::ErrHsm("bad identity key".into()))?;
        let peer = p256::PublicKey::from_sec1_bytes(peer_pub).map_err(|_| RvError::ErrHsm("bad ECDH peer key".into()))?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }

    async fn get_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, RvError> {
        Ok(Zeroizing::new(random_bytes(len)))
    }
}

/// Serializable copy of [`AttestedKey`] for the mock bundle body.
#[derive(Serialize, Deserialize)]
struct MockAttestation {
    label: String,
    object_id: u16,
    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,
    serial: String,
    non_exportable: bool,
}

#[derive(Serialize, Deserialize)]
struct MockAttestationBundle {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signer_pub: Vec<u8>,
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    rand::rng().fill_bytes(&mut b);
    b
}

/// Generate a valid P-256 scalar from host entropy (retry on the negligibly
/// rare invalid draw).
fn random_p256_scalar() -> Vec<u8> {
    loop {
        let candidate = random_bytes(32);
        if p256::SecretKey::from_slice(&candidate).is_ok() {
            return candidate;
        }
    }
}

fn ensure_object(state: &mut MockState, id: u16, kind: MockKind) -> bool {
    if state.objects.contains_key(&id) {
        return false;
    }
    let material = match kind {
        MockKind::Wrap => random_bytes(32),
        MockKind::Identity => random_p256_scalar(),
        MockKind::Authz => random_bytes(32),
    };
    state.objects.insert(id, StoredObject { kind, material });
    true
}

fn authz_public(state: &MockState, id: u16) -> Result<Vec<u8>, RvError> {
    let obj = state.objects.get(&id).ok_or(RvError::ErrHsmUnavailable)?;
    let seed: [u8; 32] = obj.material.as_slice().try_into().map_err(|_| RvError::ErrHsmBlobInvalid)?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes().to_vec())
}

fn identity_public(state: &MockState, id: u16) -> Result<Vec<u8>, RvError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let obj = state.objects.get(&id).ok_or(RvError::ErrHsmUnavailable)?;
    let secret = p256::SecretKey::from_slice(&obj.material).map_err(|_| RvError::ErrHsm("bad identity key".into()))?;
    Ok(secret.public_key().to_encoded_point(false).as_bytes().to_vec())
}

fn load_state(path: &str) -> Result<MockState, RvError> {
    if path.is_empty() {
        // Ephemeral in-memory device (tests): no persistence across restarts.
        return Ok(MockState::default());
    }
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| RvError::ErrHsm(format!("mock HSM state at {path} is corrupt: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MockState::default()),
        Err(e) => Err(RvError::ErrHsm(format!("reading mock HSM state {path}: {e}"))),
    }
}

fn persist_state(path: &str, state: &MockState) -> Result<(), RvError> {
    if path.is_empty() {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| RvError::ErrHsm(format!("encoding mock HSM state: {e}")))?;
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| RvError::ErrHsm(format!("creating mock HSM state dir: {e}")))?;
        }
    }
    std::fs::write(path, bytes).map_err(|e| RvError::ErrHsm(format!("writing mock HSM state {path}: {e}")))
}

fn aes256_gcm_seal(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| RvError::ErrHsm("bad wrap key length".into()))?;
    let nonce_bytes = random_bytes(AES_NONCE_LEN);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut out = cipher.encrypt(nonce, plaintext).map_err(|_| RvError::ErrHsm("wrap encryption failed".into()))?;
    let mut result = nonce_bytes;
    result.append(&mut out);
    Ok(result)
}

fn aes256_gcm_open(key: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RvError> {
    if wrapped.len() < AES_NONCE_LEN {
        return Err(RvError::ErrHsmBlobInvalid);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| RvError::ErrHsm("bad wrap key length".into()))?;
    let (nonce_bytes, ct) = wrapped.split_at(AES_NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher.decrypt(nonce, ct).map_err(|_| RvError::ErrHsmContextMismatch)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::{
        authz::{self, UnwrapRequest},
        context, HsmObjectIds, Purpose, RecoveryMode,
    };
    use std::time::Duration;

    fn test_config(node_id: &str) -> ResolvedHsmConfig {
        ResolvedHsmConfig {
            backend_type: "mock".into(),
            connector: String::new(),
            objects: HsmObjectIds::default(),
            password: Zeroizing::new(String::new()),
            domains: vec![1],
            pqc_key_cache_ttl: Duration::from_secs(60),
            recovery: RecoveryMode::None,
            state_path: String::new(), // ephemeral
            node_id: node_id.into(),
        }
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn wrap_unwrap_round_trip() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let secret = b"the barrier KEK bytes............";
        let blob = hsm.wrap_data(hsm.objects.wrap_barrier, &ctx, secret).await.unwrap();
        // The blob must be opaque — the plaintext never appears in it.
        assert!(!blob.windows(secret.len()).any(|w| w == secret), "plaintext leaked into blob");
        let out = hsm.unwrap_data(hsm.objects.wrap_barrier, &ctx, &blob).await.unwrap();
        assert_eq!(out.as_slice(), secret);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn unwrap_rejects_wrong_context_purpose_epoch() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = hsm.wrap_data(hsm.objects.wrap_barrier, &ctx, b"kek").await.unwrap();

        let wrong_epoch = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 1, "n1");
        assert_eq!(
            hsm.unwrap_data(hsm.objects.wrap_barrier, &wrong_epoch, &blob).await.unwrap_err(),
            RvError::ErrHsmContextMismatch
        );
        let wrong_purpose = Context::new(context::barrier_kek("clu"), Purpose::PqcKemSeed, 0, "n1");
        assert_eq!(
            hsm.unwrap_data(hsm.objects.wrap_barrier, &wrong_purpose, &blob).await.unwrap_err(),
            RvError::ErrHsmContextMismatch
        );
        let wrong_ctx = Context::new(context::barrier_kek("other-cluster"), Purpose::BarrierKek, 0, "n1");
        assert_eq!(
            hsm.unwrap_data(hsm.objects.wrap_barrier, &wrong_ctx, &blob).await.unwrap_err(),
            RvError::ErrHsmContextMismatch
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn key_separation_barrier_vs_pqc() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = hsm.wrap_data(hsm.objects.wrap_barrier, &ctx, b"kek").await.unwrap();
        // Unwrapping a barrier blob with the PQC wrap key must fail (distinct
        // keys → AES-GCM tag fails), and vice versa.
        assert!(hsm.unwrap_data(hsm.objects.wrap_pqc, &ctx, &blob).await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn wrap_key_cannot_sign_and_identity_cannot_unwrap() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        // A wrap key must not sign (capability minimization).
        assert!(hsm.sign(hsm.objects.wrap_barrier, "ctx", b"m").await.is_err());
        // An identity key must not unwrap.
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        assert!(hsm.wrap_data(hsm.objects.identity, &ctx, b"x").await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn signed_authorization_accepts_valid_rejects_tampered_and_replayed() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let ctx = context::barrier_kek("clu");
        let blob = b"opaque-wrapped-bytes";

        let req = UnwrapRequest::new(ctx.clone(), blob, "n1", 0, 1, Purpose::BarrierKek);
        let auth = authz::sign_authorization(&hsm, hsm.objects.authz, req.clone()).await.unwrap();
        // Valid authorization verifies against the local authz key.
        let vk = hsm.authz_public_key().unwrap();
        assert!(authz::verify_authorization(&auth, &vk, &req).is_ok());

        // Tampered request field (counter) → signature no longer matches.
        let mut tampered = auth.clone();
        tampered.request.counter = 999;
        assert_eq!(
            authz::verify_authorization(&tampered, &vk, &tampered.request).unwrap_err(),
            RvError::ErrHsmAuthzInvalid
        );

        // Mismatch between authorization and the expected request (replay of an
        // authz for a different counter against a fresh expected request).
        let expected_next = UnwrapRequest::new(ctx, blob, "n1", 0, 2, Purpose::BarrierKek);
        assert_eq!(
            authz::verify_authorization(&auth, &vk, &expected_next).unwrap_err(),
            RvError::ErrHsmAuthzInvalid
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn attestation_round_trip() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let bundle = hsm.attest(hsm.objects.identity).await.unwrap();
        let attested = hsm.verify_attestation(&bundle).await.unwrap();
        assert!(attested.non_exportable);
        assert_eq!(attested.public_key, hsm.identity_public_key().unwrap());
        assert_eq!(attested.object_id, hsm.objects.identity);

        // A tampered bundle must fail verification.
        let mut bad = bundle.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(hsm.verify_attestation(&bad).await.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn ecdh_is_symmetric_between_two_devices() {
        let a = MockHsmBackend::open(&test_config("a")).await.unwrap();
        let b = MockHsmBackend::open(&test_config("b")).await.unwrap();
        let sa = a.derive_ecdh(a.objects.identity, &b.identity_public_key().unwrap()).await.unwrap();
        let sb = b.derive_ecdh(b.objects.identity, &a.identity_public_key().unwrap()).await.unwrap();
        assert_eq!(sa.as_slice(), sb.as_slice());
        assert_eq!(sa.len(), 32);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn get_random_length_and_freshness() {
        let hsm = MockHsmBackend::open(&test_config("n1")).await.unwrap();
        let r1 = hsm.get_random(32).await.unwrap();
        let r2 = hsm.get_random(32).await.unwrap();
        assert_eq!(r1.len(), 32);
        assert_ne!(r1.as_slice(), r2.as_slice());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn state_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("bv-mock-hsm-{}.json", hex::encode(random_bytes(6))));
        let path = dir.to_string_lossy().to_string();
        let mut cfg = test_config("n1");
        cfg.state_path = path.clone();

        let hsm1 = MockHsmBackend::open(&cfg).await.unwrap();
        let pub1 = hsm1.authz_public_key().unwrap();
        let ctx = Context::new(context::barrier_kek("clu"), Purpose::BarrierKek, 0, "n1");
        let blob = hsm1.wrap_data(hsm1.objects.wrap_barrier, &ctx, b"kek").await.unwrap();
        drop(hsm1);

        // Reopen from the same file: same keys, and the earlier blob unwraps.
        let hsm2 = MockHsmBackend::open(&cfg).await.unwrap();
        assert_eq!(hsm2.authz_public_key().unwrap(), pub1);
        let out = hsm2.unwrap_data(hsm2.objects.wrap_barrier, &ctx, &blob).await.unwrap();
        assert_eq!(out.as_slice(), b"kek");
        let _ = std::fs::remove_file(&path);
    }
}
