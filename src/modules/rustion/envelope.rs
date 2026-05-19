//! Thin adapter between the in-tree `bv_crypto::bvrg` envelope crate
//! and BastionVault's own master-key store + Rustion target registry.
//!
//! The envelope wire format itself is owned by `bv_crypto` (Phase 2
//! deliverable) — this module supplies the **glue** that:
//!   - loads the master keypair from the rustion-master PKI slot,
//!   - resolves a Rustion target's hybrid pubkey from the registry,
//!   - stamps the standard operator/correlation/nonce metadata,
//!   - returns the bytes a higher-level handler will POST at the
//!     Rustion control plane.
//!
//! Phase 2 ships the **builders** for the four envelope operations
//! (`open`, `renew`, `kill`, `attest`); the session-state machine
//! that consumes them lands in Phase 3 alongside the dispatcher.
//! Verify is not exposed here — BastionVault doesn't decrypt
//! envelopes it builds (Rustion does); the verify entry point is in
//! `bv_crypto::bvrg::verify` and is consumed by integration tests +
//! the Rustion-side control-plane crate.

use bv_crypto::{
    bvrg, BvrgCredential, BvrgError, BvrgMasterPublicKey, BvrgMasterSigningKey, BvrgOperator,
    BvrgPayload, BvrgSession, BvrgTarget,
};
use uuid::Uuid;

use super::config::RustionTarget;

/// One operator's audit + correlation context for a single envelope.
/// Populated by the Tauri command surface from the calling token's
/// metadata before the build call; never assembled inside this module
/// because the source-of-truth is the auth layer.
#[derive(Debug, Clone)]
pub struct OperatorContext {
    pub vault_user_id: String,
    pub vault_user_name: String,
    pub vault_session_id: String,
    pub src_ip: String,
    /// Deployment id for the Phase-9 attestation binding. Set on the
    /// master at init time; threaded through every envelope so a
    /// cloned BV reusing the master pubkey is refused by Rustion
    /// with `attestation_mismatch`.
    pub deployment_id: String,
}

/// Result of a build call: the wire bytes plus the envelope's
/// SHA-256 fingerprint, which audit handlers need to link the
/// outgoing envelope to follow-up Rustion-side hash-chain entries
/// without re-hashing.
pub struct BuiltEnvelope {
    pub bytes: Vec<u8>,
    pub fingerprint: [u8; 32],
    pub nonce: Vec<u8>,
    pub correlation_id: String,
}

/// What kind of credential is being shipped inside the envelope. The
/// caller pulls one of these out of the credential-source resolver
/// (Phase 3) and hands it to `build_open`.
#[derive(Debug, Clone)]
pub struct CredentialMaterial {
    pub kind: String,
    pub username: String,
    pub material: Vec<u8>,
}

/// Build an `open` envelope. Phase 3 calls this once the operator's
/// credential source has been resolved and the dispatcher has picked
/// the destination Rustion target.
pub fn build_open(
    master: &BvrgMasterSigningKey,
    target: &RustionTarget,
    operator: &OperatorContext,
    op_target_host: &str,
    op_target_port: u16,
    op_target_protocol: &str,
    op_target_hostkey_pin: Option<String>,
    credential: CredentialMaterial,
    ttl_secs: u32,
    max_renewals: u8,
    recording: &str,
) -> Result<BuiltEnvelope, BvrgError> {
    let nonce = bvrg::fresh_nonce();
    let correlation_id = Uuid::new_v4().to_string();
    let issued_at = bvrg::unix_now();
    // `not_after` bounds signature validity, not session TTL. 5 min
    // window matches the spec's recommended replay-window default
    // on the Rustion side; envelopes that take longer than that to
    // arrive get a fresh build on the next attempt.
    let not_after = issued_at + 5 * 60;

    let payload = BvrgPayload {
        v: 1,
        op: "open".to_string(),
        nonce: nonce.clone(),
        issued_at,
        not_after,
        target: Some(BvrgTarget {
            host: op_target_host.to_string(),
            port: op_target_port,
            protocol: op_target_protocol.to_string(),
            hostkey_pin: op_target_hostkey_pin,
        }),
        credential: Some(BvrgCredential {
            kind: credential.kind,
            username: credential.username,
            material: credential.material,
            extra: None,
        }),
        session: Some(BvrgSession {
            ttl_secs,
            max_renewals,
            recording: recording.to_string(),
        }),
        operator: BvrgOperator {
            vault_user_id: operator.vault_user_id.clone(),
            vault_user_name: operator.vault_user_name.clone(),
            vault_session_id: operator.vault_session_id.clone(),
            src_ip: operator.src_ip.clone(),
            deployment_id: operator.deployment_id.clone(),
        },
        correlation_id: correlation_id.clone(),
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope {
        bytes,
        fingerprint,
        nonce,
        correlation_id,
    })
}

/// Build a `renew` envelope referencing the same `correlation_id` +
/// `vault_session_id` as the open it extends. Rustion refuses
/// renewals whose correlation differs from the original.
pub fn build_renew(
    master: &BvrgMasterSigningKey,
    target: &RustionTarget,
    operator: &OperatorContext,
    correlation_id: &str,
    extend_secs: u32,
) -> Result<BuiltEnvelope, BvrgError> {
    let nonce = bvrg::fresh_nonce();
    let issued_at = bvrg::unix_now();
    let payload = BvrgPayload {
        v: 1,
        op: "renew".to_string(),
        nonce: nonce.clone(),
        issued_at,
        not_after: issued_at + 5 * 60,
        target: None,
        credential: None,
        session: Some(BvrgSession {
            ttl_secs: extend_secs,
            max_renewals: 0,
            recording: "always".to_string(),
        }),
        operator: BvrgOperator {
            vault_user_id: operator.vault_user_id.clone(),
            vault_user_name: operator.vault_user_name.clone(),
            vault_session_id: operator.vault_session_id.clone(),
            src_ip: operator.src_ip.clone(),
            deployment_id: operator.deployment_id.clone(),
        },
        correlation_id: correlation_id.to_string(),
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope {
        bytes,
        fingerprint,
        nonce,
        correlation_id: correlation_id.to_string(),
    })
}

/// Build a `kill` envelope. Rustion drops the matching session
/// immediately on a verified `kill`; the chain logs
/// `session.terminate` on the Rustion side.
pub fn build_kill(
    master: &BvrgMasterSigningKey,
    target: &RustionTarget,
    operator: &OperatorContext,
    correlation_id: &str,
) -> Result<BuiltEnvelope, BvrgError> {
    let nonce = bvrg::fresh_nonce();
    let issued_at = bvrg::unix_now();
    let payload = BvrgPayload {
        v: 1,
        op: "kill".to_string(),
        nonce: nonce.clone(),
        issued_at,
        not_after: issued_at + 5 * 60,
        target: None,
        credential: None,
        session: None,
        operator: BvrgOperator {
            vault_user_id: operator.vault_user_id.clone(),
            vault_user_name: operator.vault_user_name.clone(),
            vault_session_id: operator.vault_session_id.clone(),
            src_ip: operator.src_ip.clone(),
            deployment_id: operator.deployment_id.clone(),
        },
        correlation_id: correlation_id.to_string(),
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope {
        bytes,
        fingerprint,
        nonce,
        correlation_id: correlation_id.to_string(),
    })
}

/// Build an `attest` envelope. Phase 9's weekly re-attestation timer
/// calls this once per enrolled target; Rustion bumps the authority
/// record's `attestation_renew_at` on acceptance.
pub fn build_attest(
    master: &BvrgMasterSigningKey,
    target: &RustionTarget,
    operator: &OperatorContext,
) -> Result<BuiltEnvelope, BvrgError> {
    let nonce = bvrg::fresh_nonce();
    let correlation_id = Uuid::new_v4().to_string();
    let issued_at = bvrg::unix_now();
    let payload = BvrgPayload {
        v: 1,
        op: "attest".to_string(),
        nonce: nonce.clone(),
        issued_at,
        not_after: issued_at + 5 * 60,
        target: None,
        credential: None,
        session: None,
        operator: BvrgOperator {
            vault_user_id: operator.vault_user_id.clone(),
            vault_user_name: operator.vault_user_name.clone(),
            vault_session_id: operator.vault_session_id.clone(),
            src_ip: operator.src_ip.clone(),
            deployment_id: operator.deployment_id.clone(),
        },
        correlation_id: correlation_id.clone(),
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope {
        bytes,
        fingerprint,
        nonce,
        correlation_id,
    })
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Resolve the **KEM** public key for a Rustion target.
///
/// Important distinction from the **signing** pubkey on the same
/// authority record: BV signs the envelope (so the receiver pins the
/// BV master pubkey) and encrypts the payload to Rustion (so the
/// sender needs Rustion's KEM pubkey). The two are independent
/// keypairs on the Rustion identity side — the authority record
/// pins the signing pubkey for the recording webhook, and the
/// target's `public_key` field on the BV side pins the KEM pubkey.
///
/// Today the target registry stores the **Ed25519 + ML-DSA-65 hybrid
/// signing pubkey** Rustion uses for outbound `recording.ready`
/// webhooks. The KEM pubkey is a future extension: the Phase 2 spec
/// notes that each Rustion instance has "its own hybrid keypair" for
/// envelope encryption, distinct from the signing pubkey. Until the
/// registry grows a dedicated `kem_public_key` field, we synthesise
/// the KEM pubkey from a deterministic transform on the signing
/// pubkey so tests and integration scaffolding compile end-to-end.
/// **This MUST be replaced before Phase 2 closes** with a real KEM
/// pubkey field on `RustionTarget`.
///
/// TODO(phase2): add `kem_public_key: Vec<u8>` to RustionTarget and
/// have the enrolment wizard collect it alongside the signing pubkey.
fn resolve_kem_pubkey(target: &RustionTarget) -> Result<Vec<u8>, BvrgError> {
    // Decode the base64 Ed25519 + ML-DSA-65 halves. The KEM pubkey is
    // a separate slot once the registry schema lands; for now we use
    // the signing pubkey concatenation as a placeholder so the test
    // surface compiles.
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let ed25519 = STANDARD
        .decode(target.public_key.ed25519.as_bytes())
        .map_err(|_| BvrgError::PublicKeyLength)?;
    let mldsa65 = STANDARD
        .decode(target.public_key.mldsa65.as_bytes())
        .map_err(|_| BvrgError::PublicKeyLength)?;
    // The signing-pubkey bytes are NOT a valid ML-KEM-768 pubkey —
    // this synthesis path will fail at `KemDemEnvelopeV1::seal` time
    // with a coerced error. That's intentional: until the registry
    // gets a real KEM-pubkey field, build_open / build_renew /
    // build_kill / build_attest must be exercised against synthetic
    // targets in tests (which supply a freshly-generated ML-KEM-768
    // pubkey). Production callers will see a clear
    // `PublicKeyLength` error pointing them at the missing field.
    let mut concat = Vec::with_capacity(ed25519.len() + mldsa65.len());
    concat.extend_from_slice(&ed25519);
    concat.extend_from_slice(&mldsa65);
    Ok(concat)
}

/// Compute the same SHA-256(magic || ct_len || ct) the verify path
/// derives. Re-implemented here so audit handlers don't need to
/// re-parse the envelope.
fn envelope_fingerprint(envelope: &[u8]) -> Result<[u8; 32], BvrgError> {
    use sha2::{Digest, Sha256};

    if envelope.len() < bv_crypto::BVRG_MAGIC.len() + 2 + 4 {
        return Err(BvrgError::EnvelopeTooShort);
    }
    let mut cursor = bv_crypto::BVRG_MAGIC.len();
    let sig_len = u16::from_be_bytes(envelope[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2 + sig_len;
    if cursor + 4 > envelope.len() {
        return Err(BvrgError::EnvelopeTooShort);
    }
    let ct_len = u32::from_be_bytes(envelope[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let ct = &envelope[cursor..];
    let mut h = Sha256::new();
    h.update(bv_crypto::BVRG_MAGIC);
    h.update(ct_len.to_be_bytes());
    h.update(ct);
    Ok(h.finalize().into())
}

/// Resolve the master signing keypair the build calls need.
///
/// Phase 2 ships the loader stub — the full PKI hookup
/// (issue + persist + rotate) rides on Phase 9's enrolment lifecycle
/// and is wired in once `master.rs` grows its issue-from-PKI path.
/// Today the caller passes a freshly generated keypair via the test
/// surface; production callers see a clear "master not initialised"
/// error from the higher-level handler.
pub fn load_master_signing_key() -> Result<BvrgMasterSigningKey, BvrgError> {
    Err(BvrgError::PublicKeyLength) // sentinel — replaced in Phase 9
}

/// Project the master pubkey for `bvault rustion master export` and
/// for the test surface. Returns `Err` when the master hasn't been
/// initialised yet; the GUI surfaces this as "configure master first".
pub fn load_master_public_key() -> Result<BvrgMasterPublicKey, BvrgError> {
    Err(BvrgError::PublicKeyLength) // sentinel — replaced in Phase 9
}

#[cfg(test)]
mod tests {
    use super::*;
    use bv_crypto::{KemProvider, MlKem768Provider};

    fn synthetic_target_with_kem_pub(kem_pub: &[u8]) -> RustionTarget {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        // For the test scaffold, the legacy registry's hybrid pubkey
        // field is repurposed to carry the KEM pubkey (ed25519 slot
        // empty, mldsa65 slot = base64(kem_pub)). resolve_kem_pubkey
        // currently concatenates ed25519 || mldsa65 so we land at
        // the requested kem_pub on the wire.
        RustionTarget {
            id: "rt_test".into(),
            name: "test-bastion".into(),
            endpoint: "rustion-test.internal:9443".into(),
            public_key: crate::modules::rustion::config::HybridPubKey {
                ed25519: String::new(),
                mldsa65: STANDARD.encode(kem_pub),
            },
            fingerprint: String::new(),
            description: String::new(),
            tags: vec![],
            enabled: true,
            default_recording_dir: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn op_ctx() -> OperatorContext {
        OperatorContext {
            vault_user_id: "uuid-op".into(),
            vault_user_name: "alice".into(),
            vault_session_id: "uuid-sess".into(),
            src_ip: "10.0.1.5".into(),
            deployment_id: "uuid-deploy".into(),
        }
    }

    #[test]
    fn build_open_then_verify_roundtrips() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let master_pub = master.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built = build_open(
            &master,
            &target,
            &op_ctx(),
            "prod-web-01.internal",
            22,
            "ssh",
            None,
            CredentialMaterial {
                kind: "ssh-password".into(),
                username: "deploy".into(),
                material: b"hunter2".to_vec(),
            },
            3600,
            3,
            "always",
        )
        .expect("build_open");

        let verified =
            bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).expect("verify");
        assert_eq!(verified.payload.op, "open");
        assert_eq!(verified.payload.correlation_id, built.correlation_id);
        assert_eq!(verified.envelope_fingerprint, built.fingerprint);
        let cred = verified.payload.credential.unwrap();
        assert_eq!(cred.username, "deploy");
    }

    #[test]
    fn build_renew_carries_correlation() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let master_pub = master.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built =
            build_renew(&master, &target, &op_ctx(), "uuid-corr-original", 1800).unwrap();
        let verified =
            bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).expect("verify");
        assert_eq!(verified.payload.op, "renew");
        assert_eq!(verified.payload.correlation_id, "uuid-corr-original");
        assert!(verified.payload.session.unwrap().ttl_secs == 1800);
    }

    #[test]
    fn build_kill_omits_credential_and_target() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let master_pub = master.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built = build_kill(&master, &target, &op_ctx(), "uuid-corr").unwrap();
        let verified = bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).unwrap();
        assert_eq!(verified.payload.op, "kill");
        assert!(verified.payload.credential.is_none());
        assert!(verified.payload.target.is_none());
    }

    #[test]
    fn build_attest_op() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let master_pub = master.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built = build_attest(&master, &target, &op_ctx()).unwrap();
        let verified = bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).unwrap();
        assert_eq!(verified.payload.op, "attest");
        assert_eq!(verified.payload.operator.deployment_id, "uuid-deploy");
    }
}
