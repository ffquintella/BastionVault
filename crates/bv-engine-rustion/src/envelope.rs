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
    bvrg, BvrgCredential, BvrgError, BvrgMasterPublicKey, BvrgMasterSigningKey, BvrgOperator, BvrgPayload, BvrgSession,
    BvrgTarget,
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
    /// For `ssh-cert`: the signed OpenSSH certificate text. Sealed into
    /// the envelope's `credential.extra["cert"]` map — the same shape
    /// Rustion's control plane reads (`SessionCredential::openssh_cert`).
    /// `material` carries the matching ephemeral private key. `None` for
    /// every other kind.
    pub cert: Option<String>,
    /// For `rdp-cert` (smart-card RDP through the bastion): the private
    /// key + PIN + optional domain that go alongside the certificate.
    /// `material` carries the certificate DER; this struct carries the
    /// rest, sealed into the envelope's `credential.extra` map under
    /// `key` / `pin` / `domain`. Rustion decrypts them inside its own
    /// process and drives the upstream Kerberos PKINIT / SPNEGO CredSSP
    /// exchange with the smart-card identity. `None` for every other
    /// kind.
    pub rdp_cert: Option<RdpCertMaterial>,
}

/// Smart-card material for an `rdp-cert` envelope. The certificate DER
/// travels in `CredentialMaterial::material`; the private key + PIN
/// travel here and are sealed into `credential.extra`.
#[derive(Debug, Clone)]
pub struct RdpCertMaterial {
    /// DER-encoded private key matching the certificate. PKCS#1 or
    /// PKCS#8; the bastion's sspi smart-card identity parses either.
    pub private_key_der: Vec<u8>,
    /// Smart-card PIN. The bastion's emulated PIV card accepts any
    /// non-empty value; carried so the sspi credential is well-formed.
    pub pin: String,
    /// Optional AD domain / realm. Empty when the UPN in the cert is
    /// authoritative.
    pub domain: String,
}

/// Build the `credential.extra` CBOR map for a credential, or `None`
/// when the kind carries no side data. Keeps the two cert-bearing kinds
/// (`ssh-cert` text vs `rdp-cert` key/pin/domain) in one place so the
/// wire shape Rustion reads back stays in lockstep with what we write.
fn build_credential_extra(credential: &CredentialMaterial) -> Option<ciborium::value::Value> {
    use ciborium::value::Value as CborValue;
    if let Some(cert) = &credential.cert {
        // ssh-cert: the signed OpenSSH certificate text.
        return Some(CborValue::Map(vec![(CborValue::Text("cert".to_string()), CborValue::Text(cert.clone()))]));
    }
    if let Some(rc) = &credential.rdp_cert {
        // rdp-cert: private key (DER bytes) + PIN (+ optional domain).
        let mut map = vec![
            (CborValue::Text("key".to_string()), CborValue::Bytes(rc.private_key_der.clone())),
            (CborValue::Text("pin".to_string()), CborValue::Text(rc.pin.clone())),
        ];
        if !rc.domain.is_empty() {
            map.push((CborValue::Text("domain".to_string()), CborValue::Text(rc.domain.clone())));
        }
        return Some(CborValue::Map(map));
    }
    None
}

/// Longest command an `exec` open may seal (Rustion
/// `docs/rustion-agent-exec.md` § Envelope; 4 KiB so a command plus a
/// password credential still fits the frozen 16 KiB envelope).
pub const MAX_EXEC_COMMAND_BYTES: usize = 4096;

/// What an `open` envelope asks the bastion to start
/// (`features/rustion-agent-exec.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenKind<'a> {
    /// A shell or desktop. Seals neither `kind` nor `command`, so the
    /// envelope is byte-for-byte what earlier releases built.
    Interactive,
    /// One operator-confirmed command, bound into the sealed payload.
    Exec { command: &'a str },
}

/// Why an `open` envelope was not built. Every variant is decided before
/// anything is posted.
#[derive(Debug, thiserror::Error)]
pub enum OpenEnvelopeError {
    /// The exec form breaks one of the bastion's open rules. `code` and
    /// `detail` are Rustion's own (`exec_command_invalid` /
    /// `command_too_long`, …), so the vault refuses with the answer the
    /// bastion would have given, without the round trip.
    #[error("{code}: {detail}")]
    ExecForm { code: &'static str, detail: &'static str },
    /// The sealed envelope would exceed [`bv_crypto::MAX_ENVELOPE_BYTES`];
    /// the bastion refuses it before decrypting, so it is never posted.
    #[error(
        "envelope_too_large: the sealed open envelope exceeds the bastion's {} byte limit; the command plus the \
         credential is too long (shorten the command)",
        bv_crypto::MAX_ENVELOPE_BYTES
    )]
    TooLarge,
    #[error(transparent)]
    Bvrg(BvrgError),
}

impl From<BvrgError> for OpenEnvelopeError {
    fn from(e: BvrgError) -> Self {
        match e {
            // Both caps are size caps on what would be sent: the payload's
            // inner budget and the frame's.
            BvrgError::EnvelopeTooLong | BvrgError::PayloadTooLong => Self::TooLarge,
            other => Self::Bvrg(other),
        }
    }
}

/// The bastion's open rules for the exec form, checked before anything is
/// sealed: a command of 1-4096 UTF-8 bytes that is not all whitespace and
/// has no NUL, an SSH target, and a non-empty host-key pin (an exec has no
/// operator to judge a trust-on-first-use prompt).
pub fn validate_exec_form(command: &str, protocol: &str, hostkey_pin: Option<&str>) -> Result<(), OpenEnvelopeError> {
    let invalid = |detail| OpenEnvelopeError::ExecForm { code: "exec_command_invalid", detail };
    if command.trim().is_empty() {
        return Err(invalid("command_empty"));
    }
    if command.len() > MAX_EXEC_COMMAND_BYTES {
        return Err(invalid("command_too_long"));
    }
    if command.contains('\0') {
        return Err(invalid("command_contains_nul"));
    }
    if protocol != "ssh" {
        return Err(OpenEnvelopeError::ExecForm { code: "exec_protocol_unsupported", detail: "exec_requires_ssh" });
    }
    if hostkey_pin.map(str::trim).is_none_or(str::is_empty) {
        return Err(OpenEnvelopeError::ExecForm { code: "exec_hostkey_pin_required", detail: "hostkey_pin_required" });
    }
    Ok(())
}

/// Build an `open` envelope once the credential is resolved and the
/// dispatcher has picked the Rustion target. [`OpenKind::Exec`] seals
/// `kind = "exec"` and the command (after [`validate_exec_form`]); an
/// envelope past the bastion's cap is [`OpenEnvelopeError::TooLarge`].
#[allow(clippy::too_many_arguments)]
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
    kind: OpenKind<'_>,
) -> Result<BuiltEnvelope, OpenEnvelopeError> {
    let (kind, command) = match kind {
        OpenKind::Interactive => (None, None),
        OpenKind::Exec { command } => {
            validate_exec_form(command, op_target_protocol, op_target_hostkey_pin.as_deref())?;
            (Some("exec".to_string()), Some(command.to_string()))
        }
    };
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
            // Seal any credential-kind side data into `extra`: for
            // `ssh-cert` the signed OpenSSH cert text under `cert`; for
            // `rdp-cert` the smart-card private key + PIN under
            // `key`/`pin`/`domain`. Rustion decrypts inside its own
            // process. Other kinds carry no `extra`.
            extra: build_credential_extra(&credential),
            kind: credential.kind,
            username: credential.username,
            material: credential.material,
        }),
        session: Some(BvrgSession { ttl_secs, max_renewals, recording: recording.to_string() }),
        operator: BvrgOperator {
            vault_user_id: operator.vault_user_id.clone(),
            vault_user_name: operator.vault_user_name.clone(),
            vault_session_id: operator.vault_session_id.clone(),
            src_ip: operator.src_ip.clone(),
            deployment_id: operator.deployment_id.clone(),
        },
        correlation_id: correlation_id.clone(),
        kind,
        command,
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    // `build` already refuses past the cap; checked again here, where the
    // bytes are handed out to be posted, so no later change to the builder
    // can send the bastion an envelope it would only refuse.
    if bytes.len() > bv_crypto::MAX_ENVELOPE_BYTES {
        return Err(OpenEnvelopeError::TooLarge);
    }
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope { bytes, fingerprint, nonce, correlation_id })
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
        session: Some(BvrgSession { ttl_secs: extend_secs, max_renewals: 0, recording: "always".to_string() }),
        operator: BvrgOperator {
            vault_user_id: operator.vault_user_id.clone(),
            vault_user_name: operator.vault_user_name.clone(),
            vault_session_id: operator.vault_session_id.clone(),
            src_ip: operator.src_ip.clone(),
            deployment_id: operator.deployment_id.clone(),
        },
        correlation_id: correlation_id.to_string(),
        kind: None,
        command: None,
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope { bytes, fingerprint, nonce, correlation_id: correlation_id.to_string() })
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
        kind: None,
        command: None,
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope { bytes, fingerprint, nonce, correlation_id: correlation_id.to_string() })
}

/// Build a `deenrol` envelope. Phase 9.2 — BV sends this just before
/// deleting a target locally so Rustion can tombstone the authority
/// in lock-step rather than discovering the deletion via timeout.
pub fn build_deenrol(
    master: &BvrgMasterSigningKey,
    target: &RustionTarget,
    operator: &OperatorContext,
    reason: &str,
) -> Result<BuiltEnvelope, BvrgError> {
    let nonce = bvrg::fresh_nonce();
    let correlation_id = Uuid::new_v4().to_string();
    let issued_at = bvrg::unix_now();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("reason".to_string(), reason.to_string());
    let payload = BvrgPayload {
        v: 1,
        op: "deenrol".to_string(),
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
        kind: None,
        command: None,
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    // `extra` isn't carried inside `BvrgPayload` directly; the reason is
    // surfaced only in the BV-side audit. Rustion infers the deenrol
    // intent from `op = "deenrol"`.
    let _ = extra;
    Ok(BuiltEnvelope { bytes, fingerprint, nonce, correlation_id })
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
        kind: None,
        command: None,
    };

    let rustion_pub = resolve_kem_pubkey(target)?;
    let bytes = bvrg::build(&payload, master, &rustion_pub)?;
    let fingerprint = envelope_fingerprint(&bytes)?;
    Ok(BuiltEnvelope { bytes, fingerprint, nonce, correlation_id })
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Resolve the **KEM** public key for a Rustion target.
///
/// Important distinction from the **signing** pubkey on the same
/// authority record: BV signs the envelope (so the receiver pins the
/// BV master pubkey) and encrypts the payload to Rustion (so the
/// sender needs Rustion's KEM pubkey). The two are independent
/// keypairs on the Rustion identity side — the authority record
/// pins the signing pubkey for the recording webhook + signed-nonce
/// health responses, and the dedicated `kem_public_key` field on
/// the registry pins the ML-KEM-768 pubkey for envelope encryption.
///
/// Decode the base64 pubkey bytes; an empty field means the
/// enrolment never collected the KEM half (registry record predates
/// the schema extension or operator skipped the wizard step). In
/// both cases we refuse the envelope build with a clear error
/// pointing the operator at the enrolment wizard.
fn resolve_kem_pubkey(target: &RustionTarget) -> Result<Vec<u8>, BvrgError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if target.kem_public_key.trim().is_empty() {
        return Err(BvrgError::PublicKeyLength);
    }
    STANDARD.decode(target.kem_public_key.as_bytes()).map_err(|_| BvrgError::PublicKeyLength)
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

/// Verify an envelope against an ordered list of acceptable master
/// pubkeys. Tries each in turn; on first success returns the
/// verified payload + the index of the key that matched (so callers
/// can audit "this envelope was accepted by the previous master").
///
/// Phase 2 grace-window contract: `master_pubs[0]` is the current
/// master, `master_pubs[1..]` is the previous master while it is
/// still inside the rotate-grace window. `MasterStore::load_active_keys`
/// only emits the previous key when `now < previous_grace_until`,
/// so a stale previous key is never even offered to this helper.
///
/// All-failure case returns the error from the **last** attempt —
/// the current master — so the operator-facing message stays focused
/// on the live binding rather than the previous one.
pub fn verify_with_grace(
    envelope: &[u8],
    master_pubs: &[BvrgMasterPublicKey],
    rustion_kem_secret: &[u8],
) -> Result<(bv_crypto::bvrg::VerifiedEnvelope, usize), BvrgError> {
    if master_pubs.is_empty() {
        return Err(BvrgError::PublicKeyLength);
    }
    let mut last_err: Option<BvrgError> = None;
    for (idx, pk) in master_pubs.iter().enumerate() {
        match bvrg::verify(envelope, pk, rustion_kem_secret) {
            Ok(v) => return Ok((v, idx)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(BvrgError::PublicKeyLength))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bv_crypto::{KemProvider, MlKem768Provider};

    fn synthetic_target_with_kem_pub(kem_pub: &[u8]) -> RustionTarget {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        RustionTarget {
            id: "rt_test".into(),
            name: "test-bastion".into(),
            endpoint: "rustion-test.internal:9443".into(),
            public_key: crate::config::HybridPubKey {
                ed25519: STANDARD.encode([7u8; 32]), // synthetic — unused by KEM path
                mldsa65: STANDARD.encode([7u8; 16]),
            },
            kem_public_key: STANDARD.encode(kem_pub),
            fingerprint: String::new(),
            description: String::new(),
            tags: vec![],
            enabled: true,
            default_recording_dir: String::new(),
            tls_pinned_cert_pem: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            ssh_listener_host: String::new(),
            ssh_listener_port: 0,
            rdp_listener_host: String::new(),
            rdp_listener_port: 0,
            listeners_synced_at: String::new(),
            ssh_host_key_fingerprint: String::new(),
            rdp_tls_pin_sha256: String::new(),
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
                cert: None,
                rdp_cert: None,
            },
            3600,
            3,
            "always",
            OpenKind::Interactive,
        )
        .expect("build_open");

        let verified = bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).expect("verify");
        assert_eq!(verified.payload.op, "open");
        assert_eq!(verified.payload.correlation_id, built.correlation_id);
        assert_eq!(verified.envelope_fingerprint, built.fingerprint);
        let cred = verified.payload.credential.unwrap();
        assert_eq!(cred.username, "deploy");
    }

    #[test]
    fn build_open_ssh_cert_seals_cert_in_extra() {
        // A brokered `ssh-cert` envelope carries the ephemeral private key
        // in `material` and the signed OpenSSH certificate text under
        // `extra["cert"]` — the shape Rustion's control plane consumes.
        let master = BvrgMasterSigningKey::generate().unwrap();
        let master_pub = master.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built = build_open(
            &master,
            &target,
            &op_ctx(),
            "db01.internal",
            22,
            "ssh",
            None,
            CredentialMaterial {
                kind: "ssh-cert".into(),
                username: "alice".into(),
                material: b"-----BEGIN OPENSSH PRIVATE KEY-----\nEPHEMERAL\n-----END OPENSSH PRIVATE KEY-----\n"
                    .to_vec(),
                cert: Some("ssh-ed25519-cert-v01@openssh.com AAAA... alice".into()),
                rdp_cert: None,
            },
            900,
            0,
            "always",
            OpenKind::Interactive,
        )
        .expect("build_open ssh-cert");

        let verified = bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).expect("verify");
        let cred = verified.payload.credential.expect("credential present");
        assert_eq!(cred.kind, "ssh-cert");
        assert_eq!(cred.username, "alice");
        assert!(!cred.material.is_empty(), "ephemeral private key must be carried in material");
        // The cert text round-trips under extra["cert"], matching
        // Rustion's `SessionCredential::openssh_cert` extraction.
        let extra = cred.extra.expect("extra map present");
        let ciborium::value::Value::Map(pairs) = extra else {
            panic!("extra must be a CBOR map");
        };
        let cert = pairs
            .iter()
            .find(|(k, _)| k.as_text() == Some("cert"))
            .and_then(|(_, v)| v.as_text())
            .expect("cert key in extra");
        assert_eq!(cert, "ssh-ed25519-cert-v01@openssh.com AAAA... alice");
    }

    #[test]
    fn build_open_rdp_cert_seals_key_pin_domain_in_extra() {
        // A brokered `rdp-cert` envelope carries the certificate DER in
        // `material` and the smart-card private key + PIN (+ domain)
        // under `extra` — the shape Rustion's RDP proxy consumes to drive
        // upstream Kerberos PKINIT / SPNEGO CredSSP.
        let master = BvrgMasterSigningKey::generate().unwrap();
        let master_pub = master.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built = build_open(
            &master,
            &target,
            &op_ctx(),
            "win-db01.internal",
            3389,
            "rdp",
            None,
            CredentialMaterial {
                kind: "rdp-cert".into(),
                username: "alice@corp.example".into(),
                material: b"\x30\x82CERTDER".to_vec(),
                cert: None,
                rdp_cert: Some(RdpCertMaterial {
                    private_key_der: b"\x30\x82KEYDER".to_vec(),
                    pin: "0000".into(),
                    domain: "CORP".into(),
                }),
            },
            900,
            0,
            "always",
            OpenKind::Interactive,
        )
        .expect("build_open");

        let verified = bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).expect("verify");
        let cred = verified.payload.credential.unwrap();
        assert_eq!(cred.kind, "rdp-cert");
        assert_eq!(cred.material, b"\x30\x82CERTDER", "cert DER in material");
        let ciborium::value::Value::Map(pairs) = cred.extra.expect("extra map") else {
            panic!("extra must be a CBOR map");
        };
        let key = pairs
            .iter()
            .find(|(k, _)| k.as_text() == Some("key"))
            .and_then(|(_, v)| match v {
                ciborium::value::Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .expect("key bytes in extra");
        assert_eq!(key, b"\x30\x82KEYDER");
        let pin = pairs
            .iter()
            .find(|(k, _)| k.as_text() == Some("pin"))
            .and_then(|(_, v)| v.as_text())
            .expect("pin in extra");
        assert_eq!(pin, "0000");
        let domain = pairs
            .iter()
            .find(|(k, _)| k.as_text() == Some("domain"))
            .and_then(|(_, v)| v.as_text())
            .expect("domain in extra");
        assert_eq!(domain, "CORP");
    }

    const PIN: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    fn password(material: &[u8]) -> CredentialMaterial {
        CredentialMaterial {
            kind: "ssh-password".into(),
            username: "ops".into(),
            material: material.to_vec(),
            cert: None,
            rdp_cert: None,
        }
    }

    fn open_exec(
        master: &BvrgMasterSigningKey,
        target: &RustionTarget,
        protocol: &str,
        pin: Option<&str>,
        credential: CredentialMaterial,
        command: &str,
    ) -> Result<BuiltEnvelope, OpenEnvelopeError> {
        build_open(
            master,
            target,
            &op_ctx(),
            "web-01.internal",
            22,
            protocol,
            pin.map(str::to_string),
            credential,
            90,
            0,
            "always",
            OpenKind::Exec { command },
        )
    }

    /// T483: the exec form seals `kind = "exec"` and exactly the confirmed
    /// command bytes; an interactive open seals neither.
    #[test]
    fn build_open_exec_seals_the_command_byte_for_byte() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());
        let command = "journalctl -u nginx -n 20 --no-pager | grep -v 'ok' ; echo \"é ✓\"";
        let built = open_exec(&master, &target, "ssh", Some(PIN), password(b"pw"), command).unwrap();
        let verified = bvrg::verify(&built.bytes, &master.public_key(), kp.secret_key()).unwrap();
        assert_eq!(verified.payload.kind.as_deref(), Some("exec"));
        assert_eq!(verified.payload.command.as_deref().map(str::as_bytes), Some(command.as_bytes()));
        assert_eq!(verified.payload.target.unwrap().hostkey_pin.as_deref(), Some(PIN));

        let interactive = build_open(
            &master,
            &target,
            &op_ctx(),
            "web-01.internal",
            22,
            "ssh",
            None,
            password(b"pw"),
            90,
            0,
            "always",
            OpenKind::Interactive,
        )
        .unwrap();
        let verified = bvrg::verify(&interactive.bytes, &master.public_key(), kp.secret_key()).unwrap();
        assert_eq!((verified.payload.kind, verified.payload.command), (None, None));
    }

    /// The bastion's open rules are applied before anything is sealed, with
    /// the bastion's own codes.
    #[test]
    fn build_open_exec_refuses_what_the_bastion_would_refuse() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());
        let refused = |protocol: &str, pin: Option<&str>, command: &str| match open_exec(
            &master,
            &target,
            protocol,
            pin,
            password(b"pw"),
            command,
        ) {
            Err(OpenEnvelopeError::ExecForm { code, detail }) => (code, detail),
            Err(other) => panic!("expected an exec-form refusal, got {other}"),
            Ok(_) => panic!("expected an exec-form refusal for {command:?}"),
        };
        assert_eq!(refused("ssh", Some(PIN), ""), ("exec_command_invalid", "command_empty"));
        assert_eq!(refused("ssh", Some(PIN), " \t\n"), ("exec_command_invalid", "command_empty"));
        assert_eq!(refused("ssh", Some(PIN), "id\0x"), ("exec_command_invalid", "command_contains_nul"));
        let long = "x".repeat(MAX_EXEC_COMMAND_BYTES + 1);
        assert_eq!(refused("ssh", Some(PIN), &long), ("exec_command_invalid", "command_too_long"));
        assert_eq!(refused("rdp", Some(PIN), "id"), ("exec_protocol_unsupported", "exec_requires_ssh"));
        assert_eq!(refused("ssh", None, "id"), ("exec_hostkey_pin_required", "hostkey_pin_required"));
        assert_eq!(refused("ssh", Some("  "), "id"), ("exec_hostkey_pin_required", "hostkey_pin_required"));
        // The limit is inclusive.
        assert!(open_exec(&master, &target, "ssh", Some(PIN), password(b"pw"), &"x".repeat(4096)).is_ok());
    }

    /// An envelope past the bastion's 16 KiB cap is refused here as
    /// `envelope_too_large`, never posted to be refused there: a 4 KiB
    /// command with a large credential does not fit.
    #[test]
    fn build_open_exec_refuses_an_envelope_past_the_cap() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());
        let command = "y".repeat(MAX_EXEC_COMMAND_BYTES);
        let big_key = vec![b'k'; 5 * 1024];
        match open_exec(&master, &target, "ssh", Some(PIN), password(&big_key), &command) {
            Err(e @ OpenEnvelopeError::TooLarge) => {
                assert!(e.to_string().starts_with("envelope_too_large: "), "{e}")
            }
            Err(other) => panic!("expected envelope_too_large, got {other}"),
            Ok(built) => panic!("built a {} byte envelope past the cap", built.bytes.len()),
        }
        // A short command with the same credential fits.
        let built = open_exec(&master, &target, "ssh", Some(PIN), password(b"pw"), "uptime").unwrap();
        assert!(built.bytes.len() <= bv_crypto::MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn build_renew_carries_correlation() {
        let master = BvrgMasterSigningKey::generate().unwrap();
        let master_pub = master.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built = build_renew(&master, &target, &op_ctx(), "uuid-corr-original", 1800).unwrap();
        let verified = bvrg::verify(&built.bytes, &master_pub, kp.secret_key()).expect("verify");
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
    fn verify_with_grace_accepts_previous_master() {
        let prev = BvrgMasterSigningKey::generate().unwrap();
        let curr = BvrgMasterSigningKey::generate().unwrap();
        let curr_pub = curr.public_key();
        let prev_pub = prev.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        // Signed by the *previous* master.
        let built = build_attest(&prev, &target, &op_ctx()).unwrap();

        // Current alone refuses.
        assert!(bvrg::verify(&built.bytes, &curr_pub, kp.secret_key()).is_err());

        // Current + previous accepts and reports the previous index.
        let (verified, idx) = verify_with_grace(&built.bytes, &[curr_pub.clone(), prev_pub.clone()], kp.secret_key())
            .expect("verify_with_grace");
        assert_eq!(verified.payload.op, "attest");
        assert_eq!(idx, 1);
    }

    #[test]
    fn verify_with_grace_rejects_when_only_current_offered() {
        // Simulates the post-grace state: load_active_keys drops the
        // previous master, so verify_with_grace gets only [current].
        let prev = BvrgMasterSigningKey::generate().unwrap();
        let curr = BvrgMasterSigningKey::generate().unwrap();
        let curr_pub = curr.public_key();
        let kp = MlKem768Provider.generate_keypair().unwrap();
        let target = synthetic_target_with_kem_pub(kp.public_key());

        let built = build_attest(&prev, &target, &op_ctx()).unwrap();
        let err = verify_with_grace(&built.bytes, &[curr_pub], kp.secret_key());
        assert!(err.is_err(), "previous-master envelope must be refused once grace ends");
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
