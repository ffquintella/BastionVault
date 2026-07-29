//! SSH security-key enrolment
//! (`features/connect-mfa-and-fido2-ssh.md`).
//!
//! Registers a FIDO2 credential under the OpenSSH *application* (`ssh:` by
//! default) rather than the vault's WebAuthn relying party, derives the
//! matching `sk-` public key, and stores it against the calling operator's
//! principal.
//!
//! An `sk-` credential is a genuinely different credential from the operator's
//! WebAuthn passkey even on the same authenticator, because the relying-party
//! id differs. Enrolling one here does not affect FIDO2 login, and vice versa.
//!
//! Nothing secret crosses this module: the private half stays in the
//! authenticator and cannot be exported, and what we persist is a public key
//! plus a credential handle.

use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::Duration;

use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs};
use authenticator::crypto::{COSEKeyType, COSEAlgorithm};
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, PublicKeyCredentialParameters,
    PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
    UserVerificationRequirement,
};
use authenticator::statecallback::StateCallback;
use authenticator::StatusUpdate;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter, State};

use bv_client::Operation;

use crate::commands::fido2_native::handle_status_updates;
use crate::commands::make_request;
use crate::error::{CmdResult, CommandError};
use crate::session::sk_signer::{
    sk_ecdsa_p256_public_key, sk_ed25519_public_key, ALG_SK_ECDSA_P256, ALG_SK_ED25519,
};
use crate::state::AppState;

/// OpenSSH's default application for security-key credentials.
pub const DEFAULT_APPLICATION: &str = "ssh:";

/// How long the operator has to touch the key during enrolment. Longer than
/// the connect-time budget: enrolment may also require setting or entering a
/// PIN, which is slower than a bare touch.
const ENROL_TIMEOUT_MS: u64 = 60_000;

const SELF_PATH: &str = "sys/identity/ssh-security-key/self";

/// One principal's enrolment as the GUI sees it. Mirrors the server's
/// response shape; `enrolled = false` carries empty fields rather than an
/// error, so the settings page can render an "enrol a key" form.
#[derive(Debug, Clone, Serialize)]
pub struct SshSecurityKeyInfo {
    pub mount: String,
    pub name: String,
    pub enrolled: bool,
    pub algorithm: String,
    pub public_key: String,
    pub credential_id: String,
    pub application: String,
    pub comment: String,
    pub updated_at: String,
}

impl SshSecurityKeyInfo {
    fn from_map(m: &Map<String, Value>) -> Self {
        let s = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        Self {
            mount: s("mount"),
            name: s("name"),
            enrolled: m.get("enrolled").and_then(|v| v.as_bool()).unwrap_or(false),
            algorithm: s("algorithm"),
            public_key: s("public_key"),
            credential_id: s("credential_id"),
            application: s("application"),
            comment: s("comment"),
            updated_at: s("updated_at"),
        }
    }
}

/// Read the calling operator's own enrolment.
#[tauri::command]
pub async fn ssh_security_key_self_read(
    state: State<'_, AppState>,
) -> CmdResult<SshSecurityKeyInfo> {
    let resp = make_request(&state, Operation::Read, SELF_PATH.to_string(), None).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    Ok(SshSecurityKeyInfo::from_map(&data))
}

/// Remove the calling operator's own enrolment.
///
/// This only stops BastionVault from offering the key. It does not revoke
/// access to any target — that means removing the public key from the
/// target's `authorized_keys`, exactly as for any other SSH key. The GUI says
/// so next to the button.
#[tauri::command]
pub async fn ssh_security_key_self_delete(state: State<'_, AppState>) -> CmdResult<()> {
    make_request(&state, Operation::Delete, SELF_PATH.to_string(), None).await?;
    Ok(())
}

/// Every principal with an enrolled key (admin view).
#[tauri::command]
pub async fn ssh_security_key_list(
    state: State<'_, AppState>,
) -> CmdResult<Vec<SshSecurityKeyInfo>> {
    let resp =
        make_request(&state, Operation::List, "sys/identity/ssh-security-key".to_string(), None)
            .await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let keys = data.get("keys").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    Ok(keys
        .iter()
        .filter_map(|v| v.as_object())
        .map(|m| {
            let mut info = SshSecurityKeyInfo::from_map(m);
            // The list projection omits `enrolled`; every row in it is one.
            info.enrolled = true;
            info
        })
        .collect())
}

/// Remove another principal's enrolment (admin).
#[tauri::command]
pub async fn ssh_security_key_admin_delete(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    let mount = mount.trim().trim_end_matches('/').to_string();
    let path = format!("sys/identity/ssh-security-key/{mount}/{name}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

/// Enrol a new SSH security key for the calling operator.
///
/// Runs a CTAP2 `makeCredential` against the OpenSSH application, derives the
/// `sk-` public key from the returned COSE key, and stores it. Replaces any
/// existing enrolment — v1 is one key per principal.
///
/// `user_label` only ends up in the authenticator's own credential metadata
/// and the record's comment; it is not an identity claim.
#[tauri::command]
pub async fn ssh_security_key_enroll(
    state: State<'_, AppState>,
    app_handle: AppHandle,
    user_label: String,
    application: Option<String>,
    comment: Option<String>,
) -> CmdResult<SshSecurityKeyInfo> {
    let application = application
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| DEFAULT_APPLICATION.to_string());
    if !application.starts_with("ssh:") {
        return Err(CommandError::from(
            "the OpenSSH application must start with `ssh:` — a key registered under \
             anything else cannot be used for SSH."
                .to_string(),
        ));
    }
    let comment = comment.unwrap_or_default();

    // A fresh challenge per enrolment. Nothing verifies it (we request no
    // attestation), but reusing one across enrolments would let an
    // authenticator conflate two ceremonies.
    let client_data_hash: [u8; 32] = {
        let mut h = [0u8; 32];
        rand::rng().fill_bytes(&mut h);
        h
    };
    let user_id: Vec<u8> = {
        let mut id = [0u8; 16];
        rand::rng().fill_bytes(&mut id);
        id.to_vec()
    };

    let label = if user_label.trim().is_empty() { "bastionvault" } else { user_label.trim() };

    let register_args = RegisterArgs {
        client_data_hash,
        relying_party: RelyingParty {
            id: application.clone(),
            name: Some("BastionVault SSH".to_string()),
        },
        origin: application.clone(),
        user: PublicKeyCredentialUserEntity {
            id: user_id,
            name: Some(label.to_string()),
            display_name: Some(label.to_string()),
        },
        // Ed25519 first: it produces the smaller, simpler `sk-ssh-ed25519`
        // key. ES256 is the fallback for the many authenticators that do not
        // implement EdDSA.
        pub_cred_params: vec![
            PublicKeyCredentialParameters { alg: COSEAlgorithm::EDDSA },
            PublicKeyCredentialParameters { alg: COSEAlgorithm::ES256 },
        ],
        exclude_list: Vec::new(),
        user_verification_req: UserVerificationRequirement::Preferred,
        // v1 stores the credential id server-side, so a discoverable key would
        // consume one of the authenticator's scarce resident slots for no
        // benefit.
        resident_key_req: ResidentKeyRequirement::Discouraged,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let (pin_tx, pin_rx) = channel::<String>();
    {
        let mut guard = state.pin_sender.lock().unwrap();
        *guard = Some(pin_tx);
    }

    let handle = app_handle.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut service = AuthenticatorService::new()
            .map_err(|e| CommandError::from(format!("failed to init authenticator: {e:?}")))?;
        service.add_detected_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (result_tx, result_rx) = channel();

        let handle_clone = handle.clone();
        std::thread::spawn(move || {
            handle_status_updates(status_rx, handle_clone, pin_rx);
        });

        let callback = StateCallback::new(Box::new(move |rv| {
            let _ = result_tx.send(rv);
        }));

        let _ = handle.emit("fido2-status", "insert-key");

        service.register(ENROL_TIMEOUT_MS, register_args, status_tx, callback)
            .map_err(CommandError::from)?;

        match result_rx.recv_timeout(Duration::from_millis(ENROL_TIMEOUT_MS + 5_000)) {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(CommandError::from(e)),
            Err(RecvTimeoutError::Timeout) => {
                Err(CommandError::from("security-key enrolment timed out"))
            }
            Err(e) => Err(CommandError::from(format!("enrolment channel error: {e}"))),
        }
    })
    .await
    .map_err(|e| CommandError::from(format!("task join error: {e}")))??;

    let _ = state.pin_sender.lock().unwrap().take();
    let _ = app_handle.emit("fido2-status", "processing");

    let cred_data = result.att_obj.auth_data.credential_data.as_ref().ok_or_else(|| {
        CommandError::from(
            "the authenticator returned no credential data; enrolment cannot continue"
                .to_string(),
        )
    })?;

    let (algorithm, public_key) = match &cred_data.credential_public_key.key {
        COSEKeyType::OKP(okp) => (
            ALG_SK_ED25519.to_string(),
            sk_ed25519_public_key(&okp.x, &application, comment.trim())
                .map_err(CommandError::from)?,
        ),
        COSEKeyType::EC2(ec2) => {
            // SEC1 uncompressed point: 0x04 ‖ X ‖ Y.
            let mut point = Vec::with_capacity(1 + ec2.x.len() + ec2.y.len());
            point.push(0x04);
            point.extend_from_slice(&ec2.x);
            point.extend_from_slice(&ec2.y);
            (
                ALG_SK_ECDSA_P256.to_string(),
                sk_ecdsa_p256_public_key(&point, &application, comment.trim())
                    .map_err(CommandError::from)?,
            )
        }
        COSEKeyType::RSA(_) => {
            return Err(CommandError::from(
                "this authenticator produced an RSA credential; OpenSSH security keys \
                 must be Ed25519 or NIST P-256."
                    .to_string(),
            ));
        }
    };

    let mut body = Map::new();
    body.insert("algorithm".into(), Value::String(algorithm));
    body.insert("public_key".into(), Value::String(public_key));
    body.insert(
        "credential_id".into(),
        Value::String(URL_SAFE_NO_PAD.encode(&cred_data.credential_id)),
    );
    body.insert("application".into(), Value::String(application));
    body.insert("comment".into(), Value::String(comment.trim().to_string()));

    let resp = make_request(&state, Operation::Write, SELF_PATH.to_string(), Some(body)).await?;
    let data = resp.and_then(|r| r.data).unwrap_or_default();

    let _ = app_handle.emit("fido2-status", "complete");
    Ok(SshSecurityKeyInfo::from_map(&data))
}
